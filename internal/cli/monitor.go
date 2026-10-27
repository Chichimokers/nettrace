//go:build windows

package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"nettrace/internal/collector"
	"nettrace/internal/model"
	"nettrace/internal/network"
	"nettrace/internal/process"
	"nettrace/internal/storage"
	"nettrace/internal/timeutil"
	"nettrace/internal/winproc"
)

var envPercent = regexp.MustCompile(`%([^%]+)%`)

func runMonitor(args []string) int {
	fs := flag.NewFlagSet("monitor", flag.ContinueOnError)
	var (
		common    commonFlags
		exePath   string
		exeName   string
		noETW     bool
		quiet     bool
		verbose   bool
		duration  time.Duration
		pollEvery time.Duration
		dnsUnattr bool
	)
	addCommon(fs, &common)
	fs.StringVar(&exePath, "exe", "", "full path to the executable to monitor")
	fs.StringVar(&exeName, "name", "", "executable file name to monitor (all instances)")
	fs.BoolVar(&noETW, "no-etw", false, "do not use ETW; sample IP Helper and Toolhelp32 instead")
	fs.BoolVar(&quiet, "quiet", false, "do not print individual events")
	fs.BoolVar(&verbose, "verbose", false, "also print TCP data and UDP datagram events")
	fs.DurationVar(&duration, "duration", 0, "stop automatically after this duration (for example 30s)")
	fs.DurationVar(&pollEvery, "poll-interval", 0, "process/IP Helper polling interval (default from config)")
	fs.BoolVar(&dnsUnattr, "dns-unattributed", false, "store DNS queries that cannot be attributed to a monitored PID")
	if err := parseFlags(fs, args, func() { monitorUsage(fs) }); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	cfg, err := common.load()
	if err != nil {
		return failf("configuration: %v", err)
	}
	target, warning, err := resolveTarget(exePath, exeName)
	if err != nil {
		return failf("%v", err)
	}
	if warning != "" {
		fmt.Fprintf(os.Stderr, "nettrace: note: %s\n", warning)
	}
	if pollEvery <= 0 {
		pollEvery = cfg.PollInterval()
	}
	if dnsUnattr {
		cfg.StoreUnattributedDNS = true
	}

	store, err := openStore(cfg)
	if err != nil {
		return failf("database: %v", err)
	}
	defer store.Close()

	elevated := winproc.Elevated()
	started := time.Now().UTC()
	note := initialCaptureNote(elevated, noETW)
	sessionID, err := store.CreateSession(model.SessionStart{
		Target:      target,
		StartedUTC:  started,
		CaptureNote: note,
		ETWEnabled:  !noETW,
		Sources:     []string{},
		Host:        winproc.Hostname(),
		Username:    winproc.Username(),
		OSVersion:   winproc.OSVersion(),
		AppVersion:  model.Version,
	})
	if err != nil {
		return failf("create session: %v", err)
	}

	fmt.Printf("%s %s\n", model.AppName, model.Version)
	fmt.Printf("Database: %s\n", store.Path())
	if target.Kind == model.MatchPath {
		fmt.Printf("Target:   %s (match by full path)\n", target.Path)
	} else {
		fmt.Printf("Target:   %s (match by executable name)\n", target.Name)
		fmt.Printf("          all instances with this file name will be monitored\n")
	}
	fmt.Printf("Session:  #%d\n", sessionID)
	fmt.Printf("Started:  %s local  (%s)\n", timeutil.Local(started), timeutil.UTCString(started))
	if elevated {
		fmt.Printf("Token:    administrator (kernel ETW providers available)\n")
	} else {
		fmt.Printf("Token:    standard user (kernel ETW providers require Administrator)\n")
	}
	if noETW {
		fmt.Printf("Capture:  sampled IP Helper + Toolhelp32 (ETW disabled)\n")
	} else {
		fmt.Printf("Capture:  ETW requested; sources are enabled before waiting for the process\n")
	}
	fmt.Printf("          collection starts now; use Ctrl+C to stop\n")

	writer := store.NewWriter()
	writer.Start()

	procs := process.New(store, target, sessionID, started, func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "nettrace: %s\n", fmt.Sprintf(format, a...))
	})
	resolver := network.NewResolver(cfg.LocalAddrRefresh(), winproc.LocalAddresses)

	col := collector.New(collector.Options{
		Store:                store,
		Writer:               writer,
		Procs:                procs,
		Resolver:             resolver,
		SessionID:            sessionID,
		PollInterval:         pollEvery,
		UseETW:               !noETW,
		StoreUnattributedDNS: cfg.StoreUnattributedDNS,
		Quiet:                quiet,
		Verbose:              verbose,
		Out:                  os.Stdout,
	})

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	if duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, duration)
		defer cancel()
		fmt.Printf("Duration: %s\n", duration)
	}

	if err := col.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nettrace: collector: %v\n", err)
	}
	writer.Stop()
	stats := col.Stats()
	written, dropped, failed, lastErr := writer.Stats()

	ended := time.Now().UTC()
	already := countAlreadyRunning(store, sessionID)
	finalNote := buildFinalNote(elevated, stats, dropped, lastErr, already)
	if err := store.UpdateSessionRuntime(sessionID, stats.ETWEnabled, finalNote, col.Sources()); err != nil {
		fmt.Fprintf(os.Stderr, "nettrace: %v\n", err)
	}
	if err := store.FinishSession(sessionID, ended, "finished", finalNote, col.Sources()); err != nil {
		fmt.Fprintf(os.Stderr, "nettrace: %v\n", err)
	}

	counts, _ := store.CountsForSession(sessionID)

	fmt.Printf("\nCapture stopped: %s local\n", timeutil.Local(ended))
	fmt.Printf("Session #%d summary\n", sessionID)
	fmt.Printf("  duration:    %s\n", ended.Sub(started).Round(time.Millisecond))
	fmt.Printf("  processes:   %d (started before capture: %d)\n", counts.Processes, already)
	switch {
	case etwActive(stats, model.SourceETWNetwork):
		fmt.Printf("  connections: %d aggregated rows (ETW state changes + byte counters)\n", counts.Connections)
	case stats.PollConnections:
		fmt.Printf("  connections: %d sampled rows from IP Helper tables (short-lived connections may be missing)\n", counts.Connections)
	default:
		fmt.Printf("  connections: %d aggregated rows\n", counts.Connections)
	}
	fmt.Printf("  dns:         %d queries\n", counts.DNS)
	fmt.Printf("  ETW:         %s\n", etwSummary(stats))
	if stats.ETWLost > 0 || stats.ETWDropped > 0 {
		fmt.Printf("  ETW loss:    %d events reported lost by ETW, %d dropped by NetTrace queue\n",
			stats.ETWLost, stats.ETWDropped)
	}
	fmt.Printf("  storage:     %d written, %d dropped, %d failed\n", written, dropped, failed)
	if lastErr != "" {
		fmt.Printf("  last error:  %s\n", lastErr)
	}
	fmt.Printf("  completeness: %s\n", completenessText(stats))
	fmt.Printf("Inspect with:\n  nettrace history --session %d\n  nettrace export --what all --format json --out nettrace-session-%d.json\n",
		sessionID, sessionID)
	return 0
}

func monitorUsage(fs *flag.FlagSet) {
	fmt.Fprintf(fs.Output(), `Usage:
  nettrace monitor --exe "C:\path\program.exe" [flags]
  nettrace monitor --name "program.exe" [flags]

Capture starts before NetTrace waits for the executable. Every matching
instance is monitored. If the executable is already running, the instance is
recorded as "already_running" and no earlier activity is invented.

Flags:
`)
	fs.PrintDefaults()
	fmt.Fprintf(fs.Output(), `
Examples:
  nettrace monitor --exe "D:\Games\StarCraft II\SC2_x64.exe"
  nettrace monitor --name "Battle.net.exe" --duration 5m
  nettrace monitor --name "game.exe" --no-etw
`)
}

func resolveTarget(exePath, exeName string) (model.Target, string, error) {
	exePath = strings.TrimSpace(exePath)
	exeName = strings.TrimSpace(exeName)
	switch {
	case exePath == "" && exeName == "":
		return model.Target{}, "", fmt.Errorf("one of --exe or --name is required")
	case exePath != "" && exeName != "":
		return model.Target{}, "", fmt.Errorf("use either --exe or --name, not both")
	}
	if exeName != "" {
		if strings.ContainsAny(exeName, `\/`) || filepath.IsAbs(exeName) {
			return model.Target{}, "", fmt.Errorf("--name expects a file name, not a path: %q", exeName)
		}
		return model.NewTargetName(exeName, exeName), "", nil
	}

	expanded := expandEnv(exePath)
	if !strings.ContainsAny(expanded, `\/`) && !filepath.IsAbs(expanded) {
		// A bare executable name is accepted as a convenience but recorded as a
		// name match, not as a path match.
		return model.NewTargetName(exePath, expanded),
			fmt.Sprintf("--exe %q has no directory component; monitoring by executable name instead", exePath), nil
	}
	abs, err := filepath.Abs(expanded)
	if err != nil {
		return model.Target{}, "", fmt.Errorf("resolve --exe path: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return model.Target{}, "", fmt.Errorf("executable does not exist: %s", abs)
		}
		return model.Target{}, "", fmt.Errorf("cannot access %s: %w", abs, err)
	}
	if info.IsDir() {
		return model.Target{}, "", fmt.Errorf("--exe points to a directory: %s", abs)
	}
	return model.NewTargetPath(exePath, abs), "", nil
}

func expandEnv(s string) string {
	s = envPercent.ReplaceAllStringFunc(s, func(m string) string {
		name := strings.Trim(m, "%")
		if v := os.Getenv(name); v != "" {
			return v
		}
		return m
	})
	return os.ExpandEnv(s)
}

func initialCaptureNote(elevated, noETW bool) string {
	var parts []string
	parts = append(parts, "capture started before waiting for the target; activity before this instant is unknown")
	if !elevated {
		parts = append(parts, "process token is not elevated; kernel ETW providers may be unavailable")
	}
	if noETW {
		parts = append(parts, "ETW disabled with --no-etw")
	}
	return strings.Join(parts, "; ")
}

func buildFinalNote(elevated bool, stats collector.Stats, writerDropped uint64, lastErr string,
	alreadyRunning int64) string {
	var parts []string
	parts = append(parts, "capture started before waiting for the target; activity before this instant is unknown")
	if !elevated {
		parts = append(parts, "process token is not elevated")
	}
	if stats.ETWEnabled {
		if active, failing := splitETWSources(stats); len(failing) == 0 {
			parts = append(parts, "ETW sources were active ("+strings.Join(active, ", ")+")")
		} else {
			parts = append(parts, "ETW was only partially available; "+
				describeSources(active, failing))
		}
	} else {
		reason := stats.ETWProblem
		if reason == "" {
			reason = "not available"
		}
		parts = append(parts, "ETW was not active ("+reason+"); connection history is sampled and DNS is missing")
	}
	if stats.PollConnections {
		parts = append(parts, "IP Helper/Toolhelp32 sampling was used; short-lived connections can be missed")
	}
	if alreadyRunning > 0 {
		parts = append(parts, fmt.Sprintf("%d process instance(s) were already running when capture started", alreadyRunning))
	}
	if stats.ETWLost > 0 {
		parts = append(parts, fmt.Sprintf("ETW reported %d lost events", stats.ETWLost))
	}
	if stats.ETWDropped > 0 {
		parts = append(parts, fmt.Sprintf("NetTrace dropped %d ETW events because its ingest queue was full", stats.ETWDropped))
	}
	if writerDropped > 0 {
		parts = append(parts, fmt.Sprintf("%d records were dropped before they could be stored", writerDropped))
	}
	if lastErr != "" {
		parts = append(parts, "last storage error: "+lastErr)
	}
	if etwActive(stats, model.SourceETWNetwork) && stats.ETWLost == 0 && stats.ETWDropped == 0 {
		parts = append(parts, "history is limited to observed events; ETW buffers can still lose data on a busy system")
	}
	return strings.Join(parts, "; ")
}

// etwLabels maps the three ETW providers to the names used in operator output.
var etwLabels = []struct {
	label  string
	source string
}{
	{"Kernel-Network", model.SourceETWNetwork},
	{"Kernel-Process", model.SourceETWProcess},
	{"DNS-Client", model.SourceETWDNS},
}

func etwActive(stats collector.Stats, source string) bool {
	return stats.Sources[source] == model.SourceRunning
}

// splitETWSources classifies each provider by its final state. Only providers
// whose status is literally "running" count as active, so partial ETW success
// is never reported as full coverage.
func splitETWSources(stats collector.Stats) (active, failing []string) {
	for _, item := range etwLabels {
		if etwActive(stats, item.source) {
			active = append(active, item.label)
			continue
		}
		detail := stats.SourceDetails[item.source]
		if detail == "" {
			detail = "not enabled"
		}
		failing = append(failing, fmt.Sprintf("%s (%s)", item.label, detail))
	}
	return active, failing
}

func describeSources(active, failing []string) string {
	var parts []string
	if len(active) > 0 {
		parts = append(parts, "active: "+strings.Join(active, ", "))
	}
	if len(failing) > 0 {
		parts = append(parts, "unavailable: "+strings.Join(failing, ", "))
	}
	return strings.Join(parts, "; ")
}

func etwSummary(stats collector.Stats) string {
	if !stats.ETWEnabled {
		reason := stats.ETWProblem
		if reason == "" {
			reason = "not available"
		}
		return "inactive - " + reason
	}
	active, failing := splitETWSources(stats)
	switch {
	case len(failing) == 0:
		return "active (" + strings.Join(active, ", ") + ")"
	case len(active) == 0:
		return "inactive - no provider could be enabled: " + strings.Join(failing, ", ")
	default:
		return "partially active; " + describeSources(active, failing)
	}
}

func completenessText(stats collector.Stats) string {
	network := etwActive(stats, model.SourceETWNetwork)
	dns := etwActive(stats, model.SourceETWDNS)
	switch {
	case !stats.ETWEnabled:
		return "limited (sampled sources; short-lived connections can be missed; DNS is not collected)"
	case !network && !dns:
		return "limited (network and DNS are sampled or missing; short-lived connections can be missed)"
	case !network:
		return "limited (connections are sampled from IP Helper tables; short-lived connections can be missed)"
	case !dns:
		return "limited (DNS is not collected; connection events start at capture time)"
	default:
		return "limited to events observed after capture started; ETW buffer loss is possible"
	}
}

func countAlreadyRunning(store *storage.Store, sessionID int64) int64 {
	var n int64
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM process_instances
		WHERE session_id=? AND already_running=1`, sessionID).Scan(&n)
	return n
}
