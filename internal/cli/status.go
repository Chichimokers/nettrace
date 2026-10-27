//go:build windows

package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"nettrace/internal/etwhelp"
	"nettrace/internal/model"
	"nettrace/internal/storage"
	"nettrace/internal/timeutil"
	"nettrace/internal/winproc"
)

type sourceReport struct {
	Source    string `json:"source"`
	Available bool   `json:"registered"`
	Enabled   bool   `json:"reported_enabled"`
	State     string `json:"state,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

type statusReport struct {
	App         string         `json:"app"`
	Version     string         `json:"version"`
	OS          string         `json:"os"`
	Host        string         `json:"host"`
	User        string         `json:"user"`
	Elevated    bool           `json:"elevated"`
	DBPath      string         `json:"db_path"`
	DBOK        bool           `json:"db_ok"`
	DBError     string         `json:"db_error,omitempty"`
	DBSizeBytes int64          `json:"db_size_bytes"`
	Schema      int            `json:"schema"`
	Sessions    int64          `json:"sessions"`
	Processes   int64          `json:"processes"`
	Connections int64          `json:"connections"`
	DNS         int64          `json:"dns"`
	Sources     []sourceReport `json:"providers"`
	Latest      *latestReport  `json:"latest_session,omitempty"`
}

type latestReport struct {
	ID          int64                 `json:"session_id"`
	Target      string                `json:"target"`
	MatchKind   string                `json:"match_kind"`
	StartedUTC  string                `json:"started_utc"`
	EndedUTC    string                `json:"ended_utc,omitempty"`
	Status      string                `json:"status"`
	CaptureNote string                `json:"capture_note,omitempty"`
	ETWEnabled  bool                  `json:"etw_enabled"`
	Counts      storage.SessionCounts `json:"counts"`
	Sources     []model.SourceStatus  `json:"sources,omitempty"`
}

func runStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	var (
		common commonFlags
		asJSON bool
	)
	addCommon(fs, &common)
	fs.BoolVar(&asJSON, "json", false, "print the report as JSON")
	if err := parseFlags(fs, args, func() { statusUsage(fs) }); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	cfg, err := common.load()
	if err != nil {
		return failf("configuration: %v", err)
	}
	rep := statusReport{
		App:      model.AppName,
		Version:  model.Version,
		OS:       winproc.OSVersion() + " " + runtime.GOARCH,
		Host:     winproc.Hostname(),
		User:     winproc.Username(),
		Elevated: winproc.Elevated(),
		DBPath:   cfg.DBPath,
		Sources: []sourceReport{
			{Source: model.ProviderKernelNetwork, Available: etwhelp.ProviderAvailable(model.ProviderKernelNetwork)},
			{Source: model.ProviderKernelProcess, Available: etwhelp.ProviderAvailable(model.ProviderKernelProcess)},
			{Source: model.ProviderDNSClient, Available: etwhelp.ProviderAvailable(model.ProviderDNSClient)},
		},
	}

	if st, err := os.Stat(cfg.DBPath); err == nil && !st.IsDir() {
		rep.DBSizeBytes = st.Size()
	}
	store, err := storage.Open(cfg.DBPath)
	if err != nil {
		rep.DBError = err.Error()
	} else {
		defer store.Close()
		rep.DBOK = true
		if counts, err := store.Counts(); err == nil {
			rep.Schema = counts.Schema
			rep.Sessions = counts.Sessions
			rep.Processes = counts.Processes
			rep.Connections = counts.Connections
			rep.DNS = counts.DNS
		}
		if latest, err := store.LatestSession(); err == nil && latest != nil {
			lr := &latestReport{
				ID: latest.ID, Target: targetLabel(latest), MatchKind: string(latest.MatchKind),
				StartedUTC: timeutil.UTCString(latest.StartedUTC), EndedUTC: utcOrEmpty(latest.EndedUTC),
				Status: latest.Status, CaptureNote: latest.CaptureNote, ETWEnabled: latest.ETWEnabled,
			}
			lr.Counts, _ = store.CountsForSession(latest.ID)
			lr.Sources, _ = store.SourceStatuses(latest.ID)
			rep.Latest = lr
		}
	}

	if asJSON {
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return failf("json: %v", err)
		}
		fmt.Println(string(data))
	} else {
		printStatus(rep)
	}
	if !rep.DBOK {
		return 1
	}
	return 0
}

func printStatus(rep statusReport) {
	fmt.Printf("%s %s\n", rep.App, rep.Version)
	fmt.Printf("Host:      %s  user: %s\n", rep.Host, rep.User)
	fmt.Printf("OS:        %s\n", rep.OS)
	if rep.Elevated {
		fmt.Printf("Privilege: administrator (kernel ETW providers can be enabled)\n")
	} else {
		fmt.Printf("Privilege: standard user - kernel ETW providers require Administrator\n")
		fmt.Printf("           monitor falls back to sampled IP Helper/Toolhelp data if they are denied\n")
	}
	fmt.Printf("Database:  %s\n", rep.DBPath)
	if !rep.DBOK {
		fmt.Printf("           ERROR: %s\n", rep.DBError)
	} else {
		fmt.Printf("           ok - schema %d, %.1f KiB\n", rep.Schema, float64(rep.DBSizeBytes)/1024)
		fmt.Printf("           sessions=%d processes=%d connections=%d dns=%d\n",
			rep.Sessions, rep.Processes, rep.Connections, rep.DNS)
	}
	fmt.Printf("\nEvent sources:\n")
	for _, s := range rep.Sources {
		state := "not registered"
		if s.Available {
			state = "registered"
		}
		fmt.Printf("  %-36s %s\n", s.Source, state)
	}
	fmt.Printf("  note: registered providers still require an elevated process to enable\n")

	if rep.Latest == nil {
		fmt.Printf("\nNo monitoring sessions stored yet.\n")
		return
	}
	fmt.Printf("\nLast session:\n")
	fmt.Printf("  #%d  %s  match=%s  status=%s  etw=%s\n",
		rep.Latest.ID, rep.Latest.Target, rep.Latest.MatchKind,
		rep.Latest.Status, etwStateText(rep.Latest))
	fmt.Printf("  started=%s  ended=%s\n",
		timeutil.Local(mustTime(rep.Latest.StartedUTC)), endText(mustTime(rep.Latest.EndedUTC)))
	fmt.Printf("  processes=%d connections=%d dns=%d\n",
		rep.Latest.Counts.Processes, rep.Latest.Counts.Connections, rep.Latest.Counts.DNS)
	if len(rep.Latest.Sources) > 0 {
		fmt.Printf("  source health:\n")
		for _, s := range rep.Latest.Sources {
			fmt.Printf("    %-24s %-12s %s\n", s.Source, s.State, s.Detail)
		}
	}
	if rep.Latest.CaptureNote != "" {
		fmt.Printf("  capture note: %s\n", rep.Latest.CaptureNote)
	}
}

func statusUsage(fs *flag.FlagSet) {
	fmt.Fprintf(fs.Output(), `Usage:
  nettrace status [--db PATH] [--json]

Checks the database, the Windows privilege level and whether the ETW provider
manifests are registered. It does not start a capture.

Flags:
`)
	fs.PrintDefaults()
}

func targetLabel(s *model.MonitorSession) string {
	if s.MatchKind == model.MatchPath && s.TargetPath != "" {
		return s.TargetPath
	}
	return s.TargetName
}

func utcOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return timeutil.UTCString(t)
}

// etwStateText reports whether a session used ETW and, when it did, how many
// of the three providers actually reached the running state. A session marked
// etw_enabled can still have had network or process tracing denied.
func etwStateText(l *latestReport) string {
	pairs := make([]string, 0, len(l.Sources))
	for _, s := range l.Sources {
		pairs = append(pairs, s.Source+"="+s.State)
	}
	return model.ETWStateFromPairs(pairs, l.ETWEnabled)
}

func mustTime(s string) time.Time {
	t, _ := timeutil.ParseDB(s)
	return t
}
