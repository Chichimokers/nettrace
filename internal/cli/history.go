package cli

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"nettrace/internal/exporter"
	"nettrace/internal/history"
	"nettrace/internal/model"
	"nettrace/internal/timeutil"
)

type filterFlags struct {
	exe     string
	name    string
	pid     uint
	session int64
	since   string
	until   string
	ip      string
	port    int
	proto   string
	domain  string
	event   string
	limit   int
}

func addFilterFlags(fs *flag.FlagSet, f *filterFlags, defaultLimit int) {
	fs.StringVar(&f.exe, "exe", "", "filter by executable name or path")
	fs.StringVar(&f.name, "name", "", "alias for --exe")
	fs.UintVar(&f.pid, "pid", 0, "filter by process ID")
	fs.Int64Var(&f.session, "session", 0, "filter by monitoring session ID")
	fs.StringVar(&f.since, "since", "", "start time (RFC3339, \"2006-01-02 15:04:05\" or \"2006-01-02\")")
	fs.StringVar(&f.until, "until", "", "end time (same formats as --since)")
	fs.StringVar(&f.ip, "ip", "", "filter by local or remote IP address")
	fs.IntVar(&f.port, "port", 0, "filter by local or remote port")
	fs.StringVar(&f.proto, "proto", "", "filter by protocol (tcp or udp)")
	fs.StringVar(&f.domain, "domain", "", "filter DNS records by domain (suffix match)")
	fs.StringVar(&f.event, "event", "", "filter connections by event_type")
	fs.IntVar(&f.limit, "limit", defaultLimit, "maximum rows per section (0 = no limit)")
}

func (f *filterFlags) build() (history.Filter, error) {
	var out history.Filter
	exe := f.exe
	if strings.TrimSpace(f.name) != "" {
		if strings.TrimSpace(exe) != "" {
			return out, fmt.Errorf("use either --exe or --name, not both")
		}
		exe = f.name
	}
	out.Exe = strings.TrimSpace(exe)
	out.SessionID = f.session
	out.PID = uint32(f.pid)
	out.Limit = f.limit
	out.Event = strings.TrimSpace(f.event)

	now := time.Now()
	var err error
	if out.Since, err = timeutil.SinceOrZero(f.since, now); err != nil {
		return out, fmt.Errorf("--since: %w", err)
	}
	if out.Until, err = timeutil.SinceOrZero(f.until, now); err != nil {
		return out, fmt.Errorf("--until: %w", err)
	}
	if !out.Since.IsZero() && !out.Until.IsZero() && out.Since.After(out.Until) {
		return out, fmt.Errorf("--since is after --until")
	}
	if ip := strings.TrimSpace(f.ip); ip != "" {
		if _, err := netip.ParseAddr(ip); err != nil {
			return out, fmt.Errorf("--ip expects an IP address: %w", err)
		}
		out.IP = ip
	}
	if f.port < 0 || f.port > 65535 {
		return out, fmt.Errorf("--port must be between 1 and 65535")
	}
	out.Port = uint16(f.port)
	proto := strings.ToLower(strings.TrimSpace(f.proto))
	if proto != "" && proto != "tcp" && proto != "udp" {
		return out, fmt.Errorf("--proto must be tcp or udp")
	}
	out.Proto = proto
	out.Domain = strings.TrimSpace(f.domain)
	return out, nil
}

func (f *filterFlags) describe() string {
	var parts []string
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	add("exe", f.exe)
	add("name", f.name)
	if f.pid != 0 {
		parts = append(parts, fmt.Sprintf("pid=%d", f.pid))
	}
	if f.session != 0 {
		parts = append(parts, fmt.Sprintf("session=%d", f.session))
	}
	add("since", f.since)
	add("until", f.until)
	add("ip", f.ip)
	if f.port != 0 {
		parts = append(parts, fmt.Sprintf("port=%d", f.port))
	}
	add("proto", f.proto)
	add("domain", f.domain)
	add("event", f.event)
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}

func runHistory(args []string) int {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	var (
		common  commonFlags
		filters filterFlags
		asJSON  bool
		dnsOnly bool
	)
	addCommon(fs, &common)
	addFilterFlags(fs, &filters, 200)
	fs.BoolVar(&asJSON, "json", false, "print the result as JSON")
	fs.BoolVar(&dnsOnly, "dns", false, "show only DNS records")
	if err := parseFlags(fs, args, func() { historyUsage(fs) }); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	cfg, err := common.load()
	if err != nil {
		return failf("configuration: %v", err)
	}
	filter, err := filters.build()
	if err != nil {
		return failf("%v", err)
	}
	store, err := openStore(cfg)
	if err != nil {
		return failf("database: %v", err)
	}
	defer store.Close()

	res, err := history.Query(context.Background(), store.DB(), filter)
	if err != nil {
		return failf("history: %v", err)
	}

	if asJSON {
		data, err := exporter.MarshalJSON(res, []string{"all"}, time.Now())
		if err != nil {
			return failf("json: %v", err)
		}
		os.Stdout.Write(data)
		return 0
	}

	fmt.Printf("%s %s - history\n", model.AppName, model.Version)
	fmt.Printf("Database: %s\n", store.Path())
	fmt.Printf("Filters:  %s\n", filters.describe())
	fmt.Printf("Times:    local timezone; timestamps are stored in UTC\n")
	if filter.Limit > 0 {
		fmt.Printf("Limit:    %d rows per section (use --limit 0 for all)\n", filter.Limit)
	}

	if !dnsOnly {
		printSessions(res.Sessions)
		printProcesses(res.Processes)
		printConnections(res.Connections)
	}
	printDNS(res.DNS)
	return 0
}

func historyUsage(fs *flag.FlagSet) {
	fmt.Fprintf(fs.Output(), `Usage:
  nettrace history [filters] [flags]

Shows monitoring sessions, process instances, TCP/UDP connection events and DNS
queries stored in the database.

Flags:
`)
	fs.PrintDefaults()
	fmt.Fprintf(fs.Output(), `
Examples:
  nettrace history
  nettrace history --exe "SC2_x64.exe" --limit 50
  nettrace history --pid 1234
  nettrace history --since "2026-10-26 10:00:00" --proto tcp --port 443
  nettrace history --domain battle.net
  nettrace history --json
`)
}

func printSessions(sessions []model.MonitorSession) {
	fmt.Printf("\nSessions (%d)\n", len(sessions))
	if len(sessions) == 0 {
		fmt.Printf("  (none)\n")
		return
	}
	for _, s := range sessions {
		fmt.Printf("  #%d  %s -> %s  %s  match=%s  status=%s  etw=%s\n",
			s.ID, timeutil.Local(s.StartedUTC), endText(s.EndedUTC), s.TargetName,
			s.MatchKind, s.Status, s.ETWState())
		if s.TargetPath != "" {
			fmt.Printf("       path: %s\n", s.TargetPath)
		}
		if s.CaptureNote != "" {
			fmt.Printf("       note: %s\n", s.CaptureNote)
		}
	}
}

func printProcesses(procs []model.ProcessInstance) {
	fmt.Printf("\nProcesses (%d)\n", len(procs))
	if len(procs) == 0 {
		fmt.Printf("  (none)\n")
		return
	}
	for _, p := range procs {
		state := p.CaptureState
		if p.AlreadyRunning {
			state += ",present_at_start"
		}
		fmt.Printf("  pid=%d ppid=%d  session=#%d  %s  %s  start=%s end=%s  %s  src=%s\n",
			p.PID, p.ParentPID, p.SessionID, p.ExeName, pathText(p.ExePath),
			timeutil.Local(p.StartedUTC), endText(p.EndedUTC), state, p.Source)
		if p.MatchNote != "" {
			fmt.Printf("       note: %s\n", p.MatchNote)
		}
	}
}

func printConnections(conns []model.ConnectionEvent) {
	fmt.Printf("\nConnections (%d)\n", len(conns))
	if len(conns) == 0 {
		fmt.Printf("  (none)\n")
		return
	}
	for _, c := range conns {
		detail := ""
		if c.Detail != "" {
			detail = "  detail=" + c.Detail
		}
		fmt.Printf("  %s  pid=%d  %s  %s  %s:%d -> %s:%d  %s/%s  bytes=%d/%d n=%d  src=%s%s\n",
			timeutil.Local(c.FirstSeenUTC), c.PID, c.ExeName, c.Proto,
			c.LocalAddr, c.LocalPort, c.RemoteAddr, c.RemotePort,
			c.EventType, dash(c.State), c.BytesSent, c.BytesRecv, c.Occurrences,
			c.Source, detail)
	}
}

func printDNS(queries []model.DNSQuery) {
	fmt.Printf("\nDNS (%d)\n", len(queries))
	if len(queries) == 0 {
		fmt.Printf("  (none)\n")
		return
	}
	for _, q := range queries {
		attr := "attributed"
		if !q.Attributed {
			attr = "unattributed"
		}
		answers := "-"
		if len(q.Answers) > 0 {
			answers = strings.Join(q.Answers, ",")
		}
		fmt.Printf("  %s  pid=%d  %s  %s  %s  %s  answers=%s  n=%d  %s  src=%s\n",
			timeutil.Local(q.FirstSeenUTC), q.PID, q.ExeName, q.QueryName, q.QueryTypeName,
			q.StatusText, answers, q.Occurrences, attr, q.Source)
	}
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func endText(t time.Time) string {
	if t.IsZero() {
		return "running"
	}
	return timeutil.Local(t)
}

func pathText(p string) string {
	if p == "" {
		return "(path unavailable)"
	}
	return p
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
