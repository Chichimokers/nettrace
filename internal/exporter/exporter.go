// Package exporter writes history query results as CSV or JSON.
package exporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nettrace/internal/history"
	"nettrace/internal/model"
	"nettrace/internal/timeutil"
)

// Options controls an export.
type Options struct {
	Format string   // "csv" or "json"
	What   []string // sessions, processes, connections, dns, all
	Out    string
	Now    time.Time
}

// NormalizeWhat validates and expands the --what values.
func NormalizeWhat(what []string) ([]string, error) {
	if len(what) == 0 {
		return []string{"all"}, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, item := range what {
		for _, part := range strings.Split(item, ",") {
			part = strings.ToLower(strings.TrimSpace(part))
			if part == "" || seen[part] {
				continue
			}
			switch part {
			case "all", "sessions", "processes", "connections", "dns":
			default:
				return nil, fmt.Errorf("unknown export type %q (use all, sessions, processes, connections or dns)", part)
			}
			seen[part] = true
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return []string{"all"}, nil
	}
	for _, part := range out {
		if part == "all" {
			return []string{"all"}, nil
		}
	}
	return out, nil
}

func wants(what []string, name string) bool {
	for _, w := range what {
		if w == "all" || w == name {
			return true
		}
	}
	return false
}

// Write exports res and returns the paths that were written.
func Write(res *history.Result, opts Options) ([]string, error) {
	format := strings.ToLower(strings.TrimSpace(opts.Format))
	if format == "" {
		format = "csv"
	}
	what, err := NormalizeWhat(opts.What)
	if err != nil {
		return nil, err
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	if format == "json" {
		return writeJSON(res, what, opts)
	}
	if format != "csv" {
		return nil, fmt.Errorf("unknown format %q (use csv or json)", format)
	}
	return writeCSV(res, what, opts)
}

type jsonExport struct {
	ExportedUTC string       `json:"exported_utc"`
	App         string       `json:"app"`
	Version     string       `json:"version"`
	Sessions    []sessionRow `json:"sessions,omitempty"`
	Processes   []processRow `json:"processes,omitempty"`
	Connections []connRow    `json:"connections,omitempty"`
	DNS         []dnsRow     `json:"dns,omitempty"`
}

func writeJSON(res *history.Result, what []string, opts Options) ([]string, error) {
	data, err := MarshalJSON(res, what, opts.Now)
	if err != nil {
		return nil, err
	}
	path := opts.Out
	if path == "" {
		path = filepath.Join(".", "nettrace-export-"+opts.Now.Format("20060102-150405")+".json")
	}
	if err := ensureDir(path); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return []string{path}, nil
}

// ensureDir creates the parent directory of an output file when needed.
func ensureDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create output directory %s: %w", dir, err)
	}
	return nil
}

// MarshalJSON builds the JSON representation used by export and history --json.
func MarshalJSON(res *history.Result, what []string, now time.Time) ([]byte, error) {
	out := jsonExport{
		ExportedUTC: timeutil.UTCString(now),
		App:         model.AppName,
		Version:     model.Version,
	}
	if wants(what, "sessions") {
		for _, s := range res.Sessions {
			out.Sessions = append(out.Sessions, sessionToRow(s))
		}
	}
	if wants(what, "processes") {
		for _, p := range res.Processes {
			out.Processes = append(out.Processes, processToRow(p))
		}
	}
	if wants(what, "connections") {
		for _, c := range res.Connections {
			out.Connections = append(out.Connections, connToRow(c))
		}
	}
	if wants(what, "dns") {
		for _, q := range res.DNS {
			out.DNS = append(out.DNS, dnsToRow(q))
		}
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func writeCSV(res *history.Result, what []string, opts Options) ([]string, error) {
	tables := what
	if len(what) == 1 && what[0] == "all" {
		tables = []string{"sessions", "processes", "connections", "dns"}
	}
	var written []string
	base := strings.TrimSuffix(opts.Out, ".csv")
	if base == "" {
		base = "nettrace-export-" + opts.Now.Format("20060102-150405")
	}
	for _, table := range tables {
		path := opts.Out
		if path == "" || len(tables) > 1 {
			path = base + "." + table + ".csv"
		}
		if err := writeTable(path, table, res); err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}

func writeTable(path, table string, res *history.Result) error {
	if err := ensureDir(path); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	write := func(record []string) error { return w.Write(record) }

	switch table {
	case "sessions":
		_ = write([]string{"session_id", "target_input", "target_path", "target_name", "match_kind",
			"started_utc", "ended_utc", "status", "capture_note", "etw_enabled", "etw_state", "sources",
			"host", "username", "os_version", "app_version"})
		for _, s := range res.Sessions {
			_ = write([]string{
				strconv.FormatInt(s.ID, 10), s.TargetInput, s.TargetPath, s.TargetName, string(s.MatchKind),
				timeutil.UTCString(s.StartedUTC), utcPtr(s.EndedUTC), s.Status, s.CaptureNote,
				strconv.FormatBool(s.ETWEnabled), s.ETWState(), s.SourcesJSON,
				s.Host, s.Username, s.OSVersion, s.AppVersion,
			})
		}
	case "processes":
		_ = write([]string{"process_instance_id", "session_id", "pid", "parent_pid", "exe_name", "exe_path",
			"started_utc", "detected_utc", "ended_utc", "exit_code", "already_running", "capture_state",
			"match_note", "source"})
		for _, p := range res.Processes {
			exit := ""
			if p.ExitCode != nil {
				exit = strconv.FormatUint(uint64(*p.ExitCode), 10)
			}
			_ = write([]string{
				strconv.FormatInt(p.ID, 10), strconv.FormatInt(p.SessionID, 10),
				strconv.FormatUint(uint64(p.PID), 10), strconv.FormatUint(uint64(p.ParentPID), 10),
				p.ExeName, p.ExePath,
				timeutil.UTCString(p.StartedUTC), timeutil.UTCString(p.DetectedUTC), utcPtr(p.EndedUTC),
				exit, strconv.FormatBool(p.AlreadyRunning), p.CaptureState, p.MatchNote, p.Source,
			})
		}
	case "connections":
		_ = write([]string{"connection_id", "session_id", "process_instance_id", "pid", "exe_name",
			"proto", "ip_version", "local_addr", "local_port", "remote_addr", "remote_port",
			"state", "event_type", "first_seen_utc", "last_seen_utc",
			"bytes_sent", "bytes_recv", "occurrences", "source", "detail"})
		for _, c := range res.Connections {
			_ = write([]string{
				strconv.FormatInt(c.ID, 10), strconv.FormatInt(c.SessionID, 10),
				strconv.FormatInt(c.ProcessInstanceID, 10), strconv.FormatUint(uint64(c.PID), 10),
				c.ExeName, c.Proto, strconv.Itoa(c.IPVersion),
				c.LocalAddr, strconv.FormatUint(uint64(c.LocalPort), 10),
				c.RemoteAddr, strconv.FormatUint(uint64(c.RemotePort), 10),
				c.State, c.EventType,
				timeutil.UTCString(c.FirstSeenUTC), timeutil.UTCString(c.LastSeenUTC),
				strconv.FormatUint(c.BytesSent, 10), strconv.FormatUint(c.BytesRecv, 10),
				strconv.FormatUint(c.Occurrences, 10), c.Source, c.Detail,
			})
		}
	case "dns":
		_ = write([]string{"dns_id", "session_id", "process_instance_id", "pid", "exe_name",
			"query_name", "query_type", "query_type_name", "status", "status_text", "answers",
			"attributed", "attribution", "first_seen_utc", "last_seen_utc", "occurrences", "source", "raw"})
		for _, q := range res.DNS {
			_ = write([]string{
				strconv.FormatInt(q.ID, 10), strconv.FormatInt(q.SessionID, 10),
				strconv.FormatInt(q.ProcessInstanceID, 10), strconv.FormatUint(uint64(q.PID), 10),
				q.ExeName, q.QueryName, strconv.Itoa(int(q.QueryType)), q.QueryTypeName,
				strconv.FormatUint(uint64(q.Status), 10), q.StatusText, strings.Join(q.Answers, ";"),
				strconv.FormatBool(q.Attributed), q.Attribution,
				timeutil.UTCString(q.FirstSeenUTC), timeutil.UTCString(q.LastSeenUTC),
				strconv.FormatUint(q.Occurrences, 10), q.Source, q.Raw,
			})
		}
	default:
		return fmt.Errorf("unknown table %q", table)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func utcPtr(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return timeutil.UTCString(t)
}

type sessionRow struct {
	SessionID   int64    `json:"session_id"`
	TargetInput string   `json:"target_input"`
	TargetPath  string   `json:"target_path"`
	TargetName  string   `json:"target_name"`
	MatchKind   string   `json:"match_kind"`
	StartedUTC  string   `json:"started_utc"`
	EndedUTC    string   `json:"ended_utc,omitempty"`
	Status      string   `json:"status"`
	CaptureNote string   `json:"capture_note,omitempty"`
	ETWEnabled  bool     `json:"etw_enabled"`
	ETWState    string   `json:"etw_state"`
	Sources     []string `json:"sources"`
	Host        string   `json:"host,omitempty"`
	Username    string   `json:"username,omitempty"`
	OSVersion   string   `json:"os_version,omitempty"`
	AppVersion  string   `json:"app_version,omitempty"`
}

type processRow struct {
	ProcessInstanceID int64   `json:"process_instance_id"`
	SessionID         int64   `json:"session_id"`
	PID               uint32  `json:"pid"`
	ParentPID         uint32  `json:"parent_pid"`
	ExeName           string  `json:"exe_name"`
	ExePath           string  `json:"exe_path,omitempty"`
	StartedUTC        string  `json:"started_utc"`
	DetectedUTC       string  `json:"detected_utc"`
	EndedUTC          string  `json:"ended_utc,omitempty"`
	ExitCode          *uint32 `json:"exit_code,omitempty"`
	AlreadyRunning    bool    `json:"already_running"`
	CaptureState      string  `json:"capture_state"`
	MatchNote         string  `json:"match_note,omitempty"`
	Source            string  `json:"source"`
}

type connRow struct {
	ConnectionID      int64  `json:"connection_id"`
	SessionID         int64  `json:"session_id"`
	ProcessInstanceID int64  `json:"process_instance_id"`
	PID               uint32 `json:"pid"`
	ExeName           string `json:"exe_name"`
	Proto             string `json:"proto"`
	IPVersion         int    `json:"ip_version"`
	LocalAddr         string `json:"local_addr"`
	LocalPort         uint16 `json:"local_port"`
	RemoteAddr        string `json:"remote_addr"`
	RemotePort        uint16 `json:"remote_port"`
	State             string `json:"state,omitempty"`
	EventType         string `json:"event_type"`
	FirstSeenUTC      string `json:"first_seen_utc"`
	LastSeenUTC       string `json:"last_seen_utc"`
	BytesSent         uint64 `json:"bytes_sent"`
	BytesRecv         uint64 `json:"bytes_recv"`
	Occurrences       uint64 `json:"occurrences"`
	Source            string `json:"source"`
	Detail            string `json:"detail,omitempty"`
}

type dnsRow struct {
	DNSID             int64    `json:"dns_id"`
	SessionID         int64    `json:"session_id"`
	ProcessInstanceID int64    `json:"process_instance_id"`
	PID               uint32   `json:"pid"`
	ExeName           string   `json:"exe_name,omitempty"`
	QueryName         string   `json:"query_name"`
	QueryType         uint16   `json:"query_type"`
	QueryTypeName     string   `json:"query_type_name"`
	Status            uint32   `json:"status"`
	StatusText        string   `json:"status_text"`
	Answers           []string `json:"answers,omitempty"`
	Attributed        bool     `json:"attributed"`
	Attribution       string   `json:"attribution"`
	FirstSeenUTC      string   `json:"first_seen_utc"`
	LastSeenUTC       string   `json:"last_seen_utc"`
	Occurrences       uint64   `json:"occurrences"`
	Source            string   `json:"source"`
	Raw               string   `json:"raw,omitempty"`
}

func sessionToRow(s model.MonitorSession) sessionRow {
	var sources []string
	_ = json.Unmarshal([]byte(s.SourcesJSON), &sources)
	return sessionRow{
		SessionID: s.ID, TargetInput: s.TargetInput, TargetPath: s.TargetPath,
		TargetName: s.TargetName, MatchKind: string(s.MatchKind),
		StartedUTC: timeutil.UTCString(s.StartedUTC), EndedUTC: utcPtr(s.EndedUTC),
		Status: s.Status, CaptureNote: s.CaptureNote, ETWEnabled: s.ETWEnabled,
		ETWState: s.ETWState(), Sources: sources, Host: s.Host, Username: s.Username,
		OSVersion: s.OSVersion, AppVersion: s.AppVersion,
	}
}

func processToRow(p model.ProcessInstance) processRow {
	return processRow{
		ProcessInstanceID: p.ID, SessionID: p.SessionID, PID: p.PID, ParentPID: p.ParentPID,
		ExeName: p.ExeName, ExePath: p.ExePath,
		StartedUTC: timeutil.UTCString(p.StartedUTC), DetectedUTC: timeutil.UTCString(p.DetectedUTC),
		EndedUTC: utcPtr(p.EndedUTC), ExitCode: p.ExitCode,
		AlreadyRunning: p.AlreadyRunning, CaptureState: p.CaptureState,
		MatchNote: p.MatchNote, Source: p.Source,
	}
}

func connToRow(c model.ConnectionEvent) connRow {
	return connRow{
		ConnectionID: c.ID, SessionID: c.SessionID, ProcessInstanceID: c.ProcessInstanceID,
		PID: c.PID, ExeName: c.ExeName, Proto: c.Proto, IPVersion: c.IPVersion,
		LocalAddr: c.LocalAddr, LocalPort: c.LocalPort,
		RemoteAddr: c.RemoteAddr, RemotePort: c.RemotePort,
		State: c.State, EventType: c.EventType,
		FirstSeenUTC: timeutil.UTCString(c.FirstSeenUTC), LastSeenUTC: timeutil.UTCString(c.LastSeenUTC),
		BytesSent: c.BytesSent, BytesRecv: c.BytesRecv, Occurrences: c.Occurrences,
		Source: c.Source, Detail: c.Detail,
	}
}

func dnsToRow(q model.DNSQuery) dnsRow {
	return dnsRow{
		DNSID: q.ID, SessionID: q.SessionID, ProcessInstanceID: q.ProcessInstanceID,
		PID: q.PID, ExeName: q.ExeName, QueryName: q.QueryName,
		QueryType: q.QueryType, QueryTypeName: q.QueryTypeName,
		Status: q.Status, StatusText: q.StatusText, Answers: q.Answers,
		Attributed: q.Attributed, Attribution: q.Attribution,
		FirstSeenUTC: timeutil.UTCString(q.FirstSeenUTC), LastSeenUTC: timeutil.UTCString(q.LastSeenUTC),
		Occurrences: q.Occurrences, Source: q.Source, Raw: q.Raw,
	}
}
