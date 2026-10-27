// Package history implements read-only queries with the filters exposed by the
// history and export commands.
package history

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"nettrace/internal/model"
	"nettrace/internal/timeutil"
)

// Filter selects the rows returned by Query. Zero values mean "no filter".
type Filter struct {
	SessionID int64
	Exe       string
	PID       uint32
	Since     time.Time
	Until     time.Time
	IP        string
	Port      uint16
	Proto     string
	Domain    string
	Event     string
	Limit     int
}

// Result contains every table touched by a query.
type Result struct {
	Sessions    []model.MonitorSession
	Processes   []model.ProcessInstance
	Connections []model.ConnectionEvent
	DNS         []model.DNSQuery
}

// Query runs the filters against the database.
func Query(ctx context.Context, db *sql.DB, f Filter) (*Result, error) {
	res := &Result{}
	var err error
	if res.Sessions, err = querySessions(ctx, db, f); err != nil {
		return nil, err
	}
	if res.Processes, err = queryProcesses(ctx, db, f); err != nil {
		return nil, err
	}
	if res.Connections, err = queryConnections(ctx, db, f); err != nil {
		return nil, err
	}
	if res.DNS, err = queryDNS(ctx, db, f); err != nil {
		return nil, err
	}
	return res, nil
}

type whereBuilder struct {
	conds  []string
	args   []any
	limitN int
}

func (w *whereBuilder) add(cond string, args ...any) {
	w.conds = append(w.conds, cond)
	w.args = append(w.args, args...)
}

func (w *whereBuilder) sql() string {
	if len(w.conds) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(w.conds, " AND ")
}

func (w *whereBuilder) limit() string {
	if w.limitN > 0 {
		return fmt.Sprintf(" LIMIT %d", w.limitN)
	}
	return ""
}

// limitN is kept outside add() because LIMIT cannot be parameterized safely in
// a shared clause list.
func (w *whereBuilder) setLimit(n int) { w.limitN = n }

func exeCond(w *whereBuilder, f Filter, directPath bool) {
	exe := strings.TrimSpace(f.Exe)
	if exe == "" {
		return
	}
	if !strings.ContainsAny(exe, `\/`) {
		w.add("lower(exe_name) = lower(?)", exe)
		return
	}
	// A directory-qualified value matches the stored image path exactly or as
	// a suffix (so "\Games\game.exe" works without a drive letter). Matching
	// only the base name here would make C:\Other\game.exe match C:\Games\game.exe.
	suffix := "%" + escapeLike(exe)
	pathCond := "(lower(exe_path) = lower(?) OR lower(exe_path) LIKE lower(?) ESCAPE '\\')"
	if directPath {
		w.add(pathCond, exe, suffix)
		return
	}
	// Connection and DNS rows do not store the image path; resolve it through
	// the owning process instance so --exe still accepts a full path.
	w.add("process_instance_id IN (SELECT id FROM process_instances WHERE "+pathCond+")", exe, suffix)
}

// baseName returns the last path component, accepting both Windows and Unix
// separators so the same filter works regardless of how the path was typed.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// escapeLike escapes LIKE metacharacters so a literal file name or path is
// matched (patterns use ESCAPE '\').
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func timeCond(w *whereBuilder, column string, since, until time.Time) {
	if !since.IsZero() {
		w.add(column+" >= ?", timeutil.UTCString(since))
	}
	if !until.IsZero() {
		w.add(column+" <= ?", timeutil.UTCString(until))
	}
}

func sessionCond(w *whereBuilder, id int64) {
	if id > 0 {
		w.add("session_id = ?", id)
	}
}

func querySessions(ctx context.Context, db *sql.DB, f Filter) ([]model.MonitorSession, error) {
	var w whereBuilder
	w.setLimit(f.Limit)
	if f.SessionID > 0 {
		w.add("id = ?", f.SessionID)
	}
	if strings.TrimSpace(f.Exe) != "" {
		exe := strings.TrimSpace(f.Exe)
		if strings.ContainsAny(exe, `\/`) {
			suffix := "%" + escapeLike(exe)
			w.add("(lower(target_name) = lower(?) OR lower(target_path) = lower(?) OR "+
				"lower(target_path) LIKE lower(?) ESCAPE '\\')", baseName(exe), exe, suffix)
		} else {
			w.add("lower(target_name) = lower(?)", exe)
		}
	}
	timeCond(&w, "started_utc", f.Since, f.Until)
	rows, err := db.QueryContext(ctx, `SELECT id, target_input, target_path, target_name, match_kind,
			started_utc, ended_utc, status, capture_note, etw_enabled, sources_json,
			host, username, os_version, app_version
		FROM monitor_sessions`+w.sql()+` ORDER BY id DESC`+w.limit(), w.args...)
	if err != nil {
		return nil, fmt.Errorf("query sessions: %w", err)
	}
	defer rows.Close()
	var out []model.MonitorSession
	for rows.Next() {
		s, err := scanSessionRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

func queryProcesses(ctx context.Context, db *sql.DB, f Filter) ([]model.ProcessInstance, error) {
	var w whereBuilder
	w.setLimit(f.Limit)
	sessionCond(&w, f.SessionID)
	exeCond(&w, f, true)
	if f.PID != 0 {
		w.add("pid = ?", f.PID)
	}
	timeCond(&w, "started_utc", f.Since, f.Until)
	rows, err := db.QueryContext(ctx, `SELECT id, session_id, pid, parent_pid, exe_name, exe_path,
			started_utc, detected_utc, ended_utc, exit_code, already_running,
			capture_state, match_note, source
		FROM process_instances`+w.sql()+` ORDER BY started_utc, id`+w.limit(), w.args...)
	if err != nil {
		return nil, fmt.Errorf("query processes: %w", err)
	}
	defer rows.Close()
	var out []model.ProcessInstance
	for rows.Next() {
		var (
			p        model.ProcessInstance
			started  string
			detected string
			ended    string
			exitCode sql.NullInt64
			already  int
		)
		if err := rows.Scan(&p.ID, &p.SessionID, &p.PID, &p.ParentPID, &p.ExeName, &p.ExePath,
			&started, &detected, &ended, &exitCode, &already,
			&p.CaptureState, &p.MatchNote, &p.Source); err != nil {
			return nil, err
		}
		p.AlreadyRunning = already != 0
		if p.StartedUTC, err = timeutil.ParseDB(started); err != nil {
			return nil, err
		}
		if p.DetectedUTC, err = timeutil.ParseDB(detected); err != nil {
			return nil, err
		}
		if p.EndedUTC, err = timeutil.ParseDB(ended); err != nil {
			return nil, err
		}
		if exitCode.Valid {
			v := uint32(exitCode.Int64)
			p.ExitCode = &v
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func queryConnections(ctx context.Context, db *sql.DB, f Filter) ([]model.ConnectionEvent, error) {
	var w whereBuilder
	w.setLimit(f.Limit)
	sessionCond(&w, f.SessionID)
	exeCond(&w, f, false)
	if f.PID != 0 {
		w.add("pid = ?", f.PID)
	}
	timeCond(&w, "first_seen_utc", f.Since, f.Until)
	if ip := strings.TrimSpace(f.IP); ip != "" {
		w.add("(local_addr = ? OR remote_addr = ?)", ip, ip)
	}
	if f.Port != 0 {
		w.add("(local_port = ? OR remote_port = ?)", f.Port, f.Port)
	}
	if proto := strings.ToLower(strings.TrimSpace(f.Proto)); proto != "" {
		w.add("proto = ?", proto)
	}
	if ev := strings.TrimSpace(f.Event); ev != "" {
		w.add("event_type = ?", ev)
	}
	rows, err := db.QueryContext(ctx, `SELECT id, session_id, process_instance_id, pid, exe_name,
			proto, ip_version, local_addr, local_port, remote_addr, remote_port,
			state, event_type, first_seen_utc, last_seen_utc,
			bytes_sent, bytes_recv, occurrences, source, detail, dedup_key
		FROM connection_events`+w.sql()+` ORDER BY first_seen_utc, id`+w.limit(), w.args...)
	if err != nil {
		return nil, fmt.Errorf("query connections: %w", err)
	}
	defer rows.Close()
	var out []model.ConnectionEvent
	for rows.Next() {
		var (
			e          model.ConnectionEvent
			first      string
			last       string
			localPort  int64
			remotePort int64
		)
		if err := rows.Scan(&e.ID, &e.SessionID, &e.ProcessInstanceID, &e.PID, &e.ExeName,
			&e.Proto, &e.IPVersion, &e.LocalAddr, &localPort, &e.RemoteAddr, &remotePort,
			&e.State, &e.EventType, &first, &last,
			&e.BytesSent, &e.BytesRecv, &e.Occurrences, &e.Source, &e.Detail, &e.DedupKey); err != nil {
			return nil, err
		}
		e.LocalPort = uint16(localPort)
		e.RemotePort = uint16(remotePort)
		if e.FirstSeenUTC, err = timeutil.ParseDB(first); err != nil {
			return nil, err
		}
		if e.LastSeenUTC, err = timeutil.ParseDB(last); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func queryDNS(ctx context.Context, db *sql.DB, f Filter) ([]model.DNSQuery, error) {
	var w whereBuilder
	w.setLimit(f.Limit)
	sessionCond(&w, f.SessionID)
	exeCond(&w, f, false)
	if f.PID != 0 {
		w.add("pid = ?", f.PID)
	}
	timeCond(&w, "first_seen_utc", f.Since, f.Until)
	if domain := strings.TrimSpace(f.Domain); domain != "" {
		// Suffix match so "example.com" also finds "api.example.com".
		w.add("(lower(query_name) = lower(?) OR lower(query_name) LIKE lower(?) ESCAPE '\\')",
			domain, "%."+escapeLike(domain))
	}
	rows, err := db.QueryContext(ctx, `SELECT id, session_id, process_instance_id, pid, exe_name,
			query_name, query_type, query_type_name, status, status_text, answers,
			attributed, attribution, first_seen_utc, last_seen_utc,
			occurrences, source, raw, dedup_key
		FROM dns_queries`+w.sql()+` ORDER BY first_seen_utc, id`+w.limit(), w.args...)
	if err != nil {
		return nil, fmt.Errorf("query dns: %w", err)
	}
	defer rows.Close()
	var out []model.DNSQuery
	for rows.Next() {
		var (
			q       model.DNSQuery
			first   string
			last    string
			answers string
			attr    int
		)
		if err := rows.Scan(&q.ID, &q.SessionID, &q.ProcessInstanceID, &q.PID, &q.ExeName,
			&q.QueryName, &q.QueryType, &q.QueryTypeName, &q.Status, &q.StatusText, &answers,
			&attr, &q.Attribution, &first, &last,
			&q.Occurrences, &q.Source, &q.Raw, &q.DedupKey); err != nil {
			return nil, err
		}
		q.Attributed = attr != 0
		if answers != "" {
			q.Answers = strings.Split(answers, ",")
		}
		if q.FirstSeenUTC, err = timeutil.ParseDB(first); err != nil {
			return nil, err
		}
		if q.LastSeenUTC, err = timeutil.ParseDB(last); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

func scanSessionRow(rows *sql.Rows) (*model.MonitorSession, error) {
	var (
		s          model.MonitorSession
		started    string
		ended      string
		matchKind  string
		etwEnabled int
	)
	if err := rows.Scan(&s.ID, &s.TargetInput, &s.TargetPath, &s.TargetName, &matchKind,
		&started, &ended, &s.Status, &s.CaptureNote, &etwEnabled, &s.SourcesJSON,
		&s.Host, &s.Username, &s.OSVersion, &s.AppVersion); err != nil {
		return nil, err
	}
	s.MatchKind = model.MatchKind(matchKind)
	s.ETWEnabled = etwEnabled != 0
	var err error
	if s.StartedUTC, err = timeutil.ParseDB(started); err != nil {
		return nil, err
	}
	if s.EndedUTC, err = timeutil.ParseDB(ended); err != nil {
		return nil, err
	}
	return &s, nil
}
