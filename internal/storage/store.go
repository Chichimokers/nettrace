// Package storage owns the SQLite database: schema migrations, inserts and
// the asynchronous, non-blocking write pipeline used while monitoring.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"nettrace/internal/model"
	"nettrace/internal/timeutil"
)

// Store is a handle to the NetTrace SQLite database.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens (and creates if needed) the database at path, applies migrations
// and records basic metadata.
func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("empty database path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	dsn := abs + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite database: %w", err)
	}
	s := &Store{db: db, path: abs}
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.putSetting("db_created_utc", time.Now().UTC().Format(time.RFC3339Nano), false); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.putSetting("app_version", model.Version, true); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) putSetting(key, value string, overwrite bool) error {
	sqlText := `INSERT INTO settings(key, value, updated_utc) VALUES(?, ?, ?)
		ON CONFLICT(key) DO NOTHING`
	if overwrite {
		sqlText = `INSERT INTO settings(key, value, updated_utc) VALUES(?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_utc=excluded.updated_utc`
	}
	_, err := s.db.Exec(sqlText, key, value, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// DB exposes the raw handle for read-only queries in the history package.
func (s *Store) DB() *sql.DB { return s.db }

// Path returns the absolute database path.
func (s *Store) Path() string { return s.path }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// CreateSession inserts a monitoring session and returns its ID.
func (s *Store) CreateSession(st model.SessionStart) (int64, error) {
	sources := st.Sources
	if sources == nil {
		sources = []string{}
	}
	sourcesJSON, err := json.Marshal(sources)
	if err != nil {
		return 0, err
	}
	res, err := s.db.Exec(`INSERT INTO monitor_sessions(
			target_input, target_path, target_name, match_kind,
			started_utc, status, capture_note, etw_enabled, sources_json,
			host, username, os_version, app_version)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		st.Target.Input, st.Target.Path, st.Target.Name, string(st.Target.Kind),
		timeutil.UTCString(st.StartedUTC), "running", st.CaptureNote, boolInt(st.ETWEnabled),
		string(sourcesJSON), st.Host, st.Username, st.OSVersion, st.AppVersion)
	if err != nil {
		return 0, fmt.Errorf("insert monitoring session: %w", err)
	}
	return res.LastInsertId()
}

// UpdateSessionRuntime records the sources that actually worked and the final
// capture notes after the collector stopped.
func (s *Store) UpdateSessionRuntime(id int64, etwEnabled bool, note string, sources []string) error {
	sourcesJSON, err := json.Marshal(sources)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE monitor_sessions
		SET etw_enabled=?, capture_note=?, sources_json=?
		WHERE id=?`,
		boolInt(etwEnabled), note, string(sourcesJSON), id)
	if err != nil {
		return fmt.Errorf("update session runtime: %w", err)
	}
	return nil
}

// FinishSession closes a monitoring session.
func (s *Store) FinishSession(id int64, ended time.Time, status, note string, sources []string) error {
	sourcesJSON, err := json.Marshal(sources)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE monitor_sessions
		SET ended_utc=?, status=?, capture_note=?, sources_json=?
		WHERE id=?`,
		timeutil.UTCString(ended), status, note, string(sourcesJSON), id)
	if err != nil {
		return fmt.Errorf("finish monitoring session %d: %w", id, err)
	}
	return nil
}

// InsertProcess records a process instance. It is called synchronously from the
// ingest goroutine (never from the ETW callback thread).
func (s *Store) InsertProcess(p *model.ProcessInstance) (int64, error) {
	if p.StartedUTC.IsZero() {
		p.StartedUTC = p.DetectedUTC
	}
	res, err := s.db.Exec(`INSERT INTO process_instances(
			session_id, pid, parent_pid, exe_name, exe_path,
			started_utc, detected_utc, already_running, capture_state, match_note, source)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(session_id, pid, started_utc) DO NOTHING`,
		p.SessionID, p.PID, p.ParentPID, p.ExeName, p.ExePath,
		timeutil.UTCString(p.StartedUTC), timeutil.UTCString(p.DetectedUTC),
		boolInt(p.AlreadyRunning), p.CaptureState, p.MatchNote, p.Source)
	if err != nil {
		return 0, fmt.Errorf("insert process instance: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		id, err := res.LastInsertId()
		if err != nil {
			return 0, err
		}
		p.ID = id
		return id, nil
	}
	var id int64
	err = s.db.QueryRow(`SELECT id FROM process_instances
		WHERE session_id=? AND pid=? AND started_utc=?`,
		p.SessionID, p.PID, timeutil.UTCString(p.StartedUTC)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("lookup existing process instance: %w", err)
	}
	p.ID = id
	return id, nil
}

// EndProcess records the end of a process instance.
func (s *Store) EndProcess(pe model.ProcessEnd) error {
	var exit any
	if pe.ExitCode != nil {
		exit = int64(*pe.ExitCode)
	}
	_, err := s.db.Exec(`UPDATE process_instances
		SET ended_utc=?, exit_code=COALESCE(?, exit_code)
		WHERE id=? AND (ended_utc='' OR ended_utc < ?)`,
		timeutil.UTCString(pe.EndedUTC), exit, pe.InstanceID, timeutil.UTCString(pe.EndedUTC))
	if err != nil {
		return fmt.Errorf("end process instance %d: %w", pe.InstanceID, err)
	}
	return nil
}

// UpsertConnection inserts or aggregates one connection observation.
func (s *Store) UpsertConnection(e *model.ConnectionEvent) error {
	if e.DedupKey == "" {
		e.ComputeDedupKey()
	}
	_, err := s.db.Exec(connectionUpsertSQL,
		e.SessionID, e.ProcessInstanceID, int64(e.PID), e.ExeName, e.Proto, e.IPVersion,
		e.LocalAddr, int64(e.LocalPort), e.RemoteAddr, int64(e.RemotePort),
		e.State, e.EventType,
		timeutil.UTCString(e.FirstSeenUTC), timeutil.UTCString(e.LastSeenUTC),
		int64(e.BytesSent), int64(e.BytesRecv),
		e.Source, e.Detail, e.DedupKey)
	if err != nil {
		return fmt.Errorf("upsert connection: %w", err)
	}
	return nil
}

// UpsertDNS inserts or aggregates one completed DNS query.
func (s *Store) UpsertDNS(q *model.DNSQuery) error {
	if q.DedupKey == "" {
		q.ComputeDedupKey()
	}
	_, err := s.db.Exec(dnsUpsertSQL,
		q.SessionID, q.ProcessInstanceID, int64(q.PID), q.ExeName,
		q.QueryName, int64(q.QueryType), q.QueryTypeName, int64(q.Status), q.StatusText,
		strings.Join(q.Answers, ","),
		boolInt(q.Attributed), q.Attribution,
		timeutil.UTCString(q.FirstSeenUTC), timeutil.UTCString(q.LastSeenUTC),
		q.Source, q.Raw, q.DedupKey)
	if err != nil {
		return fmt.Errorf("upsert dns query: %w", err)
	}
	return nil
}

// SetSourceStatus upserts a health row for a source.
func (s *Store) SetSourceStatus(st model.SourceStatus) error {
	_, err := s.db.Exec(`INSERT INTO source_status(session_id, source, state, detail, updated_utc)
		VALUES(?,?,?,?,?)
		ON CONFLICT(session_id, source) DO UPDATE SET
			state=excluded.state, detail=excluded.detail, updated_utc=excluded.updated_utc`,
		st.SessionID, st.Source, st.State, st.Detail, timeutil.UTCString(st.UpdatedUTC))
	if err != nil {
		return fmt.Errorf("set source status: %w", err)
	}
	return nil
}

// Counts summarizes the database for the status command.
type Counts struct {
	Sessions    int64
	Processes   int64
	Connections int64
	DNS         int64
	Schema      int
}

// Counts returns database-wide row counts.
func (s *Store) Counts() (Counts, error) {
	var c Counts
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM monitor_sessions`).Scan(&c.Sessions); err != nil {
		return c, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM process_instances`).Scan(&c.Processes); err != nil {
		return c, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM connection_events`).Scan(&c.Connections); err != nil {
		return c, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM dns_queries`).Scan(&c.DNS); err != nil {
		return c, err
	}
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&c.Schema); err != nil {
		return c, err
	}
	return c, nil
}

// SessionCounts summarizes one monitoring session.
type SessionCounts struct {
	Processes   int64
	Connections int64
	DNS         int64
}

// CountsForSession returns the row counts produced by one session.
func (s *Store) CountsForSession(sessionID int64) (SessionCounts, error) {
	var c SessionCounts
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM process_instances WHERE session_id=?`, sessionID).Scan(&c.Processes); err != nil {
		return c, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM connection_events WHERE session_id=?`, sessionID).Scan(&c.Connections); err != nil {
		return c, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM dns_queries WHERE session_id=?`, sessionID).Scan(&c.DNS); err != nil {
		return c, err
	}
	return c, nil
}

// LatestSession returns the most recent session, if any.
func (s *Store) LatestSession() (*model.MonitorSession, error) {
	row := s.db.QueryRow(`SELECT id, target_input, target_path, target_name, match_kind,
			started_utc, ended_utc, status, capture_note, etw_enabled, sources_json,
			host, username, os_version, app_version
		FROM monitor_sessions ORDER BY id DESC LIMIT 1`)
	return scanSession(row)
}

// SessionByID returns one session.
func (s *Store) SessionByID(id int64) (*model.MonitorSession, error) {
	row := s.db.QueryRow(`SELECT id, target_input, target_path, target_name, match_kind,
			started_utc, ended_utc, status, capture_note, etw_enabled, sources_json,
			host, username, os_version, app_version
		FROM monitor_sessions WHERE id=?`, id)
	return scanSession(row)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSession(r rowScanner) (*model.MonitorSession, error) {
	var (
		s          model.MonitorSession
		started    string
		ended      string
		matchKind  string
		etwEnabled int
	)
	if err := r.Scan(&s.ID, &s.TargetInput, &s.TargetPath, &s.TargetName, &matchKind,
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

// SourceStatuses returns the recorded health of every source of a session.
func (s *Store) SourceStatuses(sessionID int64) ([]model.SourceStatus, error) {
	rows, err := s.db.Query(`SELECT source, state, detail, updated_utc
		FROM source_status WHERE session_id=? ORDER BY source`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SourceStatus
	for rows.Next() {
		var (
			st      model.SourceStatus
			updated string
		)
		st.SessionID = sessionID
		if err := rows.Scan(&st.Source, &st.State, &st.Detail, &updated); err != nil {
			return nil, err
		}
		if st.UpdatedUTC, err = timeutil.ParseDB(updated); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// Ping verifies the database is usable.
func (s *Store) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.db.PingContext(ctx)
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
