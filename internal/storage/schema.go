package storage

import (
	"database/sql"
	"fmt"
	"time"
)

// migration is one forward-only schema step.
type migration struct {
	version    int
	statements []string
}

// schemaVersion is the newest migration known to this binary.
const schemaVersion = 1

var migrations = []migration{
	{
		version: 1,
		statements: []string{
			`CREATE TABLE IF NOT EXISTS settings (
				key         TEXT PRIMARY KEY,
				value       TEXT NOT NULL,
				updated_utc TEXT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS monitor_sessions (
				id            INTEGER PRIMARY KEY AUTOINCREMENT,
				target_input  TEXT NOT NULL,
				target_path   TEXT NOT NULL DEFAULT '',
				target_name   TEXT NOT NULL DEFAULT '',
				match_kind    TEXT NOT NULL,
				started_utc   TEXT NOT NULL,
				ended_utc     TEXT NOT NULL DEFAULT '',
				status        TEXT NOT NULL,
				capture_note  TEXT NOT NULL DEFAULT '',
				etw_enabled   INTEGER NOT NULL DEFAULT 0,
				sources_json  TEXT NOT NULL DEFAULT '[]',
				host          TEXT NOT NULL DEFAULT '',
				username      TEXT NOT NULL DEFAULT '',
				os_version    TEXT NOT NULL DEFAULT '',
				app_version   TEXT NOT NULL DEFAULT ''
			)`,
			`CREATE TABLE IF NOT EXISTS process_instances (
				id              INTEGER PRIMARY KEY AUTOINCREMENT,
				session_id      INTEGER NOT NULL REFERENCES monitor_sessions(id) ON DELETE CASCADE,
				pid             INTEGER NOT NULL,
				parent_pid      INTEGER NOT NULL DEFAULT 0,
				exe_name        TEXT NOT NULL DEFAULT '',
				exe_path        TEXT NOT NULL DEFAULT '',
				started_utc     TEXT NOT NULL,
				detected_utc    TEXT NOT NULL,
				ended_utc       TEXT NOT NULL DEFAULT '',
				exit_code       INTEGER,
				already_running INTEGER NOT NULL DEFAULT 0,
				capture_state   TEXT NOT NULL,
				match_note      TEXT NOT NULL DEFAULT '',
				source          TEXT NOT NULL,
				UNIQUE(session_id, pid, started_utc)
			)`,
			`CREATE TABLE IF NOT EXISTS connection_events (
				id                  INTEGER PRIMARY KEY AUTOINCREMENT,
				session_id          INTEGER NOT NULL REFERENCES monitor_sessions(id) ON DELETE CASCADE,
				process_instance_id INTEGER NOT NULL DEFAULT 0,
				pid                 INTEGER NOT NULL,
				exe_name            TEXT NOT NULL DEFAULT '',
				proto               TEXT NOT NULL,
				ip_version          INTEGER NOT NULL,
				local_addr          TEXT NOT NULL,
				local_port          INTEGER NOT NULL,
				remote_addr         TEXT NOT NULL,
				remote_port         INTEGER NOT NULL,
				state               TEXT NOT NULL DEFAULT '',
				event_type          TEXT NOT NULL,
				first_seen_utc      TEXT NOT NULL,
				last_seen_utc       TEXT NOT NULL,
				bytes_sent          INTEGER NOT NULL DEFAULT 0,
				bytes_recv          INTEGER NOT NULL DEFAULT 0,
				occurrences         INTEGER NOT NULL DEFAULT 1,
				source              TEXT NOT NULL,
				detail              TEXT NOT NULL DEFAULT '',
				dedup_key           TEXT NOT NULL UNIQUE
			)`,
			`CREATE TABLE IF NOT EXISTS dns_queries (
				id                  INTEGER PRIMARY KEY AUTOINCREMENT,
				session_id          INTEGER NOT NULL REFERENCES monitor_sessions(id) ON DELETE CASCADE,
				process_instance_id INTEGER NOT NULL DEFAULT 0,
				pid                 INTEGER NOT NULL DEFAULT 0,
				exe_name            TEXT NOT NULL DEFAULT '',
				query_name          TEXT NOT NULL,
				query_type          INTEGER NOT NULL DEFAULT 0,
				query_type_name     TEXT NOT NULL DEFAULT '',
				status              INTEGER NOT NULL DEFAULT 0,
				status_text         TEXT NOT NULL DEFAULT '',
				answers             TEXT NOT NULL DEFAULT '',
				attributed          INTEGER NOT NULL DEFAULT 0,
				attribution         TEXT NOT NULL DEFAULT '',
				first_seen_utc      TEXT NOT NULL,
				last_seen_utc       TEXT NOT NULL,
				occurrences         INTEGER NOT NULL DEFAULT 1,
				source              TEXT NOT NULL,
				raw                 TEXT NOT NULL DEFAULT '',
				dedup_key           TEXT NOT NULL UNIQUE
			)`,
			`CREATE TABLE IF NOT EXISTS source_status (
				id          INTEGER PRIMARY KEY AUTOINCREMENT,
				session_id  INTEGER NOT NULL REFERENCES monitor_sessions(id) ON DELETE CASCADE,
				source      TEXT NOT NULL,
				state       TEXT NOT NULL,
				detail      TEXT NOT NULL DEFAULT '',
				updated_utc TEXT NOT NULL,
				UNIQUE(session_id, source)
			)`,
			`CREATE INDEX IF NOT EXISTS idx_conn_session_time ON connection_events(session_id, first_seen_utc)`,
			`CREATE INDEX IF NOT EXISTS idx_conn_pid ON connection_events(session_id, pid)`,
			`CREATE INDEX IF NOT EXISTS idx_conn_remote ON connection_events(remote_addr, remote_port)`,
			`CREATE INDEX IF NOT EXISTS idx_conn_proto ON connection_events(proto)`,
			`CREATE INDEX IF NOT EXISTS idx_dns_name ON dns_queries(query_name)`,
			`CREATE INDEX IF NOT EXISTS idx_dns_session_time ON dns_queries(session_id, first_seen_utc)`,
			`CREATE INDEX IF NOT EXISTS idx_proc_session_pid ON process_instances(session_id, pid)`,
			`CREATE INDEX IF NOT EXISTS idx_sessions_started ON monitor_sessions(started_utc)`,
		},
	},
}

func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version     INTEGER PRIMARY KEY,
		applied_utc TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	var current int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if current > schemaVersion {
		return fmt.Errorf("database schema version %d is newer than this binary (%d)", current, schemaVersion)
	}

	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", m.version, err)
		}
		for _, stmt := range m.statements {
			if _, err := tx.Exec(stmt); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("migration %d: %w", m.version, err)
			}
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_utc) VALUES(?, ?)`,
			m.version, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", m.version, err)
		}
	}
	return nil
}
