package storage

import (
	"strings"
	"time"

	"nettrace/internal/timeutil"
)

const connectionUpsertSQL = `INSERT INTO connection_events(
		session_id, process_instance_id, pid, exe_name, proto, ip_version,
		local_addr, local_port, remote_addr, remote_port, state, event_type,
		first_seen_utc, last_seen_utc, bytes_sent, bytes_recv, occurrences,
		source, detail, dedup_key)
	VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)
	ON CONFLICT(dedup_key) DO UPDATE SET
		last_seen_utc=excluded.last_seen_utc,
		first_seen_utc=MIN(connection_events.first_seen_utc, excluded.first_seen_utc),
		bytes_sent=connection_events.bytes_sent+excluded.bytes_sent,
		bytes_recv=connection_events.bytes_recv+excluded.bytes_recv,
		occurrences=connection_events.occurrences+1,
		state=excluded.state,
		detail=excluded.detail,
		source=excluded.source,
		exe_name=CASE WHEN connection_events.exe_name='' THEN excluded.exe_name ELSE connection_events.exe_name END,
		process_instance_id=CASE WHEN connection_events.process_instance_id=0 THEN excluded.process_instance_id ELSE connection_events.process_instance_id END`

const dnsUpsertSQL = `INSERT INTO dns_queries(
		session_id, process_instance_id, pid, exe_name,
		query_name, query_type, query_type_name, status, status_text, answers,
		attributed, attribution, first_seen_utc, last_seen_utc, occurrences,
		source, raw, dedup_key)
	VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)
	ON CONFLICT(dedup_key) DO UPDATE SET
		last_seen_utc=excluded.last_seen_utc,
		first_seen_utc=MIN(dns_queries.first_seen_utc, excluded.first_seen_utc),
		occurrences=dns_queries.occurrences+1,
		status=excluded.status,
		status_text=excluded.status_text,
		answers=excluded.answers,
		raw=excluded.raw,
		process_instance_id=CASE WHEN dns_queries.process_instance_id=0 THEN excluded.process_instance_id ELSE dns_queries.process_instance_id END`

func utcString(t time.Time) string { return timeutil.UTCString(t) }

func joinAnswers(a []string) string { return strings.Join(a, ",") }
