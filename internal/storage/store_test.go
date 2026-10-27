package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"nettrace/internal/history"
	"nettrace/internal/model"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "nettrace-test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newTestSession(t *testing.T, s *Store) int64 {
	t.Helper()
	id, err := s.CreateSession(model.SessionStart{
		Target:      model.NewTargetName("game.exe", "game.exe"),
		StartedUTC:  time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC),
		CaptureNote: "test",
		Host:        "testhost",
		Username:    `TEST\user`,
		OSVersion:   "Windows test",
		AppVersion:  model.Version,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return id
}

func TestConnectionUpsertAggregates(t *testing.T) {
	s := newTestStore(t)
	sessionID := newTestSession(t, s)
	t0 := time.Date(2026, 10, 26, 8, 0, 1, 0, time.UTC)

	inst := &model.ProcessInstance{
		SessionID: sessionID, PID: 4242, ParentPID: 1,
		ExeName: "game.exe", ExePath: `C:\Games\game.exe`,
		StartedUTC: t0, DetectedUTC: t0,
		CaptureState: "captured_from_start", Source: "test",
	}
	if _, err := s.InsertProcess(inst); err != nil {
		t.Fatalf("InsertProcess: %v", err)
	}
	if inst.ID == 0 {
		t.Fatal("InsertProcess did not set the instance ID")
	}

	makeEvent := func(at time.Time, sent uint64) *model.ConnectionEvent {
		e := &model.ConnectionEvent{
			SessionID: sessionID, ProcessInstanceID: inst.ID, PID: 4242,
			ExeName: "game.exe", Proto: "tcp", IPVersion: 4,
			LocalAddr: "10.0.0.5", LocalPort: 50000,
			RemoteAddr: "1.1.1.1", RemotePort: 443,
			State: "established", EventType: "observed",
			FirstSeenUTC: at, LastSeenUTC: at, BytesSent: sent,
			Source: model.SourceIPHelper,
		}
		e.ComputeDedupKey()
		return e
	}
	if err := s.UpsertConnection(makeEvent(t0, 100)); err != nil {
		t.Fatalf("UpsertConnection: %v", err)
	}
	if err := s.UpsertConnection(makeEvent(t0.Add(2*time.Second), 50)); err != nil {
		t.Fatalf("UpsertConnection (second): %v", err)
	}

	res, err := history.Query(context.Background(), s.DB(), history.Filter{SessionID: sessionID})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res.Connections) != 1 {
		t.Fatalf("connections = %d rows; want 1 aggregated row", len(res.Connections))
	}
	c := res.Connections[0]
	if c.Occurrences != 2 {
		t.Errorf("occurrences = %d; want 2", c.Occurrences)
	}
	if c.BytesSent != 150 {
		t.Errorf("bytes sent = %d; want 150", c.BytesSent)
	}
	if !c.FirstSeenUTC.Equal(t0) {
		t.Errorf("first seen = %s; want %s", c.FirstSeenUTC, t0)
	}
	if !c.LastSeenUTC.Equal(t0.Add(2 * time.Second)) {
		t.Errorf("last seen = %s; want %s", c.LastSeenUTC, t0.Add(2*time.Second))
	}
	if c.ProcessInstanceID != inst.ID || c.ExeName != "game.exe" {
		t.Errorf("instance/exe = %d/%q", c.ProcessInstanceID, c.ExeName)
	}
}

func TestProcessInsertIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	sessionID := newTestSession(t, s)
	start := time.Date(2026, 10, 26, 8, 0, 1, 0, time.UTC)

	a := &model.ProcessInstance{SessionID: sessionID, PID: 10, ExeName: "game.exe",
		StartedUTC: start, DetectedUTC: start, CaptureState: "captured_from_start", Source: "test"}
	firstID, err := s.InsertProcess(a)
	if err != nil {
		t.Fatalf("first InsertProcess: %v", err)
	}
	b := &model.ProcessInstance{SessionID: sessionID, PID: 10, ExeName: "game.exe",
		StartedUTC: start, DetectedUTC: start.Add(time.Second), CaptureState: "captured_from_start", Source: "test"}
	secondID, err := s.InsertProcess(b)
	if err != nil {
		t.Fatalf("second InsertProcess: %v", err)
	}
	if firstID != secondID {
		t.Errorf("duplicate process inserted: %d vs %d", firstID, secondID)
	}

	var n int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM process_instances`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("process rows = %d; want 1", n)
	}
}

func TestDNSUpsertAggregates(t *testing.T) {
	s := newTestStore(t)
	sessionID := newTestSession(t, s)
	t0 := time.Date(2026, 10, 26, 8, 0, 1, 0, time.UTC)

	q := func(at time.Time) *model.DNSQuery {
		out := &model.DNSQuery{
			SessionID: sessionID, PID: 4242, ExeName: "game.exe",
			QueryName: "example.com", QueryType: 1, QueryTypeName: "A",
			Status: 0, StatusText: "success", Answers: []string{"93.184.216.34"},
			Attributed: true, Attribution: "etw_process_id",
			FirstSeenUTC: at, LastSeenUTC: at, Source: model.SourceETWDNS,
		}
		out.ComputeDedupKey()
		return out
	}
	if err := s.UpsertDNS(q(t0)); err != nil {
		t.Fatalf("UpsertDNS: %v", err)
	}
	if err := s.UpsertDNS(q(t0.Add(time.Second))); err != nil {
		t.Fatalf("UpsertDNS (second): %v", err)
	}

	res, err := history.Query(context.Background(), s.DB(), history.Filter{SessionID: sessionID})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res.DNS) != 1 {
		t.Fatalf("dns = %d rows; want 1", len(res.DNS))
	}
	if res.DNS[0].Occurrences != 2 {
		t.Errorf("occurrences = %d; want 2", res.DNS[0].Occurrences)
	}
	if len(res.DNS[0].Answers) != 1 || res.DNS[0].Answers[0] != "93.184.216.34" {
		t.Errorf("answers = %v", res.DNS[0].Answers)
	}
}

func TestHistoryFilters(t *testing.T) {
	s := newTestStore(t)
	sessionID := newTestSession(t, s)
	t0 := time.Date(2026, 10, 26, 8, 0, 1, 0, time.UTC)

	inst := &model.ProcessInstance{
		SessionID: sessionID, PID: 1, ExeName: "game.exe", ExePath: `C:\Games\game.exe`,
		StartedUTC: t0, DetectedUTC: t0, CaptureState: "captured_from_start", Source: "test",
	}
	if _, err := s.InsertProcess(inst); err != nil {
		t.Fatalf("InsertProcess: %v", err)
	}

	tcp := &model.ConnectionEvent{
		SessionID: sessionID, ProcessInstanceID: inst.ID, PID: 1, ExeName: "game.exe", Proto: "tcp", IPVersion: 4,
		LocalAddr: "10.0.0.5", LocalPort: 50000, RemoteAddr: "1.1.1.1", RemotePort: 443,
		State: "established", EventType: "connect", FirstSeenUTC: t0, LastSeenUTC: t0,
		Source: model.SourceETWNetwork,
	}
	tcp.ComputeDedupKey()
	udp := &model.ConnectionEvent{
		SessionID: sessionID, ProcessInstanceID: inst.ID, PID: 1, ExeName: "game.exe", Proto: "udp", IPVersion: 4,
		LocalAddr: "10.0.0.5", LocalPort: 50001, RemoteAddr: "8.8.8.8", RemotePort: 53,
		State: "bound", EventType: "datagram", FirstSeenUTC: t0, LastSeenUTC: t0,
		Source: model.SourceETWNetwork,
	}
	udp.ComputeDedupKey()
	for _, e := range []*model.ConnectionEvent{tcp, udp} {
		if err := s.UpsertConnection(e); err != nil {
			t.Fatalf("UpsertConnection: %v", err)
		}
	}

	q := &model.DNSQuery{
		SessionID: sessionID, ProcessInstanceID: inst.ID, PID: 1, ExeName: "game.exe",
		QueryName: "api.example.com", QueryType: 1, QueryTypeName: "A",
		Status: 0, StatusText: "success", Attributed: true,
		FirstSeenUTC: t0, LastSeenUTC: t0, Source: model.SourceETWDNS,
	}
	q.ComputeDedupKey()
	if err := s.UpsertDNS(q); err != nil {
		t.Fatalf("UpsertDNS: %v", err)
	}

	cases := []struct {
		name string
		f    history.Filter
		want int
	}{
		{"all", history.Filter{SessionID: sessionID}, 2},
		{"proto", history.Filter{SessionID: sessionID, Proto: "udp"}, 1},
		{"port", history.Filter{SessionID: sessionID, Port: 443}, 1},
		{"ip", history.Filter{SessionID: sessionID, IP: "8.8.8.8"}, 1},
		{"event", history.Filter{SessionID: sessionID, Event: "connect"}, 1},
		{"exe", history.Filter{SessionID: sessionID, Exe: "game.exe"}, 2},
		{"exe case", history.Filter{SessionID: sessionID, Exe: "GAME.EXE"}, 2},
		{"exe path", history.Filter{SessionID: sessionID, Exe: `C:\Games\game.exe`}, 2},
		{"exe path suffix", history.Filter{SessionID: sessionID, Exe: `\Games\game.exe`}, 2},
		{"exe wrong path", history.Filter{SessionID: sessionID, Exe: `C:\Other\game.exe`}, 0},
		{"exe literal underscore", history.Filter{SessionID: sessionID, Exe: "game_x.exe"}, 0},
		{"exe literal percent", history.Filter{SessionID: sessionID, Exe: "game%.exe"}, 0},
		{"since", history.Filter{SessionID: sessionID, Since: t0.Add(time.Second)}, 0},
	}
	for _, tc := range cases {
		res, err := history.Query(context.Background(), s.DB(), tc.f)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(res.Connections) != tc.want {
			t.Errorf("%s: connections = %d; want %d", tc.name, len(res.Connections), tc.want)
		}
	}

	sres, err := history.Query(context.Background(), s.DB(),
		history.Filter{SessionID: sessionID, Exe: `C:\Games\game.exe`})
	if err != nil {
		t.Fatalf("session path filter: %v", err)
	}
	if len(sres.Sessions) != 1 {
		t.Errorf("session path filter returned %d sessions; want 1", len(sres.Sessions))
	}

	res, err := history.Query(context.Background(), s.DB(), history.Filter{SessionID: sessionID, Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.DNS) != 1 {
		t.Errorf("domain suffix filter returned %d rows; want 1", len(res.DNS))
	}
	res, err = history.Query(context.Background(), s.DB(), history.Filter{SessionID: sessionID, Domain: "other.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.DNS) != 0 {
		t.Errorf("domain filter returned %d rows; want 0", len(res.DNS))
	}
}

func TestDomainFilterEscapesWildcards(t *testing.T) {
	s := newTestStore(t)
	sessionID := newTestSession(t, s)
	t0 := time.Date(2026, 10, 26, 8, 0, 1, 0, time.UTC)

	for _, name := range []string{"_dmarc.example.com", "a.xdmarc.example.com"} {
		q := &model.DNSQuery{
			SessionID: sessionID, PID: 1, ExeName: "game.exe",
			QueryName: name, QueryType: 16, QueryTypeName: "TXT",
			Status: 0, StatusText: "success", Attributed: true,
			FirstSeenUTC: t0, LastSeenUTC: t0, Source: model.SourceETWDNS,
		}
		q.ComputeDedupKey()
		if err := s.UpsertDNS(q); err != nil {
			t.Fatalf("UpsertDNS(%s): %v", name, err)
		}
	}

	cases := []struct {
		domain string
		want   int
	}{
		{"_dmarc.example.com", 1},
		{"dmarc.example.com", 0}, // '_' must not act as a LIKE wildcard
	}
	for _, tc := range cases {
		res, err := history.Query(context.Background(), s.DB(),
			history.Filter{SessionID: sessionID, Domain: tc.domain})
		if err != nil {
			t.Fatalf("%s: %v", tc.domain, err)
		}
		if len(res.DNS) != tc.want {
			t.Errorf("domain %q: dns rows = %d; want %d", tc.domain, len(res.DNS), tc.want)
		}
	}
}

func TestSessionLifecycle(t *testing.T) {
	s := newTestStore(t)
	sessionID := newTestSession(t, s)

	ended := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	if err := s.UpdateSessionRuntime(sessionID, true, "note", []string{"a=1"}); err != nil {
		t.Fatalf("UpdateSessionRuntime: %v", err)
	}
	if err := s.FinishSession(sessionID, ended, "finished", "final", []string{"a=1"}); err != nil {
		t.Fatalf("FinishSession: %v", err)
	}
	got, err := s.LatestSession()
	if err != nil {
		t.Fatalf("LatestSession: %v", err)
	}
	if got == nil || got.ID != sessionID {
		t.Fatalf("LatestSession = %+v", got)
	}
	if got.Status != "finished" || got.CaptureNote != "final" {
		t.Errorf("status/note = %q/%q", got.Status, got.CaptureNote)
	}
	if !got.EndedUTC.Equal(ended) {
		t.Errorf("ended = %s; want %s", got.EndedUTC, ended)
	}
	if !got.ETWEnabled {
		t.Error("ETW flag was not persisted")
	}
	if got.SourcesJSON != `["a=1"]` {
		t.Errorf("sources = %q", got.SourcesJSON)
	}
}

func TestSourceStatusAndCounts(t *testing.T) {
	s := newTestStore(t)
	sessionID := newTestSession(t, s)
	at := time.Now().UTC()
	if err := s.SetSourceStatus(model.SourceStatus{
		SessionID: sessionID, Source: "etw:test", State: model.SourceRunning,
		Detail: "ok", UpdatedUTC: at,
	}); err != nil {
		t.Fatalf("SetSourceStatus: %v", err)
	}
	if err := s.SetSourceStatus(model.SourceStatus{
		SessionID: sessionID, Source: "etw:test", State: model.SourceDegraded,
		Detail: "lost", UpdatedUTC: at.Add(time.Second),
	}); err != nil {
		t.Fatalf("SetSourceStatus (update): %v", err)
	}
	statuses, err := s.SourceStatuses(sessionID)
	if err != nil {
		t.Fatalf("SourceStatuses: %v", err)
	}
	if len(statuses) != 1 || statuses[0].State != model.SourceDegraded {
		t.Errorf("source statuses = %+v", statuses)
	}
	counts, err := s.Counts()
	if err != nil {
		t.Fatalf("Counts: %v", err)
	}
	if counts.Sessions != 1 || counts.Schema != 1 {
		t.Errorf("counts = %+v", counts)
	}
}

func TestWriterAppliesRecords(t *testing.T) {
	s := newTestStore(t)
	sessionID := newTestSession(t, s)
	t0 := time.Now().UTC()

	w := s.NewWriter()
	w.Start()

	ev := &model.ConnectionEvent{
		SessionID: sessionID, PID: 5, ExeName: "game.exe", Proto: "tcp", IPVersion: 4,
		LocalAddr: "10.0.0.5", LocalPort: 1000, RemoteAddr: "1.1.1.1", RemotePort: 443,
		State: "established", EventType: "observed", FirstSeenUTC: t0, LastSeenUTC: t0,
		Source: model.SourceIPHelper,
	}
	ev.ComputeDedupKey()
	if !w.Enqueue(ev) {
		t.Fatal("Enqueue returned false")
	}
	w.Stop()

	written, dropped, failed, lastErr := w.Stats()
	if written != 1 || dropped != 0 || failed != 0 {
		t.Errorf("writer stats = %d/%d/%d (%s)", written, dropped, failed, lastErr)
	}
	res, err := history.Query(context.Background(), s.DB(), history.Filter{SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Connections) != 1 {
		t.Errorf("connections = %d; want 1", len(res.Connections))
	}
}
