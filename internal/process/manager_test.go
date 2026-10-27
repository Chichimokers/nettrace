//go:build windows

package process

import (
	"path/filepath"
	"testing"
	"time"

	"nettrace/internal/model"
	"nettrace/internal/storage"
	"nettrace/internal/winproc"
)

func newManager(t *testing.T, sessionStart time.Time) (*Manager, *storage.Store, int64) {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "proc-test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	sessionID, err := store.CreateSession(model.SessionStart{
		Target:     model.NewTargetName("game.exe", "game.exe"),
		StartedUTC: sessionStart,
		AppVersion: model.Version,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	m := New(store, model.NewTargetName("game.exe", "game.exe"), sessionID, sessionStart, t.Logf)
	return m, store, sessionID
}

func targetInfo(pid uint32, start time.Time) winproc.Info {
	return winproc.Info{
		PID: pid, ParentPID: 1, Name: "game.exe", Path: `C:\Games\game.exe`,
		StartUTC: start, StartKnown: true,
	}
}

func TestConsiderClassifiesAlreadyRunning(t *testing.T) {
	base := time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)
	m, _, _ := newManager(t, base)

	if inst := m.Consider(targetInfo(100, base.Add(-time.Hour)), "test", false); inst == nil {
		t.Fatal("Consider returned nil for a matching process")
	} else if !inst.AlreadyRunning || inst.CaptureState != "already_running" {
		t.Errorf("before-start process = already=%v state=%q", inst.AlreadyRunning, inst.CaptureState)
	}

	if inst := m.Consider(targetInfo(101, base.Add(time.Second)), "test", false); inst == nil {
		t.Fatal("Consider returned nil for a matching process")
	} else if inst.AlreadyRunning || inst.CaptureState != "captured_from_start" {
		t.Errorf("after-start process = already=%v state=%q", inst.AlreadyRunning, inst.CaptureState)
	}
}

func TestConsiderInitialSnapshot(t *testing.T) {
	base := time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)
	m, _, _ := newManager(t, base)

	// Unknown start time during the initial snapshot: it must be recorded as
	// already running and never claimed to have been captured from its start.
	info := winproc.Info{PID: 200, Name: "game.exe", Path: `C:\Games\game.exe`}
	inst := m.Consider(info, "test", true)
	if inst == nil {
		t.Fatal("Consider returned nil")
	}
	if !inst.AlreadyRunning || inst.CaptureState != "already_running" {
		t.Errorf("unknown start = already=%v state=%q", inst.AlreadyRunning, inst.CaptureState)
	}
	if inst.MatchNote == "" {
		t.Error("expected a note explaining the missing start time")
	}
}

func TestConsiderDeduplicatesAndMatchesTarget(t *testing.T) {
	base := time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)
	m, store, sessionID := newManager(t, base)

	other := targetInfo(300, base.Add(time.Second))
	other.Name = "other.exe"
	other.Path = `C:\Games\other.exe`
	if inst := m.Consider(other, "test", false); inst != nil {
		t.Fatal("Consider accepted a non-matching process")
	}

	first := m.Consider(targetInfo(300, base.Add(time.Second)), "test", false)
	if first == nil {
		t.Fatal("first Consider returned nil")
	}
	if second := m.Consider(targetInfo(300, base.Add(time.Second)), "test", false); second != nil {
		t.Error("duplicate observation created a second instance")
	}
	ref, ok := m.Lookup(300)
	if !ok || ref.InstanceID != first.ID {
		t.Errorf("Lookup = %+v, %v; want instance %d", ref, ok, first.ID)
	}
	if !m.IsActive(300) {
		t.Error("IsActive(300) = false")
	}
	if got := m.Active(); len(got) != 1 || got[0].PID != 300 {
		t.Errorf("Active() = %+v", got)
	}

	counts, err := store.CountsForSession(sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Processes != 1 {
		t.Errorf("stored processes = %d; want 1", counts.Processes)
	}
}

func TestEndKeepsRecentLookupAndRecordsExit(t *testing.T) {
	base := time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)
	m, store, sessionID := newManager(t, base)

	inst := m.Consider(targetInfo(400, base.Add(time.Second)), "test", false)
	if inst == nil {
		t.Fatal("Consider returned nil")
	}
	ended := base.Add(10 * time.Second)
	exit := uint32(7)
	m.End(400, ended, &exit, "test")

	if m.IsActive(400) {
		t.Error("process is still active after End")
	}
	// Trailing connection events must still resolve to the instance.
	ref, ok := m.Lookup(400)
	if !ok || ref.InstanceID != inst.ID {
		t.Errorf("Lookup after End = %+v, %v", ref, ok)
	}

	var (
		endedStr string
		exitCode int64
	)
	if err := store.DB().QueryRow(`SELECT ended_utc, exit_code FROM process_instances WHERE session_id=? AND pid=?`,
		sessionID, 400).Scan(&endedStr, &exitCode); err != nil {
		t.Fatal(err)
	}
	if endedStr == "" {
		t.Error("ended_utc was not stored")
	}
	if exitCode != 7 {
		t.Errorf("exit code = %d; want 7", exitCode)
	}
}

func TestPIDReuseStartsNewInstance(t *testing.T) {
	base := time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)
	m, store, sessionID := newManager(t, base)

	first := m.Consider(targetInfo(500, base.Add(time.Second)), "test", false)
	if first == nil {
		t.Fatal("first Consider returned nil")
	}
	second := m.Consider(targetInfo(500, base.Add(time.Minute)), "test", false)
	if second == nil {
		t.Fatal("second Consider returned nil for a reused PID")
	}
	if second.ID == first.ID {
		t.Error("a reused PID was mapped to the old instance")
	}
	counts, err := store.CountsForSession(sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Processes != 2 {
		t.Errorf("stored processes = %d; want 2", counts.Processes)
	}
}
