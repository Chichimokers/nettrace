package model

import (
	"testing"
)

func TestTargetPathMatch(t *testing.T) {
	target := NewTargetPath(`C:\Games\Game.EXE`, `c:\games\game.exe`)
	ok, note := target.Matches("game.exe", `C:\Games\game.exe`)
	if !ok || note != "" {
		t.Fatalf("exact path match = %v, %q", ok, note)
	}
	ok, _ = target.Matches("game.exe", `C:\Games\Other\game.exe`)
	if ok {
		t.Error("path target matched a different directory")
	}
	ok, note = target.Matches("game.exe", "")
	if !ok || note == "" {
		t.Errorf("name fallback = %v, %q; want a match with a note", ok, note)
	}
	ok, _ = target.Matches("other.exe", "")
	if ok {
		t.Error("path target matched a different executable name")
	}
}

func TestTargetNameMatch(t *testing.T) {
	target := NewTargetName("game.exe", "Game.EXE")
	for _, path := range []string{`C:\Games\game.exe`, `D:\Other\GAME.EXE`, ""} {
		ok, note := target.Matches("game.exe", path)
		if !ok || note != "" {
			t.Errorf("name match for %q = %v, %q", path, ok, note)
		}
	}
	if ok, _ := target.Matches("other.exe", `C:\Games\other.exe`); ok {
		t.Error("name target matched a different executable")
	}
	if ok, _ := target.Matches("", `C:\Games\other.exe`); ok {
		t.Error("name target matched a different path")
	}
	// When only the path is known, the base name is used.
	if ok, _ := target.Matches("", `C:\Games\game.exe`); !ok {
		t.Error("name target could not derive the name from the path")
	}
}

func TestETWState(t *testing.T) {
	cases := []struct {
		name    string
		session MonitorSession
		want    string
	}{
		{"disabled", MonitorSession{}, "no"},
		{"unknown sources", MonitorSession{ETWEnabled: true}, "yes"},
		{"full", MonitorSession{ETWEnabled: true,
			SourcesJSON: `["etw:dns-client=running","etw:kernel-network=running","etw:kernel-process=running"]`},
			"yes (3/3 providers)"},
		{"partial", MonitorSession{ETWEnabled: true,
			SourcesJSON: `["etw:dns-client=running","etw:kernel-network=error","etw:kernel-process=error"]`},
			"partial (1/3 providers)"},
	}
	for _, tc := range cases {
		if got := tc.session.ETWState(); got != tc.want {
			t.Errorf("%s: ETWState = %q; want %q", tc.name, got, tc.want)
		}
	}
}

func TestConnectionDedupKey(t *testing.T) {
	a := &ConnectionEvent{SessionID: 1, PID: 2, Proto: "tcp", LocalAddr: "10.0.0.5", LocalPort: 1,
		RemoteAddr: "1.1.1.1", RemotePort: 443, EventType: "connect", State: "syn_sent"}
	b := &ConnectionEvent{SessionID: 1, PID: 2, Proto: "tcp", LocalAddr: "10.0.0.5", LocalPort: 1,
		RemoteAddr: "1.1.1.1", RemotePort: 443, EventType: "connect", State: "syn_sent"}
	if a.ComputeDedupKey() != b.ComputeDedupKey() {
		t.Error("identical events produced different dedup keys")
	}
	c := *b
	c.State = "established"
	if a.DedupKey == c.ComputeDedupKey() {
		t.Error("a state change must produce a new dedup key")
	}
}
