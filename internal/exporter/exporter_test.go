package exporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nettrace/internal/history"
	"nettrace/internal/model"
)

func sampleResult() *history.Result {
	at := time.Date(2026, 10, 26, 8, 0, 1, 0, time.UTC)
	return &history.Result{
		Sessions: []model.MonitorSession{{
			ID: 1, TargetInput: "game.exe", TargetName: "game.exe", MatchKind: model.MatchName,
			StartedUTC: at, Status: "finished",
			ETWEnabled:  true,
			SourcesJSON: `["etw:dns-client=running","etw:kernel-network=error","etw:kernel-process=error"]`,
			Host:        "host", Username: `H\user`, OSVersion: "Windows", AppVersion: model.Version,
		}},
		Processes: []model.ProcessInstance{{
			ID: 2, SessionID: 1, PID: 42, ParentPID: 1, ExeName: "game.exe",
			ExePath: `C:\Games\game.exe`, StartedUTC: at, DetectedUTC: at,
			CaptureState: "captured_from_start", Source: "test",
		}},
		Connections: []model.ConnectionEvent{{
			ID: 3, SessionID: 1, ProcessInstanceID: 2, PID: 42, ExeName: "game.exe",
			Proto: "tcp", IPVersion: 4, LocalAddr: "10.0.0.5", LocalPort: 50000,
			RemoteAddr: "1.1.1.1", RemotePort: 443, State: "established",
			EventType: "observed", FirstSeenUTC: at, LastSeenUTC: at,
			BytesSent: 10, BytesRecv: 20, Occurrences: 2, Source: "test",
		}},
		DNS: []model.DNSQuery{{
			ID: 4, SessionID: 1, ProcessInstanceID: 2, PID: 42, ExeName: "game.exe",
			QueryName: "example.com", QueryType: 1, QueryTypeName: "A",
			Status: 0, StatusText: "success", Answers: []string{"93.184.216.34"},
			Attributed: true, Attribution: "etw_process_id",
			FirstSeenUTC: at, LastSeenUTC: at, Occurrences: 1, Source: "test",
		}},
	}
}

func TestNormalizeWhat(t *testing.T) {
	if got, _ := NormalizeWhat(nil); len(got) != 1 || got[0] != "all" {
		t.Errorf("empty = %v", got)
	}
	if got, _ := NormalizeWhat([]string{"connections", "dns"}); len(got) != 2 {
		t.Errorf("list = %v", got)
	}
	if got, _ := NormalizeWhat([]string{"all", "dns"}); len(got) != 1 || got[0] != "all" {
		t.Errorf("all dominates = %v", got)
	}
	if _, err := NormalizeWhat([]string{"bogus"}); err == nil {
		t.Error("expected an error for an unknown type")
	}
}

func TestWriteCSVSingleTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conn.csv")
	paths, err := Write(sampleResult(), Options{
		Format: "csv", What: []string{"connections"}, Out: path,
		Now: time.Now(),
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(paths) != 1 || paths[0] != path {
		t.Fatalf("paths = %v", paths)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.HasPrefix(text, "connection_id,session_id,") {
		t.Errorf("unexpected CSV header: %q", strings.SplitN(text, "\n", 2)[0])
	}
	if !strings.Contains(text, "10.0.0.5,50000,1.1.1.1,443,established,observed") {
		t.Errorf("CSV row missing expected values:\n%s", text)
	}
	if !strings.Contains(text, "2026-10-26T08:00:01Z") {
		t.Errorf("CSV timestamp is not UTC RFC3339:\n%s", text)
	}
}

func TestWriteCSVAllUsesBaseName(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "export")
	paths, err := Write(sampleResult(), Options{
		Format: "csv", What: []string{"all"}, Out: base + ".csv", Now: time.Now(),
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(paths) != 4 {
		t.Fatalf("paths = %v; want 4 files", paths)
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}

func TestWriteJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "export.json")
	paths, err := Write(sampleResult(), Options{
		Format: "json", What: []string{"all"}, Out: path,
		Now: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(paths) != 1 || paths[0] != path {
		t.Fatalf("paths = %v", paths)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		ExportedUTC string `json:"exported_utc"`
		App         string `json:"app"`
		Sessions    []struct {
			SessionID int64  `json:"session_id"`
			ETWState  string `json:"etw_state"`
		} `json:"sessions"`
		Connections []struct {
			LocalPort int `json:"local_port"`
			BytesSent int `json:"bytes_sent"`
		} `json:"connections"`
		DNS []struct {
			Answers []string `json:"answers"`
		} `json:"dns"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, data)
	}
	if decoded.App != model.AppName || decoded.ExportedUTC != "2026-10-26T12:00:00Z" {
		t.Errorf("metadata = %q/%q", decoded.App, decoded.ExportedUTC)
	}
	if len(decoded.Sessions) != 1 || decoded.Sessions[0].SessionID != 1 {
		t.Errorf("sessions = %+v", decoded.Sessions)
	}
	if decoded.Sessions[0].ETWState != "partial (1/3 providers)" {
		t.Errorf("etw_state = %q; want partial coverage", decoded.Sessions[0].ETWState)
	}
	if len(decoded.Connections) != 1 || decoded.Connections[0].LocalPort != 50000 || decoded.Connections[0].BytesSent != 10 {
		t.Errorf("connections = %+v", decoded.Connections)
	}
	if len(decoded.DNS) != 1 || len(decoded.DNS[0].Answers) != 1 {
		t.Errorf("dns = %+v", decoded.DNS)
	}
}

func TestWriteCreatesOutputDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "deeper", "conn.csv")
	if _, err := Write(sampleResult(), Options{
		Format: "csv", What: []string{"connections"}, Out: path, Now: time.Now(),
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("output file was not created: %v", err)
	}
}

func TestWriteRejectsUnknownFormat(t *testing.T) {
	if _, err := Write(sampleResult(), Options{Format: "xml"}); err == nil {
		t.Error("expected an error for an unknown format")
	}
}
