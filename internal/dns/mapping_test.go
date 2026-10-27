package dns

import (
	"encoding/hex"
	"testing"
	"time"

	"nettrace/internal/model"
)

func TestQueryTypeName(t *testing.T) {
	cases := map[uint16]string{
		1: "A", 28: "AAAA", 5: "CNAME", 16: "TXT", 65: "HTTPS", 255: "ANY", 999: "TYPE999",
	}
	for in, want := range cases {
		if got := QueryTypeName(in); got != want {
			t.Errorf("QueryTypeName(%d) = %q; want %q", in, got, want)
		}
	}
}

func TestStatusText(t *testing.T) {
	cases := map[uint32]string{
		0: "success", 9003: "name_not_found", 1460: "timeout", 11001: "host_not_found",
		11004: "no_data", 12345: "status_12345",
	}
	for in, want := range cases {
		if got := StatusText(in); got != want {
			t.Errorf("StatusText(%d) = %q; want %q", in, got, want)
		}
	}
}

func TestParseQueryResultsDNSMessage(t *testing.T) {
	msg := buildDNSResponse()
	answers, raw := ParseQueryResults(hex.EncodeToString(msg))
	if len(answers) != 2 {
		t.Fatalf("answers = %v; want 2 records", answers)
	}
	if answers[0] != "93.184.216.34" || answers[1] != "2001:db8::1" {
		t.Errorf("answers = %v", answers)
	}
	if raw == "" {
		t.Error("raw hex was not preserved")
	}
}

func TestParseQueryResultsEmptyMessage(t *testing.T) {
	// A valid NXDOMAIN response with no answers must parse successfully with
	// an empty answer list (not as an error).
	msg := []byte{
		0x12, 0x34, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	answers, raw := ParseQueryResults(hex.EncodeToString(msg))
	if len(answers) != 0 {
		t.Fatalf("answers = %v; want none", answers)
	}
	if raw == "" {
		t.Error("raw hex was not preserved for an NXDOMAIN response")
	}
}

func TestParseQueryResultsText(t *testing.T) {
	answers, raw := ParseQueryResults("1.2.3.4; 5.6.7.8, 1.2.3.4")
	if raw != "" {
		t.Errorf("raw = %q; want empty", raw)
	}
	if len(answers) != 2 || answers[0] != "1.2.3.4" || answers[1] != "5.6.7.8" {
		t.Errorf("answers = %v", answers)
	}
}

func TestMapRaw(t *testing.T) {
	msg := buildDNSResponse()
	at := time.Date(2026, 10, 26, 9, 30, 0, 0, time.UTC)
	q, ok := MapRaw(model.RawEvent{
		ID: 3008, PID: 4242, TimeUTC: at,
		Fields: map[string]string{
			"QueryName":    "Example.COM.",
			"QueryType":    "1",
			"QueryStatus":  "0",
			"QueryResults": hex.EncodeToString(msg),
		},
	})
	if !ok {
		t.Fatal("MapRaw rejected a valid DNS event")
	}
	if q.QueryName != "Example.COM" {
		t.Errorf("query name = %q", q.QueryName)
	}
	if q.QueryType != 1 || q.QueryTypeName != "A" {
		t.Errorf("query type = %d/%s", q.QueryType, q.QueryTypeName)
	}
	if q.Status != 0 || q.StatusText != "success" {
		t.Errorf("status = %d/%s", q.Status, q.StatusText)
	}
	if q.PID != 4242 || q.Source != model.SourceETWDNS {
		t.Errorf("pid/source = %d/%s", q.PID, q.Source)
	}
	if !q.FirstSeenUTC.Equal(at) {
		t.Errorf("first seen = %s; want %s", q.FirstSeenUTC, at)
	}
	if len(q.Answers) != 2 {
		t.Errorf("answers = %v", q.Answers)
	}

	if _, ok := MapRaw(model.RawEvent{ID: 3008, PID: 0}); ok {
		t.Error("MapRaw accepted PID 0")
	}
	if _, ok := MapRaw(model.RawEvent{ID: 3006, PID: 1, Fields: map[string]string{"QueryName": "x"}}); ok {
		t.Error("MapRaw accepted an event other than 3008")
	}
}

func TestDNSDedupKeyIsCaseInsensitive(t *testing.T) {
	a := &model.DNSQuery{SessionID: 1, PID: 2, QueryName: "Example.COM", QueryType: 1}
	b := &model.DNSQuery{SessionID: 1, PID: 2, QueryName: "example.com", QueryType: 1}
	if a.ComputeDedupKey() != b.ComputeDedupKey() {
		t.Errorf("dedup keys differ: %q vs %q", a.DedupKey, b.DedupKey)
	}
}

func buildDNSResponse() []byte {
	var b []byte
	// Header: id, flags=standard response + recursion available, qd=1, an=2.
	b = append(b, 0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00)
	// Question: example.com A IN
	b = append(b, 7)
	b = append(b, []byte("example")...)
	b = append(b, 3)
	b = append(b, []byte("com")...)
	b = append(b, 0x00, 0x00, 0x01, 0x00, 0x01)
	// Answer 1: pointer to the question name, A, IN, ttl 60, 93.184.216.34.
	b = append(b, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
		93, 184, 216, 34)
	// Answer 2: pointer, AAAA, IN, ttl 60, 2001:db8::1.
	b = append(b, 0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x10,
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
	return b
}
