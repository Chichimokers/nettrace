package network

import (
	"testing"
	"time"

	"nettrace/internal/model"
)

func TestParseAddrIPv4(t *testing.T) {
	// 10.0.0.5 is stored in memory as 0A 00 00 05; TDH renders the
	// little-endian DWORD 0x0500000A as the decimal string 83886090.
	got, ok := parseAddr("83886090", 4)
	if !ok || got != "10.0.0.5" {
		t.Fatalf("parseAddr decimal = %q, %v; want 10.0.0.5, true", got, ok)
	}
	if got, ok := parseAddr("127.0.0.1", 4); !ok || got != "127.0.0.1" {
		t.Fatalf("parseAddr dotted = %q, %v; want 127.0.0.1, true", got, ok)
	}
	if _, ok := parseAddr("not-an-ip", 4); ok {
		t.Fatal("parseAddr accepted garbage")
	}
}

func TestParseAddrIPv6(t *testing.T) {
	got, ok := parseAddr("20010db8000000000000000000000001", 6)
	if !ok || got != "2001:db8::1" {
		t.Fatalf("parseAddr hex = %q, %v; want 2001:db8::1, true", got, ok)
	}
	if got, ok := parseAddr("[2001:db8::1]", 6); !ok || got != "2001:db8::1" {
		t.Fatalf("parseAddr bracketed = %q, %v", got, ok)
	}
	if _, ok := parseAddr("0001", 6); ok {
		t.Fatal("parseAddr accepted a short IPv6 value")
	}
}

func TestMapRawOrientsOutboundData(t *testing.T) {
	r := newTestResolver("10.0.0.5")
	at := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	raw := model.RawEvent{
		ID: 10, PID: 4242, TimeUTC: at,
		Fields: map[string]string{
			"PID": "4242", "saddr": "83886090", "sport": "50000",
			"daddr": "16843009", "dport": "443", "size": "100",
			"connid": "77",
		},
	}
	ev, ok := MapRaw(raw, r)
	if !ok {
		t.Fatal("MapRaw rejected a valid outbound data event")
	}
	if ev.LocalAddr != "10.0.0.5" || ev.LocalPort != 50000 {
		t.Errorf("local = %s:%d; want 10.0.0.5:50000", ev.LocalAddr, ev.LocalPort)
	}
	if ev.RemoteAddr != "1.1.1.1" || ev.RemotePort != 443 {
		t.Errorf("remote = %s:%d; want 1.1.1.1:443", ev.RemoteAddr, ev.RemotePort)
	}
	if ev.EventType != "data" || ev.Proto != "tcp" || ev.IPVersion != 4 {
		t.Errorf("type/proto/version = %s/%s/%d", ev.EventType, ev.Proto, ev.IPVersion)
	}
	if ev.BytesSent != 100 || ev.BytesRecv != 0 {
		t.Errorf("bytes = %d/%d; want 100/0", ev.BytesSent, ev.BytesRecv)
	}
	if ev.Detail != "connid=77" {
		t.Errorf("detail = %q; want connid=77", ev.Detail)
	}
	if !ev.FirstSeenUTC.Equal(at) {
		t.Errorf("first seen = %s; want %s", ev.FirstSeenUTC, at)
	}
}

func TestMapRawOrientsInboundData(t *testing.T) {
	r := newTestResolver("10.0.0.5")
	raw := model.RawEvent{
		ID: 11, PID: 7, TimeUTC: time.Now(),
		Fields: map[string]string{
			"saddr": "16843009", "sport": "443",
			"daddr": "83886090", "dport": "50000", "size": "200",
		},
	}
	ev, ok := MapRaw(raw, r)
	if !ok {
		t.Fatal("MapRaw rejected a valid inbound data event")
	}
	if ev.LocalAddr != "10.0.0.5" || ev.LocalPort != 50000 {
		t.Errorf("local = %s:%d; want 10.0.0.5:50000", ev.LocalAddr, ev.LocalPort)
	}
	if ev.BytesRecv != 200 || ev.BytesSent != 0 {
		t.Errorf("bytes = %d/%d; want 0/200", ev.BytesSent, ev.BytesRecv)
	}
}

func TestMapRawIPv6(t *testing.T) {
	r := newTestResolver("2001:db8::1")
	raw := model.RawEvent{
		ID: 26, PID: 7, TimeUTC: time.Now(),
		Fields: map[string]string{
			"saddr": "20010db8000000000000000000000001", "sport": "50000",
			"daddr": "20010db8000000000000000000000002", "dport": "443",
			"size": "64",
		},
	}
	ev, ok := MapRaw(raw, r)
	if !ok {
		t.Fatal("MapRaw rejected a valid IPv6 event")
	}
	if ev.IPVersion != 6 || ev.LocalAddr != "2001:db8::1" || ev.RemoteAddr != "2001:db8::2" {
		t.Errorf("ipv6 mapping = v%d %s -> %s", ev.IPVersion, ev.LocalAddr, ev.RemoteAddr)
	}
	if ev.BytesSent != 64 {
		t.Errorf("bytes sent = %d; want 64", ev.BytesSent)
	}
}

func TestMapRawConnectAndFail(t *testing.T) {
	r := newTestResolver("10.0.0.5")
	at := time.Now()
	connect := model.RawEvent{
		ID: 12, PID: 9, TimeUTC: at,
		Fields: map[string]string{
			"saddr": "83886090", "sport": "50000", "daddr": "16843009", "dport": "443",
		},
	}
	ev, ok := MapRaw(connect, r)
	if !ok || ev.EventType != "connect" || ev.State != "syn_sent" || ev.BytesSent != 0 {
		t.Fatalf("connect mapping = %+v, %v", ev, ok)
	}

	fail := model.RawEvent{
		ID: 17, PID: 9, TimeUTC: at,
		Fields: map[string]string{
			"PID": "9", "saddr": "83886090", "sport": "50000",
			"daddr": "16843009", "dport": "443", "size": "10061",
		},
	}
	ev, ok = MapRaw(fail, r)
	if !ok || ev.EventType != "fail" || ev.State != "failed" {
		t.Fatalf("fail mapping = %+v, %v", ev, ok)
	}
	if ev.Detail != "failure_code=10061" {
		t.Errorf("fail detail = %q; want failure_code=10061", ev.Detail)
	}
}

func TestMapRawRejectsUnknown(t *testing.T) {
	if _, ok := MapRaw(model.RawEvent{ID: 999, PID: 1}, nil); ok {
		t.Fatal("MapRaw accepted an unknown event ID")
	}
	if _, ok := MapRaw(model.RawEvent{ID: 10, PID: 0}, nil); ok {
		t.Fatal("MapRaw accepted PID 0")
	}
	if KnownEvent(999) {
		t.Fatal("KnownEvent(999) = true")
	}
}

func TestMapSnapshot(t *testing.T) {
	at := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	ev := MapSnapshot(SnapshotEntry{
		Proto: "tcp", IPVersion: 4,
		LocalAddr: "10.0.0.5", LocalPort: 50000,
		RemoteAddr: "1.1.1.1", RemotePort: 443,
		State: "established", PID: 42,
	}, at)
	if ev.EventType != "observed" || ev.Source != model.SourceIPHelper {
		t.Errorf("snapshot type/source = %s/%s", ev.EventType, ev.Source)
	}
	if !ev.FirstSeenUTC.Equal(at) || !ev.LastSeenUTC.Equal(at) {
		t.Errorf("snapshot time = %s/%s", ev.FirstSeenUTC, ev.LastSeenUTC)
	}
	if ev.LocalPort != 50000 || ev.RemotePort != 443 || ev.PID != 42 {
		t.Errorf("snapshot tuple = %+v", ev)
	}
}

func TestResolverRefreshFailureKeepsLastSet(t *testing.T) {
	calls := 0
	r := NewResolver(time.Nanosecond, func() (map[string]bool, error) {
		calls++
		if calls == 1 {
			return map[string]bool{"10.0.0.5": true}, nil
		}
		return nil, errFake
	})
	// Force a refresh that fails; the previous set must survive.
	r.refresh(true)
	if !r.IsLocal("10.0.0.5") {
		t.Error("local address was lost after a failed refresh")
	}
	if r.Err() == nil {
		t.Error("expected the refresh error to be reported")
	}
}

type fakeErr struct{}

func (fakeErr) Error() string { return "loader failed" }

var errFake = fakeErr{}

func newTestResolver(local string) *Resolver {
	return NewResolver(time.Minute, func() (map[string]bool, error) {
		return map[string]bool{local: true}, nil
	})
}
