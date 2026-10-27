//go:build windows

package winproc

import (
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestFiletimeToTime guards the historical double-offset bug: Filetime's
// Nanoseconds already returns nanoseconds since 1970, so a correct conversion
// must round-trip the original instant.
func TestFiletimeToTime(t *testing.T) {
	at := time.Date(2026, 10, 26, 8, 0, 1, 250000000, time.UTC)
	ft := windows.NsecToFiletime(at.UnixNano())
	got := filetimeToTime(ft)
	if !got.Equal(at) {
		t.Fatalf("filetimeToTime = %s; want %s", got, at)
	}
	if got.Year() != 2026 {
		t.Fatalf("year = %d; want 2026 (double offset bug?)", got.Year())
	}
	if !filetimeToTime(windows.Filetime{}).IsZero() {
		t.Error("zero FILETIME did not convert to the zero time")
	}
}

func TestLocalAddressesIncludesLoopback(t *testing.T) {
	set, _ := LocalAddresses()
	for _, want := range []string{"127.0.0.1", "::1", "0.0.0.0", "::"} {
		if !set[want] {
			t.Errorf("LocalAddresses is missing %s", want)
		}
	}
}

func TestTCPStateName(t *testing.T) {
	cases := map[uint32]string{
		1: "closed", 2: "listen", 3: "syn_sent", 5: "established", 11: "time_wait", 99: "state_99",
	}
	for in, want := range cases {
		if got := tcpStateName(in); got != want {
			t.Errorf("tcpStateName(%d) = %q; want %q", in, got, want)
		}
	}
}

func TestPortFromDWORD(t *testing.T) {
	// Port 443 stored in network byte order inside the low 16 bits.
	if got := portFromDWORD(0xBB01); got != 443 {
		t.Errorf("portFromDWORD(0xBB01) = %d; want 443", got)
	}
}

func TestIPv4FromDWORD(t *testing.T) {
	// 127.0.0.1 arrives as the little-endian DWORD 0x0100007F.
	if got := ipv4FromDWORD(0x0100007F); got != "127.0.0.1" {
		t.Errorf("ipv4FromDWORD = %q; want 127.0.0.1", got)
	}
}
