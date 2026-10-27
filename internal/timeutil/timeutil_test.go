package timeutil

import (
	"testing"
	"time"
)

func TestUTCStringRoundTrip(t *testing.T) {
	at := time.Date(2026, 10, 26, 8, 0, 1, 123456789, time.UTC)
	got, err := ParseDB(UTCString(at))
	if err != nil {
		t.Fatalf("ParseDB: %v", err)
	}
	if !got.Equal(at) {
		t.Errorf("round trip = %s; want %s", got, at)
	}
	if got.Location() != time.UTC {
		t.Errorf("location = %s; want UTC", got.Location())
	}
}

func TestParseDBEmpty(t *testing.T) {
	got, err := ParseDB("  ")
	if err != nil || !got.IsZero() {
		t.Errorf("ParseDB(empty) = %s, %v", got, err)
	}
	if _, err := ParseDB("not-a-time"); err == nil {
		t.Error("ParseDB accepted garbage")
	}
}

func TestLocalFormat(t *testing.T) {
	if Local(time.Time{}) != "-" {
		t.Error("zero time should render as -")
	}
	at := time.Date(2026, 10, 26, 8, 0, 1, 999000000, time.UTC)
	got := Local(at)
	want := at.Local().Format("2006-01-02 15:04:05.000")
	if got != want {
		t.Errorf("Local = %q; want %q", got, want)
	}
	if len(got) != len("2006-01-02 15:04:05.000") {
		t.Errorf("Local format = %q", got)
	}
}

func TestParseUserTime(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.Local)
	cases := []struct {
		in   string
		want time.Time
	}{
		{"2026-10-26T10:00:00Z", time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)},
		{"2026-10-26 10:00:00", time.Date(2026, 10, 26, 10, 0, 0, 0, time.Local).UTC()},
		{"2026-10-26", time.Date(2026, 10, 26, 0, 0, 0, 0, time.Local).UTC()},
		{"09:30:00", time.Date(2026, 10, 26, 9, 30, 0, 0, time.Local).UTC()},
	}
	for _, tc := range cases {
		got, err := ParseUserTime(tc.in, now)
		if err != nil {
			t.Errorf("ParseUserTime(%q): %v", tc.in, err)
			continue
		}
		if !got.Equal(tc.want) {
			t.Errorf("ParseUserTime(%q) = %s; want %s", tc.in, got, tc.want)
		}
	}
	if _, err := ParseUserTime("", now); err == nil {
		t.Error("empty timestamp accepted")
	}
	if _, err := ParseUserTime("yesterday", now); err == nil {
		t.Error("garbage timestamp accepted")
	}
}

func TestSinceOrZero(t *testing.T) {
	if got, err := SinceOrZero("", time.Now()); err != nil || !got.IsZero() {
		t.Errorf("SinceOrZero(empty) = %s, %v", got, err)
	}
}
