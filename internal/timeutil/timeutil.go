// Package timeutil centralizes the timestamp conventions used by NetTrace.
//
// Storage always keeps UTC timestamps in RFC3339Nano form. The console shows
// local time with millisecond precision.
package timeutil

import (
	"fmt"
	"strings"
	"time"
)

const (
	// DBFormat is the canonical timestamp format written to SQLite.
	DBFormat = time.RFC3339Nano
	// ConsoleFormat is used for every timestamp printed to the console.
	ConsoleFormat = "2006-01-02 15:04:05.000"
)

// UTCString formats t in UTC using RFC3339Nano.
func UTCString(t time.Time) string {
	return t.UTC().Format(DBFormat)
}

// ParseDB parses a timestamp previously written by UTCString. An empty string
// returns the zero time.
func ParseDB(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}

// Local formats t in the local timezone for console output.
func Local(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format(ConsoleFormat)
}

// LocalPtr formats a possibly missing timestamp.
func LocalPtr(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return Local(*t)
}

var userLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.000",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.000",
	"2006-01-02 15:04:05",
	"2006-01-02 15:04",
	"2006-01-02",
	"15:04:05.000",
	"15:04:05",
	"15:04",
}

// ParseUserTime accepts RFC3339, ISO-like local timestamps, a bare date, or a
// time of day (interpreted as today in the local timezone). Timestamps without
// an explicit zone are interpreted as local time.
func ParseUserTime(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}
	if now.IsZero() {
		now = time.Now()
	}
	for _, layout := range userLayouts {
		var (
			t   time.Time
			err error
		)
		if layout == "15:04:05.000" || layout == "15:04:05" || layout == "15:04" {
			t, err = time.ParseInLocation(layout, s, now.Location())
			if err == nil {
				local := time.Date(now.Year(), now.Month(), now.Day(),
					t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), now.Location())
				return local.UTC(), nil
			}
			continue
		}
		if strings.Contains(layout, "Z07:00") {
			t, err = time.Parse(layout, s)
		} else {
			t, err = time.ParseInLocation(layout, s, now.Location())
		}
		if err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized timestamp %q (use RFC3339, \"2006-01-02 15:04:05\" or \"2006-01-02\")", s)
}

// SinceOrZero parses an optional user timestamp.
func SinceOrZero(s string, now time.Time) (time.Time, error) {
	if strings.TrimSpace(s) == "" {
		return time.Time{}, nil
	}
	return ParseUserTime(s, now)
}
