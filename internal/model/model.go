// Package model contains the data types shared by every NetTrace package.
//
// The types in this file deliberately have no dependency on Windows, on the
// ETW library or on SQLite so they can be used by tests on any platform.
package model

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const (
	AppName = "NetTrace"
	Version = "0.1.0"
)

// MatchKind describes how the monitored executable was selected.
type MatchKind string

const (
	MatchPath MatchKind = "path"
	MatchName MatchKind = "name"
)

// Target is the executable being monitored.
type Target struct {
	Input string
	Path  string
	Name  string
	Kind  MatchKind
}

// NewTargetPath builds a target that matches a full image path.
func NewTargetPath(input, absPath string) Target {
	return Target{
		Input: input,
		Path:  filepath.Clean(absPath),
		Name:  filepath.Base(absPath),
		Kind:  MatchPath,
	}
}

// NewTargetName builds a target that matches by executable file name.
func NewTargetName(input, name string) Target {
	name = filepath.Base(strings.TrimSpace(name))
	return Target{
		Input: input,
		Name:  name,
		Kind:  MatchName,
	}
}

// Matches reports whether a process image belongs to the target. The second
// return value is a human readable note that explains a degraded match.
func (t Target) Matches(exeName, exePath string) (bool, string) {
	exeName = strings.TrimSpace(exeName)
	exePath = strings.TrimSpace(exePath)
	if exePath != "" && exeName == "" {
		exeName = filepath.Base(exePath)
	}

	switch t.Kind {
	case MatchPath:
		if exePath != "" {
			if samePath(exePath, t.Path) {
				return true, ""
			}
			return false, ""
		}
		// The OS refused to give us the image path (protected process, access
		// denied). Matching by base name can produce a false positive, so the
		// caller records the note and the history shows that the match was not
		// path-verified.
		if exeName != "" && strings.EqualFold(exeName, t.Name) {
			return true, "process path unavailable; matched by executable name"
		}
		return false, ""
	case MatchName:
		if exeName == "" && exePath != "" {
			exeName = filepath.Base(exePath)
		}
		if exeName != "" {
			return strings.EqualFold(exeName, t.Name), ""
		}
		return false, ""
	default:
		return false, ""
	}
}

func samePath(a, b string) bool {
	a = strings.TrimRight(filepath.Clean(a), `\/`)
	b = strings.TrimRight(filepath.Clean(b), `\/`)
	return strings.EqualFold(a, b)
}

func (t Target) String() string {
	if t.Kind == MatchPath {
		return t.Path
	}
	return t.Name
}

// ProcessRef is the in-memory association between a PID and the process
// instance row that owns it for the current monitoring session.
type ProcessRef struct {
	InstanceID int64
	ExeName    string
}

// SessionStart is the information required to create a monitoring session.
type SessionStart struct {
	Target      Target
	StartedUTC  time.Time
	CaptureNote string
	ETWEnabled  bool
	Sources     []string
	Host        string
	Username    string
	OSVersion   string
	AppVersion  string
}

// MonitorSession is one run of "nettrace monitor".
type MonitorSession struct {
	ID          int64
	TargetInput string
	TargetPath  string
	TargetName  string
	MatchKind   MatchKind
	StartedUTC  time.Time
	EndedUTC    time.Time
	Status      string
	CaptureNote string
	ETWEnabled  bool
	SourcesJSON string
	Host        string
	Username    string
	OSVersion   string
	AppVersion  string
}

// ETWState summarizes how much of the requested ETW coverage was available.
// A session can have etw_enabled set while individual providers were denied,
// so this label distinguishes full, partial, and unused ETW.
func (s MonitorSession) ETWState() string {
	if !s.ETWEnabled {
		return "no"
	}
	var pairs []string
	if s.SourcesJSON != "" {
		_ = json.Unmarshal([]byte(s.SourcesJSON), &pairs)
	}
	return ETWStateFromPairs(pairs, true)
}

// ETWStateFromPairs derives the ETW coverage label from "source=state" pairs,
// as stored in MonitorSession.SourcesJSON or read from source_statuses.
func ETWStateFromPairs(pairs []string, enabled bool) string {
	if !enabled {
		return "no"
	}
	running, total := 0, 0
	for _, p := range pairs {
		source, state, ok := strings.Cut(p, "=")
		if !ok || !strings.HasPrefix(source, "etw:") {
			continue
		}
		total++
		if state == SourceRunning {
			running++
		}
	}
	if total == 0 {
		return "yes"
	}
	if running == total {
		return fmt.Sprintf("yes (%d/%d providers)", running, total)
	}
	return fmt.Sprintf("partial (%d/%d providers)", running, total)
}

// ProcessInstance is one observed execution of the target executable.
type ProcessInstance struct {
	ID             int64
	SessionID      int64
	PID            uint32
	ParentPID      uint32
	ExeName        string
	ExePath        string
	StartedUTC     time.Time
	DetectedUTC    time.Time
	EndedUTC       time.Time
	ExitCode       *uint32
	AlreadyRunning bool
	CaptureState   string // "captured_from_start" or "already_running"
	MatchNote      string
	Source         string
}

// ConnectionEvent is an aggregated connection/DNS observation. Data events
// (TCP segments, UDP datagrams) are folded into a single row per
// (session, pid, protocol, endpoint tuple, event type, state).
type ConnectionEvent struct {
	ID                int64
	SessionID         int64
	ProcessInstanceID int64
	PID               uint32
	ExeName           string
	Proto             string
	IPVersion         int
	LocalAddr         string
	LocalPort         uint16
	RemoteAddr        string
	RemotePort        uint16
	State             string
	EventType         string
	FirstSeenUTC      time.Time
	LastSeenUTC       time.Time
	BytesSent         uint64
	BytesRecv         uint64
	Occurrences       uint64
	Source            string
	Detail            string
	DedupKey          string
}

// ComputeDedupKey sets and returns the stable key used to avoid duplicate rows.
func (e *ConnectionEvent) ComputeDedupKey() string {
	e.DedupKey = fmt.Sprintf("%d|%d|%s|%s|%d|%s|%d|%s|%s",
		e.SessionID, e.PID, e.Proto,
		e.LocalAddr, e.LocalPort, e.RemoteAddr, e.RemotePort,
		e.EventType, e.State)
	return e.DedupKey
}

// DNSQuery is a completed DNS query. Identical queries inside one session are
// aggregated (occurrences + first/last seen).
type DNSQuery struct {
	ID                int64
	SessionID         int64
	ProcessInstanceID int64
	PID               uint32
	ExeName           string
	QueryName         string
	QueryType         uint16
	QueryTypeName     string
	Status            uint32
	StatusText        string
	Answers           []string
	Attributed        bool
	Attribution       string
	FirstSeenUTC      time.Time
	LastSeenUTC       time.Time
	Occurrences       uint64
	Source            string
	Raw               string
	DedupKey          string
}

// ComputeDedupKey sets and returns the stable key used to aggregate queries.
func (q *DNSQuery) ComputeDedupKey() string {
	q.DedupKey = fmt.Sprintf("%d|%d|%s|%d", q.SessionID, q.PID, strings.ToLower(q.QueryName), q.QueryType)
	return q.DedupKey
}

// SourceStatus is a health update for one collection source.
type SourceStatus struct {
	SessionID  int64
	Source     string
	State      string
	Detail     string
	UpdatedUTC time.Time
}

// ProcessEnd is a deferred update for an instance that is already in the DB.
type ProcessEnd struct {
	InstanceID int64
	EndedUTC   time.Time
	ExitCode   *uint32
}

// RawEvent is a source-neutral event. The ETW collector converts ETW events to
// this type so that the network and DNS mapping code can be unit tested without
// an elevated ETW session.
type RawEvent struct {
	ID      uint16
	PID     uint32
	TimeUTC time.Time
	Fields  map[string]string
}

// Provider names and GUIDs used by NetTrace.
const (
	ProviderKernelNetwork = "Microsoft-Windows-Kernel-Network"
	ProviderDNSClient     = "Microsoft-Windows-DNS-Client"
	ProviderKernelProcess = "Microsoft-Windows-Kernel-Process"

	GUIDKernelNetwork = "{7dd42a49-5329-4832-8dfd-43d979153a88}"
	GUIDDNSClient     = "{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}"
	GUIDKernelProcess = "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"
)

// Source identifiers stored in the database.
const (
	SourceETWNetwork = "etw:kernel-network"
	SourceETWDNS     = "etw:dns-client"
	SourceETWProcess = "etw:kernel-process"
	SourceToolhelp   = "toolhelp:snapshot"
	SourceIPHelper   = "iphlpapi:poll"
)

// Source states.
const (
	SourceRunning     = "running"
	SourceStopped     = "stopped"
	SourceDegraded    = "degraded"
	SourceError       = "error"
	SourceUnavailable = "unavailable"
)
