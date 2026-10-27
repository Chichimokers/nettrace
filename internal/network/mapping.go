// Package network maps Microsoft-Windows-Kernel-Network events to NetTrace
// connection records and resolves endpoint orientation.
package network

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"nettrace/internal/model"
)

// Loader returns the set of local addresses (canonical strings).
type Loader func() (map[string]bool, error)

// Resolver caches the local address set to decide which side of a kernel event
// is local. This is needed because the Kernel-Network provider swaps saddr and
// daddr depending on the event direction.
type Resolver struct {
	mu      sync.Mutex
	last    time.Time
	local   map[string]bool
	ttl     time.Duration
	load    Loader
	now     func() time.Time
	lastErr error
}

// NewResolver creates a resolver. load may be nil, in which case only the
// unspecified and loopback addresses are considered local.
func NewResolver(ttl time.Duration, load Loader) *Resolver {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	r := &Resolver{
		ttl:   ttl,
		load:  load,
		now:   time.Now,
		local: map[string]bool{"0.0.0.0": true, "::": true, "127.0.0.1": true, "::1": true},
	}
	r.refresh(true)
	return r
}

// IsLocal reports whether addr belongs to this host.
func (r *Resolver) IsLocal(addr string) bool {
	r.refresh(false)
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.local[addr]
}

// Err returns the last refresh error, if any.
func (r *Resolver) Err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastErr
}

func (r *Resolver) refresh(force bool) {
	r.mu.Lock()
	if !force && r.now().Sub(r.last) < r.ttl {
		r.mu.Unlock()
		return
	}
	r.last = r.now()
	load := r.load
	r.mu.Unlock()
	if load == nil {
		return
	}
	set, err := load()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastErr = err
	if err == nil && len(set) > 0 {
		r.local = set
	}
}

type eventMeta struct {
	proto string
	ipv   int
	kind  string
	state string
	dir   int // -1 outbound, +1 inbound, 0 unresolved
	data  bool
}

// eventMetaTable documents every Kernel-Network event that NetTrace consumes.
var eventMetaTable = map[uint16]eventMeta{
	10: {"tcp", 4, "data", "", -1, true},
	11: {"tcp", 4, "data", "", 1, true},
	12: {"tcp", 4, "connect", "syn_sent", -1, false},
	13: {"tcp", 4, "close", "closed", 0, false},
	14: {"tcp", 4, "retransmit", "", -1, false},
	15: {"tcp", 4, "establish", "established", 0, false},
	16: {"tcp", 4, "reconnect", "reconnecting", -1, false},
	17: {"tcp", 4, "fail", "failed", -1, false},
	18: {"tcp", 4, "copy", "", 0, false},
	26: {"tcp", 6, "data", "", -1, true},
	27: {"tcp", 6, "data", "", 1, true},
	28: {"tcp", 6, "connect", "syn_sent", -1, false},
	29: {"tcp", 6, "close", "closed", 0, false},
	30: {"tcp", 6, "retransmit", "", -1, false},
	31: {"tcp", 6, "establish", "established", 0, false},
	32: {"tcp", 6, "reconnect", "reconnecting", -1, false},
	33: {"tcp", 6, "fail", "failed", -1, false},
	34: {"tcp", 6, "copy", "", 0, false},
	42: {"udp", 4, "datagram", "", -1, true},
	43: {"udp", 4, "datagram", "", 1, true},
	49: {"udp", 4, "fail", "failed", -1, false},
	58: {"udp", 6, "datagram", "", -1, true},
	59: {"udp", 6, "datagram", "", 1, true},
}

// KnownEvent reports whether id is a Kernel-Network event used by NetTrace.
func KnownEvent(id uint16) bool {
	_, ok := eventMetaTable[id]
	return ok
}

// MapRaw converts a Kernel-Network event into a connection record. The record
// has no session ID yet; the collector fills that in.
func MapRaw(raw model.RawEvent, resolver *Resolver) (*model.ConnectionEvent, bool) {
	meta, ok := eventMetaTable[raw.ID]
	if !ok || raw.PID == 0 {
		return nil, false
	}
	if resolver == nil {
		resolver = NewResolver(0, nil)
	}

	saddr, ok1 := parseAddr(raw.Fields["saddr"], meta.ipv)
	daddr, ok2 := parseAddr(raw.Fields["daddr"], meta.ipv)
	if !ok1 || !ok2 || saddr == "" || daddr == "" {
		return nil, false
	}
	sport, ok1 := parsePort(raw.Fields["sport"])
	dport, ok2 := parsePort(raw.Fields["dport"])
	if !ok1 || !ok2 {
		return nil, false
	}

	localAddr, localPort, remoteAddr, remotePort := orient(
		saddr, sport, daddr, dport, meta.dir, resolver.IsLocal)

	ev := &model.ConnectionEvent{
		PID:          raw.PID,
		Proto:        meta.proto,
		IPVersion:    meta.ipv,
		LocalAddr:    localAddr,
		LocalPort:    localPort,
		RemoteAddr:   remoteAddr,
		RemotePort:   remotePort,
		State:        meta.state,
		EventType:    meta.kind,
		FirstSeenUTC: raw.TimeUTC.UTC(),
		LastSeenUTC:  raw.TimeUTC.UTC(),
		Occurrences:  1,
		Source:       model.SourceETWNetwork,
	}

	outbound := localAddr == saddr && localPort == sport
	if saddr == daddr && sport == dport {
		outbound = meta.dir < 0
	}

	if meta.data && raw.ID != 14 && raw.ID != 18 {
		size, _ := parseUint(raw.Fields["size"])
		if outbound {
			ev.BytesSent = size
		} else {
			ev.BytesRecv = size
		}
	}

	if meta.kind == "fail" {
		code, ok := parseUint(firstField(raw.Fields, "FailureCode", "size"))
		if ok {
			ev.Detail = fmt.Sprintf("failure_code=%d", code)
		}
	}
	if connID, ok := parseUint(raw.Fields["connid"]); ok && connID != 0 {
		if ev.Detail != "" {
			ev.Detail += " "
		}
		ev.Detail += fmt.Sprintf("connid=%d", connID)
	}
	return ev, true
}

// MapSnapshot converts one IP Helper table row to an observation. The event
// type is "observed" and the state is part of the dedup key, so state
// transitions are visible but repeated samples of the same state collapse.
func MapSnapshot(entry SnapshotEntry, at time.Time) *model.ConnectionEvent {
	local, remote := entry.LocalAddr, entry.RemoteAddr
	if entry.Proto == "udp" {
		return &model.ConnectionEvent{
			PID:          entry.PID,
			Proto:        "udp",
			IPVersion:    entry.IPVersion,
			LocalAddr:    local,
			LocalPort:    entry.LocalPort,
			RemoteAddr:   remote,
			RemotePort:   entry.RemotePort,
			State:        entry.State,
			EventType:    "observed",
			FirstSeenUTC: at.UTC(),
			LastSeenUTC:  at.UTC(),
			Occurrences:  1,
			Source:       model.SourceIPHelper,
			Detail:       "sampled from IP Helper tables",
		}
	}
	return &model.ConnectionEvent{
		PID:          entry.PID,
		Proto:        "tcp",
		IPVersion:    entry.IPVersion,
		LocalAddr:    local,
		LocalPort:    entry.LocalPort,
		RemoteAddr:   remote,
		RemotePort:   entry.RemotePort,
		State:        entry.State,
		EventType:    "observed",
		FirstSeenUTC: at.UTC(),
		LastSeenUTC:  at.UTC(),
		Occurrences:  1,
		Source:       model.SourceIPHelper,
		Detail:       "sampled from IP Helper tables",
	}
}

// SnapshotEntry is a neutral IP Helper row used by the collector and tests.
type SnapshotEntry struct {
	Proto      string
	IPVersion  int
	LocalAddr  string
	LocalPort  uint16
	RemoteAddr string
	RemotePort uint16
	State      string
	PID        uint32
}

func orient(saddr string, sport uint16, daddr string, dport uint16, dir int, isLocal func(string) bool) (string, uint16, string, uint16) {
	sLocal := isLocal(saddr)
	dLocal := isLocal(daddr)
	switch {
	case sLocal && !dLocal:
		return saddr, sport, daddr, dport
	case dLocal && !sLocal:
		return daddr, dport, saddr, sport
	}
	if dir > 0 {
		return daddr, dport, saddr, sport
	}
	return saddr, sport, daddr, dport
}

func parseAddr(s string, ipv int) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if ipv == 4 {
		if strings.Contains(s, ".") {
			addr, err := netip.ParseAddr(s)
			if err != nil || !addr.Is4() {
				return "", false
			}
			return addr.String(), true
		}
		v, err := strconv.ParseUint(s, 0, 32)
		if err != nil {
			return "", false
		}
		// Little-endian byte order, as returned by the kernel/ETW decoder.
		return netip.AddrFrom4([4]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}).String(), true
	}

	if strings.Contains(s, ":") && !strings.HasPrefix(strings.ToLower(s), "0x") {
		addr, err := netip.ParseAddr(strings.Trim(s, "[]"))
		if err != nil || !addr.Is6() {
			return "", false
		}
		return addr.Unmap().String(), true
	}
	hexStr := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(s), "0x"), "0X")
	hexStr = strings.NewReplacer(" ", "", "-", "", ":", "", "\t", "").Replace(hexStr)
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(b) != 16 {
		return "", false
	}
	var arr [16]byte
	copy(arr[:], b)
	return netip.AddrFrom16(arr).Unmap().String(), true
}

func parsePort(s string) (uint16, bool) {
	v, ok := parseUint(s)
	if !ok || v > 65535 {
		return 0, false
	}
	return uint16(v), true
}

func parseUint(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func firstField(fields map[string]string, names ...string) string {
	for _, n := range names {
		if v, ok := fields[n]; ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// EventIDs returns the Kernel-Network event IDs NetTrace requests, for
// documentation and tests.
func EventIDs() []uint16 {
	out := make([]uint16, 0, len(eventMetaTable))
	for id := range eventMetaTable {
		out = append(out, id)
	}
	return out
}
