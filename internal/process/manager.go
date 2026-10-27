//go:build windows

// Package process tracks every instance of the monitored executable. It uses
// ETW process events as the primary source and Toolhelp32 snapshots as a
// fallback for start/stop detection.
package process

import (
	"fmt"
	"sync"
	"time"

	"nettrace/internal/model"
	"nettrace/internal/storage"
	"nettrace/internal/winproc"
)

const recentTTL = 30 * time.Second

type recentRef struct {
	ref   model.ProcessRef
	until time.Time
}

// Manager owns the in-memory PID -> instance mapping for one session.
type Manager struct {
	mu           sync.Mutex
	store        *storage.Store
	target       model.Target
	sessionID    int64
	sessionStart time.Time
	active       map[uint32]*model.ProcessInstance
	recent       map[uint32]recentRef
	logf         func(string, ...any)
	now          func() time.Time

	// OnStart and OnEnd are called after the database row exists. They are
	// invoked from the ingest or poll goroutine, never from the ETW callback.
	OnStart func(*model.ProcessInstance)
	OnEnd   func(*model.ProcessInstance)
}

// New creates a manager for one monitoring session.
func New(store *storage.Store, target model.Target, sessionID int64, sessionStart time.Time,
	logf func(string, ...any)) *Manager {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Manager{
		store:        store,
		target:       target,
		sessionID:    sessionID,
		sessionStart: sessionStart.UTC(),
		active:       make(map[uint32]*model.ProcessInstance),
		recent:       make(map[uint32]recentRef),
		logf:         logf,
		now:          time.Now,
	}
}

// Consider evaluates one process image and starts tracking it when it matches.
// Duplicate observations (ETW + polling) are ignored.
func (m *Manager) Consider(info winproc.Info, source string, initial bool) *model.ProcessInstance {
	ok, note := m.target.Matches(info.Name, info.Path)
	if !ok {
		return nil
	}
	detected := m.now().UTC()

	m.mu.Lock()
	if cur := m.active[info.PID]; cur != nil {
		if !info.StartKnown || cur.StartedUTC.Equal(info.StartUTC) {
			m.mu.Unlock()
			return nil
		}
		// Same PID, different creation time: the old process ended and the PID
		// was reused. Close the old instance before creating the new one.
		m.mu.Unlock()
		m.endPID(info.PID, detected, nil, source)
		m.mu.Lock()
	}

	started := info.StartUTC.UTC()
	startKnown := info.StartKnown && !started.IsZero()
	already := initial
	captureState := "captured_from_start"
	if startKnown {
		already = started.Before(m.sessionStart.Add(-time.Second))
	}
	if already {
		captureState = "already_running"
	}
	if !startKnown {
		started = detected
		if initial {
			note = joinNote(note, "start time unavailable; process was present when capture started")
		}
	}

	inst := &model.ProcessInstance{
		SessionID:      m.sessionID,
		PID:            info.PID,
		ParentPID:      info.ParentPID,
		ExeName:        info.Name,
		ExePath:        info.Path,
		StartedUTC:     started,
		DetectedUTC:    detected,
		AlreadyRunning: already,
		CaptureState:   captureState,
		MatchNote:      note,
		Source:         source,
	}
	delete(m.recent, info.PID)
	m.active[info.PID] = inst
	m.mu.Unlock()

	id, err := m.store.InsertProcess(inst)
	if err != nil {
		m.logf("storage: %v (process pid=%d will still be monitored)", err, inst.PID)
	} else {
		inst.ID = id
	}

	m.mu.Lock()
	// InsertProcess may have updated inst.ID; make sure the map has the same
	// pointer (it does) and the PID was not replaced while we were writing.
	if m.active[info.PID] == inst {
		m.mu.Unlock()
		if m.OnStart != nil {
			m.OnStart(inst)
		}
		return inst
	}
	m.mu.Unlock()
	return nil
}

// End marks a PID as finished. exitCode may be nil when the source cannot
// provide it. The call is idempotent.
func (m *Manager) End(pid uint32, at time.Time, exitCode *uint32, source string) {
	m.endPID(pid, at.UTC(), exitCode, source)
}

func (m *Manager) endPID(pid uint32, at time.Time, exitCode *uint32, source string) {
	m.mu.Lock()
	inst := m.active[pid]
	if inst == nil {
		// A late exit event for an instance we already closed: update the exit
		// code if we now have one.
		if r, ok := m.recent[pid]; ok && exitCode != nil && r.ref.InstanceID != 0 {
			m.mu.Unlock()
			if err := m.store.EndProcess(model.ProcessEnd{
				InstanceID: r.ref.InstanceID, EndedUTC: at, ExitCode: exitCode,
			}); err != nil {
				m.logf("storage: %v", err)
			}
			return
		}
		m.mu.Unlock()
		return
	}
	delete(m.active, pid)
	inst.EndedUTC = at
	if exitCode != nil {
		inst.ExitCode = exitCode
	}
	m.recent[pid] = recentRef{
		ref:   model.ProcessRef{InstanceID: inst.ID, ExeName: inst.ExeName},
		until: m.now().Add(recentTTL),
	}
	m.mu.Unlock()

	if inst.ID != 0 {
		if err := m.store.EndProcess(model.ProcessEnd{
			InstanceID: inst.ID, EndedUTC: at, ExitCode: exitCode,
		}); err != nil {
			m.logf("storage: %v", err)
		}
	}
	if m.OnEnd != nil {
		m.OnEnd(inst)
	}
	_ = source
}

// Lookup resolves a PID to a process instance. Recently ended instances remain
// resolvable for a short grace period so trailing close/data events are not
// discarded.
func (m *Manager) Lookup(pid uint32) (model.ProcessRef, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if inst := m.active[pid]; inst != nil {
		return model.ProcessRef{InstanceID: inst.ID, ExeName: inst.ExeName}, true
	}
	now := m.now()
	for p, r := range m.recent {
		if now.After(r.until) {
			delete(m.recent, p)
		}
	}
	if r, ok := m.recent[pid]; ok && m.now().Before(r.until) {
		return r.ref, true
	}
	return model.ProcessRef{}, false
}

// IsActive reports whether pid is an active monitored instance.
func (m *Manager) IsActive(pid uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.active[pid]
	return ok
}

// Active returns a snapshot of the active instances.
func (m *Manager) Active() []*model.ProcessInstance {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*model.ProcessInstance, 0, len(m.active))
	for _, inst := range m.active {
		cp := *inst
		out = append(out, &cp)
	}
	return out
}

// Scan reconciles the in-memory state with a Toolhelp32 snapshot.
func (m *Manager) Scan(initial bool) error {
	infos, err := winproc.FindTargets(m.target)
	if err != nil {
		return fmt.Errorf("process snapshot: %w", err)
	}
	seen := make(map[uint32]bool, len(infos))
	for _, info := range infos {
		seen[info.PID] = true
		source := model.SourceToolhelp
		if initial {
			source = model.SourceToolhelp + ":initial"
		}
		m.Consider(info, source, initial)
	}
	m.mu.Lock()
	var gone []uint32
	for pid := range m.active {
		if !seen[pid] {
			gone = append(gone, pid)
		}
	}
	m.mu.Unlock()
	for _, pid := range gone {
		if winproc.Alive(pid) {
			// Path became unavailable but the process is still alive.
			continue
		}
		m.endPID(pid, m.now().UTC(), nil, model.SourceToolhelp)
	}
	return nil
}

func joinNote(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}
