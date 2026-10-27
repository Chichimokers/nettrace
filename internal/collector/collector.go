//go:build windows

// Package collector wires the ETW sources, the process manager, the polling
// fallback and the storage writer together.
package collector

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/golang-etw/etw"

	"nettrace/internal/dns"
	"nettrace/internal/etwhelp"
	"nettrace/internal/model"
	"nettrace/internal/network"
	"nettrace/internal/process"
	"nettrace/internal/storage"
	"nettrace/internal/timeutil"
	"nettrace/internal/winproc"
)

// Options configures a Collector.
type Options struct {
	Store                *storage.Store
	Writer               *storage.Writer
	Procs                *process.Manager
	Resolver             *network.Resolver
	SessionID            int64
	PollInterval         time.Duration
	UseETW               bool
	StoreUnattributedDNS bool
	Quiet                bool
	Verbose              bool
	Out                  io.Writer
	Now                  func() time.Time
}

// Collector owns the running sources for one monitoring session.
type Collector struct {
	opts    Options
	printMu sync.Mutex
	out     io.Writer
	now     func() time.Time

	etw        *etwRuntime
	etwUsed    bool
	etwErr     string
	etwDropped uint64
	etwLost    uint64

	mu            sync.Mutex
	sourceStates  map[string]string
	sourceDetails map[string]string
	counts        map[string]uint64
	warned        map[string]bool
	polling       bool

	wg         sync.WaitGroup
	ingestDone chan struct{}
}

// New creates a collector.
func New(opts Options) *Collector {
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 2 * time.Second
	}
	c := &Collector{
		opts:          opts,
		out:           opts.Out,
		now:           opts.Now,
		sourceStates:  make(map[string]string),
		sourceDetails: make(map[string]string),
		counts:        make(map[string]uint64),
		warned:        make(map[string]bool),
	}
	opts.Procs.OnStart = c.ProcessStarted
	opts.Procs.OnEnd = c.ProcessEnded
	return c
}

// ETWEnabled reports whether at least one ETW provider was active.
func (c *Collector) ETWEnabled() bool { return c.etwUsed }

// ETWProblem returns why ETW is not active, if applicable.
func (c *Collector) ETWProblem() string { return c.etwErr }

// Run starts collection, blocks until ctx is cancelled and then stops every
// source cleanly.
func (c *Collector) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	c.setSource(model.SourceETWProcess, model.SourceUnavailable, "ETW not started")
	c.setSource(model.SourceETWNetwork, model.SourceUnavailable, "ETW not started")
	c.setSource(model.SourceETWDNS, model.SourceUnavailable, "ETW not started")
	c.setSource(model.SourceToolhelp, model.SourceRunning, "Toolhelp32 process polling")

	if c.opts.UseETW {
		if err := c.startETW(runCtx); err != nil {
			c.etwErr = err.Error()
			c.warnf("ETW sources unavailable: %v", err)
			c.warnf("falling back to sampled IP Helper tables and Toolhelp32; short-lived connections and DNS cannot be observed")
			c.markETWDown(err)
		} else {
			c.etwUsed = true
		}
	} else {
		c.etwErr = "disabled with --no-etw"
		c.setPolling(true)
		c.warnf("ETW disabled (--no-etw): connection history is sampled from IP Helper tables; DNS is not collected")
	}

	if err := c.opts.Procs.Scan(true); err != nil {
		c.warnf("initial process snapshot: %v", err)
	}

	c.wg.Add(2)
	go c.processPollLoop(runCtx)
	go c.connectionPollLoop(runCtx)
	if c.etw != nil {
		c.wg.Add(1)
		go c.healthLoop(runCtx)
	}

	<-ctx.Done()
	cancel()
	c.wg.Wait()
	c.stopETW()

	c.flushSourceStatuses()
	return nil
}

// Stats describes what was collected.
type Stats struct {
	ETWEnabled      bool
	ETWProblem      string
	ETWDropped      uint64
	ETWLost         uint64
	Sources         map[string]string
	SourceDetails   map[string]string
	EventCounts     map[string]uint64
	PollConnections bool
}

// Stats returns a snapshot of the collection counters.
func (c *Collector) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	src := make(map[string]string, len(c.sourceStates))
	for k, v := range c.sourceStates {
		src[k] = v
	}
	details := make(map[string]string, len(c.sourceDetails))
	for k, v := range c.sourceDetails {
		details[k] = v
	}
	counts := make(map[string]uint64, len(c.counts))
	for k, v := range c.counts {
		counts[k] = v
	}
	st := Stats{
		ETWEnabled:      c.etwUsed,
		ETWProblem:      c.etwErr,
		Sources:         src,
		SourceDetails:   details,
		EventCounts:     counts,
		PollConnections: c.polling,
	}
	// stopETW clears c.etw; keep the final counters so the summary can report
	// losses after the session has been closed.
	if c.etw != nil {
		st.ETWDropped = c.etw.dropped.Load()
		st.ETWLost = c.etw.lost
	} else {
		st.ETWDropped = c.etwDropped
		st.ETWLost = c.etwLost
	}
	return st
}

func (c *Collector) startETW(ctx context.Context) error {
	rt, err := startETWRuntime(ctx)
	if err != nil {
		return err
	}
	c.etw = rt
	c.ingestDone = make(chan struct{})
	go func() {
		defer close(c.ingestDone)
		for ev := range rt.events {
			c.handleETW(ev)
		}
	}()
	if rt.dnsEnabled {
		c.setSource(model.SourceETWDNS, model.SourceRunning, "Microsoft-Windows-DNS-Client")
	} else {
		c.setSource(model.SourceETWDNS, model.SourceError, rt.dnsProblem)
	}
	if rt.networkEnabled {
		c.setSource(model.SourceETWNetwork, model.SourceRunning, "Microsoft-Windows-Kernel-Network")
	} else {
		c.setSource(model.SourceETWNetwork, model.SourceError, rt.networkProblem)
		c.setPolling(true)
	}
	if rt.processEnabled {
		c.setSource(model.SourceETWProcess, model.SourceRunning, "Microsoft-Windows-Kernel-Process")
	} else {
		c.setSource(model.SourceETWProcess, model.SourceError, rt.processProblem)
	}
	if !rt.networkEnabled && !rt.processEnabled && !rt.dnsEnabled {
		_ = rt.stop()
		c.etw = nil
		return fmt.Errorf("no ETW provider could be enabled: %s", rt.problemSummary())
	}
	return nil
}

func (c *Collector) stopETW() {
	if c.etw == nil {
		return
	}
	rt := c.etw
	if err := rt.stop(); err != nil && !isAlreadyStopped(err) {
		c.warnf("stopping ETW consumer: %v", err)
	}
	close(rt.events)
	<-c.ingestDone
	if err := rt.session.Stop(); err != nil && !isAlreadyStopped(err) {
		c.warnf("stopping ETW session: %v", err)
	}
	rt.lost = rt.consumer.LostEvents
	c.etwDropped = rt.dropped.Load()
	c.etwLost = rt.lost
	c.etw = nil
}

func (c *Collector) handleETW(ev *etw.Event) {
	if ev == nil {
		return
	}
	at := ev.System.TimeCreated.SystemTime.UTC()
	headerPID := ev.System.Execution.ProcessID
	fields := eventFields(ev)

	switch providerKind(ev) {
	case providerNetwork:
		pid, _ := parseFieldUint(fields, "PID")
		if pid == 0 {
			pid = headerPID
		}
		raw := model.RawEvent{ID: ev.System.EventID, PID: pid, TimeUTC: at, Fields: fields}
		conn, ok := network.MapRaw(raw, c.opts.Resolver)
		if !ok {
			return
		}
		c.recordConnection(conn)
	case providerDNS:
		if ev.System.EventID != 3008 {
			// 3006 is the "query called" event. It has no answers, so recording
			// it would duplicate the completed 3008 row without adding data.
			return
		}
		q, ok := dns.MapRaw(model.RawEvent{ID: ev.System.EventID, PID: headerPID, TimeUTC: at, Fields: fields})
		if !ok {
			return
		}
		ref, monitored := c.opts.Procs.Lookup(headerPID)
		if monitored {
			q.ProcessInstanceID = ref.InstanceID
			q.ExeName = ref.ExeName
			q.Attributed = true
			q.Attribution = "etw_process_id"
		} else if c.opts.StoreUnattributedDNS {
			q.Attribution = "unattributed"
			q.Attributed = false
		} else {
			return
		}
		q.SessionID = c.opts.SessionID
		q.ComputeDedupKey()
		c.opts.Writer.Enqueue(q)
		c.bump("dns:" + q.StatusText)
		c.eventf("dns %d %s %s %s %s%s", q.PID, q.ExeName, q.QueryName, q.QueryTypeName, q.StatusText, answerSuffix(q.Answers))
	case providerProcess:
		switch ev.System.EventID {
		case 1:
			c.handleProcessStart(headerPID, fields)
		case 2:
			c.handleProcessStop(headerPID, fields, at)
		}
	}
}

func (c *Collector) handleProcessStart(headerPID uint32, fields map[string]string) {
	pid, _ := parseFieldUint(fields, "ProcessID")
	if pid == 0 {
		pid = headerPID
	}
	parent, _ := parseFieldUint(fields, "ParentProcessID")
	image := winproc.DevicePathToDOS(fields["ImageName"])
	info := winproc.Info{
		PID:       pid,
		ParentPID: parent,
		Name:      baseName(image),
	}
	err := winproc.Fill(&info)
	if err != nil && image == "" {
		return
	}
	if info.Path == "" {
		info.Path = image
	}
	if info.Name == "" {
		info.Name = baseName(image)
	}
	c.opts.Procs.Consider(info, model.SourceETWProcess, false)
}

func (c *Collector) handleProcessStop(headerPID uint32, fields map[string]string, at time.Time) {
	pid, _ := parseFieldUint(fields, "ProcessID")
	if pid == 0 {
		pid = headerPID
	}
	var exit *uint32
	if v, ok := parseFieldUint(fields, "ExitCode"); ok {
		e := v
		exit = &e
	}
	c.opts.Procs.End(pid, at, exit, model.SourceETWProcess)
}

func (c *Collector) recordConnection(ev *model.ConnectionEvent) {
	ref, ok := c.opts.Procs.Lookup(ev.PID)
	if !ok {
		return
	}
	ev.SessionID = c.opts.SessionID
	ev.ProcessInstanceID = ref.InstanceID
	ev.ExeName = ref.ExeName
	ev.ComputeDedupKey()
	c.opts.Writer.Enqueue(ev)
	c.bump("network:" + ev.EventType)
	if !c.opts.Verbose && (ev.EventType == "data" || ev.EventType == "datagram" ||
		ev.EventType == "retransmit" || ev.EventType == "copy" || ev.EventType == "observed") {
		return
	}
	c.eventf("%s %s %d %s %s:%d -> %s:%d state=%s%s",
		ev.Proto, ev.EventType, ev.PID, ev.ExeName,
		ev.LocalAddr, ev.LocalPort, ev.RemoteAddr, ev.RemotePort,
		orDash(ev.State), bytesSuffix(ev))
}

// ProcessStarted is called by the process manager for console output.
func (c *Collector) ProcessStarted(inst *model.ProcessInstance) {
	c.bump("process:start")
	c.eventf("process start pid=%d ppid=%d %s %s (%s)%s",
		inst.PID, inst.ParentPID, inst.ExeName, inst.ExePath, inst.CaptureState, noteSuffix(inst.MatchNote))
}

// ProcessEnded is called by the process manager for console output.
func (c *Collector) ProcessEnded(inst *model.ProcessInstance) {
	c.bump("process:end")
	c.eventf("process end   pid=%d %s state=%s exit=%s", inst.PID, inst.ExeName, inst.CaptureState, exitText(inst.ExitCode))
}

func (c *Collector) processPollLoop(ctx context.Context) {
	defer c.wg.Done()
	ticker := time.NewTicker(c.opts.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.opts.Procs.Scan(false); err != nil {
				c.warnOnce("process-poll", "process snapshot failed: %v", err)
			}
		}
	}
}

func (c *Collector) connectionPollLoop(ctx context.Context) {
	defer c.wg.Done()
	ticker := time.NewTicker(c.opts.PollInterval)
	defer ticker.Stop()
	for {
		if c.pollingEnabled() {
			c.pollConnectionsOnce()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *Collector) pollConnectionsOnce() {
	at := c.now()
	entries, err := winproc.NetworkTable()
	if err != nil {
		c.setSource(model.SourceIPHelper, model.SourceDegraded, err.Error())
		c.warnOnce("iphlpapi", "IP Helper snapshot failed: %v", err)
		return
	}
	c.setSource(model.SourceIPHelper, model.SourceRunning, "sampled IP Helper tables")
	for _, e := range entries {
		ev := network.MapSnapshot(network.SnapshotEntry{
			Proto: e.Proto, IPVersion: e.IPVersion,
			LocalAddr: e.Local.Addr, LocalPort: e.Local.Port,
			RemoteAddr: e.Remote.Addr, RemotePort: e.Remote.Port,
			State: e.State, PID: e.PID,
		}, at)
		// recordConnection resolves the owning monitored instance and prints
		// the sample in verbose mode.
		c.recordConnection(ev)
	}
}

func (c *Collector) healthLoop(ctx context.Context) {
	defer c.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.etw == nil {
				return
			}
			alive, err := etwhelp.SessionAlive(c.etw.name)
			if err == nil && alive {
				failures = 0
				// Only refresh providers that were actually enabled. Providers
				// denied at startup must keep their error state and reason; the
				// session being alive says nothing about them.
				c.markETWAlive()
				continue
			}
			failures++
			if failures >= 2 {
				c.warnf("ETW session %q is no longer alive; switching to sampled fallback", c.etw.name)
				c.markETWDown(fmt.Errorf("ETW session disappeared: %v", err))
				return
			}
		}
	}
}

func (c *Collector) markETWAlive() {
	rt := c.etw
	if rt == nil {
		return
	}
	if rt.networkEnabled {
		c.setSource(model.SourceETWNetwork, model.SourceRunning, "ETW session alive")
	}
	if rt.dnsEnabled {
		c.setSource(model.SourceETWDNS, model.SourceRunning, "ETW session alive")
	}
	if rt.processEnabled {
		c.setSource(model.SourceETWProcess, model.SourceRunning, "ETW session alive")
	}
}

func (c *Collector) markETWDown(err error) {
	c.setPolling(true)
	detail := err.Error()
	c.setSource(model.SourceToolhelp, model.SourceRunning, "Toolhelp32 process polling")
	c.setSource(model.SourceIPHelper, model.SourceRunning, "sampled IP Helper tables")
	if c.etwUsed && c.etw != nil {
		// Degrade only the providers that had been working; keep the startup
		// error for providers that were never enabled.
		if c.etw.networkEnabled {
			c.setSource(model.SourceETWNetwork, model.SourceDegraded, detail)
		}
		if c.etw.dnsEnabled {
			c.setSource(model.SourceETWDNS, model.SourceDegraded, detail)
		}
		if c.etw.processEnabled {
			c.setSource(model.SourceETWProcess, model.SourceDegraded, detail)
		}
	}
}

func (c *Collector) setPolling(v bool) {
	c.mu.Lock()
	c.polling = v
	c.mu.Unlock()
}

func (c *Collector) pollingEnabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.polling
}

func (c *Collector) setSource(source, state, detail string) {
	c.mu.Lock()
	prevState, seen := c.sourceStates[source]
	changed := !seen || prevState != state || c.sourceDetails[source] != detail
	c.sourceStates[source] = state
	if changed {
		c.sourceDetails[source] = detail
	}
	c.mu.Unlock()
	if !changed {
		// Polling sources call this on every tick; only persist real changes so
		// the database is not flooded with identical health rows.
		return
	}
	c.opts.Writer.Enqueue(model.SourceStatus{
		SessionID: c.opts.SessionID, Source: source, State: state,
		Detail: detail, UpdatedUTC: c.now().UTC(),
	})
}

func (c *Collector) flushSourceStatuses() {
	c.mu.Lock()
	states := make(map[string]string, len(c.sourceStates))
	details := make(map[string]string, len(c.sourceStates))
	for k, v := range c.sourceStates {
		states[k] = v
	}
	for k, v := range c.sourceDetails {
		details[k] = v
	}
	c.mu.Unlock()
	at := c.now().UTC()
	for src, state := range states {
		detail := details[src]
		if detail == "" {
			detail = "final state"
		}
		c.opts.Writer.Enqueue(model.SourceStatus{
			SessionID: c.opts.SessionID, Source: src, State: state,
			Detail: detail, UpdatedUTC: at,
		})
	}
}

// Sources returns the final status of each source, sorted by name.
func (c *Collector) Sources() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.sourceStates))
	for k, v := range c.sourceStates {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

func (c *Collector) bump(key string) {
	c.mu.Lock()
	c.counts[key]++
	c.mu.Unlock()
}

func (c *Collector) warnOnce(key, format string, args ...any) {
	c.mu.Lock()
	seen := c.warned[key]
	c.warned[key] = true
	c.mu.Unlock()
	if !seen {
		c.warnf(format, args...)
	}
}

func (c *Collector) warnf(format string, args ...any) {
	c.printMu.Lock()
	defer c.printMu.Unlock()
	fmt.Fprintf(c.out, "[%s] warning: %s\n", timeutil.Local(c.now()), fmt.Sprintf(format, args...))
}

func (c *Collector) eventf(format string, args ...any) {
	if c.opts.Quiet {
		return
	}
	c.printMu.Lock()
	defer c.printMu.Unlock()
	fmt.Fprintf(c.out, "[%s] %s\n", timeutil.Local(c.now()), fmt.Sprintf(format, args...))
}

func bytesSuffix(ev *model.ConnectionEvent) string {
	if ev.BytesSent == 0 && ev.BytesRecv == 0 && ev.Occurrences <= 1 {
		return ""
	}
	return fmt.Sprintf(" bytes=%d/%d n=%d", ev.BytesSent, ev.BytesRecv, ev.Occurrences)
}

func answerSuffix(answers []string) string {
	if len(answers) == 0 {
		return ""
	}
	if len(answers) > 6 {
		answers = append(answers[:6:6], "...")
	}
	return " -> " + strings.Join(answers, ",")
}

func noteSuffix(note string) string {
	if note == "" {
		return ""
	}
	return " note=" + note
}

func exitText(code *uint32) string {
	if code == nil {
		return "unknown"
	}
	return fmt.Sprintf("%d", *code)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func baseName(path string) string {
	path = strings.TrimRight(path, `\/`)
	if i := strings.LastIndexAny(path, `\/`); i >= 0 {
		return path[i+1:]
	}
	return path
}

func parseFieldUint(fields map[string]string, name string) (uint32, bool) {
	v := strings.TrimSpace(fields[name])
	if v == "" {
		return 0, false
	}
	u, err := strconv.ParseUint(v, 0, 32)
	if err != nil {
		return 0, false
	}
	return uint32(u), true
}
