//go:build windows

package collector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
	"golang.org/x/sys/windows"

	"nettrace/internal/model"
	"nettrace/internal/network"
)

type providerType int

const (
	providerUnknown providerType = iota
	providerNetwork
	providerDNS
	providerProcess
)

var (
	guidNetwork = etw.MustParseGUIDFromString(model.GUIDKernelNetwork)
	guidDNS     = etw.MustParseGUIDFromString(model.GUIDDNSClient)
	guidProcess = etw.MustParseGUIDFromString(model.GUIDKernelProcess)
)

type providerSpec struct {
	kind    providerType
	name    string
	keyword uint64
}

var providerSpecs = []providerSpec{
	{kind: providerNetwork, name: model.ProviderKernelNetwork, keyword: 0},
	{kind: providerProcess, name: model.ProviderKernelProcess, keyword: 0x10},
	{kind: providerDNS, name: model.ProviderDNSClient, keyword: 0x8000000000000000},
}

type etwRuntime struct {
	name     string
	session  *etw.RealTimeSession
	consumer *etw.Consumer
	events   chan *etw.Event

	dropped atomic.Uint64
	lost    uint64

	networkEnabled bool
	dnsEnabled     bool
	processEnabled bool

	networkProblem string
	dnsProblem     string
	processProblem string
}

func startETWRuntime(ctx context.Context) (*etwRuntime, error) {
	name := fmt.Sprintf("NetTrace-%d-%d", os.Getpid(), time.Now().UnixNano())
	rt := &etwRuntime{
		name:   name,
		events: make(chan *etw.Event, 16384),
	}
	session := etw.NewRealTimeSession(name)
	rt.session = session

	enabled := map[providerType]bool{}
	for _, spec := range providerSpecs {
		p := etw.ResolveProvider(spec.name)
		if p.IsZero() || p.GUID == "" {
			rt.setProblem(spec.kind, "provider not registered on this system")
			continue
		}
		p.EnableLevel = 0xff
		p.MatchAnyKeyword = spec.keyword
		if err := session.EnableProvider(p); err != nil {
			rt.setProblem(spec.kind, err.Error())
			continue
		}
		enabled[spec.kind] = true
	}
	rt.networkEnabled = enabled[providerNetwork]
	rt.processEnabled = enabled[providerProcess]
	rt.dnsEnabled = enabled[providerDNS]
	if len(enabled) == 0 {
		_ = session.Stop()
		return nil, fmt.Errorf("%s", rt.problemSummary())
	}

	consumer := etw.NewRealTimeConsumer(ctx)
	consumer.FromSessions(session)
	consumer.EventRecordCallback = func(rec *etw.EventRecord) bool {
		if rec == nil {
			return false
		}
		id := rec.EventHeader.EventDescriptor.Id
		provider := &rec.EventHeader.ProviderId
		switch {
		case provider.Equals(guidNetwork):
			return network.KnownEvent(id)
		case provider.Equals(guidDNS):
			return id == 3006 || id == 3008
		case provider.Equals(guidProcess):
			return id == 1 || id == 2
		default:
			return false
		}
	}
	consumer.EventCallback = func(ev *etw.Event) error {
		// Never block the ETW consumer thread. Data events can be very frequent;
		// if the bounded queue is full we count the loss and carry on.
		select {
		case rt.events <- ev:
		default:
			rt.dropped.Add(1)
		}
		return nil
	}
	rt.consumer = consumer
	if err := consumer.Start(); err != nil {
		_ = session.Stop()
		return nil, fmt.Errorf("start ETW consumer: %w", err)
	}
	return rt, nil
}

func (rt *etwRuntime) setProblem(kind providerType, problem string) {
	switch kind {
	case providerNetwork:
		rt.networkProblem = problem
	case providerDNS:
		rt.dnsProblem = problem
	case providerProcess:
		rt.processProblem = problem
	}
}

func (rt *etwRuntime) problemSummary() string {
	parts := make([]string, 0, 3)
	if rt.networkProblem != "" {
		parts = append(parts, model.ProviderKernelNetwork+": "+rt.networkProblem)
	}
	if rt.processProblem != "" {
		parts = append(parts, model.ProviderKernelProcess+": "+rt.processProblem)
	}
	if rt.dnsProblem != "" {
		parts = append(parts, model.ProviderDNSClient+": "+rt.dnsProblem)
	}
	if len(parts) == 0 {
		return "unknown error"
	}
	return strings.Join(parts, "; ")
}

func (rt *etwRuntime) stop() error {
	if rt.consumer == nil {
		return nil
	}
	return rt.consumer.Stop()
}

func isAlreadyStopped(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, windows.ERROR_CTX_CLOSE_PENDING) ||
		errors.Is(err, windows.ERROR_WMI_INSTANCE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_INVALID_PARAMETER)
}

func providerKind(ev *etw.Event) providerType {
	name := ev.System.Provider.Name
	switch {
	case strings.EqualFold(name, model.ProviderKernelNetwork):
		return providerNetwork
	case strings.EqualFold(name, model.ProviderDNSClient):
		return providerDNS
	case strings.EqualFold(name, model.ProviderKernelProcess):
		return providerProcess
	}
	guid := &etw.GUID{}
	if parsed, err := etw.ParseGUID(ev.System.Provider.Guid); err == nil && parsed != nil {
		guid = parsed
	}
	switch {
	case guid.Equals(guidNetwork):
		return providerNetwork
	case guid.Equals(guidDNS):
		return providerDNS
	case guid.Equals(guidProcess):
		return providerProcess
	}
	return providerUnknown
}

func eventFields(ev *etw.Event) map[string]string {
	out := make(map[string]string, len(ev.EventData)+len(ev.UserData))
	add := func(m map[string]interface{}) {
		for k, v := range m {
			out[k] = valueString(v)
		}
	}
	add(ev.EventData)
	add(ev.UserData)
	return out
}

func valueString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []string:
		return strings.Join(t, ";")
	case []byte:
		return fmt.Sprintf("%x", t)
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}
