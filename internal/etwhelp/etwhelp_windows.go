//go:build windows

// Package etwhelp contains small helpers around the golang-etw library.
package etwhelp

import (
	"fmt"
	"syscall"

	"github.com/0xrawsec/golang-etw/etw"
)

// ProviderAvailable reports whether a provider manifest is registered on this
// machine. It does not require elevation.
func ProviderAvailable(name string) bool {
	p := etw.ResolveProvider(name)
	return !p.IsZero() && p.GUID != ""
}

// ProviderGUID returns the GUID registered for name, or "".
func ProviderGUID(name string) string {
	return etw.ResolveProvider(name).GUID
}

// SessionAlive asks ETW whether the named real-time session still exists.
func SessionAlive(name string) (bool, error) {
	props := etw.NewRealTimeEventTraceSessionProperties(name)
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}
	if err := etw.ControlTrace(0, namePtr, props, etw.EVENT_TRACE_CONTROL_QUERY); err != nil {
		return false, fmt.Errorf("query ETW session %q: %w", name, err)
	}
	return true, nil
}
