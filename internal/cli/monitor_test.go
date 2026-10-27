//go:build windows

package cli

import (
	"strings"
	"testing"

	"nettrace/internal/collector"
	"nettrace/internal/model"
)

func statsWith(sources map[string]string, details map[string]string, enabled bool, problem string) collector.Stats {
	return collector.Stats{
		ETWEnabled:    enabled,
		ETWProblem:    problem,
		Sources:       sources,
		SourceDetails: details,
	}
}

func allRunning() collector.Stats {
	return statsWith(map[string]string{
		model.SourceETWNetwork: model.SourceRunning,
		model.SourceETWProcess: model.SourceRunning,
		model.SourceETWDNS:     model.SourceRunning,
	}, map[string]string{}, true, "")
}

func TestETWSummaryFull(t *testing.T) {
	got := etwSummary(allRunning())
	want := "active (Kernel-Network, Kernel-Process, DNS-Client)"
	if got != want {
		t.Errorf("etwSummary = %q; want %q", got, want)
	}
}

func TestETWSummaryPartial(t *testing.T) {
	stats := statsWith(map[string]string{
		model.SourceETWNetwork: model.SourceError,
		model.SourceETWProcess: model.SourceError,
		model.SourceETWDNS:     model.SourceRunning,
	}, map[string]string{
		model.SourceETWNetwork: "Access is denied.",
		model.SourceETWProcess: "Access is denied.",
	}, true, "")
	got := etwSummary(stats)
	if !strings.HasPrefix(got, "partially active;") {
		t.Fatalf("etwSummary = %q; want a partial state", got)
	}
	for _, want := range []string{"DNS-Client", "Kernel-Network (Access is denied.)", "Kernel-Process (Access is denied.)"} {
		if !strings.Contains(got, want) {
			t.Errorf("etwSummary %q is missing %q", got, want)
		}
	}
	if strings.Contains(got, "active (Kernel-Network, Kernel-Process, DNS-Client)") {
		t.Error("partial ETW was reported as fully active")
	}
}

func TestETWSummaryInactive(t *testing.T) {
	stats := statsWith(map[string]string{
		model.SourceETWNetwork: model.SourceUnavailable,
		model.SourceETWProcess: model.SourceUnavailable,
		model.SourceETWDNS:     model.SourceUnavailable,
	}, nil, false, "disabled with --no-etw")
	if got := etwSummary(stats); got != "inactive - disabled with --no-etw" {
		t.Errorf("etwSummary = %q", got)
	}
}

func TestCompletenessTextTracksNetworkSource(t *testing.T) {
	if got := completenessText(allRunning()); !strings.Contains(got, "buffer loss") {
		t.Errorf("full ETW completeness = %q", got)
	}
	partial := statsWith(map[string]string{
		model.SourceETWNetwork: model.SourceError,
		model.SourceETWProcess: model.SourceRunning,
		model.SourceETWDNS:     model.SourceRunning,
	}, nil, true, "")
	if got := completenessText(partial); !strings.Contains(got, "IP Helper") {
		t.Errorf("partial ETW completeness = %q; want a sampling caveat", got)
	}
	disabled := statsWith(map[string]string{
		model.SourceETWNetwork: model.SourceUnavailable,
		model.SourceETWProcess: model.SourceUnavailable,
		model.SourceETWDNS:     model.SourceUnavailable,
	}, nil, false, "no provider")
	if got := completenessText(disabled); !strings.Contains(got, "DNS is not collected") {
		t.Errorf("disabled ETW completeness = %q", got)
	}
}

func TestBuildFinalNoteDoesNotClaimETWWhenPartial(t *testing.T) {
	partial := statsWith(map[string]string{
		model.SourceETWNetwork: model.SourceError,
		model.SourceETWProcess: model.SourceError,
		model.SourceETWDNS:     model.SourceRunning,
	}, map[string]string{
		model.SourceETWNetwork: "Access is denied.",
		model.SourceETWProcess: "Access is denied.",
	}, true, "")
	note := buildFinalNote(false, partial, 0, "", 0)
	if strings.Contains(note, "ETW sources were active") {
		t.Errorf("note claimed full ETW coverage: %q", note)
	}
	if !strings.Contains(note, "partially available") || !strings.Contains(note, "Access is denied.") {
		t.Errorf("note does not explain the partial state: %q", note)
	}
	if strings.Contains(note, "ETW buffers can still lose data") {
		t.Errorf("note claimed an ETW buffer caveat although network ETW was down: %q", note)
	}
}
