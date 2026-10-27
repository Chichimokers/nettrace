//go:build windows

package winproc

import (
	"net"
	"os"
	"testing"
)

// TestNetworkTableIncludesListener verifies the IP Helper parsing end to end:
// a loopback listener owned by this process must appear with the right local
// port, protocol, state and owning PID.
func TestNetworkTableIncludesListener(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	pid := uint32(os.Getpid())

	entries, err := NetworkTable()
	if err != nil {
		t.Fatalf("NetworkTable: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("NetworkTable returned no entries: IP Helper parsing is broken")
	}
	for _, e := range entries {
		if e.PID == pid && e.Proto == "tcp" && e.IPVersion == 4 &&
			e.Local.Addr == "127.0.0.1" && e.Local.Port == port && e.State == "listen" {
			return
		}
	}
	// Help diagnose failures by showing the rows owned by this process.
	for _, e := range entries {
		if e.PID == pid {
			t.Logf("own row: %s v%d %s:%d -> %s:%d state=%s",
				e.Proto, e.IPVersion, e.Local.Addr, e.Local.Port,
				e.Remote.Addr, e.Remote.Port, e.State)
		}
	}
	t.Fatalf("listener 127.0.0.1:%d (pid %d) not found in %d table rows", port, pid, len(entries))
}

// TestNetworkTableHasSystemEntries guards against a silent regression where the
// API succeeds but the row count is read from the wrong offset.
func TestNetworkTableHasSystemEntries(t *testing.T) {
	entries, err := NetworkTable()
	if err != nil {
		t.Fatalf("NetworkTable: %v", err)
	}
	var tcp4, tcp6, udp4, udp6 int
	for _, e := range entries {
		switch {
		case e.Proto == "tcp" && e.IPVersion == 4:
			tcp4++
		case e.Proto == "tcp" && e.IPVersion == 6:
			tcp6++
		case e.Proto == "udp" && e.IPVersion == 4:
			udp4++
		case e.Proto == "udp" && e.IPVersion == 6:
			udp6++
		default:
			t.Fatalf("unexpected row: %+v", e)
		}
	}
	t.Logf("rows: tcp4=%d tcp6=%d udp4=%d udp6=%d", tcp4, tcp6, udp4, udp6)
	if tcp4 == 0 {
		t.Error("no IPv4 TCP rows: a normal Windows system always has some")
	}
	if udp4 == 0 {
		t.Error("no IPv4 UDP rows: a normal Windows system always has some")
	}
}
