//go:build windows

package winproc

import (
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Endpoint is an IP address plus port.
type Endpoint struct {
	Addr string
	Port uint16
}

// TableEntry is one row of the IP Helper TCP/UDP owner tables.
type TableEntry struct {
	Proto     string // "tcp" or "udp"
	IPVersion int    // 4 or 6
	Local     Endpoint
	Remote    Endpoint
	State     string
	PID       uint32
}

const (
	afInet  = 2
	afInet6 = 23

	tcpTableOwnerPidAll = 5
	udpTableOwnerPid    = 1

	errorInsufficientBuffer = syscall.Errno(122)
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

// mibTCPRow mirrors MIB_TCPROW_OWNER_PID.
type mibTCPRow struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

// mibTCP6Row mirrors MIB_TCP6ROW_OWNER_PID.
type mibTCP6Row struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

// mibUDPRow mirrors MIB_UDPROW_OWNER_PID.
type mibUDPRow struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

// mibUDP6Row mirrors MIB_UDP6ROW_OWNER_PID.
type mibUDP6Row struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	OwningPID    uint32
}

// NetworkTable reads the current TCP/UDP owner tables. This is the documented
// IP Helper fallback used when ETW is unavailable or loses its session. It is a
// snapshot: short-lived connections can be missed entirely.
func NetworkTable() ([]TableEntry, error) {
	var out []TableEntry

	tcp4, err := readTCPTable(afInet, tcpTableOwnerPidAll)
	if err != nil {
		return nil, err
	}
	for _, r := range tcp4 {
		out = append(out, TableEntry{
			Proto: "tcp", IPVersion: 4,
			Local:  Endpoint{Addr: ipv4FromDWORD(r.LocalAddr), Port: portFromDWORD(r.LocalPort)},
			Remote: Endpoint{Addr: ipv4FromDWORD(r.RemoteAddr), Port: portFromDWORD(r.RemotePort)},
			State:  tcpStateName(r.State), PID: r.OwningPID,
		})
	}

	tcp6, err := readTCP6Table()
	if err != nil {
		return out, err
	}
	for _, r := range tcp6 {
		out = append(out, TableEntry{
			Proto: "tcp", IPVersion: 6,
			Local:  Endpoint{Addr: ipv6FromBytes(r.LocalAddr), Port: portFromDWORD(r.LocalPort)},
			Remote: Endpoint{Addr: ipv6FromBytes(r.RemoteAddr), Port: portFromDWORD(r.RemotePort)},
			State:  tcpStateName(r.State), PID: r.OwningPID,
		})
	}

	udp4, err := readUDPTable()
	if err != nil {
		return out, err
	}
	for _, r := range udp4 {
		out = append(out, TableEntry{
			Proto: "udp", IPVersion: 4,
			Local:  Endpoint{Addr: ipv4FromDWORD(r.LocalAddr), Port: portFromDWORD(r.LocalPort)},
			Remote: Endpoint{Addr: "0.0.0.0", Port: 0},
			State:  "bound", PID: r.OwningPID,
		})
	}

	udp6, err := readUDP6Table()
	if err != nil {
		return out, err
	}
	for _, r := range udp6 {
		out = append(out, TableEntry{
			Proto: "udp", IPVersion: 6,
			Local:  Endpoint{Addr: ipv6FromBytes(r.LocalAddr), Port: portFromDWORD(r.LocalPort)},
			Remote: Endpoint{Addr: "::", Port: 0},
			State:  "bound", PID: r.OwningPID,
		})
	}
	return out, nil
}

func readTCPTable(af, class uint32) ([]mibTCPRow, error) {
	buf, err := readTable(procGetExtendedTcpTable, af, class)
	if err != nil {
		return nil, err
	}
	count, ok := tableCount(buf, int(unsafe.Sizeof(mibTCPRow{})), 4)
	if !ok {
		return nil, nil
	}
	rows := unsafe.Slice((*mibTCPRow)(unsafe.Pointer(&buf[4])), count)
	out := make([]mibTCPRow, count)
	copy(out, rows)
	return out, nil
}

func readTCP6Table() ([]mibTCP6Row, error) {
	buf, err := readTable(procGetExtendedTcpTable, afInet6, tcpTableOwnerPidAll)
	if err != nil {
		return nil, err
	}
	count, ok := tableCount(buf, int(unsafe.Sizeof(mibTCP6Row{})), 4)
	if !ok {
		return nil, nil
	}
	rows := unsafe.Slice((*mibTCP6Row)(unsafe.Pointer(&buf[4])), count)
	out := make([]mibTCP6Row, count)
	copy(out, rows)
	return out, nil
}

func readUDPTable() ([]mibUDPRow, error) {
	buf, err := readTable(procGetExtendedUdpTable, afInet, udpTableOwnerPid)
	if err != nil {
		return nil, err
	}
	count, ok := tableCount(buf, int(unsafe.Sizeof(mibUDPRow{})), 4)
	if !ok {
		return nil, nil
	}
	rows := unsafe.Slice((*mibUDPRow)(unsafe.Pointer(&buf[4])), count)
	out := make([]mibUDPRow, count)
	copy(out, rows)
	return out, nil
}

func readUDP6Table() ([]mibUDP6Row, error) {
	buf, err := readTable(procGetExtendedUdpTable, afInet6, udpTableOwnerPid)
	if err != nil {
		return nil, err
	}
	count, ok := tableCount(buf, int(unsafe.Sizeof(mibUDP6Row{})), 4)
	if !ok {
		return nil, nil
	}
	rows := unsafe.Slice((*mibUDP6Row)(unsafe.Pointer(&buf[4])), count)
	out := make([]mibUDP6Row, count)
	copy(out, rows)
	return out, nil
}

func readTable(proc *windows.LazyProc, af, class uint32) ([]byte, error) {
	var size uint32
	ret, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0,
		uintptr(af), uintptr(class), 0)
	if syscall.Errno(ret) != errorInsufficientBuffer {
		if ret != 0 {
			return nil, fmt.Errorf("size query failed: %w", syscall.Errno(ret))
		}
		if size == 0 {
			return nil, nil
		}
	}
	for attempt := 0; attempt < 4; attempt++ {
		if size == 0 {
			size = 4096
		}
		buf := make([]byte, size)
		ret, _, _ = proc.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0, uintptr(af), uintptr(class), 0)
		if ret == 0 {
			return buf, nil
		}
		if syscall.Errno(ret) != errorInsufficientBuffer {
			return nil, fmt.Errorf("table query failed: %w", syscall.Errno(ret))
		}
		size += 4096
	}
	return nil, fmt.Errorf("table query kept returning ERROR_INSUFFICIENT_BUFFER")
}

func tableCount(buf []byte, rowSize, headerSize int) (int, bool) {
	if len(buf) < headerSize {
		return 0, false
	}
	count := int(*(*uint32)(unsafe.Pointer(&buf[0])))
	if count <= 0 {
		return 0, false
	}
	if headerSize+count*rowSize > len(buf) {
		return 0, false
	}
	return count, true
}

func ipv4FromDWORD(v uint32) string {
	// The DWORD is stored in network byte order; reading it as a little-endian
	// integer reverses the octets.
	return netip.AddrFrom4([4]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}).String()
}

func ipv6FromBytes(b [16]byte) string {
	addr, ok := netip.AddrFromSlice(b[:])
	if !ok {
		return ""
	}
	return addr.Unmap().String()
}

func portFromDWORD(v uint32) uint16 {
	p := uint16(v & 0xffff)
	return p<<8 | p>>8
}

func tcpStateName(state uint32) string {
	switch state {
	case 1:
		return "closed"
	case 2:
		return "listen"
	case 3:
		return "syn_sent"
	case 4:
		return "syn_received"
	case 5:
		return "established"
	case 6:
		return "fin_wait_1"
	case 7:
		return "fin_wait_2"
	case 8:
		return "close_wait"
	case 9:
		return "closing"
	case 10:
		return "last_ack"
	case 11:
		return "time_wait"
	case 12:
		return "delete_tcb"
	default:
		return fmt.Sprintf("state_%d", state)
	}
}
