//go:build windows

// Package winproc wraps the Windows process APIs used by NetTrace:
// Toolhelp32 snapshots, image paths, process creation times, local addresses
// and a few informational helpers.
package winproc

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"nettrace/internal/model"
)

const stillActive = 259

// Info describes one process image.
type Info struct {
	PID        uint32
	ParentPID  uint32
	Name       string
	Path       string
	StartUTC   time.Time
	StartKnown bool
}

// Elevated reports whether the current process has an elevated token.
func Elevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// Self returns the current and parent process IDs.
func Self() (uint32, uint32) {
	return windows.GetCurrentProcessId(), 0
}

// List enumerates processes cheaply (PID, parent and executable name).
func List() ([]Info, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("Toolhelp32 snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)

	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(snap, &entry); err != nil {
		return nil, fmt.Errorf("Process32First: %w", err)
	}
	var out []Info
	for {
		out = append(out, Info{
			PID:       entry.ProcessID,
			ParentPID: entry.ParentProcessID,
			Name:      windows.UTF16ToString(entry.ExeFile[:]),
		})
		if err := windows.Process32Next(snap, &entry); err != nil {
			if errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
				break
			}
			return out, fmt.Errorf("Process32Next: %w", err)
		}
	}
	return out, nil
}

// Query returns the full details for one PID.
func Query(pid uint32) (Info, error) {
	list, err := List()
	if err != nil {
		return Info{}, err
	}
	for _, p := range list {
		if p.PID == pid {
			if err := Fill(&p); err != nil {
				return p, err
			}
			return p, nil
		}
	}
	return Info{}, fmt.Errorf("pid %d not found", pid)
}

// Fill adds the image path, parent PID (if missing) and creation time.
func Fill(p *Info) error {
	if p == nil || p.PID == 0 {
		return fmt.Errorf("invalid process info")
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.PID)
	if err != nil {
		return fmt.Errorf("open pid %d: %w", p.PID, err)
	}
	defer windows.CloseHandle(h)

	if p.Path == "" {
		buf := make([]uint16, 32768)
		size := uint32(len(buf))
		if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err == nil {
			p.Path = windows.UTF16ToString(buf[:size])
		}
	}
	if p.Name == "" && p.Path != "" {
		p.Name = filepath.Base(p.Path)
	}
	if !p.StartKnown {
		var creation, exit, kernel, user windows.Filetime
		if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err == nil {
			if t := filetimeToTime(creation); !t.IsZero() {
				p.StartUTC = t
				p.StartKnown = true
			}
		}
	}
	return nil
}

// FindTargets returns the running instances that match the target. Processes
// are filtered by base name before any expensive per-process call.
func FindTargets(t model.Target) ([]Info, error) {
	list, err := List()
	if err != nil {
		return nil, err
	}
	var out []Info
	for _, p := range list {
		if p.Name == "" || !strings.EqualFold(p.Name, t.Name) {
			continue
		}
		if err := Fill(&p); err != nil {
			// Keep the name-only information: a path match cannot be verified
			// but a name match still can. Matches() records the limitation.
			p.Path = ""
			p.StartKnown = false
		}
		if ok, _ := t.Matches(p.Name, p.Path); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// Alive reports whether the process exists and is still running.
func Alive(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}

// ExitCode returns the process exit code if the process has terminated and it
// is still queryable.
func ExitCode(pid uint32) (uint32, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return 0, false
	}
	if code == stillActive {
		return 0, false
	}
	return code, true
}

// LocalAddresses returns a canonical set of local unicast addresses. The
// unspecified addresses are included because unbound sockets report them.
func LocalAddresses() (map[string]bool, error) {
	set := map[string]bool{
		"0.0.0.0":   true,
		"::":        true,
		"127.0.0.1": true,
		"::1":       true,
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return set, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			if addr, ok := netip.AddrFromSlice(ip); ok {
				set[addr.Unmap().String()] = true
			}
		}
	}
	return set, nil
}

// DevicePathToDOS converts an NT device path such as
// "\Device\HarddiskVolume3\Games\game.exe" to "C:\Games\game.exe" using the
// current drive mappings. Paths that are already DOS paths are returned as is.
func DevicePathToDOS(path string) string {
	if path == "" || !strings.HasPrefix(path, `\Device\`) {
		return path
	}
	for _, drive := range dosDrives() {
		if strings.HasPrefix(strings.ToLower(path), strings.ToLower(drive.Device+`\`)) {
			return drive.Letter + path[len(drive.Device):]
		}
	}
	return path
}

type dosDrive struct {
	Letter string // "C:"
	Device string // "\Device\HarddiskVolume3"
}

func dosDrives() []dosDrive {
	var out []dosDrive
	for c := 'A'; c <= 'Z'; c++ {
		letter := string(c) + ":"
		name, err := syscall.UTF16PtrFromString(letter)
		if err != nil {
			continue
		}
		buf := make([]uint16, 1024)
		n, err := windows.QueryDosDevice(name, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			continue
		}
		device := windows.UTF16ToString(buf[:n])
		if device == "" {
			continue
		}
		out = append(out, dosDrive{Letter: letter, Device: strings.TrimRight(device, `\`)})
	}
	return out
}

// OSVersion returns a short Windows version string.
func OSVersion() string {
	v := windows.RtlGetVersion()
	if v == nil {
		return "Windows"
	}
	return fmt.Sprintf("Windows %d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}

// Username returns DOMAIN\user.
func Username() string {
	user := os.Getenv("USERNAME")
	domain := os.Getenv("USERDOMAIN")
	if user == "" {
		return ""
	}
	if domain != "" {
		return domain + `\` + user
	}
	return user
}

// Hostname returns the local computer name.
func Hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// filetimeToTime converts a Windows FILETIME to UTC. windows.Filetime's
// Nanoseconds method already returns nanoseconds since the Unix epoch
// (1970-01-01), so no further offset may be applied.
func filetimeToTime(ft windows.Filetime) time.Time {
	// A zero FILETIME would overflow int64 in Nanoseconds (it subtracts the
	// 1601 offset before multiplying), so reject it before converting.
	if ft.LowDateTime == 0 && ft.HighDateTime == 0 {
		return time.Time{}
	}
	ns := ft.Nanoseconds()
	if ns <= 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).UTC()
}
