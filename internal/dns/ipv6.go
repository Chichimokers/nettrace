package dns

import "net"

// formatIPv6 renders 16 raw bytes using the standard compressed notation.
func formatIPv6(b []byte) string {
	if len(b) != net.IPv6len {
		return ""
	}
	return net.IP(b).String()
}
