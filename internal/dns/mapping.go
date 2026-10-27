// Package dns maps Microsoft-Windows-DNS-Client events to NetTrace DNS records
// and parses the binary QueryResults blob when possible.
package dns

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"nettrace/internal/model"
)

// QueryTypeName returns the conventional mnemonic for a DNS record type.
func QueryTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 13:
		return "HINFO"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 35:
		return "NAPTR"
	case 39:
		return "DNAME"
	case 43:
		return "DS"
	case 46:
		return "RRSIG"
	case 47:
		return "NSEC"
	case 48:
		return "DNSKEY"
	case 64:
		return "SVCB"
	case 65:
		return "HTTPS"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

// StatusText translates the QueryStatus values emitted by DNS-Client. The
// values are a mix of DNS error codes and Winsock getaddrinfo errors.
func StatusText(code uint32) string {
	switch code {
	case 0:
		return "success"
	case 9001:
		return "format_error"
	case 9002:
		return "server_failure"
	case 9003:
		return "name_not_found"
	case 9004:
		return "not_implemented"
	case 9005:
		return "refused"
	case 9010:
		return "not_authoritative"
	case 9501:
		return "no_records"
	case 9502:
		return "bad_key"
	case 9503:
		return "no_question"
	case 1460:
		return "timeout"
	case 11001:
		return "host_not_found"
	case 11002:
		return "try_again"
	case 11003:
		return "no_recovery"
	case 11004:
		return "no_data"
	default:
		return fmt.Sprintf("status_%d", code)
	}
}

// MapRaw converts a completed DNS-Client event (ID 3008) into a DNS record.
// The PID comes from the ETW event header, which is the process that called the
// DNS API (dnsapi.dll emits the event in the caller's context).
func MapRaw(raw model.RawEvent) (*model.DNSQuery, bool) {
	if raw.ID != 3008 || raw.PID == 0 {
		return nil, false
	}
	name := cleanName(raw.Fields["QueryName"])
	if name == "" {
		return nil, false
	}
	qtype, _ := strconv.ParseUint(strings.TrimSpace(raw.Fields["QueryType"]), 0, 16)
	status, _ := strconv.ParseUint(strings.TrimSpace(raw.Fields["QueryStatus"]), 0, 32)
	answers, rawHex := ParseQueryResults(raw.Fields["QueryResults"])
	if len(rawHex) > 2048 {
		rawHex = rawHex[:2048]
	}
	q := &model.DNSQuery{
		PID:           raw.PID,
		QueryName:     name,
		QueryType:     uint16(qtype),
		QueryTypeName: QueryTypeName(uint16(qtype)),
		Status:        uint32(status),
		StatusText:    StatusText(uint32(status)),
		Answers:       answers,
		FirstSeenUTC:  raw.TimeUTC.UTC(),
		LastSeenUTC:   raw.TimeUTC.UTC(),
		Occurrences:   1,
		Source:        model.SourceETWDNS,
		Raw:           rawHex,
	}
	return q, true
}

func cleanName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	if len(name) > 255 {
		name = name[:255]
	}
	return name
}

// ParseQueryResults decodes the QueryResults property. It accepts a hex string
// (the TDH representation of win:Binary) and tries a full DNS message first,
// then a bare answer-record sequence. The second return value is the hex form
// kept in the database for later analysis.
func ParseQueryResults(s string) ([]string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, ""
	}
	b, ok := decodeBinary(s)
	if !ok {
		return parseTextAnswers(s), ""
	}
	rawHex := strings.ToUpper(fmt.Sprintf("%x", b))
	if answers, ok := parseDNSMessage(b); ok {
		return answers, rawHex
	}
	if answers, ok := parseRecordSequence(b); ok {
		return answers, rawHex
	}
	return nil, rawHex
}

func parseTextAnswers(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ';' || r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		part = strings.TrimSpace(part)
		if part == "" || seen[part] {
			continue
		}
		seen[part] = true
		out = append(out, part)
		if len(out) >= 32 {
			break
		}
	}
	return out
}

func decodeBinary(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if strings.ContainsAny(s, "ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ") {
		return nil, false
	}
	replacer := strings.NewReplacer(" ", "", "-", "", ":", "", "\t", "", "\n", "", "\r", "")
	s = replacer.Replace(s)
	if s == "" || len(s)%2 != 0 {
		return nil, false
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, ok1 := hexNibble(s[i*2])
		lo, ok2 := hexNibble(s[i*2+1])
		if !ok1 || !ok2 {
			return nil, false
		}
		out[i] = hi<<4 | lo
	}
	return out, true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func parseDNSMessage(b []byte) ([]string, bool) {
	if len(b) < 12 {
		return nil, false
	}
	flags := uint16(b[2])<<8 | uint16(b[3])
	if flags&0x8000 == 0 {
		return nil, false
	}
	qd := int(uint16(b[4])<<8 | uint16(b[5]))
	an := int(uint16(b[6])<<8 | uint16(b[7]))
	ns := int(uint16(b[8])<<8 | uint16(b[9]))
	ar := int(uint16(b[10])<<8 | uint16(b[11]))
	if qd > 64 || an > 512 || ns > 512 || ar > 512 {
		return nil, false
	}
	off := 12
	var ok bool
	for i := 0; i < qd; i++ {
		if _, off, ok = readName(b, off); !ok {
			return nil, false
		}
		if off+4 > len(b) {
			return nil, false
		}
		off += 4
	}
	answers := make([]string, 0, an)
	seen := map[string]bool{}
	for i := 0; i < an; i++ {
		if _, off, ok = readName(b, off); !ok {
			return nil, false
		}
		if off+10 > len(b) {
			return nil, false
		}
		rtype := uint16(b[off])<<8 | uint16(b[off+1])
		rdlen := int(uint16(b[off+8])<<8 | uint16(b[off+9]))
		off += 10
		if rdlen < 0 || off+rdlen > len(b) {
			return nil, false
		}
		switch rtype {
		case 1:
			if rdlen == 4 {
				addAnswer(&answers, seen, ipv4String(b[off:off+4]))
			}
		case 28:
			if rdlen == 16 {
				addAnswer(&answers, seen, ipv6String(b[off:off+16]))
			}
		case 5:
			if name, _, ok := readName(b, off); ok && name != "" {
				addAnswer(&answers, seen, "cname="+name)
			}
		}
		off += rdlen
	}
	// A valid message with zero answers is still useful (NXDOMAIN, NODATA).
	return answers, true
}

func parseRecordSequence(b []byte) ([]string, bool) {
	off := 0
	answers := make([]string, 0, 4)
	seen := map[string]bool{}
	records := 0
	for off < len(b) {
		name, next, ok := readName(b, off)
		if !ok || next+10 > len(b) {
			return nil, false
		}
		_ = name
		rtype := uint16(b[next])<<8 | uint16(b[next+1])
		rdlen := int(uint16(b[next+8])<<8 | uint16(b[next+9]))
		next += 10
		if rdlen < 0 || next+rdlen > len(b) {
			return nil, false
		}
		switch rtype {
		case 1:
			if rdlen == 4 {
				addAnswer(&answers, seen, ipv4String(b[next:next+4]))
			}
		case 28:
			if rdlen == 16 {
				addAnswer(&answers, seen, ipv6String(b[next:next+16]))
			}
		}
		off = next + rdlen
		records++
		if records > 512 {
			return nil, false
		}
	}
	return answers, records > 0 && len(answers) > 0
}

func readName(b []byte, off int) (string, int, bool) {
	var labels []string
	pos := off
	next := off
	jumps := 0
	first := true
	for {
		if pos < 0 || pos >= len(b) {
			return "", off, false
		}
		l := int(b[pos])
		switch {
		case l == 0:
			if first {
				next = pos + 1
			}
			return strings.Join(labels, "."), next, true
		case l&0xC0 == 0xC0:
			if pos+1 >= len(b) {
				return "", off, false
			}
			ptr := int(uint16(b[pos]&0x3F)<<8 | uint16(b[pos+1]))
			if ptr < 0 || ptr >= len(b) || jumps > 32 {
				return "", off, false
			}
			if first {
				next = pos + 2
				first = false
			}
			pos = ptr
			jumps++
		case l&0xC0 != 0:
			return "", off, false
		default:
			if pos+1+l > len(b) || l > 63 {
				return "", off, false
			}
			labels = append(labels, string(b[pos+1:pos+1+l]))
			if len(labels) > 32 {
				return "", off, false
			}
			pos += 1 + l
			if first {
				next = pos
			}
		}
	}
}

func addAnswer(list *[]string, seen map[string]bool, value string) {
	if value == "" || seen[value] || len(*list) >= 32 {
		return
	}
	seen[value] = true
	*list = append(*list, value)
}

func ipv4String(b []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func ipv6String(b []byte) string {
	// Best effort without importing net/netip: use net.IP formatting via a small
	// helper in this package.
	return formatIPv6(b)
}

// MapUnattributed builds an unattributed DNS record (used only when the user
// explicitly enables --dns-unattributed).
func MapUnattributed(raw model.RawEvent, at time.Time) *model.DNSQuery {
	q := &model.DNSQuery{
		QueryName:     cleanName(raw.Fields["QueryName"]),
		QueryTypeName: QueryTypeName(parseType(raw.Fields["QueryType"])),
		QueryType:     parseType(raw.Fields["QueryType"]),
		Status:        parseStatus(raw.Fields["QueryStatus"]),
		FirstSeenUTC:  at.UTC(),
		LastSeenUTC:   at.UTC(),
		Occurrences:   1,
		Source:        model.SourceETWDNS,
		Attributed:    false,
		Attribution:   "unattributed",
	}
	q.StatusText = StatusText(q.Status)
	answers, rawHex := ParseQueryResults(raw.Fields["QueryResults"])
	if len(rawHex) > 2048 {
		rawHex = rawHex[:2048]
	}
	q.Answers = answers
	q.Raw = rawHex
	if q.QueryName == "" {
		return nil
	}
	return q
}

func parseType(s string) uint16 {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 0, 16)
	if err != nil {
		return 0
	}
	return uint16(v)
}

func parseStatus(s string) uint32 {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 0, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}
