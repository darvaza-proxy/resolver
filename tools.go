package resolver

import (
	"fmt"
	"net"
	"strings"

	"darvaza.org/core"
	"github.com/miekg/dns"
	"golang.org/x/net/idna"

	"darvaza.org/resolver/pkg/errors"
)

func sanitiseNetwork(network string) (string, error) {
	s := strings.ToLower(network)
	switch s {
	case "":
		return "ip", nil
	case "ip", "ip4", "ip6":
		return s, nil
	default:
		return "", fmt.Errorf("%q: invalid network", network)
	}
}

func sanitiseHost(host string, p *idna.Profile) (string, error) {
	if host != "" {
		s, err := p.ToASCII(host)
		if err != nil {
			return "", core.Wrap(err, "%q: invalid host", host)
		}
		return s, nil
	}

	return "", errors.New("empty host")
}

func sanitiseHost2(host string, p *idna.Profile) (string, *net.DNSError) {
	s, err := sanitiseHost(host, p)
	if err == nil {
		return s, nil
	}

	return "", &net.DNSError{
		Name: host,
		Err:  err.Error(),
	}
}

func eqIP(ip1, ip2 net.IP) bool {
	return ip1.Equal(ip2)
}

func isIP4(s string) bool {
	addr, err := core.ParseAddr(s)
	if err != nil || !addr.IsValid() {
		return false
	}
	return addr.Is4()
}

func msgQuestion(m *dns.Msg) *dns.Question {
	if m != nil && len(m.Question) > 0 {
		return &m.Question[0]
	}
	return nil
}

func msgQName(m *dns.Msg) string {
	if q := msgQuestion(m); q != nil {
		return q.Name
	}
	return ""
}

func msgQType(m *dns.Msg) uint16 {
	if q := msgQuestion(m); q != nil {
		return q.Qtype
	}
	return 0
}

func msgQClass(m *dns.Msg) uint16 {
	if q := msgQuestion(m); q != nil {
		return q.Qclass
	}
	return 0
}

// Decanonize removes the trailing . if present, unless
// it's the root dot
func Decanonize(qname string) string {
	if l := len(qname); l > 1 {
		if qname[l-1] == '.' {
			return qname[:l-1]
		}
	}
	return qname
}

// ForEachAnswer calls a function for each answer of the specified type.
func ForEachAnswer[T dns.RR](msg *dns.Msg, fn func(v T)) {
	if fn == nil || msg == nil {
		return
	}

	for _, ans := range msg.Answer {
		if v, ok := ans.(T); ok {
			fn(v)
		}
	}
}

// GetFirstAnswer returns the first answer for a specified type
func GetFirstAnswer[T dns.RR](msg *dns.Msg) T {
	var zero T

	if msg != nil {
		for _, ans := range msg.Answer {
			if v, ok := ans.(T); ok {
				return v
			}
		}
	}

	return zero
}

// HasAnswerType checks if a [dns.Msg] contains answers of the
// specified type.
func HasAnswerType(msg *dns.Msg, qType uint16) bool {
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == qType {
			return true
		}
	}
	return false
}

// AsServerAddress validates and optionally appends :53 port if
// it wasn't specified already
func AsServerAddress(server string) (string, error) {
	host, port, err := core.SplitHostPort(server)
	if err != nil {
		return "", err
	}

	if port == "" {
		port = "53"
	}

	addr, err := core.ParseAddr(host)
	switch {
	case err != nil:
		return "", err
	case addr.Is6():
		return fmt.Sprintf("[%s]:%s", host, port), nil
	default:
		return host + ":" + port, nil
	}
}
