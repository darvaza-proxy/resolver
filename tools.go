package resolver

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"darvaza.org/core"
	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

func successMsg(m *dns.Msg) bool {
	if m != nil && m.Rcode == dns.RcodeSuccess && len(m.Answer) > 0 {
		return true
	}
	return false
}

func validateResp(server string, r *dns.Msg, err error) error {
	name := nameFromMsg(r, "unknown")

	if e, ok := err.(*net.DNSError); ok {
		// pass through
		if e.Server == "" {
			e.Server = server
		}
		return e
	}

	if err != nil {
		// TODO: extract information from err.(type)
		var timeout bool
		var temporary bool
		var notfound bool

		return &net.DNSError{
			Err:         err.Error(),
			Server:      server,
			Name:        name,
			IsTimeout:   timeout,
			IsTemporary: temporary,
			IsNotFound:  notfound,
		}
	}

	if r.Truncated {
		return &net.DNSError{
			Err:    "dns response was truncated",
			Server: server,
			Name:   name,
		}
	}

	if r.Rcode != dns.RcodeSuccess {
		// TODO: decipher Rcode
		var timeout bool
		var temporary bool
		var notfound bool

		return &net.DNSError{
			Err:         dns.RcodeToString[r.Rcode],
			Server:      server,
			Name:        name,
			IsTimeout:   timeout,
			IsTemporary: temporary,
			IsNotFound:  notfound,
		}
	}

	// Success
	return nil
}

func nameFromMsg(msg *dns.Msg, fallback string) string {
	for _, q := range msg.Question {
		if len(q.Name) > 0 {
			return q.Name
		}
	}
	return fallback
}

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

func sanitiseHost(host string) (string, error) {
	if host != "" {
		s, err := idna.Display.ToASCII(host)
		if err != nil {
			return "", core.Wrapf(err, "%q: invalid host", host)
		}
		return s, nil
	}

	return "", errors.New("empty host")
}

func coalesceError(err ...error) error {
	for _, e := range err {
		if e != nil {
			return e
		}
	}
	return nil
}

func eqIP(ip1, ip2 net.IP) bool {
	return ip1.Equal(ip2)
}

// ForEachAnswer calls a function for each answer of the specified type.
func ForEachAnswer[T any](msg *dns.Msg, fn func(v T)) {
	if fn == nil || msg == nil {
		return
	}

	for _, ans := range msg.Answer {
		if v, ok := ans.(T); ok {
			fn(v)
		}
	}
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

	if addr, err := core.ParseAddr(server); err != nil {
		return "", err
	} else if addr.Is6() {
		return fmt.Sprintf("[%s]:%s", host, port), nil
	} else {
		return host + ":" + port, nil
	}
}
