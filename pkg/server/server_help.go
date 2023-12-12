package server

import (
	"io"
	"net"
	"net/netip"

	"darvaza.org/core"
	"github.com/miekg/dns"
)

// AddrPortStrings converts a slice of [netip.AddrPort] into
// a slice of strings
func AddrPortStrings(s []netip.AddrPort) []string {
	out := make([]string, 0, len(s))
	for _, ap := range s {
		out = append(out, ap.String())
	}
	return out
}

// CloseAll closes all the given objects, discarding
// errors
func CloseAll[T io.Closer](s []T) {
	for _, p := range s {
		_ = p.Close()
	}
}

// DNSServerAddr attempts to extract transport and listening
// address from a [dns.Server].
func DNSServerAddr(s *dns.Server) (string, net.Addr, bool) {
	switch {
	case s == nil:
		return "undefined", nil, false
	case s.PacketConn != nil:
		return "udp", s.PacketConn.LocalAddr(), true
	case s.Listener == nil:
		return "undefined", nil, false
	case s.TLSConfig == nil:
		return "tcp", s.Listener.Addr(), true
	default:
		return "tcp+tls", s.Listener.Addr(), true
	}
}

// ParsePortAddr parses a list of host-port entries,
// using the given port if no port is specified, and assuming
// wildcard when nothing is provided.
func ParsePortAddr(defaultPort uint16, values ...string) ([]netip.AddrPort, error) {
	if len(values) == 0 {
		values = []string{"0"}
	}

	out := make([]netip.AddrPort, 0, len(values))

	for _, s := range values {
		// sanitize
		addr, port, err := core.SplitAddrPort(s)
		switch {
		case err != nil:
			// bad entry
			return nil, err
		case port == 0:
			// no port
			port = defaultPort
		}

		out = append(out, netip.AddrPortFrom(addr, port))
	}

	return out, nil
}
