package resolver

import (
	"context"
	"net"
	"net/netip"

	"github.com/miekg/dns"

	"darvaza.org/resolver/pkg/errors"
	"darvaza.org/resolver/pkg/exdns"
)

// A DialerFunc is a function that establishes TCP or UDP connection
type DialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

// A Resolver implements the interface of net.Resolver
type Resolver interface {
	// LookupIPAddr looks up host using the assigned Lookuper.
	// It returns a slice of that host's IPv4 and IPv6 addresses.
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)

	// LookupIP looks up host for the given network using assigned Lookuper
	// It returns a slice of that host's IP addresses of the type specified
	// by network. network must be one of "ip", "ip4" or "ip6".
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)

	// LookupNetIP looks up host using the assigned Lookuper. It returns a
	// slice of that host's IP addresses of the type specified by network.
	// The network must be one of "ip", "ip4" or "ip6".
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)

	// LookupAddr performs a reverse lookup for the given address, returning a list
	// of names mapping to that address.
	//
	// The returned names are validated to be properly formatted presentation-format
	// domain names. If the response contains invalid names, those records are
	// filtered out and an error will be returned alongside the remaining results,
	// if any.
	LookupAddr(ctx context.Context, addr string) ([]string, error)

	// LookupCNAME returns the canonical name for the given host. Callers that do not
	// care about the canonical name can call LookupHost or LookupIP directly; both
	// take care of resolving the canonical name as part of the lookup.
	// A canonical name is the final name after following zero or more CNAME records.
	// LookupCNAME does not return an error if host does not contain DNS "CNAME"
	// records, as long as host resolves to address records.
	// The returned canonical name is validated to be a properly formatted
	// presentation-format domain name.
	LookupCNAME(ctx context.Context, host string) (string, error)

	// LookupHost looks up the given host using the assigned Lookuper. It returns a
	// slice of that host's addresses.
	LookupHost(ctx context.Context, host string) (addrs []string, err error)

	// LookupMX returns the DNS MX records for the given domain name sorted by
	// preference.
	// The returned mail server names are validated to be properly formatted
	// presentation-format domain names. If the response contains invalid names,
	// those records are filtered out and an error will be returned alongside
	// the remaining results, if any.
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)

	// LookupNS returns the DNS NS records for the given domain name.
	// The returned name server names are validated to be properly formatted
	// presentation-format domain names. If the response contains invalid names,
	// those records are filtered out and an error will be returned alongside
	// the remaining results, if any.
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)

	// LookupSRV tries to resolve an SRV query of the given service, protocol,
	// and domain name. The proto is "tcp" or "udp". The returned records are
	// sorted by priority and randomized by weight within a priority.
	//
	// LookupSRV constructs the DNS name to look up following RFC 2782. That is,
	// it looks up _service._proto.name. To accommodate services publishing SRV
	// records under non-standard names, if both service and proto are empty
	// strings, LookupSRV looks up name directly.
	//
	// The returned service names are validated to be properly formatted
	// presentation-format domain names. If the response contains invalid names,
	// those records are filtered out and an error will be returned alongside
	// the remaining results, if any.
	LookupSRV(ctx context.Context, service, proto, name string) (cname string,
		addrs []*net.SRV, err error)

	// LookupTXT returns the DNS TXT records for the given domain name.
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Lookuper is the interface that wraps the basic iterative Lookup method.
type Lookuper interface {
	Lookup(ctx context.Context, qName string, qType uint16) (*dns.Msg, error)
}

// LookuperFunc is a function that implements the [Lookuper] interface
type LookuperFunc func(context.Context, string, uint16) (*dns.Msg, error)

// Lookup implements the [Lookuper] interface
func (fn LookuperFunc) Lookup(ctx context.Context, qName string, qType uint16) (*dns.Msg, error) {
	return fn(ctx, qName, qType)
}

// Exchange implements the [Exchanger] interface using a [Lookuper] function
func (fn LookuperFunc) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if msg != nil && len(msg.Question) > 0 {
		q := msg.Question[0]
		return fn(ctx, q.Name, q.Qtype)
	}

	return nil, errors.ErrBadRequest()
}

// Exchanger performs a Lookup using a pre-assembled [dns.Msg] question.
type Exchanger interface {
	Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error)
}

// ExchangerFunc is a function that implements the [Exchanger] interface
type ExchangerFunc func(context.Context, *dns.Msg) (*dns.Msg, error)

// Exchange implements the [Exchanger] interface
func (fn ExchangerFunc) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	return fn(ctx, msg)
}

// Lookup implements the [Lookuper] interface using an [Exchanger] function
func (fn ExchangerFunc) Lookup(ctx context.Context, qName string, qType uint16) (*dns.Msg, error) {
	msg := exdns.NewRequestFromParts(dns.Fqdn(qName), dns.ClassINET, qType)
	return fn(ctx, msg)
}
