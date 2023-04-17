// Package resolver provides DNS lookup functions
package resolver

import (
	"context"
	"errors"
	"net"

	"github.com/miekg/dns"
)

var (
	_ Resolver = (*LookupResolver)(nil)

	_ Lookuper = (*ZeroLookuper)(nil)
)

var (
	errNotImplemented = errors.New("not implemented")
	errBadMessage     = errors.New("bad DNS message")
	errBadType        = errors.New("bad DNS question type")
)

// A ZeroLookuper is a Lookuper that never finds anything
type ZeroLookuper struct{}

// Lookup implements Lookuper but always fails
func (ZeroLookuper) Lookup(_ context.Context, qName string, _ uint16) (*dns.Msg, error) {
	err := &net.DNSError{
		Err:  "no answer",
		Name: qName,
	}
	return nil, err
}

// NewResolver returns a Resolver using the provided Lookuper
func NewResolver(h Lookuper) *LookupResolver {
	if h == nil {
		return nil
	}
	return &LookupResolver{h: h}
}

// LookupResolver uses a Lookuper to implement the Resolver inteface
type LookupResolver struct {
	h Lookuper
}

// LookupIPAddr returns the IP addresses of a host
func (LookupResolver) LookupIPAddr(_ context.Context,
	_ string,
) ([]net.IPAddr, error) {
	//
	return nil, errNotImplemented
}

// LookupIP returns the IP addresses of a host
func (LookupResolver) LookupIP(_ context.Context,
	_, _ string,
) ([]net.IP, error) {
	//
	return nil, errNotImplemented
}

// LookupAddr performs a reverse lookup for the given address, returning a
// list of names mapping to that address
func (LookupResolver) LookupAddr(_ context.Context,
	_ string,
) ([]string, error) {
	//
	return nil, errNotImplemented
}

// LookupCNAME returns the final canonical name after following zero or
// more CNAME records
func (LookupResolver) LookupCNAME(_ context.Context,
	_ string,
) (string, error) {
	//
	return "", errNotImplemented
}

// LookupHost returns a slice of the host's addresses
func (LookupResolver) LookupHost(_ context.Context,
	_ string,
) (addrs []string, err error) {
	//
	return nil, errNotImplemented
}

// LookupMX returns the DNS MX records for the given domain name
// sorted by preference
func (LookupResolver) LookupMX(_ context.Context,
	_ string,
) ([]*net.MX, error) {
	//
	return nil, errNotImplemented
}

// LookupNS returns the DNS NS records for the given domain name
func (LookupResolver) LookupNS(_ context.Context,
	_ string,
) ([]*net.NS, error) {
	//
	return nil, errNotImplemented
}

// LookupSRV returns the DNS SRV for _service._proto.domain
func (LookupResolver) LookupSRV(_ context.Context,
	_, _, _ string,
) (cname string, addrs []*net.SRV, err error) {
	//
	return "", nil, errNotImplemented
}
