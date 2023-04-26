// Package resolver provides DNS lookup functions
package resolver

import (
	"context"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

var (
	_ Resolver = (*LookupResolver)(nil)

	_ Lookuper = (*ZeroLookuper)(nil)
)

// A ZeroLookuper is a Lookuper that never finds anything
type ZeroLookuper struct{}

// Lookup implements Lookuper but always fails
func (ZeroLookuper) Lookup(_ context.Context, qName string, _ uint16) (*dns.Msg, error) {
	return nil, ErrTimeoutMessage(qName, "no answer")
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

// LookupAddr performs a reverse lookup for the given address, returning a
// list of names mapping to that address
func (LookupResolver) LookupAddr(_ context.Context,
	name string,
) ([]string, error) {
	//
	return nil, ErrNotImplemented(name)
}

// LookupHost returns a slice of the host's addresses
func (LookupResolver) LookupHost(_ context.Context,
	name string,
) (addrs []string, err error) {
	//
	return nil, ErrNotImplemented(name)
}

// LookupMX returns the DNS MX records for the given domain name
// sorted by preference
func (LookupResolver) LookupMX(_ context.Context,
	name string,
) ([]*net.MX, error) {
	//
	return nil, ErrNotImplemented(name)
}

// LookupNS returns the DNS NS records for the given domain name
func (LookupResolver) LookupNS(_ context.Context,
	name string,
) ([]*net.NS, error) {
	//
	return nil, ErrNotImplemented(name)
}

// LookupSRV returns the DNS SRV for _service._proto.domain
func (LookupResolver) LookupSRV(_ context.Context,
	service, proto, name string,
) (cname string, addrs []*net.SRV, err error) {
	//
	host := fmt.Sprintf("_%s._%s.%s", service, proto, name)
	return "", nil, ErrNotImplemented(host)
}
