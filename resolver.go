// Package resolver provides DNS lookup functions
package resolver

import (
	"context"
	"net"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"

	"darvaza.org/resolver/pkg/errors"
)

var (
	_ Resolver = (*LookupResolver)(nil)

	_ Lookuper = (*ZeroLookuper)(nil)
)

// A ZeroLookuper is a Lookuper that never finds anything
type ZeroLookuper struct{}

// Lookup implements Lookuper but always fails
func (ZeroLookuper) Lookup(_ context.Context, qName string, _ uint16) (*dns.Msg, error) {
	return nil, errors.ErrTimeoutMessage(qName, errors.NOANSWER)
}

// NewResolver returns a Resolver using the provided Lookuper
func NewResolver(h Lookuper) *LookupResolver {
	if h == nil {
		return nil
	}
	strict := idna.Lookup
	loose := idna.New(
		idna.MapForLookup(),
		idna.StrictDomainName(false))
	return &LookupResolver{h: h, strict: strict, loose: loose}
}

// LookupResolver uses a Lookuper to implement the Resolver inteface
type LookupResolver struct {
	h      Lookuper
	strict *idna.Profile
	loose  *idna.Profile
}

// LookupAddr performs a reverse lookup for the given address, returning a
// list of names mapping to that address
func (LookupResolver) LookupAddr(_ context.Context,
	name string,
) ([]string, error) {
	//
	return nil, errors.ErrNotImplemented(name)
}

// LookupHost returns a slice of the host's addresses
func (LookupResolver) LookupHost(_ context.Context,
	name string,
) (addrs []string, err error) {
	//
	return nil, errors.ErrNotImplemented(name)
}

// LookupNS returns the DNS NS records for the given domain name
func (LookupResolver) LookupNS(_ context.Context,
	name string,
) ([]*net.NS, error) {
	//
	return nil, errors.ErrNotImplemented(name)
}
