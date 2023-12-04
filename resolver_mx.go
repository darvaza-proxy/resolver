package resolver

import (
	"context"
	"net"

	"darvaza.org/resolver/pkg/errors"
	"github.com/miekg/dns"
)

// LookupMX returns the DNS MX records for the given domain name
// sorted by preference
func (r LookupResolver) LookupMX(ctx context.Context,
	name string) ([]*net.MX, error) {
	var netmxs []*net.MX
	name = dns.Fqdn(name)
	msg, err := r.h.Lookup(ctx, dns.CanonicalName(name), dns.TypeMX)
	if err2 := errors.ValidateResponse("", msg, err); err2 != nil {
		return nil, err2
	}

	ForEachAnswer(msg, func(rr *dns.MX) {
		z := makeNetMX(rr)
		if z != nil {
			netmxs = append(netmxs, z)
		}
	})
	return netmxs, nil
}

func makeNetMX(d *dns.MX) *net.MX {
	if d != nil {
		return &net.MX{
			Pref: d.Preference,
			Host: d.Mx,
		}
	}
	return nil
}
