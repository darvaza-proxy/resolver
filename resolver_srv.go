package resolver

import (
	"context"
	"net"

	"github.com/miekg/dns"
)

// LookupSRV returns the DNS SRV for _service._proto.domain
func (r LookupResolver) LookupSRV(ctx context.Context,
	service, proto, name string) (string, []*net.SRV, error) {
	target := ""
	var netsrvs []*net.SRV

	if service == "" && proto == "" {
		target = name
	} else {
		target = "_" + service + "._" + proto + "." + name
	}
	target = dns.Fqdn(target)

	msg, err := r.h.Lookup(ctx, dns.CanonicalName(target), dns.TypeSRV)

	if err2 := validateResp("", msg, err); err2 != nil {
		return "", nil, err2
	}

	ForEachAnswer(msg, func(rr *dns.SRV) {
		z := makeNetSRV(rr)
		if z != nil {
			netsrvs = append(netsrvs, z)
		}
	})
	return target, netsrvs, nil
}

func makeNetSRV(d *dns.SRV) *net.SRV {
	if d != nil {
		return &net.SRV{
			Target:   d.Target,
			Port:     d.Port,
			Priority: d.Priority,
			Weight:   d.Weight,
		}
	}
	return nil
}
