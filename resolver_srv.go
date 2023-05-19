package resolver

import (
	"context"
	"fmt"
	"net"
	"sort"

	"github.com/miekg/dns"
)

// LookupSRV returns the DNS SRV for _service._proto.domain
func (r LookupResolver) LookupSRV(ctx context.Context,
	service, proto, name string) (string, []*net.SRV, error) {
	//
	if ctx == nil {
		ctx = context.Background()
	}

	target, err := r.sanitiseTargetSRV(service, proto, name)
	if err != nil {
		return "", nil, err
	}

	netsrvs, err := r.doLookupSRV(ctx, target)
	return dns.Fqdn(name), netsrvs, err
}

func (r LookupResolver) sanitiseTargetSRV(service, proto, name string) (string, error) {
	var target string

	switch {
	case service != "" && proto != "":
		target = "_" + service + "._" + proto + "." + name
	case service != "":
		target = "_" + service + "." + name
	case proto != "":
		return "", fmt.Errorf("%q: proto (%q) can't be specified without service for SRV", name, proto)
	default:
		target = name
	}

	return sanitiseHost(dns.Fqdn(target), r.loose)
}

func (r LookupResolver) doLookupSRV(ctx context.Context,
	host string) ([]*net.SRV, error) {
	//
	var err error

	msg, e1 := r.h.Lookup(ctx, dns.CanonicalName(host), dns.TypeSRV)
	srv, e2 := msgToSRV(msg)

	switch {
	case len(srv) > 0:
		err = nil
	case e1 != nil:
		err = e1
	case e2 != nil:
		e2.Name = host
		err = e2
	default:
		err = ErrNotFound(host)
	}

	return srv, err
}

func msgToSRV(msg *dns.Msg) ([]*net.SRV, *net.DNSError) {
	if successMsg(msg) {
		var out []*net.SRV
		var err *net.DNSError

		ForEachAnswer(msg, func(rr *dns.SRV) {
			srv := &net.SRV{
				Target:   rr.Target,
				Port:     rr.Port,
				Priority: rr.Priority,
				Weight:   rr.Weight,
			}

			if e := validateSRV(srv); e != nil {
				// bad
				err = e
			} else {
				// good
				out = append(out, srv)
			}
		})

		switch {
		case len(out) > 0:
			return sortSRV(out), nil
		case err != nil:
			return nil, err
		}
	}
	return nil, ErrBadResponse()
}

func validateSRV(_ *net.SRV) *net.DNSError {
	// TODO: implement sanity checks
	return nil
}

func sortSRV(srv []*net.SRV) []*net.SRV {
	sort.Slice(srv, func(i, j int) bool {
		a, b := srv[i], srv[j]

		switch {
		case a.Priority < b.Priority:
			return true
		case a.Priority > b.Priority:
			return false
		default:
			return a.Weight < b.Weight
		}
	})
	return srv
}
