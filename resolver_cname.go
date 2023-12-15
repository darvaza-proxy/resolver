package resolver

import (
	"context"
	"net"

	"darvaza.org/core"
	"github.com/miekg/dns"

	"darvaza.org/resolver/pkg/errors"
)

// LookupCNAME returns the final canonical name after following zero or
// more CNAME records
func (r LookupResolver) LookupCNAME(ctx context.Context,
	host string) (string, error) {
	//
	host, err := sanitiseHost(host, r.strict)
	if err != nil {
		return "", err
	}

	qName := dns.CanonicalName(host)
	cname, e2 := r.doLookupCNAME(ctx, qName)
	switch {
	case e2 == nil:
		return Decanonize(cname), nil
	case !e2.IsNotFound:
		return "", e2
	}

	// No CNAME, but does it have addresses?
	var addrs []net.IP
	addrs, err = r.doLookupIP(ctx, netIP4or6, qName, false)
	switch {
	case err != nil:
		return "", err
	case len(addrs) > 0:
		return host, nil
	default:
		return "", e2
	}
}

func (r LookupResolver) doLookupCNAME(ctx context.Context,
	host string) (string, *net.DNSError) {
	//
	var visited []string
	var found bool

	qName := host
	for !core.SliceContains(visited, qName) {
		visited = append(visited, qName)

		// try once
		name, err := r.stepLookupCNAME(ctx, qName)
		switch {
		case err == nil:
			if name == qName {
				// end of the line
				return qName, nil
			}

			// new candidate
			found = true
			qName = dns.CanonicalName(name)
		case err.IsNotFound && found:
			// happy with what we got
			return qName, nil
		default:
			return "", err
		}
	}

	err := &net.DNSError{
		Err:  "CNAME loop",
		Name: host,
	}
	return "", err
}

func (r LookupResolver) stepLookupCNAME(ctx context.Context, qName string) (string, *net.DNSError) {
	//
	var cname string

	// Expired?
	select {
	case <-ctx.Done():
		return "", errors.ErrTimeout(qName, ctx.Err())
	default:
	}

	msg, err := r.h.Lookup(ctx, qName, dns.TypeCNAME)
	if e2 := errors.ValidateResponse("", msg, err); e2 != nil {
		return "", e2
	}

	ForEachAnswer(msg, func(v *dns.CNAME) {
		if len(v.Target) > 0 {
			cname = v.Target
		}
	})

	switch {
	case cname == "":
		// No CNAME answer
		return "", errors.ErrNotFound(qName)
	default:
		return sanitiseHost2(cname, r.strict)
	}
}
