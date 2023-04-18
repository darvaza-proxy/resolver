package resolver

import (
	"context"
	"net/netip"
	"sync"

	"darvaza.org/core"
	"github.com/miekg/dns"
)

// LookupNetIP looks up host using the assigned Lookuper. It returns a
// slice of that host's IP addresses of the type specified by network.
// The network must be one of "ip", "ip4" or "ip6".
func (r LookupResolver) LookupNetIP(ctx context.Context,
	network, host string) (s []netip.Addr, err error) {
	//
	network, err = sanitiseNetwork(network)
	if err != nil {
		return nil, err
	}

	host, err = sanitiseHost(host)
	if err != nil {
		return nil, err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	return r.doLookupNetIP(ctx, network, host)
}

func (r LookupResolver) doLookupNetIP(ctx context.Context,
	network, host string) ([]netip.Addr, error) {
	//
	qhost := dns.CanonicalName(host)

	switch network {
	case "ip":
		return r.goLookupNetIP(ctx, qhost)
	case "ip4":
		return r.goLookupNetIPq(ctx, qhost, dns.TypeA)
	default:
		return r.goLookupNetIPq(ctx, qhost, dns.TypeAAAA)
	}
}

func (r LookupResolver) goLookupNetIP(ctx context.Context,
	qhost string) ([]netip.Addr, error) {
	//
	var wg sync.WaitGroup
	var s1, s2 []netip.Addr
	var e1, e2 error

	wg.Add(2)
	go func() {
		defer wg.Done()
		s1, e1 = r.goLookupNetIPq(ctx, qhost, dns.TypeA)
	}()
	go func() {
		defer wg.Done()
		s2, e2 = r.goLookupNetIPq(ctx, qhost, dns.TypeAAAA)
	}()
	wg.Wait()

	return append(s1, s2...), coalesceError(e1, e2)
}

func (r LookupResolver) goLookupNetIPq(ctx context.Context,
	qhost string, qType uint16) ([]netip.Addr, error) {
	//
	var wg sync.WaitGroup
	var s1, s3 []netip.Addr
	var e1, e2, e3 error

	wg.Add(2)
	go func() {
		defer wg.Done()
		var msg *dns.Msg
		var e1p error

		msg, e1 = r.h.Lookup(ctx, qhost, qType)
		s1, e1p = msgToNetIPq(msg, qType)

		if e1 == nil {
			e1 = e1p
		}
	}()

	go func() {
		var cname string

		defer wg.Done()

		cname, e2 = r.LookupCNAME(ctx, qhost)
		if cname != "" {
			cname = dns.CanonicalName(cname)
			if cname != qhost {
				s3, e3 = r.goLookupNetIPq(ctx, cname, qType)
			}
		}
	}()
	wg.Wait()

	s := append(s1, s3...)
	core.SliceUniquifyFn(&s, eqNetIP)

	return s, coalesceError(e1, e2, e3)
}

func eqNetIP(ip1, ip2 netip.Addr) bool {
	if res := ip1.Compare(ip2); res == 0 {
		return true
	}
	return false
}

// revive:disable:cognitive-complexity
func msgToNetIPq(m *dns.Msg, qType uint16) ([]netip.Addr, error) {
	// revive:enable:cognitive-complexity
	var s []netip.Addr

	if successMsg(m) {
		switch qType {
		case dns.TypeA:
			ForEachAnswer(m, func(r *dns.A) {
				if ip, ok := netip.AddrFromSlice(r.A); ok {
					s = append(s, ip)
				}
			})
		case dns.TypeAAAA:
			ForEachAnswer(m, func(r *dns.AAAA) {
				if ip, ok := netip.AddrFromSlice(r.AAAA); ok {
					s = append(s, ip)
				}
			})
		}

		if len(s) > 0 {
			return s, nil
		}
	}

	return nil, errBadMessage
}
