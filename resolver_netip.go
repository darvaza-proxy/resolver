package resolver

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"darvaza.org/core"
	"github.com/miekg/dns"
)

// LookupIPAddr returns the IP addresses of a host
// in the form of a slice of net.IPAddr
func (r LookupResolver) LookupIPAddr(ctx context.Context,
	host string) ([]net.IPAddr, error) {
	//
	addrs, err := r.LookupIP(ctx, "ip", host)
	out := make([]net.IPAddr, 0, len(addrs))

	for _, ip := range addrs {
		out = append(out, net.IPAddr{IP: ip})
	}

	return out, err
}

// LookupNetIP looks up host using the assigned Lookuper. It returns a
// slice of that host's IP addresses of the type specified by network.
// The network must be one of "ip", "ip4" or "ip6".
func (r LookupResolver) LookupNetIP(ctx context.Context,
	network, host string) ([]netip.Addr, error) {
	//
	addrs, err := r.LookupIP(ctx, network, host)
	out := make([]netip.Addr, 0, len(addrs))

	for _, ip := range addrs {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			if addr.IsValid() {
				out = append(out, addr)
			}
		}
	}

	return out, err
}

// LookupIP returns the IP addresses of a host
// in the form of a slice of net.IP.
// The network must be one of "ip", "ip4" or "ip6".
func (r LookupResolver) LookupIP(ctx context.Context,
	network, host string) (s []net.IP, err error) {
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

	return r.doLookupIP(ctx, network, host)
}

func (r LookupResolver) doLookupIP(ctx context.Context,
	network, host string) ([]net.IP, error) {
	//
	qhost := dns.CanonicalName(host)

	switch network {
	case "ip":
		return r.goLookupIP(ctx, qhost)
	case "ip4":
		return r.goLookupIPq(ctx, qhost, dns.TypeA)
	default:
		return r.goLookupIPq(ctx, qhost, dns.TypeAAAA)
	}
}

func (r LookupResolver) goLookupIP(ctx context.Context,
	qhost string) ([]net.IP, error) {
	//
	var wg sync.WaitGroup
	var s1, s2 []net.IP
	var e1, e2 error

	wg.Add(2)
	go func() {
		defer wg.Done()
		s1, e1 = r.goLookupIPq(ctx, qhost, dns.TypeA)
	}()
	go func() {
		defer wg.Done()
		s2, e2 = r.goLookupIPq(ctx, qhost, dns.TypeAAAA)
	}()
	wg.Wait()

	return append(s1, s2...), coalesceError(e1, e2)
}

func (r LookupResolver) goLookupIPq(ctx context.Context,
	qhost string, qType uint16) ([]net.IP, error) {
	//
	var wg sync.WaitGroup
	var s1, s3 []net.IP
	var e1, e2, e3 error

	wg.Add(2)
	go func() {
		defer wg.Done()
		var msg *dns.Msg
		var e1p error

		msg, e1 = r.h.Lookup(ctx, qhost, qType)
		s1, e1p = msgToIPq(msg, qType)

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
				s3, e3 = r.goLookupIPq(ctx, cname, qType)
			}
		}
	}()
	wg.Wait()

	s := append(s1, s3...)
	core.SliceUniquifyFn(&s, eqIP)

	return s, coalesceError(e1, e2, e3)
}

// revive:disable:cognitive-complexity
func msgToIPq(m *dns.Msg, qType uint16) ([]net.IP, error) {
	// revive:enable:cognitive-complexity
	if successMsg(m) {
		var s []net.IP

		switch qType {
		case dns.TypeA:
			ForEachAnswer(m, func(r *dns.A) {
				s = append(s, r.A)
			})
		case dns.TypeAAAA:
			ForEachAnswer(m, func(r *dns.AAAA) {
				s = append(s, r.AAAA)
			})
		}

		if len(s) > 0 {
			return s, nil
		}
	}

	return nil, errBadMessage
}
