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

	return r.doLookupIP(ctx, network, host, true)
}

func (r LookupResolver) doLookupIP(ctx context.Context,
	network, host string, cname bool) ([]net.IP, error) {
	//
	qhost := dns.CanonicalName(host)

	switch network {
	case "ip":
		return r.goLookupIP(ctx, qhost, cname)
	case "ip4":
		return r.goLookupIPq(ctx, qhost, dns.TypeA, cname)
	default:
		return r.goLookupIPq(ctx, qhost, dns.TypeAAAA, cname)
	}
}

func (r LookupResolver) goLookupIP(ctx context.Context,
	qhost string, cname bool) ([]net.IP, error) {
	//
	var wg sync.WaitGroup
	var s1, s2 []net.IP
	var e1, e2 error

	wg.Add(2)
	go func() {
		defer wg.Done()
		s1, e1 = r.goLookupIPq(ctx, qhost, dns.TypeA, cname)
	}()
	go func() {
		defer wg.Done()
		s2, e2 = r.goLookupIPq(ctx, qhost, dns.TypeAAAA, cname)
	}()
	wg.Wait()

	s := append(s1, s2...)
	switch {
	case len(s) > 0:
		return s, nil
	case e1 != nil:
		return nil, e1
	case e2 != nil:
		return nil, e2
	default:
		return nil, ErrNotFound(qhost)
	}
}

// revive:disable:flag-parameter
func (r LookupResolver) goLookupIPq(ctx context.Context,
	qHost string, qType uint16, cname bool) ([]net.IP, error) {
	// revive:enable:flag-parameter
	var wg sync.WaitGroup
	var s1, s2 []net.IP
	var e1, e2 error

	wg.Add(1)
	go func() {
		defer wg.Done()
		s1, e1 = r.lookupIPq(ctx, qHost, qType)
	}()

	if cname {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s2, e2 = r.lookupIPqCNAME(ctx, qHost, qType)
		}()
	}

	wg.Wait()

	s := append(s1, s2...)
	switch {
	case len(s) > 0:
		core.SliceUniquifyFn(&s, eqIP)
		return s, nil
	case e1 != nil:
		return nil, e1
	case e2 != nil:
		return nil, e2
	default:
		return nil, ErrNotFound(qHost)
	}
}

func (r LookupResolver) lookupIPq(ctx context.Context,
	qHost string, qType uint16) ([]net.IP, error) {
	//
	msg, e1 := r.h.Lookup(ctx, qHost, qType)
	s, e2 := msgToIPq(msg, qType)

	switch {
	case len(s) > 0:
		return s, nil
	case e1 != nil:
		return nil, e1
	default:
		e2.Name = qHost
		return nil, e2
	}
}

func (r LookupResolver) lookupIPqCNAME(ctx context.Context,
	qHost string, qType uint16) ([]net.IP, error) {
	//
	cname, e1 := r.doLookupCNAME(ctx, qHost)

	select {
	case <-ctx.Done():
		return nil, ErrTimeout(qHost, ctx.Err())
	default:
	}

	if cname != "" {
		cname = dns.CanonicalName(cname)
		if cname != qHost {
			return r.goLookupIPq(ctx, cname, qType, false)
		}
	}

	return nil, e1
}

// revive:disable:cognitive-complexity
func msgToIPq(m *dns.Msg, qType uint16) ([]net.IP, *net.DNSError) {
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

		return nil, ErrNotFound("")
	}

	return nil, ErrBadResponse()
}
