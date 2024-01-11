package resolver

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"

	"darvaza.org/core"
	"darvaza.org/slog"

	"darvaza.org/resolver/pkg/client"
	"darvaza.org/resolver/pkg/errors"
	"darvaza.org/resolver/pkg/exdns"
)

var (
	_ Lookuper  = (*RootLookuper)(nil)
	_ Exchanger = (*RootLookuper)(nil)
	_ Lookuper  = (*IteratorLookuper)(nil)
	_ Exchanger = (*IteratorLookuper)(nil)
)

var roots = map[string]string{
	"a.root-servers.net": "198.41.0.4",
	"b.root-servers.net": "170.247.170.2",
	"c.root-servers.net": "192.33.4.12",
	"d.root-servers.net": "199.7.91.13",
	"e.root-servers.net": "192.203.230.10",
	"f.root-servers.net": "192.5.5.241",
	"g.root-servers.net": "192.112.36.4",
	"h.root-servers.net": "198.97.190.53",
	"i.root-servers.net": "192.36.148.17",
	"j.root-servers.net": "192.58.128.30",
	"k.root-servers.net": "193.0.14.129",
	"l.root-servers.net": "199.7.83.42",
	"m.root-servers.net": "202.12.27.33",
}

// deadline used when the iterator needs to make extra queries
// not governed by the initial Lookup/Exchange.
const iteratorDeadline = 1 * time.Second

// RootLookuper does iterative lookup using the root servers.
type RootLookuper struct {
	l *IteratorLookuper
}

// NewRootLookuper creates a RootLookuper using the indicated root, or random
// if the argument is ""
func NewRootLookuper(start string) (*RootLookuper, error) {
	return safeNewRootLookuper(start, nil)
}

// NewRootLookuperWithClient creates a RootLookuper using the indicated root, or
// random if the argument is "", and uses the given [client.Client] to connect.
func NewRootLookuperWithClient(start string, c client.Client) (*RootLookuper, error) {
	return safeNewRootLookuper(start, c)
}

func safeNewRootLookuper(start string, c client.Client) (*RootLookuper, error) {
	var err error

	l := NewIteratorLookuper("root", 0, c)

	if start == "" {
		err = l.AddRootServers()
	} else {
		err = l.AddFrom(".", 0, start)
	}

	if err != nil {
		return nil, err
	}

	return &RootLookuper{
		l: l,
	}, nil
}

// NewRootResolver creates a LookupResolver using iterative lookup from a given root-server,
// or random if the argument is ""
func NewRootResolver(start string) (*LookupResolver, error) {
	h, err := NewRootLookuper(start)
	if err != nil {
		return nil, err
	}
	return NewResolver(h), nil
}

// Lookup performs an iterative lookup
func (r RootLookuper) Lookup(ctx context.Context, qName string, qType uint16) (*dns.Msg, error) {
	return r.l.Lookup(ctx, qName, qType)
}

// Exchange queries any root server and validates the response
func (r RootLookuper) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	return r.l.Exchange(ctx, m)
}

// DisableAAAA prevents the use of IPv6 entries on NS glue.
func (r RootLookuper) DisableAAAA() {
	r.l.DisableAAAA()
}

// IteratorLookuper is a generic iterative lookuper, caching zones
// glue and NS information.
type IteratorLookuper struct {
	c    client.Client
	nsc  *NSCache
	aaaa bool
}

// SetPersistent flags a zone for being restored automatically
// if evicted.
func (r *IteratorLookuper) SetPersistent(qName string) error {
	return r.nsc.SetPersistence(qName, true)
}

// AddRootServers loads the embedded table of root servers,
// and made persistent.
func (r *IteratorLookuper) AddRootServers() error {
	return r.AddMapPersistent(".", 518400, roots)
}

// AddMap loads NS servers from a map
func (r *IteratorLookuper) AddMap(qName string, ttl uint32, servers map[string]string) error {
	if !r.aaaa {
		servers = r.mapWithoutAAAA(servers)
	}
	return r.nsc.AddMap(qName, ttl, servers)
}

// AddMapPersistent loads NS servers from a map but prevents it from being permanently evicted.
func (r *IteratorLookuper) AddMapPersistent(qName string, ttl uint32,
	servers map[string]string) error {
	//
	err := r.AddMap(qName, ttl, servers)
	if err != nil {
		return err
	}

	return r.SetPersistent(qName)
}

// AddServer loads NS servers from a list.
func (r *IteratorLookuper) AddServer(qName string, ttl uint32, servers ...string) error {
	zone, err := r.newManualZone(qName, servers...)
	if err == nil {
		zone.SetTTL(ttl, ttl/2)
		err = r.nsc.Add(zone)
	}

	if err != nil {
		return core.Wrap(err, "%q: failed to create zone", qName)
	}
	return nil
}

// AddFrom asks the specified server for the NS servers.
func (r *IteratorLookuper) AddFrom(qName string, ttl uint32, server ...string) error {
	// assemble temporary NSCacheZone
	zone, err := r.newManualZone(qName, server...)
	if err == nil {
		err = r.nsc.Add(zone)
	}

	if err != nil {
		return core.Wrap(err, "%q: failed to create zone", qName)
	}

	// pull the real information
	deadline := time.Now().Add(iteratorDeadline)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	resp, err := r.lookupAddFrom(ctx, qName)
	if err != nil {
		r.nsc.Evict(qName)
		return err
	}

	// assemble final Zone
	zone, err = NewNSCacheZoneFromNS(resp)
	if err == nil {
		zone.SetTTL(ttl, ttl/2)
		err = r.getGlue(ctx, zone)
	}

	if err == nil {
		err = r.nsc.Add(zone)
	}

	if err != nil {
		r.nsc.Evict(qName)
		return core.Wrap(err, "%q: failed to create zone", qName)
	}

	return nil
}

func (r *IteratorLookuper) lookupAddFrom(ctx context.Context, qName string) (*dns.Msg, error) {
	resp, err := r.Lookup(ctx, qName, dns.TypeNS)
	if err2 := exdns.ValidateResponse("", resp, err); err2 != nil {
		return nil, err2
	}

	// Authoritative answers only
	if !resp.Authoritative {
		return nil, core.Wrap(core.ErrInvalid, "not authoritative")
	}

	// Remove AAAA if we don't support it
	if !r.aaaa {
		resp = r.responseWithoutAAAA(resp)
	}

	return resp, nil
}

func (r *IteratorLookuper) newManualZone(qName string, servers ...string) (*NSCacheZone, error) {
	var nameTemplate string

	// servers
	addrs, err := r.ParseAddrs(servers)
	switch {
	case err != nil:
		return nil, err
	case len(addrs) == 0:
		return nil, errors.New("no servers specified")
	}

	// names
	if qName == "." {
		nameTemplate = "fake-ns%v.root-servers.net."
	} else {
		nameTemplate = "fake-ns%v." + qName
	}

	// assemble
	zone := NewNSCacheZone(qName)
	for i, ip := range addrs {
		name := fmt.Sprintf(nameTemplate, i)
		if !zone.AddGlueNS(name, ip) {
			panic("unreachable")
		}
	}

	return zone, nil
}

// DisableAAAA prevents the use of IPv6 entries on NS glue.
func (r *IteratorLookuper) DisableAAAA() {
	r.aaaa = false
}

// SetLogger sets [NSCache]'s logger. [slog.Debug] is used to record
// when entries are added or removed.
func (r *IteratorLookuper) SetLogger(log slog.Logger) {
	r.nsc.SetLogger(log)
}

// Lookup performs an iterative lookup
func (r *IteratorLookuper) Lookup(ctx context.Context,
	name string, qType uint16) (*dns.Msg, error) {
	//
	if ctx == nil {
		return nil, errors.ErrBadRequest()
	}

	req := exdns.NewRequestFromParts(dns.Fqdn(name), dns.ClassINET, qType)
	return r.doIterate(ctx, req)
}

// Exchange queries any root server and validates the response
func (r *IteratorLookuper) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if ctx == nil || req == nil {
		return nil, errors.ErrBadRequest()
	}

	q := msgQuestion(req)
	if q == nil {
		// nothing to answer
		msg := new(dns.Msg)
		msg.SetReply(req)
		return msg, nil
	}

	// sanitize request
	req2 := exdns.NewRequestFromParts(q.Name, q.Qclass, q.Qtype)

	// TODO: preserve EDNS0_SUBNET
	// TODO: any other option useful/safe on the original request to cherry-pick?

	resp, err := r.doIterate(ctx, req2)
	return exdns.RestoreReturn(req, resp, err)
}

func (r *IteratorLookuper) doIterate(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	for {
		resp, err := r.doIteratePass(ctx, req)
		switch {
		case err != nil:
			// failed
			return nil, err
		case r.responseIsFinal(resp):
			return resp, nil
		}
	}
}

func (r *IteratorLookuper) doIteratePass(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	resp, err := r.doExchange(ctx, req)
	switch {
	case err != nil:
		return nil, err
	case resp == nil:
		return nil, errors.ErrBadResponse()
	case resp.Rcode == dns.RcodeSuccess:
		return r.handleSuccess(ctx, req, resp)
	default:
		return nil, errors.ErrBadResponse()
	}
}

func (r *IteratorLookuper) handleSuccess(ctx context.Context,
	req, resp *dns.Msg) (*dns.Msg, error) {
	//
	switch {
	case len(resp.Answer) > 0:
		return r.handleSuccessAnswer(ctx, req, resp)
	case exdns.HasNsType(resp, dns.TypeNS):
		return r.handleSuccessDelegation(ctx, req, resp)
	case exdns.HasNsType(resp, dns.TypeSOA):
		return handleSuccessNoData(resp)
	default:
		return nil, errors.ErrBadResponse()
	}
}

func (r *IteratorLookuper) doExchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return r.nsc.ExchangeWithClient(ctx, req, r.c)
	}
}

func handleSuccessNoData(resp *dns.Msg) (*dns.Msg, error) {
	if resp.Authoritative {
		// We have a NODATA response with Authority section
		// from an authoritative server, so pass it on for the Auth section
		return resp, nil
	}

	return nil, errors.ErrBadResponse()
}

func (r *IteratorLookuper) handleSuccessAnswer(ctx context.Context,
	req, resp *dns.Msg) (*dns.Msg, error) {
	//
	if exdns.HasAnswerType(resp, msgQType(req)) {
		// we got what we asked for
		return resp, nil
	}

	// we asked for some type but we got back a CNAME so
	// we need to query further with the same type but the
	// new name.
	if rr := exdns.GetFirstAnswer[*dns.CNAME](resp); rr != nil {
		return r.handleCNAMEAnswer(ctx, req, resp, rr.Target)
	}

	return nil, errors.ErrBadResponse()
}

func (r *IteratorLookuper) handleCNAMEAnswer(ctx context.Context,
	req, resp *dns.Msg, cname string) (*dns.Msg, error) {
	// assemble request for information about the CNAME
	q := msgQuestion(req)
	req2 := exdns.NewRequestFromParts(dns.Fqdn(cname), q.Qclass, q.Qtype)

	// reuse OPTs
	exdns.ForEachRR(req.Extra, func(rr dns.RR) {
		req2.Extra = append(req2.Extra, rr)
	})

	// ask
	resp2, err := r.Exchange(ctx, req2)
	if err != nil {
		// failed, return what we had.
		return resp, nil
	}

	// merge
	resp3 := r.mergeCNAMEAnswer(resp, resp2)
	return resp3, nil
}

func (IteratorLookuper) mergeCNAMEAnswer(resp1, resp2 *dns.Msg) *dns.Msg {
	resp := resp1.Copy()
	exdns.ForEachRR(resp2.Answer, func(rr dns.RR) {
		resp.Answer = append(resp.Answer, rr)
	})
	exdns.ForEachRR(resp2.Ns, func(rr dns.RR) {
		resp.Ns = append(resp.Ns, rr)
	})
	exdns.ForEachRR(resp2.Extra, func(rr dns.RR) {
		switch rr.Header().Rrtype {
		case dns.TypeA, dns.TypeAAAA:
			resp.Extra = append(resp.Extra, rr)
		}
	})

	return resp
}

func (r *IteratorLookuper) handleSuccessDelegation(ctx context.Context,
	_, resp *dns.Msg) (*dns.Msg, error) {
	//
	ns, ok := exdns.GetFirstRR[*dns.NS](resp.Ns)
	if !ok {
		panic("unreachable")
	}

	name := ns.Header().Name
	if _, _, ok := r.nsc.Get(name); !ok {
		// not cached
		_, err := r.addDelegation(ctx, resp)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func (r *IteratorLookuper) addDelegation(ctx context.Context, resp *dns.Msg) (bool, error) {
	if !r.aaaa {
		resp = r.responseWithoutAAAA(resp)
	}

	zone, err := NewNSCacheZoneFromDelegation(resp)
	if err != nil {
		return false, err
	}

	if !zone.HasGlue() {
		err = r.getGlue(ctx, zone)
	}

	if err == nil {
		err = r.nsc.Add(zone)
	}

	return err == nil, err
}

// revive:disable:cognitive-complexity
func (r *IteratorLookuper) getGlue(ctx context.Context,
	zone *NSCacheZone) error {
	// revive:enable:cognitive-complexity
	var wg sync.WaitGroup

	deadline := time.Now().Add(iteratorDeadline)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	spawnGoGetGlue := func(qName string, qType uint16) {
		wg.Add(1)

		go func() {
			defer wg.Done()
			r.goGetGlue(ctx, qName, qType, zone)
		}()
	}

	zone.ForEachNS(func(qName string, addrs []netip.Addr) {
		switch {
		case len(addrs) > 0:
			return
		case dns.IsSubDomain(zone.name, qName):
			return
		}

		spawnGoGetGlue(qName, dns.TypeA)
		if r.aaaa {
			spawnGoGetGlue(qName, dns.TypeAAAA)
		}
	})

	wg.Wait()

	if !zone.HasGlue() {
		// nothing
		return errors.ErrTimeout(zone.name, nil)
	}

	return nil
}

func (r *IteratorLookuper) goGetGlue(ctx context.Context,
	qName string, qType uint16, zone *NSCacheZone) bool {
	//
	var addrs []netip.Addr

	resp, err := r.Lookup(ctx, qName, qType)
	if err != nil {
		return false
	}

	eqAddr := func(a, b netip.Addr) bool {
		return a.Compare(b) == 0
	}

	exdns.ForEachAnswer(resp, func(rr dns.RR) {
		ip, ok := r.getIPfromRR(rr)
		if ok && !core.SliceContainsFn(addrs, ip, eqAddr) {
			addrs = append(addrs, ip)
		}
	})

	if len(addrs) > 0 {
		return zone.SetGlue(qName, addrs)
	}
	return false
}

func (r *IteratorLookuper) getIPfromRR(rr dns.RR) (netip.Addr, bool) {
	switch v := rr.(type) {
	case *dns.A:
		return netip.AddrFromSlice(v.A)
	case *dns.AAAA:
		if r.aaaa {
			return netip.AddrFromSlice(v.AAAA)
		}
	}
	return netip.Addr{}, false
}

func (r *IteratorLookuper) responseIsFinal(resp *dns.Msg) bool {
	q := msgQuestion(resp)
	if q == nil || len(resp.Answer) > 0 {
		// no questions, or answers.
		return true
	}

	ns, ok := exdns.GetFirstRR[*dns.NS](resp.Ns)
	if ok {
		_, _, cached := r.nsc.Get(ns.Hdr.Name)
		if cached {
			// another loop
			return false
		}
	}

	return true
}

func (*IteratorLookuper) responseHasAAAA(resp *dns.Msg) bool {
	for _, rr := range resp.Answer {
		if rrIsAAAA(rr) {
			return true
		}
	}

	for _, rr := range resp.Extra {
		if rrIsAAAA(rr) {
			return true
		}
	}

	return false
}

func (r *IteratorLookuper) responseWithoutAAAA(resp *dns.Msg) *dns.Msg {
	if !r.responseHasAAAA(resp) {
		// return as-is
		return resp
	}

	// copy and remove
	resp2 := resp.Copy()
	removeAAAA := func(_ []dns.RR, rr dns.RR) (dns.RR, bool) {
		return rr, !rrIsAAAA(rr)
	}

	resp2.Answer = core.SliceReplaceFn(resp2.Answer, removeAAAA)
	resp2.Extra = core.SliceReplaceFn(resp2.Extra, removeAAAA)
	return resp2
}

func (*IteratorLookuper) mapWithoutAAAA(original map[string]string) map[string]string {
	// copy and remove AAAA entries
	m := make(map[string]string)
	for k, s := range original {
		ip, _ := core.ParseAddr(s)
		if ip.IsValid() && ip.Is4() {
			m[k] = s
		}
	}
	return m
}

// ParseAddrs parses a list of addresses, and returns the
// acceptable ones and the first error.
func (r *IteratorLookuper) ParseAddrs(servers []string) ([]netip.Addr, error) {
	var out = make([]netip.Addr, 0, len(servers))
	var err error

	for _, s := range servers {
		ip, ok, e := r.ParseAddr(s)
		switch {
		case ok:
			out = append(out, ip)
		case err == nil:
			err = e
		}
	}

	return out, err
}

// ParseAddr parses an address and returns if it's acceptable considering
// if AAAA is enabled or not.
func (r *IteratorLookuper) ParseAddr(server string) (netip.Addr, bool, error) {
	ip, err := core.ParseAddr(server)
	if ip.IsValid() {
		if r.aaaa || ip.Is4() {
			return ip, true, nil
		}
	}
	return ip, false, err
}

// NewIteratorLookuper creates a new [IteratorLookuper].
// name and maxRR are used to assemble the [NSCache].
func NewIteratorLookuper(name string, maxRR uint, c client.Client) *IteratorLookuper {
	if c == nil {
		// use default singleflight client
		c1 := client.NewDefaultClient(0)
		c = client.NewSingleFlight(c1, 0)
	}

	iter := &IteratorLookuper{
		c:    c,
		nsc:  NewNSCache(name, maxRR),
		aaaa: client.HasIPv6Support(),
	}
	return iter
}
