package resolver

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"

	"darvaza.org/core"

	"darvaza.org/resolver/pkg/errors"
	"darvaza.org/resolver/pkg/exdns"
)

const (
	// MinimumNSCacheTTL tells the minimum time, in seconds,
	// entries remain in the cache
	MinimumNSCacheTTL = 10
)

// NSCacheZone represents the NS data and glue for a domain name.
type NSCacheZone struct {
	mu       sync.Mutex
	name     string
	ns       []string
	sortedNS []string
	glue     map[string][]netip.Addr

	ttl      uint32
	until    time.Time
	halfLife time.Time

	s map[string]string
}

// Name returns the domain name associated to these servers.
func (zone *NSCacheZone) Name() string {
	return zone.name
}

// Expire tells when this information is no long valid.
func (zone *NSCacheZone) Expire() time.Time {
	return zone.until
}

// TTL returns the number of seconds the data has to live.
func (zone *NSCacheZone) TTL() uint32 {
	now := time.Now()
	duration := now.Sub(zone.until)
	if duration > 0 {
		return uint32(duration / time.Second)
	}
	return 0
}

// OriginalTTL returns the number of seconds the data was
// set to live initially.
func (zone *NSCacheZone) OriginalTTL() uint32 {
	return zone.ttl
}

// NeedsRefresh tells when this information should be refreshed.
func (zone *NSCacheZone) NeedsRefresh() bool {
	return time.Now().After(zone.halfLife)
}

// Len returns the number of dns.RR entries stored.
func (zone *NSCacheZone) Len() int {
	return len(zone.ns) + len(zone.glue)
}

// IsValid tells if a zone can be stored.
func (zone *NSCacheZone) IsValid() bool {
	switch {
	case zone == nil || len(zone.ns) == 0 || len(zone.glue) == 0:
		return false
	case zone.name == "":
		return false
	default:
		return true
	}
}

// SetTTL sets the expiration and half-life times in
// seconds from Now.
func (zone *NSCacheZone) SetTTL(ttl, half uint32) {
	switch {
	case ttl == 0 && half == 0:
		// apply defaults
		ttl = MinimumNSCacheTTL
		half = ttl / 2
	case ttl < MinimumNSCacheTTL:
		// too short, but preserve the half-life value.
		ttl = MinimumNSCacheTTL
	}

	if half >= ttl {
		// half-life needs to be lower than the maximum.
		half = ttl / 2
	}

	zone.mu.Lock()
	defer zone.mu.Unlock()

	zone.unsafeSetTTL(ttl, half)
}

func (zone *NSCacheZone) unsafeSetTTL(ttl, half uint32) {
	now := time.Now().UTC()
	zone.ttl = ttl
	zone.until = now.Add(time.Duration(ttl) * time.Second)
	zone.halfLife = now.Add(time.Duration(half) * time.Second)
}

// Index processes the zone data and prepares it to be used.
func (zone *NSCacheZone) Index() {
	zone.mu.Lock()
	defer zone.mu.Unlock()

	if zone.ttl == 0 {
		zone.unsafeSetTTL(MinimumNSCacheTTL, MinimumNSCacheTTL/2)
	}

	zone.sortedNS = make([]string, len(zone.ns))
	copy(zone.sortedNS, zone.ns)
	sort.Strings(zone.sortedNS)

	for k, addrs := range zone.glue {
		zone.glue[k] = nsCacheSortAddr(addrs)
	}
	zone.s = nsCacheGlueMap(zone.glue)
}

// ExportNS produces a [dns.RR] slice containing all the NS
// entries
func (zone *NSCacheZone) ExportNS() []dns.RR {
	ttl := zone.TTL()

	zone.mu.Lock()
	defer zone.mu.Unlock()

	out := make([]dns.RR, len(zone.ns))
	for i, name := range zone.ns {
		out[i] = &dns.NS{
			Hdr: dns.RR_Header{
				Name:   zone.name,
				Class:  dns.ClassINET,
				Rrtype: dns.TypeNS,
				Ttl:    ttl,
			},
			Ns: name,
		}
	}

	return out
}

// ExportGlue produces a [dns.RR] slice containing all the
// A/AAAA entries known for this zone.
func (zone *NSCacheZone) ExportGlue() []dns.RR {
	var out []dns.RR

	ttl := zone.TTL()

	zone.mu.Lock()
	defer zone.mu.Unlock()

	for _, name := range zone.sortedNS {
		for _, ip := range zone.glue[name] {
			rr, ok := newGlueRR(name, ttl, ip)
			if ok {
				out = append(out, rr)
			}
		}
	}

	return out
}

func newGlueRR(name string, ttl uint32, ip netip.Addr) (dns.RR, bool) {
	var rr dns.RR
	switch {
	case !ip.IsValid():
		// skip
	case ip.Is6():
		rr = &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   name,
				Class:  dns.ClassINET,
				Rrtype: dns.TypeAAAA,
				Ttl:    ttl,
			},
			AAAA: ip.AsSlice(),
		}
	default:
		rr = &dns.A{
			Hdr: dns.RR_Header{
				Name:   name,
				Class:  dns.ClassINET,
				Rrtype: dns.TypeA,
				Ttl:    ttl,
			},
			A: ip.AsSlice(),
		}
	}

	return rr, rr != nil
}

// Addrs produces a sorted string array containing
// all the A/AAAA entries known for this zone.
func (zone *NSCacheZone) Addrs() []string {
	var addrs []netip.Addr

	zone.mu.Lock()
	for _, s := range zone.glue {
		addrs = append(addrs, s...)
	}
	zone.mu.Unlock()

	sort.Slice(addrs, func(i, j int) bool {
		return addrs[i].Compare(addrs[j]) < 0
	})

	out := make([]string, len(addrs))
	for i, ip := range addrs {
		out[i] = ip.String()
	}

	return out
}

// RandomAddrs produces a randomly shuffled strings array
// containing all the A/AAAA entries known for this zone
func (zone *NSCacheZone) RandomAddrs() []string {
	zone.mu.Lock()
	out := make([]string, 0, len(zone.s))
	for _, s := range zone.s {
		out = append(out, s)
	}
	zone.mu.Unlock()

	return out
}

// Servers produces a string array containing all the
// NS entries known for this zone.
func (zone *NSCacheZone) Servers() []string {
	zone.mu.Lock()
	defer zone.mu.Lock()

	out := make([]string, len(zone.ns))
	copy(out, zone.ns)
	return out
}

// Server returns one address chosen randomly or
// and empty string if there is none.
func (zone *NSCacheZone) Server() string {
	zone.mu.Lock()
	defer zone.mu.Unlock()

	for _, s := range zone.s {
		return s
	}

	return ""
}

// AddNS adds the name of a NS to the zone, and returns true
// if it's new.
func (zone *NSCacheZone) AddNS(name string) bool {
	if name == "" || name == "." {
		// invalid
		// TODO: validate further
		return false
	}

	name = dns.Fqdn(name)

	zone.mu.Lock()
	defer zone.mu.Unlock()

	if _, ok := zone.glue[name]; ok {
		// known
		return false
	}

	zone.ns = append(zone.ns, name)
	zone.glue[name] = []netip.Addr{}
	return true
}

// AddGlue adds an A/AAAA entry to the zone if the name is a
// registered NS. Returns true if it was added.
func (zone *NSCacheZone) AddGlue(name string, addrs ...netip.Addr) bool {
	var added bool

	zone.mu.Lock()
	defer zone.mu.Unlock()

	if s, ok := zone.glue[name]; ok {
		// known NS
		eq := func(a, b netip.Addr) bool {
			return a.Compare(b) == 0
		}

		for _, addr := range addrs {
			if !core.SliceContainsFn(s, addr, eq) {
				zone.glue[name] = append(s, addr)
				added = true
			}
		}
	}
	return added
}

// SetGlue set the A/AAAA entries for a NS of a zone
// if it's registered as such.
// Returns true if it was set.
func (zone *NSCacheZone) SetGlue(name string, addrs []netip.Addr) bool {
	zone.mu.Lock()
	defer zone.mu.Unlock()

	if _, ok := zone.glue[name]; ok {
		// known NS
		zone.glue[name] = addrs
		return true
	}
	return false
}

// AddGlueNS adds an A/AAAA entry to the zone and, if necessary,
// the name as NS. Returns true if it was added.
func (zone *NSCacheZone) AddGlueNS(name string, addrs ...netip.Addr) bool {
	zone.AddNS(name)
	return zone.AddGlue(name, addrs...)
}

// AddGlueRR adds an A/AAAA entry to the zone from a [dns.RR] record,
// if the name is a registered NS. Returns true
func (zone *NSCacheZone) AddGlueRR(rr dns.RR) bool {
	switch v := rr.(type) {
	case *dns.A:
		ip, _ := netip.AddrFromSlice(v.A)
		if ip.IsValid() {
			return zone.AddGlue(v.Hdr.Name, ip)
		}
	case *dns.AAAA:
		ip, _ := netip.AddrFromSlice(v.AAAA)
		if ip.IsValid() {
			return zone.AddGlue(v.Hdr.Name, ip)
		}
	}

	return false
}

// ForEachNS calls the function for each registered NS, including any known
// glue addresses.
func (zone *NSCacheZone) ForEachNS(fn func(name string, addrs []netip.Addr)) {
	if zone != nil && fn != nil {
		zone.mu.Lock()
		names := make([]string, len(zone.ns))
		copy(names, zone.ns)
		zone.mu.Unlock()

		for _, name := range names {
			fn(name, zone.glue[name])
		}
	}
}

// ForEachAddr calls a function for each address in random order.
// return true to terminate the loop.
func (zone *NSCacheZone) ForEachAddr(fn func(string) bool) {
	if fn == nil {
		return
	}

	for _, addr := range zone.RandomAddrs() {
		if fn(addr) {
			break
		}
	}
}

// NewNSCacheZone creates a blank [NSCacheZone].
func NewNSCacheZone(name string) *NSCacheZone {
	if name != "" {
		name = dns.Fqdn(name)
	}
	return &NSCacheZone{
		name: name,
		glue: make(map[string][]netip.Addr),
	}
}

// NewNSCacheZoneFromDelegation creates a new [NSCacheZone] using the delegation information
// on a response.
func NewNSCacheZoneFromDelegation(resp *dns.Msg) (*NSCacheZone, error) {
	if !exdns.HasNsType(resp, dns.TypeNS) {
		// no delegation
		return nil, core.ErrInvalid
	}

	resp2 := resp.Copy()
	sanitizeDelegation(resp2, ".")
	zone, ttl, ok := assembleNSCacheZoneFromDelegation(resp2)
	if !ok {
		return nil, errors.ErrBadResponse()
	}

	zone.SetTTL(ttl, ttl/2)
	return zone, nil
}

// NewNSCacheZoneFromMap creates a new [NSCacheZone] using a map for the NS server
// addresses.
func NewNSCacheZoneFromMap(name string, ttl uint32, m map[string]string) *NSCacheZone {
	if ttl < MinimumNSCacheTTL {
		ttl = MinimumNSCacheTTL
	}

	zone := assembleNSCacheZoneFromMap(dns.Fqdn(name), m)
	zone.SetTTL(ttl, ttl/2)
	return zone
}

func sanitizeDelegation(resp *dns.Msg, authority string) {
	if len(resp.Answer) == 0 {
		// pure NS mode. one zone and its addresses.
		sanitizePureDelegation(resp, authority)
	} else {
		// hybrid, only remove NS entries not
		// controlled by the authority.
		filterNs := func(_ []dns.RR, rr dns.RR) (dns.RR, bool) {
			hdr := rr.Header()
			if hdr.Class == dns.ClassINET && hdr.Rrtype == dns.TypeNS {
				keep := dns.IsSubDomain(authority, hdr.Name)
				return rr, keep
			}
			// keep
			return rr, true
		}

		resp.Ns = core.SliceReplaceFn(resp.Ns, filterNs)
	}
}

// revive:disable:cognitive-complexity
// revive:disable:cyclomatic
func sanitizePureDelegation(resp *dns.Msg, authority string) {
	// revive:enable:cognitive-complexity
	// revive:enable:cyclomatic
	var domain string
	var nsNames = make(map[string]bool, len(resp.Ns))

	// NS for a single name.
	filterNs := func(rr dns.RR) bool {
		switch p := rr.(type) {
		case *dns.NS:
			// NS
			switch {
			case domain == "":
				// first
				if !dns.IsSubDomain(authority, p.Hdr.Name) {
					// NS outside the authority's domain
					return false
				}

				domain = p.Hdr.Name
				fallthrough
			case p.Hdr.Name == domain:
				// same name
				nsNames[p.Ns] = true
				return true
			default:
				// wrong name
				return false
			}
		default:
			// let other types pass

			// TODO: assess if further pruning is desired.
			return true
		}
	}

	resp.Ns = core.SliceReplaceFn(resp.Ns,
		func(_ []dns.RR, rr dns.RR) (dns.RR, bool) {
			var keep bool
			// only INET
			if rr.Header().Class == dns.ClassINET {
				keep = filterNs(rr)
			}
			return rr, keep
		})

	// only A/AAAA referencing NS names on resp.Extra
	// TODO: anything else to filter out? narrow further?
	filterGlue := func(rr dns.RR) bool {
		hdr := rr.Header()

		switch hdr.Rrtype {
		case dns.TypeA, dns.TypeAAAA:
			if nsNames[hdr.Name] {
				// NS address
				return true
			}
			// remove other addresses
			return false
		default:
			// let other types pass
			return true
		}
	}

	resp.Extra = core.SliceReplaceFn(resp.Extra,
		func(_ []dns.RR, rr dns.RR) (dns.RR, bool) {
			var keep bool
			if rr.Header().Class == dns.ClassINET {
				keep = filterGlue(rr)
			}
			return rr, keep
		})
}

// revive:disable:cognitive-complexity
func assembleNSCacheZoneFromDelegation(resp *dns.Msg) (*NSCacheZone, uint32, bool) {
	// revive:enable:cognitive-complexity
	var ttl uint32

	zone := NewNSCacheZone("")

	// collect NS entries
	fNS := func(rr *dns.NS) {
		hdr := rr.Header()

		if zone.name == "" {
			// first
			zone.name = dns.Fqdn(hdr.Name)
			ttl = hdr.Ttl
		}

		if rr.Hdr.Ttl < ttl {
			ttl = rr.Hdr.Ttl
		}

		zone.AddNS(rr.Ns)
	}

	// collect A/AAAA entries
	fRR := func(rr dns.RR) {
		if zone.AddGlueRR(rr) {
			// accepted
			if n := rr.Header().Ttl; n < ttl {
				ttl = n
			}
		}
	}

	exdns.ForEachRR(resp.Ns, fNS)
	exdns.ForEachRR(resp.Extra, fRR)
	return zone, ttl, true
}

func assembleNSCacheZoneFromMap(qName string, m map[string]string) *NSCacheZone {
	zone := NewNSCacheZone(qName)

	for k, sAddr := range m {
		k = dns.Fqdn(k)
		addr, _ := netip.ParseAddr(sAddr)
		if addr.IsValid() {
			zone.AddGlueNS(k, addr)
		}
	}

	return zone
}

func nsCacheSortAddr(addrs []netip.Addr) []netip.Addr {
	sort.Slice(addrs, func(i, j int) bool {
		a, b := addrs[i], addrs[j]
		return a.Compare(b) < 0
	})
	return addrs
}

func nsCacheGlueMap(glue map[string][]netip.Addr) map[string]string {
	out := make(map[string]string)
	for _, e := range glue {
		for _, ip := range e {
			key := ip.String()
			addr, err := exdns.AsServerAddress(key)
			if err == nil {
				out[key] = addr
			}
		}
	}
	return out
}
