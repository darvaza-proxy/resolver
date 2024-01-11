package resolver

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"

	"darvaza.org/cache/x/simplelru"
	"darvaza.org/core"
	"darvaza.org/slog"
	"darvaza.org/slog/handlers/discard"

	"darvaza.org/resolver/pkg/client"
	"darvaza.org/resolver/pkg/errors"
	"darvaza.org/resolver/pkg/exdns"
)

var (
	_ Exchanger = (*NSCache)(nil)
)

const (
	// DefaultNSCacheSize indicates the cache size if none
	// is specified.
	DefaultNSCacheSize = 1024
)

// NSCache is a non-recursive [Exchanger] that caches
// authoritative delegation information.
type NSCache struct {
	name string
	mu   sync.Mutex
	log  slog.Logger

	lru *simplelru.LRU[string, *NSCacheZone]

	persistent map[string]bool
}

// SetLogger attaches a logger to the Cache. [slog.Debug] level
// is used when adding or removing entries.
func (nsc *NSCache) SetLogger(log slog.Logger) {
	nsc.mu.Lock()
	defer nsc.mu.Unlock()

	if log == nil {
		log = discard.New()
	}
	nsc.log = log
}

func (nsc *NSCache) onLRUAdd(qName string, zone *NSCacheZone, size int, expire time.Time) {
	if l, ok := nsc.log.Debug().WithEnabled(); ok {
		l = l.WithFields(slog.Fields{
			"domain":  qName,
			"entries": size,
			"cache":   nsc.name,
		})

		l = nsc.addLogFieldTimeNotZero(l, "expire", expire)
		l = nsc.addLogFieldCleanRR(l, "ns", zone.ExportNS())
		l = nsc.addLogFieldCleanRR(l, "extra", zone.ExportGlue())

		l.Print("cached")
	}
}

func (*NSCache) addLogFieldTimeNotZero(l slog.Logger, name string, t time.Time) slog.Logger {
	if !t.IsZero() {
		return l.WithField(name, t.UTC().Format(time.RFC3339))
	}
	return l
}

func (*NSCache) addLogFieldCleanRR(l slog.Logger, name string, records []dns.RR) slog.Logger {
	if n := len(records); n > 0 {
		s := make([]string, n)
		for i, rr := range records {
			s[i] = exdns.CleanString(rr)
		}
		return l.WithField(name, s)
	}

	return l
}

func (nsc *NSCache) onLRUEvict(qName string, zone *NSCacheZone, size int) {
	nsc.log.Debug().WithFields(slog.Fields{
		"domain":  qName,
		"entries": size,
		"cache":   nsc.name,
	})

	if qName != zone.Name() {
		panic("unreachable")
	}

	if nsc.persistent[qName] {
		// TODO: assess deadlock risk
		_, _, ok := nsc.lru.Get(qName)
		if !ok {
			// gone, restore
			expire := time.Now().UTC().Add(MinimumNSCacheTTL)
			nsc.doAdd(zone, expire)
		}
	}
}

// AddMap adds data from a predefined map.
func (nsc *NSCache) AddMap(name string, ttl uint32, m map[string]string) error {
	zone := NewNSCacheZoneFromMap(name, ttl, m)
	return nsc.Add(zone)
}

// Add adds a preassembles [NSCacheZone].
func (nsc *NSCache) Add(zone *NSCacheZone) error {
	if !zone.IsValid() {
		return core.ErrInvalid
	}

	nsc.mu.Lock()
	defer nsc.mu.Unlock()

	zone.unsafeIndex()

	nsc.doAdd(zone, zone.Expire())
	return nil
}

// Evict removes a zone from the cache if present.
func (nsc *NSCache) Evict(name string) {
	nsc.mu.Lock()
	defer nsc.mu.Unlock()

	nsc.lru.Evict(name)
}

func (nsc *NSCache) doAdd(zone *NSCacheZone, expire time.Time) {
	nsc.lru.Add(zone.Name(), zone, zone.Len(), expire)
}

// Lookup finds the best NS match in the [NSCache] for a name.
func (nsc *NSCache) Lookup(qName string) (*NSCacheZone, bool) {
	nsc.mu.Lock()
	defer nsc.mu.Unlock()

	for _, name := range nsc.Suffixes(qName) {
		data, _, ok := nsc.lru.Get(name)
		if ok {
			return data, true
		}
	}

	return nil, false
}

// Get finds the exact NS match in the [NSCache] for a name.
func (nsc *NSCache) Get(qName string) (*NSCacheZone, time.Time, bool) {
	nsc.mu.Lock()
	defer nsc.mu.Unlock()

	return nsc.lru.Get(qName)
}

// revive:disable:flag-parameter

// SetPersistence flags a zone to be restore if evicted.
func (nsc *NSCache) SetPersistence(qName string, persistent bool) error {
	// revive:enable:flag-parameter
	nsc.mu.Lock()
	defer nsc.mu.Unlock()

	if !persistent {
		delete(nsc.persistent, qName)
		return nil
	}

	_, _, ok := nsc.lru.Get(qName)
	if !ok {
		// unknown
		return errors.ErrNotFound(qName)
	}
	nsc.persistent[qName] = true
	return nil
}

// Suffixes returns the possible suffixes for a domain name.
func (*NSCache) Suffixes(qName string) []string {
	idx := dns.Split(qName)
	out := make([]string, 0, len(idx)+1)
	for _, off := range idx {
		out = append(out, qName[off:])
	}
	out = append(out, ".")

	return out
}

// Exchange attempts to get an authoritative response
// using the default [client.Client].
func (nsc *NSCache) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	c := client.NewDefaultClient(0)
	return nsc.ExchangeWithClient(ctx, req, c)
}

// ExchangeWithClient attempts to get an authoritative response
// using the given [client.Client].
func (nsc *NSCache) ExchangeWithClient(ctx context.Context,
	req *dns.Msg, c client.Client) (*dns.Msg, error) {
	//
	q := msgQuestion(req)
	if q == nil {
		// nothing to answer
		resp := new(dns.Msg)
		resp.SetReply(req)
		return resp, nil
	}

	zone, ok := nsc.Lookup(q.Name)
	if !ok {
		// no suitable servers
		return nil, errors.ErrRefused(q.Name)
	}

	// each pass uses a new random server
	for _, server := range zone.s {
		// TODO: make fault tolerant
		return nsc.doExchange(ctx, req, server, c, zone.name)
	}

	return nil, errors.ErrRefused(q.Name)
}

func (nsc *NSCache) doExchange(ctx context.Context,
	req *dns.Msg, server string,
	c client.Client, authority string) (*dns.Msg, error) {
	//
	resp, _, err := c.ExchangeContext(ctx, req, server)
	err2 := errors.ValidateResponse(server, resp, err)
	switch {
	case err2 == nil:
		return nsc.handleSuccess(resp, authority)
	case err2.Err == errors.NODATA:
		return nsc.handleNODATA(resp, err2)
	default:
		return nil, err2
	}
}

func (*NSCache) handleNODATA(resp *dns.Msg, err error) (*dns.Msg, error) {
	if exdns.HasNsType(resp, dns.TypeSOA) {
		// pass over SOA data
		return resp, nil
	}
	return nil, err
}

func (*NSCache) handleSuccess(resp *dns.Msg, authority string) (*dns.Msg, error) {
	if exdns.HasNsType(resp, dns.TypeNS) {
		sanitizeDelegation(resp, authority)
	}

	return resp, nil
}

// NewNSCache creates a new [NSCache].
func NewNSCache(name string, maxRR uint) *NSCache {
	if maxRR == 0 {
		maxRR = DefaultNSCacheSize
	}

	nsc := &NSCache{
		name:       name,
		log:        discard.New(),
		persistent: make(map[string]bool),
	}

	nsc.lru = simplelru.NewLRU(int(maxRR), nsc.onLRUAdd, nsc.onLRUEvict)
	return nsc
}
