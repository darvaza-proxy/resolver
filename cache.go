package resolver

import (
	"context"

	"github.com/miekg/dns"

	"darvaza.org/cache"
	"darvaza.org/core"
	"darvaza.org/resolver/pkg/errors"
)

var (
	_ Exchanger = (*Cached)(nil)
	_ Lookuper  = (*Cached)(nil)
)

// Cached implements a caching layer in front of a
// [Lookuper] or [Exchanger]
type Cached struct {
	e Exchanger

	cache           cache.Cache
	cacheRequestCtx *core.ContextKey[*dns.Msg]
}

// Lookup resolves an INET lookup request implementing the [Lookuper] interface using
// cache when possible.
func (c *Cached) Lookup(ctx context.Context, qName string, qType uint16) (*dns.Msg, error) {
	req := &dns.Msg{
		Question: []dns.Question{
			{
				Name:   qName,
				Qtype:  qType,
				Qclass: dns.ClassINET,
			},
		},
	}

	return c.Exchange(ctx, req)
}

// Exchange resolves a [dns.Msg] request implementing the [Exchanger] interface using
// cache when possible
func (c *Cached) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if ctx == nil || req == nil {
		return nil, errors.ErrBadRequest()
	}

	if len(req.Question) != 1 {
		return nil, errors.ErrNotImplemented("")
	}

	ctx, key := c.withRequest(ctx, req)
	dest := new(RRCacheSink)

	if err := c.cache.Get(ctx, key, dest); err != nil {
		// TODO: log error
		return nil, err
	}

	return dest.ExportMsg()
}

// NewCachedLookuper wraps a [Lookuper] with a cache
func NewCachedLookuper(l Lookuper, store cache.Store, name string, bytes uint) (*Cached, error) {
	var e Exchanger

	if l != nil {
		var ok bool
		e, ok = l.(Exchanger)
		if !ok {
			e = LookuperFunc(l.Lookup)
		}
	}

	return NewCachedExchanger(e, store, name, bytes)
}

// NewCachedExchanger wraps an [Exchanger] with a cache
func NewCachedExchanger(e Exchanger, store cache.Store, name string, maxRRs uint) (*Cached, error) {
	if e == nil || store == nil {
		return nil, errors.New("invalid arguments")
	}

	c := &Cached{
		e: e,
	}

	c.cache = store.NewCache(name, int64(maxRRs), cache.GetterFunc(c.getCache))
	c.cacheRequestCtx = core.NewContextKey[*dns.Msg]("dns.request")
	return c, nil
}
