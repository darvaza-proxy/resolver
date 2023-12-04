package resolver

import (
	"context"
	"fmt"

	"github.com/miekg/dns"

	"darvaza.org/cache"
	"darvaza.org/resolver/pkg/errors"
)

func (c *Cached) withRequest(ctx context.Context, req *dns.Msg) (context.Context, string) {
	q := msgQuestion(req)
	key := fmt.Sprintf("%s:%v:%v:%v", q.Name, q.Qclass, q.Qtype, req.RecursionDesired)

	ctx = c.cacheRequestCtx.WithValue(ctx, req)
	return ctx, key
}

func (c *Cached) getCache(ctx context.Context, key string, dest cache.Sink) error {
	var q *dns.Msg

	req, ok := c.cacheRequestCtx.Get(ctx)
	if !ok {
		// TODO: parse key if reachable
		panic("unreachable")
	}

	// assemble new
	q = &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: req.RecursionDesired,
		},
		Question: []dns.Question{
			req.Question[0],
		},
	}

	resp, err := c.e.Exchange(ctx, q)
	if err != nil {
		return c.handleCacheExchangeError(ctx, key, dest, resp, err)
	}

	return c.handleCacheExchangeSuccess(ctx, key, dest, resp)
}

func (*Cached) handleCacheExchangeError(context.Context, string, cache.Sink,
	*dns.Msg, error) error {
	//
	return errors.ErrNotImplemented("")
}

func (*Cached) handleCacheExchangeSuccess(context.Context, string, cache.Sink,
	*dns.Msg) error {
	//
	return errors.ErrNotImplemented("")
}
