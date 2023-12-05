package client

import (
	"context"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"darvaza.org/resolver/pkg/errors"
)

var (
	_ Client = (*SingleFlight)(nil)
)

const (
	// DefaultSingleFlightExpiration tells how long will we cache
	// the result after an exchange
	DefaultSingleFlightExpiration = 1 * time.Second
)

// SingleFlight wraps a [Client] to minimize redundant queries
type SingleFlight struct {
	c   Client
	g   singleflight.Group
	exp time.Duration
}

// ExchangeContext makes a DNS query to a server, minimizing duplications.
func (sfc *SingleFlight) ExchangeContext(ctx context.Context, req *dns.Msg,
	server string) (*dns.Msg, time.Duration, error) {
	//
	if ctx == nil || req == nil {
		return nil, 0, errors.ErrBadRequest()
	}

	switch len(req.Question) {
	case 0:
		// nothing to answer
		msg := new(dns.Msg)
		msg.SetReply(req)
		return msg, 0, nil
	case 1:
		// ready
	default:
		// shrink
		req.Question = []dns.Question{req.Question[0]}
	}

	if req.Id == 0 {
		// make sure we have a unique Id for future
		// disambiguation
		req.Id = dns.Id()
	}

	return sfc.doExchange(ctx, req, server)
}

func (sfc *SingleFlight) doExchange(ctx context.Context, req *dns.Msg,
	server string) (*dns.Msg, time.Duration, error) {
	//
	key := sfc.RequestKey(req, server)
	v, err, shared := sfc.g.Do(key, func() (any, error) {
		// TODO: how to allow retries on error properly?
		data, err := sfc.doExchangeResult(ctx, req, server)

		sfc.deferredExpiration(key)

		return data, err
	})

	data, ok := v.(sfResult)
	if !ok {
		panic("unreachable")
	}

	return data.Export(req, err, shared)
}

func (sfc *SingleFlight) deferredExpiration(key string) {
	switch {
	case sfc.exp > 0:
		// deferred expiration
		go func(key string) {
			<-time.After(sfc.exp)
			sfc.g.Forget(key)
		}(key)
	default:
		// immediate
		sfc.g.Forget(key)
	}
}

func (sfc *SingleFlight) doExchangeResult(ctx context.Context, req *dns.Msg,
	server string) (sfResult, error) {
	//
	if sfc.c == nil {
		// it doesn't matter if this happens multiple times
		// and will only happens if the user didn't use
		// NewSingleFlight()
		sfc.c = NewDefaultClient()
	}

	res, rtt, err := sfc.c.ExchangeContext(ctx, req, server)

	data := sfResult{
		res: res,
		rtt: rtt,
	}

	return data, err
}

// RequestKey serializes a DNS request to act as temporary cache key
func (*SingleFlight) RequestKey(req *dns.Msg, server string) string {
	var key string

	if req != nil {
		// serialize the whole request, except the Id.
		// TODO: could we do better?
		r2 := req.Copy()
		r2.Id = 0

		key = r2.String()
	}

	switch {
	case server == "":
		return key
	case key == "":
		return server
	default:
		return key + "\n; " + server
	}
}

type sfResult struct {
	res *dns.Msg
	rtt time.Duration
}

// revive:disable:flag-parameter
func (d sfResult) Export(req *dns.Msg, err error, shared bool) (*dns.Msg, time.Duration, error) {
	// revive:enable:flag-parameter
	res := d.res
	rtt := d.rtt

	if shared && res != nil {
		res = res.Copy()
		res.Id = req.Id
	}

	return res, rtt, err
}

// NewSingleFlight creates a [SingleFlight] Client around another.
// if no Client is specified, the default udp dns.Client will be used.
// if exp is positive, the result will be cached that long.
// if exp is negative, the result will expire immediately
// if exp is zero, [DefaultSingleFlightExpiration] will be used
func NewSingleFlight(c Client, exp time.Duration) *SingleFlight {
	if c == nil {
		c = NewDefaultClient()
	}

	if exp == 0 {
		exp = DefaultSingleFlightExpiration
	}

	return &SingleFlight{c: c, exp: exp}
}
