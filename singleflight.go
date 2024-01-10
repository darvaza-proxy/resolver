package resolver

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"darvaza.org/core"

	"darvaza.org/resolver/pkg/client"
	"darvaza.org/resolver/pkg/errors"
	"darvaza.org/resolver/pkg/exdns"
)

var (
	_ Lookuper  = (*SingleFlight)(nil)
	_ Exchanger = (*SingleFlight)(nil)
)

// SingleFlightHasher is a function that generates the
// caching key for a request.
type SingleFlightHasher func(context.Context, *dns.Msg) (string, error)

// SingleFlight is an [Exchanger]/[Lookuper] that holds/caches
// identical queries before passing them over to another [Exchanger].
type SingleFlight struct {
	e   Exchanger
	g   singleflight.Group
	exp time.Duration
	h   SingleFlightHasher
}

// Lookup implements the [Lookuper] interface holding/caching
// identical queries.
func (sf *SingleFlight) Lookup(ctx context.Context, qName string, qType uint16) (*dns.Msg, error) {
	if ctx == nil {
		return nil, errors.ErrBadRequest()
	}

	req := exdns.NewRequestFromParts(qName, dns.ClassINET, qType)
	return sf.Exchange(ctx, req)
}

// Exchange implements the [Exchanger] interface holding/caching
// identical queries.
func (sf *SingleFlight) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	var original *dns.Msg

	if ctx == nil || req == nil {
		return nil, errors.ErrBadRequest()
	}

	switch len(req.Question) {
	case 0:
		// nothing to answer
		msg := new(dns.Msg)
		msg.SetReply(req)
		return msg, nil
	case 1:
		if req.Id == 0 {
			// make sure it comes with an ID
			req.Id = dns.Id()
		}
	default:
		// shrink
		original = req

		req = req.Copy()
		req.Id = dns.Id()
		req.Question = []dns.Question{
			req.Question[0],
		}
	}

	resp, err := sf.doExchange(ctx, req)
	return exdns.RestoreReturn(original, resp, err)
}

func (sf *SingleFlight) doExchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	//
	key, err := sf.h(ctx, req)
	if err != nil {
		return nil, err
	}
	v, err, _ := sf.g.Do(key, func() (any, error) {
		resp, err := sf.e.Exchange(ctx, req)
		sf.deferredExpiration(key)
		return resp, err
	})

	resp, ok := v.(*dns.Msg)
	switch {
	case ok:
		// pass through
		return resp, err
	case err == nil:
		// this can't happen
		q := msgQuestion(req)
		return nil, errors.ErrInternalError(q.Name, "singleflight")
	default:
		// failed
		return nil, err
	}
}

func (sf *SingleFlight) deferredExpiration(key string) {
	switch {
	case sf.exp > 0:
		// deferred expiration
		go func(key string) {
			<-time.After(sf.exp)
			sf.g.Forget(key)
		}(key)
	default:
		// immediate
		sf.g.Forget(key)
	}
}

// NewSingleFlight creates a [Exchanger] wrapper holding/caching identical
// requests for up to the given time, using the given function to produce
// the keys or base64 packed if no hasher is provided.
// use negative exp to indicate immediate as zero will be replaced
// with the default of 1s.
func NewSingleFlight(next Exchanger, exp time.Duration,
	hasher SingleFlightHasher) (*SingleFlight, error) {
	//
	if next == nil || exp < 0 {
		return nil, core.ErrInvalid
	}

	if exp == 0 {
		exp = client.DefaultSingleFlightExpiration
	}

	if hasher == nil {
		hasher = DefaultSingleFlightHasher
	}

	sf := &SingleFlight{
		e:   next,
		exp: exp,
		h:   hasher,
	}
	return sf, nil
}

// DefaultSingleFlightHasher returns the base64 encoded
// representation of the packed request, ignoring the ID.
func DefaultSingleFlightHasher(_ context.Context, req *dns.Msg) (string, error) {
	if req == nil {
		return "", core.ErrInvalid
	}

	id := req.Id
	req.Id = 0
	b, err := req.Pack()
	req.Id = id

	if err != nil {
		return "", errors.ErrBadRequest()
	}

	s := base64.RawStdEncoding.EncodeToString(b)
	return s, nil
}
