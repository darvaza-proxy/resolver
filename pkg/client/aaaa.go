package client

import (
	"context"
	"time"

	"github.com/miekg/dns"

	"darvaza.org/resolver/pkg/common"
	"darvaza.org/resolver/pkg/errors"
)

var (
	_ Client    = (*NoAAAA)(nil)
	_ Unwrapper = (*NoAAAA)(nil)
)

// NoAAAA is a dns.Client middleware to remove AAAA entries from all responses
type NoAAAA struct {
	Client
}

// ExchangeContext calls the next client in the chain if it's not an AAAA,
// and discards all AAAA entries on the response.
func (c NoAAAA) ExchangeContext(ctx context.Context, req *dns.Msg,
	server string) (*dns.Msg, time.Duration, error) {
	//
	start := time.Now()

	if req == nil {
		return nil, 0, errors.ErrBadRequest()
	}

	req2 := req.Copy()
	req2.Question = common.TrimQ(req2.Question, qIsAAAA)
	if len(req2.Question) == 0 {
		// nothing to answer
		resp := new(dns.Msg)
		resp.SetReply(req)
		return resp, time.Since(start), nil
	}

	resp, _, err := c.Client.ExchangeContext(ctx, req, server)
	if resp != nil {
		resp.Answer = common.TrimRR(resp.Answer, rrIsAAAA)
		resp.Ns = common.TrimRR(resp.Ns, rrIsAAAA)
		resp.Extra = common.TrimRR(resp.Extra, rrIsAAAA)
	}

	return resp, time.Since(start), err
}

func (c NoAAAA) Unwrap() *dns.Client {
	return Unwrap(c.Client)
}

func rrIsAAAA(rr dns.RR) bool {
	h := rr.Header()
	return h.Class == dns.ClassINET && h.Rrtype == dns.TypeAAAA
}

func qIsAAAA(q dns.Question) bool {
	return q.Qclass == dns.ClassINET && q.Qtype == dns.TypeAAAA
}

// NewNoAAAA creates a Client middleware that filters out
// all AAAA entries
func NewNoAAAA(c Client) *NoAAAA {
	if c != nil {
		return &NoAAAA{Client: c}
	}
	return nil
}
