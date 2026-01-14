package resolver

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"darvaza.org/resolver/pkg/client"
	"darvaza.org/resolver/pkg/exdns"
)

func TestPoolExchangeWithMetaDivergence(t *testing.T) {
	p := newTestPool(t)
	c := newDivergentClient()
	result := exchangeWithMeta(t, p, c)

	assertDivergence(t, result)
}

func newTestPool(t *testing.T) *Pool {
	t.Helper()

	p, err := NewPoolExchanger(nil, "192.0.2.1:53")
	if err != nil {
		t.Fatalf("NewPoolExchanger: %v", err)
	}
	p.Attempts = 2
	p.Interval = 0
	return p
}

func newDivergentClient() client.Client {
	var calls atomic.Uint32
	return client.ExchangeFunc(func(_ context.Context, req *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		resp := new(dns.Msg)
		resp.SetReply(req)

		ip := net.IPv4(192, 0, 2, 1)
		if calls.Add(1)%2 == 0 {
			ip = net.IPv4(192, 0, 2, 2)
		}

		resp.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Class:  dns.ClassINET,
					Rrtype: dns.TypeA,
					Ttl:    60,
				},
				A: ip,
			},
		}

		return resp, 0, nil
	})
}

type metaExchangeResult struct {
	resp  *dns.Msg
	meta  *ResolveMeta
	store *DivergenceStore
	err   error
}

func exchangeWithMeta(t *testing.T, p *Pool, c client.Client) *metaExchangeResult {
	t.Helper()

	meta := new(ResolveMeta)
	store := NewDivergenceStore(16, 1*time.Minute)
	observer := func(a, b *dns.Msg, aServer, bServer string) string {
		q := divergenceQuery{name: a.Question[0].Name, qType: a.Question[0].Qtype}
		pair := divergencePair{a: a, b: b, aServer: aServer, bServer: bServer}
		rec := newDivergenceRecord(q, pair)
		return store.Add(rec)
	}

	opts := &ExchangeMetaOptions{
		Meta:          meta,
		CompareWindow: 1 * time.Second,
		Observer:      observer,
	}

	req := exdns.NewRequestFromParts("example.", dns.ClassINET, dns.TypeA)
	resp, err := p.ExchangeWithClientMeta(context.Background(), req, c, opts)
	return &metaExchangeResult{
		resp:  resp,
		meta:  meta,
		store: store,
		err:   err,
	}
}

func assertDivergence(t *testing.T, result *metaExchangeResult) {
	t.Helper()

	if result.err != nil {
		t.Fatalf("ExchangeWithClientMeta: %v", result.err)
	}
	if result.resp == nil {
		t.Fatal("ExchangeWithClientMeta returned nil response")
	}
	if !result.meta.Diverged {
		t.Fatal("expected divergence to be detected")
	}
	if result.meta.DivergenceID == "" {
		t.Fatal("expected divergence ID to be set")
	}
	if _, ok := result.store.Get(result.meta.DivergenceID); !ok {
		t.Fatalf("divergence ID %q not found in store", result.meta.DivergenceID)
	}
}
