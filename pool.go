package resolver

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"

	"darvaza.org/core"
	"darvaza.org/resolver/pkg/client"
	"darvaza.org/resolver/pkg/errors"
	"darvaza.org/resolver/pkg/exdns"
)

// interface assertions
var (
	_ Lookuper  = (*Pool)(nil)
	_ Exchanger = (*Pool)(nil)
)

// A Pool is a Exchanger with multiple possible servers behind and tries
// some at random up to a given limit of parallel requests.
type Pool struct {
	mu sync.Mutex
	c  client.Client
	s  map[string]string

	// Attempts indicates how many times we will try. A negative
	// value indicates we will keep on trying
	Attempts int

	// Deadline is an optional maximum time exchanges can take.
	Deadline time.Duration

	// Interval indicates how long to wait until a new attempt is
	// started.
	Interval time.Duration
}

// Add adds servers to the [Pool].
func (p *Pool) Add(servers ...string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, s := range servers {
		s, err := exdns.AsServerAddress(s)
		if err != nil {
			return err
		}

		p.s[s] = s
	}

	return nil
}

// Remove removes servers from the [Pool].
func (p *Pool) Remove(servers ...string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, s := range servers {
		s, err := exdns.AsServerAddress(s)
		if err != nil {
			return err
		}

		delete(p.s, s)
	}

	return nil
}

// Servers returns the list of registered servers
// in random order.
func (p *Pool) Servers() []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make([]string, 0, len(p.s))
	for _, s := range p.s {
		out = append(out, s)
	}

	return out
}

// Server returns on registered server chosen at
// random. They can repeat.
func (p *Pool) Server() string {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, s := range p.s {
		return s
	}

	return ""
}

// Len indicates how many servers are registered
// in the [Pool].
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.s)
}

// ForEach calls a function for each registered server
// in random order.
// Return true to terminate the loop.
func (p *Pool) ForEach(fn func(string) bool) {
	if fn != nil {
		for _, s := range p.Servers() {
			if fn(s) {
				return
			}
		}
	}
}

// Lookup makes an INET DNS request to a random server in the [Pool]
func (p *Pool) Lookup(ctx context.Context, qName string, qType uint16) (*dns.Msg, error) {
	req := exdns.NewRequestFromParts(qName, dns.ClassINET, qType)
	return p.ExchangeWithClient(ctx, req, p.c)
}

// Exchange makes a DNS request to a random server in the [Pool]
func (p *Pool) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return p.ExchangeWithClient(ctx, req, p.c)
}

// ExchangeWithClient makes a DNS request to a random
// server in the [Pool] using the given [client.Client].
func (p *Pool) ExchangeWithClient(ctx context.Context, req *dns.Msg, c client.Client) (*dns.Msg, error) {
	switch {
	case ctx == nil || req == nil:
		// invalid call
		return nil, core.ErrInvalid
	case len(req.Question) == 0:
		// nothing to answer
		resp := new(dns.Msg)
		resp.SetReply(req)
		return resp, nil
	}

	switch {
	case c != nil:
		// client given
	case p.c != nil:
		// use build-time client
		c = p.c
	default:
		// use fresh default client
		c = client.NewDefaultClient(0)
	}

	return p.doExchangeWithClient(ctx, req, c)
}

func (p *Pool) doExchangeWithClient(ctx context.Context, req *dns.Msg, c client.Client) (*dns.Msg, error) {
	// context
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if p.Deadline > 0 {
		until := time.Now().Add(p.Deadline)

		ctx, cancel = context.WithDeadline(ctx, until)
		defer cancel()
	}

	n, t := p.Attempts, p.Interval
	switch {
	case n == 0, n == 1:
		// once
		return p.doExchangeOnce(ctx, req, c)
	case t > 0:
		// launch a new request every `t`
		return p.doExchangeInterval(ctx, req, c, n, t)
	default:
		// launch a new request after the previous has finished
		return p.doExchangeWait(ctx, req, c, n)
	}
}

func (p *Pool) doExchangeCh(ctx context.Context, req *dns.Msg, c client.Client, out chan<- *poolEx) {
	server := p.Server()
	resp, _, err := c.ExchangeContext(ctx, req, server)
	if e2 := errors.ValidateResponse(server, resp, err); e2 != nil {
		err = e2
	}

	// out would be closed if we already delivered a response.
	defer func() { _ = recover() }()
	out <- &poolEx{resp, err}
}

func (*Pool) returnTimeout(req *dns.Msg, err error) (*dns.Msg, error) {
	qName := req.Question[0].Name
	return nil, errors.ErrTimeout(qName, err)
}

func (p *Pool) doExchangeOnce(ctx context.Context, req *dns.Msg,
	c client.Client) (*dns.Msg, error) {
	// spawn
	ch := make(chan *poolEx)
	defer close(ch)

	go p.doExchangeCh(ctx, req, c, ch)

	// wait
	select {
	case <-ctx.Done():
		// timed out
		return p.returnTimeout(req, ctx.Err())
	case resp := <-ch:
		// done
		return resp.Unwrap(req)
	}
}

func (p *Pool) doExchangeWait(ctx context.Context, req *dns.Msg,
	c client.Client, n int) (*dns.Msg, error) {
	//
	var err error

	ch := make(chan *poolEx)
	defer close(ch)

	for p.next(&n) {
		go p.doExchangeCh(ctx, req, c, ch)

		select {
		case <-ctx.Done():
			// timed out
			return p.returnTimeout(req, ctx.Err())
		case resp := <-ch:
			// finished
			switch {
			case resp.IsKeeper():
				// done
				return resp.Unwrap(req)
			case err == nil:
				// remember first error
				err = resp.Err()
			}
		}
	}

	return p.returnTimeout(req, err)
}

func (p *Pool) doExchangeInterval(ctx context.Context, req *dns.Msg,
	c client.Client, n int, interval time.Duration) (*dns.Msg, error) {
	//
	var wg sync.WaitGroup
	var err error

	// responses
	ch := make(chan *poolEx)
	defer close(ch)

	// spawning timer
	tick := time.NewTicker(interval)
	defer tick.Stop()

	// spawn first
	p.spawnExchangeCh(ctx, req, &wg, c, ch)

	for p.next(&n) {
		select {
		case resp := <-ch:
			// someone finished
			switch {
			case resp.IsKeeper():
				// done
				return resp.Unwrap(req)
			case err == nil:
				// remember first error
				err = resp.Err()
			}
		case <-ctx.Done():
			// timed out
			return p.returnTimeout(req, ctx.Err())
		case <-tick.C:
			// spawn another
			p.spawnExchangeCh(ctx, req, &wg, c, ch)
		}
	}

	tick.Stop()
	// carry on waiting
	return p.waitExchangeInterval(ctx, req, &wg, ch, err)
}

func (p *Pool) waitExchangeInterval(ctx context.Context, req *dns.Msg,
	wg *sync.WaitGroup, ch <-chan *poolEx, err error) (*dns.Msg, error) {
	// watch end
	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
	}()

	// and wait...
	for {
		select {
		case resp := <-ch:
			// someone finished
			switch {
			case resp.IsKeeper():
				// done
				return resp.Unwrap(req)
			case err == nil:
				// remember first error
				err = resp.Err()
			}
		case <-ctx.Done():
			// timed out
			return p.returnTimeout(req, ctx.Err())
		case <-done:
			// all finished, and no keepers.
			return p.returnTimeout(req, err)
		}
	}
}

func (p *Pool) spawnExchangeCh(ctx context.Context, req *dns.Msg,
	wg *sync.WaitGroup,
	c client.Client, ch chan<- *poolEx) {
	//
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.doExchangeCh(ctx, req, c, ch)
	}()
}

func (*Pool) next(n *int) bool {
	switch {
	case *n < 0:
		// unlimited
		return true
	case *n == 0:
		// done
		return false
	default:
		// carry on
		*n--
		return true
	}
}

type poolEx struct {
	resp *dns.Msg
	err  error
}

// IsKeeper determines if the response is to be passed
// through to the caller, or we carry on retrying and waiting
// for something better.
func (r *poolEx) IsKeeper() bool {
	switch {
	case r == nil, errors.IsTimeout(r.err):
		return false
	case r.resp != nil:
		return true
	default:
		return !errors.IsTemporary(r.err)
	}
}

func (r *poolEx) Unwrap(req *dns.Msg) (*dns.Msg, error) {
	var qName string

	if r.resp != nil || r.err != nil {
		return r.resp, r.err
	}

	if req != nil {
		qName = req.Question[0].Name
	}

	return nil, errors.ErrTimeout(qName, nil)
}

func (r *poolEx) Err() error {
	if r != nil {
		return r.err
	}
	return nil
}

// NewPoolExchanger creates a new [PoolExchanger] middleware.
func NewPoolExchanger(c client.Client, servers ...string) (*Pool, error) {
	p := &Pool{
		c: c,
		s: make(map[string]string),
	}

	err := p.Add(servers...)
	if err != nil {
		return nil, err
	}

	return p, nil
}
