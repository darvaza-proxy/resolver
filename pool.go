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

// ExchangeMetaOptions configures response comparison during a meta exchange.
type ExchangeMetaOptions struct {
	Meta          *ResolveMeta
	CompareWindow time.Duration
	Observer      DivergenceObserver
}

func (o *ExchangeMetaOptions) enabled() bool {
	return o != nil && o.Meta != nil && o.Observer != nil && o.CompareWindow > 0
}

type exchangeMetaState struct {
	mu           sync.Mutex
	opts         *ExchangeMetaOptions
	first        *poolEx
	compareUntil time.Time
	err          error
}

func newExchangeMetaState(opts *ExchangeMetaOptions) *exchangeMetaState {
	return &exchangeMetaState{opts: opts}
}

func (s *exchangeMetaState) expiredFirst() (*poolEx, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.first == nil || s.compareUntil.IsZero() || time.Now().Before(s.compareUntil) {
		return nil, false
	}

	return s.first, true
}

func (s *exchangeMetaState) onResponse(resp *poolEx) bool {
	if resp == nil {
		return false
	}

	if resp.IsKeeper() {
		return s.onKeeper(resp)
	}

	s.setErrIfNil(resp.Err())
	return false
}

func (s *exchangeMetaState) onKeeper(resp *poolEx) bool {
	if s.trySetFirst(resp) {
		return false
	}

	return s.compare(resp)
}

func (s *exchangeMetaState) compare(resp *poolEx) bool {
	if s.opts == nil || s.opts.Meta == nil || s.opts.Observer == nil {
		return false
	}

	first := s.firstKeeper()
	if first == nil {
		return false
	}

	equal := responsesEqual(first.resp, resp.resp)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.opts.Meta.Compared = true

	if equal {
		return false
	}

	s.opts.Meta.Diverged = true
	if s.opts.Meta.DivergenceID == "" {
		s.opts.Meta.DivergenceID = s.opts.Observer(
			first.resp, resp.resp, first.server, resp.server,
		)
	}

	return true
}

func (s *exchangeMetaState) trySetFirst(resp *poolEx) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.first != nil {
		return false
	}

	s.first = resp
	s.compareUntil = time.Now().Add(s.opts.CompareWindow)
	return true
}

func (s *exchangeMetaState) firstKeeper() *poolEx {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.first
}

func (s *exchangeMetaState) compareDeadline() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.compareUntil
}

func (s *exchangeMetaState) errValue() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.err
}

func (s *exchangeMetaState) setErrIfNil(err error) {
	if err == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.err == nil {
		s.err = err
	}
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

// ExchangeWithClientMeta performs a DNS request and optionally compares
// responses from multiple servers for divergence.
func (p *Pool) ExchangeWithClientMeta(ctx context.Context, req *dns.Msg, c client.Client,
	opts *ExchangeMetaOptions) (*dns.Msg, error) {
	//
	if opts == nil || !opts.enabled() {
		return p.ExchangeWithClient(ctx, req, c)
	}

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

	return p.doExchangeWithClientMeta(ctx, req, c, opts)
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

func (p *Pool) doExchangeWithClientMeta(ctx context.Context, req *dns.Msg, c client.Client,
	opts *ExchangeMetaOptions) (*dns.Msg, error) {
	//
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
		if opts.enabled() {
			return nil, core.Wrap(core.ErrInvalid, "meta comparison requires multiple attempts")
		}
		return p.doExchangeOnce(ctx, req, c)
	case t > 0:
		return p.doExchangeIntervalMeta(ctx, req, c, opts)
	default:
		return p.doExchangeWaitMeta(ctx, req, c, opts)
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
	out <- &poolEx{server: server, resp: resp, err: err}
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

func (p *Pool) doExchangeWaitMeta(ctx context.Context, req *dns.Msg,
	c client.Client, opts *ExchangeMetaOptions) (*dns.Msg, error) {
	//
	state := newExchangeMetaState(opts)
	n := p.Attempts

	ch := make(chan *poolEx)
	defer close(ch)

	mx := metaExchange{
		p:     p,
		ctx:   ctx,
		req:   req,
		c:     c,
		state: state,
		ch:    ch,
	}

	for p.next(&n) {
		if first, expired := state.expiredFirst(); expired {
			return first.Unwrap(req)
		}

		go p.doExchangeCh(ctx, req, c, ch)

		if resp, done, err := mx.waitOnce(); done {
			return resp, err
		}
	}

	return mx.finish()
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

func (p *Pool) doExchangeIntervalMeta(ctx context.Context, req *dns.Msg,
	c client.Client, opts *ExchangeMetaOptions) (*dns.Msg, error) {
	//
	state := newExchangeMetaState(opts)

	var wg sync.WaitGroup

	ch := make(chan *poolEx)
	defer close(ch)

	tick := time.NewTicker(p.Interval)
	defer tick.Stop()

	mx := metaExchange{
		p:     p,
		ctx:   ctx,
		req:   req,
		c:     c,
		state: state,
		ch:    ch,
		wg:    &wg,
		tick:  tick,
	}

	counters := metaIntervalCounters{remaining: p.Attempts}
	spawnCfg := metaIntervalSpawn{
		ctx:    ctx,
		p:      p,
		req:    req,
		client: c,
		wg:     &wg,
		ch:     ch,
	}
	mx.spawn = counters.spawnFunc(spawnCfg)

	return mx.runInterval(&counters)
}

type metaIntervalCounters struct {
	remaining int
	spawned   int
}

type metaIntervalSpawn struct {
	ctx    context.Context
	p      *Pool
	req    *dns.Msg
	client client.Client
	wg     *sync.WaitGroup
	ch     chan<- *poolEx
}

func (c *metaIntervalCounters) spawnFunc(spawnCfg metaIntervalSpawn) func() bool {
	return func() bool {
		if c.remaining == 0 {
			return false
		}
		spawnCfg.p.spawnExchangeCh(spawnCfg.ctx, spawnCfg.req, spawnCfg.wg, spawnCfg.client, spawnCfg.ch)
		c.spawned++
		if c.remaining > 0 {
			c.remaining--
		}
		return true
	}
}

func (c *metaIntervalCounters) shouldContinue() bool {
	return c.remaining != 0
}

func (c *metaIntervalCounters) ensureCompareSpawn(spawn func() bool) {
	if spawn == nil || c.spawned >= 2 {
		return
	}
	spawn()
}

type metaExchange struct {
	p     *Pool
	ctx   context.Context
	req   *dns.Msg
	c     client.Client
	state *exchangeMetaState
	ch    chan *poolEx
	wg    *sync.WaitGroup
	tick  *time.Ticker
	spawn func() bool
}

func (mx *metaExchange) runInterval(counters *metaIntervalCounters) (*dns.Msg, error) {
	if counters == nil {
		return nil, core.ErrInvalid
	}

	if mx.spawn != nil {
		mx.spawn()
	}

	for counters.shouldContinue() {
		if resp, done, err := mx.waitInterval(); done {
			return resp, err
		}
		if mx.state.firstKeeper() == nil {
			continue
		}
		counters.ensureCompareSpawn(mx.spawn)
		return mx.waitCompare()
	}

	return mx.p.waitExchangeInterval(mx.ctx, mx.req, mx.wg, mx.ch, mx.state.errValue())
}

func (mx *metaExchange) waitOnce() (*dns.Msg, bool, error) {
	select {
	case <-mx.ctx.Done():
		resp, err := mx.p.returnTimeout(mx.req, mx.ctx.Err())
		return resp, true, err
	case resp := <-mx.ch:
		if mx.state.onResponse(resp) {
			out, err := mx.state.first.Unwrap(mx.req)
			return out, true, err
		}
	}

	return nil, false, nil
}

func (mx *metaExchange) waitInterval() (*dns.Msg, bool, error) {
	select {
	case resp := <-mx.ch:
		if mx.state.onResponse(resp) {
			out, err := mx.state.first.Unwrap(mx.req)
			return out, true, err
		}
	case <-mx.ctx.Done():
		resp, err := mx.p.returnTimeout(mx.req, mx.ctx.Err())
		return resp, true, err
	case <-mx.tick.C:
		if mx.spawn != nil {
			mx.spawn()
		} else {
			mx.p.spawnExchangeCh(mx.ctx, mx.req, mx.wg, mx.c, mx.ch)
		}
	}

	if first, expired := mx.state.expiredFirst(); expired {
		resp, err := first.Unwrap(mx.req)
		return resp, true, err
	}

	return nil, false, nil
}

func (mx *metaExchange) waitCompare() (*dns.Msg, error) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		mx.wg.Wait()
	}()

	timer := time.NewTimer(time.Until(mx.state.compareDeadline()))
	defer timer.Stop()

	for {
		if resp, ok, err := mx.waitFinish(done, timer.C); ok {
			return resp, err
		}
	}
}

func (mx *metaExchange) waitFinish(done <-chan struct{}, timer <-chan time.Time) (*dns.Msg, bool, error) {
	select {
	case resp := <-mx.ch:
		if mx.state.onResponse(resp) {
			out, err := mx.state.first.Unwrap(mx.req)
			return out, true, err
		}
	case <-mx.ctx.Done():
		resp, err := mx.p.returnTimeout(mx.req, mx.ctx.Err())
		return resp, true, err
	case <-done:
		resp, err := mx.state.first.Unwrap(mx.req)
		return resp, true, err
	case <-timer:
		resp, err := mx.state.first.Unwrap(mx.req)
		return resp, true, err
	}

	return nil, false, nil
}

func (mx *metaExchange) finish() (*dns.Msg, error) {
	if first := mx.state.firstKeeper(); first != nil {
		return first.Unwrap(mx.req)
	}

	return mx.p.returnTimeout(mx.req, mx.state.errValue())
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
	server string
	resp   *dns.Msg
	err    error
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
