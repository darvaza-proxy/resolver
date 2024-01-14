package client

import (
	"context"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"darvaza.org/core"
)

var (
	// DefaultWorkerPoolSize indicates how many parallel workers a
	// [WorkerPool] contains if the amount wasn't specified when created.
	DefaultWorkerPoolSize = runtime.NumCPU()
)

// interface assertions
var _ Client = (*WorkerPool)(nil)

// A WorkerPool limits the number of parallel requests.
type WorkerPool struct {
	wg        core.WaitGroup
	cancelled atomic.Bool
	cancel    chan struct{}
	ch        chan exReq
	err       error

	c        Client
	onCancel func(error)
	max      int
}

// prepare is called on Start()
func (wp *WorkerPool) prepare(ctx context.Context) error {
	switch {
	case ctx == nil:
		return core.ErrInvalid
	case wp.ch != nil:
		return core.ErrExists
	}

	if wp.max <= 0 {
		wp.max = DefaultWorkerPoolSize
	}

	wp.ch = make(chan exReq, wp.max)

	// set watchers
	wp.wg.OnError(wp.wgWatchWorkers)
	wp.wg.Go(func() error {
		return wp.wgWatchContext(ctx)
	})

	return nil
}

// ExchangeContext implements a restricted parallel [Client] interface.
func (wp *WorkerPool) ExchangeContext(ctx context.Context,
	req *dns.Msg, server string) (*dns.Msg, time.Duration, error) {
	//
	switch {
	case ctx == nil || req == nil || server == "":
		// bad arguments
		return nil, 0, core.ErrInvalid
	case wp.ch == nil:
		// not started
		return nil, 0, core.Wrap(core.ErrNotExists, "WorkerPool not started")
	case len(req.Question) == 0:
		// nothing to answer
		resp := new(dns.Msg)
		resp.SetReply(req)
		return resp, 0, nil
	case wp.IsCancelled():
		// shutting down
		return nil, 0, wp.wg.Err()
	default:
		since := time.Now()
		resp, err := wp.doExchange(ctx, req, server)
		return resp, time.Since(since), err
	}
}

func (wp *WorkerPool) doExchange(ctx context.Context,
	req *dns.Msg, server string) (*dns.Msg, error) {
	// submit and wait
	select {
	case <-ctx.Done():
		// deadline
		return nil, ctx.Err()
	case r, ok := <-wp.submit(ctx, req, server):
		if ok {
			// response received
			return r.resp, r.err
		}

		// closed
		return nil, wp.wg.Err()
	}
}

func (wp *WorkerPool) submit(ctx context.Context, req *dns.Msg, server string) <-chan exResp {
	ch := make(chan exResp)

	r := exReq{
		ctx:    ctx,
		req:    req,
		server: server,
		ch:     ch,
	}

	wp.ch <- r
	return ch
}

func (wp *WorkerPool) run() error {
	for req := range wp.ch {
		resp, _, err := wp.c.ExchangeContext(req.ctx, req.req, req.server)
		req.ch <- exResp{
			resp: resp,
			err:  err,
		}
	}
	return nil
}

type exReq struct {
	ctx    context.Context
	req    *dns.Msg
	ch     chan<- exResp
	server string
}

type exResp struct {
	resp *dns.Msg
	err  error
}

// Start launches the workers
func (wp *WorkerPool) Start(ctx context.Context) error {
	if err := wp.prepare(ctx); err != nil {
		return err
	}

	for i := 0; i < wp.max; i++ {
		wp.wg.Go(wp.run)
	}

	return nil
}

// Shutdown initiates a shutdown and waits until all workers
// have finished or the given context expires.
func (wp *WorkerPool) Shutdown(ctx context.Context) error {
	wp.doCancel(context.Canceled)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-wp.wg.Done():
		return wp.wg.Err()
	}
}

func (wp *WorkerPool) wgWatchWorkers(err error) error {
	if err != nil {
		// shutdown on error
		wp.doCancel(err)
	}
	return nil
}

func (wp *WorkerPool) wgWatchContext(ctx context.Context) error {
	<-ctx.Done()
	// shutdown on cancellation
	wp.doCancel(ctx.Err())
	return nil
}

func (wp *WorkerPool) doCancel(cause error) {
	if cause == nil {
		cause = context.Canceled
	}

	if wp.cancelled.CompareAndSwap(false, true) {
		defer close(wp.ch)
		defer close(wp.cancel)
		wp.err = cause

		if wp.onCancel != nil {
			wp.onCancel(cause)
		}
	}
}

// IsCancelled tells if shutdown has been initiated
func (wp *WorkerPool) IsCancelled() bool {
	return wp.cancelled.Load()
}

// Wait blocks until all workers have finished.
func (wp *WorkerPool) Wait() error { return wp.wg.Wait() }

// Cancelled returns a channel that indicates when a shutdown has
// started/
func (wp *WorkerPool) Cancelled() <-chan struct{} {
	return wp.cancel
}

// Done returns a channel that indicates when all workers have finished.
func (wp *WorkerPool) Done() <-chan struct{} { return wp.wg.Done() }

// OnShutdown receives a function to call when shutdown has
// been initiated, and the cause.
func (wp *WorkerPool) OnShutdown(fn func(error)) {
	wp.onCancel = fn
}

// NewWorkerPool creates a [WorkerPool] with a specified number of workers
// using the given [Client].
func NewWorkerPool(c Client, maxWorkers int) (*WorkerPool, error) {
	if c == nil || maxWorkers < 0 {
		return nil, core.ErrInvalid
	}

	if maxWorkers == 0 {
		maxWorkers = DefaultWorkerPoolSize
	}

	p := &WorkerPool{
		cancel: make(chan struct{}),

		c:   c,
		max: maxWorkers,
	}

	return p, nil
}
