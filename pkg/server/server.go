// Package server aids writing DNS servers
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"darvaza.org/slog"
	"darvaza.org/slog/handlers/discard"
)

const (
	// DefaultDNSPort is the port we listen if none is specified on the address.
	DefaultDNSPort = 53
)

// Server is a DNS resolver
type Server struct {
	Addr    []string
	Handler dns.Handler

	Context   context.Context
	TLSConfig *tls.Config
	Logger    slog.Logger

	TCP []net.Listener
	UDP []net.PacketConn
	dns []*dns.Server

	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	cancelled atomic.Bool

	eg    *errgroup.Group
	egCtx context.Context
}

// SetDefaults fills gaps in the configuration
func (srv *Server) SetDefaults() {
	// Handler
	if srv.Handler == nil {
		srv.Handler = dns.NewServeMux()
	}

	// Context
	if srv.Context == nil {
		srv.Context = context.Background()
	}

	if srv.ctx == nil {
		ctx, cancel := context.WithCancel(srv.Context)
		srv.ctx = ctx
		srv.cancel = cancel
	}

	if srv.eg == nil {
		eg, ctx := errgroup.WithContext(srv.ctx)
		srv.eg = eg
		srv.egCtx = ctx
	}

	// Logger
	if srv.Logger == nil {
		srv.Logger = discard.New()
	}
}

// Serve runs the DNS resolver until shutdown
func (srv *Server) Serve() error {
	if err := srv.prepare(); err != nil {
		return err
	}

	srv.spawnAll()
	return srv.eg.Wait()
}

// Spawn launches all workers but waits a given time
// for early failures.
func (srv *Server) Spawn(wait time.Duration) error {
	if err := srv.prepare(); err != nil {
		return err
	}

	srv.spawnAll()
	if wait > 0 {
		select {
		case <-time.After(wait):
			// done waiting
			return nil
		case <-srv.egCtx.Done():
			// failed while waiting
			return srv.eg.Wait()
		}
	}
	return nil
}

// ShutdownWithTimeout initiates a graceful shutdown
func (srv *Server) ShutdownWithTimeout(wait time.Duration) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.cancelled.CompareAndSwap(false, true) {
		// shutdown workers
		srv.cancel()

		// close listeners
		CloseAll(srv.TCP)
		CloseAll(srv.UDP)
		srv.TCP = []net.Listener{}
		srv.UDP = []net.PacketConn{}
	}

	if wait > 0 {
		// and wait for workers to finish
		waitCh := make(chan error)
		defer close(waitCh)

		go func() {
			waitCh <- srv.eg.Wait()
		}()

		select {
		case <-time.After(wait):
			return errors.New("shutdown timed out")
		case err := <-waitCh:
			return err
		}
	}

	return nil
}

// Wait blocks until all workers have stopped
func (srv *Server) Wait() error {
	return srv.eg.Wait()
}

// Cancelled tells if a shutdown has been initiated
func (srv *Server) Cancelled() bool {
	return srv.cancelled.Load()
}
