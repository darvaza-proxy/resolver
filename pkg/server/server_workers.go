package server

import (
	"syscall"

	"darvaza.org/core"
	"github.com/miekg/dns"
)

func (srv *Server) prepare() error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if len(srv.dns) > 0 {
		// BUSY
		return core.Wrap(syscall.EBUSY, "server already running")
	}

	if len(srv.TCP) == 0 && len(srv.UDP) == 0 {
		// No listeners
		return core.Wrap(core.ErrInvalid, "no listeners open")
	}

	// a new server for each listener
	for _, lsn := range srv.TCP {
		s := &dns.Server{
			Listener:  lsn,
			TLSConfig: srv.TLSConfig,
			Handler:   srv.Handler,
		}
		srv.dns = append(srv.dns, s)
	}

	for _, lsn := range srv.UDP {
		s := &dns.Server{
			PacketConn: lsn,
			TLSConfig:  srv.TLSConfig,
			Handler:    srv.Handler,
		}
		srv.dns = append(srv.dns, s)
	}

	return nil
}

func (srv *Server) spawnAll() {
	// spawn workers
	for i := range srv.dns {
		srv.spawnOne(srv.dns[i])
	}
}

func (srv *Server) spawnOne(s *dns.Server) {
	srv.eg.Go(func() error {
		if s.Listener != nil {
			defer s.Listener.Close()
		}

		if s.PacketConn != nil {
			defer s.PacketConn.Close()
		}

		srv.sayListening(s)
		err := s.ActivateAndServe()
		if srv.cancelled.Load() {
			// ignore errors when cancelled
			return nil
		}
		return err
	})

	srv.eg.Go(func() error {
		<-srv.egCtx.Done()
		return s.Shutdown()
	})
}
