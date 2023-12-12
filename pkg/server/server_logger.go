package server

import (
	"net/netip"

	"darvaza.org/core"
	"darvaza.org/slog"
	"github.com/miekg/dns"
)

func (srv *Server) error(err error) slog.Logger {
	l := srv.Logger.Error()
	if err != nil {
		l = l.WithField(slog.ErrorFieldName, err)
	}
	return l
}

func (srv *Server) info() slog.Logger {
	return srv.Logger.Info()
}

func (srv *Server) sayListening(s *dns.Server) {
	if log, ok := srv.info().WithEnabled(); ok {
		var ap netip.AddrPort

		t, n, _ := DNSServerAddr(s)
		if n != nil {
			ap, _ = core.AddrPort(n)
		}

		switch {
		case !ap.IsValid():
			log = srv.error(nil)
			srv.sayListeningString(log, t, n.String())
		case !ap.Addr().IsUnspecified():
			srv.sayListeningString(log, t, ap.String())
		default:
			srv.sayListeningUnspecified(t, ap.Addr(), ap.Port())
		}
	}
}

func (srv *Server) sayListeningUnspecified(t string, ip netip.Addr, port uint16) {
	nAddrs, _ := core.GetIPAddresses()
	if len(nAddrs) == 0 {
		nAddrs = []netip.Addr{ip}
	}

	sAddrs := make([]string, 0, len(nAddrs))
	for _, ip := range nAddrs {
		ap := netip.AddrPortFrom(ip, port)
		sAddrs = append(sAddrs, ap.String())
	}

	for _, s := range sAddrs {
		srv.sayListeningString(srv.info(), t, s)
	}
}

func (*Server) sayListeningString(log slog.Logger, transport string, s string) {
	log.Printf("listening %s (%s)", s, transport)
}
