package server

import (
	"net"
	"net/netip"
	"syscall"

	"darvaza.org/core"
	"darvaza.org/darvaza/shared/net/bind"
)

// ListenAndServe listens all ports and run the Server
func (srv *Server) ListenAndServe() error {
	if err := srv.Listen(); err != nil {
		return err
	}

	return srv.Serve()
}

// Listen opens all addresses in TCP and UDP. if the
// port isn't specified, :53 is used.
func (srv *Server) Listen() error {
	if srv.ctx == nil {
		srv.SetDefaults()
	}

	lc := bind.NewListenConfig(srv.ctx, 0)
	return srv.ListenWithListener(lc)
}

// ListenWithUpgrader uses a bind.ListenerUpgrader like tableflip
// to open all addresses in TCP and UDP. if the
// port isn't specified, :53 is used.
func (srv *Server) ListenWithUpgrader(upg bind.Upgrader) error {
	if upg == nil {
		return core.Wrap(core.ErrInvalid, "no Upgrader provided")
	}

	if srv.ctx == nil {
		srv.SetDefaults()
	}

	lc := bind.NewListenConfig(srv.ctx, 0)
	return srv.ListenWithListener(lc.WithUpgrader(upg))
}

// ListenWithListener uses a net.ListenerConfig context to
// opens all addresses in TCP and UDP. if the
// port isn't specified, :53 is used.
func (srv *Server) ListenWithListener(lc bind.TCPUDPListener) error {
	if lc == nil {
		return core.Wrap(core.ErrInvalid, "no ListenerConfig provided")
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()

	if len(srv.UDP) > 0 || len(srv.TCP) > 0 {
		return core.Wrap(syscall.EBUSY, "server already listening")
	}

	// sanitize addresses
	addrs, err := ParsePortAddr(DefaultDNSPort, srv.Addr...)
	if err != nil {
		return err
	}

	// listen
	udp, tcp, err := srv.unsafeListenAll(lc, addrs)
	if err != nil {
		return err
	}

	// store
	srv.Addr = AddrPortStrings(addrs)
	srv.TCP = tcp
	srv.UDP = udp
	return nil
}

func (srv *Server) unsafeListenAll(lc bind.TCPUDPListener,
	addrs []netip.AddrPort) ([]net.PacketConn, []net.Listener, error) {
	//
	var ok bool

	udp := make([]net.PacketConn, 0, len(addrs))
	tcp := make([]net.Listener, 0, len(addrs))

	defer func() {
		if !ok {
			// close all
			CloseAll(udp)
			CloseAll(tcp)
		}
	}()

	for _, ap := range addrs {
		udpLsn, tcpLsn, err := srv.unsafeListenOne(lc, ap)
		if err != nil {
			return nil, nil, err
		}

		udp = append(udp, udpLsn)
		tcp = append(tcp, tcpLsn)
	}

	ok = true
	return udp, tcp, nil
}

func (*Server) unsafeListenOne(lc bind.TCPUDPListener,
	ap netip.AddrPort) (net.PacketConn, net.Listener, error) {
	//
	ip := net.IP(ap.Addr().AsSlice())
	port := int(ap.Port())

	tcpLsn, err := lc.ListenTCP("tcp", &net.TCPAddr{
		IP:   ip,
		Port: port,
	})

	if err != nil {
		return nil, nil, err
	}

	udpLsn, err := lc.ListenUDP("udp", &net.UDPAddr{
		IP:   ip,
		Port: port,
	})
	if err != nil {
		_ = tcpLsn.Close()
		return nil, nil, err
	}

	return udpLsn, tcpLsn, nil
}

// Close closes all listeners if the server isn't running,
// or initiates an immediate [srv.Shutdown].
func (srv *Server) Close() error {
	return srv.ShutdownWithTimeout(0)
}
