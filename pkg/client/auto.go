package client

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"darvaza.org/resolver/pkg/errors"
	"darvaza.org/resolver/pkg/exdns"
)

var (
	_ Client = (*Auto)(nil)
)

// Auto is a client that allows different networks based on the server's
// prefix.
// * udp:// for UDP-only
// * tcp:// for TCP-only
// * tls:// for TCP+TLS
// * and without prefix for TCP-fallback
type Auto struct {
	UDP Client
	TCP Client
	TLS Client

	sfc *SingleFlight
}

// ExchangeContext uses different exchange networks based on the prefix
// of the server string.
func (c *Auto) ExchangeContext(ctx context.Context, req *dns.Msg,
	server string) (*dns.Msg, time.Duration, error) {
	//
	return c.sfc.ExchangeContext(ctx, req, server)
}

func (c *Auto) sfExchange(ctx context.Context, req *dns.Msg,
	server string) (*dns.Msg, time.Duration, error) {
	//
	for _, p := range []string{
		"udp://",
		"tcp://",
		"tls://",
	} {
		if s, ok := strings.CutPrefix(server, p); ok {
			return c.sfNetExchange(ctx, req, p, s)
		}
	}

	return c.sfAutoExchange(ctx, req, server)
}

func (c *Auto) sfAutoExchange(ctx context.Context, req *dns.Msg,
	server string) (*dns.Msg, time.Duration, error) {
	//
	if c.UDP != nil || c.TCP != nil {
		var resp *dns.Msg
		var err error

		start := time.Now()
		truncated := true

		if c.UDP != nil {
			resp, _, err = c.UDP.ExchangeContext(ctx, req, server)
			err = exdns.ValidateResponse(server, resp, err)
			truncated = isTruncated(err)
		}

		if truncated && c.TCP != nil {
			resp, _, err = c.TCP.ExchangeContext(ctx, req, server)
		}

		return resp, time.Since(start), err
	}

	return nil, 0, errors.ErrNotImplemented("")
}

func (c *Auto) sfNetExchange(ctx context.Context, req *dns.Msg,
	network string, server string) (*dns.Msg, time.Duration, error) {
	//
	var next Client

	switch network {
	case "udp://":
		next = c.UDP
	case "tcp://":
		next = c.TCP
	case "tls://":
		next = c.TLS
	}

	if next == nil {
		return nil, 0, errors.ErrNotImplemented(network)
	}

	return next.ExchangeContext(ctx, req, server)
}

func isTruncated(err error) bool {
	if e, ok := err.(*net.DNSError); ok {
		return e.Err == errors.TRUNCATED
	}
	return false
}

// NewAutoClient allocates a new [Auto] client. If changes to fields are done
// manually after this call, or manually assembling the [Auto] struct, it is
// required to call [Auto.SetDefaults].
//
// NewAutoClient allows specifying a custom expiration value for [SingleFlight], but
// when [Auto] is assembled manually or `exp == 0`,
// [DefaultSingleFlightExpiration] will be used.
func NewAutoClient(udp, tcp Client, exp time.Duration) (*Auto, error) {
	c := &Auto{
		UDP: udp,
		TCP: tcp,
	}

	c.sfc = NewSingleFlight(ExchangeFunc(c.sfExchange), exp)
	if err := c.SetDefaults(); err != nil {
		return nil, err
	}

	return c, nil
}

// SetDefaults fills the configuration gaps
func (c *Auto) SetDefaults() error {
	if err := c.setUDP(); err != nil {
		return err
	}

	if err := c.setTCP(); err != nil {
		return err
	}

	if err := c.setTLS(); err != nil {
		return err
	}

	if c.sfc == nil {
		c.sfc = NewSingleFlight(ExchangeFunc(c.sfExchange), 0)
	}

	return nil
}

func (c *Auto) setUDP() error {
	if c.UDP == nil {
		c.UDP = NewDefaultClient(0)
	}

	if dc := Unwrap(c.UDP); dc != nil {
		// make sure it's set for UDP connections
		dc.Net = "udp"
	}

	return nil
}

func (c *Auto) setTCP() error {
	if c.TCP == nil {
		c.TCP = new(dns.Client)
	}

	if dc := Unwrap(c.TCP); dc != nil {
		// make sure it's set for TCP connections
		dc.Net = "tcp"
	}

	return nil
}

func (c *Auto) setTLS() error {
	dc := Unwrap(c.TLS)
	switch {
	case dc == nil:
		// nothing we can do
		return nil
	case dc.TLSConfig == nil:
		// incomplete
		return errors.New("TLS Client doesn't contain TLS Config")
	default:
		// make sure it's set for TLS connections
		dc.Net = "tcp+tls"
		return nil
	}
}
