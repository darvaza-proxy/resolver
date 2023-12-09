// Package client implements DNS client wrappers
package client

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

var (
	_ Client = (*dns.Client)(nil)
	_ Client = (ExchangeFunc)(nil)
)

// A Client makes a request to a server
type Client interface {
	ExchangeContext(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error)
}

// ExchangeFunc is a function that implements the [Client] interface
type ExchangeFunc func(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error)

// ExchangeContext implements the [Client] interface
func (fn ExchangeFunc) ExchangeContext(ctx context.Context, req *dns.Msg,
	server string) (*dns.Msg, time.Duration, error) {
	return fn(ctx, req, server)
}

// NewDefaultClient allocate a default [dns.Client] in the same
// manner as dns.ExchangeContext(), plain UDP.
func NewDefaultClient(udpSize uint16) *dns.Client {
	if udpSize == 0 {
		udpSize = dns.DefaultMsgSize
	}

	c := &dns.Client{Net: "udp"}
	c.UDPSize = udpSize
	return c
}
