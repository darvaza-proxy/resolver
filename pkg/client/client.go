// Package client implements DNS client wrappers
package client

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

var (
	_ Client = (*dns.Client)(nil)
)

// A Client makes a request to a server
type Client interface {
	ExchangeContext(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error)
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
