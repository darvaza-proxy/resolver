package resolver

import (
	"context"

	"darvaza.org/resolver/pkg/client"
	"darvaza.org/resolver/pkg/errors"
	"github.com/miekg/dns"
)

var (
	_ Lookuper  = (*SingleLookuper)(nil)
	_ Exchanger = (*SingleLookuper)(nil)
)

// SingleLookuper asks a single server for a direct answer
// to the query preventing repetition
type SingleLookuper struct {
	c         client.Client
	remote    string
	recursive bool
}

// Lookup asks the designed remote to make a DNS Lookup
func (r SingleLookuper) Lookup(ctx context.Context,
	qName string, qType uint16) (*dns.Msg, error) {
	//
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: r.recursive,
		},
		Question: []dns.Question{
			{Name: qName, Qtype: qType, Qclass: dns.ClassINET},
		},
	}

	return r.Exchange(ctx, m)
}

// Exchange exchanges a message with a designed server
func (r SingleLookuper) Exchange(ctx context.Context,
	msg *dns.Msg) (*dns.Msg, error) {
	//
	res, _, err := r.c.ExchangeContext(ctx, msg, r.remote)
	if werr := errors.ValidateResponse(r.remote, res, err); werr != nil {
		return nil, werr
	}

	return res, nil
}

// NewSingleLookuper creates a Lookuper that asks one particular
// server
func NewSingleLookuper(server string, recursive bool) (*SingleLookuper, error) {
	return NewSingleLookuperWithClient(server, recursive, nil)
}

// NewSingleLookuperWithClient creates a lookuper that asks one particular
// server using the provided DNS client
func NewSingleLookuperWithClient(server string, recursive bool,
	c client.Client) (*SingleLookuper, error) {
	//
	server, err := AsServerAddress(server)
	if err != nil {
		return nil, err
	}

	if c == nil {
		c1 := new(dns.Client)
		c1.UDPSize = DefaultUDPSize
		c = client.NewSingleFlight(c1, 0)
	}

	h := &SingleLookuper{
		c:         c,
		remote:    server,
		recursive: recursive,
	}
	return h, nil
}
