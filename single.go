package resolver

import (
	"context"

	"github.com/miekg/dns"
)

// SingleLookuper asks a single server for a direct answer
// to the query preventing repetition
type SingleLookuper struct {
	c         *dns.Client
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
	if werr := validateResp(r.remote, res, err); werr != nil {
		return nil, werr
	}

	return res, nil
}

// NewSingleLookuper creates a Lookuper that asks one particular
// server
func NewSingleLookuper(server string, recursive bool) (*SingleLookuper, error) {
	server, err := AsServerAddress(server)
	if err != nil {
		return nil, err
	}

	return newSingleLookuperUnsafe(server, recursive), nil
}

func newSingleLookuperUnsafe(server string, recursive bool) *SingleLookuper {
	c := new(dns.Client)
	c.SingleInflight = true
	c.UDPSize = DefaultUDPSize

	return &SingleLookuper{
		c:         c,
		remote:    server,
		recursive: recursive,
	}
}
