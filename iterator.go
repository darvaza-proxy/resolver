package resolver

import (
	"context"
	"fmt"
	"net"

	"darvaza.org/core"
	"github.com/miekg/dns"

	"darvaza.org/resolver/pkg/client"
	"darvaza.org/resolver/pkg/errors"
)

var _ Lookuper = (*RootLookuper)(nil)
var _ Exchanger = (*RootLookuper)(nil)

var roots = map[string]string{
	"a.root-servers.net": "198.41.0.4",
	"b.root-servers.net": "199.9.14.201",
	"c.root-servers.net": "192.33.4.12",
	"d.root-servers.net": "199.7.91.13",
	"e.root-servers.net": "192.203.230.10",
	"f.root-servers.net": "192.5.5.241",
	"g.root-servers.net": "192.112.36.4",
	"h.root-servers.net": "198.97.190.53",
	"i.root-servers.net": "192.36.148.17",
	"j.root-servers.net": "192.58.128.30",
	"k.root-servers.net": "193.0.14.129",
	"l.root-servers.net": "199.7.83.42",
	"m.root-servers.net": "202.12.27.33",
}

// RootLookuper does iterative lookup using the given root-server
// as starting point
type RootLookuper struct {
	c     client.Client
	Start string
}

// NewRootLookuper creates a RootLookuper using the indicated root, or random
// if the argument is ""
func NewRootLookuper(start string) (*RootLookuper, error) {
	return safeNewRootLookuper(start, nil)
}

// NewRootLookuperWithClient creates a RootLookuper using the indicated root, or
// random if the argument is "", and uses the given [client.Client] to connect.
func NewRootLookuperWithClient(start string, c client.Client) (*RootLookuper, error) {
	return safeNewRootLookuper(start, c)
}

func safeNewRootLookuper(start string, c client.Client) (*RootLookuper, error) {
	if c == nil {
		// use default singleflight client
		c1 := client.NewDefaultClient(0)
		c = client.NewSingleFlight(c1, 0)
	}

	if start == "" {
		return newRootLookuperUnchecked(pickRoot(), c), nil
	}

	for _, addr := range roots {
		if start == addr {
			return newRootLookuperUnchecked(addr, c), nil
		}
	}

	if addr, ok := roots[start]; ok {
		return newRootLookuperUnchecked(addr, c), nil
	}

	err := &net.DNSError{
		Err:  "invalid root server",
		Name: start,
	}

	return nil, err
}

func newRootLookuperUnchecked(start string, c client.Client) *RootLookuper {
	return &RootLookuper{
		c:     c,
		Start: start,
	}
}

// NewRootResolver creates a LookupResolver using iterative lookup from a given root-server,
// or random if the argument is ""
func NewRootResolver(start string) (*LookupResolver, error) {
	h, err := NewRootLookuper(start)
	if err != nil {
		return nil, err
	}
	return NewResolver(h), nil
}

// Lookup performs an iterative lookup
func (r RootLookuper) Lookup(ctx context.Context, qName string, qType uint16) (*dns.Msg, error) {
	return r.Iterate(ctx, qName, qType, "")
}

// Exchange queries any root server and validates the response
func (r RootLookuper) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	return r.IterateMsg(ctx, m, "")
}

func (r RootLookuper) doExchange(ctx context.Context, m *dns.Msg,
	server string) (*dns.Msg, error) {
	// TODO: add cache

	c := r.c
	if c == nil {
		c = client.NewDefaultClient(0)
	}

	resp, _, err := c.ExchangeContext(ctx, m, server)
	if err := errors.ValidateResponse(server, resp, err); err != nil {
		return nil, err
	}

	return resp, nil
}

// Iterate is an iterative lookup implementation
func (r RootLookuper) Iterate(ctx context.Context, name string,
	qtype uint16, startAt string,
) (*dns.Msg, error) {
	if ctx == nil {
		return nil, errors.ErrBadRequest()
	}

	req := r.newMsgFromParts(dns.Fqdn(name), dns.ClassINET, qtype)
	return r.unsafeIterateMsg(ctx, req, startAt)
}

// IterateMsg is an iterative exchange implementation
func (r RootLookuper) IterateMsg(ctx context.Context, req *dns.Msg,
	startAt string,
) (*dns.Msg, error) {
	if ctx == nil || req == nil {
		return nil, errors.ErrBadRequest()
	}

	if q := msgQuestion(req); q != nil {
		// sanitize request
		req = r.newMsgFromParts(q.Name, q.Qclass, q.Qtype)
		return r.unsafeIterateMsg(ctx, req, startAt)
	}

	// nothing to answer
	msg := new(dns.Msg)
	msg.SetReply(req)
	return msg, nil
}

func (r RootLookuper) unsafeIterateMsg(ctx context.Context, req *dns.Msg,
	startAt string,
) (*dns.Msg, error) {
	var server string

	switch {
	case startAt != "":
		server = startAt
	case r.Start != "":
		server = r.Start
	default:
		server = pickRoot()
	}

	return r.doIterate(ctx, req, server)
}

func (r RootLookuper) doIterate(ctx context.Context, req *dns.Msg,
	server string,
) (*dns.Msg, error) {
	//
	for {
		var err error
		var resp *dns.Msg

		server, resp, err = r.doIteratePass(ctx, req, server)
		switch {
		case err != nil:
			return nil, err
		case resp != nil:
			return resp, nil
		}
	}
}

func (r RootLookuper) doIteratePass(ctx context.Context, req *dns.Msg,
	server string,
) (string, *dns.Msg, error) {
	//
	server, err := AsServerAddress(server)
	if err != nil {
		return "", nil, err
	}

	resp, err := r.doExchange(ctx, req, server)
	switch {
	case err != nil:
		return "", nil, err
	case resp == nil:
		return "", nil, errors.ErrBadResponse()
	case resp.Rcode == dns.RcodeSuccess:
		switch {
		case len(resp.Answer) > 0:
			return r.handleSuccessAnswer(ctx, req, resp, server)
		case HasNsType(resp, dns.TypeNS):
			return r.handleSuccessDelegation(ctx, req, resp, server)
		default:
			return "", nil, errors.ErrBadResponse()
		}
	default:
		return "", nil, errors.ErrBadResponse()
	}
}

func (RootLookuper) handleSuccessAnswer(_ context.Context,
	req *dns.Msg, resp *dns.Msg, server string,
) (string, *dns.Msg, error) {
	if HasAnswerType(resp, msgQType(req)) {
		// we got what we asked for
		return "", resp, nil
	}

	// we asked for some type but we got back a CNAME so
	// we need to query further with the same type but the
	// new name.
	if rr := GetFirstAnswer[*dns.CNAME](resp); rr != nil {
		req.Question[0].Name = dns.Fqdn(rr.Target)
		return server, nil, nil
	}

	return "", nil, errors.ErrBadResponse()
}

func (r RootLookuper) handleSuccessDelegation(ctx context.Context,
	_ *dns.Msg, resp *dns.Msg, _ string,
) (string, *dns.Msg, error) {
	if len(resp.Extra) < 2 {
		// name zone
		server, err := r.getNextServer(ctx, r.getNS(resp.Ns))
		return server, nil, err
	}

	// Delegation
	server, err := r.getNextServer(ctx, r.getA(resp.Extra))
	return server, nil, err
}

func (r RootLookuper) getNextServer(ctx context.Context, servers []string) (string, error) {
	var err error

	nns, ok := core.SliceRandom(servers)
	if !ok {
		return "", fmt.Errorf("cannot extract nextServer from list")
	}

	server, ok := roots[nns]
	if !ok {
		server = nns
		if !isIP4(server) {
			server, err = r.hostFromRoot(ctx, nns)
			if err != nil {
				return "", err
			}
		}
	}

	return server, nil
}

func (RootLookuper) getA(answers []dns.RR) []string {
	var out []string

	for _, ref := range answers {
		if rr, ok := ref.(*dns.A); ok {
			out = append(out, rr.A.String())
		}
	}

	return out
}

func (RootLookuper) getNS(answers []dns.RR) []string {
	var out []string

	for _, ref := range answers {
		if rr, ok := ref.(*dns.NS); ok {
			out = append(out, Decanonize(rr.Ns))
		}
	}

	return out
}

func (r RootLookuper) getOneA(answers []dns.RR) (string, bool) {
	return core.SliceRandom(r.getA(answers))
}

func (r RootLookuper) hostFromRoot(ctx context.Context, h string) (string, error) {
	msg, err := r.Iterate(ctx, h, dns.TypeA, "")
	if err != nil {
		return "", err
	}

	result, ok := r.getOneA(msg.Answer)
	if !ok {
		return "", fmt.Errorf("cannot select random from answer")
	}
	return result, nil
}

func (RootLookuper) newMsgFromParts(qName string, qClass uint16, qType uint16) *dns.Msg {
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: false,
		},
		Question: []dns.Question{
			{
				Name:   qName,
				Qclass: qClass,
				Qtype:  qType,
			},
		},
	}

	msg = msg.SetEdns0(dns.DefaultMsgSize, false)
	return msg
}

func pickRoot() string {
	// randomized by range internally
	for _, x := range roots {
		return x
	}
	return ""
}
