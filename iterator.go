package resolver

import (
	"context"
	"fmt"
	"net"

	"darvaza.org/core"
	"github.com/miekg/dns"

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
	c     *dns.Client
	Start string
}

// NewRootLookuper creates a RootLookuper using the indicated root, or random
// if the argument is ""
func NewRootLookuper(start string) (*RootLookuper, error) {
	if start == "" {
		return newRootLookuperUnchecked(pickRoot()), nil
	}

	for _, addr := range roots {
		if start == addr {
			return newRootLookuperUnchecked(addr), nil
		}
	}

	if addr, ok := roots[start]; ok {
		return newRootLookuperUnchecked(addr), nil
	}

	err := &net.DNSError{
		Err:  "invalid root server",
		Name: start,
	}
	return nil, err
}

func newRootLookuperUnchecked(start string) *RootLookuper {
	c := new(dns.Client)
	c.SingleInflight = true
	c.UDPSize = DefaultUDPSize

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
	//
	var resp *dns.Msg
	var err error

	// TODO: add cache

	if r.c != nil {
		resp, _, err = r.c.ExchangeContext(ctx, m, server)
	} else {
		resp, err = dns.ExchangeContext(ctx, m, server)
	}

	if werr := errors.ValidateResponse(server, resp, err); werr != nil {
		return nil, werr
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
		server = r.Start + ":53"
	default:
		server = pickRoot() + ":53"
	}

	return r.doIterate(ctx, req, server)
}

func (r RootLookuper) doIterate(ctx context.Context, req *dns.Msg,
	server string,
) (*dns.Msg, error) {
	resp, err := r.doExchange(ctx, req, server)
	if err != nil {
		return nil, err
	}

	rCase := typify(resp)
	switch rCase {
	case "Delegation":
		servers := r.getNextServer(resp.Extra, dns.TypeA)
		return r.doIterateNext(ctx, req, servers)
	case "Namezone":
		servers := r.getNextServer(resp.Ns, dns.TypeNS)
		return r.doIterateNext(ctx, req, servers)
	case "Answer":
		return resp, nil
	case "Cname":
		// we asked for something else, noit CNAME so continue with the
		// same type but the new name
		if rr := GetFirstAnswer[*dns.CNAME](resp); rr != nil {
			name := rr.Target
			qType := msgQType(req)
			return r.Iterate(ctx, name, qType, server)
		}
		return nil, errors.ErrBadResponse()
	case "NoRecord":
		return nil, fmt.Errorf("no record")
	default:
		return nil, fmt.Errorf("got error %s", rCase)
	}
}

func (r RootLookuper) doIterateNext(ctx context.Context, req *dns.Msg, nextServer []string,
) (*dns.Msg, error) {
	var err error

	nns, ok := core.SliceRandom(nextServer)
	if !ok {
		return nil, fmt.Errorf("cannot extract nextServer from list")
	}

	server, ok := roots[nns]
	if !ok {
		server = nns
		if !isIP4(server) {
			if server, err = r.hostFromRoot(ctx, nns); err != nil {
				return nil, err
			}
		}
	}

	return r.doIterate(ctx, req, server+":53")
}

// revive:disable:cognitive-complexity
func (RootLookuper) getNextServer(answers []dns.RR, aType uint16) []string {
	// revive:enable:cognitive-complexity
	var out []string

	switch aType {
	case dns.TypeA:
		for _, ref := range answers {
			if rr, ok := ref.(*dns.A); ok {
				out = append(out, rr.A.String())
			}
		}
	case dns.TypeNS:
		for _, ref := range answers {
			if rr, ok := ref.(*dns.NS); ok {
				out = append(out, Decanonize(rr.Ns))
			}
		}
	}

	return out
}

func isIP4(s string) bool {
	return net.ParseIP(s) != nil
}

func (r RootLookuper) hostFromRoot(ctx context.Context, h string) (string, error) {
	askRoot := pickRoot()
	if askRoot == "" {
		return "", fmt.Errorf("could not pick root")
	}
	askRoot = askRoot + ":53"
	msg, err := r.Iterate(ctx, h, dns.TypeA, askRoot)
	if err != nil {
		return "", err
	}

	ans, ok := core.SliceRandom(msg.Answer)
	if !ok {
		return "", fmt.Errorf("cannot select random from answer")
	}
	result := ans.(*dns.A).A.String()
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

	msg = msg.SetEdns0(2048, false)
	return msg
}

func pickRoot() string {
	// randomized by range internally
	for _, x := range roots {
		return x
	}
	return ""
}

func typify(m *dns.Msg) string {
	if m != nil {
		switch m.Rcode {
		case dns.RcodeSuccess:
			return recType(m)
		case dns.RcodeRefused:
			return "Refused"
		case dns.RcodeFormatError:
			return "NoEDNS"
		default:
			return "Unknown"
		}
	}
	return "Nil message"
}

// revive:disable:cognitive-complexity
func recType(m *dns.Msg) string {
	// revive:enable:cognitive-complexity
	if len(m.Answer) > 0 {
		if m.Question[0].Qtype == m.Answer[0].Header().Rrtype {
			// we got what we asked for
			return "Answer"
		}
		// we asked for some type but we got back a CNAME so
		// we need to query further
		return "Cname"
	}

	if len(m.Ns) > 0 && m.Ns[0].Header().Rrtype == dns.TypeNS {
		if len(m.Extra) < 2 {
			return "Namezone"
		}
		return "Delegation"
	}
	if m.Authoritative {
		return "NoRecord"
	}
	return "Unknown"
}
