package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"

	"darvaza.org/core"
	"github.com/miekg/dns"
)

var _ Lookuper = (*RootLookuper)(nil)

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
	start := r.Start
	if start == "" {
		start = pickRoot()
	}

	return r.Iterate(ctx, qName, qType, start+":53")
}

// Exchange queries a server and validates the response
func (r RootLookuper) Exchange(ctx context.Context, m *dns.Msg, server string) (*dns.Msg, error) {
	var resp *dns.Msg
	var err error

	if r.c != nil {
		resp, _, err = r.c.ExchangeContext(ctx, m, server)
	} else {
		resp, err = dns.ExchangeContext(ctx, m, server)
	}

	if werr := validateResp(server, resp, err); werr != nil {
		return nil, werr
	}

	return resp, nil
}

// Iterate is an iterative lookup implementation
// revive:disable:cognitive-complexity
// revive:disable:cyclomatic
func (r RootLookuper) Iterate(ctx context.Context, name string,
	qtype uint16, startAt string,
) (*dns.Msg, error) {
	// revive:enable:cognitive-complexity
	// revive:enable:cyclomatic
	if startAt == "" {
		startAt = pickRoot() + ":53"
	}
	server := startAt
	name = dns.Fqdn(name)

	msg := r.newMsgFromParts(name, qtype)
	resp, err := r.Exchange(ctx, msg, server)
	if err != nil {
		return nil, err
	}

	nextServer := make([]string, 0)
	rCase := typify(resp)
	switch rCase {
	case "Delegation", "Namezone":
		if rCase == "Delegation" {
			for _, ref := range resp.Extra {
				if ref.Header().Rrtype == dns.TypeA {
					nextServer = append(nextServer, ref.(*dns.A).A.String())
				}
			}
		} else {
			for _, ns := range resp.Ns {
				if ns.Header().Rrtype == dns.TypeNS {
					nextServer = append(nextServer, strings.TrimSuffix(ns.(*dns.NS).Ns, "."))
				}
			}
		}
		nns, ok := core.SliceRandom(nextServer)
		if !ok {
			return nil, fmt.Errorf("cannot extract nextServer from list")
		}
		server, ok = roots[nns]
		if !ok {
			server = nns
			if !isIP4(server) {
				if server, err = r.hostFromRoot(ctx, nns); err != nil {
					return nil, err
				}
			}
		}
		return r.Iterate(ctx, name, qtype, server+":53")
	case "Answer":
		return resp, nil
	case "Cname":
		return r.Iterate(ctx, resp.Answer[0].(*dns.CNAME).Target, qtype, "")
	default:
		return nil, fmt.Errorf("got error %s", rCase)
	}
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

func (RootLookuper) newMsgFromParts(qName string, qType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(qName, qType)
	msg.RecursionDesired = false
	msg = msg.SetEdns0(65000, false)
	return msg
}

func pickRoot() string {
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

func recType(m *dns.Msg) string {
	if len(m.Answer) > 0 {
		if m.Answer[0].Header().Rrtype == dns.TypeCNAME {
			return "Cname"
		}
		return "Answer"
	}
	if len(m.Ns) > 0 {
		if len(m.Extra) < 2 {
			return "Namezone"
		}
	}
	return "Delegation"
}
