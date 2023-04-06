// Package resolver provides DNS lookup functions
package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"darvaza.org/core"
	"github.com/miekg/dns"
)

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

// Iterate is an iterative lookup implementation
// revive:disable:cognitive-complexity
// revive:disable:cyclomatic
func Iterate(ctx context.Context, name string,
	qtype uint16, startAt string,
) (*dns.Msg, error) {
	// revive:enable:cognitive-complexity
	// revive:enable:cyclomatic
	if startAt == "" {
		return nil, fmt.Errorf("no anchor given")
	}
	server := startAt
	name = dns.Fqdn(name)
	msg := newMsgFromParts(name, qtype)
	resp, err := dns.ExchangeContext(ctx, msg, server)
	if werr := validateResp(resp, err); werr != nil {
		return nil, werr
	}

	if len(resp.Answer) == 0 {
		nextServer := make([]string, 0)
		if len(resp.Ns) > 0 {
			if len(resp.Extra) > 1 {
				// we have referral and GLUE so use GLUE
				// nextServer is an IP, no need to look it up
				// we always have 1 Extra because we increase UDP
				// packet size
				for _, ref := range resp.Extra {
					if ref.Header().Rrtype == dns.TypeA {
						nextServer = append(nextServer, ref.(*dns.A).A.String())
					}
				}
			} else {
				// We have referral but no GLUE, use referral
				// nextServer is a hostname and we need to look it up
				for _, ns := range resp.Ns {
					if ns.Header().Rrtype == dns.TypeNS {
						nextServer = append(nextServer, strings.TrimSuffix(ns.(*dns.NS).Ns, "."))
					}
				}
			}
			nns, ok := core.SliceRandom(nextServer)
			if !ok {
				return nil, fmt.Errorf("cannot extract nextServer from referrals")
			}
			// is the nextServer a Root Server?
			server, ok = roots[nns]
			if !ok {
				// server is not a root server set it back
				server = nns
				if !isIP4(server) {
					// server is a hostname we  need to resolve
					if server, err = hostFromRoot(ctx, nns); err != nil {
						return nil, err
					}
				}
			}
			return Iterate(ctx, name, qtype, server+":53")
		}
		return nil, fmt.Errorf("server %s is lame, gave no answer nor referal", server)
	}
	// We got an answer
	return resp, nil
}

func isIP4(s string) bool {
	return net.ParseIP(s) != nil
}

func hostFromRoot(ctx context.Context, h string) (string, error) {
	askRoot := pickRoot()
	if askRoot == "" {
		return "", fmt.Errorf("could not pick root")
	}
	askRoot = askRoot + ":53"
	msg, err := Iterate(ctx, h, dns.TypeA, askRoot)
	if werr := validateResp(msg, err); werr != nil {
		return "", werr
	}
	ans, ok := core.SliceRandom(msg.Answer)
	if !ok {
		return "", fmt.Errorf("cannot select random from answer")
	}
	result := ans.(*dns.A).A.String()
	return result, nil
}

func newMsgFromParts(qName string, qType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(qName, qType)
	msg.RecursionDesired = false
	msg = msg.SetEdns0(65000, false)
	return msg
}

func pickRoot() string {
	var mu sync.RWMutex
	mu.RLock()
	defer mu.RUnlock()
	for _, x := range roots {
		return x
	}
	return ""
}

func validateResp(r *dns.Msg, err error) error {
	if err != nil {
		return err
	}
	if r.Truncated {
		return fmt.Errorf("dns response was truncated")
	}
	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("dns response error: %s", dns.RcodeToString[r.Rcode])
	}
	return nil
}
