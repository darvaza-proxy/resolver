// Package resolver provides DNS lookup functions
package resolver

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Resolver  is the struct that implements the Lookuper intrface
type Resolver struct {
	rootip string
}

// Lookuper is the interface that wraps the basic iterative Lookup method.
type Lookuper interface {
	Lookup(ctx context.Context, qNamei string, qType uint16) (*dns.Msg, error)
}

// NewResolver  returns a Resolver starting from a root server ip
func NewResolver(s string) *Resolver {
	return &Resolver{rootip: s}
}

// Lookup implements the Lookuper interface on the Resolver
// revive:disable:cognitive-complexity
func (r *Resolver) Lookup(name string, qtype uint16) (*dns.Msg, error) {
	// revive:enable:cognitive-complexity
	server := r.rootip
	name = dns.Fqdn(name)
	msg := newMsgFromParts(name, qtype)
	resp, _, err := clientTalk(msg, server)
	if werr := validateResp(resp, err); werr != nil {
		return nil, err
	}

	if len(resp.Answer) == 0 && len(resp.Ns) > 0 {
		// We are in referral mode, get the next server
		nextServer := make([]string, 0)
		for _, ns := range resp.Ns {
			if ns.Header().Rrtype == dns.TypeNS {
				nextServer = append(nextServer, strings.TrimSuffix(ns.(*dns.NS).Ns, "."))
			}
		}
		if len(nextServer) == 0 {
			return nil, fmt.Errorf("no authoritative server found in referral")
		}
		// Begin again with new forces
		newMsg := newMsgFromParts(name, dns.TypeNS)
		newMsg.Question[0].Qclass = dns.ClassINET

		nns := randomFromSlice(nextServer)
		rsp, _, err := clientTalk(newMsg, nns+":53")
		if wwerr := validateResp(rsp, err); wwerr != nil {
			return nil, err
		}
		r.rootip = nns + ":53"
		return r.Lookup(name, qtype)
	}
	// We got an answer
	return resp, nil
}

func newMsgFromParts(qName string, qType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(qName, qType)
	msg.RecursionDesired = false
	return msg
}

func clientTalk(msg *dns.Msg, server string) (r *dns.Msg, rtt time.Duration, err error) {
	client := &dns.Client{}
	client.Net = "tcp"

	return client.Exchange(msg, server)
}

func randomFromSlice(s []string) string {
	var result string

	switch len(s) {
	case 0:
		result = ""
	case 1:
		result = s[0]
	default:
		rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
		id := rnd.Intn(len(s))
		result = s[id]
	}
	return result
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
