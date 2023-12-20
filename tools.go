package resolver

import (
	"fmt"
	"net"
	"strings"

	"darvaza.org/core"
	"github.com/miekg/dns"
	"golang.org/x/net/idna"

	"darvaza.org/resolver/pkg/errors"
)

const (
	netIP4or6  = "ip"
	netIP4only = "ip4"
	netIP6only = "ip6"
)

func sanitiseNetwork(network string) (string, error) {
	s := strings.ToLower(network)
	switch s {
	case "":
		return netIP4or6, nil
	case netIP4or6, netIP4only, netIP6only:
		return s, nil
	default:
		return "", fmt.Errorf("%q: invalid network", network)
	}
}

func sanitiseHost(host string, p *idna.Profile) (string, error) {
	if host != "" {
		s, err := p.ToASCII(host)
		if err != nil {
			return "", core.Wrap(err, "%q: invalid host", host)
		}
		return s, nil
	}

	return "", errors.New("empty host")
}

func sanitiseHost2(host string, p *idna.Profile) (string, *net.DNSError) {
	s, err := sanitiseHost(host, p)
	if err == nil {
		return s, nil
	}

	return "", &net.DNSError{
		Name: host,
		Err:  err.Error(),
	}
}

func eqIP(ip1, ip2 net.IP) bool {
	return ip1.Equal(ip2)
}

func msgQuestion(m *dns.Msg) *dns.Question {
	if m != nil && len(m.Question) > 0 {
		return &m.Question[0]
	}
	return nil
}

func msgQType(m *dns.Msg) uint16 {
	if q := msgQuestion(m); q != nil {
		return q.Qtype
	}
	return 0
}
