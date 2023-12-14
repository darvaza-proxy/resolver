package resolver

import (
	"context"

	"darvaza.org/resolver/pkg/exdns"
	"github.com/miekg/dns"
)

// LookupTXT returns the DNS TXT records for the given domain name
func (r LookupResolver) LookupTXT(ctx context.Context,
	name string) ([]string, error) {
	//
	var txt []string

	name, err := sanitiseHost(name, r.loose)
	if err != nil {
		return nil, err
	}

	msg, err := r.h.Lookup(ctx, dns.CanonicalName(name), dns.TypeTXT)

	exdns.ForEachAnswer(msg, func(rr *dns.TXT) {
		if txt == nil {
			txt = rr.Txt
		} else {
			txt = append(txt, rr.Txt...)
		}
	})

	return txt, err
}
