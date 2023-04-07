package resolver

import (
	"net"

	"github.com/miekg/dns"
)

func validateResp(server string, r *dns.Msg, err error) error {
	name := nameFromMsg(r, "unknown")

	if err != nil {
		// TODO: extract information from err.(type)
		var timeout bool
		var temporary bool
		var notfound bool

		return &net.DNSError{
			Err:         err.Error(),
			Server:      server,
			Name:        name,
			IsTimeout:   timeout,
			IsTemporary: temporary,
			IsNotFound:  notfound,
		}
	}

	if r.Truncated {
		return &net.DNSError{
			Err:    "dns response was truncated",
			Server: server,
			Name:   name,
		}
	}

	if r.Rcode != dns.RcodeSuccess {
		// TODO: decipher Rcode
		var timeout bool
		var temporary bool
		var notfound bool

		return &net.DNSError{
			Err:         dns.RcodeToString[r.Rcode],
			Server:      server,
			Name:        name,
			IsTimeout:   timeout,
			IsTemporary: temporary,
			IsNotFound:  notfound,
		}
	}

	// Success
	return nil
}

func nameFromMsg(msg *dns.Msg, fallback string) string {
	for _, q := range msg.Question {
		if len(q.Name) > 0 {
			return q.Name
		}
	}
	return fallback
}
