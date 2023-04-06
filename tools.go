package resolver

import (
	"errors"
	"net"

	"darvaza.org/core"
	"github.com/miekg/dns"
	"golang.org/x/net/idna"
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

func sanitiseHost(host string) (string, error) {
	if host != "" {
		s, err := idna.Display.ToASCII(host)
		if err != nil {
			return "", core.Wrapf(err, "%q: invalid host", host)
		}
		return s, nil
	}

	return "", errors.New("empty host")
}

// ForEachAnswer calls a function for each answer of the specified type.
func ForEachAnswer[T any](msg *dns.Msg, fn func(v T)) {
	if fn == nil || msg == nil {
		return
	}

	for _, ans := range msg.Answer {
		if v, ok := ans.(T); ok {
			fn(v)
		}
	}
}
