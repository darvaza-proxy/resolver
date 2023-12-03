package errors

import (
	"net"

	"darvaza.org/core"
	"github.com/miekg/dns"
)

// MsgAsError validates a response and produces
// a matching [net.DNSError] if due.
func MsgAsError(r *dns.Msg) *net.DNSError {
	name := nameFromMsg(r)

	switch {
	case r == nil:
		// no message
		return &net.DNSError{
			Err:         NOANSWER,
			Name:        name,
			IsTemporary: true,
		}
	case r.Truncated:
		// truncated
		return &net.DNSError{
			Err:         TRUNCATED,
			Name:        name,
			IsTemporary: true,
		}
	default:
		switch r.Rcode {
		case dns.RcodeSuccess:
			// Success could mean NOTYPE if it's authoritative
			if len(r.Answer) == 0 && r.Authoritative {
				return &net.DNSError{
					Err:        NOTYPE,
					Name:       name,
					IsNotFound: true,
				}
			}

			return nil
		case dns.RcodeNameError:
			// Unknown name
			return &net.DNSError{
				Err:        NXDOMAIN,
				Name:       name,
				IsNotFound: true,
			}
		default:
			// TODO: decipher Rcode further
			var timeout bool
			var temporary bool
			var notfound bool

			return &net.DNSError{
				Err:         dns.RcodeToString[r.Rcode],
				Name:        name,
				IsTimeout:   timeout,
				IsTemporary: temporary,
				IsNotFound:  notfound,
			}
		}
	}
}

// ValidateResponse analyses a [dns.Exchange] response and
// produces a matching [net.DNSError] if it's an error
func ValidateResponse(server string, r *dns.Msg, err error) *net.DNSError {
	name := nameFromMsg(r)

	if err == nil {
		if e := MsgAsError(r); e != nil {
			// error message detected
			e.Server = server
			return e
		}

		// not an error
		return nil
	}

	if e, ok := err.(*net.DNSError); ok {
		// pass through
		e.Server = core.Coalesce(e.Server, server)
		e.Name = core.Coalesce(e.Name, name)
		return e
	}

	// any other kind of error
	return &net.DNSError{
		Err:         err.Error(),
		Server:      server,
		Name:        name,
		IsTimeout:   IsTimeout(err),
		IsTemporary: IsTemporary(err),
		IsNotFound:  IsNotFound(err),
	}
}

func nameFromMsg(msg *dns.Msg) string {
	if msg != nil {
		for _, q := range msg.Question {
			if len(q.Name) > 0 {
				return q.Name
			}
		}
	}
	return ""
}
