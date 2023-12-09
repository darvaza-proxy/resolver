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
			// Success could mean NODATA if it's authoritative
			if len(r.Answer) == 0 && r.Authoritative {
				return ErrTypeNotFound(name)
			}

			return nil
		case dns.RcodeNameError:
			// Unknown name
			return ErrNotFound(name)
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

// ErrorAsMsg attempts to convert a [net.DNSError] into a [dns.Msg] response
func ErrorAsMsg(req *dns.Msg, err error) *dns.Msg {
	if err == nil {
		// no error
		if req == nil {
			return nil
		}

		// good reply
		return newResponseSuccess(req)
	}

	if e, ok := err.(*net.DNSError); ok {
		// net.DNSError
		return dnsErrorAsMsg(req, e)
	}

	// any other error
	return newResponseServerFailure(req)
}

func dnsErrorAsMsg(req *dns.Msg, err *net.DNSError) *dns.Msg {
	switch err.Err {
	case NOANSWER:
	case NODATA:
		resp := newResponseSuccess(req)
		resp.Authoritative = true
		return resp
	case NXDOMAIN:
		return newResponseRcode(req, dns.RcodeNameError)
	case TRUNCATED:
	case BADREQUEST:
	case BADRESPONSE:
	case NOTIMPLEMENTED:
		return newResponseRcode(req, dns.RcodeNotImplemented)
	default:
		rcode, ok := dns.StringToRcode[err.Err]
		if ok {
			return newResponseRcode(req, rcode)
		}
	}

	// any other error
	return newResponseServerFailure(req)
}

func newResponseRcode(req *dns.Msg, rcode int) *dns.Msg {
	if req == nil {
		// we can't SetRcode with a nil request
		req = new(dns.Msg)
	}

	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	return resp
}

func newResponseSuccess(req *dns.Msg) *dns.Msg {
	return newResponseRcode(req, dns.RcodeSuccess)
}

func newResponseServerFailure(req *dns.Msg) *dns.Msg {
	return newResponseRcode(req, dns.RcodeServerFailure)
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
