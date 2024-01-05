package exdns

import (
	"github.com/miekg/dns"

	"darvaza.org/resolver/pkg/errors"
)

// ValidateResponse wraps [errors.ValidateResponse] to avoid getting
// nil errors typed as *[net.DNSError], which aren't nil anymore.
func ValidateResponse(server string, resp *dns.Msg, err error) error {
	e2 := errors.ValidateResponse(server, resp, err)
	if e2 != nil {
		return e2
	}
	return nil
}

// ValidateRestoreReturn validates a response and makes
// sure it carries the same ID as the original request
func ValidateRestoreReturn(req, resp *dns.Msg,
	server string, err error) (*dns.Msg, error) {
	e2 := errors.ValidateResponse(server, resp, err)
	switch {
	case e2 != nil:
		// failed
		return nil, e2
	case req == nil || req.Id == 0:
		// original request no provided or not valid.
		return resp, nil
	case req.Id == resp.Id:
		// correct ID
		return resp, nil
	default:
		// restore ID
		resp.Id = req.Id
		return resp, nil
	}
}
