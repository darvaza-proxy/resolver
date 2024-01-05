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
