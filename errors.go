package resolver

import (
	"net"
	"strings"

	"darvaza.org/core"
)

// ErrTimeout assembles a Timeout() error
func ErrTimeout(qName string, err error) *net.DNSError {
	if e, ok := err.(*net.DNSError); ok {
		if e.Name == "" || !e.IsTimeout {
			// copy
			out := *e
			out.Name = core.Coalesce(e.Name, qName)
			out.IsTimeout = true
			return &out
		}
		// pass through
		return e
	}

	msg := core.Coalesce(err.Error(), "request timed out")

	return &net.DNSError{
		Err:         strings.TrimPrefix(msg, "dns: "),
		Name:        qName,
		IsTimeout:   true,
		IsTemporary: true,
	}
}
