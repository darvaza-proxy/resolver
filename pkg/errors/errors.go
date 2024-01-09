// Package errors aids error handling for [dns.Msg] and [darvaza.org/resolver]
// related functions
package errors

import (
	"net"
	"os"
	"strings"

	"github.com/miekg/dns"

	"darvaza.org/core"
)

// ErrNotFound assembles a net.DNSError indicating
// the asked name doesn't exist.
func ErrNotFound(qName string) *net.DNSError {
	return &net.DNSError{
		Err:        NXDOMAIN,
		Name:       qName,
		IsNotFound: true,
	}
}

// ErrTypeNotFound assembles a net.DNSError indicating
// the name exists but not the requested qType/qClass.
func ErrTypeNotFound(qName string) *net.DNSError {
	return &net.DNSError{
		Err:        NODATA,
		Name:       qName,
		IsNotFound: true,
	}
}

// ErrTimeoutMessage is a variant of ErrTimeout that uses
// a given message instead of wrapping an error
func ErrTimeoutMessage(qName string, msg string) *net.DNSError {
	return &net.DNSError{
		Err:         msg,
		Name:        qName,
		IsTimeout:   true,
		IsTemporary: true,
	}
}

// ErrBadRequest reports an invalid request from the client
func ErrBadRequest() *net.DNSError {
	return &net.DNSError{
		Err:         BADREQUEST,
		IsTemporary: true,
	}
}

// ErrBadResponse reports a bad response from the server
func ErrBadResponse() *net.DNSError {
	return &net.DNSError{
		Err:         BADRESPONSE,
		IsTemporary: true,
	}
}

// ErrInternalError reports there was a failure on our side.
func ErrInternalError(name, server string) *net.DNSError {
	return &net.DNSError{
		Err:         dns.RcodeToString[dns.RcodeServerFailure],
		Name:        name,
		Server:      server,
		IsTemporary: true,
	}
}

// ErrNotImplemented reports something isn't implemented
func ErrNotImplemented(name string) *net.DNSError {
	return &net.DNSError{
		Err:  NOTIMPLEMENTED,
		Name: name,
	}
}

// ErrRefused reports we can't answer
func ErrRefused(name string) *net.DNSError {
	return &net.DNSError{
		Err:  dns.RcodeToString[dns.RcodeRefused],
		Name: name,
	}
}

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
	return ErrTimeoutMessage(qName, strings.TrimPrefix(msg, "dns: "))
}

// IsNotFound checks if the given error represents a NotFound
func IsNotFound(err error) bool {
	switch e := err.(type) {
	case *net.DNSError:
		return e.IsNotFound
	case nil:
		return false
	default:
		return os.IsNotExist(err)
	}
}

// IsTimeout checks if the given error represents a Timeout
func IsTimeout(err error) bool {
	switch e := err.(type) {
	case *net.DNSError:
		return e.Timeout()
	case nil:
		return false
	default:
		return os.IsTimeout(err)
	}
}

// IsTemporary checks if the given error could be rechecked
func IsTemporary(err error) bool {
	if e, ok := err.(interface {
		Temporary() bool
	}); ok {
		return e.Temporary()
	}
	return false
}
