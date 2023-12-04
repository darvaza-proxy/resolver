// Package errors aids error handling for [dns.Msg] and [darvaza.org/resolver]
// related functions
package errors

import (
	"net"
	"os"
	"strings"

	"darvaza.org/core"
)

// ErrNotFound assembles an net.DNSError error with
// IsNotFound set
func ErrNotFound(qName string) *net.DNSError {
	return &net.DNSError{
		Err:        "entry not found",
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

// ErrBadResponse reports a bad response from the server
func ErrBadResponse() *net.DNSError {
	return &net.DNSError{
		Err:         BADRESPONSE,
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
