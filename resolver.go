// Package resolver provides DNS lookup functions
package resolver

import (
	"context"
	"errors"

	"github.com/miekg/dns"
)

var (
	_ Lookuper = (*ZeroLookuper)(nil)
)

var (
	errNoAnswer = errors.New("no answer")
)

// A ZeroLookuper is a Lookuper that never finds anything
type ZeroLookuper struct{}

// Lookup implements Lookuper but always fails
func (ZeroLookuper) Lookup(_ context.Context, _ string, _ uint16) (*dns.Msg, error) {
	return nil, errNoAnswer
}
