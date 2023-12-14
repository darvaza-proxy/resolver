package reflect

import (
	"context"
	"time"

	"github.com/miekg/dns"

	"darvaza.org/core"
	"darvaza.org/resolver"
	"darvaza.org/slog"
)

var (
	_ resolver.Lookuper  = (*Lookuper)(nil)
	_ resolver.Exchanger = (*Lookuper)(nil)
)

// Lookuper is a logging wrapper for another [resolver.Lookuper]
// or [resolver.Exchanger]
// [Lookuper] will log requests and responses if `GetEnabled(ctx)`
// returns true.
type Lookuper struct {
	name string
	log  slog.Logger
	next resolver.Exchanger

	Extra  map[string]any
	Rename map[string]string
}

// Lookup implements the [resolver.Lookuper] interface.
func (l *Lookuper) Lookup(ctx context.Context, qName string, qType uint16) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(qName), qType)
	return l.Exchange(ctx, req)
}

// Exchange implements the [resolver.Exchanger] interface.
func (l *Lookuper) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if ctx == nil || req == nil {
		return nil, core.ErrInvalid
	}

	return l.doExchange(ctx, req)
}

func (l *Lookuper) doExchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	var id string

	level, enabled := GetEnabled(ctx, l.name)
	if enabled {
		id, _ = GetID(ctx)

		doLog(l.log, level, reflectOptions{
			Name:    l.name,
			ID:      id,
			Request: req,
			Extra:   l.Extra,
			Rename:  l.Rename,
		})
	}

	start := time.Now()
	resp, err := l.next.Exchange(ctx, req)
	if enabled {
		doLog(l.log, level, reflectOptions{
			Name:     l.name,
			ID:       id,
			Response: resp,
			RTT:      time.Since(start),
			Err:      err,
			Extra:    l.Extra,
			Rename:   l.Rename,
		})
	}

	return resp, err
}

// NewWithLookuper creates a new [Lookuper] wrapper to log requests and responses
// to the specified [resolver.Lookuper].
// If the next [resolver.Lookuper] also implements [resolver.Exchanger], that
// interface will be used instead.
func NewWithLookuper(name string, log slog.Logger, next resolver.Lookuper) (*Lookuper, error) {
	var e resolver.Exchanger

	switch l := next.(type) {
	case resolver.Exchanger:
		// promoted to exchanger
		e = l
	case resolver.Lookuper:
		// wrapped to implement a minimal dns.ClassINET Exchanger
		e = resolver.LookuperFunc(l.Lookup)
	}

	return NewWithExchanger(name, log, e)
}

// NewWithExchanger creates a new [Lookuper] wrapper to log requests and responses
// to the specified [resolver.Exchanger].
func NewWithExchanger(name string, log slog.Logger, next resolver.Exchanger) (*Lookuper, error) {
	switch {
	case next == nil || log == nil:
		return nil, core.ErrInvalid
	default:
		l := &Lookuper{
			name: name,
			log:  log,
			next: next,
		}

		return l, nil
	}
}
