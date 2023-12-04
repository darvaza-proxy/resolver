package resolver

import (
	"net"
	"time"

	"github.com/miekg/dns"

	"darvaza.org/cache"
	"darvaza.org/core"
	"darvaza.org/resolver/pkg/errors"
)

var (
	_ cache.Sink = (*RRCacheSink)(nil)
)

// RRCacheSink ...
type RRCacheSink struct {
	b []byte
	m *dns.Msg
	e time.Time
	t time.Time
}

// Bytes ...
func (sink *RRCacheSink) Bytes() []byte {
	switch {
	case len(sink.b) > 0:
		return sink.b
	case sink.m == nil:
		return []byte{}
	default:
		// prepare for storing
		msg := sink.m.Copy()
		msg.Id = 0
		// pack to binary
		b, err := msg.Pack()
		if err != nil {
			panic(err)
		}
		// store
		sink.b = b
		return b
	}
}

// Expire ...
func (sink *RRCacheSink) Expire() time.Time {
	return sink.e
}

// Len ...
func (sink *RRCacheSink) Len() int {
	switch {
	case sink.m != nil:
		// ready
		return sink.rrCount() + 1
	case len(sink.b) == 0:
		// empty
		return 0
	default:
		if err := sink.unpack(); err != nil {
			// bad data, make it fat and expired
			sink.e = time.Now()
			return len(sink.b)
		}
		return sink.rrCount() + 1
	}
}

func (sink *RRCacheSink) rrCount() int {
	l := 0
	l += len(sink.m.Question)
	l += len(sink.m.Answer)
	l += len(sink.m.Ns)
	l += len(sink.m.Extra)
	return l
}

// Reset ...
func (sink *RRCacheSink) Reset() {
	*sink = RRCacheSink{}
}

// SetString ...
func (sink *RRCacheSink) SetString(string, time.Time) error {
	sink.Reset()
	return core.ErrNotImplemented
}

// SetBytes ...
func (sink *RRCacheSink) SetBytes(v []byte, e time.Time) error {
	*sink = RRCacheSink{
		b: v,
		e: e,
	}
	return nil
}

// SetValue ...
func (sink *RRCacheSink) SetValue(v any, e time.Time) error {
	if msg, ok := v.(*dns.Msg); ok {
		return sink.SetMsg(msg, e)
	}

	return core.ErrInvalid
}

// SetMsg ...
func (sink *RRCacheSink) SetMsg(msg *dns.Msg, e time.Time) error {
	*sink = RRCacheSink{
		m: msg,
		e: e,
		t: time.Now(),
	}
	return nil
}

// ExportMsg ...
func (sink *RRCacheSink) ExportMsg() (*dns.Msg, error) {
	switch {
	case len(sink.b) > 0:
		// restored
		if sink.m == nil {
			if err := sink.unpack(); err != nil {
				// corrupted
				return nil, err
			}
		}

		// update TTLs
		return sink.exportUpdatedMsg()
	case sink.m == nil:
		return nil, &net.DNSError{Err: errors.NOANSWER}
	default:
		return sink.m, nil
	}
}

func (sink *RRCacheSink) exportUpdatedMsg() (*dns.Msg, error) {
	msg := sink.m.Copy()
	// TODO: update TTL
	return msg, nil
}

func (sink *RRCacheSink) unpack() error {
	msg := new(dns.Msg)
	if err := msg.Unpack(sink.b); err != nil {
		// corrupted
		return err
	}

	sink.m = msg
	return nil
}
