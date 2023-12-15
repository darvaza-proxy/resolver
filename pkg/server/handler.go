package server

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"

	"darvaza.org/core"
	"darvaza.org/resolver"
	"darvaza.org/resolver/pkg/errors"
)

const (
	// DefaultLookupTimeout is the maximum time INET lookups
	// can take unless [Handler.Timeout] is specified
	DefaultLookupTimeout = 5 * time.Second
)

var _ dns.Handler = (*Handler)(nil)

// Handler provides a [dns.Handler] for [dns.ServeMux]
type Handler struct {
	Hostname string
	Version  string
	Authors  string

	Context  context.Context
	Timeout  time.Duration
	Lookuper resolver.Lookuper
	Extra    map[uint16]dns.HandlerFunc

	RemoteAddr *core.ContextKey[netip.Addr]

	OnError func(dns.ResponseWriter, *dns.Msg, error)
}

// SetDefaults fills gaps in the [Handler] struct
func (h *Handler) SetDefaults() {
	if h.Context == nil {
		h.Context = context.Background()
	}
	if h.Timeout == 0 {
		h.Timeout = DefaultLookupTimeout
	}
	if h.Extra == nil {
		h.Extra = make(map[uint16]dns.HandlerFunc)
	}
}

func (h *Handler) onError(rw dns.ResponseWriter, req *dns.Msg, err error) {
	if h != nil && h.OnError != nil && err != nil {
		h.OnError(rw, req, err)
	}
}

// ServeDNS handles requests passed by [dns.ServeMUX]
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	var err error

	if len(r.Question) != 1 {
		err = handleNotImplemented(w, r)
		if err != nil {
			h.onError(w, r, err)
		}
		return
	}

	// TODO: what about the other questions?
	q := r.Question[0]
	switch q.Qclass {
	case dns.ClassCHAOS:
		// call CHAOS class handler
		err = h.handleCHAOS(w, r, q)
	case dns.ClassINET:
		// call INET class handler
		err = h.handleINET(w, r, q)
	default:
		// check other classes
		err = h.handleExtra(w, r, q)
	}

	if err != nil {
		h.onError(w, r, err)
	}
}

func (h *Handler) handleCHAOS(w dns.ResponseWriter, r *dns.Msg, q dns.Question) error {
	switch q.Name {
	case "authors.bind.":
		if s := h.Authors; s != "" {
			return handleTXTResponse(w, r, s)
		}
	case "version.bind.", "version.server.":
		if s := h.Version; s != "" {
			return handleTXTResponse(w, r, s)
		}
	case "hostname.bind.", "id.server.":
		if s := h.Hostname; s != "" {
			return handleTXTResponse(w, r, s)
		}
	}

	return handleNotImplemented(w, r)
}

func (h *Handler) handleINET(w dns.ResponseWriter, r *dns.Msg, q dns.Question) error {
	if h.Lookuper == nil {
		return handleNotImplemented(w, r)
	}

	ctx, cancel := h.newLookupContext(w.RemoteAddr())
	defer cancel()

	rsp, err := h.Lookuper.Lookup(ctx, q.Name, q.Qtype)
	switch {
	case err != nil:
		// TODO: log error
		rsp := errors.ErrorAsMsg(r, err)
		return w.WriteMsg(rsp)
	case rsp == nil:
		// nil answer from resolver
		return handleRcodeError(w, r, dns.RcodeServerFailure)
	default:
		// success
		rsp.SetReply(r)
		rsp.SetRcode(r, dns.RcodeSuccess)
		return w.WriteMsg(rsp)
	}
}

func (h *Handler) newLookupContext(remoteAddr net.Addr) (context.Context, context.CancelFunc) {
	var ctx context.Context
	// parent
	ctx = h.Context
	if ctx == nil {
		ctx = context.Background()
	}
	// RemoteAddr
	if h.RemoteAddr != nil {
		addr, ok := core.AddrFromNetIP(remoteAddr)
		if ok {
			ctx = h.RemoteAddr.WithValue(ctx, addr)
		}
	}
	// timeout
	if h.Timeout > 0 {
		return context.WithTimeout(ctx, h.Timeout)
	}
	return ctx, func() {}
}

func (h *Handler) handleExtra(w dns.ResponseWriter, r *dns.Msg, q dns.Question) error {
	if h.Extra != nil {
		fn, ok := h.Extra[q.Qclass]
		if ok && fn != nil {
			// call extra class handler
			fn(w, r)
			return nil
		}
	}
	return handleNotImplemented(w, r)
}

func handleTXTResponse(w dns.ResponseWriter, r *dns.Msg, content ...string) error {
	q := r.Question[0]

	hdr := dns.RR_Header{
		Name:   q.Name,
		Rrtype: dns.TypeTXT,
		Class:  q.Qclass,
	}

	m := newResponse(r)
	m.Answer = []dns.RR{
		&dns.TXT{
			Hdr: hdr,
			Txt: content,
		},
	}
	m.SetRcode(m, dns.RcodeSuccess)
	return w.WriteMsg(m)
}

func handleNotImplemented(w dns.ResponseWriter, r *dns.Msg) error {
	return handleRcodeError(w, r, dns.RcodeNotImplemented)
}

func handleRcodeError(w dns.ResponseWriter, r *dns.Msg, rcode int) error {
	m := newResponse(r)
	m.SetRcode(r, rcode)
	return w.WriteMsg(m)
}

func newResponse(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.RecursionAvailable = true
	return m
}
