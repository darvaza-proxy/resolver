package server

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"

	"darvaza.org/resolver"
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

// ServeDNS handles requests passed by [dns.ServeMUX]
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) != 1 {
		handleNotImplemented(w, r)
		return
	}

	// TODO: what about the other questions?
	q := r.Question[0]
	switch q.Qclass {
	case dns.ClassCHAOS:
		// call CHAOS class handler
		h.handleCHAOS(w, r, q)
	case dns.ClassINET:
		// call INET class handler
		h.handleINET(w, r, q)
	default:
		// check other classes
		h.handleExtra(w, r, q)
	}
}

func (h *Handler) handleCHAOS(w dns.ResponseWriter, r *dns.Msg, q dns.Question) {
	switch q.Name {
	case "authors.bind.":
		if s := h.Authors; s != "" {
			handleTXTResponse(w, r, s)
			return
		}
	case "version.bind.", "version.server.":
		if s := h.Version; s != "" {
			handleTXTResponse(w, r, s)
			return
		}
	case "hostname.bind.", "id.server.":
		if s := h.Hostname; s != "" {
			handleTXTResponse(w, r, s)
			return
		}
	}

	handleNotImplemented(w, r)
}

func (h *Handler) handleINET(w dns.ResponseWriter, r *dns.Msg, q dns.Question) {
	if h.Lookuper == nil {
		handleNotImplemented(w, r)
		return
	}

	ctx, cancel := h.newLookupContext()
	defer cancel()

	rsp, err := h.Lookuper.Lookup(ctx, q.Name, q.Qtype)
	switch {
	case err != nil:
		h.handleLookupErr(w, r, err)
	case rsp == nil:
		// nil answer from resolver
		handleRcodeError(w, r, dns.RcodeServerFailure)
	default:
		// success
		rsp.SetReply(r)
		rsp.SetRcode(r, dns.RcodeSuccess)
		w.WriteMsg(rsp)
	}
}

func (*Handler) handleLookupErr(w dns.ResponseWriter, r *dns.Msg, err error) {
	// TODO: log error
	m := newResponse(r)
	if n, ok := err.(*net.DNSError); ok {
		if n.Err == "NXDOMAIN" {
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)
			return
		}
	}
	// NOTYPE and possible others arrive here
	m.SetRcode(r, dns.RcodeSuccess)
	w.WriteMsg(m)
}

func (h *Handler) newLookupContext() (context.Context, context.CancelFunc) {
	var ctx context.Context
	// parent
	ctx = h.Context
	if ctx == nil {
		ctx = context.Background()
	}
	// timeout
	if h.Timeout > 0 {
		return context.WithTimeout(ctx, h.Timeout)
	}
	return ctx, func() {}
}

func (h *Handler) handleExtra(w dns.ResponseWriter, r *dns.Msg, q dns.Question) {
	if h.Extra != nil {
		fn, ok := h.Extra[q.Qclass]
		if ok && fn != nil {
			// call extra class handler
			fn(w, r)
			return
		}
	}
	handleNotImplemented(w, r)
}

func handleTXTResponse(w dns.ResponseWriter, r *dns.Msg, content ...string) {
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
	w.WriteMsg(m)
}

func handleNotImplemented(w dns.ResponseWriter, r *dns.Msg) {
	handleRcodeError(w, r, dns.RcodeNotImplemented)
}

func handleRcodeError(w dns.ResponseWriter, r *dns.Msg, rcode int) {
	m := newResponse(r)
	m.SetRcode(r, rcode)
	w.WriteMsg(m)
}

func newResponse(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.RecursionAvailable = true
	return m
}
