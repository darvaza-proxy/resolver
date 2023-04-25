package resolver

import (
	"context"

	"darvaza.org/core"
	"github.com/miekg/dns"
)

// MultiLookuper queries multiple Lookupers in parallel
// and takes the first non-error answer
type MultiLookuper struct {
	m []Lookuper
}

// Lookup queries all Lookupers in parallel and returns the
// quickest to answer
func (r MultiLookuper) Lookup(ctx context.Context,
	qName string, qType uint16) (*dns.Msg, error) {
	//
	var wg core.WaitGroup

	ctx2, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	ch := make(chan *dns.Msg)

	// on success done will be closed and we cancel
	// all others
	go func() {
		<-done
		cancel()
	}()

	for i := range r.m {
		h := r.m[i]
		wg.Go(func() error {
			return r.lookupOne(ctx2, h, ch,
				qName, qType)
		})
	}

	// if all workers finished unsuccessfully, free the waiter
	go func() {
		wg.Wait()
		close(ch)
	}()

	// wait for a response
	first := <-ch
	close(done)

	if first != nil {
		// good
		return first, nil
	}

	// first reason
	err := wg.Err()
	if err == nil {
		// none? make one up
		err = ErrTimeoutMessage(qName, "no answer")
	}
	return nil, err
}

func (MultiLookuper) lookupOne(ctx context.Context,
	h Lookuper, out chan<- *dns.Msg,
	qName string, qType uint16,
) error {
	//
	msg, err := h.Lookup(ctx, qName, qType)
	if err == nil && msg != nil {
		out <- msg
	}
	return err
}

// NewMultiLookuper creates a new Multilookuper using the
// given Lookupers
func NewMultiLookuper(lookupers ...Lookuper) *MultiLookuper {
	if len(lookupers) > 0 {
		return &MultiLookuper{
			m: lookupers,
		}
	}
	return nil
}

// NewMultiLookuperAddresses creates a new Multilookuper composing
// SingleLookupers for each given address
func NewMultiLookuperAddresses(servers ...string) (*MultiLookuper, error) {
	var err core.CompoundError

	m := make([]Lookuper, 0, len(servers))

	for _, server := range servers {
		r, e := NewSingleLookuper(server)
		if e != nil {
			err.AppendError(e)
		} else {
			m = append(m, r)
		}
	}

	return NewMultiLookuper(m...), err.AsError()
}

// SingleLookuper asks a single server for a direct answer
// to the query preventing repetition
type SingleLookuper struct {
	c      *dns.Client
	remote string
}

// Lookup asks the designed remote to make a DNS Lookup
func (r SingleLookuper) Lookup(ctx context.Context,
	qName string, qType uint16) (*dns.Msg, error) {
	//
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{
			{Name: qName, Qtype: qType, Qclass: dns.ClassINET},
		},
	}

	return r.Exchange(ctx, m)
}

// Exchange exchanges a message with a designed server
func (r SingleLookuper) Exchange(ctx context.Context,
	msg *dns.Msg) (*dns.Msg, error) {
	//
	res, _, err := r.c.ExchangeContext(ctx, msg, r.remote)
	if werr := validateResp(r.remote, res, err); werr != nil {
		return nil, werr
	}

	return res, nil
}

// NewSingleLookuper creates a Lookuper that asks one particular
// server
func NewSingleLookuper(server string) (*SingleLookuper, error) {
	server, err := AsServerAddress(server)
	if err != nil {
		return nil, err
	}

	return newSingleLookuperUnsafe(server), nil
}

func newSingleLookuperUnsafe(server string) *SingleLookuper {
	c := new(dns.Client)
	c.SingleInflight = true
	c.UDPSize = DefaultUDPSize

	return &SingleLookuper{
		c:      c,
		remote: server,
	}
}
