package resolver

import (
	"context"

	"darvaza.org/core"
	"github.com/miekg/dns"

	"darvaza.org/resolver/pkg/errors"
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
		err = errors.ErrTimeoutMessage(qName, errors.NOANSWER)
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
		r, e := NewSingleLookuper(server, true)
		if e != nil {
			err.AppendError(e)
		} else {
			m = append(m, r)
		}
	}

	return NewMultiLookuper(m...), err.AsError()
}
