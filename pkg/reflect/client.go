package reflect

import (
	"context"
	"time"

	"github.com/miekg/dns"

	"darvaza.org/core"
	"darvaza.org/resolver/pkg/client"
	"darvaza.org/resolver/pkg/errors"
	"darvaza.org/slog"
)

var (
	_ client.Client    = (*Client)(nil)
	_ client.Unwrapper = (*Client)(nil)
)

// Client is a logging wrapper for another [client.Client].
// [Client] will log requests and responses if `GetEnabled(ctx)`
// returns true.
type Client struct {
	name string
	log  slog.Logger
	next client.Client

	Extra  map[string]any
	Rename map[string]string
}

// ExchangeContext implements the [client.Client] interface.
func (c *Client) ExchangeContext(ctx context.Context, req *dns.Msg,
	server string) (*dns.Msg, time.Duration, error) {
	//
	if ctx == nil || req == nil {
		return nil, 0, errors.ErrBadRequest()
	}

	return c.doExchange(ctx, req, server)
}

func (c *Client) doExchange(ctx context.Context, req *dns.Msg,
	server string) (*dns.Msg, time.Duration, error) {
	//
	var options reflectOptions
	var id string

	start := time.Now()
	level, enabled := GetEnabled(ctx, c.name)
	if enabled {
		id, _ = GetID(ctx)
		options = reflectOptions{
			Name:    c.name,
			ID:      id,
			Request: req,
			Server:  server,
			Extra:   c.Extra,
			Rename:  c.Rename,
		}

		doLog(c.log, level, options)
	}

	resp, rtt, err := c.next.ExchangeContext(ctx, req, server)
	if enabled {
		options.Err = err
		options.Response = resp
		options.RTT = core.IIf(rtt > 0, rtt, -1)

		doLog(c.log, level, options)
	}

	return resp, time.Since(start), err
}

func (c *Client) Unwrap() *dns.Client {
	return client.Unwrap(c.next)
}

// NewWithClient creates a new [Client] wrapper to log requests and responses
// to the specified [client.Client].
func NewWithClient(name string, log slog.Logger, next client.Client) (*Client, error) {
	if next == nil || log == nil {
		return nil, core.ErrInvalid
	}

	c := &Client{
		name: name,
		log:  log,
		next: next,
	}

	return c, nil
}
