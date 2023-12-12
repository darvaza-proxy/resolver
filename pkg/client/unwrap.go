package client

import "github.com/miekg/dns"

// An Unwrapper can tell what's the underlying [*dns.Client]
type Unwrapper interface {
	Unwrap() *dns.Client
}

// Unwrap uses the [Unwrapper] interface to find the underlying [*dns.Client]
func Unwrap(c Client) *dns.Client {
	switch t := c.(type) {
	case *dns.Client:
		return t
	case Unwrapper:
		return t.Unwrap()
	default:
		return nil
	}
}
