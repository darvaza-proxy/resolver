package resolver

import "net"

var (
	_ Resolver = (*net.Resolver)(nil)
)

// SystemResolver returns a standard net.Resolver configured to preferGo or not
func SystemResolver(preferGo bool) *net.Resolver {
	return SystemResolverWithDialer(preferGo, nil)
}

// SystemResolverWithDialer returns a standard net.Resolver configured to preferGo
// or not and use the given Dialer instead of the default
func SystemResolverWithDialer(preferGo bool, dialer DialerFunc) *net.Resolver {
	return &net.Resolver{
		PreferGo: preferGo,
		Dial:     dialer,
	}
}
