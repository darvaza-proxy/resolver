package client

import "net"

var hasIPv6Support bool

// HasIPv6Support tells if the system supports IPv6 or not.
// This doesn't guarantee connections will be successful.
func HasIPv6Support() bool {
	return hasIPv6Support
}

func init() {
	l, err := net.Listen("tcp6", "::1")
	if err == nil {
		hasIPv6Support = true
		_ = l.Close()
	}
}
