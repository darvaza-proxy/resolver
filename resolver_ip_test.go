package resolver

import (
	"context"
	"net/netip"
	"testing"
)

func TestLookupNetIP(t *testing.T) {
	tests := []struct {
		name    string
		network string
	}{
		{name: "google.com", network: "ip"},
		{name: "google.com", network: "ip4"},
		{name: "google.com", network: "ip6"},
	}

	ctx := context.Background()
	l := NewResolver(NewCloudflareLookuper())
	for _, tc := range tests {
		s, err := l.LookupNetIP(ctx, tc.network, tc.name)
		switch {
		case err != nil:
			t.Errorf("%q %q failed: %s", tc.name, tc.network, err)
		case checkTestLookupNetIPResponse(t, tc.name, tc.network, s):
			t.Logf("%q %q: %q", tc.name, tc.network, s)
		}
	}
}

func checkTestLookupNetIPResponse(t *testing.T,
	name, network string,
	result []netip.Addr) bool {
	//
	var ip4, ip6, invalid bool
	var msg string

	for _, addr := range result {
		switch {
		case !addr.IsValid():
			invalid = true
		case addr.Is4():
			ip4 = true
		case addr.Is6():
			ip6 = true
		default:
			invalid = true
		}
	}

	msg, ok := validateTestLookupNetIPResult(network, invalid, ip4, ip6)
	if !ok {
		t.Errorf("%q %q: %s: %q", name, network, msg, result)
	}
	return ok
}

// revive:disable:cyclomatic
func validateTestLookupNetIPResult(network string,
	invalid, ip4, ip6 bool) (string, bool) {
	// revive:enable:cyclomatic
	want4 := network == "ip" || network == "ip4"
	want6 := network == "ip" || network == "ip6"

	switch {
	case invalid:
		return "invalid address", false
	case ip4 && !want4:
		return "unexpected IPv4 address", false
	case ip6 && !want6:
		return "unexpected IPv6 address", false
	case !ip4 && want4:
		return "missing IPv4 address", false
	case !ip6 && want6:
		return "missing IPv6 address", false
	default:
		return "", true
	}
}
