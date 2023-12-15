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
		fail    bool
	}{
		{name: "google.com", network: "ip"},
		{name: "google.com", network: "ip4"},
		{name: "google.com", network: "ip6"},
		{name: "ipv6.google.com", network: "ip4", fail: true},
		{name: "ipv6.google.com", network: "ip6"},
	}

	ctx := context.Background()
	l, err := NewRootResolver("")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range tests {
		s, err := l.LookupNetIP(ctx, tc.network, tc.name)
		switch {
		case err != nil && tc.fail:
			// failed as expected
			t.Logf("%q %q: %s", tc.name, tc.network, err)
		case err != nil && !tc.fail:
			// not expected to fail
			t.Errorf("%q %q failed: %s", tc.name, tc.network, err)
		case err == nil && tc.fail:
			// expected to fail
			msg := "expected to fail"
			t.Fatalf("%q %q %s: %q", tc.name, tc.network, msg, s)
		case checkTestLookupNetIPResponse(t, tc.name, tc.network, s):
			// good
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
	want4 := network == netIP4or6 || network == netIP4only
	want6 := network == netIP4or6 || network == netIP6only

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
