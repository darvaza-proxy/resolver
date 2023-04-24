package resolver

import (
	"context"
	"testing"
)

//revive:disable
func TestLookupNetIP(t *testing.T) {
	tests := []struct {
		name    string
		network string
		wantok  bool
	}{
		{name: "IP", network: "ip", wantok: false},
		{name: "IPv4", network: "ip4", wantok: true},
		{name: "IPv6", network: "ip6", wantok: true},
	}
	h, err := NewRootLookuper("")
	if err != nil {
		t.Fatal(err)
	}
	l := NewResolver(h)
	for _, tc := range tests {
		s, err := l.LookupNetIP(context.Background(), tc.network, "google.com")
		if err != nil {
			t.Fatalf(err.Error())
		}
		t.Log(s)
		if tc.wantok {
			if tc.network == "ip4" {
				if !s[0].Is4() {
					t.Fatalf("called for IPv4, received something else")
				}
			}
			if tc.network == "ip6" {
				if !s[0].Is6() {
					t.Fatalf("called for IPv6, received something else")
				}
			}
		}
	}
}
