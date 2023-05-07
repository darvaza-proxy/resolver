package resolver

import (
	"context"
	"strings"
	"testing"
)

// revive:disable:cognitive-complexity
func TestLookupSRV(t *testing.T) {
	tests := []struct {
		service, proto, name string
		cname, target        string
	}{
		{
			"ldap", "tcp", "google.com",
			"google.com.", "google.com.",
		},
		{
			"ldap", "tcp", "google.com.",
			"google.com.", "google.com.",
		},
		{
			"", "", "_ldap._tcp.google.com",
			"google.com.", "google.com.",
		},
		{
			"", "", "_ldap._tcp.google.com.",
			"google.com.", "google.com.",
		},
	}
	ctx := context.Background()
	l, err := NewRootResolver("")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(tests); i++ {
		tt := tests[i]
		cname, srvs, err := l.LookupSRV(ctx, tt.service, tt.proto, tt.name)
		if err != nil {
			t.Fatal(err)
		}
		if len(srvs) == 0 {
			t.Error("got no record")
		}
		if !hasSuffixFold(cname, tt.cname) {
			t.Errorf("got %s; want %s", cname, tt.cname)
		}
		for _, srv := range srvs {
			if !hasSuffixFold(srv.Target, tt.target) {
				t.Errorf("got %v; want a record containing %s", srv, tt.target)
			}
			t.Logf("got %v; want a record containing %s", srv, tt.target)
		}
	}
}
func hasSuffixFold(s, suffix string) bool {
	return strings.HasSuffix(strings.ToLower(s), strings.ToLower(suffix))
}
