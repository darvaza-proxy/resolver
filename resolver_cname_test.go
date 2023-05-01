package resolver

import (
	"context"
	"strings"
	"testing"
)

func TestLookupCNAME(t *testing.T) {
	tests := []struct {
		name   string
		cnames []string
	}{
		{"www.iana.org", []string{"icann.org", "ianawww.vip.icann.org"}},
		{"cname-to-txt.go4.org", []string{"test-txt-record.go4.org"}},
	}
	ctx := context.Background()
	l, err := NewRootResolver("")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range tests {
		s, err := l.LookupCNAME(ctx, tc.name)
		if err != nil {
			t.Fatalf(err.Error())
		}

		if cnameInList(s, tc.cnames...) {
			t.Logf("%q CNAME %q", tc.name, s)
		} else {
			t.Errorf("%q CNAME %q, expected %q", tc.name, s, tc.cnames)
		}
	}
}

func cnameInList(value string, options ...string) bool {
	value = Decanonize(strings.ToLower(value))
	for _, opt := range options {
		if value == opt {
			return true
		}
	}
	return false
}
