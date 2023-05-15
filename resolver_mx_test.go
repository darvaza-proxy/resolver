package resolver

import (
	"context"
	"testing"
)

// revive:disable:cognitive-complexity
func TestLookupMX(t *testing.T) {
	tests := []struct {
		name, host string
	}{
		{
			"gmail.com", "google.com.",
		},
		{
			"gmail.com.", "google.com.",
		},
	}
	ctx := context.Background()
	l, err := NewRootResolver("")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(tests); i++ {
		tt := tests[i]
		mxs, err := l.LookupMX(ctx, tt.name)
		if err != nil {
			t.Fatal(err)
		}
		if len(mxs) == 0 {
			t.Error("got no record")
		}
		for _, mx := range mxs {
			if !hasSuffixFold(mx.Host, tt.host) {
				t.Errorf("got %v; want a record containing %s", mx.Host, tt.host)
			}
			t.Logf("got %v; want a record containing %s", mx.Host, tt.host)
		}
	}
}
