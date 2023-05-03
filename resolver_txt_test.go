package resolver

import (
	"context"
	"strings"
	"testing"
)

// revive:disable:cognitive-complexity
func TestLookupTXT(t *testing.T) {
	tests := []struct {
		name string
		txt  string
		host string
	}{
		{"gmail.com", "spf", "google.com"},
		{"gmail.com.", "spf", "google.com"},
	}
	ctx := context.Background()
	l, err := NewRootResolver("")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(tests); i++ {
		tt := tests[i]
		txts, err := l.LookupTXT(ctx, tt.name)
		if err != nil {
			t.Fatal(err)
		}
		if len(txts) == 0 {
			t.Error("got no record")
		}
		found := false
		for _, txt := range txts {
			if strings.Contains(txt, tt.txt) &&
				(strings.HasSuffix(txt, tt.host) ||
					strings.HasSuffix(txt, tt.host+".")) {
				found = true
				t.Logf("TXT record for %q contains %q", tt.name, tt.host)
				break
			}
		}
		if !found {
			t.Errorf("got %v; want a record containing %s, %s", txts, tt.txt, tt.host)
		}
	}
}
