package resolver

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

func TestRootLookup(t *testing.T) {
	root, err := NewRootLookuper("")
	if err != nil {
		t.Fatal(err)
	}

	// Simple
	testRootTypeA(t, root, "karasz.im", "95.216.149.141")
	// Complex
	testRootTypeA(t, root, "fda.my.salesforce.com", "")
	// EDU
	testRootTypeA(t, root, "www.seas.upenn.edu", "")
}

func testRootTypeA(t *testing.T, h Lookuper, name, address string) {
	z, err := h.Lookup(context.TODO(), name, dns.TypeA)
	if err != nil {
		t.Errorf("%s: %s", name, err.Error())
		return
	}

	first := z.Answer[0].(*dns.A).A.String()

	if address != "" {
		if first != address {
			t.Errorf("%s: %s (expected %s)", name, first, address)
			return
		}
	}

	t.Logf("%s: %s", name, first)
}
