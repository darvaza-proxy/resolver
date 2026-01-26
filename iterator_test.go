package resolver

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"darvaza.org/resolver/pkg/errors"
	"darvaza.org/resolver/pkg/exdns"
)

func TestRootLookup(t *testing.T) {
	root, err := NewRootLookuper("")
	if err != nil {
		t.Fatal(err)
	}
	root.DisableAAAA() // for github sake

	// Simple
	testRootTypeA(t, root, "karasz.im", "95.216.149.141")
	// Complex
	testRootTypeA(t, root, "fda.my.salesforce.com", "")
	// EDU
	testRootTypeA(t, root, "www.seas.upenn.edu", "")
}

func TestRootLookupFrom(t *testing.T) {
	root, err := NewRootLookuper(roots["a.root-servers.net"])
	if err != nil {
		t.Fatal(err)
	}
	root.DisableAAAA() // for github sake

	// Simple
	testRootTypeA(t, root, "karasz.im", "95.216.149.141")
}

func testRootTypeA(t *testing.T, h Lookuper, name, address string) {
	t.Helper()

	z, err := h.Lookup(context.TODO(), name, dns.TypeA)
	if !handleRootLookupError(t, name, address, err) {
		return
	}

	handleRootLookupAnswer(t, name, address, z)
}

func handleRootLookupError(t *testing.T, name, address string, err error) bool {
	t.Helper()

	if err == nil {
		return true
	}
	// Some external domains (e.g., delegated SaaS subdomains) can return
	// NXDOMAIN depending on authoritative changes; tolerate NotFound when
	// this test doesn't assert a specific address to reduce flakiness.
	if address == "" && errors.IsNotFound(err) {
		t.Logf("%s: not found", name)
		return false
	}
	t.Errorf("%s: %s", name, err.Error())
	return false
}

func handleRootLookupAnswer(t *testing.T, name, address string, z *dns.Msg) {
	t.Helper()

	rr := exdns.GetFirstAnswer[*dns.A](z)
	if rr == nil {
		if address != "" {
			t.Errorf("%s: no answer (expected %s)", name, address)
		} else {
			t.Errorf("%s: no answer", name)
		}
		return
	}

	first := rr.A.String()

	if address != "" {
		if first != address {
			t.Errorf("%s: %s (expected %s)", name, first, address)
			return
		}
	}

	t.Logf("%s: %s", name, first)
}
