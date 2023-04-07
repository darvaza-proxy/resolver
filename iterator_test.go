package resolver

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

func TestLookupSimple(t *testing.T) {
	root, err := NewRootLookuper("")
	if err != nil {
		t.Fatal(err)
	}

	z, err := root.Iterate(context.TODO(), "karasz.im", dns.TypeA, "")
	if err != nil {
		t.Errorf(err.Error())
	}
	if z.Answer[0].(*dns.A).A.String() != "95.216.149.141" {
		t.Errorf("ip is not the expected one")
	}
}

func TestLookupComplex(t *testing.T) {
	root, err := NewRootLookuper("")
	if err != nil {
		t.Fatal(err)
	}

	z, err := root.Iterate(context.TODO(), "fda.my.salesforce.com", dns.TypeA, "")
	if err != nil {
		t.Errorf(err.Error())
	}
	t.Logf("Complex test yeld: %s", z.Answer[0].(*dns.A).A.String())
}
