package resolver

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

func TestLookup(t *testing.T) {
	start := "192.33.4.12:53"
	z, err := Iterate(context.TODO(), "karasz.im", dns.TypeA, start)
	if err != nil {
		t.Errorf(err.Error())
	} else {
		t.Log(z.Answer[0].(*dns.A).A.String(), "95.216.149.141")
	}
	if z.Answer[0].(*dns.A).A.String() != "95.216.149.141" {
		t.Errorf("ip is not the expected one")
	}
}
