package resolver

import (
	"testing"

	"github.com/miekg/dns"
)

func TestLookup(t *testing.T) {
	x := NewResolver("192.33.4.12:53")
	z, err := x.Lookup("karasz.im", dns.TypeA)
	if err != nil {
		t.Errorf(err.Error())
	}
	if z.Answer[0].(*dns.A).A.String() != "95.216.149.141" {
		t.Errorf("ip is not the expected one")
	}
}
