package resolver

import "darvaza.org/resolver/pkg/client"

func mustSingleLookuperWithClient(start string, recursive bool,
	c client.Client) *SingleLookuper {
	//
	h, err := NewSingleLookuperWithClient(start, recursive, c)
	if err != nil {
		panic(err)
	}
	return h
}

// NewGoogleLookuper creates a Lookuper asking 8.8.8.8 (Google)
func NewGoogleLookuper() *SingleLookuper {
	return mustSingleLookuperWithClient("8.8.8.8:53", true, nil)
}

// NewGoogleLookuper2 creates a Lookuper asking 8.8.4.4 (Google)
func NewGoogleLookuper2() *SingleLookuper {
	return mustSingleLookuperWithClient("8.8.4.4:53", true, nil)
}

// NewCloudflareLookuper creates a Lookuper asking 1.1.1.1 (Cloudflare)
func NewCloudflareLookuper() *SingleLookuper {
	return mustSingleLookuperWithClient("1.1.1.1:53", true, nil)
}

// NewQuad9Lookuper creates a Lookuper asking 9.9.9.9 (Quad9.net)
func NewQuad9Lookuper() *SingleLookuper {
	return mustSingleLookuperWithClient("9.9.9.9:53", true, nil)
}

// NewQuad9Lookuper6 creates a Lookuper asking Quad9.net using IPv6
func NewQuad9Lookuper6() *SingleLookuper {
	return mustSingleLookuperWithClient("[2620:fe::f3]:53", true, nil)
}
