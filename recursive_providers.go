package resolver

func mustSingleRecursiveForwarder(server string) *SingleLookuper {
	h, err := NewSingleLookuperWithClient(server, true, nil)
	if err != nil {
		panic(err)
	}
	return h
}

// NewGoogleLookuper creates a Lookuper asking 8.8.8.8 (Google)
func NewGoogleLookuper() *SingleLookuper {
	return mustSingleRecursiveForwarder("8.8.8.8:53")
}

// NewGoogleLookuper2 creates a Lookuper asking 8.8.4.4 (Google)
func NewGoogleLookuper2() *SingleLookuper {
	return mustSingleRecursiveForwarder("8.8.4.4:53")
}

// NewCloudflareLookuper creates a Lookuper asking 1.1.1.1 (Cloudflare)
func NewCloudflareLookuper() *SingleLookuper {
	return mustSingleRecursiveForwarder("1.1.1.1:53")
}

// NewQuad9Lookuper creates a Lookuper asking 9.9.9.9 (Quad9.net)
func NewQuad9Lookuper() *SingleLookuper {
	return mustSingleRecursiveForwarder("9.9.9.9:53")
}

// NewQuad9Lookuper6 creates a Lookuper asking Quad9.net using IPv6
func NewQuad9Lookuper6() *SingleLookuper {
	return mustSingleRecursiveForwarder("[2620:fe::f3]:53")
}
