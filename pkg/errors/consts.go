package errors

const (
	// NOANSWER is the text on [net.DNSError].Err if no [dns.Msg] was returned
	NOANSWER = "no answer"
	// NOTYPE is the text on [net.DNSError].Err if an authoritative server
	// returned no answer
	NOTYPE = "NOTYPE"
	// NXDOMAIN is the text on [net.DNSError].Err if the server returned a
	// Name error
	NXDOMAIN = "NXDOMAIN"
	// TRUNCATED is the text on [net.DNSError].Err if the server returned a
	// truncated response
	TRUNCATED = "dns response was truncated"
)
