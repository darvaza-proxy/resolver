package errors

import "context"

const (
	// NOANSWER is the text on [net.DNSError].Err if no [dns.Msg] was returned
	NOANSWER = "no answer"
	// NODATA is the text on [net.DNSError].Err if an authoritative server
	// returned no answer
	NODATA = "NODATA"
	// NXDOMAIN is the text on [net.DNSError].Err if the server returned a
	// Name error
	NXDOMAIN = "NXDOMAIN"
	// TRUNCATED is the text on [net.DNSError].Err if the server returned a
	// truncated response
	TRUNCATED = "dns response was truncated"
	// BADREQUEST is the text on [net.DNSError].Err if the client request
	// is invalid
	BADREQUEST = "invalid dns request"
	// BADRESPONSE is the text on [net.DNSError].Err if the server response
	// in invalid
	BADRESPONSE = "invalid dns response from server"
	// NOTIMPLEMENTED is the text on [net.DNSError].Err if the requested
	// functionality isn't implemented by the server
	NOTIMPLEMENTED = "feature not implemented by the server"
)

var (
	// CANCELLED indicates the context the exchange was using was
	// cancelled.
	CANCELLED = context.Canceled.Error()
	// DEADLINEEXCEEDED indicates the deadline the exchange was given
	// has been exceeded.
	DEADLINEEXCEEDED = context.DeadlineExceeded.Error()
)
