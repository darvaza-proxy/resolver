# errors

[![Go Reference][godoc-badge]][godoc]

[godoc]: https://pkg.go.dev/darvaza.org/resolver/pkg/errors
[godoc-badge]: https://pkg.go.dev/badge/darvaza.org/resolver/pkg/errors.svg

The `errors` package provides DNS error handling utilities, converting between
`net.DNSError` and DNS protocol messages for consistent error representation.

## Features

- **Standard Error Format**: All errors as `*net.DNSError` for consistency
- **Message Conversion**: Transform DNS response codes to errors and vice versa
- **Error Categories**: NXDOMAIN, NODATA, timeout, and malformed responses
- **Bi-directional Mapping**: Convert errors to DNS messages for protocol
  responses

## Error Types

### DNS Response Errors

```go
// NXDOMAIN - Domain does not exist
err := errors.ErrNXDOMAIN("example.invalid")

// NODATA - Domain exists but no records of requested type
err := errors.ErrNODATA("example.com", dns.TypeAAAA)

// Not Found - Generic not found error
err := errors.ErrNotFound("example.com")
```

### Protocol Errors

```go
// Bad Request - Malformed query
err := errors.ErrBadRequest("invalid query format")

// Bad Response - Invalid server response
err := errors.ErrBadResponse("truncated message")

// Not Implemented - Unsupported operation
err := errors.ErrNotImplemented("AXFR not supported")
```

### Timeout Errors

```go
// Timeout with specific operation
err := errors.ErrTimeoutMessage("example.com", errors.NXDOMAIN)

// Deadline exceeded
err := errors.ErrDeadlineExceeded("example.com")
```

## Message Conversion

### Error to DNS Message

```go
// Convert error to DNS response message
func handleError(query *dns.Msg, err error) *dns.Msg {
    return errors.ErrorAsMsg(query, err)
}

// The response will have appropriate RCODE:
// - NXDOMAIN errors -> RCODE 3
// - NODATA errors -> RCODE 0 with no answers
// - Bad request -> RCODE 1 (FORMERR)
// - Not implemented -> RCODE 4
```

### DNS Message to Error

```go
// Convert DNS response to error if applicable
func checkResponse(resp *dns.Msg, qname string) error {
    return errors.MsgAsError(resp, qname)
}

// Returns appropriate error for:
// - NXDOMAIN responses
// - NODATA responses (no answers)
// - Server failures
// - Format errors
```

## Usage Examples

### Error Handling in Resolver

```go
func (r *Resolver) Lookup(ctx context.Context, qname string,
    qtype uint16) (*dns.Msg, error) {
    msg, err := r.exchange(ctx, qname, qtype)
    if err != nil {
        // Network or timeout error
        return nil, err
    }

    // Check DNS response for errors
    if err := errors.MsgAsError(msg, qname); err != nil {
        return nil, err
    }

    return msg, nil
}
```

### Error Response Generation

```go
func (h *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
    resp, err := h.resolver.Lookup(ctx, req.Question[0].Name,
        req.Question[0].Qtype)

    if err != nil {
        // Convert error to appropriate DNS response
        resp = errors.ErrorAsMsg(req, err)
    }

    w.WriteMsg(resp)
}
```

### Custom Error Checking

```go
// Check for specific error types
if errors.IsNXDOMAIN(err) {
    // Handle non-existent domain
}

if errors.IsTimeout(err) {
    // Handle timeout, maybe retry
}

if errors.IsTemporary(err) {
    // Temporary error, can retry
}
```

## Constants

The package defines standard DNS error codes:

- `NOANSWER` - Query successful but no answers
- `NODATA` - Domain exists but no data for type
- `NXDOMAIN` - Domain does not exist
- `BADREQUEST` - Malformed request
- `BADRESPONSE` - Invalid response
- `NOTIMPLEMENTED` - Feature not supported
- `DEADLINEEXCEEDED` - Operation timed out

## See also

- [darvaza.org/resolver][resolver] - Main resolver package
- [net.DNSError][dnserror] - Go standard DNS error type
- [github.com/miekg/dns][dns] - DNS protocol implementation

[resolver]: https://pkg.go.dev/darvaza.org/resolver
[dnserror]: https://pkg.go.dev/net#DNSError
[dns]: https://github.com/miekg/dns
