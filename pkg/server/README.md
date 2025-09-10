# server

[![Go Reference][godoc-badge]][godoc]

[godoc]: https://pkg.go.dev/darvaza.org/resolver/pkg/server
[godoc-badge]: https://pkg.go.dev/badge/darvaza.org/resolver/pkg/server.svg

The `server` package implements DNS server handlers that bridge between the
`miekg/dns` server interface and `darvaza.org/resolver` Lookuper/Exchanger
implementations.

## Features

- **Handler Implementation**: `dns.Handler` interface for DNS servers
- **Lookuper Integration**: Use any Lookuper as a DNS server backend
- **Exchanger Support**: Direct message exchange handling
- **Error Mapping**: Automatic error to DNS response conversion
- **EDNS Support**: Proper EDNS0 handling and response sizing

## Basic Usage

### Creating a DNS Server

```go
import (
    "github.com/miekg/dns"
    "darvaza.org/resolver"
    "darvaza.org/resolver/pkg/server"
)

// Create a resolver backend
lookuper := resolver.NewRootLookuper()

// Create DNS handler
handler := server.NewHandler(lookuper)

// Start DNS server
srv := &dns.Server{
    Addr:    ":53",
    Net:     "udp",
    Handler: handler,
}

err := srv.ListenAndServe()
```

### Custom Handler Options

```go
// Create handler with options
handler := server.NewHandler(lookuper,
    server.WithMaxSize(4096),        // Maximum response size
    server.WithTimeout(5*time.Second), // Query timeout
    server.WithEDNS(true),           // Enable EDNS support
)
```

## Handler Types

### Lookuper Handler

Wraps a Lookuper for standard queries:

```go
type cachedResolver struct {
    cache map[string]*dns.Msg
    resolver.Lookuper
}

func (r *cachedResolver) Lookup(ctx context.Context, qname string,
    qtype uint16) (*dns.Msg, error) {
    key := fmt.Sprintf("%s:%d", qname, qtype)
    if msg, ok := r.cache[key]; ok {
        return msg, nil
    }

    msg, err := r.Lookuper.Lookup(ctx, qname, qtype)
    if err == nil {
        r.cache[key] = msg
    }
    return msg, err
}

// Use as handler
handler := server.NewHandler(&cachedResolver{
    cache: make(map[string]*dns.Msg),
    Lookuper: resolver.NewSingleLookuper("8.8.8.8:53"),
})
```

### Exchanger Handler

For full message control:

```go
type customExchanger struct{}

func (e *customExchanger) Exchange(ctx context.Context,
    req *dns.Msg) (*dns.Msg, error) {
    // Custom logic based on full request
    if len(req.Question) == 0 {
        return errors.ErrorAsMsg(req, errors.ErrBadRequest("no question"))
    }

    // Handle different query types
    switch req.Question[0].Qtype {
    case dns.TypeAXFR:
        return errors.ErrorAsMsg(req, errors.ErrNotImplemented("AXFR"))
    default:
        // Forward to upstream
        return upstream.Exchange(ctx, req)
    }
}

handler := server.NewHandler(&customExchanger{})
```

## Advanced Usage

### Multiple Handlers

```go
// Different handlers for different zones
mux := dns.NewServeMux()

// Internal zone
internalHandler := server.NewHandler(internalResolver)
mux.Handle("internal.local.", internalHandler)

// External queries
externalHandler := server.NewHandler(externalResolver)
mux.Handle(".", externalHandler)

srv := &dns.Server{
    Addr:    ":53",
    Net:     "udp",
    Handler: mux,
}
```

### Handler Middleware

```go
// Logging middleware
type loggingHandler struct {
    dns.Handler
    logger slog.Logger
}

func (h *loggingHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
    start := time.Now()

    // Wrap writer to capture response
    rw := &responseWriter{ResponseWriter: w}
    h.Handler.ServeDNS(rw, req)

    h.logger.Info().
        WithField("query", req.Question[0].Name).
        WithField("type", dns.TypeToString[req.Question[0].Qtype]).
        WithField("client", w.RemoteAddr()).
        WithField("rcode", dns.RcodeToString[rw.msg.Rcode]).
        WithField("duration", time.Since(start)).
        Print("DNS query handled")
}

// Use with server handler
baseHandler := server.NewHandler(resolver)
loggedHandler := &loggingHandler{
    Handler: baseHandler,
    logger: logger,
}
```

### Rate Limiting

```go
type rateLimitHandler struct {
    dns.Handler
    limiter *rate.Limiter
}

func (h *rateLimitHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
    if !h.limiter.Allow() {
        resp := new(dns.Msg)
        resp.SetReply(req)
        resp.Rcode = dns.RcodeRefused
        w.WriteMsg(resp)
        return
    }

    h.Handler.ServeDNS(w, req)
}

// Apply rate limiting
handler := &rateLimitHandler{
    Handler: server.NewHandler(resolver),
    limiter: rate.NewLimiter(100, 10), // 100 QPS with burst of 10
}
```

## Error Handling

The handler automatically converts resolver errors to appropriate DNS responses:

```go
// Resolver returns error
err := errors.ErrNXDOMAIN("non-existent.example.com")
// Handler returns NXDOMAIN response

err := errors.ErrTimeout("slow.example.com")
// Handler returns SERVFAIL response

err := errors.ErrNotImplemented("AXFR")
// Handler returns NOTIMP response
```

## EDNS Handling

```go
handler := server.NewHandler(resolver,
    server.WithEDNS(true),
    server.WithEDNSBufferSize(4096),
)

// Handler automatically:
// - Preserves EDNS0 from request
// - Sets appropriate buffer size
// - Handles DNSSEC OK flag
// - Truncates responses if needed
```

## TCP vs UDP

```go
// Handler works with both TCP and UDP
tcpServer := &dns.Server{
    Addr:    ":53",
    Net:     "tcp",
    Handler: handler,
}

udpServer := &dns.Server{
    Addr:    ":53",
    Net:     "udp",
    Handler: handler,
    UDPSize: 4096, // EDNS buffer size
}

// Start both
go tcpServer.ListenAndServe()
go udpServer.ListenAndServe()
```

## Testing

```go
func TestHandler(t *testing.T) {
    // Create test resolver
    resolver := &testResolver{
        responses: map[string]*dns.Msg{
            "example.com.": makeAResponse("example.com.", "192.0.2.1"),
        },
    }

    // Create handler
    handler := server.NewHandler(resolver)

    // Test with dns.Client
    client := new(dns.Client)
    query := new(dns.Msg)
    query.SetQuestion("example.com.", dns.TypeA)

    // Use test server
    srv := &dns.Server{
        Addr:    "127.0.0.1:0",
        Net:     "udp",
        Handler: handler,
    }
    go srv.ListenAndServe()
    defer srv.Shutdown()

    // Query test server
    resp, _, err := client.Exchange(query, srv.Addr)
    assert.NoError(t, err)
    assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
}
```

## See also

- [darvaza.org/resolver][resolver] - Main resolver package
- [github.com/miekg/dns][dns] - DNS server implementation
- [darvaza.org/resolver/pkg/errors][errors] - Error handling utilities

[resolver]: https://pkg.go.dev/darvaza.org/resolver
[dns]: https://github.com/miekg/dns
[errors]: https://pkg.go.dev/darvaza.org/resolver/pkg/errors
