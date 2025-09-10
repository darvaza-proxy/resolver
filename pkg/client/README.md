# client

[![Go Reference][godoc-badge]][godoc]

[godoc]: https://pkg.go.dev/darvaza.org/resolver/pkg/client
[godoc-badge]: https://pkg.go.dev/badge/darvaza.org/resolver/pkg/client.svg

The `client` package provides DNS client implementations with advanced features
including automatic protocol selection, middleware patterns, and connection
pooling.

## Features

- **Protocol Auto-detection**: Automatic selection between UDP, TCP, and TLS
- **Truncation Handling**: Automatic TCP retry for truncated UDP responses
- **Middleware Pattern**: Composable client middleware for caching, rate
  limiting
- **Connection Pooling**: Worker pool for concurrent query management
- **IPv6 Filtering**: NoAAAA middleware for IPv6-challenged environments
- **SingleFlight**: Deduplication of identical concurrent queries

## Client Types

### Auto Client

Automatically selects the appropriate protocol based on server URL:

```go
client := client.NewAuto()

// UDP by default, TCP retry on truncation
resp, _, err := client.ExchangeContext(ctx, msg, "8.8.8.8:53")

// Force TCP with prefix
resp, _, err := client.ExchangeContext(ctx, msg, "tcp://8.8.8.8:53")

// TLS connection
resp, _, err := client.ExchangeContext(ctx, msg, "tls://8.8.8.8:853")
```

### NoAAAA Client

Filters out AAAA records for systems without IPv6 support:

```go
baseClient := client.NewAuto()
noAAAAClient := client.NewNoAAAA(baseClient)

// AAAA queries return empty results
resp, _, err := noAAAAClient.ExchangeContext(ctx, msg, server)
```

### SingleFlight Client

Deduplicates concurrent identical queries:

```go
baseClient := client.NewAuto()
sfClient := client.NewSingleFlight(baseClient)

// Multiple concurrent identical queries result in single upstream query
// All callers receive the same response
```

### WorkerPool Client

Limits concurrent upstream queries:

```go
baseClient := client.NewAuto()
poolClient := client.NewWorkerPool(baseClient, 10) // Max 10 concurrent queries

// Queries beyond limit wait for available worker
```

## Usage Examples

### Middleware Composition

```go
// Build a client stack
base := client.NewDefaultClient()
filtered := client.NewNoAAAA(base)           // Filter IPv6
deduped := client.NewSingleFlight(filtered)  // Deduplicate
pooled := client.NewWorkerPool(deduped, 20)  // Limit concurrency

// Use the composed client
resp, rtt, err := pooled.ExchangeContext(ctx, query, "8.8.8.8:53")
```

### Custom Client Implementation

```go
type LoggingClient struct {
    client.Client
    logger slog.Logger
}

func (c *LoggingClient) ExchangeContext(ctx context.Context,
    req *dns.Msg, server string) (*dns.Msg, time.Duration, error) {
    start := time.Now()
    resp, rtt, err := c.Client.ExchangeContext(ctx, req, server)

    c.logger.Info().
        WithField("server", server).
        WithField("query", req.Question[0].Name).
        WithField("rtt", rtt).
        Print("DNS query completed")

    return resp, rtt, err
}
```

## See also

- [darvaza.org/resolver][resolver] - Main resolver package
- [github.com/miekg/dns][dns] - Underlying DNS library

[resolver]: https://pkg.go.dev/darvaza.org/resolver
[dns]: https://github.com/miekg/dns
