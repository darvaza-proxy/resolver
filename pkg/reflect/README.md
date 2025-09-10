# reflect
<!-- cspell:ignore zerolog -->

[![Go Reference][godoc-badge]][godoc]

[godoc]: https://pkg.go.dev/darvaza.org/resolver/pkg/reflect
[godoc-badge]: https://pkg.go.dev/badge/darvaza.org/resolver/pkg/reflect.svg

The `reflect` package provides logging and debugging middleware for DNS
operations, enabling detailed tracing of queries and responses with optional
correlation IDs.

## Features

- **Transparent Logging**: Middleware pattern for `Lookuper` and `Client`
- **Correlation IDs**: Track requests across distributed systems
- **Structured Logging**: Integration with `darvaza.org/slog` interface
- **Performance Metrics**: Log query times and response details
- **Debug Control**: Dynamic enable/disable without restart

## Reflect Lookuper

Wraps any `Lookuper` or `Exchanger` with logging capabilities:

```go
import (
    "darvaza.org/resolver/pkg/reflect"
    "darvaza.org/slog/handlers/zerolog"
)

// Create base resolver
base := resolver.NewSingleLookuper("8.8.8.8:53")

// Add logging layer
logger := zerolog.New()
logged := reflect.NewLookuper(base, logger)

// Optional: set trace ID for correlation
logged = logged.WithTraceID("req-123")

// Use normally - all operations are logged
resp, err := logged.Lookup(ctx, "example.com", dns.TypeA)
```

## Reflect Client

Wraps any DNS `Client` with logging:

```go
// Create base client
base := client.NewAuto()

// Add logging layer
logger := slog.New()
logged := reflect.NewClient(base, logger)

// Set trace ID for this request flow
logged = logged.WithTraceID("trace-456")

// All exchanges are logged with timing
resp, rtt, err := logged.ExchangeContext(ctx, msg, "8.8.8.8:53")
```

## Logging Output

### Query Logging

```json
{
  "level": "debug",
  "trace_id": "req-123",
  "query": "example.com",
  "type": "A",
  "class": "IN",
  "server": "8.8.8.8:53",
  "message": "DNS query started"
}
```

### Response Logging

```json
{
  "level": "info",
  "trace_id": "req-123",
  "query": "example.com",
  "type": "A",
  "rtt_ms": 23,
  "answers": 1,
  "rcode": "NOERROR",
  "flags": "qr rd ra",
  "message": "DNS query completed"
}
```

### Error Logging

```json
{
  "level": "error",
  "trace_id": "req-123",
  "query": "example.com",
  "type": "A",
  "error": "i/o timeout",
  "server": "8.8.8.8:53",
  "message": "DNS query failed"
}
```

## Advanced Usage

### Conditional Logging

```go
type ConditionalLogger struct {
    *reflect.Lookuper
    enabled bool
}

func (l *ConditionalLogger) SetEnabled(enabled bool) {
    l.enabled = enabled
    if enabled {
        l.Lookuper.SetLogger(logger)
    } else {
        l.Lookuper.SetLogger(nil)
    }
}
```

### Request Correlation

```go
// Extract trace ID from HTTP request
func handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
    traceID := r.Header.Get("X-Trace-ID")
    if traceID == "" {
        traceID = generateTraceID()
    }

    // Create resolver with trace ID
    resolver := baseResolver.WithTraceID(traceID)

    // All DNS queries in this request are correlated
    result, err := resolver.Lookup(ctx, domain, dns.TypeA)

    // Include trace ID in response
    w.Header().Set("X-Trace-ID", traceID)
}
```

### Middleware Stacking

```go
// Build a complete middleware stack
func buildResolver() Lookuper {
    // Base resolver
    base := resolver.NewRootLookuper()

    // Add caching
    cached := cache.New(base)

    // Add logging (only for cache misses)
    logged := reflect.NewLookuper(cached, logger)

    // Add metrics
    metered := metrics.New(logged)

    return metered
}
```

## Performance Considerations

- Logging overhead is minimal when logger is nil
- Structured logging allows efficient filtering
- Trace IDs enable distributed tracing
- Consider log levels for production environments

## Integration Examples

### With Context

```go
// Store logger in context
ctx := reflect.WithLogger(ctx, logger)
ctx = reflect.WithTraceID(ctx, "trace-789")

// Extract and use in resolver
if logger := reflect.LoggerFromContext(ctx); logger != nil {
    resolver = reflect.NewLookuper(resolver, logger)
}
if traceID := reflect.TraceIDFromContext(ctx); traceID != "" {
    resolver = resolver.WithTraceID(traceID)
}
```

### With Metrics

```go
// Combine with Prometheus metrics
type MetricsLogger struct {
    *reflect.Lookuper
    queries *prometheus.CounterVec
    latency *prometheus.HistogramVec
}

func (m *MetricsLogger) Lookup(ctx context.Context, qname string,
    qtype uint16) (*dns.Msg, error) {
    start := time.Now()
    resp, err := m.Lookuper.Lookup(ctx, qname, qtype)

    labels := prometheus.Labels{
        "type": dns.TypeToString[qtype],
        "status": getStatus(err),
    }

    m.queries.With(labels).Inc()
    m.latency.With(labels).Observe(time.Since(start).Seconds())

    return resp, err
}
```

## See also

- [darvaza.org/resolver][resolver] - Main resolver package
- [darvaza.org/slog][slog] - Structured logging interface
- [darvaza.org/resolver/pkg/client][client] - DNS client implementations

[resolver]: https://pkg.go.dev/darvaza.org/resolver
[slog]: https://pkg.go.dev/darvaza.org/slog
[client]: https://pkg.go.dev/darvaza.org/resolver/pkg/client
