# exdns
<!-- cspell:ignore Decanonicalise -->

[![Go Reference][godoc-badge]][godoc]

[godoc]: https://pkg.go.dev/darvaza.org/resolver/pkg/exdns
[godoc-badge]: https://pkg.go.dev/badge/darvaza.org/resolver/pkg/exdns.svg

The `exdns` package provides extended DNS functionality and utilities for
working with DNS messages, including type-safe access to DNS records and
message manipulation helpers.

## Features

- **Type-safe Record Access**: Generic functions for extracting specific RR
  types
- **Message Building**: Helpers for constructing DNS queries and responses
- **Record Filtering**: Utilities for filtering and extracting DNS records
- **EDNS Support**: Extended DNS handling utilities
- **Name Processing**: Domain name manipulation and comparison

## Message Utilities

### Type-safe Record Extraction

```go
// Get first A record from answer section
aRecord := exdns.GetFirstAnswer[*dns.A](msg)
if aRecord != nil {
    fmt.Printf("IP: %s\n", aRecord.A)
}

// Get all MX records
mxRecords := exdns.GetAnswers[*dns.MX](msg)
for _, mx := range mxRecords {
    fmt.Printf("MX: %d %s\n", mx.Preference, mx.Mx)
}

// Get CNAME from answer section
cname := exdns.GetFirstAnswer[*dns.CNAME](msg)
if cname != nil {
    fmt.Printf("CNAME: %s\n", cname.Target)
}
```

### Message Building

```go
// Create a query message
query := exdns.NewQuery("example.com", dns.TypeA)

// Create response from query
response := exdns.ResponseFromQuery(query)
response.Answer = append(response.Answer, &dns.A{
    Hdr: dns.RR_Header{
        Name:   "example.com.",
        Rrtype: dns.TypeA,
        Class:  dns.ClassINET,
        Ttl:    300,
    },
    A: net.ParseIP("192.0.2.1"),
})
```

### Record Filtering

```go
// Filter specific record types
func FilterAnswers[T dns.RR](msg *dns.Msg) []T {
    var results []T
    exdns.ForEachAnswer(msg, func(rr dns.RR) bool {
        if record, ok := rr.(T); ok {
            results = append(results, record)
        }
        return true // continue iteration
    })
    return results
}

// Check if response has records
if exdns.HasAnswers(msg) {
    // Process answers
}
```

## Name Processing

### Domain Name Utilities

```go
// Canonicalise domain name
canonical := exdns.Canonicalise("EXAMPLE.COM")
// Returns: "example.com."

// Decanonicalise for display
display := exdns.Decanonicalise("example.com.")
// Returns: "example.com"

// Compare domain names
if exdns.SameDomainName("example.com.", "EXAMPLE.COM") {
    // Names match
}
```

### EDNS Processing

```go
// Check for EDNS0 support
if exdns.HasEDNS0(msg) {
    opt := exdns.GetEDNS0(msg)
    fmt.Printf("EDNS buffer size: %d\n", opt.UDPSize())
}

// Add EDNS0 to query
exdns.SetEDNS0(query, 4096) // Set buffer size
```

## Error Handling

```go
// Check response code
if msg.Rcode != dns.RcodeSuccess {
    err := exdns.ResponseError(msg)
    // Handle DNS error
}

// Check for truncation
if exdns.IsTruncated(msg) {
    // Retry with TCP
}
```

## Usage Examples

### Complete Query Handler

```go
func handleQuery(query *dns.Msg) *dns.Msg {
    // Extract question details
    qname := query.Question[0].Name
    qtype := query.Question[0].Qtype

    // Perform lookup
    answers := lookupRecords(qname, qtype)

    // Build response
    resp := exdns.ResponseFromQuery(query)
    resp.Authoritative = true

    // Add answers based on type
    switch qtype {
    case dns.TypeA:
        for _, ip := range answers {
            resp.Answer = append(resp.Answer, &dns.A{
                Hdr: exdns.NewHeader(qname, dns.TypeA, 300),
                A:   ip,
            })
        }
    case dns.TypeCNAME:
        // Add CNAME record
    }

    return resp
}
```

### Record Set Operations

```go
// Collect all IPs from response
func collectIPs(msg *dns.Msg) []net.IP {
    var ips []net.IP

    // Get A records
    for _, a := range exdns.GetAnswers[*dns.A](msg) {
        ips = append(ips, a.A)
    }

    // Get AAAA records
    for _, aaaa := range exdns.GetAnswers[*dns.AAAA](msg) {
        ips = append(ips, aaaa.AAAA)
    }

    return ips
}
```

## See also

- [darvaza.org/resolver][resolver] - Main resolver package
- [github.com/miekg/dns][dns] - Core DNS library

[resolver]: https://pkg.go.dev/darvaza.org/resolver
[dns]: https://github.com/miekg/dns
