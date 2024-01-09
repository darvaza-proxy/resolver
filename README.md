# Darvaza DNS Resolver

[![Go Reference][godoc-badge]][godoc]
[![Go Report Card][goreport-badge]][goreport]
[![Codebeat Score][codebeat-badge]][codebeat]

[codebeat]: https://codebeat.co/projects/github-com-darvaza-proxy-resolver-main
[codebeat-badge]: https://codebeat.co/badges/20a9893f-b3df-4a45-a1a8-f54a656b0447
[godoc]: https://pkg.go.dev/darvaza.org/resolver
[godoc-badge]: https://pkg.go.dev/badge/darvaza.org/resolver.svg
[goreport]: https://goreportcard.com/report/darvaza.org/resolver
[goreport-badge]: https://goreportcard.com/badge/darvaza.org/resolver

[dns.Client]: https://pkg.go.dev/github.com/miekg/dns#Client
[dns.Handler]: https://pkg.go.dev/github.com/miekg/dns#Handler
[dns.Msg]: https://pkg.go.dev/github.com/miekg/dns#Msg
[net.DNSError]: https://pkg.go.dev/net#DNSError
[net.Resolver]: https://pkg.go.dev/net#Resolver
[slog.Logger]: https://pkg.go.dev/darvaza.org/slog#Logger

## Resolver

The `Resolver` interface reproduces the standard [`net.Resolver`][net.Resolver]
but allows us to make a custom implementation on top of any `Lookuper`.

We provide three mechanisms to create a `Resolver`:

* `SystemResolver()`/`SystemResolverWithDialer()` as shortcuts for allocating
a standard [`*net.Resolver{}`][net.Resolver].
* `NewResolver()` returning a `Resolver` using the given `Lookuper{}`
* and `NewRootResolver()` returning a `Resolver` using iterative lookup.

## Lookuper

The `Lookuper` interface is centred on `Resolver`, making simple `INET` queries.

```go
type Lookuper interface {
    Lookup(ctx context.Context, qName string, qType uint16) (*dns.Msg, error)
}

type LookuperFunc func(ctx context.Context, qName string, qType uint16) (*dns.Msg, error)
```

Additionally we can use any function implementing the same signature as `LookuperFunc`,
which returns a type implementing `Lookuper` and `Exchanger` using the given function.

## Exchanger

The `Exchanger` interface is an alternative to `Lookuper` but taking pre-assembled
[`*dns.Msg{}`][dns.Msg] queries.

```go
type Exchanger interface {
    Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
}

type ExchangerFunc func(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
```

Additionally we can use any function implementing the same signature as `ExchangerFunc`,
which returns a type implementing `Lookuper` and `Exchanger` using the
given function.

## client.Client

The `client.Client` interface represents `ExchangeContext()` of [*dns.Client][dns.Client] to perform a [*dns.Msg{}][dns.Msg] against the specified _server_.

```go
type Client interface {
    ExchangeContext(ctx context.Context, req *dns.Msg, server string) (*dns.Msg, time.Duration, error)
}

type ExchangeFunc func(ctx context.Context, req *dns.Msg, server string) (*dns.Msg, time.Duration, error)

type Unwrapper interface {
    Unwrap() *dns.Client
}
```

Additionally we can use any function implementing the same signature as `client.ExchangeFunc`, which returns a type implementing `client.Client` using the given functions.

`Client`s are advised to also implement `Unwrapper` to access the underlying [`*dns.Client{}`][dns.Client].

## Errors

We use the standard [*net.DNSError{}][net.DNSError] for all our errors, but also provide `errors.MsgAsError()` and `errors.ErrorAsMsg()` to convert back and forth between the errors we emit and an equivalent [*dns.Msg][dns.Msg].

## server.Handler

`server.Handler` implements a [dns.Handler][dns.Handler] on top of a `Lookuper` or `Exchanger`.

## Client Implementations

### Default Standard Client

`client.NewDefaultClient()` can be used to get a plain `UDP` [`*dns.Client{}`][dns.Client] with an optional message size.

### client.Auto

The `client.Auto` Client distinguishes requests by server protocol and retries truncated UDP requests as TCP.
`client.Auto` uses `udp://`, `tcp://` and `tls://` server prefixes for protocol specific and uses `UDP` followed by a `TCP` retry if no prefix is specified.

### client.NoAAAA

`client.NoAAAA` is a Client Middleware that removes all `AAAA` entries, to be used on systems were IPv6 isn't fully functional.

### client.SingleFlight

`client.SingleFlight` is a Client Middleware that implements a barrier to catch identical queries, with a small caching period. Only the `req.Id` is ignored when comparing requests, and it operates per-server.

### reflect.Client

`reflect.Client` implements logging middleware if front of a `client.Client`.

## Lookuper Implementations

### RootLookuper

The `RootLookuper` implements an iterative `Lookuper`/`Exchanger`, supporting an optional custom `client.Client`.

### SingleLookuper

`SingleLookuper` implements a forwarding `Lookuper`/`Exchanger` passing requests as-is to a `client.Client`.

### MultiLookuper

`MultiLookuper` implements a parallel `Lookuper`/`Exchanger` that will pass the request to multiple `Lookuper`/`Exchanger` instances and return the first response.

### SingleFlight

`SingleFlight` implements a `Lookuper`/`Exchanger` barrier to hold identical requests at
the same time, before passing them over to another.

### reflect.Lookuper

`reflect.Lookuper` implements logging middleware in front of a `Lookuper` or `Exchanger`.

### Well-known recursive resolvers

For convenience we provide shortcuts to create forwarding `Lookuper`s to well known recursive resolvers.

* `NewGoogleLookuper()` using `8.8.8.8`,
* `NewGoogleLookuper2()` using `8.8.4.4`,
* `NewCloudflareLookuper()` using `1.1.1.1`,
* `NewQuad9Lookuper()` using `9.9.9.9`,
* and `NewQuad9Lookuper6()` using Quad9's `2620:fe::f3`.

## Reflection

`reflect.Lookuper` and `reflect.Client` allow us to hook a dynamically enabled logging layer with an optional tracing ID, using the [`darvaza.org/slog.Logger`][slog.Logger] interface.

## See also

* [github.com/miekg/dns](https://github.com/miekg/dns)
* [darvaza.org/core](https://darvaza.org/core)
* [darvaza.org/slog](https://darvaza.org/slog)
