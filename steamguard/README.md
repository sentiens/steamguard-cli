# steamguard

The library used by steamguard-cli to all the steamguard related things, such as generating 2FA codes and responding to confirmations.

## Test endpoints

The `test-endpoints` Cargo feature allows integration tests to route requests to local servers. It
is disabled by default. When enabled, the library reads these variables the first time each base
URL is needed and retains that value for the rest of the process:

- `STEAMGUARD_API_BASE_URL`
- `STEAMGUARD_COMMUNITY_BASE_URL`
- `STEAMGUARD_LOGIN_BASE_URL`

An unset variable uses the production URL. Set all required variables before making the first
request in the process.

## Proxy errors and offline resolver (E4-FORK-03)

`steamguard::transport::NetworkErrorKind` includes `ProxyAuth` and `ProxyConnect`.
On transports created by `WebApiTransport::new_with_proxy`, non-TLS, non-timeout
connector failures are `ProxyConnect`. Typed TLS and timeout evidence retains its
existing classification. Generic `NetworkError::from(reqwest::Error)` conversions
retain `Connection`, because they have no proof of a configured proxy or of the
absence of earlier requests.

**Pinned-stack limitation:** `ProxyAuth` is reserved and is not currently emitted.
Hyper-util 0.1.20 declares `SocksError<C>` and `SocksV5Error::Auth(AuthError)` inside
private `client::legacy::connect::proxy::socks` modules. The public `proxy` module
re-exports only `SocksV4`, `SocksV5`, and `Tunnel`; it does not export `SocksError`,
`SocksV5Error`, `AuthError`, or `tunnel::TunnelError`. `SocksError<C>` implements
`std::error::Error` without overriding `source()`, so its auth/command payloads are
not reachable through the source chain either. Reqwest 0.12.28's enclosing
`connect::socks::SocksProxyError` is also private. There is no supported concrete
error downcast that distinguishes SOCKS auth refusals under these versions.
`TunnelError::ProxyAuthRequired` (HTTP CONNECT 407) is inaccessible too.

The best available typed discriminator is `reqwest::Error::is_connect()`, together
with knowledge of the approved explicit proxy route; `rustls::Error` is inspected
through `Error::source()` and `std::io::Error::get_ref()` to preserve TLS errors.
No error text is parsed. SOCKS auth rejection, SOCKS command rejection (including
general failure and connection not allowed), unreachable proxies, and HTTP CONNECT
non-2xx replies therefore all use the conservative `ProxyConnect` fallback.
T-41/C05's distinct auth classification requires an upstream public error API
(and a direct dependency or reqwest re-export); this change cannot close that part.

`RequestSent::No` is justified on this route by reqwest's typed connector-stage
failure: no stream was returned for sending the origin HTTP request. SOCKS/CONNECT
handshake bytes may have reached the proxy. Redirects and retries are disabled by
the factory, so there cannot have been an earlier origin request in the same call.
A normal HTTP forward-proxy response is still `HttpStatus` / `Yes`, not evidence
that the origin received nothing. Arbitrary source messages remain available for
typed inspection only; `NetworkError`'s own Debug/Display redact them.

With `test-endpoints`, these fork-owned APIs need no consumer dependency on reqwest:

```rust,ignore
use steamguard::test_support::{ProxyConfig, RecordingResolver, WebApiTransport};

let recorder = RecordingResolver::new();
let config = ProxyConfig::new("http://proxy.invalid:8080")?;
let transport = WebApiTransport::new_with_proxy_and_recording_resolver(&config, &recorder)?;
// After a request, recorder.names() is a snapshot of local DNS requests.
```

Exact new signatures:

```rust,ignore
impl RecordingResolver {
    pub fn new() -> Self;
    pub fn names(&self) -> Vec<String>;
}
impl WebApiTransport {
    pub fn new_with_proxy_and_recording_resolver(
        proxy: &ProxyConfig,
        resolver: &RecordingResolver,
    ) -> Result<Self, ProxyTransportError>;
}
```

`RecordingResolver` also implements `Clone` and `Default`. Clones share an
`Arc<Mutex<Vec<String>>>`; snapshots are independent. Every requested name is
recorded in order and resolution always fails without real DNS. Debug redacts
names, whereas the explicit `names()` accessor exposes them for assertions.
Literal IP addresses bypass DNS and can still connect: use only loopback stands
for those tests. A named proxy is recorded and fails before any connection.

`steamguard::test_support` re-exports `RecordingResolver`, `ProxyConfig`,
`ProxyConfigError`, `ProxyTransportError`, `WebApiTransport`, `Transport`,
`WebEndpoint`, `WebRequest`, `WebResponse`, `NetworkError`, `NetworkErrorKind`, and
`RequestSent`. `WebEndpoint::Test(&str)` is now available with `test-endpoints`
for isolated per-request local URLs. All resolver entry points call
`new_with_proxy`, the only proxy client constructor, and share its pinned policy.
The older generic `new_with_proxy_and_test_resolver` remains compatible.

Reqwest's resolution behavior differs from a direct connection:

| Proxy scheme | Destination name | Proxy hostname |
| --- | --- | --- |
| `socks5h` | Sent to proxy in SOCKS domain ATYP; no local lookup | Local lookup |
| `http` | Sent in absolute request URL or HTTPS CONNECT; no local lookup | Local lookup |
| `https` | Same routing as HTTP, over TLS to proxy; no local destination lookup | Local lookup |
| `socks5` | Local lookup before connecting to proxy | Local lookup after destination succeeds |

The approved factory continues to reject `socks5` without `h`. A raw reqwest
negative-control test verifies its local lookup using the same recording resolver.
The fork-only integration tests exercise SOCKS domain forwarding, HTTP forwarding,
HTTP CONNECT rejection, named proxy resolution failure, shared recordings, and
redacted diagnostics. An HTTPS proxy with a failing hostname resolver stops before
TLS, so that control observes only proxy-host resolution, not a completed tunnel.
