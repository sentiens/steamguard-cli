# Changelog

## SGM fork — E4-FORK-05 (pin-05)

SGM T-43 can validate a refresh-only login token before sending it back to Steam:
`UserLogin<T>::poll_once_tokens_only(&mut self) -> Result<PollTokensOutcome, LoginError>`
returns `Waiting`, `Tokens(Tokens)`, or `RefreshTokenOnly(Jwt)` after one poll.
`PollTokensOutcome` is available at the crate root and under `userlogin`; Debug
redacts both token variants. The existing `PollOutcome`, `poll_once`, and
`poll_until_tokens` retain their behavior, including automatic generation.

After checking the refresh JWT's `sub` against the known account and the
begin-auth subject, call
`UserLogin<T>::generate_access_token(&mut self, refresh: &Jwt) -> Result<Tokens, LoginError>`.
This makes one generation request, retaining the refresh token unless Steam
rotates it. Invalid JWT subjects fail locally; decoding does not verify the JWT
signature. Validate both returned subjects, including any rotated refresh token,
before accepting the session. Neither new method sleeps or retries.

Credentials login now checks the RSA response's `EResult` before using key fields.
Every non-OK result stops before begin-auth, even when key fields are present;
`LoginError::eresult().map(EResult::code)` retains the exact rejection code.

With `test-endpoints`, the transport refuses API, login, and community base URLs
unless their host is a literal loopback IP and their scheme is HTTP(S). Missing
overrides therefore fail locally instead of contacting Steam. Explicit
`WebEndpoint::Test` URLs used by the synthetic `.invalid` proxy/DNS tests remain
separate from these service base URLs; their stands use loopback proxies or a
resolver that refuses DNS.

## SGM fork — E4-FORK-04 (pin-04)

- T-43/C07: changed `LoginError::{TooManyAttempts, SessionExpired}` and
  `userlogin::UpdateAuthSessionError::{TooManyAttempts, SessionExpired}` to carry
  an `EResult`. Both conversions preserve `RateLimitExceeded`,
  `AccountLoginDeniedThrottle`, `Expired`, and `FileNotFound` in curated variants.
  Update callers to tuple patterns such as `TooManyAttempts(code)` or
  `TooManyAttempts(_)`.
- Added `LoginError::eresult(&self) -> Option<EResult>` and
  `UpdateAuthSessionError::eresult(&self) -> Option<EResult>`. These include the
  fixed results for `BadCredentials`, `IncorrectSteamGuardCode`, and
  `DuplicateRequest`, and the payload of `UnknownEResult`; transport and local
  errors return `None`. Use `EResult::code()` for the exact numeric result.
  Display/Debug expose curated variants and typed results, not Steam's raw
  `message` or `extended_error_message`.
- T-43/IDENTITY: added `UserLogin<T>::started_steam_id(&self) -> Option<u64>`
  (`T: Transport + Clone`). SGM can compare the credentials begin-auth subject
  with its known account before code submission or polling. Returns `None`
  before auth starts or for QR auth; does not establish completed authentication.
- No `EResult::Unauthorized` was added: Steam defines no such result. HTTP 401
  remains `TransportError::Unauthorized`.
