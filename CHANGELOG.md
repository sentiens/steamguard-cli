# Changelog

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
