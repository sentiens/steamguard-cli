# steamguard-cli

[![Lint, Build, Test](https://github.com/dyc3/steamguard-cli/actions/workflows/rust.yml/badge.svg)](https://github.com/dyc3/steamguard-cli/actions/workflows/rust.yml)
[![AUR Tester](https://github.com/dyc3/steamguard-cli/actions/workflows/aur-checker.yml/badge.svg)](https://github.com/dyc3/steamguard-cli/actions/workflows/aur-checker.yml)

A command line utility for setting up and using Steam Mobile Authenticator (AKA Steam 2FA). It can also be used to respond to trade, market, and any other steam mobile confirmations that you would normally get in the app.

**The only legitimate place to download steamguard-cli binaries is through this repo's releases, or by any package manager that is linked in this document.**

# Disclaimer
**This utility is effectively in beta. Use this software at your own risk. Make sure to back up your maFiles regularly, and make sure to actually write down your revocation code. If you lose both of these, we can't help you, your only recourse is to beg Steam support.**

# Quickstart

If you have no idea what the rest of this document is talking about, go read the [quickstart](docs/quickstart.md).

# Features

- Generate 2FA codes
- Respond to trade, market or any other confirmations
- Encrypted storage of your 2FA secrets
  - With the option to store your encryption passkey in the system keyring
- Special memory-clearing data structures to prevent leaking secrets
- QR code generation for importing 2FA secrets into other applications, like KeeWeb
- QR code logins for quickly logging into Steam on a new device, like the Steam Deck
- Able to read Steam Desktop Authenticator's `maFiles` format
- Uses as many official Steam APIs as possible, unlikely to break

# Install

If you have the Rust toolchain installed:
```
cargo install steamguard-cli
```

Arch-based systems can install from the AUR:

- [steamguard-cli](https://aur.archlinux.org/packages/steamguard-cli/) tracks the latest release
- [steamguard-cli-git](https://aur.archlinux.org/packages/steamguard-cli-git/) tracks the latest git commit

Otherwise, you can download binaries from the releases.

## Building From Source

```
cargo build --release
```

# Usage
`steamguard-cli` looks for your `maFiles/manifest.json` in at these paths, in this order:

Linux:
- `~/.config/steamguard-cli/maFiles/`
- `~/maFiles/`

Windows:
- `%APPDATA%\steamguard-cli\maFiles\`
- `%USERPROFILE%\maFiles\`

Your `maFiles` can be created with or imported from [Steam Desktop Authenticator][SDA]. You can create `maFiles` with steamguard-cli using the `setup` action (`steamguard setup`).

**REMEMBER TO MAKE BACKUPS OF YOUR `maFiles`, AND TO WRITE DOWN YOUR RECOVERY CODE!**

[SDA]: https://github.com/Jessecar96/SteamDesktopAuthenticator

Full helptext can be displayed with:
```
steamguard --help
```

## One Liners

Generate and copy a new code to clipboard:
```bash
steamguard | xclip -selection clipboard
```

## Importing 2FA Secret Into Other Applications

It's possible to import your 2FA secret into other applications. This is useful if you want to use a password manager to generate your 2FA codes, like KeeWeb.

To make this easy, steamguard-cli can generate a QR code for your 2FA secret. You can then scan this QR code with your password manager.

```bash
steamguard qr # print QR code for the first account in your maFiles
steamguard -u <account name> qr # print QR code for a specific account
```

There are some applications that do not generate correct 2fa codes from the secret, so **do not use them**:
- Google Authenticator
- Authy

Other applications require a different format. If you use either Bitwarden or KeePassXC, you can generate a compatible QR code using their respective flags:
```bash
steamguard qr --format bitwarden # Bitwarden compatible format
steamguard qr --format keepassxc # KeePassXC compatible format
```

# Contributing

By contributing code to this project, you give me and any future maintainers a non-exclusive transferable license to use that code for this project, including permission to modify, redistribute, and relicense it.

# License

`steamguard-cli`, the command line program is licensed under GPLv3.

`steamguard`, the library that is used by `steamguard-cli` is dual licensed under MIT or Apache 2.0, at your option.

# Used By

* [Unreal Engine to Steam publishing CI/CD pipeline](https://github.com/kasp1/dozer-pipelines), a sample pipeline built for [Dozer](https://github.com/kasp1/Dozer), a simple CI/CD runner

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

E4-FORK-05b: with `test-endpoints`, API, login, and community base URLs must
use HTTP(S), and either the base host or the configured proxy host must be a
literal loopback IP (`IpAddr::is_loopback()`). Thus remote `.invalid` fixture
names can reach a loopback HTTP/HTTPS/socks5h proxy. The proxy IP is captured
from the configuration used by `new_with_proxy` at client construction, retained
by clones, and never read from environment variables or resolved through DNS.
Externally supplied clients have no trusted proxy metadata. The existing factory
policy still rejects `socks5` (local destination DNS). Without a qualifying proxy,
missing overrides and non-loopback bases fail locally with `InvalidRequest` /
`RequestSent::No`; named and non-loopback proxies do not grant an exception. Explicit
`WebEndpoint::Test` URLs used by the synthetic `.invalid` proxy/DNS tests remain
separate from these service base URLs; their stands use loopback proxies or a
resolver that refuses DNS.

## SGM fork — E4-FORK-04

SGM T-43 consumes two typed login APIs at pin-04. `LoginError::eresult()` and
`userlogin::UpdateAuthSessionError::eresult()` return `Option<EResult>` with the
exact Steam result (numeric value via `.code()`). Both errors now retain their
curated `TooManyAttempts(EResult)` and `SessionExpired(EResult)` variants, including
throttle and missing-session aliases. Consumers must update unit-variant matches
to tuple patterns. Transport and local errors return `None`; raw Steam messages
are excluded from these errors' Display/Debug output. This closes T-43/C07.

`UserLogin::started_steam_id(&self) -> Option<u64>` exposes the successful
credentials begin-auth response's subject before code submission or polling,
allowing SGM to compare it against a known account for T-43/IDENTITY. It returns
`None` before begin or for QR auth. This subject is not completed authentication;
consumers must still validate the subjects of the final tokens.

An `EResult::Unauthorized` variant is out of scope: Steam has no such EResult.
HTTP 401 remains `TransportError::Unauthorized`.
