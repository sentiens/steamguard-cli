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
