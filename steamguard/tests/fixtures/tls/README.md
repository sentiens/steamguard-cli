This is a public synthetic self-signed certificate and its unencrypted test key.
They are used only by loopback TLS tests, for `127.0.0.1` and
`origin-canary.invalid`, and are never a production trust root or credential.

Generated with OpenSSL using an RSA 2048-bit key, SHA-256, and CA:false.
The validity period is September 5, 2026 through September 2, 2036. The positive
fixture control will fail when the certificate expires; regenerate both DER
files together then. Rejection tests require the typed `UnknownIssuer` cause.
