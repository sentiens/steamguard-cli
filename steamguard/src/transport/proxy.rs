use std::fmt;

use reqwest::{Proxy, Url};
use secrecy::{ExposeSecret, SecretString};

/// Proxy settings used to construct a [`super::WebApiTransport`].
///
/// HTTP, HTTPS, and `socks5h` proxy URLs are supported. Destination names are resolved by
/// the proxy, including when using SOCKS.
#[derive(Clone)]
pub struct ProxyConfig {
	url: Url,
	credentials: Option<ProxyCredentials>,
}

#[derive(Clone)]
struct ProxyCredentials {
	username: SecretString,
	password: SecretString,
}

impl ProxyConfig {
	/// Parses a proxy URL without authentication.
	///
	/// Credentials in the URL are rejected so they cannot be copied into diagnostics produced by
	/// the HTTP stack. Use [`ProxyConfig::with_basic_auth`] to add them separately.
	pub fn new(url: impl AsRef<str>) -> Result<Self, ProxyConfigError> {
		let input = url.as_ref();
		if input
			.chars()
			.any(|c| c.is_ascii_whitespace() || c.is_ascii_control() || c == '\\')
		{
			return Err(ProxyConfigError::InvalidUrl);
		}
		let url = Url::parse(input).map_err(|_| ProxyConfigError::InvalidUrl)?;
		let authority = input
			.split_once("://")
			.ok_or(ProxyConfigError::InvalidUrl)?
			.1
			.split(['/', '?', '#'])
			.next()
			.unwrap_or_default();
		// URL normalization removes empty userinfo, so also inspect the original authority.
		if authority.contains('@') || !url.username().is_empty() || url.password().is_some() {
			return Err(ProxyConfigError::CredentialsInUrl);
		}
		if !matches!(url.scheme(), "http" | "https" | "socks5h")
			|| url.host_str().is_none_or(str::is_empty)
			|| authority.is_empty()
			|| url.port() == Some(0)
			|| !matches!(url.path(), "" | "/")
			|| url.query().is_some()
			|| url.fragment().is_some()
		{
			return Err(ProxyConfigError::InvalidUrl);
		}

		Ok(Self {
			url,
			credentials: None,
		})
	}

	/// Adds HTTP Basic authentication to the proxy configuration.
	pub fn with_basic_auth(
		mut self,
		username: impl Into<String>,
		password: impl Into<String>,
	) -> Self {
		self.credentials = Some(ProxyCredentials {
			username: SecretString::new(username.into()),
			password: SecretString::new(password.into()),
		});
		self
	}

	pub(crate) fn to_reqwest_proxy(&self) -> Result<Proxy, ProxyTransportError> {
		let mut proxy =
			Proxy::all(self.url.clone()).map_err(|_| ProxyTransportError::InvalidProxy)?;
		if let Some(credentials) = &self.credentials {
			// reqwest stores auth in a URL whose setters preserve percent escapes; its connector
			// then decodes them. Escape literal percent signs so separate auth round-trips exactly.
			let username =
				zeroize::Zeroizing::new(credentials.username.expose_secret().replace('%', "%25"));
			let password =
				zeroize::Zeroizing::new(credentials.password.expose_secret().replace('%', "%25"));
			proxy = proxy.basic_auth(&username, &password);
		}
		Ok(proxy)
	}
}

impl fmt::Debug for ProxyConfig {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("ProxyConfig")
			.field("scheme", &self.url.scheme())
			.field("address", &"[REDACTED]")
			.field(
				"credentials",
				&self.credentials.as_ref().map(|_| "[REDACTED]"),
			)
			.finish_non_exhaustive()
	}
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyConfigError {
	#[error("invalid proxy URL")]
	InvalidUrl,
	#[error("proxy credentials must be supplied separately")]
	CredentialsInUrl,
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyTransportError {
	#[error("invalid or unsupported proxy configuration")]
	InvalidProxy,
	#[error("failed to build the HTTP client")]
	ClientBuild,
}

#[cfg(test)]
mod tests {
	use std::{
		io::{BufRead, BufReader, Write},
		net::TcpListener,
		thread,
	};

	use super::*;
	use crate::transport::{Transport, WebApiTransport};
	use base64::{engine::general_purpose::STANDARD, Engine};

	#[test]
	fn proxy_config_rejects_credentials_in_url() {
		for url in [
			"http://user@localhost:8080",
			"https://:password@localhost:8080",
			"socks5h://user:password@localhost:1080",
			"http://@localhost:8080",
			"http://%75ser:p%40ss@localhost:8080",
		] {
			assert!(matches!(
				ProxyConfig::new(url),
				Err(ProxyConfigError::CredentialsInUrl)
			));
		}
		assert!(ProxyConfig::new("http://localhost:8080")
			.unwrap()
			.with_basic_auth("user", "p:a%40ss")
			.to_reqwest_proxy()
			.is_ok());
	}

	#[test]
	fn proxy_config_accepts_only_supported_routes() {
		for url in [
			"http://localhost",
			"https://[::1]:8443",
			"socks5h://localhost:1080",
		] {
			assert!(ProxyConfig::new(url).is_ok());
		}
		for url in [
			"socks5://localhost:1080",
			"socks4://localhost:1080",
			"socks4a://localhost:1080",
			"ftp://localhost",
			"file:///tmp/proxy",
			"mailto:proxy@example.invalid",
			"http://",
			"http://localhost:0",
			"http://localhost:65536",
			"socks5h:///",
			"http://localhost/path",
			"http://localhost?query",
			"http://localhost#fragment",
			" http://localhost",
			"http://local\nhost",
			"http:\\localhost",
		] {
			assert!(
				matches!(ProxyConfig::new(url), Err(ProxyConfigError::InvalidUrl)),
				"accepted {url:?}"
			);
		}
	}

	#[test]
	fn proxy_debug_has_no_address_or_credentials() {
		let config = ProxyConfig::new("http://proxy-address-canary.invalid:43827")
			.unwrap()
			.with_basic_auth("proxy-user-canary", "proxy-password-canary");
		let debug = format!("{config:?} {config:#?}");
		for value in [
			"proxy-address-canary",
			"43827",
			"proxy-user-canary",
			"proxy-password-canary",
		] {
			assert!(!debug.contains(value));
		}
		assert!(debug.contains("[REDACTED]"));
	}

	#[test]
	fn proxy_config_debug_redacts_credentials() {
		let config = ProxyConfig::new("http://proxy.example:8080")
			.unwrap()
			.with_basic_auth("proxy-user-canary", "proxy-password-canary");
		let output = format!("{config:?}");

		assert!(!output.contains("proxy-user-canary"));
		assert!(!output.contains("proxy-password-canary"));
		assert!(output.contains("[REDACTED]"));
	}

	#[test]
	fn proxy_errors_do_not_repeat_the_input() {
		let input = "proxy-password-canary is not a URL";
		let error = ProxyConfig::new(input).unwrap_err();
		let output = format!("{error:?} {error}");

		assert!(!output.contains(input));
	}

	#[test]
	fn configured_proxy_handles_http_and_https_requests() {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let proxy_address = listener.local_addr().unwrap();
		let server = thread::spawn(move || {
			let mut requests = Vec::new();
			for stream in listener.incoming().take(2) {
				let mut stream = stream.unwrap();
				let mut request = String::new();
				{
					let mut reader = BufReader::new(&mut stream);
					loop {
						let mut line = String::new();
						let bytes_read = reader.read_line(&mut line).unwrap();
						assert_ne!(bytes_read, 0, "proxy request ended before its headers");
						request.push_str(&line);
						if line == "\r\n" {
							break;
						}
					}
				}
				requests.push(request);
				stream
					.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
					.unwrap();
			}
			requests
		});

		let proxy = ProxyConfig::new(format!("http://{proxy_address}"))
			.unwrap()
			.with_basic_auth("proxy-user-%40-canary", "proxy:password-%40-canary");
		let transport = WebApiTransport::new_with_proxy(&proxy).unwrap();
		let client = transport.innner_http_client().unwrap();

		let _ = client.get("http://example.invalid/proxy-check").send();
		let _ = client.get("https://example.invalid/proxy-check").send();

		let requests = server.join().unwrap();
		assert!(requests
			.iter()
			.any(|request| request.starts_with("GET http://example.invalid/proxy-check HTTP/1.1")));
		assert!(requests
			.iter()
			.any(|request| request.starts_with("CONNECT example.invalid:443 HTTP/1.1")));
		let expected_auth = format!(
			"Proxy-Authorization: Basic {}",
			STANDARD.encode("proxy-user-%40-canary:proxy:password-%40-canary")
		);
		assert!(requests.iter().all(|request| request
			.lines()
			.any(|line| line.eq_ignore_ascii_case(&expected_auth))));
	}

	#[test]
	fn transport_debug_redacts_proxy_credentials() {
		let proxy = ProxyConfig::new("http://127.0.0.1:1")
			.unwrap()
			.with_basic_auth("proxy-user-canary", "proxy-password-canary");
		let transport = WebApiTransport::new_with_proxy(&proxy).unwrap();
		let output = format!("{transport:?}");

		assert!(!output.contains("proxy-user-canary"));
		assert!(!output.contains("proxy-password-canary"));
		assert!(output.contains("[REDACTED]"));
	}

	#[test]
	fn request_errors_redact_proxy_credentials() {
		let proxy = ProxyConfig::new("http://127.0.0.1:1")
			.unwrap()
			.with_basic_auth("proxy-user-canary", "proxy-password-canary");
		let transport = WebApiTransport::new_with_proxy(&proxy).unwrap();
		let error = transport
			.innner_http_client()
			.unwrap()
			.get("http://example.invalid/proxy-check")
			.send()
			.unwrap_err();
		let output = format!("{error:?} {error}");

		assert!(!output.contains("proxy-user-canary"));
		assert!(!output.contains("proxy-password-canary"));
	}
}
