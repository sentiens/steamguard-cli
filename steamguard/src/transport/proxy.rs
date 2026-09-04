use std::fmt;

use reqwest::{Proxy, Url};
use secrecy::{ExposeSecret, SecretString};

/// Proxy settings used to construct a [`super::WebApiTransport`].
///
/// HTTP and HTTPS proxy URLs are supported. SOCKS proxy URLs require reqwest's `socks` feature.
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
		let url = Url::parse(url.as_ref()).map_err(|_| ProxyConfigError::InvalidUrl)?;
		if !url.username().is_empty() || url.password().is_some() {
			return Err(ProxyConfigError::CredentialsInUrl);
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
			proxy = proxy.basic_auth(
				credentials.username.expose_secret(),
				credentials.password.expose_secret(),
			);
		}
		Ok(proxy)
	}
}

impl fmt::Debug for ProxyConfig {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("ProxyConfig")
			.field("scheme", &self.url.scheme())
			.field("host", &self.url.host_str())
			.field("port", &self.url.port())
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
			.with_basic_auth("proxy-user-canary", "proxy-password-canary");
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
			STANDARD.encode("proxy-user-canary:proxy-password-canary")
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
