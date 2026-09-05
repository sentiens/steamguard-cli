use std::{error::Error, fmt};

use reqwest::{
	blocking::Response,
	header::{HeaderValue, RETRY_AFTER},
	StatusCode,
};

/// A stable classification for failures in the HTTP transport.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkErrorKind {
	Timeout,
	Connection,
	Tls,
	HttpStatus,
	Redirect,
	Body,
	Request,
	InvalidRequest,
	UnsupportedTransport,
}

/// Whether the origin could have received the request. This never asserts side-effect success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestSent {
	No,
	Maybe,
	Yes,
}

/// An HTTP transport failure with a stable category and its original source, when available.
///
/// Use the source chain only for typed inspection. Its arbitrary messages must not be logged
/// or presented to users; this type's own `Display` and `Debug` expose safe diagnostics.
pub struct NetworkError {
	kind: NetworkErrorKind,
	status: Option<StatusCode>,
	retry_after: Option<HeaderValue>,
	sent: RequestSent,
	source: Option<Box<dyn Error + Send + Sync>>,
}

impl NetworkError {
	fn new(source: reqwest::Error, retry_after: Option<HeaderValue>) -> Self {
		let kind = classify(&source);
		let status = source.status();
		// Neither builder nor connection errors prove no send: a generic client can return
		// either after a redirect. Only response evidence gives certainty here.
		let sent = if status.is_some() || source.is_decode() || source.is_redirect() {
			RequestSent::Yes
		} else {
			RequestSent::Maybe
		};
		Self {
			kind,
			status,
			retry_after,
			sent,
			source: Some(Box::new(source.without_url())),
		}
	}

	pub(crate) fn from_request_build(source: reqwest::Error) -> Self {
		// The library's RequestBuilder::build_split failed before Client::execute was called.
		let mut error = Self::from(source);
		error.sent = RequestSent::No;
		error
	}

	pub(crate) fn from_approved_send(source: reqwest::Error) -> Self {
		// Redirects and reqwest retries are disabled on the approved route. Its connection
		// failures precede the origin request; generic clients do not provide this proof.
		let before_request = source.is_connect();
		let mut error = Self::from(source);
		if before_request {
			error.sent = RequestSent::No;
		}
		error
	}

	pub(crate) fn http_status(response: &Response) -> Self {
		Self {
			kind: NetworkErrorKind::HttpStatus,
			status: Some(response.status()),
			retry_after: response.headers().get(RETRY_AFTER).cloned(),
			sent: RequestSent::Yes,
			source: response
				.error_for_status_ref()
				.err()
				.map(|e| Box::new(e.without_url()) as _),
		}
	}

	pub(crate) fn response_body(status: StatusCode, source: Option<std::io::Error>) -> Self {
		let timeout = source.as_ref().is_some_and(|e| {
			e.kind() == std::io::ErrorKind::TimedOut
				|| e.get_ref()
					.and_then(|e| e.downcast_ref::<reqwest::Error>())
					.is_some_and(reqwest::Error::is_timeout)
		});
		Self {
			kind: if timeout {
				NetworkErrorKind::Timeout
			} else {
				NetworkErrorKind::Body
			},
			status: Some(status),
			retry_after: None,
			sent: RequestSent::Yes,
			source: source.map(|e| Box::new(e) as _),
		}
	}

	pub(crate) fn ensure_success(response: Response) -> Result<Response, Self> {
		let retry_after = response.headers().get(RETRY_AFTER).cloned();
		match response.error_for_status_ref() {
			Ok(_) => Ok(response),
			Err(error) => Err(Self::new(error, retry_after)),
		}
	}

	pub(crate) fn invalid_request() -> Self {
		Self {
			kind: NetworkErrorKind::InvalidRequest,
			status: None,
			retry_after: None,
			sent: RequestSent::No,
			source: None,
		}
	}

	pub(crate) fn unsupported_transport() -> Self {
		Self {
			kind: NetworkErrorKind::UnsupportedTransport,
			status: None,
			retry_after: None,
			sent: RequestSent::No,
			source: None,
		}
	}

	pub fn kind(&self) -> NetworkErrorKind {
		self.kind
	}

	pub fn status(&self) -> Option<StatusCode> {
		self.status
	}

	pub fn sent(&self) -> RequestSent {
		self.sent
	}

	/// Returns the unparsed `Retry-After` header supplied with an HTTP error response.
	pub fn retry_after(&self) -> Option<&HeaderValue> {
		self.retry_after.as_ref()
	}
}

impl From<reqwest::Error> for NetworkError {
	fn from(source: reqwest::Error) -> Self {
		Self::new(source, None)
	}
}

impl fmt::Debug for NetworkError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("NetworkError")
			.field("kind", &self.kind)
			.field("status", &self.status)
			.field("sent", &self.sent)
			.field(
				"retry_after",
				&self.retry_after.as_ref().map(|_| "[REDACTED]"),
			)
			.finish_non_exhaustive()
	}
}

impl fmt::Display for NetworkError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match (self.kind, self.status) {
			(NetworkErrorKind::Timeout, _) => f.write_str("network request timed out"),
			(NetworkErrorKind::Connection, _) => f.write_str("connection failed"),
			(NetworkErrorKind::Tls, _) => f.write_str("TLS negotiation failed"),
			(NetworkErrorKind::HttpStatus, Some(status)) => {
				write!(f, "server returned HTTP status {status}")
			}
			(NetworkErrorKind::HttpStatus, None) => {
				f.write_str("server returned an HTTP error status")
			}
			(NetworkErrorKind::Redirect, _) => f.write_str("redirect was rejected"),
			(NetworkErrorKind::Body, _) => f.write_str("response body could not be read"),
			(NetworkErrorKind::Request, _) => f.write_str("network request failed"),
			(NetworkErrorKind::InvalidRequest, _) => f.write_str("network request was invalid"),
			(NetworkErrorKind::UnsupportedTransport, _) => {
				f.write_str("transport does not support community web requests")
			}
		}
	}
}

impl Error for NetworkError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		self.source
			.as_ref()
			.map(|source| source.as_ref() as &(dyn Error + 'static))
	}
}

fn classify(error: &reqwest::Error) -> NetworkErrorKind {
	if error.is_timeout() {
		NetworkErrorKind::Timeout
	} else if error_chain_contains::<rustls::Error>(error) {
		NetworkErrorKind::Tls
	} else if error.is_status() {
		NetworkErrorKind::HttpStatus
	} else if error.is_connect() {
		NetworkErrorKind::Connection
	} else if error.is_redirect() {
		NetworkErrorKind::Redirect
	} else if error.is_body() || error.is_decode() {
		NetworkErrorKind::Body
	} else {
		NetworkErrorKind::Request
	}
}

fn error_chain_contains<T>(error: &(dyn Error + 'static)) -> bool
where
	T: Error + 'static,
{
	if error.is::<T>() {
		return true;
	}
	if let Some(io_error) = error.downcast_ref::<std::io::Error>() {
		if let Some(inner) = io_error.get_ref() {
			if error_chain_contains::<T>(inner) {
				return true;
			}
		}
	}
	error
		.source()
		.is_some_and(|source| error_chain_contains::<T>(source))
}

#[cfg(test)]
mod tests {
	use std::{
		error::Error,
		io::{Read, Write},
		net::TcpListener,
		thread,
		time::Duration,
	};

	use super::*;
	use crate::transport::TransportError;

	#[test]
	fn classifies_connection_failures() {
		let (_reservation, address) = super::super::tests::refused_endpoint();

		let error = test_client()
			.get(format!("http://{address}"))
			.send()
			.unwrap_err();
		let error = NetworkError::from(error);

		assert_eq!(
			error.kind(),
			NetworkErrorKind::Connection,
			"{}",
			super::super::tests::error_facts(&error)
		);
		assert_eq!(error.sent(), RequestSent::Maybe);
		assert!(error.source().is_some());
	}

	#[test]
	fn classifies_timeouts() {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		let server = thread::spawn(move || {
			let (mut stream, _) = listener.accept().unwrap();
			let mut request = [0; 1024];
			let _ = stream.read(&mut request).unwrap();
			thread::sleep(Duration::from_millis(100));
		});
		let client = reqwest::blocking::Client::builder()
			.no_proxy()
			.timeout(Duration::from_millis(20))
			.build()
			.unwrap();

		let error = client.get(format!("http://{address}")).send().unwrap_err();
		let error = NetworkError::from(error);

		assert_eq!(error.kind(), NetworkErrorKind::Timeout);
		assert_eq!(error.sent(), RequestSent::Maybe);
		server.join().unwrap();
	}

	#[test]
	fn classifies_tls_failures() {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		let server = thread::spawn(move || {
			let (mut stream, _) = listener.accept().unwrap();
			let mut request = [0; 1024];
			let _ = stream.read(&mut request).unwrap();
			stream.write_all(b"not a TLS record").unwrap();
		});

		let error = test_client()
			.get(format!("https://{address}"))
			.send()
			.unwrap_err();
		let error = NetworkError::from(error);

		assert_eq!(error.kind(), NetworkErrorKind::Tls);
		server.join().unwrap();
	}

	#[test]
	fn error_display_never_formats_arbitrary_sources() {
		struct Untrusted;
		impl fmt::Debug for Untrusted {
			fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
				panic!("untrusted Debug invoked")
			}
		}
		impl fmt::Display for Untrusted {
			fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
				panic!("untrusted Display invoked")
			}
		}
		impl Error for Untrusted {}
		for kind in [
			NetworkErrorKind::Timeout,
			NetworkErrorKind::Connection,
			NetworkErrorKind::Tls,
			NetworkErrorKind::HttpStatus,
			NetworkErrorKind::Redirect,
			NetworkErrorKind::Body,
			NetworkErrorKind::Request,
			NetworkErrorKind::InvalidRequest,
			NetworkErrorKind::UnsupportedTransport,
		] {
			let error = NetworkError {
				kind,
				status: Some(StatusCode::BAD_GATEWAY),
				retry_after: Some(HeaderValue::from_static(
					"https://proxy-user:proxy-password@source-canary.invalid",
				)),
				sent: RequestSent::Maybe,
				source: Some(Box::new(std::io::Error::other(Untrusted))),
			};
			assert!(error_chain_contains::<Untrusted>(&error));
			let diagnostic = format!("{error} {error:?}");
			let diagnostic = format!("{diagnostic} {:?}", TransportError::NetworkFailure(error));
			for canary in ["://", "proxy-user", "proxy-password", "source-canary"] {
				assert!(!diagnostic.contains(canary));
			}
		}
		for error in [
			TransportError::Unknown(anyhow::Error::new(Untrusted)),
			TransportError::HeaderParseFailure {
				header: "header-canary".into(),
				source: anyhow::Error::new(Untrusted),
			},
		] {
			assert!(!format!("{error} {error:?}").contains("header-canary"));
		}
		let tls = std::io::Error::other(rustls::Error::InvalidCertificate(
			rustls::CertificateError::UnknownIssuer,
		));
		assert!(error_chain_contains::<rustls::Error>(&tls));
		assert_eq!(NetworkError::invalid_request().sent(), RequestSent::No);
		assert_eq!(
			NetworkError::unsupported_transport().sent(),
			RequestSent::No
		);
	}

	#[test]
	fn error_display_never_contains_response_body_or_retry_after_data() {
		for retry in [
			b"120".as_slice(),
			b"Wed, 21 Oct 2037 07:28:00 GMT",
			b"https://proxy-user:proxy-password@source-canary.invalid",
			b"\xffraw-canary",
		] {
			let listener = TcpListener::bind("127.0.0.1:0").unwrap();
			let address = listener.local_addr().unwrap();
			let retry = retry.to_vec();
			let sent_retry = retry.clone();
			let server = thread::spawn(move || {
				let mut stream = super::super::tests::accept(&listener);
				super::super::tests::read_headers(&mut stream);
				stream
					.write_all(b"HTTP/1.1 429 Failure\r\nRetry-After: ")
					.unwrap();
				stream.write_all(&sent_retry).unwrap();
				stream.write_all(b"\r\nContent-Length: 31\r\nConnection: close\r\n\r\n<html>secret-body-canary</html>").unwrap();
			});
			let response = test_client()
				.get(format!("http://{address}/url-canary"))
				.send()
				.unwrap();
			let error = NetworkError::ensure_success(response).unwrap_err();
			assert_eq!(error.retry_after().unwrap().as_bytes(), retry);
			let diagnostic = format!("{error} {error:?}");
			for canary in [
				"://",
				"url-canary",
				"proxy-user",
				"proxy-password",
				"source-canary",
				"secret-body-canary",
				"raw-canary",
			] {
				assert!(
					!diagnostic.contains(canary),
					"diagnostic leaked untrusted data"
				);
			}
			server.join().unwrap();
		}
	}

	#[test]
	fn http_status_carries_status_and_retry_after() {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		let server = thread::spawn(move || {
			let (mut stream, _) = listener.accept().unwrap();
			let mut request = [0; 1024];
			let _ = stream.read(&mut request).unwrap();
			stream
				.write_all(
					b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nContent-Length: 0\r\n\r\n",
				)
				.unwrap();
		});

		let response = test_client()
			.get(format!(
				"http://{address}/?access_token=query-secret-canary"
			))
			.send()
			.unwrap();
		let error = NetworkError::ensure_success(response).unwrap_err();

		assert_eq!(error.kind(), NetworkErrorKind::HttpStatus);
		assert_eq!(error.sent(), RequestSent::Yes);
		assert_eq!(error.status(), Some(StatusCode::TOO_MANY_REQUESTS));
		assert_eq!(error.retry_after().unwrap(), "120");
		assert!(error.source().is_some());
		let output = format!("{error:?} {error}");
		assert!(!output.contains("query-secret-canary"));
		let source_output = error.source().unwrap().to_string();
		assert!(!source_output.contains("query-secret-canary"));
		server.join().unwrap();
	}

	fn test_client() -> reqwest::blocking::Client {
		reqwest::blocking::Client::builder()
			.no_proxy()
			.build()
			.unwrap()
	}
}
