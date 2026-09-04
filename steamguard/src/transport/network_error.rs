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
}

/// An HTTP transport failure with a stable category and its original source.
pub struct NetworkError {
	kind: NetworkErrorKind,
	status: Option<StatusCode>,
	retry_after: Option<HeaderValue>,
	source: Option<reqwest::Error>,
}

impl NetworkError {
	fn new(source: reqwest::Error, retry_after: Option<HeaderValue>) -> Self {
		let kind = classify(&source);
		let status = source.status();
		Self {
			kind,
			status,
			retry_after,
			source: Some(source.without_url()),
		}
	}

	pub(crate) fn ensure_success(response: Response) -> Result<Response, Self> {
		let retry_after = response.headers().get(RETRY_AFTER).cloned();
		match response.error_for_status_ref() {
			Ok(_) => Ok(response),
			Err(error) => Err(Self::new(error, retry_after)),
		}
	}

	pub fn kind(&self) -> NetworkErrorKind {
		self.kind
	}

	pub fn status(&self) -> Option<StatusCode> {
		self.status
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
			.field("retry_after", &self.retry_after)
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
		}
	}
}

impl Error for NetworkError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		self.source
			.as_ref()
			.map(|source| source as &(dyn Error + 'static))
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

	#[test]
	fn classifies_connection_failures() {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		drop(listener);

		let error = test_client()
			.get(format!("http://{address}"))
			.send()
			.unwrap_err();
		let error = NetworkError::from(error);

		assert_eq!(error.kind(), NetworkErrorKind::Connection);
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
