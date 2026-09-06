use std::{
	error::Error,
	io::{Read, Write},
	net::{SocketAddr, TcpListener, TcpStream},
	process::Command,
	sync::{mpsc, Arc},
	thread,
	time::{Duration, Instant},
};

use super::*;

#[cfg(feature = "test-endpoints")]
mod callers;

pub(super) fn accept(listener: &TcpListener) -> TcpStream {
	listener.set_nonblocking(true).unwrap();
	let deadline = Instant::now() + Duration::from_secs(5);
	loop {
		match listener.accept() {
			Ok((stream, _)) => {
				stream.set_nonblocking(false).unwrap();
				stream
					.set_read_timeout(Some(Duration::from_secs(5)))
					.unwrap();
				stream
					.set_write_timeout(Some(Duration::from_secs(5)))
					.unwrap();
				return stream;
			}
			Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
				thread::sleep(Duration::from_millis(5));
			}
			Err(_) => panic!("loopback accept failed"),
		}
	}
}

pub(super) fn read_headers(stream: &mut impl Read) -> String {
	let mut bytes = Vec::new();
	while !bytes.ends_with(b"\r\n\r\n") {
		assert!(
			bytes.len() < 64 * 1024,
			"test request exceeded header budget"
		);
		let mut byte = [0];
		stream.read_exact(&mut byte).unwrap();
		bytes.push(byte[0]);
	}
	String::from_utf8(bytes).unwrap()
}

// Inspect typed fields without invoking arbitrary source Display or Debug implementations.
pub(super) fn error_facts(error: &(dyn Error + 'static)) -> String {
	let facts = if let Some(error) = error.downcast_ref::<reqwest::Error>() {
		format!(
			"reqwest(builder={}, request={}, connect={}, timeout={}, status={:?}, redirect={}, body={}, decode={})",
			error.is_builder(), error.is_request(), error.is_connect(), error.is_timeout(),
			error.status().map(|status| status.as_u16()), error.is_redirect(), error.is_body(), error.is_decode()
		)
	} else if let Some(error) = error.downcast_ref::<std::io::Error>() {
		format!("io(kind={:?}, os={:?})", error.kind(), error.raw_os_error())
	} else {
		"opaque cause".to_owned()
	};
	let source = error
		.downcast_ref::<std::io::Error>()
		.and_then(|error| error.get_ref().map(|inner| inner as &(dyn Error + 'static)))
		.or_else(|| error.source());
	match source {
		Some(source) => format!("{facts} -> {}", error_facts(source)),
		None => facts,
	}
}

pub(super) fn refused_endpoint() -> ((TcpStream, TcpStream), SocketAddr) {
	// A bound-only socket can silently drop SYNs on some platforms. Hold a connected client
	// endpoint and its peer instead: the target port stays out of ephemeral allocation and
	// never listens. This does not prevent explicit SO_REUSEADDR rebinding on every platform.
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let client =
		TcpStream::connect_timeout(&listener.local_addr().unwrap(), Duration::from_secs(2))
			.unwrap();
	let (peer, _) = listener.accept().unwrap();
	let address = client.local_addr().unwrap();
	((client, peer), address)
}

#[test]
fn held_client_endpoint_refuses_new_connections() {
	let ((mut client, mut peer), address) = refused_endpoint();
	assert!(
		(TcpStream::connect_timeout(&address, Duration::from_secs(2))
			.unwrap_err()
			.kind()) == (std::io::ErrorKind::ConnectionRefused),
		"sensitive assertion failed"
	);
	client
		.set_read_timeout(Some(Duration::from_secs(2)))
		.unwrap();
	peer.set_write_timeout(Some(Duration::from_secs(2)))
		.unwrap();
	peer.write_all(b"held").unwrap();
	let mut bytes = [0; 4];
	client.read_exact(&mut bytes).unwrap();
	assert!((&bytes) == (b"held"), "sensitive assertion failed");
}

#[cfg(feature = "test-endpoints")]
fn read_api_request(stream: &mut TcpStream) -> String {
	let headers = read_headers(stream);
	let length = headers
		.lines()
		.filter_map(|line| line.split_once(':'))
		.find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
		.map_or(0, |(_, value)| value.trim().parse::<usize>().unwrap());
	assert!(length < 64 * 1024, "oversized synthetic request");
	stream.read_exact(&mut vec![0; length]).unwrap();
	headers
}

fn pending_connections(listener: &TcpListener) -> usize {
	listener.set_nonblocking(true).unwrap();
	let mut count = 0;
	loop {
		match listener.accept() {
			Ok(_) => count += 1,
			Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return count,
			Err(_) => panic!("counting loopback attempts failed"),
		}
	}
}

pub(super) fn proxied(listener: &TcpListener) -> WebApiTransport {
	WebApiTransport::new_with_proxy(
		&ProxyConfig::new(format!("http://{}", listener.local_addr().unwrap())).unwrap(),
	)
	.unwrap()
}

pub(super) fn web_get(transport: &WebApiTransport, url: &str) -> Result<WebResponse, NetworkError> {
	transport.send_web(WebRequest::new(
		WebEndpoint::Test(url),
		&[],
		"test",
		"",
		"en",
	))
}

fn in_environment(name: &str, environment: &[(&str, String)]) -> bool {
	if std::env::var("STEAMGUARD_TEST_PROCESS").as_deref() == Ok(name) {
		return false;
	}
	let output = Command::new(std::env::current_exe().unwrap())
		.args([
			"--exact",
			&format!("transport::tests::{name}"),
			"--test-threads=1",
		])
		.env_clear()
		.env("STEAMGUARD_TEST_PROCESS", name)
		.env("TMPDIR", "/private/tmp")
		.envs(environment.iter().map(|(key, value)| (*key, value)))
		.output()
		.unwrap();
	let stdout = String::from_utf8_lossy(&output.stdout);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		!stdout.contains("Operation not permitted") && !stderr.contains("Operation not permitted"),
		"loopback fixture blocked: EPERM"
	);
	assert!(
		output.status.success() && stdout.contains("test result: ok. 1 passed;"),
		"sensitive assertion failed"
	);
	true
}

#[test]
fn assigned_proxy_is_not_bypassed_by_env() {
	let competitor = TcpListener::bind("127.0.0.1:0").unwrap();
	let address = format!("http://{}", competitor.local_addr().unwrap());
	let environment: Vec<_> = [
		"HTTP_PROXY",
		"HTTPS_PROXY",
		"ALL_PROXY",
		"http_proxy",
		"https_proxy",
		"all_proxy",
	]
	.into_iter()
	.map(|name| (name, address.clone()))
	.chain([("NO_PROXY", "*".into()), ("no_proxy", "*".into())])
	.collect();
	if in_environment("assigned_proxy_is_not_bypassed_by_env", &environment) {
		assert_eq!(pending_connections(&competitor), 0);
		return;
	}
	let assigned = TcpListener::bind("127.0.0.1:0").unwrap();
	let origin = TcpListener::bind("127.0.0.1:0").unwrap();
	let transport = proxied(&assigned);
	let server = thread::spawn(move || {
		let mut stream = accept(&assigned);
		let request = read_headers(&mut stream);
		stream
			.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			.unwrap();
		request
	});
	let url = format!("http://{}/route", origin.local_addr().unwrap());
	assert_eq!(web_get(&transport, &url).unwrap().into_body(), "ok");
	assert!(server
		.join()
		.unwrap()
		.starts_with(&format!("GET {url} HTTP/1.1")));
	assert_eq!(pending_connections(&origin), 0);
}

#[test]
fn proxied_client_never_redirects_and_never_retries() {
	let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
	let target = TcpListener::bind("127.0.0.1:0").unwrap();
	let target_url = format!("http://{}/redirected", target.local_addr().unwrap());
	let transport = proxied(&proxy);
	let server = thread::spawn(move || {
		let mut stream = accept(&proxy);
		read_headers(&mut stream);
		write!(stream, "HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
		proxy
	});
	// The raw client returns an unfollowed redirect; approved operations classify its status.
	let response = transport
		.innner_http_client()
		.unwrap()
		.get("http://origin.invalid/start")
		.send()
		.unwrap();
	assert_eq!(response.status(), 302);
	assert_eq!(pending_connections(&server.join().unwrap()), 0);
	assert_eq!(pending_connections(&target), 0);

	let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
	let transport = proxied(&proxy);
	let server = thread::spawn(move || {
		let mut stream = accept(&proxy);
		read_headers(&mut stream);
		drop(stream);
		proxy
	});
	assert_eq!(
		web_get(&transport, "http://origin.invalid/cut")
			.unwrap_err()
			.sent(),
		RequestSent::Maybe
	);
	let proxy = server.join().unwrap();
	assert_eq!(
		1 + pending_connections(&proxy),
		1,
		"automatic retry reached the proxy"
	);
}

#[test]
fn plain_constructor_is_unchanged() {
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let url = format!("http://{}", listener.local_addr().unwrap());
	let server = thread::spawn(move || {
		let mut first = accept(&listener);
		read_headers(&mut first);
		first.write_all(b"HTTP/1.1 302 Found\r\nLocation: /end\r\nSet-Cookie: saved=caller\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
		let mut second = accept(&listener);
		let request = read_headers(&mut second);
		second
			.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			.unwrap();
		request
	});
	let client = reqwest::blocking::Client::builder()
		.no_proxy()
		.cookie_store(true)
		.user_agent("caller-selected-agent")
		.redirect(reqwest::redirect::Policy::limited(1))
		.timeout(Duration::from_secs(2))
		.build()
		.unwrap();
	let transport = WebApiTransport::new(client);
	assert_eq!(
		transport
			.innner_http_client()
			.unwrap()
			.get(url)
			.send()
			.unwrap()
			.text()
			.unwrap(),
		"ok"
	);
	let request = server.join().unwrap().to_ascii_lowercase();
	assert!(request.starts_with("get /end http/1.1"));
	assert!(
		request.contains("cookie: saved=caller"),
		"sensitive assertion failed"
	);
	assert!(request.contains("user-agent: caller-selected-agent"));
}

#[test]
fn redirect_then_connection_failure_does_not_prove_no_send() {
	for raw_conversion in [false, true] {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let url = format!("http://{}/already-sent", listener.local_addr().unwrap());
		let (_reservation, destination) = refused_endpoint();
		let server = thread::spawn(move || {
			let mut stream = accept(&listener);
			let request = read_headers(&mut stream);
			write!(stream, "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{destination}/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
			request
		});
		let client = reqwest::blocking::Client::builder()
			.no_proxy()
			.timeout(Duration::from_secs(2))
			.build()
			.unwrap();
		let error = if raw_conversion {
			NetworkError::from(client.get(&url).send().unwrap_err())
		} else {
			web_get(&WebApiTransport::new(client), &url).unwrap_err()
		};
		assert!(server.join().unwrap().starts_with("GET /already-sent "));
		assert!(
			(error.kind()) == (NetworkErrorKind::Connection),
			"test invariant failed"
		);
		assert!(
			(error.sent()) == (RequestSent::Maybe),
			"sensitive assertion failed"
		);
	}
}

#[test]
fn approved_connection_refusal_preserves_no_send_proof() {
	let (_reservation, address) = refused_endpoint();
	let proxy = ProxyConfig::new(format!("http://{address}")).unwrap();
	let transport = WebApiTransport::new_with_proxy(&proxy).unwrap();
	let error = web_get(&transport, "http://origin.invalid/refused").unwrap_err();
	eprintln!(
		"refusal: kind={:?}, sent={:?}, {}",
		error.kind(),
		error.sent(),
		error_facts(&error)
	);
	assert!(
		(error.kind()) == (NetworkErrorKind::Connection),
		"test invariant failed"
	);
	assert!(
		(error.sent()) == (RequestSent::No),
		"sensitive assertion failed"
	);
	assert!(
		error.source().unwrap().is::<reqwest::Error>(),
		"sensitive assertion failed"
	);
}

fn assert_redirect_builder_is_maybe(raw_conversion: bool) {
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let url = format!("http://{}/already-sent", listener.local_addr().unwrap());
	let server = thread::spawn(move || {
		let mut stream = accept(&listener);
		let request = read_headers(&mut stream);
		stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: ftp://redirect-canary.invalid/file\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
		(request, listener)
	});
	let client = reqwest::blocking::Client::builder()
		.no_proxy()
		.timeout(Duration::from_secs(2))
		.build()
		.unwrap();
	let error = if raw_conversion {
		NetworkError::from(client.get(&url).send().unwrap_err())
	} else {
		web_get(&WebApiTransport::new(client), &url).unwrap_err()
	};
	let (request, listener) = server.join().unwrap();
	assert!(request.starts_with("GET /already-sent HTTP/1.1\r\n"));
	assert_eq!(1 + pending_connections(&listener), 1);
	let source = error
		.source()
		.unwrap()
		.downcast_ref::<reqwest::Error>()
		.unwrap();
	assert!(source.is_builder(), "test invariant failed");
	assert!(source.url().is_none());
	assert!(source.source().is_some());
	assert!(
		(error.kind()) == (NetworkErrorKind::Request),
		"sensitive assertion failed"
	);
	for diagnostic in [
		format!("{error}"),
		format!("{error:#}"),
		format!("{error:?}"),
		format!("{error:#?}"),
	] {
		assert!(!diagnostic.contains("://"), "sensitive assertion failed");
		assert!(
			!diagnostic.contains("redirect-canary"),
			"sensitive assertion failed"
		);
	}
	eprintln!(
		"redirect: raw_conversion={raw_conversion}, received=1, kind={:?}, sent={:?}, {}",
		error.kind(),
		error.sent(),
		error_facts(&error)
	);
	assert!(
		(error.sent()) == (RequestSent::Maybe),
		"sensitive assertion failed"
	);
}

#[test]
fn generic_redirect_to_unsupported_scheme_does_not_prove_no_send() {
	assert_redirect_builder_is_maybe(true);
}

#[test]
fn plain_redirect_to_unsupported_scheme_does_not_prove_no_send() {
	assert_redirect_builder_is_maybe(false);
}

#[test]
fn local_request_construction_preserves_no_send_proof() {
	for approved in [false, true] {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let url = format!("http://{}/not-sent", listener.local_addr().unwrap());
		let transport = if approved {
			proxied(&listener)
		} else {
			WebApiTransport::new(
				reqwest::blocking::Client::builder()
					.no_proxy()
					.build()
					.unwrap(),
			)
		};
		let error = transport
			.send_web(WebRequest::new(
				WebEndpoint::Test(&url),
				&[],
				"invalid\nheader",
				"",
				"en",
			))
			.unwrap_err();
		assert!(
			(error.kind()) == (NetworkErrorKind::Request),
			"sensitive assertion failed"
		);
		assert!(
			(error.sent()) == (RequestSent::No),
			"sensitive assertion failed"
		);
		let source = error
			.source()
			.unwrap()
			.downcast_ref::<reqwest::Error>()
			.unwrap();
		assert!(source.is_builder());
		assert!(source.source().is_some());
		assert!(source.url().is_none());
		let error = web_get(&transport, "invalid URL").unwrap_err();
		assert!(
			(error.kind()) == (NetworkErrorKind::InvalidRequest),
			"sensitive assertion failed"
		);
		assert!(
			(error.sent()) == (RequestSent::No),
			"sensitive assertion failed"
		);
		assert_eq!(pending_connections(&listener), 0);
	}
}

#[test]
fn generic_builder_conversion_does_not_assume_local_provenance() {
	let client = reqwest::blocking::Client::builder()
		.no_proxy()
		.build()
		.unwrap();
	let source = client
		.get("http://origin.invalid/not-sent")
		.header("user-agent", "invalid\nheader")
		.build()
		.unwrap_err();
	assert!(source.is_builder());
	// The recipient of a public conversion cannot know which boundary produced this category.
	let error = NetworkError::from(source);
	assert!(
		(error.kind()) == (NetworkErrorKind::Request),
		"sensitive assertion failed"
	);
	assert!(
		(error.sent()) == (RequestSent::Maybe),
		"sensitive assertion failed"
	);
	assert!(
		error.source().unwrap().is::<reqwest::Error>(),
		"sensitive assertion failed"
	);
}

#[test]
fn unsupported_web_transport_preserves_no_send_proof() {
	struct Unsupported;
	impl Transport for Unsupported {
		fn send_request<
			Req: crate::steamapi::BuildableRequest + protobuf::MessageFull,
			Res: protobuf::MessageFull,
		>(
			&self,
			_: crate::steamapi::ApiRequest<Req>,
		) -> Result<crate::steamapi::ApiResponse<Res>, TransportError> {
			panic!("unsupported web request must not invoke the API transport");
		}
		fn close(&mut self) {}
	}
	let error = Unsupported
		.send_web(WebRequest::new(
			WebEndpoint::Test("http://origin.invalid/not-sent"),
			&[],
			"test",
			"",
			"en",
		))
		.unwrap_err();
	assert!(
		(error.kind()) == (NetworkErrorKind::UnsupportedTransport),
		"sensitive assertion failed"
	);
	assert!(
		(error.sent()) == (RequestSent::No),
		"sensitive assertion failed"
	);
}

#[test]
fn plain_web_no_follow_preserves_redirect_response() {
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let target = TcpListener::bind("127.0.0.1:0").unwrap();
	let url = format!("http://{}", listener.local_addr().unwrap());
	let destination = target.local_addr().unwrap();
	let server = thread::spawn(move || {
		let mut stream = accept(&listener);
		read_headers(&mut stream);
		write!(stream, "HTTP/1.1 302 Found\r\nLocation: http://{destination}/next\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{{\"success\":true}}").unwrap();
	});
	let client = reqwest::blocking::Client::builder()
		.no_proxy()
		.redirect(reqwest::redirect::Policy::none())
		.timeout(Duration::from_secs(2))
		.build()
		.unwrap();
	let response = web_get(&WebApiTransport::new(client), &url).unwrap();
	server.join().unwrap();
	assert_eq!(response.status(), 302);
	assert_eq!(response.into_body(), r#"{"success":true}"#);
	assert_eq!(pending_connections(&target), 0);
}

// Public synthetic self-signed identity; never used outside loopback tests.
const CERT: &[u8] = include_bytes!("../../tests/fixtures/tls/certificate.der");
const KEY: &[u8] = include_bytes!("../../tests/fixtures/tls/private-key.der");

fn tls_server(listener: TcpListener, tunnel: bool) -> thread::JoinHandle<bool> {
	use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
	let config = rustls::ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(
			vec![CertificateDer::from(CERT.to_vec())],
			PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec())),
		)
		.unwrap();
	thread::spawn(move || {
		let mut stream = accept(&listener);
		if tunnel {
			assert!(
				read_headers(&mut stream).starts_with("CONNECT origin-canary.invalid:443 HTTP/1.1"),
				"sensitive assertion failed"
			);
			stream
				.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
				.unwrap();
		}
		let mut connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
		if let Err(error) = connection.complete_io(&mut stream) {
			assert!(
				error.get_ref().is_some_and(|cause| matches!(
					cause.downcast_ref::<rustls::Error>(),
					Some(rustls::Error::AlertReceived(
						rustls::AlertDescription::UnknownCA
					))
				)),
				"test invariant failed"
			);
			return false;
		}
		let mut tls = rustls::StreamOwned::new(connection, stream);
		read_headers(&mut tls);
		tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			.unwrap();
		tls.flush().unwrap();
		true
	})
}

fn has_untrusted_certificate(error: &(dyn Error + 'static)) -> bool {
	if matches!(
		error.downcast_ref::<rustls::Error>(),
		Some(rustls::Error::InvalidCertificate(
			rustls::CertificateError::UnknownIssuer
		))
	) {
		return true;
	}
	if let Some(inner) = error
		.downcast_ref::<std::io::Error>()
		.and_then(std::io::Error::get_ref)
	{
		if has_untrusted_certificate(inner) {
			return true;
		}
	}
	error.source().is_some_and(has_untrusted_certificate)
}

#[test]
fn tls_rejection_is_classified_as_tls_for_origin_and_https_proxy() {
	for tunnel in [true, false] {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let scheme = if tunnel { "http" } else { "https" };
		let proxy =
			ProxyConfig::new(format!("{scheme}://{}", listener.local_addr().unwrap())).unwrap();
		let transport = WebApiTransport::new_with_proxy(&proxy).unwrap();
		let server = tls_server(listener, tunnel);
		let error = web_get(&transport, "https://origin-canary.invalid/mitm").unwrap_err();
		assert!(
			(error.kind()) == (NetworkErrorKind::Tls),
			"test invariant failed"
		);
		assert!(
			(error.sent()) == (RequestSent::No),
			"sensitive assertion failed"
		);
		assert!(
			has_untrusted_certificate(&error),
			"expected typed UnknownIssuer, not a setup failure"
		);
		assert!(!server.join().unwrap());
	}
	// The same fixture succeeds only when explicitly trusted by a caller-supplied test client.
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let url = format!("https://{}", listener.local_addr().unwrap());
	let server = tls_server(listener, false);
	let client = reqwest::blocking::Client::builder()
		.no_proxy()
		.add_root_certificate(reqwest::Certificate::from_der(CERT).unwrap())
		.timeout(Duration::from_secs(2))
		.build()
		.unwrap();
	assert_eq!(
		web_get(&WebApiTransport::new(client), &url)
			.unwrap()
			.into_body(),
		"ok"
	);
	assert!(server.join().unwrap());
}

#[test]
#[ignore = "uses the real 10 second connect and 30 second total timeouts"]
fn silent_proxy_obeys_connect_and_total_timeouts() {
	for (url, seconds) in [
		("https://origin.invalid/", 10),
		("http://origin.invalid/", 30),
	] {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let transport = proxied(&listener);
		let (done, wait) = mpsc::channel();
		let server = thread::spawn(move || {
			let mut stream = accept(&listener);
			read_headers(&mut stream);
			if seconds == 30 {
				stream
					.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nx")
					.unwrap();
			}
			wait.recv_timeout(Duration::from_secs(40)).unwrap();
		});
		let start = Instant::now();
		let error = web_get(&transport, url).unwrap_err();
		let elapsed = start.elapsed();
		done.send(()).unwrap();
		server.join().unwrap();
		assert!(
			(error.kind()) == (NetworkErrorKind::Timeout),
			"sensitive assertion failed"
		);
		assert!(
			elapsed >= Duration::from_secs(seconds - 1)
				&& elapsed < Duration::from_secs(seconds + 5),
			"test invariant failed"
		);
	}
}

#[cfg(feature = "test-endpoints")]
#[test]
fn transport_error_carries_network_failure() {
	if in_environment(
		"transport_error_carries_network_failure",
		&[(
			concat!("STEAMGUARD_", "API_BASE_URL"),
			"http://origin.invalid".into(),
		)],
	) {
		return;
	}
	use crate::steamapi::TwoFactorClient;
	for status in [302, 401, 403, 429, 500, 503] {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let transport = proxied(&listener);
		let (done, wait) = mpsc::channel();
		let server = thread::spawn(move || {
			let mut stream = accept(&listener);
			let request = read_api_request(&mut stream);
			assert!(request.contains("/ITwoFactorService/QueryTime/v1"));
			write!(stream, "HTTP/1.1 {status} Failure\r\nRetry-After: 120\r\nContent-Length: 999999999\r\nConnection: close\r\n\r\n").unwrap();
			// Non-success must be classified without trying to read its unbounded body.
			wait.recv_timeout(Duration::from_secs(3)).unwrap();
		});
		let result = TwoFactorClient::new(transport).query_time();
		done.send(()).unwrap();
		server.join().unwrap();
		match result.unwrap_err() {
			TransportError::NetworkFailure(error) => {
				assert!(
					(error.kind()) == (NetworkErrorKind::HttpStatus),
					"sensitive assertion failed"
				);
				assert!(
					(error.status().unwrap().as_u16()) == (status),
					"sensitive assertion failed"
				);
				assert!(
					(error.retry_after().unwrap()) == ("120"),
					"sensitive assertion failed"
				);
				assert!(
					(error.sent()) == (RequestSent::Yes),
					"sensitive assertion failed"
				);
			}
			_ => panic!("HTTP status was lost outside NetworkFailure"),
		}
	}
}

fn response_fixture(
	headers: &str,
	body: Vec<u8>,
	chunked: bool,
) -> Result<WebResponse, NetworkError> {
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let transport = proxied(&listener);
	let headers = headers.to_owned();
	let server = thread::spawn(move || {
		let mut stream = accept(&listener);
		read_headers(&mut stream);
		write!(
			stream,
			"HTTP/1.1 200 OK\r\n{headers}Connection: close\r\n\r\n"
		)
		.unwrap();
		let result = if chunked {
			write!(stream, "{:x}\r\n", body.len())
				.and_then(|_| stream.write_all(&body))
				.and_then(|_| stream.write_all(b"\r\n0\r\n\r\n"))
		} else {
			stream.write_all(&body)
		};
		if let Err(error) = result {
			assert!(
				matches!(
					error.kind(),
					std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
				),
				"sensitive assertion failed"
			);
		}
	});
	let result = web_get(&transport, "http://origin.invalid/body");
	server.join().unwrap();
	result
}

#[test]
fn response_body_limits_cover_length_chunked_and_eof() {
	const LIMIT: usize = 8 * 1024 * 1024;
	for length in [LIMIT - 1, LIMIT, LIMIT + 1] {
		for framing in ["length", "chunked", "eof"] {
			let headers = match framing {
				"length" => format!("Content-Length: {length}\r\n"),
				"chunked" => "Transfer-Encoding: chunked\r\n".into(),
				_ => String::new(),
			};
			let result = response_fixture(&headers, vec![b'x'; length], framing == "chunked");
			if length <= LIMIT {
				assert_eq!(result.unwrap().into_body().len(), length);
			} else {
				let error = result.unwrap_err();
				assert!(
					(error.kind()) == (NetworkErrorKind::Body),
					"sensitive assertion failed"
				);
				assert!(
					(error.status().unwrap().as_u16()) == (200),
					"sensitive assertion failed"
				);
				assert!(
					(error.sent()) == (RequestSent::Yes),
					"sensitive assertion failed"
				);
			}
		}
	}
	let error = response_fixture("Content-Length: 10\r\n", b"short".to_vec(), false).unwrap_err();
	assert!(
		(error.kind()) == (NetworkErrorKind::Body),
		"sensitive assertion failed"
	);
	assert!(error.source().is_some(), "sensitive assertion failed");
	assert!(
		(response_fixture("Content-Length: 1\r\n", vec![255], false)
			.unwrap_err()
			.kind()) == (NetworkErrorKind::Body),
		"sensitive assertion failed"
	);
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
	let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
	encoder.write_all(bytes).unwrap();
	encoder.finish().unwrap()
}

#[test]
fn gzip_limits_apply_before_and_after_decompression() {
	const LIMIT: usize = 16 * 1024 * 1024;
	for length in [LIMIT - 1, LIMIT, LIMIT + 1] {
		let bytes = gzip(&vec![b'x'; length]);
		assert!(bytes.len() < 8 * 1024 * 1024, "sensitive assertion failed");
		let result = response_fixture(
			"Content-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n",
			bytes,
			true,
		);
		if length <= LIMIT {
			assert_eq!(result.unwrap().into_body().len(), length);
		} else {
			assert!(
				(result.unwrap_err().kind()) == (NetworkErrorKind::Body),
				"sensitive assertion failed"
			);
		}
	}
	// Valid concatenated members must share one decoded budget.
	let mut bytes = gzip(&vec![b'x'; LIMIT]);
	bytes.extend(gzip(b"x"));
	assert!(
		(response_fixture("Content-Encoding: gzip\r\n", bytes, false)
			.unwrap_err()
			.kind()) == (NetworkErrorKind::Body),
		"sensitive assertion failed"
	);
	// An unfinished large gzip body is refused from its raw length before it can be decoded.
	assert!(
		(response_fixture(
			"Content-Encoding: gzip\r\nContent-Length: 8388609\r\n",
			vec![],
			false
		)
		.unwrap_err()
		.kind()) == (NetworkErrorKind::Body),
		"sensitive assertion failed"
	);
	for bytes in [
		b"malformed-gzip-canary".to_vec(),
		gzip(b"canary")[..10].to_vec(),
	] {
		let error = response_fixture("Content-Encoding: gzip\r\n", bytes, false).unwrap_err();
		assert!(
			(error.kind()) == (NetworkErrorKind::Body),
			"sensitive assertion failed"
		);
		assert!(
			!format!("{error} {error:?}").contains("canary"),
			"sensitive assertion failed"
		);
	}
}

#[test]
fn oversized_headers_are_rejected_after_parsing() {
	for length in [64 * 1024 - 64, 64 * 1024] {
		let header = format!("X-Padding: {}\r\nContent-Length: 0\r\n", "x".repeat(length));
		let result = response_fixture(&header, vec![], false);
		if length < 64 * 1024 {
			assert_eq!(result.unwrap().status(), 200);
		} else {
			assert!(
				(result.unwrap_err().kind()) == (NetworkErrorKind::Body),
				"sensitive assertion failed"
			);
		}
	}
}

#[test]
fn proxied_client_does_not_persist_cookies() {
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let transport = proxied(&listener);
	let server = thread::spawn(move || {
		for _ in 0..2 {
			let mut stream = accept(&listener);
			assert!(
				!read_headers(&mut stream)
					.to_ascii_lowercase()
					.contains("saved=canary"),
				"sensitive assertion failed"
			);
			stream.write_all(b"HTTP/1.1 200 OK\r\nSet-Cookie: saved=canary\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
		}
	});
	for _ in 0..2 {
		assert!(
			(web_get(&transport, "http://origin.invalid/cookies")
				.unwrap()
				.status()) == (200),
			"sensitive assertion failed"
		);
	}
	server.join().unwrap();
}

#[cfg(feature = "test-endpoints")]
#[test]
fn api_diagnostics_never_format_upstream_text() {
	if in_environment(
		"api_diagnostics_never_format_upstream_text",
		&[(
			concat!("STEAMGUARD_", "API_BASE_URL"),
			"http://origin-canary.invalid".into(),
		)],
	) {
		return;
	}
	struct Capture;
	static LOGS: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
	impl log::Log for Capture {
		fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
			metadata.target().starts_with("steamguard::")
		}
		fn log(&self, record: &log::Record<'_>) {
			if self.enabled(record.metadata()) {
				LOGS.lock()
					.unwrap()
					.push_str(&format!("{}\n", record.args()));
			}
		}
		fn flush(&self) {}
	}
	log::set_logger(&Capture).unwrap();
	log::set_max_level(log::LevelFilter::Trace);
	for eresult in ["1", "untrusted-result-canary"] {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let transport = proxied(&listener);
		let server = thread::spawn(move || {
			let mut stream = accept(&listener);
			read_api_request(&mut stream);
			write!(stream, "HTTP/1.1 200 OK\r\nx-eresult: {eresult}\r\nx-error_message: arbitrary-message-canary\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
		});
		let response = crate::steamapi::TwoFactorClient::new(transport).query_time();
		server.join().unwrap();
		if eresult == "1" {
			assert!(
				(response.as_ref().unwrap().error_message().unwrap())
					== ("arbitrary-message-canary"),
				"sensitive assertion failed"
			);
		} else {
			assert!(
				matches!(response, Err(TransportError::HeaderParseFailure { .. })),
				"sensitive assertion failed"
			);
		}
		assert!(
			!format!("{response:?}").contains("canary"),
			"sensitive assertion failed"
		);
	}
	let logs = LOGS.lock().unwrap();
	assert!(logs.contains("HTTP Request method:"));
	assert!(!logs.contains("canary"), "sensitive assertion failed");
	assert!(!logs.contains("://"));
}
