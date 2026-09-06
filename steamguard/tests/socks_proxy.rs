#![cfg(feature = "test-endpoints")]

// Consumer-facing coverage deliberately imports only fork-owned types.
use std::{
	io::{Read, Write},
	net::{TcpListener, TcpStream},
	thread,
	time::{Duration, Instant},
};
use steamguard::test_support::{
	NetworkError, NetworkErrorKind, ProxyConfig, RecordingResolver, RequestSent, Transport,
	WebApiTransport, WebEndpoint, WebRequest,
};

const TARGET: &str = "origin-host-canary.invalid";
const USERNAME: &str = "proxy-user-%40-canary";
const PASSWORD: &str = "proxy:password-%40-canary";

// Same bounded, blocking-on-accept pattern as the T-09 SOCKS stand. It never
// resolves or opens an origin connection; only the local proxy socket is used.
fn accept(listener: TcpListener) -> TcpStream {
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

fn read_string(stream: &mut TcpStream) -> Vec<u8> {
	let mut length = [0];
	stream.read_exact(&mut length).unwrap();
	let mut value = vec![0; usize::from(length[0])];
	stream.read_exact(&mut value).unwrap();
	value
}

fn negotiate(stream: &mut TcpStream, method: u8) {
	let mut version = [0];
	stream.read_exact(&mut version).unwrap();
	assert_eq!(version, [5]);
	let _methods = read_string(stream);
	stream.write_all(&[5, method]).unwrap();
}

fn refuse_connect(stream: &mut TcpStream, reply: u8) {
	let mut connect = [0; 4];
	stream.read_exact(&mut connect).unwrap();
	assert_eq!(connect, [5, 1, 0, 3]);
	assert!(
		read_string(stream) == TARGET.as_bytes(),
		"destination hostname changed"
	);
	let mut port = [0; 2];
	stream.read_exact(&mut port).unwrap();
	assert!([80, 443].contains(&u16::from_be_bytes(port)));
	stream
		.write_all(&[5, reply, 0, 1, 127, 0, 0, 1, 0, 0])
		.unwrap();
}

fn request(transport: &WebApiTransport, scheme: &str) -> NetworkError {
	transport
		.send_web(WebRequest::new(
			WebEndpoint::Test(&format!("{scheme}://{TARGET}/probe")),
			&[],
			"test",
			"",
			"en",
		))
		.unwrap_err()
}

fn assert_proxy_connect(error: &NetworkError) {
	assert!(
		error.kind() == NetworkErrorKind::ProxyConnect,
		"wrong proxy failure classification"
	);
	assert!(
		error.sent() == RequestSent::No,
		"proxy handshake must precede origin request"
	);
	assert!(
		error.status().is_none(),
		"proxy reply is not an origin HTTP status"
	);
}

// T-41/C05 fallback: hyper-util 0.1.20 hides the typed auth variants. This test
// intentionally asserts ProxyConnect, not the unavailable ProxyAuth distinction.
#[test]
fn socks_auth_refusal_uses_typed_fallback_sent_no() {
	for method in [2, 0xff] {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let proxy = ProxyConfig::new(format!("socks5h://{}", listener.local_addr().unwrap()))
			.unwrap()
			.with_basic_auth(USERNAME, PASSWORD);
		let server = thread::spawn(move || {
			let mut stream = accept(listener);
			negotiate(&mut stream, method);
			if method == 2 {
				let mut version = [0];
				stream.read_exact(&mut version).unwrap();
				assert_eq!(version, [1]);
				assert!(
					read_string(&mut stream) == USERNAME.as_bytes(),
					"username did not round-trip"
				);
				assert!(
					read_string(&mut stream) == PASSWORD.as_bytes(),
					"password did not round-trip"
				);
				stream.write_all(&[1, 1]).unwrap();
			}
		});
		let transport = WebApiTransport::new_with_proxy(&proxy).unwrap();
		let error = request(&transport, "https");
		server.join().unwrap();
		assert_proxy_connect(&error);
	}
}

#[test]
fn socks_connect_refusal_is_proxy_connect_sent_no() {
	for reply in [1, 2, 4, 5] {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let proxy =
			ProxyConfig::new(format!("socks5h://{}", listener.local_addr().unwrap())).unwrap();
		let server = thread::spawn(move || {
			let mut stream = accept(listener);
			negotiate(&mut stream, 0);
			refuse_connect(&mut stream, reply);
		});
		let error = request(&WebApiTransport::new_with_proxy(&proxy).unwrap(), "https");
		server.join().unwrap();
		assert_proxy_connect(&error);
	}
}

fn http_sink(listener: TcpListener, scheme: &'static str, status: u16) -> thread::JoinHandle<()> {
	thread::spawn(move || {
		let mut stream = accept(listener);
		let mut headers = Vec::new();
		while !headers.ends_with(b"\r\n\r\n") {
			assert!(headers.len() < 65536, "headers exceeded budget");
			let mut byte = [0];
			stream.read_exact(&mut byte).unwrap();
			headers.push(byte[0]);
		}
		let expected = if scheme == "https" {
			format!("CONNECT {TARGET}:443 HTTP/1.1\r\n")
		} else {
			format!("GET http://{TARGET}/probe HTTP/1.1\r\n")
		};
		assert!(
			headers.starts_with(expected.as_bytes()),
			"proxy did not receive destination hostname"
		);
		write!(
			stream,
			"HTTP/1.1 {status} Refused\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
		)
		.unwrap();
	})
}

#[test]
fn http_connect_403_is_proxy_connect() {
	for status in [403, 407, 502] {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let proxy = ProxyConfig::new(format!("http://{}", listener.local_addr().unwrap())).unwrap();
		let server = http_sink(listener, "https", status);
		let error = request(&WebApiTransport::new_with_proxy(&proxy).unwrap(), "https");
		server.join().unwrap();
		assert_proxy_connect(&error);
	}
}

#[test]
fn socks5h_hostname_goes_to_proxy_not_resolver() {
	for scheme in ["http", "https"] {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let proxy =
			ProxyConfig::new(format!("socks5h://{}", listener.local_addr().unwrap())).unwrap();
		let recorder = RecordingResolver::new();
		let transport =
			WebApiTransport::new_with_proxy_and_recording_resolver(&proxy, &recorder).unwrap();
		let server = thread::spawn(move || {
			let mut stream = accept(listener);
			negotiate(&mut stream, 0);
			refuse_connect(&mut stream, 2);
		});
		let error = request(&transport, scheme);
		server.join().unwrap();
		assert_proxy_connect(&error);
		assert!(recorder.names().is_empty());
	}
}

#[test]
fn http_proxy_also_resolves_destination_remotely() {
	for scheme in ["http", "https"] {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let proxy = ProxyConfig::new(format!("http://{}", listener.local_addr().unwrap())).unwrap();
		let recorder = RecordingResolver::new();
		let transport =
			WebApiTransport::new_with_proxy_and_recording_resolver(&proxy, &recorder).unwrap();
		let server = http_sink(listener, scheme, 403);
		let error = request(&transport, scheme);
		server.join().unwrap();
		if scheme == "https" {
			assert_proxy_connect(&error);
		} else {
			assert!(
				error.kind() == NetworkErrorKind::HttpStatus,
				"forward proxy HTTP status must stay HTTP status"
			);
			assert!(
				error.sent() == RequestSent::Yes,
				"HTTP forwarding cannot prove no origin send"
			);
		}
		assert!(recorder.names().is_empty());
	}
}

#[test]
fn named_proxies_are_recorded_and_resolution_always_fails() {
	let recorder = RecordingResolver::new();
	let handle = recorder.clone();
	for scheme in ["http", "https", "socks5h"] {
		let proxy = ProxyConfig::new(format!("{scheme}://proxy-host-canary.invalid:1080")).unwrap();
		let transport =
			WebApiTransport::new_with_proxy_and_recording_resolver(&proxy, &recorder).unwrap();
		assert_proxy_connect(&request(&transport, "https"));
	}
	assert!(
		handle.names() == vec!["proxy-host-canary.invalid"; 3],
		"named proxy lookup recording changed"
	);
	let mut snapshot = handle.names();
	snapshot.clear();
	assert_eq!(recorder.names().len(), 3);
}

#[test]
fn proxy_failure_debug_and_display_redact_credentials_and_hostnames() {
	let recorder = RecordingResolver::new();
	let proxy = ProxyConfig::new("http://proxy-host-canary.invalid:1080")
		.unwrap()
		.with_basic_auth(USERNAME, PASSWORD);
	let transport =
		WebApiTransport::new_with_proxy_and_recording_resolver(&proxy, &recorder).unwrap();
	let error = request(&transport, "https");
	assert_proxy_connect(&error);
	let diagnostic = format!("{error} {error:?} {error:#?} {proxy:?} {transport:?} {recorder:?}");
	for value in [TARGET, "proxy-host-canary.invalid", USERNAME, PASSWORD] {
		assert!(
			!diagnostic.contains(value),
			"proxy diagnostics leaked private data"
		);
	}
}
