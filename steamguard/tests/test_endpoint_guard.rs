#![cfg(feature = "test-endpoints")]

use std::{
	io::{BufRead, BufReader, Read, Write},
	net::{TcpListener, TcpStream},
	process::Command,
	sync::Arc,
	thread,
	time::{Duration, Instant},
};
use steamguard::{
	protobufs::steammessages_auth_steamclient::EAuthTokenPlatformType,
	steamapi::TwoFactorClient,
	test_support::RecordingResolver,
	transport::{
		NetworkError, NetworkErrorKind, ProxyConfig, RequestSent, Transport, TransportError,
		WebApiTransport, WebEndpoint, WebRequest,
	},
	DeviceDetails, LoginError, UserLogin,
};

#[test]
fn test_endpoint_bases_refuse_non_loopback_before_network() {
	const CHILD: &str = "STEAMGUARD_LOOPBACK_GUARD_CHILD";
	if std::env::var_os(CHILD).is_none() {
		for base in [
			None,
			Some("https://login.steampowered.com"),
			Some("https://api.steampowered.com"),
			Some("https://steamcommunity.com"),
			Some("http://192.0.2.1"),
			Some("http://[2001:db8::1]"),
			Some("http://localhost"),
			Some("http://time-fixture.invalid"),
			Some("http://127.0.0.1.example.com"),
			Some("http://127.0.0.1@live.example.com"),
			Some("invalid-url"),
		] {
			let mut child = Command::new(std::env::current_exe().unwrap());
			child.args([
				"--exact",
				"test_endpoint_bases_refuse_non_loopback_before_network",
			]);
			child.env(CHILD, "1");
			for service in ["API", "LOGIN", "COMMUNITY"] {
				let key = format!("STEAMGUARD_{service}_BASE_URL");
				child.env_remove(&key);
				if let Some(base) = base {
					child.env(key, base);
				}
			}
			let output = child.output().unwrap();
			assert!(output.status.success(), "test invariant failed");
		}
		return;
	}

	let recorder = RecordingResolver::new();
	let transport = WebApiTransport::new(
		reqwest::blocking::Client::builder()
			.no_proxy()
			.dns_resolver(Arc::new(recorder.clone()))
			.timeout(std::time::Duration::from_secs(1))
			.build()
			.unwrap(),
	);
	let mut login = UserLogin::new(
		transport.clone(),
		DeviceDetails {
			friendly_name: "guard test".to_owned(),
			platform_type: EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp,
			os_type: 0,
			gaming_device_type: 0,
		},
	);
	let LoginError::TransportError(TransportError::NetworkFailure(error)) = login
		.begin_auth_via_credentials("account-canary", "password-canary")
		.unwrap_err()
	else {
		panic!("expected local endpoint rejection")
	};
	assert!(
		(error.kind()) == (NetworkErrorKind::InvalidRequest),
		"test invariant failed"
	);
	let TransportError::NetworkFailure(error) = TwoFactorClient::new(transport.clone())
		.query_time()
		.unwrap_err()
	else {
		panic!("expected local endpoint rejection")
	};
	assert!(
		(error.kind()) == (NetworkErrorKind::InvalidRequest),
		"test invariant failed"
	);
	let error = transport
		.send_web(WebRequest::new(
			WebEndpoint::ConfirmationList,
			&[],
			"test",
			"",
			"en",
		))
		.unwrap_err();
	assert!(
		(error.kind()) == (NetworkErrorKind::InvalidRequest),
		"test invariant failed"
	);
	assert!(
		error.sent() == RequestSent::No,
		"unexpected network classification"
	);
	assert!(recorder.names().is_empty());
}

// Run each service-base case in a fresh process because endpoint overrides are cached.
fn in_child(name: &str, base: &str) -> bool {
	const CHILD: &str = "STEAMGUARD_PROXY_GUARD_CHILD";
	if std::env::var(CHILD).as_deref() == Ok(name) {
		return true;
	}
	let output = Command::new(std::env::current_exe().unwrap())
		.args(["--exact", name])
		.env(CHILD, name)
		.env("STEAMGUARD_API_BASE_URL", base)
		.env("STEAMGUARD_COMMUNITY_BASE_URL", base)
		// Approved clients must keep their explicit route despite ambient proxy settings.
		.env("HTTP_PROXY", "http://10.255.255.1:1080")
		.env("HTTPS_PROXY", "http://10.255.255.1:1080")
		.env("ALL_PROXY", "socks5h://10.255.255.1:1080")
		.env("NO_PROXY", "*")
		.output()
		.unwrap();
	assert!(
		output.status.success()
			&& String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
		"endpoint guard subprocess failed",
	);
	false
}

fn service_errors(transport: &WebApiTransport) -> [NetworkError; 2] {
	let TransportError::NetworkFailure(api) = TwoFactorClient::new(transport.clone())
		.query_time()
		.unwrap_err()
	else {
		panic!("expected network failure")
	};
	let community = transport
		.send_web(WebRequest::new(
			WebEndpoint::ConfirmationList,
			&[],
			"test",
			"",
			"en",
		))
		.unwrap_err();
	[api, community]
}

#[test]
fn test_endpoint_non_loopback_proxy_refused_before_connect() {
	if !in_child(
		"test_endpoint_non_loopback_proxy_refused_before_connect",
		"http://time-fixture.invalid",
	) {
		return;
	}
	for scheme in ["http", "https", "socks5h"] {
		for host in [
			"10.255.255.1",
			"[2001:db8::1]",
			"localhost",
			"127.0.0.1.example.invalid",
		] {
			let proxy = ProxyConfig::new(format!("{scheme}://{host}:1080")).unwrap();
			let recorder = RecordingResolver::new();
			let transport =
				WebApiTransport::new_with_proxy_and_recording_resolver(&proxy, &recorder).unwrap();
			for error in service_errors(&transport) {
				assert!(
					error.kind() == NetworkErrorKind::InvalidRequest,
					"unexpected network classification"
				);
				assert!(
					error.sent() == RequestSent::No,
					"unexpected network classification"
				);
			}
			assert!(recorder.names().is_empty());
		}
	}
}

fn accept(listener: &TcpListener) -> TcpStream {
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
			Err(error)
				if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
			{
				thread::sleep(Duration::from_millis(5));
			}
			Err(error) => panic!("loopback accept failed: {error}"),
		}
	}
}

fn read_headers(stream: &mut TcpStream) -> String {
	let mut reader = BufReader::new(stream);
	let mut headers = String::new();
	loop {
		let mut line = String::new();
		assert_ne!(reader.read_line(&mut line).unwrap(), 0);
		headers.push_str(&line);
		if line == "\r\n" {
			return headers;
		}
	}
}

const REFUSE: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

fn loopback_http_proxy_case(name: &str, scheme: &str) {
	if !in_child(name, &format!("{scheme}://time-fixture.invalid")) {
		return;
	}
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let proxy = ProxyConfig::new(format!("http://{}", listener.local_addr().unwrap())).unwrap();
	let server = thread::spawn(move || {
		(0..2)
			.map(|_| {
				let mut stream = accept(&listener);
				let headers = read_headers(&mut stream);
				stream.write_all(REFUSE).unwrap();
				headers
			})
			.collect::<Vec<_>>()
	});
	let recorder = RecordingResolver::new();
	let transport =
		WebApiTransport::new_with_proxy_and_recording_resolver(&proxy, &recorder).unwrap();
	// The stored proxy proof must survive dropping the config and cloning the transport.
	drop(proxy);
	for error in service_errors(&transport.clone()) {
		assert!(
			error.kind()
				== if scheme == "https" {
					NetworkErrorKind::ProxyConnect
				} else {
					NetworkErrorKind::HttpStatus
				},
			"unexpected network classification"
		);
	}
	let requests = server.join().unwrap();
	for (request, path) in requests
		.iter()
		.zip(["/ITwoFactorService/QueryTime/v1", "/mobileconf/getlist"])
	{
		if scheme == "https" {
			assert!(request.starts_with("CONNECT time-fixture.invalid:443 HTTP/1.1\r\n"));
		} else {
			assert!(
				request.starts_with(&format!("POST http://time-fixture.invalid{path}"))
					|| request.starts_with(&format!("GET http://time-fixture.invalid{path}"))
			);
		}
	}
	assert!(recorder.names().is_empty());
}

#[test]
fn test_endpoint_remote_base_loopback_http_proxy_admitted_without_dns() {
	loopback_http_proxy_case(
		"test_endpoint_remote_base_loopback_http_proxy_admitted_without_dns",
		"http",
	);
}

#[test]
fn test_endpoint_remote_base_loopback_connect_proxy_admitted_without_dns() {
	loopback_http_proxy_case(
		"test_endpoint_remote_base_loopback_connect_proxy_admitted_without_dns",
		"https",
	);
}

#[test]
fn test_endpoint_remote_base_loopback_socks5h_proxy_admitted_without_dns() {
	if !in_child(
		"test_endpoint_remote_base_loopback_socks5h_proxy_admitted_without_dns",
		"http://time-fixture.invalid",
	) {
		return;
	}
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let proxy = ProxyConfig::new(format!("socks5h://{}", listener.local_addr().unwrap())).unwrap();
	let server = thread::spawn(move || {
		for _ in 0..2 {
			let mut stream = accept(&listener);
			let mut greeting = [0; 2];
			stream.read_exact(&mut greeting).unwrap();
			assert_eq!(greeting[0], 5);
			let mut methods = vec![0; usize::from(greeting[1])];
			stream.read_exact(&mut methods).unwrap();
			assert!(methods.contains(&0));
			stream.write_all(&[5, 0]).unwrap();
			let mut connect = [0; 5];
			stream.read_exact(&mut connect).unwrap();
			assert_eq!(&connect[..4], &[5, 1, 0, 3]);
			let mut host = vec![0; usize::from(connect[4])];
			stream.read_exact(&mut host).unwrap();
			assert_eq!(host, b"time-fixture.invalid");
			let mut port = [0; 2];
			stream.read_exact(&mut port).unwrap();
			assert_eq!(u16::from_be_bytes(port), 80);
			stream.write_all(&[5, 5, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
		}
	});
	let recorder = RecordingResolver::new();
	let transport =
		WebApiTransport::new_with_proxy_and_recording_resolver(&proxy, &recorder).unwrap();
	for error in service_errors(&transport) {
		assert!(
			error.kind() == NetworkErrorKind::ProxyConnect,
			"unexpected network classification"
		);
		assert!(
			error.sent() == RequestSent::No,
			"unexpected network classification"
		);
	}
	server.join().unwrap();
	assert!(recorder.names().is_empty());
}

#[test]
fn test_endpoint_loopback_base_without_proxy_admitted() {
	const NAME: &str = "test_endpoint_loopback_base_without_proxy_admitted";
	if std::env::var("STEAMGUARD_PROXY_GUARD_CHILD").as_deref() != Ok(NAME) {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let base = format!("http://{}", listener.local_addr().unwrap());
		let server = thread::spawn(move || {
			for path in ["/ITwoFactorService/QueryTime/v1", "/mobileconf/getlist"] {
				let mut stream = accept(&listener);
				assert!(read_headers(&mut stream)
					.lines()
					.next()
					.unwrap()
					.contains(path));
				stream.write_all(REFUSE).unwrap();
			}
		});
		assert!(!in_child(NAME, &base));
		server.join().unwrap();
		return;
	}
	let recorder = RecordingResolver::new();
	let transport = WebApiTransport::new(
		reqwest::blocking::Client::builder()
			.no_proxy()
			.dns_resolver(Arc::new(recorder.clone()))
			.timeout(Duration::from_secs(5))
			.build()
			.unwrap(),
	);
	for error in service_errors(&transport) {
		assert!(
			error.kind() == NetworkErrorKind::HttpStatus,
			"unexpected network classification"
		);
	}
	assert!(recorder.names().is_empty());
}
