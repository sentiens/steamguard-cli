#![cfg(feature = "test-endpoints")]

use std::{
	io::{BufRead, BufReader, Read, Write},
	net::TcpListener,
	thread,
	time::{Duration, Instant},
};
use steamguard::{
	protobufs::service_phone::CPhone_SendPhoneVerificationCode_Request,
	steamapi::{EResult, PhoneClient},
	token::Jwt,
	transport::WebApiTransport,
};

// Separate binary: one fixed API endpoint for the process-cached test override.
// Fake transports cannot verify the HTTP status captured by WebApiTransport.
#[test]
fn loopback_decoded_steam_rejections_retain_actual_http_status() {
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	listener.set_nonblocking(true).unwrap();
	std::env::set_var(
		"STEAMGUARD_API_BASE_URL",
		format!("http://{}", listener.local_addr().unwrap()),
	);
	let cases = [
		(200, EResult::OK),
		(200, EResult::SMSCodeFailed),
		(201, EResult::Unknown(-9876)),
	];
	let server = thread::spawn(move || {
		for (status, result) in cases {
			let deadline = Instant::now() + Duration::from_secs(5);
			let mut stream = loop {
				match listener.accept() {
					Ok((stream, _)) => break stream,
					Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
						assert!(Instant::now() < deadline, "test invariant failed");
						thread::sleep(Duration::from_millis(5));
					}
					Err(_) => panic!("loopback accept failed"),
				}
			};
			stream
				.set_read_timeout(Some(Duration::from_secs(5)))
				.unwrap();
			stream
				.set_write_timeout(Some(Duration::from_secs(5)))
				.unwrap();
			let mut reader = BufReader::new(&mut stream);
			let mut line = String::new();
			reader.read_line(&mut line).unwrap();
			assert!(
				line.contains("/IPhoneService/SendPhoneVerificationCode/v1"),
				"test invariant failed"
			);
			let mut length = 0;
			loop {
				line.clear();
				assert!(
					reader.read_line(&mut line).unwrap() > 0,
					"test invariant failed"
				);
				if line == "\r\n" {
					break;
				}
				if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
					length = value.trim().parse::<usize>().unwrap();
				}
			}
			reader.read_exact(&mut vec![0; length]).unwrap();
			write!(stream, "HTTP/1.1 {status} Synthetic\r\nx-eresult: {}\r\nx-error_message: message-canary\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", result.code()).unwrap();
		}
	});
	let transport = WebApiTransport::new(
		reqwest::blocking::Client::builder()
			.no_proxy()
			.timeout(Duration::from_secs(5))
			.build()
			.unwrap(),
	);
	let client = PhoneClient::new(transport);
	let token = Jwt::from("access-canary".to_owned());
	for (status, result) in cases {
		let response = client
			.send_phone_verification_code(CPhone_SendPhoneVerificationCode_Request::new(), &token)
			.unwrap();
		assert!(
			(response.http_status()) == (Some(status)),
			"test invariant failed"
		);
		assert!(
			(response.clone().http_status()) == (Some(status)),
			"test invariant failed"
		);
		assert!((response.result()) == (result), "test invariant failed");
		assert!(
			!format!("{response:?}").contains("canary"),
			"test invariant failed"
		);
	}
	server.join().unwrap();
}
