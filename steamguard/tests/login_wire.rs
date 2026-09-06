#![cfg(feature = "test-endpoints")]

use protobuf::Message;
use std::{
	io::{BufRead, BufReader, Read, Write},
	net::TcpListener,
	thread,
	time::{Duration, Instant},
};
use steamguard::{
	protobufs::steammessages_auth_steamclient::{
		CAuthentication_BeginAuthSessionViaCredentials_Response as CredentialsResponse,
		CAuthentication_GetPasswordRSAPublicKey_Response as RsaResponse,
		CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response as UpdateResponse,
		EAuthSessionGuardType, EAuthTokenPlatformType,
	},
	steamapi::EResult,
	transport::WebApiTransport,
	DeviceDetails, UserLogin,
};

fn wire_response(result: EResult, data: impl Message) -> Vec<u8> {
	let body = data.write_to_bytes().unwrap();
	let mut response = format!(
		"HTTP/1.1 200 OK\r\nx-eresult: {}\r\nx-error_message: message-canary\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
		result.code(), body.len()
	).into_bytes();
	response.extend(body);
	response
}

// This binary has one test, so the process-cached endpoint is isolated from other tests.
#[test]
fn loopback_begin_subject_and_exact_eresults_redact_wire_messages() {
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	listener.set_nonblocking(true).unwrap();
	// IAuthenticationService uses the login endpoint, independently of the API endpoint.
	std::env::set_var(
		"STEAMGUARD_LOGIN_BASE_URL",
		format!("http://{}", listener.local_addr().unwrap()),
	);
	let mut rsa = RsaResponse::new();
	rsa.set_publickey_exp("010001".to_owned());
	rsa.set_publickey_mod("ff".repeat(128));
	rsa.set_timestamp(1);
	let mut begin = CredentialsResponse::new();
	begin.set_client_id(123);
	begin.set_request_id(b"request-id-canary".to_vec());
	begin.set_steamid(76561198000000001);
	begin.set_extended_error_message("extended-error-message-canary".to_owned());
	let results = [
		EResult::RateLimitExceeded,
		EResult::AccountLoginDeniedThrottle,
		EResult::Expired,
		EResult::FileNotFound,
	];
	let mut script = vec![
		(
			"GetPasswordRSAPublicKey",
			wire_response(EResult::OK, rsa.clone()),
		),
		(
			"BeginAuthSessionViaCredentials",
			wire_response(EResult::OK, begin.clone()),
		),
	];
	for result in results {
		script.push((
			"UpdateAuthSessionWithSteamGuardCode",
			wire_response(result, UpdateResponse::new()),
		));
	}
	for result in results {
		script.push((
			"GetPasswordRSAPublicKey",
			wire_response(EResult::OK, rsa.clone()),
		));
		script.push((
			"BeginAuthSessionViaCredentials",
			wire_response(result, begin.clone()),
		));
	}
	let server = thread::spawn(move || {
		for (method, response) in script {
			let deadline = Instant::now() + Duration::from_secs(5);
			let mut stream = loop {
				match listener.accept() {
					Ok((stream, _)) => break stream,
					Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
						assert!(Instant::now() < deadline, "request did not arrive");
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
			assert!(line.contains(method), "unexpected API request");
			let mut length = 0;
			loop {
				line.clear();
				assert!(
					reader.read_line(&mut line).unwrap() > 0,
					"incomplete request"
				);
				if line == "\r\n" {
					break;
				}
				if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
					length = value.trim().parse::<usize>().unwrap();
				}
			}
			reader.read_exact(&mut vec![0; length]).unwrap();
			stream.write_all(&response).unwrap();
		}
	});
	let transport = WebApiTransport::new(
		reqwest::blocking::Client::builder()
			.no_proxy()
			.timeout(Duration::from_secs(5))
			.build()
			.unwrap(),
	);
	let new_login = || {
		UserLogin::new(
			transport.clone(),
			DeviceDetails {
				friendly_name: "Synthetic wire test".to_owned(),
				platform_type: EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp,
				os_type: 0,
				gaming_device_type: 0,
			},
		)
	};
	let mut login = new_login();
	assert_eq!(login.started_steam_id(), None);
	login
		.begin_auth_via_credentials("synthetic-account", "password-canary")
		.unwrap();
	assert_eq!(login.started_steam_id(), Some(76561198000000001));
	for result in results {
		let error = login
			.submit_steam_guard_code(
				EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode,
				"guard-code-canary".to_owned(),
			)
			.unwrap_err();
		assert!(error.eresult() == Some(result), "Steam result was lost");
		assert!(
			!format!("{error} {error:?}").contains("canary"),
			"server message leaked"
		);
	}
	for result in results {
		let mut login = new_login();
		let error = login
			.begin_auth_via_credentials("synthetic-account", "password-canary")
			.unwrap_err();
		assert!(error.eresult() == Some(result), "Steam result was lost");
		assert!(
			!format!("{error} {error:?}").contains("canary"),
			"server message leaked"
		);
		assert_eq!(login.started_steam_id(), None);
	}
	server.join().unwrap();
}
