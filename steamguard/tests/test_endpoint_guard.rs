#![cfg(feature = "test-endpoints")]

use std::process::Command;
use steamguard::{
	protobufs::steammessages_auth_steamclient::EAuthTokenPlatformType,
	steamapi::TwoFactorClient,
	transport::{
		NetworkErrorKind, Transport, TransportError, WebApiTransport, WebEndpoint, WebRequest,
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

	let transport = WebApiTransport::new(
		reqwest::blocking::Client::builder()
			.no_proxy()
			.proxy(reqwest::Proxy::all("http://127.0.0.1:1").unwrap())
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
}
