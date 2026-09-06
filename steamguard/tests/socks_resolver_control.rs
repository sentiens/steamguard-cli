#![cfg(feature = "test-endpoints")]

// Raw reqwest is used only as a negative control for SOCKS5 local DNS. The
// approved factory intentionally rejects socks5 (without h) to prevent leaks.
use std::{sync::Arc, time::Duration};
use steamguard::test_support::{ProxyConfig, RecordingResolver};

#[test]
fn socks5_without_h_records_destination_before_any_proxy_connection() {
	let recorder = RecordingResolver::new();
	assert!(ProxyConfig::new("socks5://127.0.0.1:1").is_err());
	let client = reqwest::blocking::Client::builder()
		.no_proxy()
		.proxy(reqwest::Proxy::all("socks5://127.0.0.1:1").unwrap())
		.dns_resolver(Arc::new(recorder.clone()))
		.timeout(Duration::from_secs(2))
		.build()
		.unwrap();
	for scheme in ["http", "https"] {
		assert!(client
			.get(format!("{scheme}://local-target.invalid/probe"))
			.send()
			.is_err());
	}
	assert_eq!(
		recorder.names(),
		["local-target.invalid", "local-target.invalid"]
	);
}
