use super::*;

#[test]
fn test_endpoint_loopback_proxy_admission_matrix_without_sockets() {
	for scheme in ["http", "https", "socks5h"] {
		for host in ["127.0.0.1", "127.1.2.3", "[::1]"] {
			let proxy = ProxyConfig::new(format!("{scheme}://{host}:1080")).unwrap();
			let transport = WebApiTransport::new_with_proxy(&proxy).unwrap().clone();
			for base in [
				"http://time-fixture.invalid",
				"https://time-fixture.invalid",
				"http://192.0.2.1",
			] {
				assert!(require_loopback_route(
					&Url::parse(base).unwrap(),
					transport.proxy_host_ip
				)
				.is_ok());
			}
			for base in [
				"ftp://127.0.0.1",
				"ftp://time-fixture.invalid",
				"file:///tmp/fixture",
			] {
				let error =
					require_loopback_route(&Url::parse(base).unwrap(), transport.proxy_host_ip)
						.unwrap_err();
				assert!(
					error.kind() == super::super::NetworkErrorKind::InvalidRequest,
					"unexpected network classification"
				);
				assert!(
					error.sent() == super::super::RequestSent::No,
					"unexpected network classification"
				);
			}
		}
	}
}

#[test]
fn test_endpoint_opaque_client_cannot_claim_loopback_proxy() {
	let transport = WebApiTransport::new(
		reqwest::blocking::Client::builder()
			.no_proxy()
			.proxy(reqwest::Proxy::all("http://127.0.0.1:1080").unwrap())
			.build()
			.unwrap(),
	);
	assert_eq!(transport.proxy_host_ip, None);
	assert!(require_loopback_route(
		&Url::parse("http://time-fixture.invalid").unwrap(),
		transport.proxy_host_ip
	)
	.is_err());
}
