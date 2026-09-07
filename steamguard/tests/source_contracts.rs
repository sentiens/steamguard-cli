use regex::Regex;

fn attributes(source: &str, name: &str) -> String {
	// Deliberately limited to the ordinary item declarations used by these reviewed wrappers.
	let pattern = format!(
		r"(?m)((?:\s*#\[[^\]]*\]\s*|\s*///[^\n]*\n)*)(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum)\s+{}\b",
		regex::escape(name)
	);
	let regex = Regex::new(&pattern).unwrap();
	let matches: Vec<_> = regex.captures_iter(source).collect();
	assert!((matches.len()) == (1), "test invariant failed");
	matches[0][1].to_owned()
}

#[test]
fn derived_debug_is_absent_where_secrets_live() {
	let derives_debug = Regex::new(r"(?s)derive\s*\([^)]*\bDebug\b").unwrap();
	for (source, names) in [
		(
			include_str!("../src/token.rs"),
			&["TwoFactorSecret", "Tokens", "Jwt", "SteamJwtData"][..],
		),
		(include_str!("../src/lib.rs"), &["SteamGuardAccount"][..]),
		(
			include_str!("../src/transport/proxy.rs"),
			&["ProxyConfig", "ProxyCredentials"][..],
		),
		(
			include_str!("../src/transport/network_error.rs"),
			&["NetworkError"][..],
		),
		(
			include_str!("../src/transport/mod.rs"),
			&["TransportError"][..],
		),
		(
			include_str!("../src/transport/webapi.rs"),
			&["WebApiTransport", "WebRequest", "WebResponse"][..],
		),
		(
			include_str!("../src/steamapi.rs"),
			&["ApiRequest", "ApiResponse"][..],
		),
		(
			include_str!("../src/accountlinker.rs"),
			&["AccountLinker", "AccountLinkSuccess", "AccountLinkError"][..],
		),
		(
			include_str!("../src/phonelinker.rs"),
			&["PhoneLinker", "SetAccountPhoneNumberResponse"][..],
		),
		(include_str!("../src/refresher.rs"), &["TokenRefresher"][..]),
		(
			include_str!("../src/userlogin.rs"),
			&[
				"BeginQrLoginResponse",
				"UserLogin",
				"StartAuth",
				"LoginError",
				"UpdateAuthSessionError",
			][..],
		),
		(
			include_str!("../src/confirmation.rs"),
			&[
				"Confirmation",
				"ConfirmationId",
				"ConfirmationListResponse",
				"SendConfirmationResponse",
				"ConfirmerError",
			][..],
		),
		(
			include_str!("../src/api_responses/login.rs"),
			&["OAuthData"][..],
		),
		(
			include_str!("../src/api_responses/i_authentication_service.rs"),
			&["AllowedConfirmation"][..],
		),
		(include_str!("../src/approver.rs"), &["Challenge"][..]),
	] {
		for name in names {
			assert!(
				!derives_debug.is_match(&attributes(source, name)),
				"test invariant failed"
			);
		}
	}
	for source in [
		"#[derive(Debug)] pub struct Secret;",
		"#[derive(Clone,\nDebug)]\n/// docs\n#[serde(transparent)]\npub(crate) struct Secret;",
		"#[cfg_attr(test, derive(Debug))]\nstruct Secret;",
	] {
		assert!(
			derives_debug.is_match(&attributes(source, "Secret")),
			"sensitive assertion failed"
		);
	}
	assert!(
		!derives_debug.is_match(&attributes(
			"#[derive(Clone)] struct Secret; #[derive(Debug)] struct Public;",
			"Secret"
		)),
		"sensitive assertion failed"
	);
}

#[test]
fn timeouts_are_10s_connect_30s_total() {
	let source = include_str!("../src/transport/webapi.rs");
	let builder = source
		.split_once("pub fn new_with_proxy")
		.unwrap()
		.1
		.split_once("fn build_web_request")
		.unwrap()
		.0;
	let compact: String = builder.chars().filter(|c| !c.is_whitespace()).collect();
	for required in [
		".connect_timeout(Duration::from_secs(10))",
		".timeout(Duration::from_secs(30))",
		".redirect(reqwest::redirect::Policy::none())",
		".retry(reqwest::retry::never())",
		".no_proxy().proxy(proxy)",
		".use_rustls_tls()",
		".tls_built_in_root_certs(false).tls_built_in_webpki_certs(true)",
		".cookie_store(false)",
	] {
		assert!(
			(compact.matches(required).count()) == (1),
			"test invariant failed"
		);
	}
	assert_eq!(compact.matches("Client::builder()").count(), 1);
	assert_eq!(compact.matches(".connect_timeout(").count(), 1);
	assert_eq!(compact.matches(".timeout(").count(), 1);
	for forbidden in [
		".add_root_certificate(",
		".tls_built_in_native_certs(",
		".danger_accept_invalid",
		".use_preconfigured_tls(",
	] {
		assert!(!compact.contains(forbidden));
	}
}

fn compact_function(source: &str, declaration: &str) -> String {
	let source = source.split_once(declaration).unwrap().1;
	let start = source.find('{').unwrap();
	let mut depth = 0;
	let end = source[start..]
		.char_indices()
		.find_map(|(index, character)| {
			match character {
				'{' => depth += 1,
				'}' => depth -= 1,
				_ => {}
			}
			(depth == 0).then_some(start + index + 1)
		})
		.unwrap();
	source[start..end]
		.lines()
		.map(|line| line.split_once("//").map_or(line, |(code, _)| code))
		.flat_map(str::chars)
		.filter(|character| !character.is_whitespace())
		.collect()
}

/// T-09/C05: an allowlist of the complete reviewed construction path, paired with
/// `tls_rejection_is_classified_as_tls` for negative TLS tests on proxy and origin.
/// A new root, verifier, builder branch, or policy override requires explicit review.
#[test]
fn proxied_client_uses_only_pinned_webpki_roots() {
	let source = include_str!("../src/transport/webapi.rs");
	assert!(
		compact_function(source, "fn proxy_client_builder(")
			== concat!(
				"{letproxy=proxy.to_reqwest_proxy()?;",
				"Ok(reqwest::blocking::Client::builder()",
				".no_proxy().proxy(proxy).use_rustls_tls()",
				".tls_built_in_root_certs(false).tls_built_in_webpki_certs(true)",
				".redirect(reqwest::redirect::Policy::none()).retry(reqwest::retry::never())",
				".connect_timeout(Duration::from_secs(10)).timeout(Duration::from_secs(30))",
				".cookie_store(false).no_gzip().no_brotli().no_zstd().no_deflate())}"
			),
		"approved proxy builder policy changed"
	);
	assert_eq!(
		compact_function(source, "pub fn new_with_proxy("),
		concat!(
			"{letbuilder=Self::proxy_client_builder(proxy)?;",
			"#[cfg(feature=\"test-endpoints\")]",
			"letbuilder=match&proxy.test_resolver{",
			"Some(resolver)=>builder.dns_resolver(std::sync::Arc::new(TestResolver(",
			"std::sync::Arc::clone(resolver),))),None=>builder,};",
			"Self::from_proxy_client(builder.build(),",
			"#[cfg(feature=\"test-endpoints\")]proxy.host_ip(),)}"
		)
	);
	assert_eq!(
		compact_function(source, "pub fn new_with_proxy_and_test_resolver<"),
		concat!(
			"{letmutproxy=proxy.clone();proxy.test_resolver=Some(resolver);",
			"Self::new_with_proxy(&proxy)}"
		)
	);
	assert_eq!(
		compact_function(source, "pub fn new_with_proxy_and_recording_resolver("),
		"{Self::new_with_proxy_and_test_resolver(proxy,std::sync::Arc::new(resolver.clone()))}"
	);
	assert!(
		compact_function(source, "fn from_proxy_client(")
			== concat!(
				"{Ok(Self{client:client.map_err(|_|ProxyTransportError::ClientBuild)?,",
				"bounded_responses:true,#[cfg(feature=\"test-endpoints\")]proxy_host_ip,})}"
			),
		"approved client finalization changed"
	);
	let before_hook = source
		.split_once("pub fn new_with_proxy_and_test_resolver<")
		.unwrap()
		.0;
	assert!(before_hook
		.trim_end()
		.ends_with(r#"#[cfg(feature = "test-endpoints")]"#));
	let construction = source.split_once("fn build_web_request(").unwrap().0;
	assert_eq!(construction.matches("Client::builder()").count(), 1);
}

#[test]
fn upstream_convenience_methods_remain_available() {
	use steamguard::token::{SteamJwtData, TwoFactorSecret};
	let constructor: fn(Vec<u8>) -> TwoFactorSecret = TwoFactorSecret::from_bytes;
	assert!(
		(constructor(vec![0; 20]).expose_secret()) == (&[0; 20]),
		"sensitive assertion failed"
	);
	assert!(std::panic::catch_unwind(|| constructor(vec![0; 19])).is_err());
	let steam_id: fn(&SteamJwtData) -> u64 = SteamJwtData::steam_id;
	assert!(
		(steam_id(&SteamJwtData {
			exp: 1,
			iat: 1,
			iss: String::new(),
			aud: vec![],
			sub: "123".into(),
			jti: String::new()
		})) == (123),
		"sensitive assertion failed"
	);
}
