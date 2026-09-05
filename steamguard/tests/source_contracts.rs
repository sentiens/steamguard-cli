use regex::Regex;

fn attributes(source: &str, name: &str) -> String {
	// Deliberately limited to the ordinary item declarations used by these reviewed wrappers.
	let pattern = format!(
		r"(?m)((?:\s*#\[[^\]]*\]\s*|\s*///[^\n]*\n)*)(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum)\s+{}\b",
		regex::escape(name)
	);
	let regex = Regex::new(&pattern).unwrap();
	let matches: Vec<_> = regex.captures_iter(source).collect();
	assert_eq!(
		matches.len(),
		1,
		"missing or ambiguous declaration for {name}"
	);
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
				"derived Debug on {name}"
			);
		}
	}
	for source in [
		"#[derive(Debug)] pub struct Secret;",
		"#[derive(Clone,\nDebug)]\n/// docs\n#[serde(transparent)]\npub(crate) struct Secret;",
		"#[cfg_attr(test, derive(Debug))]\nstruct Secret;",
	] {
		assert!(derives_debug.is_match(&attributes(source, "Secret")));
	}
	assert!(!derives_debug.is_match(&attributes(
		"#[derive(Clone)] struct Secret; #[derive(Debug)] struct Public;",
		"Secret"
	)));
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
		assert_eq!(
			compact.matches(required).count(),
			1,
			"missing or duplicate setting: {required}"
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

#[test]
fn upstream_convenience_methods_remain_available() {
	use steamguard::token::{SteamJwtData, TwoFactorSecret};
	let constructor: fn(Vec<u8>) -> TwoFactorSecret = TwoFactorSecret::from_bytes;
	assert_eq!(constructor(vec![0; 20]).expose_secret(), &[0; 20]);
	assert!(std::panic::catch_unwind(|| constructor(vec![0; 19])).is_err());
	let steam_id: fn(&SteamJwtData) -> u64 = SteamJwtData::steam_id;
	assert_eq!(
		steam_id(&SteamJwtData {
			exp: 1,
			iat: 1,
			iss: String::new(),
			aud: vec![],
			sub: "123".into(),
			jti: String::new()
		}),
		123
	);
}
