use super::*;
use base64::Engine;
use protobuf::Message;
use rsa::{pkcs8::DecodePrivateKey, traits::PublicKeyParts};

use crate::{
	accountlinker::AccountLinker,
	protobufs::steammessages_auth_steamclient::{
		CAuthentication_BeginAuthSessionViaCredentials_Response,
		CAuthentication_BeginAuthSessionViaQR_Response,
		CAuthentication_GetPasswordRSAPublicKey_Response, EAuthSessionGuardType,
		EAuthTokenPlatformType,
	},
	token::Tokens,
	ConfirmationId, Confirmer, ConfirmerError, DeviceDetails, SteamGuardAccount, UserLogin,
};

fn isolated(name: &str) -> bool {
	in_environment(
		&format!("callers::{name}"),
		&[
			concat!("STEAMGUARD_", "API_BASE_URL"),
			concat!("STEAMGUARD_", "LOGIN_BASE_URL"),
			concat!("STEAMGUARD_", "COMMUNITY_BASE_URL"),
		]
		.map(|key| (key, "http://127.0.0.1:9".to_owned())),
	)
}

fn tokens() -> Tokens {
	// Reuse the synthetic Steam identity from the confirmation tests; this JWT is unsigned.
	let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
		br#"{"exp":1,"iat":1,"iss":"issuer-canary","aud":[],"sub":"7656119900000001","jti":"jwt-canary"}"#,
	);
	Tokens::new(
		format!("header.{payload}.signature"),
		"refresh-token-canary".to_owned(),
	)
}

fn account() -> SteamGuardAccount {
	SteamGuardAccount {
		steam_id: 7_656_119_900_000_001,
		device_id: "android:test-device".into(),
		identity_secret: "GQP46b73Ws7gr8GmZFR0sDuau5c=".to_owned().into(),
		tokens: Some(tokens()),
		..SteamGuardAccount::default()
	}
}

fn login(transport: WebApiTransport) -> UserLogin<WebApiTransport> {
	UserLogin::new(
		transport,
		DeviceDetails {
			friendly_name: "Synthetic login test".into(),
			platform_type: EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp,
			os_type: 0,
			gaming_device_type: 0,
		},
	)
}

fn response(status: u16, body: &[u8]) -> Vec<u8> {
	let mut bytes = format!("HTTP/1.1 {status} wire-reason-canary\r\nRetry-After: wire-retry-canary\r\nx-error_message: wire-header-canary\r\nx-eresult: 1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
	bytes.extend_from_slice(body);
	bytes
}

fn serve(listener: TcpListener, path: &'static str, response: Vec<u8>) -> thread::JoinHandle<()> {
	thread::spawn(move || {
		let mut stream = accept(&listener);
		let request = read_api_request(&mut stream);
		assert!(request.lines().next().unwrap().contains(path));
		stream.write_all(&response).unwrap();
		assert_eq!(pending_connections(&listener), 0);
	})
}

fn failure(path: &'static str) -> (WebApiTransport, thread::JoinHandle<()>) {
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let transport = proxied(&listener);
	(
		transport,
		serve(listener, path, response(429, b"wire-body-canary")),
	)
}

fn source<'a, T: Error + 'static>(error: &'a (dyn Error + 'static)) -> Option<&'a T> {
	if let Some(value) = error.downcast_ref::<T>() {
		return Some(value);
	}
	if let Some(error) = error.downcast_ref::<ConfirmerError>() {
		return error.raw_source().and_then(source::<T>);
	}
	if let Some(inner) = error
		.downcast_ref::<std::io::Error>()
		.and_then(std::io::Error::get_ref)
	{
		if let Some(value) = source::<T>(inner) {
			return Some(value);
		}
	}
	error.source().and_then(source::<T>)
}

fn assert_safe(error: &dyn Error) {
	for diagnostic in [
		format!("{error}"),
		format!("{error:#}"),
		format!("{error:?}"),
		format!("{error:#?}"),
	] {
		for canary in [
			"wire-reason-canary",
			"wire-retry-canary",
			"wire-header-canary",
			"wire-body-canary",
			"message-value-canary",
			"parse-value-canary",
			"origin-canary",
			"account-name-canary",
			"password-canary",
			"guard-code-canary",
			"issuer-canary",
			"jwt-canary",
			"wrapper-context-canary",
			"://",
		] {
			assert!(!diagnostic.contains(canary), "sensitive assertion failed");
		}
	}
}

fn assert_http(error: &(dyn Error + 'static), status: u16) {
	let network = source::<NetworkError>(error).expect("caller lost typed NetworkError source");
	assert!(
		(network.kind()) == (NetworkErrorKind::HttpStatus),
		"sensitive assertion failed"
	);
	assert_eq!(network.status().unwrap().as_u16(), status);
	assert!(
		(network.retry_after().unwrap().as_bytes()) == (b"wire-retry-canary"),
		"sensitive assertion failed"
	);
	assert_eq!(network.sent(), RequestSent::Yes);
	if status >= 400 {
		let original = source::<reqwest::Error>(error).expect("caller lost reqwest source");
		assert_eq!(original.status().unwrap().as_u16(), status);
		// Synthetic-only inspection proves the original untrusted reason was retained internally.
		assert!(
			original.to_string().contains("wire-reason-canary"),
			"sensitive assertion failed"
		);
	}
}

#[test]
fn linking_error_diagnostics_hide_http_sources() {
	if isolated("linking_error_diagnostics_hide_http_sources") {
		return;
	}
	let (transport, server) = failure("/ITwoFactorService/AddAuthenticator/v1");
	let error = AccountLinker::new(transport, tokens()).link().unwrap_err();
	server.join().unwrap();
	assert_http(&error, 429);
	assert_safe(&error);
	// The public anyhow conversions must also avoid formatting the retained source wrapper.
	let error = crate::userlogin::LoginError::from(
		anyhow::Error::new(error).context("wrapper-context-canary"),
	);
	assert_http(&error, 429);
	assert_safe(&error);
	let error = crate::userlogin::UpdateAuthSessionError::from(
		anyhow::Error::new(error).context("wrapper-context-canary"),
	);
	assert_http(&error, 429);
	assert_safe(&error);
}

#[test]
fn confirmation_status_precedes_success_json() {
	if isolated("confirmation_status_precedes_success_json") {
		return;
	}
	let account = account();
	for status in [302, 401, 403, 429, 500, 503] {
		for body in [
			b"{\"success\":true}".as_slice(),
			b"<html>wire-body-canary</html>",
		] {
			let listener = TcpListener::bind("127.0.0.1:0").unwrap();
			let transport = proxied(&listener);
			let server = serve(listener, "/mobileconf/ajaxop", response(status, body));
			let result = Confirmer::new(transport, &account)
				.with_server_time(1_617_591_917)
				.accept_confirmation(ConfirmationId {
					id: "confirmation-id-canary",
					nonce: "nonce-canary",
				});
			server.join().unwrap();
			let error = result.expect_err("non-success HTTP response became confirmation success");
			assert_http(&error, status);
			assert_safe(&error);
		}
	}
}

#[test]
fn confirmation_diagnostics_hide_messages_and_parse_sources() {
	if isolated("confirmation_diagnostics_hide_messages_and_parse_sources") {
		return;
	}
	let account = account();
	for (body, remote) in [
		(
			br#"{"success":false,"message":"message-value-canary"}"#.as_slice(),
			true,
		),
		(br#"{"success":"parse-value-canary"}"#.as_slice(), false),
	] {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let transport = proxied(&listener);
		let server = serve(listener, "/mobileconf/ajaxop", response(200, body));
		let error = Confirmer::new(transport, &account)
			.with_server_time(1_617_591_917)
			.deny_confirmation(ConfirmationId {
				id: "confirmation-id-canary",
				nonce: "nonce-canary",
			})
			.unwrap_err();
		server.join().unwrap();
		if remote {
			assert!(
				matches!(&error, ConfirmerError::RemoteFailureWithMessage(message) if message == "message-value-canary"),
				"sensitive assertion failed"
			);
		} else {
			let original = source::<serde_path_to_error::Error<serde_json::Error>>(&error).unwrap();
			assert!(
				original.to_string().contains("parse-value-canary"),
				"sensitive assertion failed"
			);
		}
		assert_safe(&error);
	}
}

#[test]
fn confirmation_time_error_diagnostics_hide_http_sources() {
	if isolated("confirmation_time_error_diagnostics_hide_http_sources") {
		return;
	}
	let (transport, server) = failure("/ITwoFactorService/QueryTime/v1");
	let account = account();
	let error = Confirmer::new(transport, &account)
		.get_confirmations()
		.unwrap_err();
	server.join().unwrap();
	assert_http(&error, 429);
	assert_safe(&error);
}

#[test]
fn plain_unauthorized_and_approved_typed_status_reach_callers() {
	if isolated("plain_unauthorized_and_approved_typed_status_reach_callers") {
		return;
	}
	for approved in [false, true] {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let transport = if approved {
			proxied(&listener)
		} else {
			WebApiTransport::new(
				reqwest::blocking::Client::builder()
					.no_proxy()
					.proxy(
						reqwest::Proxy::all(format!("http://{}", listener.local_addr().unwrap()))
							.unwrap(),
					)
					.timeout(Duration::from_secs(2))
					.build()
					.unwrap(),
			)
		};
		let server = serve(
			listener,
			"/ITwoFactorService/QueryStatus/v1",
			response(401, b"wire-body-canary"),
		);
		let error = AccountLinker::new(transport, tokens())
			.query_status(&account())
			.unwrap_err();
		server.join().unwrap();
		if approved {
			assert_http(&error, 401);
		} else {
			assert!(
				matches!(error, TransportError::Unauthorized),
				"plain caller lost legacy Unauthorized"
			);
		}
		assert_safe(&error);
	}
}

#[test]
fn login_error_delegates_http_source() {
	if isolated("login_error_delegates_http_source") {
		return;
	}
	let (transport, server) = failure("/IAuthenticationService/GetPasswordRSAPublicKey/v1");
	let error = login(transport)
		.begin_auth_via_credentials("account-name-canary", "password-canary")
		.unwrap_err();
	server.join().unwrap();
	assert_safe(&error);
	assert_http(&error, 429);
	// Exercise the preserved direct NetworkError conversions using this returned caller failure.
	let crate::userlogin::LoginError::TransportError(TransportError::NetworkFailure(network)) =
		error
	else {
		panic!("login returned an unexpected variant");
	};
	let error = crate::userlogin::LoginError::from(network);
	assert_http(&error, 429);
	assert_safe(&error);
	let crate::userlogin::LoginError::NetworkFailure(network) = error else {
		panic!("login conversion changed its public variant");
	};
	let error = crate::userlogin::UpdateAuthSessionError::from(network);
	assert_http(&error, 429);
	assert_safe(&error);
}

#[test]
fn login_error_delegates_tls_source() {
	if isolated("login_error_delegates_tls_source") {
		return;
	}
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let proxy = ProxyConfig::new(format!("https://{}", listener.local_addr().unwrap())).unwrap();
	let transport = WebApiTransport::new_with_proxy(&proxy).unwrap();
	let server = tls_server(listener, false);
	let error = login(transport)
		.begin_auth_via_credentials("account-name-canary", "password-canary")
		.unwrap_err();
	assert!(!server.join().unwrap());
	assert_safe(&error);
	assert!(
		has_untrusted_certificate(&error),
		"login lost typed UnknownIssuer"
	);
	assert!(
		(source::<NetworkError>(&error).unwrap().sent()) == (RequestSent::No),
		"sensitive assertion failed"
	);
}

#[test]
fn update_auth_error_delegates_http_source() {
	if isolated("update_auth_error_delegates_http_source") {
		return;
	}
	// Reuse the declared public TLS test identity for the synthetic login RSA response.
	let key = rsa::RsaPrivateKey::from_pkcs8_der(KEY).unwrap();
	let mut rsa = CAuthentication_GetPasswordRSAPublicKey_Response::new();
	rsa.set_publickey_mod(key.n().to_str_radix(16));
	rsa.set_publickey_exp(key.e().to_str_radix(16));
	rsa.set_timestamp(1);
	let mut started = CAuthentication_BeginAuthSessionViaCredentials_Response::new();
	started.set_client_id(1);
	started.set_request_id(b"request-id-canary".to_vec());
	started.set_steamid(7_656_119_900_000_001);
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let transport = proxied(&listener);
	let server = thread::spawn(move || {
		for (path, response) in [
			(
				"/GetPasswordRSAPublicKey/v1",
				response(200, &rsa.write_to_bytes().unwrap()),
			),
			(
				"/BeginAuthSessionViaCredentials/v1",
				response(200, &started.write_to_bytes().unwrap()),
			),
			(
				"/UpdateAuthSessionWithSteamGuardCode/v1",
				response(429, b"wire-body-canary"),
			),
		] {
			let mut stream = accept(&listener);
			assert!(read_api_request(&mut stream)
				.lines()
				.next()
				.unwrap()
				.contains(path));
			stream.write_all(&response).unwrap();
		}
		assert_eq!(pending_connections(&listener), 0);
	});
	let mut login = login(transport);
	login
		.begin_auth_via_credentials("account-name-canary", "password-canary")
		.unwrap();
	let error = login
		.submit_steam_guard_code(
			EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode,
			"guard-code-canary".into(),
		)
		.unwrap_err();
	server.join().unwrap();
	assert_safe(&error);
	assert_http(&error, 429);
}

#[test]
fn login_and_update_other_failures_retain_sources() {
	if isolated("login_and_update_other_failures_retain_sources") {
		return;
	}
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let transport = proxied(&listener);
	let mut rsa = CAuthentication_GetPasswordRSAPublicKey_Response::new();
	rsa.set_publickey_mod("11".into());
	rsa.set_publickey_exp("010001".into());
	let server = serve(
		listener,
		"/GetPasswordRSAPublicKey/v1",
		response(200, &rsa.write_to_bytes().unwrap()),
	);
	let error = login(transport)
		.begin_auth_via_credentials("account-name-canary", "password-canary")
		.unwrap_err();
	server.join().unwrap();
	assert_safe(&error);
	assert!(
		source::<rsa::Error>(&error).is_some(),
		"login lost typed RSA failure"
	);

	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let transport = proxied(&listener);
	let mut started = CAuthentication_BeginAuthSessionViaQR_Response::new();
	started.set_client_id(1);
	started.set_request_id(b"request-id-canary".to_vec());
	started.set_challenge_url("challenge-url-canary".to_owned());
	let server = serve(
		listener,
		"/BeginAuthSessionViaQR/v1",
		response(200, &started.write_to_bytes().unwrap()),
	);
	let mut login = login(transport);
	login.begin_auth_via_qr().unwrap();
	server.join().unwrap();
	let error = login
		.submit_steam_guard_code(
			EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode,
			"guard-code-canary".into(),
		)
		.unwrap_err();
	assert_safe(&error);
	assert!(
		error.source().is_some(),
		"update lost its local failure source"
	);
}

#[test]
fn adjacent_linking_errors_keep_safe_transport_diagnostics() {
	if isolated("adjacent_linking_errors_keep_safe_transport_diagnostics") {
		return;
	}
	for operation in [
		"FinalizeAddAuthenticator",
		"RemoveAuthenticator",
		"RemoveAuthenticatorViaChallengeStart",
		"RemoveAuthenticatorViaChallengeContinue",
	] {
		let (transport, server) = failure(operation);
		let mut linker = AccountLinker::new(transport, tokens());
		let error: Box<dyn Error> = match operation {
			"FinalizeAddAuthenticator" => Box::new(
				linker
					.finalize(1_617_591_917, &mut account(), "guard-code-canary".into())
					.unwrap_err(),
			),
			"RemoveAuthenticator" => Box::new(
				linker
					.remove_authenticator(Some(&"revocation-code-canary".into()))
					.unwrap_err(),
			),
			"RemoveAuthenticatorViaChallengeStart" => {
				Box::new(linker.transfer_start().unwrap_err())
			}
			_ => Box::new(linker.transfer_finish("guard-code-canary").unwrap_err()),
		};
		server.join().unwrap();
		assert_http(error.as_ref(), 429);
		assert_safe(error.as_ref());
	}
}

#[test]
fn redaction_assertion_failure_output_is_fixed() {
	const CHILD: &str = "STEAMGUARD_ASSERTION_FAILURE_CHILD";
	if std::env::var_os(CHILD).is_some() {
		let error = std::io::Error::other("wire-reason-canary");
		assert!(
			std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| assert_safe(&error))).is_err(),
			"deliberate disclosure did not fail the assertion"
		);
		return;
	}
	let output = Command::new(std::env::current_exe().unwrap())
		.args([
			"--exact",
			"transport::tests::callers::redaction_assertion_failure_output_is_fixed",
			"--nocapture",
		])
		.env(CHILD, "1")
		.output()
		.unwrap();
	let diagnostic = format!(
		"{}{}",
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr)
	);
	assert!(
		!diagnostic.contains("canary"),
		"assertion failure exposed a secret"
	);
	assert!(output.status.success(), "assertion fixture child failed");
	assert!(
		diagnostic.contains("sensitive assertion failed"),
		"expected assertion failure missing"
	);
}
