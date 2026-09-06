use base64::Engine;
use protobuf::MessageFull;
use regex::Regex;
use std::{cell::RefCell, collections::VecDeque, error::Error, rc::Rc, time::Duration};
use steamguard::{
	protobufs::{
		custom::CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData as CredentialsRequest,
		steammessages_auth_steamclient::{
			CAuthentication_AccessToken_GenerateForApp_Request as RefreshRequest,
			CAuthentication_AccessToken_GenerateForApp_Response as RefreshResponse,
			CAuthentication_BeginAuthSessionViaCredentials_Response as CredentialsResponse,
			CAuthentication_BeginAuthSessionViaQR_Request as QrRequest,
			CAuthentication_BeginAuthSessionViaQR_Response as QrResponse,
			CAuthentication_GetPasswordRSAPublicKey_Request as RsaRequest,
			CAuthentication_GetPasswordRSAPublicKey_Response as RsaResponse,
			CAuthentication_PollAuthSessionStatus_Request as PollRequest,
			CAuthentication_PollAuthSessionStatus_Response as PollResponse,
			CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request as UpdateRequest,
			CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response as UpdateResponse,
			EAuthSessionGuardType, EAuthTokenPlatformType,
		},
	},
	steamapi::{ApiRequest, ApiResponse, BuildableRequest, EResult},
	token::Tokens,
	transport::{Transport, TransportError},
	userlogin::{BeginQrLoginResponse, UpdateAuthSessionError},
	AllowedConfirmation, DeviceDetails, LoginError, PollOutcome, UserLogin,
};

const LOGIN_SOURCE: &str = include_str!("../src/userlogin.rs");
const ACCESS: &str = "access-token-canary";
const REFRESH: &str = "refresh-token-canary";
const SERVER_ERROR: &str = "password-canary; token-canary; cookie-canary";

struct Step {
	request_type: protobuf::reflect::MessageDescriptor,
	response_type: protobuf::reflect::MessageDescriptor,
	result: Result<(EResult, Vec<u8>), TransportError>,
}

impl Step {
	fn response<Req: MessageFull, Res: MessageFull>(result: EResult, data: Res) -> Self {
		Self {
			request_type: Req::descriptor(),
			response_type: Res::descriptor(),
			result: Ok((result, data.write_to_bytes().unwrap())),
		}
	}

	fn failure<Req: MessageFull, Res: MessageFull>() -> Self {
		Self {
			request_type: Req::descriptor(),
			response_type: Res::descriptor(),
			result: Err(TransportError::Unauthorized),
		}
	}
}

#[derive(Clone)]
struct FakeTransport(Rc<RefCell<VecDeque<Step>>>);

impl FakeTransport {
	fn assert_finished(&self) {
		assert!(self.0.borrow().is_empty(), "not all scripted requests ran");
	}
}

impl Transport for FakeTransport {
	fn send_request<Req: BuildableRequest + MessageFull, Res: MessageFull>(
		&self,
		_req: ApiRequest<Req>,
	) -> Result<ApiResponse<Res>, TransportError> {
		let step = self.0.borrow_mut().pop_front().expect("unexpected request");
		assert_eq!(Req::descriptor(), step.request_type);
		assert_eq!(Res::descriptor(), step.response_type);
		let (result, bytes) = step.result?;
		Ok(ApiResponse::new(
			result,
			Some(SERVER_ERROR.to_owned()),
			Res::parse_from_bytes(&bytes)?,
		))
	}

	fn close(&mut self) {}
}

fn new_login(steps: Vec<Step>) -> (UserLogin<FakeTransport>, FakeTransport) {
	let transport = FakeTransport(Rc::new(RefCell::new(steps.into())));
	let login = UserLogin::new(
		transport.clone(),
		DeviceDetails {
			friendly_name: "Synthetic polling test".to_owned(),
			platform_type: EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp,
			os_type: -500,
			gaming_device_type: 528,
		},
	);
	(login, transport)
}

fn qr_step(interval: Option<f32>) -> Step {
	let mut response = QrResponse::new();
	response.set_client_id(123);
	response.set_request_id(b"request-id-canary".to_vec());
	response.set_challenge_url("challenge-url-canary".to_owned());
	response.interval = interval;
	Step::response::<QrRequest, _>(EResult::OK, response)
}

fn started_login(
	interval: Option<f32>,
	steps: Vec<Step>,
) -> (UserLogin<FakeTransport>, FakeTransport) {
	let mut script = vec![qr_step(interval)];
	script.extend(steps);
	let (mut login, transport) = new_login(script);
	login.begin_auth_via_qr().unwrap();
	(login, transport)
}

fn poll_step(data: PollResponse) -> Step {
	Step::response::<PollRequest, _>(EResult::OK, data)
}

fn ready_response() -> PollResponse {
	poll_response(Some(ACCESS), Some(REFRESH))
}

fn poll_response(access: Option<&str>, refresh: Option<&str>) -> PollResponse {
	let mut response = PollResponse::new();
	response.access_token = access.map(str::to_owned);
	response.refresh_token = refresh.map(str::to_owned);
	response
}

fn progress_response() -> PollResponse {
	let mut response = PollResponse::new();
	response.set_had_remote_interaction(true);
	response.set_account_name("account-name-canary".to_owned());
	response.set_new_client_id(456);
	response.set_new_challenge_url("new-challenge-canary".to_owned());
	response
}

fn refresh_token(subject: &str) -> String {
	let claims = serde_json::json!({
		"exp": 2, "iat": 1, "iss": "issuer-canary", "aud": ["mobile"],
		"sub": subject, "jti": "token-id-canary"
	});
	let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string());
	format!("header.{payload}.signature-canary")
}

fn refresh_only_response() -> PollResponse {
	poll_response(None, Some(&refresh_token("76561198000000001")))
}

fn assert_tokens(outcome: PollOutcome, refresh: &str) {
	let debug = format!("{outcome:?}");
	assert!(!debug.contains(ACCESS));
	assert!(!debug.contains(refresh));
	assert!(debug.contains("[REDACTED]"));
	let PollOutcome::Tokens(tokens) = outcome else {
		panic!("expected tokens");
	};
	assert!(
		tokens.access_token().expose_secret() == ACCESS,
		"secret values differ"
	);
	assert!(
		tokens.refresh_token().expose_secret() == refresh,
		"secret values differ"
	);
}

#[test]
fn secret_token_assertion_failures_are_redacted() {
	const CHILD: &str = "FORK_FIX_01_TOKEN_ASSERTION_CHILD";
	if let Ok(which) = std::env::var(CHILD) {
		let tokens = if which == "access" {
			Tokens::new("wrong-access-canary".to_owned(), REFRESH.to_owned())
		} else {
			Tokens::new(ACCESS.to_owned(), "wrong-refresh-canary".to_owned())
		};
		assert_tokens(PollOutcome::Tokens(tokens), REFRESH);
		return;
	}
	for which in ["access", "refresh"] {
		let output = std::process::Command::new(std::env::current_exe().unwrap())
			.args([
				"--exact",
				"secret_token_assertion_failures_are_redacted",
				"--nocapture",
			])
			.env(CHILD, which)
			.output()
			.unwrap();
		assert!(
			!output.status.success(),
			"mismatched token comparison did not fail"
		);
		for bytes in [&output.stdout, &output.stderr] {
			assert!(
				!String::from_utf8_lossy(bytes).contains("canary"),
				"token assertion output exposed a secret"
			);
		}
	}
}

#[test]
fn incomplete_qr_start_is_rejected_without_storing_session() {
	for (client, request, challenge) in [
		(None, None, None),
		(
			None,
			Some(b"request-canary".to_vec()),
			Some("challenge-canary"),
		),
		(
			Some(0),
			Some(b"request-canary".to_vec()),
			Some("challenge-canary"),
		),
		(Some(123), None, Some("challenge-canary")),
		(Some(123), Some(vec![]), Some("challenge-canary")),
		(Some(123), Some(b"request-canary".to_vec()), None),
		(Some(123), Some(b"request-canary".to_vec()), Some("")),
	] {
		let mut response = QrResponse::new();
		response.client_id = client;
		response.request_id = request;
		response.challenge_url = challenge.map(str::to_owned);
		let (mut login, transport) =
			new_login(vec![Step::response::<QrRequest, _>(EResult::OK, response)]);
		assert!(
			matches!(login.begin_auth_via_qr(), Err(LoginError::UnknownOutcome)),
			"incomplete QR start was accepted"
		);
		assert!(
			matches!(login.poll_once(), Err(LoginError::SessionNotStarted)),
			"malformed start stored a session"
		);
		assert_eq!(login.poll_interval(), None);
		assert_eq!(login.started_steam_id(), None);
		transport.assert_finished();
	}
}

#[test]
fn incomplete_credentials_start_is_rejected_without_storing_session() {
	for (client, request) in [
		(None, None),
		(None, Some(b"request-canary".to_vec())),
		(Some(0), Some(b"request-canary".to_vec())),
		(Some(123), None),
		(Some(123), Some(vec![])),
	] {
		let mut rsa = RsaResponse::new();
		rsa.set_publickey_exp("010001".to_owned());
		rsa.set_publickey_mod("ff".repeat(128));
		rsa.set_timestamp(1);
		let mut response = CredentialsResponse::new();
		response.client_id = client;
		response.request_id = request;
		let (mut login, transport) = new_login(vec![
			Step::response::<RsaRequest, _>(EResult::OK, rsa),
			Step::response::<CredentialsRequest, _>(EResult::OK, response),
		]);
		assert!(
			matches!(
				login.begin_auth_via_credentials("synthetic-account", "password-canary"),
				Err(LoginError::UnknownOutcome)
			),
			"incomplete credentials start was accepted"
		);
		assert!(
			matches!(login.poll_once(), Err(LoginError::SessionNotStarted)),
			"malformed start stored a session"
		);
		assert_eq!(login.poll_interval(), None);
		assert_eq!(login.started_steam_id(), None);
		transport.assert_finished();
	}
}

#[test]
fn refresh_only_poll_preserves_replacement_refresh_token() {
	let mut generated = RefreshResponse::new();
	generated.set_access_token(ACCESS.to_owned());
	generated.set_refresh_token(REFRESH.to_owned());
	let (mut login, transport) = started_login(
		Some(5.0),
		vec![
			poll_step(refresh_only_response()),
			Step::response::<RefreshRequest, _>(EResult::OK, generated),
		],
	);
	let PollOutcome::Tokens(tokens) = login.poll_once().unwrap() else {
		panic!("expected tokens")
	};
	assert!(
		tokens.access_token().expose_secret() == ACCESS,
		"generated access token differs"
	);
	assert!(
		tokens.refresh_token().expose_secret() == REFRESH,
		"replacement refresh token was discarded"
	);
	transport.assert_finished();
}

#[test]
fn refresh_only_poll_rejects_empty_replacement_refresh_token() {
	let mut generated = RefreshResponse::new();
	generated.set_access_token(ACCESS.to_owned());
	generated.set_refresh_token(String::new());
	let (mut login, transport) = started_login(
		Some(5.0),
		vec![
			poll_step(refresh_only_response()),
			Step::response::<RefreshRequest, _>(EResult::OK, generated),
		],
	);
	assert!(
		matches!(login.poll_once(), Err(LoginError::UnknownOutcome)),
		"empty replacement refresh token accepted"
	);
	transport.assert_finished();
}

fn assert_redacted(error: &(dyn Error + 'static), extra: &str) {
	let mut current = Some(error);
	while let Some(error) = current {
		let output = format!("{error:?} {error}");
		for secret in [ACCESS, REFRESH, SERVER_ERROR, "cookie-canary", extra] {
			if !secret.is_empty() {
				assert!(!output.contains(secret), "error chain exposed a secret");
			}
		}
		current = error.source();
	}
}

fn production_code() -> String {
	let source = LOGIN_SOURCE
		.split("\n#[cfg(test)]\nmod tests")
		.next()
		.unwrap();
	// Remove comments and string literals so prose cannot satisfy or trip the source checks.
	Regex::new(r#"(?s)/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*""#)
		.unwrap()
		.replace_all(source, "")
		.into_owned()
}

fn block<'a>(source: &'a str, declaration: &str) -> &'a str {
	let tail = source
		.split_once(declaration)
		.expect("missing declaration")
		.1;
	let start = tail.find('{').expect("missing block");
	let mut depth = 0;
	for (offset, c) in tail[start..].char_indices() {
		match c {
			'{' => depth += 1,
			'}' => {
				depth -= 1;
				if depth == 0 {
					return &tail[start + 1..start + offset];
				}
			}
			_ => {}
		}
	}
	panic!("unterminated block");
}

#[test]
fn poll_once_returns_waiting_without_sleeping() {
	let code = production_code();
	let body = block(&code, "pub fn poll_once(");
	assert!(
		!Regex::new(r"\b(sleep|sleep_until|park|park_timeout|wait|wait_timeout|loop|while|for)\b")
			.unwrap()
			.is_match(body),
		"sensitive assertion failed"
	);
	assert!(
		(body.matches(".poll_auth_session(").count()) == (1),
		"sensitive assertion failed"
	);
	assert!(
		!body.contains("self.poll_once("),
		"sensitive assertion failed"
	);
	assert!(
		!Regex::new(r"\.(unwrap|expect)\s*\(|\b(panic|unreachable|todo)\s*!")
			.unwrap()
			.is_match(&code),
		"sensitive assertion failed"
	);

	for response in [PollResponse::new(), progress_response()] {
		let (mut login, transport) = started_login(Some(5.0), vec![poll_step(response)]);
		let start = std::time::Instant::now();
		let outcome = login.poll_once().unwrap();
		let elapsed = start.elapsed();
		assert!(matches!(outcome, PollOutcome::Waiting));
		assert!(elapsed < Duration::from_millis(50), "test invariant failed");
		transport.assert_finished();
	}
}

#[test]
fn poll_once_returns_tokens_when_ready() {
	let (mut login, transport) = started_login(Some(5.0), vec![poll_step(ready_response())]);
	assert_tokens(login.poll_once().unwrap(), REFRESH);
	transport.assert_finished();

	// Both omitted and explicitly empty access tokens take the refresh-only path.
	for access in [None, Some(String::new())] {
		let mut response = refresh_only_response();
		response.access_token = access;
		let refresh = response.refresh_token().to_owned();
		let mut generated = RefreshResponse::new();
		generated.set_access_token(ACCESS.to_owned());
		let (mut login, transport) = started_login(
			Some(5.0),
			vec![
				poll_step(response),
				Step::response::<RefreshRequest, _>(EResult::OK, generated),
			],
		);
		assert_tokens(login.poll_once().unwrap(), &refresh);
		transport.assert_finished();
	}
}

#[test]
fn poll_interval_comes_from_steam() {
	assert_eq!(new_login(vec![]).0.poll_interval(), None);
	for (interval, expected) in [
		(Some(2.75), Some(Duration::from_millis(2750))),
		(Some(0.0), Some(Duration::ZERO)),
		(None, None),
	] {
		let (mut login, transport) = started_login(interval, vec![poll_step(PollResponse::new())]);
		assert_eq!(login.poll_interval(), expected);
		assert!(matches!(login.poll_once().unwrap(), PollOutcome::Waiting));
		assert_eq!(login.poll_interval(), expected);
		transport.assert_finished();

		// A synthetic public modulus is sufficient for encryption; no private key or server is used.
		let mut rsa = RsaResponse::new();
		rsa.set_publickey_exp("010001".to_owned());
		rsa.set_publickey_mod("ff".repeat(128));
		rsa.set_timestamp(1);
		let mut credentials = CredentialsResponse::new();
		credentials.set_client_id(123);
		credentials.set_request_id(b"request-id-canary".to_vec());
		credentials.interval = interval;
		let (mut login, transport) = new_login(vec![
			Step::response::<RsaRequest, _>(EResult::OK, rsa),
			Step::response::<CredentialsRequest, _>(EResult::OK, credentials),
		]);
		login
			.begin_auth_via_credentials("synthetic-account", "password-canary")
			.unwrap();
		assert_eq!(login.poll_interval(), expected);
		transport.assert_finished();
	}
	for invalid in [-1.0, f32::NAN, f32::INFINITY, f32::NEG_INFINITY, f32::MAX] {
		let (mut login, transport) = new_login(vec![qr_step(Some(invalid))]);
		let error = login.begin_auth_via_qr().unwrap_err();
		assert!(
			matches!(error, LoginError::OtherFailure(_)),
			"sensitive assertion failed"
		);
		assert_redacted(&error, "challenge-url-canary");
		assert_eq!(login.poll_interval(), None);
		assert_eq!(login.started_steam_id(), None);
		transport.assert_finished();
	}
}

#[test]
fn poll_until_tokens_is_built_on_poll_once() {
	let code = production_code();
	let body = block(&code, "pub fn poll_until_tokens(");
	let waits =
		Regex::new(r"\b(sleep|sleep_until|park|park_timeout|wait|wait_timeout)\s*\(").unwrap();
	let loops = Regex::new(r"\b(loop|while)\b|\bfor\s+[^{};]*\bin\b").unwrap();
	assert!(
		(body.matches("self.poll_once()").count()) == (1),
		"sensitive assertion failed"
	);
	assert!(
		(body.matches("self.poll_interval()").count()) == (1),
		"sensitive assertion failed"
	);
	assert!(
		(waits.find_iter(&code).count()) == (1),
		"sensitive assertion failed"
	);
	assert!(
		(waits.find_iter(body).count()) == (1),
		"sensitive assertion failed"
	);
	assert!(
		(loops.find_iter(&code).count()) == (1),
		"sensitive assertion failed"
	);
	assert!(
		(loops.find_iter(body).count()) == (1),
		"sensitive assertion failed"
	);
	assert!(
		!body.contains(".poll_auth_session("),
		"sensitive assertion failed"
	);
	assert!(
		!code.contains("poll_until_info"),
		"sensitive assertion failed"
	);

	for interval in [Some(0.002), None] {
		let (mut login, transport) = started_login(
			interval,
			vec![
				poll_step(PollResponse::new()),
				poll_step(progress_response()),
				poll_step(ready_response()),
			],
		);
		let start = std::time::Instant::now();
		let tokens = login.poll_until_tokens().unwrap();
		if interval.is_some() {
			assert!(start.elapsed() >= Duration::from_millis(4));
		}
		assert_tokens(PollOutcome::Tokens(tokens), REFRESH);
		transport.assert_finished();
	}
	let (mut login, transport) = started_login(
		Some(5.0),
		vec![Step::response::<PollRequest, _>(
			EResult::Expired,
			PollResponse::new(),
		)],
	);
	let error = login.poll_until_tokens().unwrap_err();
	assert!(
		matches!(
			error.downcast_ref::<LoginError>(),
			Some(LoginError::SessionExpired(EResult::Expired))
		),
		"sensitive assertion failed"
	);
	transport.assert_finished();
}

#[test]
fn poll_once_maps_errors() {
	let (mut login, transport) = new_login(vec![]);
	assert!(
		matches!(login.poll_once(), Err(LoginError::SessionNotStarted)),
		"sensitive assertion failed"
	);
	transport.assert_finished();

	for result in [
		EResult::Expired,
		EResult::FileNotFound,
		EResult::RateLimitExceeded,
		EResult::AccountLoginDeniedThrottle,
		EResult::InvalidPassword,
		EResult::Fail,
		EResult::Invalid,
	] {
		for refresh in [false, true] {
			let steps = if refresh {
				vec![
					poll_step(refresh_only_response()),
					Step::response::<RefreshRequest, _>(result, RefreshResponse::new()),
				]
			} else {
				vec![Step::response::<PollRequest, _>(
					result,
					PollResponse::new(),
				)]
			};
			let (mut login, transport) = started_login(Some(5.0), steps);
			let error = login.poll_once().unwrap_err();
			assert!(error.eresult() == Some(result), "Steam result was lost");
			match result {
				EResult::Expired | EResult::FileNotFound => {
					assert!(
						matches!(error, LoginError::SessionExpired(value) if value == result),
						"sensitive assertion failed"
					)
				}
				EResult::RateLimitExceeded | EResult::AccountLoginDeniedThrottle => {
					assert!(
						matches!(error, LoginError::TooManyAttempts(value) if value == result),
						"sensitive assertion failed"
					)
				}
				EResult::InvalidPassword => assert!(
					matches!(error, LoginError::BadCredentials),
					"sensitive assertion failed"
				),
				_ => assert!(
					matches!(error, LoginError::UnknownEResult(value) if value == result),
					"sensitive assertion failed"
				),
			}
			assert_redacted(&error, "");
			transport.assert_finished();
		}
	}

	let mut agreement = PollResponse::new();
	agreement.set_agreement_session_url("agreement-url-canary".to_owned());
	for response in [
		poll_response(Some(ACCESS), None),
		poll_response(Some(""), None),
		poll_response(None, Some("")),
		agreement,
	] {
		let (mut login, transport) = started_login(Some(5.0), vec![poll_step(response)]);
		let error = login.poll_once().unwrap_err();
		assert!(
			matches!(error, LoginError::UnknownOutcome),
			"sensitive assertion failed"
		);
		assert_redacted(&error, "agreement-url-canary");
		transport.assert_finished();
	}
	for malformed in [
		"malformed-refresh-canary".to_owned(),
		"header..signature-canary".to_owned(),
		"header.not*base64.signature-canary".to_owned(),
		refresh_token("invalid-steam-id-canary"),
	] {
		let response = poll_response(None, Some(&malformed));
		let (mut login, transport) = started_login(Some(5.0), vec![poll_step(response)]);
		let error = login.poll_once().unwrap_err();
		assert!(
			matches!(error, LoginError::OtherFailure(_)),
			"sensitive assertion failed"
		);
		assert_redacted(&error, &malformed);
		assert_redacted(&error, "invalid-steam-id-canary");
		transport.assert_finished();
	}
	for access in [None, Some(String::new())] {
		let mut response = RefreshResponse::new();
		response.access_token = access;
		let (mut login, transport) = started_login(
			Some(5.0),
			vec![
				poll_step(refresh_only_response()),
				Step::response::<RefreshRequest, _>(EResult::OK, response),
			],
		);
		assert!(
			matches!(login.poll_once(), Err(LoginError::UnknownOutcome)),
			"sensitive assertion failed"
		);
		transport.assert_finished();
	}
	for steps in [
		vec![Step::failure::<PollRequest, PollResponse>()],
		vec![
			poll_step(refresh_only_response()),
			Step::failure::<RefreshRequest, RefreshResponse>(),
		],
	] {
		let (mut login, transport) = started_login(Some(5.0), steps);
		assert!(
			matches!(
				login.poll_once(),
				Err(LoginError::TransportError(TransportError::Unauthorized))
			),
			"sensitive assertion failed"
		);
		transport.assert_finished();
	}
}

#[test]
fn upstream_public_names_remain_available() {
	// Compile probes retain the upstream login method signatures and module paths.
	type Login = UserLogin<FakeTransport>;
	type Confirmations = Result<Vec<AllowedConfirmation>, LoginError>;
	let _: fn(FakeTransport, DeviceDetails) -> Login = Login::new;
	let _: fn(&mut Login, &str, &str) -> Confirmations = Login::begin_auth_via_credentials;
	let _: fn(&mut Login) -> Result<BeginQrLoginResponse, LoginError> = Login::begin_auth_via_qr;
	let _: fn(&mut Login) -> anyhow::Result<Tokens> = Login::poll_until_tokens;
	let _: fn(
		&mut Login,
		EAuthSessionGuardType,
		String,
	) -> Result<UpdateResponse, UpdateAuthSessionError> = Login::submit_steam_guard_code;
	let _: fn(&BeginQrLoginResponse) -> &String = BeginQrLoginResponse::challenge_url;
	let _: fn(&BeginQrLoginResponse) -> &Vec<AllowedConfirmation> =
		BeginQrLoginResponse::confirmation_methods;
	let _: fn(&mut Login) -> Result<steamguard::userlogin::PollOutcome, LoginError> =
		Login::poll_once;
	let _: fn(&Login) -> Option<Duration> = Login::poll_interval;

	// Public declaration inventory for both edited library files at the task's starting point.
	let public_name =
		Regex::new(r"(?m)^\s*pub\s+(?:(?:struct|enum|fn|mod)\s+([A-Za-z_]\w*)|([A-Za-z_]\w*)\s*:)")
			.unwrap();
	for (source, expected) in [
		(
			LOGIN_SOURCE,
			&[
				"LoginError",
				"BeginQrLoginResponse",
				"challenge_url",
				"confirmation_methods",
				"UserLogin",
				"new",
				"begin_auth_via_credentials",
				"begin_auth_via_qr",
				"poll_until_tokens",
				"submit_steam_guard_code",
				"DeviceDetails",
				"friendly_name",
				"platform_type",
				"os_type",
				"gaming_device_type",
				"UpdateAuthSessionError",
			][..],
		),
		(
			include_str!("../src/lib.rs"),
			&[
				"accountlinker",
				"approver",
				"phonelinker",
				"protobufs",
				"refresher",
				"steamapi",
				"token",
				"transport",
				"userlogin",
				"SteamGuardAccount",
				"account_name",
				"steam_id",
				"serial_number",
				"revocation_code",
				"shared_secret",
				"token_gid",
				"identity_secret",
				"uri",
				"device_id",
				"secret_1",
				"tokens",
				"new",
				"from_reader",
				"from_file",
				"set_tokens",
				"is_logged_in",
				"generate_code",
				"remove_authenticator",
			][..],
		),
	] {
		let names: Vec<_> = public_name
			.captures_iter(source)
			.map(|c| c.get(1).or_else(|| c.get(2)).unwrap().as_str())
			.collect();
		for name in expected {
			assert!(names.contains(name), "test invariant failed");
		}
	}
	let code = production_code();
	for (name, variants) in [
		(
			"LoginError",
			&[
				"BadCredentials",
				"TooManyAttempts",
				"SessionExpired",
				"UnknownEResult",
				"AuthAlreadyStarted",
				"TransportError",
				"NetworkFailure",
				"OtherFailure",
			][..],
		),
		(
			"UpdateAuthSessionError",
			&[
				"SessionNotStarted",
				"InvalidGuardType",
				"TooManyAttempts",
				"SessionExpired",
				"IncorrectSteamGuardCode",
				"DuplicateRequest",
				"UnknownEResult",
				"TransportError",
				"NetworkFailure",
				"OtherFailure",
			][..],
		),
	] {
		let body = block(&code, &format!("pub enum {name}"));
		for variant in variants {
			assert!(
				Regex::new(&format!(r"(?m)^\s*{variant}\b"))
					.unwrap()
					.is_match(body),
				"sensitive assertion failed"
			);
		}
	}
	for export in [
		"pub use accountlinker::{AccountLinkError, AccountLinker, FinalizeLinkError};",
		"pub use api_responses::AllowedConfirmation;",
		"pub use approver::{ApproverError, LoginApprover};",
		"pub use confirmation::*;",
		"pub use secrecy::{ExposeSecret, SecretString};",
	] {
		assert!(
			include_str!("../src/lib.rs").contains(export),
			"upstream re-export removed"
		);
	}
}

fn credentials_steps(result: EResult, steam_id: u64) -> Vec<Step> {
	let mut rsa = RsaResponse::new();
	rsa.set_publickey_exp("010001".to_owned());
	rsa.set_publickey_mod("ff".repeat(128));
	rsa.set_timestamp(1);
	let mut response = CredentialsResponse::new();
	response.set_client_id(123);
	response.set_request_id(b"request-id-canary".to_vec());
	response.set_steamid(steam_id);
	response.set_extended_error_message("extended-error-message-canary".to_owned());
	vec![
		Step::response::<RsaRequest, _>(EResult::OK, rsa),
		Step::response::<CredentialsRequest, _>(result, response),
	]
}

#[test]
fn started_steam_id_exposes_credentials_subject_before_code_or_poll() {
	let (mut login, transport) = new_login(credentials_steps(EResult::OK, 76561198000000001));
	assert_eq!(login.started_steam_id(), None);
	login
		.begin_auth_via_credentials("synthetic-account", "password-canary")
		.unwrap();
	assert_eq!(login.started_steam_id(), Some(76561198000000001));
	// No submit/poll is scripted: the accessor must not make another request.
	assert_eq!(login.started_steam_id(), Some(76561198000000001));
	transport.assert_finished();
}

#[test]
fn started_steam_id_is_none_without_auth_or_for_qr() {
	let (login, transport) = new_login(vec![]);
	assert_eq!(login.started_steam_id(), None);
	transport.assert_finished();
	let (login, transport) = started_login(None, vec![]);
	assert_eq!(login.started_steam_id(), None);
	transport.assert_finished();
}

#[test]
fn login_eresult_preserves_curated_variants_and_redacts_server_messages() {
	for (result, expected) in [
		(
			EResult::RateLimitExceeded,
			LoginError::TooManyAttempts(EResult::RateLimitExceeded),
		),
		(
			EResult::AccountLoginDeniedThrottle,
			LoginError::TooManyAttempts(EResult::AccountLoginDeniedThrottle),
		),
		(
			EResult::Expired,
			LoginError::SessionExpired(EResult::Expired),
		),
		(
			EResult::FileNotFound,
			LoginError::SessionExpired(EResult::FileNotFound),
		),
		(EResult::InvalidPassword, LoginError::BadCredentials),
		(
			EResult::TwoFactorCodeMismatch,
			LoginError::UnknownEResult(EResult::TwoFactorCodeMismatch),
		),
		(
			EResult::DuplicateRequest,
			LoginError::UnknownEResult(EResult::DuplicateRequest),
		),
		(
			EResult::AccessDenied,
			LoginError::UnknownEResult(EResult::AccessDenied),
		),
		(
			EResult::Unknown(987654),
			LoginError::UnknownEResult(EResult::Unknown(987654)),
		),
	] {
		let (mut login, transport) = new_login(credentials_steps(result, 76561198000000001));
		let error = login
			.begin_auth_via_credentials("synthetic-account", "password-canary")
			.unwrap_err();
		for error in [error, LoginError::from(result)] {
			assert!(error.eresult() == Some(result), "Steam result was lost");
			assert!(
				std::mem::discriminant(&error) == std::mem::discriminant(&expected),
				"curated variant changed"
			);
			assert_redacted(&error, "extended-error-message-canary");
		}
		assert_eq!(login.started_steam_id(), None);
		transport.assert_finished();
	}
}

#[test]
fn update_auth_eresult_preserves_curated_variants_and_redacts_server_messages() {
	for (result, expected) in [
		(
			EResult::RateLimitExceeded,
			UpdateAuthSessionError::TooManyAttempts(EResult::RateLimitExceeded),
		),
		(
			EResult::AccountLoginDeniedThrottle,
			UpdateAuthSessionError::TooManyAttempts(EResult::AccountLoginDeniedThrottle),
		),
		(
			EResult::Expired,
			UpdateAuthSessionError::SessionExpired(EResult::Expired),
		),
		(
			EResult::FileNotFound,
			UpdateAuthSessionError::SessionExpired(EResult::FileNotFound),
		),
		(
			EResult::TwoFactorCodeMismatch,
			UpdateAuthSessionError::IncorrectSteamGuardCode,
		),
		(
			EResult::DuplicateRequest,
			UpdateAuthSessionError::DuplicateRequest,
		),
		(
			EResult::InvalidPassword,
			UpdateAuthSessionError::UnknownEResult(EResult::InvalidPassword),
		),
		(
			EResult::AccessDenied,
			UpdateAuthSessionError::UnknownEResult(EResult::AccessDenied),
		),
		(
			EResult::Unknown(987654),
			UpdateAuthSessionError::UnknownEResult(EResult::Unknown(987654)),
		),
	] {
		let mut steps = credentials_steps(EResult::OK, 76561198000000001);
		steps.push(Step::response::<UpdateRequest, _>(
			result,
			UpdateResponse::new(),
		));
		let (mut login, transport) = new_login(steps);
		login
			.begin_auth_via_credentials("synthetic-account", "password-canary")
			.unwrap();
		let error = login
			.submit_steam_guard_code(
				EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode,
				"guard-code-canary".to_owned(),
			)
			.unwrap_err();
		for error in [error, UpdateAuthSessionError::from(result)] {
			assert!(error.eresult() == Some(result), "Steam result was lost");
			assert!(
				std::mem::discriminant(&error) == std::mem::discriminant(&expected),
				"curated variant changed"
			);
			assert_redacted(&error, "extended-error-message-canary");
		}
		transport.assert_finished();
	}
}

#[test]
fn login_and_update_local_and_transport_errors_have_no_eresult() {
	// Building an invalid URL fails without DNS or sockets.
	let network = || {
		reqwest::blocking::Client::new()
			.get("invalid-url")
			.build()
			.unwrap_err()
	};
	for error in [
		LoginError::SessionNotStarted,
		LoginError::AuthAlreadyStarted,
		LoginError::UnknownOutcome,
		LoginError::TransportError(TransportError::Unauthorized),
		LoginError::NetworkFailure(network().into()),
		LoginError::OtherFailure(anyhow::anyhow!("other-failure-canary")),
	] {
		assert!(
			error.eresult().is_none(),
			"non-Steam error has a Steam result"
		);
	}
	for error in [
		UpdateAuthSessionError::SessionNotStarted,
		UpdateAuthSessionError::InvalidGuardType,
		UpdateAuthSessionError::TransportError(TransportError::Unauthorized),
		UpdateAuthSessionError::NetworkFailure(network().into()),
		UpdateAuthSessionError::OtherFailure(anyhow::anyhow!("other-failure-canary")),
	] {
		assert!(
			error.eresult().is_none(),
			"non-Steam error has a Steam result"
		);
	}
}
