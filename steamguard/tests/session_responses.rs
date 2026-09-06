use protobuf::MessageFull;
use std::{cell::Cell, error::Error, rc::Rc};
use steamguard::{
	accountlinker::{AccountLinker, QueryStatusError},
	protobufs::{
		service_twofactor::{
			CTwoFactor_Status_Request as StatusRequest,
			CTwoFactor_Status_Response as StatusResponse,
		},
		steammessages_auth_steamclient::{
			CAuthentication_AccessToken_GenerateForApp_Request as RefreshRequest,
			CAuthentication_AccessToken_GenerateForApp_Response as RefreshResponse,
		},
	},
	refresher::{RefreshError, TokenRefresher},
	steamapi::{ApiRequest, ApiResponse, AuthenticationClient, BuildableRequest, EResult},
	token::{Jwt, Tokens},
	transport::{Transport, TransportError},
	SteamGuardAccount,
};

const ACCESS: &str = "replacement-access-token-canary";
const REFRESH: &str = "replacement-refresh-token-canary";
const OLD_REFRESH: &str = "original-refresh-token-canary";
const BODY: &str = "body-canary password-canary nonce-canary";

#[derive(Clone)]
struct FakeTransport {
	request_type: protobuf::reflect::MessageDescriptor,
	response_type: protobuf::reflect::MessageDescriptor,
	result: EResult,
	body: Vec<u8>,
	calls: Rc<Cell<usize>>,
}

impl FakeTransport {
	fn new<Req: MessageFull, Res: MessageFull>(result: EResult, response: Res) -> Self {
		Self {
			request_type: Req::descriptor(),
			response_type: Res::descriptor(),
			result,
			body: response.write_to_bytes().unwrap(),
			calls: Rc::default(),
		}
	}

	fn assert_finished(&self) {
		assert_eq!(self.calls.get(), 1, "expected exactly one API call");
	}
}

impl Transport for FakeTransport {
	fn send_request<Req: BuildableRequest + MessageFull, Res: MessageFull>(
		&self,
		_req: ApiRequest<Req>,
	) -> Result<ApiResponse<Res>, TransportError> {
		assert_eq!(
			self.calls.replace(self.calls.get() + 1),
			0,
			"unexpected API call"
		);
		assert_eq!(Req::descriptor(), self.request_type);
		assert_eq!(Res::descriptor(), self.response_type);
		Ok(ApiResponse::new(
			self.result,
			Some(BODY.to_owned()),
			Res::parse_from_bytes(&self.body)?,
		))
	}

	fn close(&mut self) {}
}

fn tokens() -> Tokens {
	Tokens::new(
		"original-access-token-canary".to_owned(),
		OLD_REFRESH.to_owned(),
	)
}

fn account() -> SteamGuardAccount {
	SteamGuardAccount {
		steam_id: 76561198000000001,
		..SteamGuardAccount::default()
	}
}

fn status_response(state: u32) -> StatusResponse {
	let mut response = StatusResponse::new();
	response.set_state(state);
	response.set_token_gid("token-gid-canary".to_owned());
	response.set_revocation_attempts_remaining(5);
	response.set_steamguard_scheme(2);
	response
}

fn refresher(transport: FakeTransport) -> TokenRefresher<FakeTransport> {
	TokenRefresher::new(AuthenticationClient::new(transport))
}

fn assert_safe_error(error: &(dyn Error + 'static)) {
	let mut current = Some(error);
	while let Some(error) = current {
		let output = format!("{error} {error:?}");
		assert!(!output.contains("canary"));
		current = error.source();
	}
}

#[test]
fn unknown_eresult_preserves_numeric_code() {
	for code in [4, 987654, -1, i32::MAX, i32::MIN] {
		let result = EResult::from(code);
		assert_eq!(result, EResult::Unknown(code));
		assert_eq!(result.code(), code);
		assert_eq!(i32::from(result), code);
		let response = ApiResponse::new(result, Some(BODY.to_owned()), tokens());
		assert_eq!(response.result(), EResult::Unknown(code));
		let debug = format!("{response:?}");
		assert!(debug.contains(&code.to_string()));
		assert!(!debug.contains("canary"));

		let transport = FakeTransport::new::<StatusRequest, _>(result, StatusResponse::new());
		let error = AccountLinker::new(transport.clone(), tokens())
			.query_status_checked(&account())
			.unwrap_err();
		assert!(matches!(error, QueryStatusError::SteamRejected(value) if value == result));
		assert_safe_error(&error);
		transport.assert_finished();

		let transport = FakeTransport::new::<StatusRequest, _>(result, StatusResponse::new());
		let error = AccountLinker::new(transport.clone(), tokens())
			.query_status(&account())
			.unwrap_err();
		assert_safe_error(&error);
		let TransportError::Unknown(error) = error else {
			panic!("expected a typed status error")
		};
		assert!(
			matches!(error.downcast_ref::<QueryStatusError>(), Some(QueryStatusError::SteamRejected(value)) if *value == result)
		);
		transport.assert_finished();

		let transport = FakeTransport::new::<RefreshRequest, _>(result, RefreshResponse::new());
		let error = refresher(transport.clone())
			.refresh_tokens(account().steam_id, &tokens())
			.unwrap_err();
		assert!(matches!(error, RefreshError::SteamRejected(value) if value == result));
		assert_safe_error(&error);
		transport.assert_finished();

		let transport = FakeTransport::new::<RefreshRequest, _>(result, RefreshResponse::new());
		let error = refresher(transport.clone())
			.refresh(account().steam_id, &tokens())
			.unwrap_err();
		assert!(
			matches!(error.downcast_ref::<RefreshError>(), Some(RefreshError::SteamRejected(value)) if *value == result)
		);
		assert_safe_error(error.as_ref());
		transport.assert_finished();
	}
	for (code, result) in [
		(0, EResult::Invalid),
		(1, EResult::OK),
		(2, EResult::Fail),
		(127, EResult::PhoneNumberIsVOIP),
	] {
		assert_eq!(EResult::from(code), result);
		assert_eq!(result.code(), code);
	}
}

#[test]
fn status_error_body_is_not_state_zero() {
	// Preserve the upstream method signature, including transport error matching.
	let _: fn(
		&AccountLinker<FakeTransport>,
		&SteamGuardAccount,
	) -> Result<StatusResponse, TransportError> = AccountLinker::query_status;
	for result in [
		EResult::Fail,
		EResult::AccessDenied,
		EResult::Invalid,
		EResult::Unknown(123456),
	] {
		for body in [
			StatusResponse::new(),
			status_response(0),
			status_response(1),
		] {
			let transport = FakeTransport::new::<StatusRequest, _>(result, body);
			let error = AccountLinker::new(transport.clone(), tokens())
				.query_status(&account())
				.unwrap_err();
			assert_safe_error(&error);
			let TransportError::Unknown(error) = error else {
				panic!("expected a typed status error")
			};
			assert!(
				matches!(error.downcast_ref::<QueryStatusError>(), Some(QueryStatusError::SteamRejected(value)) if *value == result)
			);
			transport.assert_finished();
		}
	}
	let mut incomplete = vec![StatusResponse::new()];
	for missing in [
		"state",
		"token_gid",
		"revocation_attempts_remaining",
		"steamguard_scheme",
	] {
		let mut response = status_response(1);
		match missing {
			"state" => response.clear_state(),
			"token_gid" => response.clear_token_gid(),
			"revocation_attempts_remaining" => response.clear_revocation_attempts_remaining(),
			"steamguard_scheme" => response.clear_steamguard_scheme(),
			_ => unreachable!(),
		}
		incomplete.push(response);
	}
	for body in incomplete {
		let transport = FakeTransport::new::<StatusRequest, _>(EResult::OK, body.clone());
		let error = AccountLinker::new(transport.clone(), tokens())
			.query_status_checked(&account())
			.unwrap_err();
		assert!(matches!(error, QueryStatusError::MalformedResponse));
		assert_safe_error(&error);
		transport.assert_finished();
		let transport = FakeTransport::new::<StatusRequest, _>(EResult::OK, body);
		let error = AccountLinker::new(transport.clone(), tokens())
			.query_status(&account())
			.unwrap_err();
		assert_safe_error(&error);
		let TransportError::Unknown(error) = error else {
			panic!("expected a typed format error")
		};
		assert!(matches!(
			error.downcast_ref::<QueryStatusError>(),
			Some(QueryStatusError::MalformedResponse)
		));
		transport.assert_finished();
	}
	// An explicit state zero is valid only in a successful, complete status response.
	for state in [0, 1, 42] {
		let expected = status_response(state);
		let transport = FakeTransport::new::<StatusRequest, _>(EResult::OK, expected.clone());
		let response = AccountLinker::new(transport.clone(), tokens())
			.query_status(&account())
			.unwrap();
		assert_eq!(response, expected);
		transport.assert_finished();
	}
}

#[test]
fn refresh_returns_new_refresh_token_when_present() {
	let _: fn(&mut TokenRefresher<FakeTransport>, u64, &Tokens) -> anyhow::Result<Jwt> =
		TokenRefresher::refresh;
	for replacement in [Some(REFRESH), None] {
		let mut response = RefreshResponse::new();
		response.set_access_token(ACCESS.to_owned());
		response.refresh_token = replacement.map(str::to_owned);
		let transport = FakeTransport::new::<RefreshRequest, _>(EResult::OK, response);
		let original = tokens();
		let updated = refresher(transport.clone())
			.refresh_tokens(account().steam_id, &original)
			.unwrap();
		assert!(
			updated.access_token().expose_secret() == ACCESS,
			"secret values differ"
		);
		assert!(
			updated.refresh_token().expose_secret() == replacement.unwrap_or(OLD_REFRESH),
			"secret values differ"
		);
		assert!(
			original.refresh_token().expose_secret() == OLD_REFRESH,
			"secret values differ"
		);
		assert!(!format!("{updated:?}").contains("canary"));
		transport.assert_finished();
	}
	for (access, refresh) in [
		(None, Some(REFRESH)),
		(Some(""), Some(REFRESH)),
		(Some(ACCESS), Some("")),
	] {
		let mut response = RefreshResponse::new();
		response.access_token = access.map(str::to_owned);
		response.refresh_token = refresh.map(str::to_owned);
		let transport = FakeTransport::new::<RefreshRequest, _>(EResult::OK, response);
		let error = refresher(transport.clone())
			.refresh_tokens(account().steam_id, &tokens())
			.unwrap_err();
		assert!(matches!(error, RefreshError::MalformedResponse));
		assert_safe_error(&error);
		transport.assert_finished();
	}
	let mut response = RefreshResponse::new();
	response.set_access_token(ACCESS.to_owned());
	let transport = FakeTransport::new::<RefreshRequest, _>(EResult::OK, response.clone());
	assert!(
		refresher(transport.clone())
			.refresh(account().steam_id, &tokens())
			.unwrap()
			.expose_secret()
			== ACCESS,
		"secret values differ"
	);
	transport.assert_finished();
	let transport = FakeTransport::new::<RefreshRequest, _>(EResult::Expired, response);
	assert!(matches!(
		refresher(transport.clone()).refresh_tokens(account().steam_id, &tokens()),
		Err(RefreshError::SteamRejected(EResult::Expired))
	));
	transport.assert_finished();
}
