use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use protobuf::MessageFull;
use std::{cell::Cell, rc::Rc};
use steamguard::{
	protobufs::{service_phone::*, service_twofactor::*},
	steamapi::{ApiRequest, ApiResponse, BuildableRequest, EResult, PhoneClient, TwoFactorClient},
	token::Tokens,
	transport::{Transport, TransportError},
	AccountLinker, ExposeSecret, TransferError,
};

const SUBJECT: u64 = 76561198000000001;

#[derive(Clone)]
struct FakeTransport {
	request_type: protobuf::reflect::MessageDescriptor,
	response_type: protobuf::reflect::MessageDescriptor,
	result: EResult,
	body: Vec<u8>,
	calls: Rc<Cell<usize>>,
}

impl FakeTransport {
	fn new<Req: MessageFull, Res: MessageFull>(result: EResult, body: Res) -> Self {
		Self {
			request_type: Req::descriptor(),
			response_type: Res::descriptor(),
			result,
			body: body.write_to_bytes().unwrap(),
			calls: Rc::default(),
		}
	}

	fn assert_finished(&self) {
		assert!((self.calls.get()) == (1), "test invariant failed");
	}
}

impl Transport for FakeTransport {
	fn send_request<Req: BuildableRequest + MessageFull, Res: MessageFull>(
		&self,
		_req: ApiRequest<Req>,
	) -> Result<ApiResponse<Res>, TransportError> {
		assert!(
			(self.calls.replace(self.calls.get() + 1)) == (0),
			"test invariant failed"
		);
		assert!(
			(Req::descriptor()) == (self.request_type),
			"test invariant failed"
		);
		assert!(
			(Res::descriptor()) == (self.response_type),
			"test invariant failed"
		);
		Ok(ApiResponse::new(
			self.result,
			Some("server-message-canary".into()),
			Res::parse_from_bytes(&self.body)?,
		))
	}

	fn close(&mut self) {}
}

fn tokens() -> Tokens {
	let payload = serde_json::json!({
		"exp": 0, "iat": 0, "iss": "canary", "aud": [],
		"sub": SUBJECT.to_string(), "jti": "canary"
	});
	Tokens::new(
		format!(
			"e30.{}.signature-canary",
			URL_SAFE_NO_PAD.encode(payload.to_string())
		),
		"refresh-canary".to_owned(),
	)
}

fn replacement(
	success: Option<bool>,
	status: Option<i32>,
	subject: Option<u64>,
) -> CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Response {
	let mut token = CRemoveAuthenticatorViaChallengeContinue_Replacement_Token::new();
	token.set_shared_secret(vec![42; 20]);
	token.set_identity_secret(vec![43; 20]);
	token.set_secret_1(vec![44; 20]);
	token.set_account_name("account-canary".into());
	token.set_serial_number(123);
	token.set_revocation_code("revocation-canary".into());
	token.set_uri("uri-canary".into());
	token.set_token_gid("gid-canary".into());
	token.status = status;
	token.steamid = subject;
	let mut response = CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Response::new();
	response.success = success;
	response.replacement_token = protobuf::MessageField::some(token);
	response
}

fn transfer_transport(
	result: EResult,
	body: CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Response,
) -> FakeTransport {
	FakeTransport::new::<CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Request, _>(
		result, body,
	)
}

#[test]
fn checked_transfer_accepts_and_preserves_optional_metadata() {
	for status in [
		None,
		Some(0),
		Some(1),
		Some(2),
		Some(-12345),
		Some(i32::MAX),
	] {
		for subject in [None, Some(SUBJECT)] {
			let transport =
				transfer_transport(EResult::OK, replacement(Some(true), status, subject));
			let finish = AccountLinker::new(transport.clone(), tokens())
				.transfer_finish_checked("sms-canary")
				.unwrap();
			assert!(finish.accepted, "test invariant failed");
			assert!(
				(finish.replacement_status) == (status),
				"test invariant failed"
			);
			assert!((finish.steam_id) == (subject), "test invariant failed");
			assert!(
				(finish.account.steam_id) == (SUBJECT),
				"test invariant failed"
			);
			assert!(
				finish.account.revocation_code.expose_secret() == "revocation-canary",
				"test invariant failed"
			);
			assert!(
				finish.account.identity_secret.expose_secret() == "KysrKysrKysrKysrKysrKysrKys=",
				"test invariant failed"
			);
			assert!(
				finish.account.device_id.starts_with("android:"),
				"test invariant failed"
			);
			assert!(
				!format!("{finish:?} {finish:#?}").contains("canary"),
				"test invariant failed"
			);
			assert!(
				!format!("{finish:?}").contains(&SUBJECT.to_string()),
				"test invariant failed"
			);
			transport.assert_finished();
		}
	}
}

#[test]
fn checked_transfer_rejects_false_before_reading_secrets() {
	for status in [None, Some(0), Some(1), Some(2), Some(-12345)] {
		for with_replacement in [false, true] {
			let mut body = replacement(Some(false), status, Some(SUBJECT));
			if with_replacement {
				body.replacement_token
					.as_mut()
					.unwrap()
					.clear_shared_secret();
			} else {
				body.replacement_token = protobuf::MessageField::none();
			}
			let transport = transfer_transport(EResult::OK, body);
			let error = AccountLinker::new(transport.clone(), tokens())
				.transfer_finish_checked("sms-canary")
				.unwrap_err();
			assert!(
				matches!(error, TransferError::NotAccepted { status: actual } if actual == if with_replacement { status } else { None }),
				"test invariant failed"
			);
			assert!(
				!format!("{error} {error:?}").contains("canary"),
				"test invariant failed"
			);
			transport.assert_finished();
		}
	}
}

#[test]
fn checked_transfer_rejects_foreign_subject_before_reading_secrets() {
	for subject in [0, SUBJECT + 1, u64::MAX] {
		let mut body = replacement(Some(true), Some(1), Some(subject));
		body.replacement_token
			.as_mut()
			.unwrap()
			.clear_shared_secret();
		let transport = transfer_transport(EResult::OK, body);
		let error = AccountLinker::new(transport.clone(), tokens())
			.transfer_finish_checked("sms-canary")
			.unwrap_err();
		assert!(
			matches!(error, TransferError::SubjectMismatch),
			"test invariant failed"
		);
		assert!(
			!format!("{error} {error:?}").contains(&subject.to_string()),
			"test invariant failed"
		);
		transport.assert_finished();
	}
}

#[test]
fn checked_transfer_distinguishes_missing_acceptance_and_replacement() {
	for success in [None, Some(true)] {
		let mut body = CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Response::new();
		body.success = success;
		let transport = transfer_transport(EResult::OK, body);
		let error = AccountLinker::new(transport.clone(), tokens())
			.transfer_finish_checked("sms-canary")
			.unwrap_err();
		assert!(
			matches!(
				(success, error),
				(None, TransferError::MissingAcceptance)
					| (Some(true), TransferError::MissingReplacementToken)
			),
			"test invariant failed"
		);
		transport.assert_finished();
	}
	let transport = transfer_transport(EResult::OK, replacement(None, Some(1), Some(SUBJECT)));
	assert!(
		matches!(
			AccountLinker::new(transport.clone(), tokens()).transfer_finish_checked("sms-canary"),
			Err(TransferError::MissingAcceptance)
		),
		"test invariant failed"
	);
	transport.assert_finished();
}

#[test]
fn checked_transfer_preserves_outer_rejections() {
	for result in [
		EResult::SMSCodeFailed,
		EResult::Fail,
		EResult::AccessDenied,
		EResult::Unknown(-9876),
	] {
		for success in [Some(true), Some(false), None] {
			let transport =
				transfer_transport(result, replacement(success, Some(42), Some(SUBJECT + 1)));
			let error = AccountLinker::new(transport.clone(), tokens())
				.transfer_finish_checked("sms-canary")
				.unwrap_err();
			assert!(
				match error {
					TransferError::BadSmsCode => result == EResult::SMSCodeFailed,
					TransferError::GenericFailure => result == EResult::Fail,
					TransferError::UnknownEResult(actual) => actual == result,
					_ => false,
				},
				"test invariant failed"
			);
			transport.assert_finished();
		}
	}
}

#[test]
fn legacy_transfer_still_ignores_body_acceptance_status_and_subject() {
	for success in [None, Some(false), Some(true)] {
		let transport = transfer_transport(
			EResult::OK,
			replacement(success, Some(-12345), Some(SUBJECT + 1)),
		);
		let account = AccountLinker::new(transport.clone(), tokens())
			.transfer_finish("sms-canary")
			.unwrap();
		assert!((account.steam_id) == (SUBJECT), "test invariant failed");
		transport.assert_finished();
	}
}

#[test]
fn phone_wait_seconds_preserve_absent_zero_and_rejection_values() {
	for result in [
		EResult::OK,
		EResult::RateLimitExceeded,
		EResult::Unknown(-4321),
	] {
		for awaiting in [None, Some(false), Some(true)] {
			for seconds in [None, Some(0), Some(17), Some(u32::MAX)] {
				let mut body = CPhone_IsAccountWaitingForEmailConfirmation_Response::new();
				body.awaiting_email_confirmation = awaiting;
				body.seconds_to_wait = seconds;
				let transport = FakeTransport::new::<
					CPhone_IsAccountWaitingForEmailConfirmation_Request,
					_,
				>(result, body);
				let response = PhoneClient::new(transport.clone())
					.is_account_waiting_for_email_confirmation(
						CPhone_IsAccountWaitingForEmailConfirmation_Request::new(),
						tokens().access_token(),
					)
					.unwrap();
				assert!(
					(response.seconds_to_wait()) == (seconds),
					"test invariant failed"
				);
				assert!((response.result()) == (result), "test invariant failed");
				assert!(response.http_status().is_none(), "test invariant failed");
				let body = response.into_response_data();
				assert!((body.seconds_to_wait) == (seconds), "test invariant failed");
				assert!(
					(body.awaiting_email_confirmation) == (awaiting),
					"test invariant failed"
				);
				transport.assert_finished();
			}
		}
	}
}

#[test]
fn other_phone_and_transfer_responses_preserve_typed_rejections_without_counts() {
	macro_rules! check {
		($client:ident, $method:ident, $req:ty, $res:ty) => {
			for result in [
				EResult::OK,
				EResult::Pending,
				EResult::SMSCodeFailed,
				EResult::RateLimitExceeded,
			] {
				let transport = FakeTransport::new::<$req, _>(result, <$res>::new());
				let response = $client::new(transport.clone())
					.$method(<$req>::new(), tokens().access_token())
					.unwrap();
				assert!((response.result()) == (result), "test invariant failed");
				assert!(response.http_status().is_none(), "test invariant failed");
				transport.assert_finished();
			}
		};
	}
	check!(
		PhoneClient,
		set_account_phone_number,
		CPhone_SetAccountPhoneNumber_Request,
		CPhone_SetAccountPhoneNumber_Response
	);
	check!(
		PhoneClient,
		send_phone_verification_code,
		CPhone_SendPhoneVerificationCode_Request,
		CPhone_SendPhoneVerificationCode_Response
	);
	check!(
		PhoneClient,
		verify_account_phone_with_code,
		CPhone_VerifyAccountPhoneWithCode_Request,
		CPhone_VerifyAccountPhoneWithCode_Response
	);
	check!(
		TwoFactorClient,
		remove_authenticator_via_challenge_start,
		CTwoFactor_RemoveAuthenticatorViaChallengeStart_Request,
		CTwoFactor_RemoveAuthenticatorViaChallengeStart_Response
	);
	check!(
		TwoFactorClient,
		remove_authenticator_via_challenge_continue,
		CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Request,
		CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Response
	);
}

#[test]
fn protocol_inventory_has_only_email_wait_seconds_and_no_attempt_counts() {
	// Review this inventory when updating protobufs: newly supplied counts/delays
	// must become typed product facts, never inferred from result codes or text.
	fn fields<M: MessageFull>(expected: &[&str]) {
		let names: Vec<_> = M::descriptor()
			.fields()
			.map(|f| f.name().to_owned())
			.collect();
		assert!((names) == (expected), "test invariant failed");
	}
	fields::<CTwoFactor_RemoveAuthenticatorViaChallengeStart_Response>(&["success"]);
	fields::<CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Response>(&[
		"success",
		"replacement_token",
	]);
	fields::<CRemoveAuthenticatorViaChallengeContinue_Replacement_Token>(&[
		"shared_secret",
		"serial_number",
		"revocation_code",
		"uri",
		"server_time",
		"account_name",
		"token_gid",
		"identity_secret",
		"secret_1",
		"status",
		"steamguard_scheme",
		"steamid",
	]);
	fields::<CPhone_SetAccountPhoneNumber_Response>(&[
		"confirmation_email_address",
		"phone_number_formatted",
	]);
	fields::<CPhone_IsAccountWaitingForEmailConfirmation_Response>(&[
		"awaiting_email_confirmation",
		"seconds_to_wait",
	]);
	fields::<CPhone_SendPhoneVerificationCode_Response>(&[]);
	fields::<CPhone_VerifyAccountPhoneWithCode_Response>(&[]);
}
