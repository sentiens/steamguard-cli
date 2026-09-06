use protobuf::MessageFull;
use serde_json::json;
use std::{cell::Cell, cell::RefCell, collections::VecDeque, error::Error, rc::Rc};
use steamguard::{
	steamapi::{ApiRequest, ApiResponse, BuildableRequest},
	token::Tokens,
	transport::{NetworkError, Transport, TransportError, WebRequest, WebResponse},
	Confirmation, ConfirmationId, ConfirmationListResponse, ConfirmationType, Confirmer,
	ConfirmerError, SendConfirmationResponse, SteamGuardAccount,
};

const COMPLETE: &str = include_str!("../src/fixtures/confirmations/list-well-formed.json");
const TRUNCATED: &str = include_str!("../src/fixtures/confirmations/list-truncated.json");
const UNKNOWN_TYPE: &str = include_str!("../src/fixtures/confirmations/list-unknown-type.json");
const MINIMAL: &str = include_str!("fixtures/confirmations/list-minimal.json");
const SECRETS: &str =
	"nonce-canary access-token-canary refresh-token-canary password-canary body-canary";

struct RecordedRequest {
	endpoint: String,
	query: Vec<(String, String)>,
	form_body: Option<String>,
}

#[derive(Clone)]
struct FakeTransport {
	bodies: Rc<RefCell<VecDeque<String>>>,
	requests: Rc<RefCell<Vec<RecordedRequest>>>,
	api_requests: Rc<Cell<usize>>,
}

impl FakeTransport {
	fn new(bodies: impl IntoIterator<Item = String>) -> Self {
		Self {
			bodies: Rc::new(RefCell::new(bodies.into_iter().collect())),
			requests: Rc::default(),
			api_requests: Rc::default(),
		}
	}

	fn assert_finished(&self) {
		assert!(self.bodies.borrow().is_empty(), "missing web request");
		assert_eq!(self.api_requests.get(), 0, "unexpected Steam time request");
	}
}

impl Transport for FakeTransport {
	fn send_request<Req: BuildableRequest + MessageFull, Res: MessageFull>(
		&self,
		_req: ApiRequest<Req>,
	) -> Result<ApiResponse<Res>, TransportError> {
		self.api_requests.set(self.api_requests.get() + 1);
		Err(TransportError::Unauthorized)
	}

	fn send_web(&self, request: WebRequest<'_>) -> Result<WebResponse, NetworkError> {
		assert_safe_text(&format!("{request:?}"));
		self.requests.borrow_mut().push(RecordedRequest {
			endpoint: format!("{:?}", request.endpoint()),
			query: request
				.query()
				.iter()
				.map(|(key, value)| (key.to_string(), value.to_string()))
				.collect(),
			form_body: request.form_body().map(str::to_owned),
		});
		Ok(WebResponse::new(
			200,
			self.bodies
				.borrow_mut()
				.pop_front()
				.expect("unexpected web request"),
		))
	}

	fn close(&mut self) {}
}

fn account() -> SteamGuardAccount {
	SteamGuardAccount {
		steam_id: 76561198000000001,
		device_id: "android:device-id-canary".to_owned(),
		identity_secret: "GQP46b73Ws7gr8GmZFR0sDuau5c=".to_owned().into(),
		tokens: Some(Tokens::new(
			"access-token-canary".to_owned(),
			"refresh-token-canary".to_owned(),
		)),
		..SteamGuardAccount::default()
	}
}

fn get_list(body: impl Into<String>) -> Result<Vec<Confirmation>, ConfirmerError> {
	let transport = FakeTransport::new([body.into()]);
	let account = account();
	let result = Confirmer::new(transport.clone(), &account)
		.with_server_time(1617591917)
		.get_confirmations();
	transport.assert_finished();
	assert_eq!(transport.requests.borrow()[0].endpoint, "confirmation-list");
	result
}

fn assert_safe_text(output: &str) {
	for canary in SECRETS.split_whitespace().chain([
		"device-id-canary",
		"GQP46b73Ws7gr8GmZFR0sDuau5c=",
		"://",
	]) {
		assert!(!output.contains(canary), "secret appeared in diagnostics");
	}
}

fn assert_safe_error(error: &(dyn Error + 'static)) {
	// Raw typed causes remain available internally; only public diagnostics may be formatted.
	for output in [
		format!("{error}"),
		format!("{error:#}"),
		format!("{error:?}"),
		format!("{error:#?}"),
	] {
		assert_safe_text(&output);
	}
}

#[test]
fn malformed_confirmation_anyhow_diagnostics_are_redacted() {
	for body in [
		r#"{"success":"password-canary"}"#,
		r#"{"success":true,"conf":[{"type":"nonce-canary"}]}"#,
	] {
		let error =
			anyhow::Error::new(get_list(body).unwrap_err()).context("checking confirmations");
		for output in [
			format!("{error:?}"),
			format!("{error:#}"),
			format!("{error:#?}"),
		] {
			assert_safe_text(&output);
		}
		let original = error
			.downcast_ref::<ConfirmerError>()
			.unwrap()
			.raw_source()
			.unwrap();
		assert!(
			original.is::<serde_path_to_error::Error<serde_json::Error>>(),
			"typed parse cause was lost"
		);
	}
}

#[test]
fn malformed_confirmation_details_anyhow_diagnostics_are_redacted() {
	let transport =
		FakeTransport::new([r#"{"success":"password-canary","html":"cookie-canary"}"#.to_owned()]);
	let account = account();
	let error = Confirmer::new(transport.clone(), &account)
		.with_server_time(0)
		.get_confirmation_details(ConfirmationId::new("id", "nonce-canary"))
		.unwrap_err();
	for output in [
		format!("{error:?}"),
		format!("{error:#}"),
		format!("{error:#?}"),
	] {
		assert_safe_text(&output);
	}
	assert!(error.downcast_ref::<ConfirmerError>().is_some());
	transport.assert_finished();
}

#[test]
fn wrapped_confirmation_causes_are_redacted() {
	struct InvalidQuery;
	impl serde::Serialize for InvalidQuery {
		fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
			Err(serde::ser::Error::custom(SECRETS))
		}
	}
	let request_error = reqwest::blocking::Client::builder()
		.no_proxy()
		.build()
		.unwrap()
		.get("https://example.invalid")
		.query(&InvalidQuery)
		.build()
		.unwrap_err();
	for cause in [
		ConfirmerError::from(request_error),
		ConfirmerError::Unknown(anyhow::anyhow!(SECRETS).context("local context")),
	] {
		let error = anyhow::Error::new(cause).context("checking confirmations");
		for output in [
			format!("{error:?}"),
			format!("{error:#}"),
			format!("{error:#?}"),
		] {
			assert_safe_text(&output);
		}
	}
}

#[test]
fn positional_confirmation_envelopes_are_rejected() {
	assert!(
		matches!(
			get_list("[true,null,[],null]"),
			Err(ConfirmerError::DeserializeError(_))
		),
		"positional list envelope accepted"
	);
	let transport = FakeTransport::new(
		["[true,null,null]", "[true,null,null]", "[true,\"html\"]"].map(str::to_owned),
	);
	let account = account();
	let confirmer = Confirmer::new(transport.clone(), &account).with_server_time(0);
	let item = get_list(MINIMAL).unwrap().remove(0);
	assert!(
		matches!(
			confirmer.accept_confirmation(&item),
			Err(ConfirmerError::DeserializeError(_))
		),
		"positional action envelope accepted"
	);
	assert!(
		matches!(
			confirmer.deny_confirmations_bulk(std::slice::from_ref(&item)),
			Err(ConfirmerError::DeserializeError(_))
		),
		"positional bulk envelope accepted"
	);
	assert!(
		confirmer.get_confirmation_details(&item).is_err(),
		"positional details envelope accepted"
	);
	transport.assert_finished();
}

#[test]
fn positional_confirmation_items_are_rejected() {
	let item = r#"[2,"Trade","id","creator","nonce-canary",1,"Cancel","Accept",null,false,"Headline",[],null]"#;
	assert!(
		serde_json::from_str::<Confirmation>(item).is_err(),
		"positional confirmation item accepted"
	);
	assert!(
		matches!(
			get_list(format!(r#"{{"success":true,"conf":[{item}]}}"#)),
			Err(ConfirmerError::DeserializeError(_))
		),
		"nested positional item accepted"
	);
}

#[test]
fn object_confirmation_duplicate_fields_remain_rejected() {
	for body in [
		r#"{"success":true,"success":true,"conf":[]}"#,
		r#"{"success":true,"conf":[],"conf":[]}"#,
		r#"{"success":true,"conf":[{"type":2,"type_name":"Trade","id":"id","creator_id":"creator","nonce":"nonce-canary","nonce":"nonce-canary","creation_time":1,"headline":"Headline","summary":[],"warn":null}]}"#,
	] {
		assert!(
			matches!(get_list(body), Err(ConfirmerError::DeserializeError(_))),
			"duplicate confirmation field accepted"
		);
	}
	assert!(
		serde_json::from_str::<SendConfirmationResponse>(r#"{"success":true,"success":true}"#)
			.is_err()
	);
}

#[test]
fn well_formed_list_is_parsed() {
	let confirmations = get_list(COMPLETE).unwrap();
	assert_eq!(
		confirmations,
		vec![
			Confirmation {
				conf_type: ConfirmationType::Trade,
				type_name: "Trade".to_owned(),
				id: "10000000001".to_owned(),
				creator_id: "20000000002".to_owned(),
				nonce: "30000000003".to_owned(),
				creation_time: 1700000000,
				cancel: "Cancel".to_owned(),
				accept: "Accept".to_owned(),
				icon: None,
				multi: false,
				headline: "Trade confirmation".to_owned(),
				summary: vec![
					"Synthetic fixture".to_owned(),
					"One item offered".to_owned()
				],
				warn: Some("Verify the recipient".to_owned()),
			},
			Confirmation {
				conf_type: ConfirmationType::MarketSell,
				type_name: "Market listing".to_owned(),
				id: "10000000002".to_owned(),
				creator_id: "20000000003".to_owned(),
				nonce: "30000000004".to_owned(),
				creation_time: 1700000060,
				cancel: "Cancel listing".to_owned(),
				accept: "Create listing".to_owned(),
				icon: Some("https://example.invalid/synthetic-item.png".to_owned()),
				multi: true,
				headline: "Market confirmation".to_owned(),
				summary: vec!["Synthetic market item".to_owned(), "Price: 1.00".to_owned()],
				warn: None,
			},
		]
	);
}

#[test]
fn successful_but_truncated_list_is_rejected() {
	for body in [
		TRUNCATED,
		r#"{"success":true,"conf":null}"#,
		r#"{"success":true,"conf":{}}"#,
		r#"{"success":true,"conf":"body-canary"}"#,
		r#"{"success":true,"conf":["body-canary"]}"#,
		r#"{"conf":[]}"#,
		r#"{"success":null,"conf":[]}"#,
		r#"{"success":"body-canary","conf":[]}"#,
		r#"{"success":true,"conf":[]} {"body-canary":1}"#,
		r#"{"success":true,"conf":[],"success":false}"#,
	] {
		let error = get_list(body).unwrap_err();
		assert!(matches!(error, ConfirmerError::DeserializeError(_)));
		assert_safe_error(&error);
	}
	let minimal: serde_json::Value = serde_json::from_str(MINIMAL).unwrap();
	for required in [
		"type",
		"type_name",
		"id",
		"nonce",
		"creation_time",
		"headline",
		"summary",
		"creator_id",
		"warn",
	] {
		let mut body = minimal.clone();
		body["conf"][0].as_object_mut().unwrap().remove(required);
		assert!(
			matches!(
				get_list(body.to_string()),
				Err(ConfirmerError::DeserializeError(_))
			),
			"missing required field: {required}"
		);
	}
	for (field, invalid) in [
		("type", json!(-1)),
		("type", json!(4294967296_u64)),
		("type", json!("body-canary")),
		("type_name", json!(false)),
		("id", json!(null)),
		("nonce", json!([])),
		("creation_time", json!(-1)),
		("headline", json!({})),
		("summary", json!("body-canary")),
		("summary", json!([false])),
		("creator_id", json!(123)),
		("warn", json!(["body-canary"])),
	] {
		let mut body = minimal.clone();
		body["conf"][0][field] = invalid;
		let error = get_list(body.to_string()).unwrap_err();
		assert!(matches!(error, ConfirmerError::DeserializeError(_)));
		assert_safe_error(&error);
	}
	assert!(get_list(r#"{"success":true,"conf":[]}"#)
		.unwrap()
		.is_empty());
}

#[test]
fn unknown_confirmation_type_is_preserved() {
	let confirmations = get_list(UNKNOWN_TYPE).unwrap();
	assert_eq!(confirmations.len(), 2);
	assert_eq!(
		confirmations[0].conf_type,
		ConfirmationType::Unknown(987654)
	);
	assert_eq!(confirmations[0].id, "40000000004");
	assert!(
		confirmations[0].nonce == "60000000006",
		"secret values differ"
	);
	assert_eq!(confirmations[1].conf_type, ConfirmationType::Trade);
	assert_eq!(confirmations[1].id, "40000000005");
	assert_eq!(confirmations[1].warn.as_deref(), Some("Verify this trade"));
	for code in [0, u32::MAX] {
		let mut body: serde_json::Value = serde_json::from_str(MINIMAL).unwrap();
		body["conf"][0]["type"] = json!(code);
		assert_eq!(
			get_list(body.to_string()).unwrap()[0].conf_type,
			ConfirmationType::Unknown(code)
		);
	}
}

#[test]
fn server_time_is_taken_from_caller() {
	// Independent HMAC-SHA1 vectors, including the full u64 timestamp range.
	for (time, conf_hash, details_hash) in [
		(
			0,
			"uCNVA0Ay3JhbhWX3bdwGR/AiMGw=",
			"5mFOZXLERnlt85qjFJRsHf8dwTg=",
		),
		(
			1617591917,
			"NaL8EIMhfy/7vBounJ0CvpKbrPk=",
			"g7tbj8ZwRV5N81fLzY+1kWAhr4g=",
		),
		(
			u64::MAX,
			"Zkzobut46UQv/lCS3wNNrncUCpg=",
			"sVHK3QmWxlUJ/sERHX88wUo7juc=",
		),
	] {
		let transport = FakeTransport::new(
			[
				MINIMAL,
				r#"{"success":true}"#,
				r#"{"success":true}"#,
				r#"{"success":true}"#,
				r#"{"success":true}"#,
				r#"{"success":true,"html":"body-canary"}"#,
			]
			.map(str::to_owned),
		);
		let account = account();
		let confirmer = Confirmer::new(transport.clone(), &account).with_server_time(time);
		let confirmations = confirmer.get_confirmations().unwrap();
		confirmer.accept_confirmation(&confirmations[0]).unwrap();
		confirmer
			.deny_confirmation(ConfirmationId::from(&confirmations[0]))
			.unwrap();
		confirmer.accept_confirmations_bulk(&confirmations).unwrap();
		confirmer.deny_confirmations_bulk(&confirmations).unwrap();
		assert!(
			confirmer
				.get_confirmation_details(&confirmations[0])
				.unwrap() == "body-canary",
			"secret values differ"
		);
		transport.assert_finished();
		let requests = transport.requests.borrow();
		assert_eq!(requests.len(), 6);
		for (request, endpoint) in requests.iter().zip([
			"confirmation-list",
			"confirmation-action",
			"confirmation-action",
			"confirmation-bulk-action",
			"confirmation-bulk-action",
			"confirmation-details",
		]) {
			assert_eq!(request.endpoint, endpoint);
			let params = match &request.form_body {
				Some(body) => {
					assert!(request.query.is_empty());
					body.split('&')
						.map(|part| {
							let (key, value) = part.split_once('=').unwrap();
							(key.to_owned(), value.to_owned())
						})
						.collect::<Vec<_>>()
				}
				None => request.query.clone(),
			};
			let value = |key| {
				params
					.iter()
					.find(|(name, _)| name == key)
					.map(|(_, value)| value.as_str())
			};
			assert_eq!(value("t"), Some(time.to_string().as_str()));
			assert_eq!(value("a"), Some("76561198000000001"));
			assert!(
				value("p") == Some("android:device-id-canary"),
				"secret values differ"
			);
			assert_eq!(value("m"), Some("react"));
			let details = endpoint == "confirmation-details";
			assert_eq!(value("tag"), Some(if details { "details" } else { "conf" }));
			assert!(
				value("k") == Some(if details { details_hash } else { conf_hash }),
				"secret values differ"
			);
		}
	}
}

#[test]
fn confirmation_debug_redacts_nonce() {
	let mut confirmation = get_list(MINIMAL).unwrap().remove(0);
	confirmation.nonce = "nonce-canary".to_owned();
	confirmation.warn = Some(SECRETS.to_owned());
	let id = ConfirmationId::new(&confirmation.id, &confirmation.nonce);
	let from = ConfirmationId::from(&confirmation);
	assert_eq!(id.id, from.id);
	assert!(id.nonce == from.nonce, "secret values differ");
	assert!(from.nonce == "nonce-canary", "secret values differ");
	for output in [
		format!("{confirmation:?}"),
		format!("{id:?}"),
		format!("{from:?}"),
	] {
		assert_safe_text(&output);
		assert!(output.contains("[REDACTED]"));
	}
}

#[test]
fn response_debug_has_no_secrets() {
	let body = json!({"success":false,"message":SECRETS,"body":SECRETS}).to_string();
	let send: SendConfirmationResponse = serde_json::from_str(&body).unwrap();
	let list: ConfirmationListResponse = serde_json::from_str(&body).unwrap();
	assert!(
		send.message.as_deref() == Some(SECRETS),
		"secret values differ"
	);
	assert!(
		list.message.as_deref() == Some(SECRETS),
		"secret values differ"
	);
	let web = WebResponse::new(200, &body);
	for output in [format!("{send:?}"), format!("{list:?}"), format!("{web:?}")] {
		assert_safe_text(&output);
		assert!(!output.contains(&body));
		assert!(output.contains("[REDACTED]"));
	}
	for body in [
		body,
		json!({"success":SECRETS}).to_string(),
		"<html>body-canary</html>".to_owned(),
	] {
		assert_safe_error(&get_list(&body).unwrap_err());
		let transport = FakeTransport::new([body.clone(), body]);
		let account = account();
		let confirmer = Confirmer::new(transport.clone(), &account).with_server_time(0);
		assert_safe_error(
			&confirmer
				.accept_confirmation(ConfirmationId::new("id", "nonce-canary"))
				.unwrap_err(),
		);
		assert_safe_error(
			&confirmer
				.deny_confirmations_bulk(&get_list(MINIMAL).unwrap())
				.unwrap_err(),
		);
		transport.assert_finished();
	}
}

#[test]
fn optional_item_fields_may_be_absent() {
	let confirmations = get_list(MINIMAL).unwrap();
	assert_eq!(confirmations.len(), 1);
	let item = &confirmations[0];
	assert!(item.cancel.is_empty());
	assert!(item.accept.is_empty());
	assert_eq!(item.icon, None);
	assert!(!item.multi);
	assert_eq!(item.warn, None);
	for message in [None, Some(json!(null)), Some(json!("body-canary"))] {
		let mut body: serde_json::Value = serde_json::from_str(MINIMAL).unwrap();
		for field in ["icon", "cancel", "accept", "multi"] {
			body["conf"][0][field] = json!(null);
		}
		if let Some(message) = message {
			body["message"] = message;
		}
		body["conf"][0]["warn"] = json!("Warning must be preserved");
		let parsed = get_list(body.to_string()).unwrap();
		assert_eq!(parsed[0].warn.as_deref(), Some("Warning must be preserved"));
		let mut expected = item.clone();
		expected.warn = parsed[0].warn.clone();
		assert_eq!(parsed, [expected]);
	}
}

#[test]
fn contradictory_auth_success_is_rejected() {
	for (success, auth) in [(true, true), (false, true), (false, false)] {
		let list = json!({"success":success,"needauth":auth,"conf":[],"message":SECRETS});
		let send = json!({"success":success,"needsauth":auth,"message":SECRETS});
		if success {
			assert!(serde_json::from_value::<ConfirmationListResponse>(list.clone()).is_err());
			assert!(serde_json::from_value::<SendConfirmationResponse>(send.clone()).is_err());
		}
		let transport = FakeTransport::new([send.to_string(), send.to_string()]);
		let account = account();
		let confirmer = Confirmer::new(transport.clone(), &account).with_server_time(0);
		for error in [
			get_list(list.to_string()).unwrap_err(),
			confirmer
				.deny_confirmation(ConfirmationId::new("id", "nonce-canary"))
				.unwrap_err(),
			confirmer
				.accept_confirmations_bulk(&get_list(MINIMAL).unwrap())
				.unwrap_err(),
		] {
			match (success, auth) {
				(true, _) => assert!(matches!(error, ConfirmerError::DeserializeError(_))),
				(false, true) => assert!(matches!(error, ConfirmerError::InvalidTokens)),
				(false, false) => {
					assert!(matches!(error, ConfirmerError::RemoteFailureWithMessage(_)))
				}
			}
			assert_safe_error(&error);
		}
		transport.assert_finished();
	}
	assert!(matches!(
		get_list(r#"{"success":false}"#),
		Err(ConfirmerError::RemoteFailure)
	));
	assert!(matches!(
		get_list(r#"{"success":false,"needauth":true}"#),
		Err(ConfirmerError::InvalidTokens)
	));
	for body in [
		r#"{"success":true}"#,
		r#"{"success":true,"needsauth":null,"message":null}"#,
		r#"{"success":true,"needsauth":false,"message":"body-canary"}"#,
	] {
		let transport = FakeTransport::new([body.to_owned()]);
		let account = account();
		Confirmer::new(transport.clone(), &account)
			.with_server_time(0)
			.accept_confirmation(ConfirmationId::new("id", "nonce-canary"))
			.unwrap();
		transport.assert_finished();
	}
}
