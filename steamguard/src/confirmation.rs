use std::{borrow::Cow, fmt};

use base64::Engine;
use hmac::{Hmac, Mac};
use log::*;
use reqwest::{cookie::CookieStore, header::HeaderValue};
use secrecy::ExposeSecret;
use serde::{Deserialize, Deserializer};
use sha1::Sha1;

use crate::{
	endpoints,
	steamapi::{self},
	transport::{NetworkError, Transport, WebEndpoint, WebRequest},
	SteamGuardAccount,
};

const ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";
const CONFIRMATION_USER_AGENT: &str =
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36";

/// Provides an interface that wraps the Steam mobile confirmation API.
///
/// The transport must support Steam Community web requests.
pub struct Confirmer<'a, T> {
	account: &'a SteamGuardAccount,
	transport: T,
	server_time: Option<u64>,
}

impl<'a, T> Confirmer<'a, T>
where
	T: Transport + Clone,
{
	pub fn new(transport: T, account: &'a SteamGuardAccount) -> Self {
		Self {
			account,
			transport,
			server_time: None,
		}
	}

	/// Uses a caller-supplied Unix timestamp for confirmation request signatures.
	///
	/// This avoids a Steam time query when the caller has already applied its server time offset.
	#[must_use]
	pub fn with_server_time(mut self, server_time: u64) -> Self {
		self.server_time = Some(server_time);
		self
	}

	fn server_time(&self) -> anyhow::Result<u64> {
		match self.server_time {
			Some(server_time) => Ok(server_time),
			None => Ok(steamapi::get_server_time(self.transport.clone())?.server_time()),
		}
	}

	fn get_confirmation_query_params<'q>(
		&'q self,
		tag: &'q str,
		time: u64,
	) -> anyhow::Result<Vec<(&'static str, Cow<'q, str>)>> {
		Ok([
			("p", self.account.device_id.as_str().into()),
			("a", self.account.steam_id.to_string().into()),
			(
				"k",
				generate_confirmation_hash_for_time(
					time,
					tag,
					self.account.identity_secret.expose_secret(),
				)?
				.into(),
			),
			("t", time.to_string().into()),
			("m", "react".into()),
			("tag", tag.into()),
		]
		.into())
	}

	fn build_cookie_header(&self) -> Result<String, ConfirmerError> {
		let cookie_url = endpoints::community_url("")?;
		let cookies = reqwest::cookie::Jar::default();
		let tokens = self
			.account
			.tokens
			.as_ref()
			.ok_or(ConfirmerError::InvalidTokens)?;
		HeaderValue::from_str(tokens.access_token().expose_secret())
			.map_err(|_| ConfirmerError::InvalidCookieHeader)?;
		cookies.add_cookie_str("dob=", &cookie_url);
		cookies.add_cookie_str(
			format!("steamid={}", self.account.steam_id).as_str(),
			&cookie_url,
		);
		cookies.add_cookie_str(
			format!(
				"steamLoginSecure={}||{}",
				self.account.steam_id,
				tokens.access_token().expose_secret()
			)
			.as_str(),
			&cookie_url,
		);
		let cookie = cookies
			.cookies(&cookie_url)
			.ok_or(ConfirmerError::InvalidCookieHeader)?;
		let cookie = cookie
			.to_str()
			.map_err(|_| ConfirmerError::InvalidCookieHeader)?;
		Ok(cookie.to_owned())
	}

	pub fn get_confirmations(&self) -> Result<Vec<Confirmation>, ConfirmerError> {
		let cookie = self.build_cookie_header()?;

		let time = self.server_time()?;
		let query_params = self.get_confirmation_query_params("conf", time)?;
		let resp = self.transport.send_web(WebRequest::new(
			WebEndpoint::ConfirmationList,
			&query_params,
			CONFIRMATION_USER_AGENT,
			&cookie,
			ACCEPT_LANGUAGE,
		))?;

		trace!("Confirmation list response status: {}", resp.status());
		let text = resp.into_body();
		debug!("Confirmation list response length: {} bytes", text.len());

		let body: ConfirmationListResponse = serde_json::from_str(&text)?;

		if body.needauth.unwrap_or(false) {
			return Err(ConfirmerError::InvalidTokens);
		}
		if !body.success {
			if let Some(msg) = body.message {
				return Err(ConfirmerError::RemoteFailureWithMessage(msg));
			} else {
				return Err(ConfirmerError::RemoteFailure);
			}
		}
		Ok(body.conf)
	}

	/// Respond to a confirmation.
	///
	/// Host: https://steamcommunity.com
	/// Steam Endpoint: `GET /mobileconf/ajaxop`
	fn send_confirmation_ajax<'id>(
		&self,
		conf: impl Into<ConfirmationId<'id>>,
		action: ConfirmationAction,
	) -> Result<(), ConfirmerError> {
		debug!("responding to a single confirmation: send_confirmation_ajax()");
		let conf = conf.into();
		let operation = action.to_operation();

		let cookie = self.build_cookie_header()?;

		let time = self.server_time()?;
		let mut query_params = self.get_confirmation_query_params("conf", time)?;
		query_params.push(("op", operation.into()));
		query_params.push(("cid", Cow::Borrowed(conf.id)));
		query_params.push(("ck", Cow::Borrowed(conf.nonce)));

		let resp = self.transport.send_web(
			WebRequest::new(
				WebEndpoint::ConfirmationAction,
				&query_params,
				CONFIRMATION_USER_AGENT,
				&cookie,
				ACCEPT_LANGUAGE,
			)
			.with_origin(endpoints::community_base_url()),
		)?;

		debug!(
			"send_confirmation_ajax() response status code: {}",
			&resp.status()
		);

		let raw = resp.into_body();
		trace!(
			"send_confirmation_ajax() response body length: {} bytes",
			raw.len()
		);

		let body: SendConfirmationResponse = serde_json::from_str(&raw)?;

		if body.needsauth.unwrap_or(false) {
			return Err(ConfirmerError::InvalidTokens);
		}
		if !body.success {
			if let Some(msg) = body.message {
				return Err(ConfirmerError::RemoteFailureWithMessage(msg));
			} else {
				return Err(ConfirmerError::RemoteFailure);
			}
		}

		Ok(())
	}

	pub fn accept_confirmation<'id>(
		&self,
		conf: impl Into<ConfirmationId<'id>>,
	) -> Result<(), ConfirmerError> {
		self.send_confirmation_ajax(conf, ConfirmationAction::Accept)
	}

	pub fn deny_confirmation<'id>(
		&self,
		conf: impl Into<ConfirmationId<'id>>,
	) -> Result<(), ConfirmerError> {
		self.send_confirmation_ajax(conf, ConfirmationAction::Deny)
	}

	/// Respond to more than 1 confirmation.
	///
	/// Host: https://steamcommunity.com
	/// Steam Endpoint: `GET /mobileconf/multiajaxop`
	fn send_multi_confirmation_ajax<TId>(
		&self,
		confs: &[TId],
		action: ConfirmationAction,
	) -> Result<(), ConfirmerError>
	where
		for<'id> &'id TId: Into<ConfirmationId<'id>>,
	{
		debug!("responding to bulk confirmations: send_multi_confirmation_ajax()");
		if confs.is_empty() {
			debug!("confs is empty, nothing to do.");
			return Ok(());
		}
		let operation = action.to_operation();

		let cookie = self.build_cookie_header()?;

		let time = self.server_time()?;
		let mut query_params = self.get_confirmation_query_params("conf", time)?;
		query_params.push(("op", operation.into()));
		for conf in confs.iter() {
			let conf = conf.into();
			query_params.push(("cid[]", Cow::Borrowed(conf.id)));
			query_params.push(("ck[]", Cow::Borrowed(conf.nonce)));
		}
		let query_params = self.build_multi_conf_query_string(&query_params);
		// despite being called query parameters, they will actually go in the body
		debug!(
			"bulk confirmation request body length: {} bytes",
			query_params.len()
		);

		let no_query = [];
		let resp = self.transport.send_web(
			WebRequest::new(
				WebEndpoint::ConfirmationBulkAction,
				&no_query,
				CONFIRMATION_USER_AGENT,
				&cookie,
				ACCEPT_LANGUAGE,
			)
			.with_origin(endpoints::community_base_url())
			.with_form_body(&query_params),
		)?;

		debug!(
			"send_multi_confirmation_ajax() response status code: {}",
			&resp.status()
		);

		let raw = resp.into_body();
		trace!(
			"send_multi_confirmation_ajax() response body length: {} bytes",
			raw.len()
		);

		let body: SendConfirmationResponse = serde_json::from_str(&raw)?;

		if body.needsauth.unwrap_or(false) {
			return Err(ConfirmerError::InvalidTokens);
		}
		if !body.success {
			if let Some(msg) = body.message {
				return Err(ConfirmerError::RemoteFailureWithMessage(msg));
			} else {
				return Err(ConfirmerError::RemoteFailure);
			}
		}

		Ok(())
	}

	/// Bulk accept confirmations.
	///
	/// Sends one request per confirmation.
	pub fn accept_confirmations<TId>(&self, confs: &[TId]) -> Result<(), ConfirmerError>
	where
		for<'id> &'id TId: Into<ConfirmationId<'id>>,
	{
		for conf in confs {
			self.accept_confirmation(conf)?;
		}

		Ok(())
	}

	/// Bulk deny confirmations.
	///
	/// Sends one request per confirmation.
	pub fn deny_confirmations<TId>(&self, confs: &[TId]) -> Result<(), ConfirmerError>
	where
		for<'id> &'id TId: Into<ConfirmationId<'id>>,
	{
		for conf in confs {
			self.deny_confirmation(conf)?;
		}

		Ok(())
	}

	/// Bulk accept confirmations.
	///
	/// Uses a different endpoint than `accept_confirmation()` to submit multiple confirmations in one request.
	pub fn accept_confirmations_bulk<TId>(&self, confs: &[TId]) -> Result<(), ConfirmerError>
	where
		for<'id> &'id TId: Into<ConfirmationId<'id>>,
	{
		self.send_multi_confirmation_ajax(confs, ConfirmationAction::Accept)
	}

	/// Bulk deny confirmations.
	///
	/// Uses a different endpoint than `deny_confirmation()` to submit multiple confirmations in one request.
	pub fn deny_confirmations_bulk<TId>(&self, confs: &[TId]) -> Result<(), ConfirmerError>
	where
		for<'id> &'id TId: Into<ConfirmationId<'id>>,
	{
		self.send_multi_confirmation_ajax(confs, ConfirmationAction::Deny)
	}

	fn build_multi_conf_query_string(&self, params: &[(&str, Cow<str>)]) -> String {
		params
			.iter()
			.map(|(k, v)| format!("{}={}", k, v))
			.collect::<Vec<_>>()
			.join("&")
	}

	/// Steam Endpoint: `GET /mobileconf/details/:id`
	pub fn get_confirmation_details<'id>(
		&self,
		conf: impl Into<ConfirmationId<'id>>,
	) -> anyhow::Result<String> {
		#[derive(Clone, Deserialize)]
		struct ConfirmationDetailsResponse {
			pub success: bool,
			pub html: String,
		}

		let cookie = self.build_cookie_header()?;

		let time = self.server_time()?;
		let query_params = self.get_confirmation_query_params("details", time)?;

		let resp = self.transport.send_web(WebRequest::new(
			WebEndpoint::ConfirmationDetails(conf.into().id),
			&query_params,
			CONFIRMATION_USER_AGENT,
			&cookie,
			ACCEPT_LANGUAGE,
		))?;

		let text = resp.into_body();
		let body: ConfirmationDetailsResponse =
			serde_json::from_str(&text).map_err(ConfirmerError::from)?;

		ensure!(body.success);
		Ok(body.html)
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationAction {
	Accept,
	Deny,
}

impl ConfirmationAction {
	fn to_operation(self) -> &'static str {
		match self {
			ConfirmationAction::Accept => "allow",
			ConfirmationAction::Deny => "cancel",
		}
	}
}

#[derive(thiserror::Error)]
pub enum ConfirmerError {
	#[error("Invalid tokens, login or token refresh required.")]
	InvalidTokens,
	#[error("Could not build the Steam Community cookie header")]
	InvalidCookieHeader,
	#[error("Network failure: {0}")]
	NetworkFailure(#[from] NetworkError),
	#[error("Failed to deserialize confirmation response")]
	DeserializeError(#[from] serde_path_to_error::Error<serde_json::Error>),
	#[error("Remote failure: Valve's server responded with a failure and did not elaborate any further. This is likely not a steamguard-cli bug, Steam's confirmation API is just unreliable. Wait a bit and try again.")]
	RemoteFailure,
	#[error("Remote failure: Valve's server rejected the request")]
	RemoteFailureWithMessage(String),
	#[error("Unexpected confirmation error")]
	Unknown(#[from] anyhow::Error),
}

impl fmt::Debug for ConfirmerError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::NetworkFailure(error) => f.debug_tuple("NetworkFailure").field(error).finish(),
			Self::DeserializeError(_) => f.write_str("DeserializeError([REDACTED])"),
			Self::RemoteFailureWithMessage(_) => {
				f.write_str("RemoteFailureWithMessage([REDACTED])")
			}
			Self::Unknown(_) => f.write_str("Unknown([REDACTED])"),
			_ => fmt::Display::fmt(self, f),
		}
	}
}

impl From<reqwest::Error> for ConfirmerError {
	fn from(error: reqwest::Error) -> Self {
		Self::NetworkFailure(error.into())
	}
}

impl From<serde_json::Error> for ConfirmerError {
	fn from(error: serde_json::Error) -> Self {
		// Retain the typed source for internal inspection; public diagnostics are redacted.
		Self::DeserializeError(serde_path_to_error::Error::new(
			serde_path_to_error::Track::new().path(),
			error,
		))
	}
}

fn default_if_null<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
	D: Deserializer<'de>,
	T: Deserialize<'de> + Default,
{
	Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// A mobile confirmation. There are multiple things that can be confirmed, like trade offers.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct Confirmation {
	#[serde(rename = "type")]
	pub conf_type: ConfirmationType,
	pub type_name: String,
	pub id: String,
	/// Trade offer ID or market transaction ID
	pub creator_id: String,
	pub nonce: String,
	pub creation_time: u64,
	#[serde(default, deserialize_with = "default_if_null")]
	pub cancel: String,
	#[serde(default, deserialize_with = "default_if_null")]
	pub accept: String,
	pub icon: Option<String>,
	#[serde(default, deserialize_with = "default_if_null")]
	pub multi: bool,
	pub headline: String,
	pub summary: Vec<String>,
	/// Steam's warning text. The field must be present, but may be null.
	#[serde(deserialize_with = "Option::deserialize")]
	pub warn: Option<String>,
}

impl fmt::Debug for Confirmation {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Confirmation")
			.field("conf_type", &self.conf_type)
			.field("type_name", &"[REDACTED]")
			.field("id", &"[REDACTED]")
			.field("creator_id", &"[REDACTED]")
			.field("nonce", &"[REDACTED]")
			.field("creation_time", &self.creation_time)
			.field("cancel", &"[REDACTED]")
			.field("accept", &"[REDACTED]")
			.field("icon", &self.icon.as_ref().map(|_| "[REDACTED]"))
			.field("multi", &self.multi)
			.field("headline", &"[REDACTED]")
			.field("summary", &"[REDACTED]")
			.field("warn", &self.warn.as_ref().map(|_| "[REDACTED]"))
			.finish()
	}
}

impl Confirmation {
	/// Human readable representation of this confirmation.
	pub fn description(&self) -> String {
		format!(
			"{:?} - {} - {}",
			self.conf_type,
			self.headline,
			self.summary.join(", ")
		)
	}
}

#[derive(Clone, Copy)]
pub struct ConfirmationId<'a> {
	pub id: &'a str,
	pub nonce: &'a str,
}

impl fmt::Debug for ConfirmationId<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("ConfirmationId")
			.field("id", &"[REDACTED]")
			.field("nonce", &"[REDACTED]")
			.finish()
	}
}

impl<'a> ConfirmationId<'a> {
	pub fn new(id: &'a str, nonce: &'a str) -> Self {
		Self { id, nonce }
	}
}

impl<'a> From<&'a Confirmation> for ConfirmationId<'a> {
	fn from(confirmation: &'a Confirmation) -> Self {
		Self::new(&confirmation.id, &confirmation.nonce)
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, num_enum::FromPrimitive)]
#[repr(u32)]
#[serde(from = "u32")]
/// Source: <https://github.com/SteamDatabase/SteamTracking/blob/6e7797e69b714c59f4b5784780b24753c17732ba/Structs/enums.steamd#L1607-L1616>
/// There are also some additional undocumented types.
pub enum ConfirmationType {
	Test = 1,
	/// Occurs when sending a trade offer or accepting a received trade offer, only when there is items on the user's side
	Trade = 2,
	/// Occurs when selling an item on the Steam community market
	MarketSell = 3,
	FeatureOptOut = 4,
	/// Occurs when changing the phone number associated with the account
	PhoneNumberChange = 5,
	/// Occurs when removing a phone number
	AccountRecovery = 6,
	/// Occurs when a new web API key is created via <https://steamcommunity.com/dev/apikey>
	ApiKeyCreation = 9,
	/// Occurs when a user is invited to join a Steam Family, and they have accepted the invitation. This is not used for accepting the initial invitation, just to confirm the acceptance.
	///
	/// Triggered upon accepting invitation here: <https://store.steampowered.com/account/familymanagement>
	JoinSteamFamily = 11,
	#[num_enum(catch_all)]
	Unknown(u32),
}

pub struct ConfirmationListResponse {
	pub success: bool,
	pub needauth: Option<bool>,
	pub conf: Vec<Confirmation>,
	pub message: Option<String>,
}

impl<'de> Deserialize<'de> for ConfirmationListResponse {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		#[derive(Deserialize)]
		struct Response {
			success: bool,
			needauth: Option<bool>,
			conf: Option<Vec<Confirmation>>,
			message: Option<String>,
		}

		let response = Response::deserialize(deserializer)?;
		if response.success && response.needauth == Some(true) {
			return Err(serde::de::Error::custom(
				"confirmation response has contradictory success and authentication status",
			));
		}
		let conf = match response.conf {
			Some(conf) => conf,
			None if response.success => return Err(serde::de::Error::missing_field("conf")),
			None => Vec::new(),
		};
		Ok(Self {
			success: response.success,
			needauth: response.needauth,
			conf,
			message: response.message,
		})
	}
}

impl fmt::Debug for ConfirmationListResponse {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("ConfirmationListResponse")
			.field("success", &self.success)
			.field("needauth", &self.needauth)
			.field("confirmation_count", &self.conf.len())
			.field("message", &self.message.as_ref().map(|_| "[REDACTED]"))
			.finish()
	}
}

#[derive(Clone)]
pub struct SendConfirmationResponse {
	pub success: bool,
	pub needsauth: Option<bool>,
	pub message: Option<String>,
}

impl<'de> Deserialize<'de> for SendConfirmationResponse {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		#[derive(Deserialize)]
		struct Response {
			success: bool,
			needsauth: Option<bool>,
			message: Option<String>,
		}

		let response = Response::deserialize(deserializer)?;
		if response.success && response.needsauth == Some(true) {
			return Err(serde::de::Error::custom(
				"confirmation response has contradictory success and authentication status",
			));
		}
		Ok(Self {
			success: response.success,
			needsauth: response.needsauth,
			message: response.message,
		})
	}
}

impl fmt::Debug for SendConfirmationResponse {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("SendConfirmationResponse")
			.field("success", &self.success)
			.field("needsauth", &self.needsauth)
			.field("message", &self.message.as_ref().map(|_| "[REDACTED]"))
			.finish()
	}
}

fn build_time_bytes(time: u64) -> [u8; 8] {
	time.to_be_bytes()
}

fn generate_confirmation_hash_for_time(
	time: u64,
	tag: &str,
	identity_secret: impl AsRef<[u8]>,
) -> anyhow::Result<String> {
	let decode = base64::engine::general_purpose::STANDARD.decode(identity_secret)?;
	let mut mac = Hmac::<Sha1>::new_from_slice(&decode)?;
	mac.update(&build_time_bytes(time));
	mac.update(tag.as_bytes());
	let result = mac.finalize();
	let hash = result.into_bytes();
	Ok(base64::engine::general_purpose::STANDARD.encode(hash))
}

#[cfg(test)]
mod tests {
	use anyhow::Context;

	use super::*;

	#[derive(Clone)]
	struct RejectingTransport;

	impl Transport for RejectingTransport {
		fn send_request<
			Req: crate::steamapi::BuildableRequest + protobuf::MessageFull,
			Res: protobuf::MessageFull,
		>(
			&self,
			_req: crate::steamapi::ApiRequest<Req>,
		) -> Result<crate::steamapi::ApiResponse<Res>, crate::transport::TransportError> {
			Err(crate::transport::TransportError::Unknown(anyhow::anyhow!(
				"unexpected time request"
			)))
		}

		fn close(&mut self) {}
	}

	#[test]
	fn test_parse_confirmations() -> anyhow::Result<()> {
		struct Test {
			text: &'static str,
			confirmation_type: ConfirmationType,
		}
		let cases = [
			Test {
				text: include_str!("fixtures/confirmations/email-change.json"),
				confirmation_type: ConfirmationType::AccountRecovery,
			},
			Test {
				text: include_str!("fixtures/confirmations/phone-number-change.json"),
				confirmation_type: ConfirmationType::PhoneNumberChange,
			},
		];
		for case in cases.iter() {
			let confirmations = serde_json::from_str::<ConfirmationListResponse>(case.text)?;

			assert_eq!(confirmations.conf.len(), 1);

			let confirmation = &confirmations.conf[0];

			assert_eq!(confirmation.conf_type, case.confirmation_type);
		}

		Ok(())
	}

	#[test]
	fn test_parse_confirmations_2() -> anyhow::Result<()> {
		struct Test {
			text: &'static str,
		}
		let cases = [Test {
			text: include_str!("fixtures/confirmations/need-auth.json"),
		}];
		for case in cases.iter() {
			let confirmations = serde_json::from_str::<ConfirmationListResponse>(case.text)?;

			assert_eq!(confirmations.conf.len(), 0);
			assert_eq!(confirmations.needauth, Some(true));
		}

		Ok(())
	}

	#[test]
	fn parses_a_complete_confirmation_list_fixture() -> anyhow::Result<()> {
		let fixture = include_str!("fixtures/confirmations/list-well-formed.json");
		let response: ConfirmationListResponse = serde_json::from_str(fixture)?;
		let raw: serde_json::Value = serde_json::from_str(fixture)?;
		let items = raw["conf"].as_array().context("fixture must have a list")?;

		assert!(response.success);
		assert_eq!(response.needauth, Some(false));
		assert_eq!(response.message, None);
		assert_eq!(response.conf.len(), 2);
		assert_eq!(response.conf[0].conf_type, ConfirmationType::Trade);
		assert_eq!(response.conf[1].conf_type, ConfirmationType::MarketSell);
		for (confirmation, item) in response.conf.iter().zip(items) {
			assert_eq!(confirmation.type_name, item["type_name"]);
			assert_eq!(confirmation.id, item["id"]);
			assert_eq!(confirmation.creator_id, item["creator_id"]);
			assert_eq!(confirmation.nonce, item["nonce"]);
			assert_eq!(confirmation.creation_time, item["creation_time"]);
			assert_eq!(confirmation.cancel, item["cancel"]);
			assert_eq!(confirmation.accept, item["accept"]);
			assert_eq!(serde_json::json!(confirmation.icon), item["icon"]);
			assert_eq!(confirmation.multi, item["multi"]);
			assert_eq!(confirmation.headline, item["headline"]);
			assert_eq!(serde_json::json!(confirmation.summary), item["summary"]);
			assert_eq!(serde_json::json!(confirmation.warn), item["warn"]);
		}
		Ok(())
	}

	#[test]
	fn rejects_a_truncated_confirmation_list_fixture() {
		let error = serde_json::from_str::<ConfirmationListResponse>(include_str!(
			"fixtures/confirmations/list-truncated.json"
		))
		.unwrap_err();

		assert!(error.to_string().contains("missing field `conf`"));
	}

	#[test]
	fn preserves_unknown_confirmation_types() -> anyhow::Result<()> {
		let response: ConfirmationListResponse = serde_json::from_str(include_str!(
			"fixtures/confirmations/list-unknown-type.json"
		))?;
		let confirmation = response
			.conf
			.first()
			.context("unknown-type fixture should contain a confirmation")?;

		assert_eq!(confirmation.conf_type, ConfirmationType::Unknown(987_654));
		Ok(())
	}

	#[test]
	fn test_generate_confirmation_hash_for_time() {
		assert_eq!(
			generate_confirmation_hash_for_time(1617591917, "conf", "GQP46b73Ws7gr8GmZFR0sDuau5c=")
				.unwrap(),
			String::from("NaL8EIMhfy/7vBounJ0CvpKbrPk=")
		);
	}

	#[test]
	fn malformed_confirmation_credentials_return_errors() {
		let transport = crate::transport::WebApiTransport::new(
			reqwest::blocking::Client::builder()
				.no_proxy()
				.build()
				.unwrap(),
		);
		let account = SteamGuardAccount::default();
		let confirmer = Confirmer::new(transport, &account);

		assert!(matches!(
			confirmer.build_cookie_header(),
			Err(ConfirmerError::InvalidTokens)
		));
		assert!(generate_confirmation_hash_for_time(1, "conf", "not-base64").is_err());

		let account = SteamGuardAccount {
			tokens: Some(crate::token::Tokens::new(
				"malformed\naccess-token".to_owned(),
				"refresh-token".to_owned(),
			)),
			..SteamGuardAccount::default()
		};
		let transport = crate::transport::WebApiTransport::new(
			reqwest::blocking::Client::builder()
				.no_proxy()
				.build()
				.unwrap(),
		);
		let confirmer = Confirmer::new(transport, &account);
		assert!(matches!(
			confirmer.build_cookie_header(),
			Err(ConfirmerError::InvalidCookieHeader)
		));
	}

	#[test]
	fn confirmation_query_uses_the_supplied_time() {
		let account = SteamGuardAccount {
			steam_id: 7_656_119_900_000_001,
			device_id: "android:test-device".to_owned(),
			identity_secret: "GQP46b73Ws7gr8GmZFR0sDuau5c=".to_owned().into(),
			..SteamGuardAccount::default()
		};
		assert!(Confirmer::new(RejectingTransport, &account)
			.server_time()
			.is_err());
		let confirmer =
			Confirmer::new(RejectingTransport, &account).with_server_time(1_617_591_917);

		let time = confirmer.server_time().unwrap();
		let query = confirmer
			.get_confirmation_query_params("conf", time)
			.unwrap();
		let value = |name| {
			query
				.iter()
				.find(|(key, _)| *key == name)
				.map(|(_, value)| value.as_ref())
		};

		assert_eq!(value("t"), Some("1617591917"));
		assert_eq!(value("k"), Some("NaL8EIMhfy/7vBounJ0CvpKbrPk="));
	}

	#[test]
	fn confirmation_debug_output_redacts_response_and_query_values() {
		let confirmation = Confirmation {
			conf_type: ConfirmationType::Trade,
			type_name: "type-name-canary".to_owned(),
			id: "confirmation-id-canary".to_owned(),
			creator_id: "creator-id-canary".to_owned(),
			nonce: "nonce-canary".to_owned(),
			creation_time: 1,
			cancel: "cancel-label-canary".to_owned(),
			accept: "accept-label-canary".to_owned(),
			icon: Some("icon-canary".to_owned()),
			multi: false,
			headline: "headline-canary".to_owned(),
			summary: vec!["summary-canary".to_owned()],
			warn: Some("warn-canary".to_owned()),
		};
		let confirmation_id = ConfirmationId::new(&confirmation.id, &confirmation.nonce);
		let response = ConfirmationListResponse {
			success: true,
			needauth: None,
			conf: vec![confirmation.clone()],
			message: Some("list-message-canary".to_owned()),
		};
		let action_response = SendConfirmationResponse {
			success: false,
			needsauth: None,
			message: Some("action-message-canary".to_owned()),
		};

		let output =
			format!("{confirmation:?} {confirmation_id:?} {response:?} {action_response:?}");
		for canary in [
			"type-name-canary",
			"confirmation-id-canary",
			"creator-id-canary",
			"nonce-canary",
			"cancel-label-canary",
			"accept-label-canary",
			"icon-canary",
			"headline-canary",
			"summary-canary",
			"warn-canary",
			"list-message-canary",
			"action-message-canary",
		] {
			assert!(!output.contains(canary));
		}
		assert!(output.contains("[REDACTED]"));
	}
}
