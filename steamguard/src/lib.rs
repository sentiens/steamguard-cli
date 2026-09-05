use crate::token::TwoFactorSecret;
use accountlinker::RemoveAuthenticatorError;
pub use accountlinker::{AccountLinkError, AccountLinker, FinalizeLinkError};
pub use api_responses::AllowedConfirmation;
pub use approver::{ApproverError, LoginApprover};
pub use confirmation::*;
pub use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::{fmt, io::Read};
use token::Tokens;
use transport::{Transport, TransportError};
pub use userlogin::{DeviceDetails, LoginError, UserLogin};

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate anyhow;
extern crate maplit;

pub mod accountlinker;
mod api_responses;
pub mod approver;
mod confirmation;
mod endpoints;
pub mod phonelinker;
pub mod protobufs;
pub mod refresher;
mod secret_string;
pub mod steamapi;
pub mod token;
pub mod transport;
pub mod userlogin;

extern crate base64;
extern crate cookie;

#[derive(Clone, Serialize, Deserialize)]
pub struct SteamGuardAccount {
	pub account_name: String,
	pub steam_id: u64,
	pub serial_number: String,
	#[serde(with = "secret_string")]
	pub revocation_code: SecretString,
	pub shared_secret: TwoFactorSecret,
	pub token_gid: String,
	#[serde(with = "secret_string")]
	pub identity_secret: SecretString,
	#[serde(with = "secret_string")]
	pub uri: SecretString,
	pub device_id: String,
	#[serde(with = "secret_string")]
	pub secret_1: SecretString,
	pub tokens: Option<Tokens>,
}

impl fmt::Debug for SteamGuardAccount {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("SteamGuardAccount")
			.field("account_name", &self.account_name)
			.field("steam_id", &self.steam_id)
			.field("serial_number", &"[REDACTED]")
			.field("revocation_code", &"[REDACTED]")
			.field("shared_secret", &"[REDACTED]")
			.field("token_gid", &"[REDACTED]")
			.field("identity_secret", &"[REDACTED]")
			.field("uri", &"[REDACTED]")
			.field("device_id", &self.device_id)
			.field("secret_1", &"[REDACTED]")
			.field("tokens", &self.tokens.as_ref().map(|_| "[REDACTED]"))
			.finish()
	}
}

impl Default for SteamGuardAccount {
	fn default() -> Self {
		Self {
			account_name: String::from(""),
			steam_id: 0,
			serial_number: String::from(""),
			revocation_code: String::from("").into(),
			shared_secret: TwoFactorSecret::new(),
			token_gid: String::from(""),
			identity_secret: String::from("").into(),
			uri: String::from("").into(),
			device_id: String::from(""),
			secret_1: String::from("").into(),
			tokens: None,
		}
	}
}

impl SteamGuardAccount {
	pub fn new() -> Self {
		Self::default()
	}

	pub fn from_reader<T>(r: T) -> anyhow::Result<Self>
	where
		T: Read,
	{
		Ok(serde_json::from_reader(r)?)
	}

	pub fn from_file(path: &str) -> anyhow::Result<Self> {
		let file = std::fs::File::open(path)?;
		Self::from_reader(file)
	}

	pub fn set_tokens(&mut self, tokens: Tokens) {
		self.tokens = Some(tokens);
	}

	pub fn is_logged_in(&self) -> bool {
		self.tokens.is_some()
	}

	pub fn generate_code(&self, time: u64) -> String {
		self.shared_secret.generate_code(time)
	}

	/// Removes the mobile authenticator from the steam account. If this operation succeeds, this object can no longer be considered valid.
	/// Returns whether or not the operation was successful.
	///
	/// A convenience method for [`AccountLinker::remove_authenticator`].
	pub fn remove_authenticator(
		&self,
		transport: impl Transport,
		revocation_code: Option<&String>,
	) -> Result<(), RemoveAuthenticatorError> {
		let Some(tokens) = &self.tokens else {
			return Err(RemoveAuthenticatorError::TransportError(
				TransportError::Unauthorized,
			));
		};
		let revocation_code =
			Some(revocation_code.unwrap_or_else(|| self.revocation_code.expose_secret()));
		let linker = AccountLinker::new(transport, tokens.clone());
		linker.remove_authenticator(revocation_code)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn account_debug_output_redacts_authenticator_secrets() {
		let account = SteamGuardAccount {
			account_name: "account-name".to_owned(),
			steam_id: 1,
			serial_number: "serial-canary".to_owned(),
			revocation_code: "revocation-canary".to_owned().into(),
			shared_secret: TwoFactorSecret::from_bytes(vec![42; 20]),
			token_gid: "token-gid-canary".to_owned(),
			identity_secret: "identity-canary".to_owned().into(),
			uri: "uri-canary".to_owned().into(),
			device_id: "device-id".to_owned(),
			secret_1: "secret-one-canary".to_owned().into(),
			tokens: Some(Tokens::new(
				"access-token-canary".to_owned(),
				"refresh-token-canary".to_owned(),
			)),
		};

		let output = format!("{account:?}");
		for canary in [
			"serial-canary",
			"revocation-canary",
			"token-gid-canary",
			"identity-canary",
			"uri-canary",
			"secret-one-canary",
			"access-token-canary",
			"refresh-token-canary",
		] {
			assert!(!output.contains(canary));
		}
		assert!(output.contains("[REDACTED]"));
	}
}
