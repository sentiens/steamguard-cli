use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum UserError {
	#[error("User aborted the operation.")]
	Aborted,
}

/// Format approved typed facts only. Anyhow contexts and raw sources may contain secrets.
pub(crate) fn safe_error(error: &(dyn std::error::Error + 'static)) -> String {
	let mut current = Some(error);
	while let Some(error) = current {
		macro_rules! approved {
			($($ty:ty),+ $(,)?) => {
				$(if let Some(error) = error.downcast_ref::<$ty>() {
					return error.to_string();
				})+
			};
		}
		approved!(
			UserError,
			steamguard::ConfirmerError,
			steamguard::transport::NetworkError,
			steamguard::transport::TransportError,
			steamguard::LoginError,
			steamguard::userlogin::UpdateAuthSessionError,
			steamguard::refresher::RefreshError,
			steamguard::accountlinker::QueryStatusError,
			steamguard::AccountLinkError,
			steamguard::phonelinker::SetPhoneNumberError,
			steamguard::phonelinker::VerifyPhoneError,
		);
		if let Some(error) = error.downcast_ref::<steamguard::ApproverError>() {
			return match error {
				steamguard::ApproverError::Unknown(_) => "Login approval failed".to_owned(),
				_ => error.to_string(),
			};
		}
		if let Some(error) = error.downcast_ref::<steamguard::FinalizeLinkError>() {
			return match error {
				steamguard::FinalizeLinkError::Unknown(_) => {
					"Authenticator finalization failed".to_owned()
				}
				_ => error.to_string(),
			};
		}
		if let Some(error) =
			error.downcast_ref::<steamguard::accountlinker::RemoveAuthenticatorError>()
		{
			return match error {
				steamguard::accountlinker::RemoveAuthenticatorError::Unknown(_) => {
					"Authenticator removal failed".to_owned()
				}
				_ => error.to_string(),
			};
		}
		if let Some(error) = error.downcast_ref::<steamguard::accountlinker::TransferError>() {
			return match error {
				steamguard::accountlinker::TransferError::Unknown(_) => {
					"Authenticator transfer failed".to_owned()
				}
				_ => error.to_string(),
			};
		}
		if let Some(error) = error.downcast_ref::<serde_json::Error>() {
			return format!(
				"Invalid JSON ({:?}, line {}, column {})",
				error.classify(),
				error.line(),
				error.column()
			);
		}
		if let Some(error) = error.downcast_ref::<reqwest::Error>() {
			return format!(
				"Network request failed (status: {:?}, timeout: {})",
				error.status(),
				error.is_timeout()
			);
		}
		if let Some(error) = error.downcast_ref::<std::io::Error>() {
			return format!(
				"I/O failure ({:?}, OS code: {:?})",
				error.kind(),
				error.raw_os_error()
			);
		}
		current = error.source();
	}
	"Operation failed; no safe diagnostic details available".to_owned()
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fmt;

	#[derive(thiserror::Error)]
	struct Untrusted;
	impl fmt::Display for Untrusted {
		fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
			panic!("untrusted Display invoked")
		}
	}
	impl fmt::Debug for Untrusted {
		fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
			panic!("untrusted Debug invoked")
		}
	}

	#[test]
	fn error_reporting_uses_only_approved_facts() {
		for error in [
			anyhow::Error::new(Untrusted).context("password-canary"),
			anyhow::Error::new(std::io::Error::other(Untrusted)),
			anyhow::Error::new(steamguard::ApproverError::Unknown(anyhow::Error::new(
				Untrusted,
			))),
			anyhow::Error::new(steamguard::FinalizeLinkError::Unknown(anyhow::Error::new(
				Untrusted,
			))),
			anyhow::Error::new(
				steamguard::accountlinker::RemoveAuthenticatorError::Unknown(anyhow::Error::new(
					Untrusted,
				)),
			),
			anyhow::Error::new(steamguard::accountlinker::TransferError::Unknown(
				anyhow::Error::new(Untrusted),
			)),
		] {
			assert!(
				!safe_error(error.as_ref()).contains("canary"),
				"error reporter exposed a secret"
			);
		}
		let malformed = serde_json::from_str::<bool>(r#""password-canary""#).unwrap_err();
		let error = anyhow::Error::new(malformed).context("cookie-canary");
		let diagnostic = safe_error(error.as_ref());
		assert!(diagnostic.contains("Invalid JSON"));
		assert!(
			!diagnostic.contains("canary"),
			"error reporter exposed a secret"
		);
	}
}
