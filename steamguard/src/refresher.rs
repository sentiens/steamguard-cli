use crate::{
	protobufs::steammessages_auth_steamclient::{
		CAuthentication_AccessToken_GenerateForApp_Request,
		CAuthentication_AccessToken_GenerateForApp_Response,
	},
	steamapi::{AuthenticationClient, EResult},
	token::{Jwt, Tokens},
	transport::{Transport, TransportError},
};

pub struct TokenRefresher<T>
where
	T: Transport,
{
	client: AuthenticationClient<T>,
}

impl<T> TokenRefresher<T>
where
	T: Transport,
{
	pub fn new(client: AuthenticationClient<T>) -> Self {
		Self { client }
	}

	/// Refreshes only the access token, retaining the upstream return type.
	/// Use [`Self::refresh_tokens`] to also receive a replacement refresh token.
	pub fn refresh(&mut self, steam_id: u64, tokens: &Tokens) -> Result<Jwt, anyhow::Error> {
		Ok(self
			.refresh_tokens(steam_id, tokens)?
			.access_token()
			.clone())
	}

	/// Returns both tokens, keeping the current refresh token only when Steam omits a replacement.
	pub fn refresh_tokens(
		&mut self,
		steam_id: u64,
		tokens: &Tokens,
	) -> Result<Tokens, RefreshError> {
		let mut req = CAuthentication_AccessToken_GenerateForApp_Request::new();
		req.set_steamid(steam_id);
		req.set_refresh_token(tokens.refresh_token().expose_secret().to_owned());

		let resp = self
			.client
			.generate_access_token(req, tokens.access_token())?;

		if resp.result != EResult::OK {
			return Err(RefreshError::SteamRejected(resp.result));
		}

		tokens_from_response(resp.into_response_data(), tokens.refresh_token())
	}
}

/// Applies the same token-presence rules to explicit refresh and refresh-only login polling.
pub(crate) fn tokens_from_response(
	mut response: CAuthentication_AccessToken_GenerateForApp_Response,
	current_refresh: &Jwt,
) -> Result<Tokens, RefreshError> {
	if response.access_token().is_empty() {
		return Err(RefreshError::MalformedResponse);
	}
	let refresh_token = match response.refresh_token.take() {
		Some(token) if token.is_empty() => return Err(RefreshError::MalformedResponse),
		Some(token) => token.into(),
		None => current_refresh.clone(),
	};
	Ok(Tokens::new(response.take_access_token(), refresh_token))
}

#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
	#[error("Steam rejected token refresh with result {0:?}")]
	SteamRejected(EResult),
	#[error("Steam returned an incomplete token refresh response")]
	MalformedResponse,
	#[error("Token refresh transport failed: {0}")]
	Transport(#[from] TransportError),
}
