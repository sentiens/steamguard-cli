use crate::api_responses::AllowedConfirmation;
use crate::protobufs::custom::CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData;
use crate::protobufs::enums::ESessionPersistence;
use crate::protobufs::steammessages_auth_steamclient::{
	CAuthentication_AccessToken_GenerateForApp_Request, CAuthentication_AllowedConfirmation,
	CAuthentication_DeviceDetails, CAuthentication_PollAuthSessionStatus_Request,
	EAuthSessionGuardType,
};
use crate::protobufs::steammessages_auth_steamclient::{
	CAuthentication_BeginAuthSessionViaCredentials_Response,
	CAuthentication_BeginAuthSessionViaQR_Request, CAuthentication_BeginAuthSessionViaQR_Response,
	CAuthentication_GetPasswordRSAPublicKey_Response,
	CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request,
	CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response, EAuthTokenPlatformType,
};
use crate::steamapi::authentication::AuthenticationClient;
use crate::steamapi::EResult;
use crate::token::Tokens;
use crate::transport::{NetworkError, Transport, TransportError};
use anyhow::Context;
use base64::Engine;
use log::*;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use std::{fmt, time::Duration};

pub enum LoginError {
	BadCredentials,
	TooManyAttempts,
	SessionExpired,
	SessionNotStarted,
	UnknownEResult(EResult),
	/// Steam returned an incomplete session/token response or an unsupported login outcome.
	UnknownOutcome,
	AuthAlreadyStarted,
	TransportError(TransportError),
	NetworkFailure(NetworkError),
	OtherFailure(anyhow::Error),
}

impl fmt::Debug for LoginError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::BadCredentials => f.write_str("BadCredentials"),
			Self::TooManyAttempts => f.write_str("TooManyAttempts"),
			Self::SessionExpired => f.write_str("SessionExpired"),
			Self::SessionNotStarted => f.write_str("SessionNotStarted"),
			Self::UnknownOutcome => f.write_str("UnknownOutcome"),
			Self::AuthAlreadyStarted => f.write_str("AuthAlreadyStarted"),
			Self::UnknownEResult(result) => f.debug_tuple("UnknownEResult").field(result).finish(),
			Self::TransportError(error) => f.debug_tuple("TransportError").field(error).finish(),
			Self::NetworkFailure(error) => f.debug_tuple("NetworkFailure").field(error).finish(),
			Self::OtherFailure(_) => f.write_str("OtherFailure([REDACTED])"),
		}
	}
}

impl std::fmt::Display for LoginError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
		write!(f, "{:?}", self)
	}
}

impl std::error::Error for LoginError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::TransportError(error) => Some(error),
			Self::NetworkFailure(error) => Some(error),
			Self::OtherFailure(error) => Some(error.as_ref()),
			_ => None,
		}
	}
}

impl From<TransportError> for LoginError {
	fn from(err: TransportError) -> Self {
		LoginError::TransportError(err)
	}
}

impl From<NetworkError> for LoginError {
	fn from(err: NetworkError) -> Self {
		LoginError::NetworkFailure(err)
	}
}

impl From<reqwest::Error> for LoginError {
	fn from(err: reqwest::Error) -> Self {
		LoginError::NetworkFailure(err.into())
	}
}

impl From<anyhow::Error> for LoginError {
	fn from(err: anyhow::Error) -> Self {
		LoginError::OtherFailure(err)
	}
}

impl From<EResult> for LoginError {
	fn from(err: EResult) -> Self {
		match err {
			EResult::InvalidPassword => LoginError::BadCredentials,
			EResult::RateLimitExceeded | EResult::AccountLoginDeniedThrottle => {
				LoginError::TooManyAttempts
			}
			// Steam also reports a missing/expired polling session as FileNotFound.
			EResult::Expired | EResult::FileNotFound => LoginError::SessionExpired,
			err => LoginError::UnknownEResult(err),
		}
	}
}

/// The result of one login polling step.
#[derive(Clone)]
pub enum PollOutcome {
	/// The session has not issued tokens yet.
	Waiting,
	/// Login completed, including access-token generation when Steam only issued a refresh token.
	Tokens(Tokens),
}

impl fmt::Debug for PollOutcome {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Waiting => f.write_str("Waiting"),
			Self::Tokens(_) => f.debug_tuple("Tokens").field(&"[REDACTED]").finish(),
		}
	}
}

#[derive(Clone)]
pub struct BeginQrLoginResponse {
	challenge_url: String,
	confirmation_methonds: Vec<AllowedConfirmation>,
}

impl fmt::Debug for BeginQrLoginResponse {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("BeginQrLoginResponse")
			.field("challenge_url", &"[REDACTED]")
			.field(
				"confirmation_method_count",
				&self.confirmation_methonds.len(),
			)
			.finish()
	}
}

impl BeginQrLoginResponse {
	pub fn challenge_url(&self) -> &String {
		&self.challenge_url
	}

	pub fn confirmation_methods(&self) -> &Vec<AllowedConfirmation> {
		&self.confirmation_methonds
	}
}

/// Handles the user login flow.
pub struct UserLogin<T>
where
	T: Transport + Clone,
{
	client: AuthenticationClient<T>,
	device_details: DeviceDetails,

	started_auth: Option<StartAuth>,
}

impl<T> fmt::Debug for UserLogin<T>
where
	T: Transport + Clone,
{
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("UserLogin")
			.field("device_details", &self.device_details)
			.field("started_auth", &self.started_auth)
			.finish_non_exhaustive()
	}
}

impl<T> UserLogin<T>
where
	T: Transport + Clone,
{
	pub fn new(transport: T, device_details: DeviceDetails) -> Self {
		Self {
			client: AuthenticationClient::new(transport),
			device_details,
			started_auth: None,
		}
	}

	pub fn begin_auth_via_credentials(
		&mut self,
		account_name: &str,
		password: &str,
	) -> Result<Vec<AllowedConfirmation>, LoginError> {
		if self.started_auth.is_some() {
			return Err(LoginError::AuthAlreadyStarted);
		}
		trace!("UserLogin::begin_auth_via_credentials");

		let rsa = self.client.fetch_rsa_key(account_name.to_owned())?;

		let mut req = CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData::new();
		req.set_account_name(account_name.to_owned());
		let rsa_resp = rsa.into_response_data();
		req.set_encryption_timestamp(rsa_resp.timestamp());
		let encrypted_password = encrypt_password(rsa_resp, password)?;
		req.set_encrypted_password(encrypted_password);
		req.set_persistence(ESessionPersistence::k_ESessionPersistence_Persistent);
		req.device_details = self.device_details.clone().into_message_field();
		req.set_language(0); // english, probably
		req.set_qos_level(2); // value from observed traffic

		let resp = self.client.begin_auth_session_via_credentials(req)?;

		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}

		let started_auth: StartAuth = resp.into_response_data().into();
		started_auth.validate()?;
		debug!("auth session started");
		let allowed_confirmations = started_auth
			.allowed_confirmations()
			.iter()
			.map(|c| c.clone().into())
			.collect();
		self.started_auth = Some(started_auth);

		Ok(allowed_confirmations)
	}

	pub fn begin_auth_via_qr(&mut self) -> Result<BeginQrLoginResponse, LoginError> {
		if self.started_auth.is_some() {
			return Err(LoginError::AuthAlreadyStarted);
		}

		let mut req = CAuthentication_BeginAuthSessionViaQR_Request::new();
		req.set_platform_type(self.device_details.platform_type);
		req.set_device_friendly_name(self.device_details.friendly_name.clone());
		let resp = self.client.begin_auth_session_via_qr(req)?;

		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}

		let data = resp.response_data();
		let return_resp = BeginQrLoginResponse {
			challenge_url: data.challenge_url().into(),
			confirmation_methonds: data
				.allowed_confirmations
				.iter()
				.map(|c| c.clone().into())
				.collect(),
		};

		let started_auth: StartAuth = resp.into_response_data().into();
		started_auth.validate()?;
		debug!("auth session started");
		self.started_auth = Some(started_auth);

		Ok(return_resp)
	}

	/// Returns Steam's requested polling interval without applying a default or a clamp.
	///
	/// Returns `None` before authentication starts or when Steam omits the interval.
	/// Invalid intervals are rejected when starting authentication.
	pub fn poll_interval(&self) -> Option<Duration> {
		self.started_auth
			.as_ref()?
			.interval()
			.and_then(|seconds| poll_interval(seconds).ok())
	}

	/// Polls the current session once, without sleeping or retrying.
	///
	/// This makes one polling request. A refresh-only response also requires one
	/// access-token request; both requests use the configured transport synchronously.
	/// Callers schedule subsequent steps using [`Self::poll_interval`].
	pub fn poll_once(&mut self) -> Result<PollOutcome, LoginError> {
		let Some(started_auth) = self.started_auth.as_mut() else {
			return Err(LoginError::SessionNotStarted);
		};

		let mut req = CAuthentication_PollAuthSessionStatus_Request::new();
		req.set_client_id(started_auth.client_id());
		req.set_request_id(started_auth.request_id().to_vec());

		let resp = self.client.poll_auth_session(req)?;
		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}

		let mut data = resp.into_response_data();
		if data.has_new_client_id() {
			started_auth.set_client_id(data.new_client_id());
		}
		if !data.agreement_session_url().is_empty() {
			return Err(LoginError::UnknownOutcome);
		}
		if !data.has_access_token() && !data.has_refresh_token() {
			return Ok(PollOutcome::Waiting);
		}
		if data.refresh_token().is_empty() {
			return Err(LoginError::UnknownOutcome);
		}

		let mut tokens = Tokens::new(data.take_access_token(), data.take_refresh_token());
		if tokens.access_token().expose_secret().is_empty() {
			// Steam has issued refresh-only login responses since 2023-09-12.
			let steam_id = tokens
				.refresh_token()
				.decode()
				.context("decoding refresh token for steam id")?
				.try_steam_id()
				.context("reading Steam ID from refresh token")?;
			let mut req = CAuthentication_AccessToken_GenerateForApp_Request::new();
			req.set_steamid(steam_id);
			req.set_refresh_token(tokens.refresh_token().expose_secret().to_owned());
			let resp = self
				.client
				.generate_access_token(req, tokens.access_token())?;
			if resp.result != EResult::OK {
				return Err(resp.result.into());
			}
			tokens = crate::refresher::tokens_from_response(
				resp.into_response_data(),
				tokens.refresh_token(),
			)
			.map_err(|_| LoginError::UnknownOutcome)?;
		}
		Ok(PollOutcome::Tokens(tokens))
	}

	/// Polls until tokens are ready, waiting between steps at Steam's requested interval.
	/// When Steam omits the interval, preserves the upstream zero-duration wait.
	pub fn poll_until_tokens(&mut self) -> anyhow::Result<Tokens> {
		loop {
			match self.poll_once()? {
				PollOutcome::Tokens(tokens) => return Ok(tokens),
				PollOutcome::Waiting => {
					let interval = match self.poll_interval() {
						Some(interval) => interval,
						None => Duration::ZERO,
					};
					std::thread::sleep(interval);
				}
			}
		}
	}

	/// Submit a 2fa code generated from a device, or received in an email.
	pub fn submit_steam_guard_code(
		&mut self,
		guard_type: EAuthSessionGuardType,
		code: String,
	) -> Result<CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response, UpdateAuthSessionError>
	{
		let Some(started_auth) = self.started_auth.as_ref() else {
			return Err(UpdateAuthSessionError::SessionNotStarted);
		};

		if guard_type != EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode
			&& guard_type != EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode
		{
			return Err(UpdateAuthSessionError::InvalidGuardType);
		}

		let mut req = CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request::new();
		req.set_client_id(started_auth.client_id());
		req.set_code_type(guard_type);
		req.set_code(code);
		match started_auth {
			StartAuth::BeginAuthSessionViaCredentials(ref resp) => {
				req.set_steamid(resp.steamid());
			}
			StartAuth::BeginAuthSessionViaQR(_) => {
				return Err(anyhow::anyhow!("qr auth not supported").into());
			}
		}

		let resp = self.client.update_session_with_steam_guard_code(req)?;

		if resp.result != EResult::OK {
			return Err(resp.result.into());
		}

		Ok(resp.into_response_data())
	}
}

fn encrypt_password(
	rsa_resp: CAuthentication_GetPasswordRSAPublicKey_Response,
	password: impl AsRef<[u8]>,
) -> anyhow::Result<String> {
	let rsa_exponent = rsa::BigUint::parse_bytes(rsa_resp.publickey_exp().as_bytes(), 16)
		.ok_or_else(|| anyhow::anyhow!("invalid RSA exponent in login response"))?;
	let rsa_modulus = rsa::BigUint::parse_bytes(rsa_resp.publickey_mod().as_bytes(), 16)
		.ok_or_else(|| anyhow::anyhow!("invalid RSA modulus in login response"))?;
	let public_key = RsaPublicKey::new(rsa_modulus, rsa_exponent)
		.context("invalid RSA public key in login response")?;
	#[cfg(test)]
	let mut rng = tests::MockStepRng::new(2, 1);
	#[cfg(not(test))]
	let mut rng = rsa::rand_core::OsRng;
	let encrypted = public_key
		.encrypt(&mut rng, Pkcs1v15Encrypt, password.as_ref())
		.context("password could not be encrypted with the login key")?;
	Ok(base64::engine::general_purpose::STANDARD.encode(encrypted))
}

fn poll_interval(seconds: f32) -> anyhow::Result<Duration> {
	Duration::try_from_secs_f32(seconds)
		.map_err(|_| anyhow::anyhow!("invalid polling interval in login response"))
}

enum StartAuth {
	BeginAuthSessionViaCredentials(CAuthentication_BeginAuthSessionViaCredentials_Response),
	BeginAuthSessionViaQR(CAuthentication_BeginAuthSessionViaQR_Response),
}

impl fmt::Debug for StartAuth {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::BeginAuthSessionViaCredentials(_) => {
				f.write_str("BeginAuthSessionViaCredentials([REDACTED])")
			}
			Self::BeginAuthSessionViaQR(_) => f.write_str("BeginAuthSessionViaQR([REDACTED])"),
		}
	}
}

impl StartAuth {
	fn validate(&self) -> Result<(), LoginError> {
		if self.client_id() == 0 || self.request_id().is_empty() {
			return Err(LoginError::UnknownOutcome);
		}
		if let Self::BeginAuthSessionViaQR(response) = self {
			if response.challenge_url().is_empty() {
				return Err(LoginError::UnknownOutcome);
			}
		}
		self.interval().map(poll_interval).transpose()?;
		Ok(())
	}

	pub(crate) fn client_id(&self) -> u64 {
		match self {
			StartAuth::BeginAuthSessionViaCredentials(resp) => resp.client_id(),
			StartAuth::BeginAuthSessionViaQR(resp) => resp.client_id(),
		}
	}

	fn set_client_id(&mut self, client_id: u64) {
		match self {
			StartAuth::BeginAuthSessionViaCredentials(resp) => resp.set_client_id(client_id),
			StartAuth::BeginAuthSessionViaQR(resp) => resp.set_client_id(client_id),
		}
	}

	pub(crate) fn request_id(&self) -> &[u8] {
		match self {
			StartAuth::BeginAuthSessionViaCredentials(resp) => resp.request_id(),
			StartAuth::BeginAuthSessionViaQR(resp) => resp.request_id(),
		}
	}

	pub(crate) fn interval(&self) -> Option<f32> {
		match self {
			StartAuth::BeginAuthSessionViaCredentials(resp) => resp.interval,
			StartAuth::BeginAuthSessionViaQR(resp) => resp.interval,
		}
	}

	pub(crate) fn allowed_confirmations(&self) -> &Vec<CAuthentication_AllowedConfirmation> {
		match self {
			StartAuth::BeginAuthSessionViaCredentials(resp) => &resp.allowed_confirmations,
			StartAuth::BeginAuthSessionViaQR(resp) => &resp.allowed_confirmations,
		}
	}
}

impl From<CAuthentication_BeginAuthSessionViaCredentials_Response> for StartAuth {
	fn from(resp: CAuthentication_BeginAuthSessionViaCredentials_Response) -> Self {
		Self::BeginAuthSessionViaCredentials(resp)
	}
}

impl From<CAuthentication_BeginAuthSessionViaQR_Response> for StartAuth {
	fn from(resp: CAuthentication_BeginAuthSessionViaQR_Response) -> Self {
		Self::BeginAuthSessionViaQR(resp)
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceDetails {
	/// The name to display for this device. You should make this unique, identifiable, and human readable. Used when managing account sessions.
	pub friendly_name: String,
	pub platform_type: EAuthTokenPlatformType,
	/// Corresponds to the EOSType enum.
	pub os_type: i32,
	/// Corresponds to the EGamingDeviceType enum.
	pub gaming_device_type: u32,
}

impl DeviceDetails {
	fn into_message_field(self) -> protobuf::MessageField<CAuthentication_DeviceDetails> {
		Some(self.into()).into()
	}
}

impl From<DeviceDetails> for CAuthentication_DeviceDetails {
	fn from(details: DeviceDetails) -> Self {
		let mut inner = CAuthentication_DeviceDetails::new();
		inner.set_device_friendly_name(details.friendly_name);
		inner.set_platform_type(details.platform_type);
		inner.set_os_type(details.os_type);
		inner.set_gaming_device_type(details.gaming_device_type);
		inner
	}
}

pub enum UpdateAuthSessionError {
	SessionNotStarted,
	InvalidGuardType,
	TooManyAttempts,
	SessionExpired,
	IncorrectSteamGuardCode,
	/// This login session already was approved somewhere else. Polling should give you the tokens.
	DuplicateRequest,
	UnknownEResult(EResult),
	TransportError(TransportError),
	NetworkFailure(NetworkError),
	OtherFailure(anyhow::Error),
}

impl fmt::Debug for UpdateAuthSessionError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::SessionNotStarted => f.write_str("SessionNotStarted"),
			Self::InvalidGuardType => f.write_str("InvalidGuardType"),
			Self::TooManyAttempts => f.write_str("TooManyAttempts"),
			Self::SessionExpired => f.write_str("SessionExpired"),
			Self::IncorrectSteamGuardCode => f.write_str("IncorrectSteamGuardCode"),
			Self::DuplicateRequest => f.write_str("DuplicateRequest"),
			Self::UnknownEResult(result) => f.debug_tuple("UnknownEResult").field(result).finish(),
			Self::TransportError(error) => f.debug_tuple("TransportError").field(error).finish(),
			Self::NetworkFailure(error) => f.debug_tuple("NetworkFailure").field(error).finish(),
			Self::OtherFailure(_) => f.write_str("OtherFailure([REDACTED])"),
		}
	}
}

impl std::fmt::Display for UpdateAuthSessionError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
		write!(f, "{:?}", self)
	}
}

impl std::error::Error for UpdateAuthSessionError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::TransportError(error) => Some(error),
			Self::NetworkFailure(error) => Some(error),
			Self::OtherFailure(error) => Some(error.as_ref()),
			_ => None,
		}
	}
}

impl From<EResult> for UpdateAuthSessionError {
	fn from(err: EResult) -> Self {
		match err {
			EResult::RateLimitExceeded => UpdateAuthSessionError::TooManyAttempts,
			EResult::Expired => UpdateAuthSessionError::SessionExpired,
			EResult::TwoFactorCodeMismatch => UpdateAuthSessionError::IncorrectSteamGuardCode,
			EResult::DuplicateRequest => UpdateAuthSessionError::DuplicateRequest,
			_ => UpdateAuthSessionError::UnknownEResult(err),
		}
	}
}

impl From<TransportError> for UpdateAuthSessionError {
	fn from(err: TransportError) -> Self {
		UpdateAuthSessionError::TransportError(err)
	}
}

impl From<NetworkError> for UpdateAuthSessionError {
	fn from(err: NetworkError) -> Self {
		UpdateAuthSessionError::NetworkFailure(err)
	}
}

impl From<reqwest::Error> for UpdateAuthSessionError {
	fn from(err: reqwest::Error) -> Self {
		UpdateAuthSessionError::NetworkFailure(err.into())
	}
}

impl From<anyhow::Error> for UpdateAuthSessionError {
	fn from(err: anyhow::Error) -> Self {
		UpdateAuthSessionError::OtherFailure(err)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	pub(crate) struct MockStepRng {
		v: u64,
		a: u64,
	}

	impl MockStepRng {
		pub(crate) fn new(initial: u64, increment: u64) -> Self {
			Self {
				v: initial,
				a: increment,
			}
		}
	}

	impl rsa::rand_core::RngCore for MockStepRng {
		fn next_u32(&mut self) -> u32 {
			self.next_u64() as u32
		}

		fn next_u64(&mut self) -> u64 {
			let result = self.v;
			self.v = self.v.wrapping_add(self.a);
			result
		}

		fn fill_bytes(&mut self, dest: &mut [u8]) {
			rsa::rand_core::impls::fill_bytes_via_next(self, dest)
		}

		fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
			self.fill_bytes(dest);
			Ok(())
		}
	}
	impl rsa::rand_core::CryptoRng for MockStepRng {}

	#[test]
	fn test_encrypt_password() {
		let mut rsa_resp = CAuthentication_GetPasswordRSAPublicKey_Response::new();
		rsa_resp.set_publickey_exp(String::from("010001"));
		rsa_resp.set_publickey_mod(String::from("98f9088c1250b17fe19d2b2422d54a1eef0036875301731f11bd17900e215318eb6de1546727c0b7b61b86cefccdcb2f8108c813154d9a7d55631965eece810d4ab9d8a59c486bda778651b876176070598a93c2325c275cb9c17bdbcacf8edc9c18c0c5d59bc35703505ef8a09ed4c62b9f92a3fac5740ce25e490ab0e26d872140e4103d912d1e3958f844264211277ee08d2b4dd3ac58b030b25342bd5c949ae7794e46a8eab26d5a8deca683bfd381da6c305b19868b8c7cd321ce72c693310a6ebf2ecd43642518f825894602f6c239cf193cb4346ce64beac31e20ef88f934f2f776597734bb9eae1ebdf4a453973b6df9d5e90777bffe5db83dd1757b"));
		rsa_resp.set_timestamp(1);
		let result = encrypt_password(rsa_resp, "kelwleofpsm3n4ofc").unwrap();
		assert_eq!(result.len(), 344);
		assert_eq!(result, "RUo/3IfbkVcJi1q1S5QlpKn1mEn3gNJoc/Z4VwxRV9DImV6veq/YISEuSrHB3885U5MYFLn1g94Y+cWRL6HGXoV+gOaVZe43m7O92RwiVz6OZQXMfAv3UC/jcqn/xkitnj+tNtmx55gCxmGbO2KbqQ0TQqAyqCOOw565B+Cwr2OOorpMZAViv9sKA/G3Q6yzscU6rhua179c8QjC1Hk3idUoSzpWfT4sHNBW/EREXZ3Dkjwu17xzpfwIUpnBVIlR8Vj3coHgUCpTsKVRA3T814v9BYPlvLYwmw5DW3ddx+2SyTY0P5uuog36TN2PqYS7ioF5eDe16gyfRR4Nzn/7wA==");
	}

	#[test]
	fn test_encrypt_password_2() {
		let mut rsa_resp = CAuthentication_GetPasswordRSAPublicKey_Response::new();
		rsa_resp.set_publickey_exp(String::from("010001"));
		rsa_resp.set_publickey_mod(String::from("ca6a8dc290279b25c38a282b9a7b01306c5978bd7a2f60dcfd52134ac58faf121568ebd85ca6a2128413b76ec70fb3150b3181bbe2a1a8349b68da9c303960bdf4e34296b27bd4ea29b4d1a695168ddfc974bb6ba427206fdcdb088bf27261a52f343a51e19759fe4072b7a2047a6bc31361950d9e87d7977b31b71696572babe45ea6a7d132547984462fd5787607e0d9ff1c637e04d593e7538c880c3cdd252b75bcb703a7b8bb01cd8898b04980f40b76235d50fc1544c39ccbe763892322fc6d0a5acaf8be09efbc20fcfebcd3b02a1eb95d9d0c338e96674c17edbb0257cd43d04974423f1f995a28b9e159322d9db2708826804c0eccafffc94dd2a3d5"));
		rsa_resp.set_timestamp(104444850000);
		let result = encrypt_password(rsa_resp, "foo").unwrap();
		assert_eq!(result, "jmlMXmhbweWn+wJnnf96W3Lsh0dRmzrBfMxREUuEW11rRYcfXWupBIT3eK1fmQHMZmyJeMhZiRpgIaZ7DafojQT6djJr+RKeREJs0ys9hKwxD5FGlqsTLXXEeuyopyd2smHBbmmF47voe59KEoiZZapP+eYnpJy3O2k7e1P9BH9LsKIN/nWF1ogM2jjJ328AejUpM64tPl/kInFJ1CHrLiAAKDPk42fLAAKs97xIi0JkosG6yp+8HhFqQxxZ8/bNI1IVkQC1Hdc2AN0QlNKxbDXquAn6ARgw/4b5DwUpnOb9de+Q6iX3v1/M07Se7JV8/4tuz8Thy2Chbxsf9E1TuQ==");
	}

	#[test]
	fn qr_login_response_debug_redacts_the_challenge() {
		let response = BeginQrLoginResponse {
			challenge_url: "challenge-url-canary".to_owned(),
			confirmation_methonds: vec![AllowedConfirmation {
				confirmation_type:
					EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation,
				associated_messsage: "confirmation-message-canary".to_owned(),
			}],
		};

		let output = format!("{response:?}");
		assert!(
			!output.contains("challenge-url-canary"),
			"sensitive assertion failed"
		);
		assert!(
			!output.contains("confirmation-message-canary"),
			"sensitive assertion failed"
		);
		assert!(output.contains("[REDACTED]"), "sensitive assertion failed");
	}

	#[test]
	fn malformed_login_parameters_return_errors() {
		let mut invalid_exponent = CAuthentication_GetPasswordRSAPublicKey_Response::new();
		invalid_exponent.set_publickey_exp("not-hex".to_owned());
		invalid_exponent.set_publickey_mod("11".to_owned());
		assert!(
			encrypt_password(invalid_exponent, "password").is_err(),
			"sensitive assertion failed"
		);

		let mut invalid_modulus = CAuthentication_GetPasswordRSAPublicKey_Response::new();
		invalid_modulus.set_publickey_exp("010001".to_owned());
		invalid_modulus.set_publickey_mod("not-hex".to_owned());
		assert!(
			encrypt_password(invalid_modulus, "password").is_err(),
			"sensitive assertion failed"
		);

		assert!(poll_interval(f32::NAN).is_err());
		assert!(poll_interval(-1.0).is_err());
	}
}
