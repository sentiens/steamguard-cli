use anyhow::Context;
use base64::Engine;
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, Secret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha1::Sha1;
use std::{convert::TryInto, fmt};

#[derive(Clone)]
pub struct TwoFactorSecret(Secret<[u8; 20]>);

impl fmt::Debug for TwoFactorSecret {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("TwoFactorSecret")
			.field(&"[REDACTED]")
			.finish()
	}
}

impl Default for TwoFactorSecret {
	fn default() -> Self {
		Self::new()
	}
}

impl TwoFactorSecret {
	pub fn new() -> Self {
		Self([0u8; 20].into())
	}

	pub fn from_bytes(bytes: Vec<u8>) -> Self {
		Self::try_from_bytes(bytes).expect("two-factor secrets must contain exactly 20 bytes")
	}

	/// Creates a two-factor secret after validating its length.
	pub fn try_from_bytes(bytes: Vec<u8>) -> anyhow::Result<Self> {
		let length = bytes.len();
		let bytes: [u8; 20] = bytes.try_into().map_err(|_| {
			anyhow::anyhow!("two-factor secret must contain exactly 20 bytes; got {length}")
		})?;
		Ok(Self(bytes.into()))
	}

	pub fn parse_shared_secret(secret: String) -> anyhow::Result<Self> {
		let bytes = base64::engine::general_purpose::STANDARD
			.decode(secret)
			.map_err(|_| anyhow::anyhow!("shared secret is not valid base64"))?;
		Self::try_from_bytes(bytes)
	}

	/// Generates a 5 character 2FA code for the supplied Unix timestamp.
	///
	/// Callers that maintain a Steam time offset should apply it before passing the timestamp.
	pub fn generate_code(&self, time: u64) -> String {
		let steam_guard_code_translations: [u8; 26] = [
			50, 51, 52, 53, 54, 55, 56, 57, 66, 67, 68, 70, 71, 72, 74, 75, 77, 78, 80, 81, 82, 84,
			86, 87, 88, 89,
		];

		let mut mac = Hmac::<Sha1>::new_from_slice(self.0.expose_secret()).unwrap();
		// this effectively makes it so that it creates a new code every 30 seconds.
		mac.update(&build_time_bytes(time / 30u64));
		let result = mac.finalize();
		let hashed_data = result.into_bytes();
		let mut code_array: [u8; 5] = [0; 5];
		let b = (hashed_data[19] & 0xF) as usize;
		let mut code_point: i32 = (((hashed_data[b] & 0x7F) as i32) << 24)
			| ((hashed_data[b + 1] as i32) << 16)
			| ((hashed_data[b + 2] as i32) << 8)
			| (hashed_data[b + 3] as i32);

		for item in &mut code_array {
			*item = steam_guard_code_translations
				[code_point as usize % steam_guard_code_translations.len()];
			code_point /= steam_guard_code_translations.len() as i32;
		}

		String::from_utf8(code_array.to_vec()).unwrap()
	}

	/// Expose the underlying secret as a byte array.
	pub fn expose_secret(&self) -> &[u8; 20] {
		self.0.expose_secret()
	}
}

impl Serialize for TwoFactorSecret {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(
			base64::engine::general_purpose::STANDARD
				.encode(self.0.expose_secret())
				.as_str(),
		)
	}
}

impl<'de> Deserialize<'de> for TwoFactorSecret {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		TwoFactorSecret::parse_shared_secret(String::deserialize(deserializer)?)
			.map_err(serde::de::Error::custom)
	}
}

impl PartialEq for TwoFactorSecret {
	fn eq(&self, other: &Self) -> bool {
		self.0.expose_secret() == other.0.expose_secret()
	}
}

impl Eq for TwoFactorSecret {}

fn build_time_bytes(time: u64) -> [u8; 8] {
	time.to_be_bytes()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Tokens {
	access_token: Jwt,
	refresh_token: Jwt,
}

impl fmt::Debug for Tokens {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Tokens")
			.field("access_token", &"[REDACTED]")
			.field("refresh_token", &"[REDACTED]")
			.finish()
	}
}

impl Tokens {
	pub fn new(access_token: impl Into<Jwt>, refresh_token: impl Into<Jwt>) -> Self {
		Self {
			access_token: access_token.into(),
			refresh_token: refresh_token.into(),
		}
	}

	pub fn access_token(&self) -> &Jwt {
		&self.access_token
	}

	pub fn set_access_token(&mut self, token: Jwt) {
		self.access_token = token;
	}

	pub fn refresh_token(&self) -> &Jwt {
		&self.refresh_token
	}
}

#[derive(Clone, Deserialize)]
pub struct Jwt(SecretString);

impl fmt::Debug for Jwt {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("Jwt").field(&"[REDACTED]").finish()
	}
}

impl Serialize for Jwt {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(self.0.expose_secret())
	}
}

impl Jwt {
	pub fn decode(&self) -> anyhow::Result<SteamJwtData> {
		decode_jwt(self.0.expose_secret())
	}

	pub fn expose_secret(&self) -> &str {
		self.0.expose_secret()
	}
}

impl From<String> for Jwt {
	fn from(s: String) -> Self {
		Self(SecretString::new(s))
	}
}

fn decode_jwt(jwt: impl AsRef<str>) -> anyhow::Result<SteamJwtData> {
	let mut parts = jwt.as_ref().split('.');
	let header = parts.next().ok_or_else(|| anyhow::anyhow!("Invalid JWT"))?;
	let data = parts.next().ok_or_else(|| anyhow::anyhow!("Invalid JWT"))?;
	let signature = parts.next().ok_or_else(|| anyhow::anyhow!("Invalid JWT"))?;
	ensure!(parts.next().is_none(), "Invalid JWT");
	ensure!(
		!header.is_empty() && !data.is_empty() && !signature.is_empty(),
		"Invalid JWT"
	);
	let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
		.decode(data)
		.map_err(|_| anyhow::anyhow!("JWT payload is not valid base64url"))?;
	// JSON/UTF-8 errors can include input strings or byte dumps. Do not retain those sources.
	let jwt_data: SteamJwtData = serde_json::from_slice(&bytes)
		.map_err(|_| anyhow::anyhow!("JWT payload is not valid claim data"))?;
	jwt_data
		.try_steam_id()
		.context("JWT subject is not a valid Steam ID")?;
	Ok(jwt_data)
}

#[derive(Deserialize)]
pub struct SteamJwtData {
	pub exp: u64,
	pub iat: u64,
	pub iss: String,
	/// Audience
	pub aud: Vec<String>,
	/// Subject (steam id)
	pub sub: String,
	pub jti: String,
}

impl fmt::Debug for SteamJwtData {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("SteamJwtData")
			.field("exp", &"[REDACTED]")
			.field("iat", &"[REDACTED]")
			.field("iss", &"[REDACTED]")
			.field("aud", &"[REDACTED]")
			.field("sub", &"[REDACTED]")
			.field("jti", &"[REDACTED]")
			.finish()
	}
}

impl SteamJwtData {
	pub fn steam_id(&self) -> u64 {
		self.try_steam_id().unwrap_or_default()
	}

	/// Parses the subject claim as a Steam ID.
	pub fn try_steam_id(&self) -> anyhow::Result<u64> {
		self.sub
			.parse::<u64>()
			.map_err(|_| anyhow::anyhow!("JWT subject is not a valid Steam ID"))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
	struct FooBar {
		secret: TwoFactorSecret,
	}

	#[test]
	fn test_serialize_2fa_secret() -> anyhow::Result<()> {
		let secret = FooBar {
			secret: TwoFactorSecret::parse_shared_secret("zvIayp3JPvtvX/QGHqsqKBk/44s=".into())?,
		};

		let serialized = serde_json::to_string(&secret)?;
		assert_eq!(serialized, "{\"secret\":\"zvIayp3JPvtvX/QGHqsqKBk/44s=\"}");

		Ok(())
	}

	#[test]
	fn test_deserialize_2fa_secret() -> anyhow::Result<()> {
		let secret: FooBar = serde_json::from_str("{\"secret\":\"zvIayp3JPvtvX/QGHqsqKBk/44s=\"}")?;

		let code = secret.secret.generate_code(1616374841u64);
		assert_eq!(code, "2F9J5");

		Ok(())
	}

	#[test]
	fn test_serialize_and_deserialize_2fa_secret() -> anyhow::Result<()> {
		let secret = FooBar {
			secret: TwoFactorSecret::parse_shared_secret("zvIayp3JPvtvX/QGHqsqKBk/44s=".into())?,
		};

		let serialized = serde_json::to_string(&secret)?;
		let deserialized: FooBar = serde_json::from_str(&serialized)?;
		assert_eq!(deserialized, secret);

		Ok(())
	}

	#[test]
	fn test_build_time_bytes() {
		let t1 = build_time_bytes(1617591917u64);
		let t2: [u8; 8] = [0, 0, 0, 0, 96, 106, 126, 109];
		assert!(
			t1.iter().zip(t2.iter()).all(|(a, b)| a == b),
			"Arrays are not equal, got {:?}",
			t1
		);
	}

	#[test]
	fn test_generate_code() -> anyhow::Result<()> {
		let secret = TwoFactorSecret::parse_shared_secret("zvIayp3JPvtvX/QGHqsqKBk/44s=".into())?;

		let code = secret.generate_code(1616374841u64);
		assert_eq!(code, "2F9J5");
		assert_eq!(secret.generate_code(1616374859u64), "2F9J5");
		Ok(())
	}

	#[test]
	fn malformed_token_is_an_error_not_a_panic() {
		let encode = |payload: &[u8]| {
			format!(
				"header.{}.signature",
				base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
			)
		};
		let mut inputs: Vec<String> = [
			"",
			"header",
			"header.payload",
			".payload.signature",
			"header..signature",
			"header.payload.",
			"a.b.c.d",
			"header.%!.signature",
		]
		.into_iter()
		.map(str::to_owned)
		.collect();
		inputs.extend([
			encode(b"\xffutf8-secret-canary"),
			encode(b"{\"secret-canary\":"),
			encode(
				br#"{"exp":"json-secret-canary","iat":1,"iss":"s","aud":[],"sub":"1","jti":"j"}"#,
			),
			encode(
				br#"{"exp":1,"iat":1,"iss":"s","aud":[],"sub":"18446744073709551616","jti":"j"}"#,
			),
		]);
		for input in inputs {
			let result = std::panic::catch_unwind(|| Jwt::from(input).decode());
			let error = result.expect("fallible JWT decoding panicked").unwrap_err();
			let diagnostic = format!("{error} {error:?} {error:#}");
			assert!(!diagnostic.contains("secret-canary"), "JWT input leaked");
			assert!(!diagnostic.contains("[255,"), "JWT byte dump leaked");
		}
	}

	#[test]
	fn shared_secret_length_is_checked() {
		for len in [0, 1, 19, 21, 40] {
			let error = TwoFactorSecret::try_from_bytes(vec![42; len]).unwrap_err();
			assert!(error.to_string().contains(&format!("got {len}")));
			let encoded = base64::engine::general_purpose::STANDARD.encode(vec![42; len]);
			let error = TwoFactorSecret::parse_shared_secret(encoded.clone()).unwrap_err();
			assert!(error.to_string().contains(&format!("got {len}")));
			if !encoded.is_empty() {
				assert!(!format!("{error:?}").contains(&encoded));
			}
		}
		assert_eq!(
			TwoFactorSecret::try_from_bytes(vec![42; 20])
				.unwrap()
				.expose_secret(),
			&[42; 20]
		);
	}

	#[test]
	fn debug_output_redacts_secrets_tokens_and_jwt_data() {
		let raw_secret = b"two-factor-canary!!!".to_vec();
		let raw_secret_debug = format!("{raw_secret:?}");
		let two_factor_secret = TwoFactorSecret::from_bytes(raw_secret);
		let tokens = Tokens::new(
			"access-token-canary".to_owned(),
			"refresh-token-canary".to_owned(),
		);
		let jwt = Jwt::from("raw-jwt-canary".to_owned());
		let jwt_data = SteamJwtData {
			exp: 8765432109,
			iat: 7654321098,
			iss: "issuer-canary".to_owned(),
			aud: vec!["audience-canary".to_owned()],
			sub: "subject-canary".to_owned(),
			jti: "identifier-canary".to_owned(),
		};

		let output = format!("{two_factor_secret:?} {tokens:?} {jwt:?} {jwt_data:?}");
		for canary in [
			"two-factor-canary!!!",
			"access-token-canary",
			"refresh-token-canary",
			"raw-jwt-canary",
			"issuer-canary",
			"audience-canary",
			"subject-canary",
			"identifier-canary",
			"8765432109",
			"7654321098",
		] {
			assert!(!output.contains(canary));
		}
		assert!(!output.contains(&raw_secret_debug));
		assert!(output.contains("[REDACTED]"));
	}

	#[test]
	fn malformed_secrets_and_tokens_return_errors() {
		assert!(TwoFactorSecret::try_from_bytes(vec![0; 19]).is_err());
		assert!(TwoFactorSecret::parse_shared_secret("c2hvcnQ=".to_owned()).is_err());
		assert!(serde_json::from_str::<FooBar>("{\"secret\":\"c2hvcnQ=\"}").is_err());
		assert!(decode_jwt("header.payload").is_err());
		assert!(decode_jwt("header.not-base64.signature").is_err());
		assert!(decode_jwt(".payload.signature").is_err());

		let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
			.encode(br#"{"exp":1,"iat":1,"iss":"steam","aud":[],"sub":"invalid","jti":"id"}"#);
		assert!(decode_jwt(format!("header.{payload}.signature")).is_err());

		let jwt_data = SteamJwtData {
			exp: 1,
			iat: 2,
			iss: "steam".to_owned(),
			aud: vec!["web".to_owned()],
			sub: "not-a-steam-id".to_owned(),
			jti: "id".to_owned(),
		};
		assert!(jwt_data.try_steam_id().is_err());
	}

	#[test]
	fn test_decode_jwt() {
		let sample: Jwt = "eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInN0ZWFtIiwgInN1YiI6ICI3NjU2MTE5OTE1NTcwNjg5MiIsICJhdWQiOiBbICJ3ZWIiLCAicmVuZXciLCAiZGVyaXZlIiBdLCAiZXhwIjogMTcwNTAxMTk1NSwgIm5iZiI6IDE2Nzg0NjQ4MzcsICJpYXQiOiAxNjg3MTA0ODM3LCAianRpIjogIjE4QzVfMjJCM0Y0MzFfQ0RGNkEiLCAib2F0IjogMTY4NzEwNDgzNywgInBlciI6IDEsICJpcF9zdWJqZWN0IjogIjY5LjEyMC4xMzYuMTI0IiwgImlwX2NvbmZpcm1lciI6ICI2OS4xMjAuMTM2LjEyNCIgfQ.7p5TPj9pGQbxIzWDDNCSP9OkKYSeDnWBE8E-M8hUrxOEPCW0XwrbDUrh199RzjPDw".to_owned().into();
		let data = sample.decode().expect("Failed to decode JWT");

		assert_eq!(data.exp, 1705011955);
		assert_eq!(data.iat, 1687104837);
		assert_eq!(data.iss, "steam");
		assert_eq!(data.aud, vec!["web", "renew", "derive"]);
		assert_eq!(data.sub, "76561199155706892");
		assert_eq!(data.try_steam_id().unwrap(), 76561199155706892);
		assert_eq!(data.jti, "18C5_22B3F431_CDF6A");
	}

	#[test]
	fn test_decode_jwt_2() {
		let sample: Jwt = "eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInI6MTRCM18yMkZEQjg0RF9BMjJDRCIsICJzdWIiOiAiNzY1NjExOTk0NDE5OTI5NzAiLCAiYXVkIjogWyAid2ViIiwgIm1vYmlsZSIgXSwgImV4cCI6IDE2OTE3NTc5MzUsICJuYmYiOiAxNjgzMDMxMDUxLCAiaWF0IjogMTY5MTY3MTA1MSwgImp0aSI6ICIxNTI1XzIyRkRCOUJBXzZBRDkwIiwgIm9hdCI6IDE2OTE2NzEwNTEsICJydF9leHAiOiAxNzEwMDExNjg5LCAicGVyIjogMCwgImlwX3N1YmplY3QiOiAiMTA0LjI0Ni4xMjUuMTQxIiwgImlwX2NvbmZpcm1lciI6ICIxMDQuMjQ2LjEyNS4xNDEiIH0.ncqc5TpVlD05lnZvy8c3Bkx70gXDvQQXN0iG5Z4mOLgY_rwasXIJXnR-X4JczT8PmZ2v5cisW5VRHAdfsz_8CA".to_owned().into();
		let data = sample.decode().expect("Failed to decode JWT");

		assert_eq!(data.aud, vec!["web", "mobile"]);
		assert_eq!(data.sub, "76561199441992970");
	}
}
