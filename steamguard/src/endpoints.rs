const DEFAULT_API_BASE_URL: &str = "https://api.steampowered.com";
const DEFAULT_COMMUNITY_BASE_URL: &str = "https://steamcommunity.com";
const DEFAULT_LOGIN_BASE_URL: &str = "https://api.steampowered.com";

#[cfg(feature = "test-endpoints")]
const API_BASE_URL_ENV: &str = "STEAMGUARD_API_BASE_URL";
#[cfg(feature = "test-endpoints")]
const COMMUNITY_BASE_URL_ENV: &str = "STEAMGUARD_COMMUNITY_BASE_URL";
#[cfg(feature = "test-endpoints")]
const LOGIN_BASE_URL_ENV: &str = "STEAMGUARD_LOGIN_BASE_URL";

lazy_static! {
	static ref API_BASE_URL: String = {
		#[cfg(feature = "test-endpoints")]
		{
			endpoint_from_env(API_BASE_URL_ENV, DEFAULT_API_BASE_URL)
		}
		#[cfg(not(feature = "test-endpoints"))]
		{
			DEFAULT_API_BASE_URL.to_owned()
		}
	};
	static ref COMMUNITY_BASE_URL: String = {
		#[cfg(feature = "test-endpoints")]
		{
			endpoint_from_env(COMMUNITY_BASE_URL_ENV, DEFAULT_COMMUNITY_BASE_URL)
		}
		#[cfg(not(feature = "test-endpoints"))]
		{
			DEFAULT_COMMUNITY_BASE_URL.to_owned()
		}
	};
	static ref LOGIN_BASE_URL: String = {
		#[cfg(feature = "test-endpoints")]
		{
			endpoint_from_env(LOGIN_BASE_URL_ENV, DEFAULT_LOGIN_BASE_URL)
		}
		#[cfg(not(feature = "test-endpoints"))]
		{
			DEFAULT_LOGIN_BASE_URL.to_owned()
		}
	};
}

pub(crate) fn api_base_url() -> &'static str {
	API_BASE_URL.as_str()
}

pub(crate) fn community_base_url() -> &'static str {
	COMMUNITY_BASE_URL.as_str()
}

pub(crate) fn login_base_url() -> &'static str {
	LOGIN_BASE_URL.as_str()
}

pub(crate) fn community_url(path: &str) -> anyhow::Result<reqwest::Url> {
	let base = community_base_url().trim_end_matches('/');
	let path = path.trim_start_matches('/');
	Ok(format!("{base}/{path}").parse()?)
}

#[cfg(feature = "test-endpoints")]
fn endpoint_from_env(variable: &str, default: &str) -> String {
	std::env::var(variable).unwrap_or_else(|_| default.to_owned())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn endpoint_overrides_are_feature_gated_and_read_once() {
		use std::process::Command;

		const CHILD_ENV: &str = "STEAMGUARD_ENDPOINT_TEST_CHILD";
		const TEST_NAME: &str =
			"endpoints::tests::endpoint_overrides_are_feature_gated_and_read_once";
		if std::env::var_os(CHILD_ENV).is_none() {
			let status = Command::new(std::env::current_exe().unwrap())
				.args(["--exact", TEST_NAME, "--nocapture"])
				.env(CHILD_ENV, "1")
				.env("STEAMGUARD_API_BASE_URL", "http://127.0.0.1:41001")
				.env("STEAMGUARD_COMMUNITY_BASE_URL", "http://127.0.0.1:41002")
				.env("STEAMGUARD_LOGIN_BASE_URL", "http://127.0.0.1:41003")
				.status()
				.unwrap();
			assert!(status.success());
			return;
		}

		#[cfg(feature = "test-endpoints")]
		let expected = (
			"http://127.0.0.1:41001",
			"http://127.0.0.1:41002",
			"http://127.0.0.1:41003",
		);
		#[cfg(not(feature = "test-endpoints"))]
		let expected = (
			DEFAULT_API_BASE_URL,
			DEFAULT_COMMUNITY_BASE_URL,
			DEFAULT_LOGIN_BASE_URL,
		);

		assert_eq!(api_base_url(), expected.0);
		assert_eq!(community_base_url(), expected.1);
		assert_eq!(login_base_url(), expected.2);

		let api_request = crate::steamapi::ApiRequest::new(
			"ITwoFactorService",
			"QueryTime",
			1,
			crate::protobufs::service_twofactor::CTwoFactor_Time_Request::new(),
		);
		let login_request = crate::steamapi::ApiRequest::new(
			"IAuthenticationService",
			"GetPasswordRSAPublicKey",
			1,
			crate::protobufs::steammessages_auth_steamclient::CAuthentication_GetPasswordRSAPublicKey_Request::new(),
		);
		assert_eq!(
			api_request.build_url(),
			format!("{}/ITwoFactorService/QueryTime/v1", expected.0)
		);
		assert_eq!(
			login_request.build_url(),
			format!(
				"{}/IAuthenticationService/GetPasswordRSAPublicKey/v1",
				expected.2
			)
		);
		assert_eq!(
			community_url("mobileconf/getlist").unwrap().as_str(),
			format!("{}/mobileconf/getlist", expected.1)
		);

		#[cfg(feature = "test-endpoints")]
		{
			std::env::set_var(API_BASE_URL_ENV, "http://127.0.0.1:42001");
			std::env::set_var(COMMUNITY_BASE_URL_ENV, "http://127.0.0.1:42002");
			std::env::set_var(LOGIN_BASE_URL_ENV, "http://127.0.0.1:42003");
			assert_eq!(api_base_url(), expected.0);
			assert_eq!(community_base_url(), expected.1);
			assert_eq!(login_base_url(), expected.2);
		}
	}
}
