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
	use std::{path::PathBuf, process::Command};

	use super::*;

	const STEAM_BASE_URLS: [&str; 3] = [
		"https://api.steampowered.com",
		"https://steamcommunity.com",
		"https://api.steampowered.com",
	];
	const TEST_BASE_URLS: [&str; 3] = [
		"http://127.0.0.1:41001",
		"http://127.0.0.1:41002",
		"http://127.0.0.1:41003",
	];

	// Each child runs one test with a fresh environment and fresh endpoint caches.
	fn in_subprocess(test_name: &str, environment: &[(&str, &str)]) -> bool {
		const CHILD_ENV: &str = "STEAMGUARD_ENDPOINT_TEST_CHILD";
		if std::env::var(CHILD_ENV).as_deref() == Ok(test_name) {
			return true;
		}
		let output = Command::new(std::env::current_exe().unwrap())
			.args([
				"--exact",
				&format!("endpoints::tests::{test_name}"),
				"--test-threads=1",
			])
			.env_clear()
			.env(CHILD_ENV, test_name)
			.envs(environment.iter().copied())
			.output()
			.unwrap();
		let stdout = String::from_utf8_lossy(&output.stdout);
		assert!(
			output.status.success() && stdout.contains("test result: ok. 1 passed;"),
			"sensitive assertion failed"
		);
		false
	}

	fn assert_endpoint_routing(expected: [&str; 3]) {
		assert_eq!(
			[api_base_url(), community_base_url(), login_base_url()],
			expected
		);

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
			format!("{}/ITwoFactorService/QueryTime/v1", expected[0])
		);
		assert!(
			(login_request.build_url())
				== (format!(
					"{}/IAuthenticationService/GetPasswordRSAPublicKey/v1",
					expected[2]
				)),
			"sensitive assertion failed"
		);
		assert_eq!(
			community_url("mobileconf/getlist").unwrap().as_str(),
			format!("{}/mobileconf/getlist", expected[1])
		);
	}

	#[test]
	fn endpoints_default_to_steam_hosts() {
		if !in_subprocess("endpoints_default_to_steam_hosts", &[]) {
			return;
		}
		assert_endpoint_routing(STEAM_BASE_URLS);
		for base in [api_base_url(), community_base_url(), login_base_url()] {
			assert!(base.starts_with("https://"));
		}
	}

	#[test]
	fn endpoints_override_only_under_feature() {
		// Construct the names so this source check does not match its own literals.
		let variables =
			["API", "COMMUNITY", "LOGIN"].map(|service| format!("STEAMGUARD_{service}_BASE_URL"));
		let mut occurrences = [0; 3];
		let mut paths = vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")];
		while let Some(path) = paths.pop() {
			if path.is_dir() {
				paths.extend(
					std::fs::read_dir(path)
						.unwrap()
						.map(|entry| entry.unwrap().path()),
				);
			} else if path.extension().is_some_and(|extension| extension == "rs") {
				let source = std::fs::read_to_string(&path).unwrap();
				let lines: Vec<_> = source.lines().map(str::trim).collect();
				for (line_number, line) in lines.iter().enumerate() {
					for (index, variable) in variables.iter().enumerate() {
						if line.contains(variable) {
							// Keep all names in directly feature-gated constants. An unguarded
							// duplicate anywhere in the library must fail this check.
							assert!(
								line.starts_with("const ")
									&& line_number > 0 && lines[line_number - 1]
									== r#"#[cfg(feature = "test-endpoints")]"#,
								"test invariant failed"
							);
							occurrences[index] += line.matches(variable.as_str()).count();
						}
					}
				}
			}
		}
		assert_eq!(occurrences, [1; 3]);

		let environment: Vec<_> = variables
			.iter()
			.map(String::as_str)
			.zip(TEST_BASE_URLS)
			.collect();
		if !in_subprocess("endpoints_override_only_under_feature", &environment) {
			return;
		}

		#[cfg(feature = "test-endpoints")]
		assert_endpoint_routing(TEST_BASE_URLS);
		#[cfg(not(feature = "test-endpoints"))]
		assert_endpoint_routing(STEAM_BASE_URLS);
	}

	#[cfg(feature = "test-endpoints")]
	#[test]
	fn endpoint_base_is_read_once() {
		let variables = [API_BASE_URL_ENV, COMMUNITY_BASE_URL_ENV, LOGIN_BASE_URL_ENV];
		let environment: Vec<_> = variables.into_iter().zip(TEST_BASE_URLS).collect();
		if !in_subprocess("endpoint_base_is_read_once", &environment) {
			return;
		}
		assert_endpoint_routing(TEST_BASE_URLS);
		for variable in variables {
			std::env::set_var(variable, "http://127.0.0.1:42001");
		}
		assert_endpoint_routing(TEST_BASE_URLS);
		for variable in variables {
			std::env::remove_var(variable);
		}
		assert_endpoint_routing(TEST_BASE_URLS);
	}
}
