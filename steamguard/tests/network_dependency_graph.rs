use std::{collections::BTreeSet, process::Command};

use serde_json::Value;

fn cargo(arguments: &[&str]) -> String {
	let output = Command::new(env!("CARGO"))
		.current_dir(env!("CARGO_MANIFEST_DIR"))
		.args(arguments)
		.env("TMPDIR", "/private/tmp")
		.output()
		.unwrap();
	assert!(
		output.status.success(),
		"offline Cargo graph command failed"
	);
	String::from_utf8(output.stdout).unwrap()
}

fn strings(value: &Value) -> BTreeSet<&str> {
	value
		.as_array()
		.unwrap()
		.iter()
		.map(|value| value.as_str().unwrap())
		.collect()
}

/// T-09/C09 reconciliation: the card literally requests `tokio-socks`, but locked
/// reqwest 0.12.28 implements SOCKS in `hyper-util` (`client-proxy`), without
/// `tokio-socks`. Its empty `socks` feature gates reqwest's connector code; reqwest
/// enables hyper-util's `client-proxy` directly on its dependency declaration.
/// Assert that real path and its activated features; adding a dummy
/// dependency would not prove the transport implementation. The manifest's
/// `rustls-tls` alias activates `rustls-tls-webpki-roots`. Existing cookies/gzip/
/// multipart features remain; the approved builder disables automatic cookies
/// and decoding. Metadata also checks the workspace feature union, while tree
/// checks steamguard's selected dependency graph, excluding the root CLI.
#[test]
fn proxy_dependency_graph_uses_webpki_and_hyper_util_socks() {
	let tree = cargo(&[
		"tree",
		"-p",
		"steamguard",
		"--locked",
		"--offline",
		"--edges",
		"normal,build",
		"--prefix",
		"none",
		"--format",
		"{p}",
	]);
	let names: BTreeSet<_> = tree
		.lines()
		.filter_map(|line| line.split_whitespace().next())
		.collect();
	for required in ["reqwest", "hyper-util", "webpki-roots"] {
		assert!(
			names.contains(required),
			"required transport dependency is absent"
		);
	}
	for forbidden in [
		"tokio-socks",
		"native-tls",
		"tokio-native-tls",
		"hyper-tls",
		"openssl",
		"openssl-sys",
		"rustls-native-certs",
	] {
		assert!(
			!names.contains(forbidden),
			"unreviewed transport dependency is present"
		);
	}

	let metadata: Value = serde_json::from_str(&cargo(&[
		"metadata",
		"--locked",
		"--offline",
		"--format-version",
		"1",
	]))
	.unwrap();
	let packages = metadata["packages"].as_array().unwrap();
	let package = |name: &str| {
		let matches: Vec<_> = packages
			.iter()
			.filter(|package| package["name"] == name)
			.collect();
		assert_eq!(
			matches.len(),
			1,
			"transport package must have one reviewed version"
		);
		matches[0]
	};
	let library = package("steamguard");
	let declarations: Vec<_> = library["dependencies"]
		.as_array()
		.unwrap()
		.iter()
		.filter(|dependency| dependency["name"] == "reqwest")
		.collect();
	assert_eq!(declarations.len(), 1);
	let declaration = declarations[0];
	assert_eq!(declaration["uses_default_features"], false);
	let declared = strings(&declaration["features"]);
	for required in ["blocking", "json", "socks", "rustls-tls"] {
		assert!(
			declared.contains(required),
			"required reqwest feature is absent"
		);
	}

	let reqwest = package("reqwest");
	assert_eq!(
		reqwest["version"], "0.12.28",
		"review the SOCKS backend on upgrade"
	);
	assert!(strings(&reqwest["features"]["rustls-tls"]).contains("rustls-tls-webpki-roots"));
	assert!(strings(&reqwest["features"]["socks"]).is_empty());
	let hyper_declarations: Vec<_> = reqwest["dependencies"]
		.as_array()
		.unwrap()
		.iter()
		.filter(|dependency| dependency["name"] == "hyper-util" && dependency["kind"].is_null())
		.collect();
	assert_eq!(hyper_declarations.len(), 1);
	assert!(strings(&hyper_declarations[0]["features"]).contains("client-proxy"));
	let nodes = metadata["resolve"]["nodes"].as_array().unwrap();
	let activated = |package: &Value| {
		strings(
			&nodes
				.iter()
				.find(|node| node["id"] == package["id"])
				.unwrap()["features"],
		)
	};
	let features = activated(reqwest);
	for required in ["rustls-tls-webpki-roots", "socks", "json", "blocking"] {
		assert!(
			features.contains(required),
			"required reqwest feature is not activated"
		);
	}
	assert!(!features.contains("default"));
	for feature in &features {
		assert!(
			!feature.contains("native")
				&& !feature.contains("openssl")
				&& *feature != "default-tls"
				&& !feature.contains("manual-roots"),
			"unreviewed reqwest TLS feature is activated"
		);
	}
	let hyper = package("hyper-util");
	assert!(activated(hyper).contains("client-proxy"));
	let reqwest_node = nodes
		.iter()
		.find(|node| node["id"] == reqwest["id"])
		.unwrap();
	assert!(strings(&reqwest_node["dependencies"]).contains(hyper["id"].as_str().unwrap()));
}
