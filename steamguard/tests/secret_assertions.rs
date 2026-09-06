use regex::Regex;
use std::path::{Path, PathBuf};

struct AssertionGuard {
	tokens: Regex,
	sensitive: Regex,
	fixed_message: Regex,
}

impl AssertionGuard {
	fn new() -> Self {
		Self {
			// Keep strings/comments atomic so fixture source is not mistaken for live macros.
			tokens: Regex::new(r####"(?s)//[^\n]*|/\*.*?\*/|b?r###".*?"###|b?r##".*?"##|b?r#".*?"#|b?r".*?"|b?"(?:\\.|[^"\\])*"|b?'(?:\\.|[^'\\])'|[A-Za-z_][A-Za-z_0-9]*|[^\s]"####).unwrap(),
			sensitive: Regex::new(r"(?i)secret|password|passkey|token|nonce|canary|cookie|jwt|authorization|retry_after|challenge_url|guard_data|error|diagnostic|payload|encoded|decoded|serialized|deserialized|diagnostic|output|plaintext|ciphertext|revocation|credential|\borig\b|generate_code|\bcode\b|\.jti\b|\.iss\b|\.sub\b|\.aud\b|\bbody\b|\bbytes\b|\bheaders\b").unwrap(),
			fixed_message: Regex::new(r#"^"[^{}]*"$"#).unwrap(),
		}
	}

	fn violations(&self, source: &str) -> Vec<usize> {
		let tokens: Vec<_> = self
			.tokens
			.find_iter(source)
			.filter(|token| !token.as_str().starts_with("//") && !token.as_str().starts_with("/*"))
			.collect();
		let mut violations = Vec::new();
		for (index, token) in tokens.iter().enumerate() {
			let name = token.as_str();
			if !matches!(
				name,
				"assert"
					| "assert_eq" | "assert_ne"
					| "debug_assert"
					| "debug_assert_eq"
					| "debug_assert_ne"
					| "prop_assert" | "prop_assert_eq"
					| "prop_assert_ne"
			) {
				continue;
			}
			if tokens.get(index + 1).map(|t| t.as_str()) != Some("!") {
				continue;
			}
			let Some(open) = tokens.get(index + 2) else {
				continue;
			};
			if !matches!(open.as_str(), "(" | "[" | "{") {
				continue;
			}
			let mut depth = 0;
			let mut start = open.end();
			let mut args = Vec::new();
			for end in &tokens[index + 3..] {
				match end.as_str() {
					")" | "]" | "}" if depth == 0 => {
						if !source[start..end.start()].trim().is_empty() {
							args.push(source[start..end.start()].trim());
						}
						break;
					}
					")" | "]" | "}" => depth -= 1,
					"(" | "[" | "{" => depth += 1,
					"," if depth == 0 => {
						args.push(source[start..end.start()].trim());
						start = end.end();
					}
					_ => {}
				}
			}
			let value_printing = name.ends_with("_eq") || name.ends_with("_ne");
			let operands = if value_printing { 2 } else { 1 };
			let sensitive = args
				.iter()
				.take(operands)
				.any(|arg| self.sensitive.is_match(arg));
			// Default assert! diagnostics stringify the expression, including literal canaries.
			// Explicit messages must be fixed: no captured interpolation or extra arguments.
			let fixed = args.len() == operands + 1 && self.fixed_message.is_match(args[operands]);
			if (sensitive && (value_printing || !fixed)) || (args.len() > operands && !fixed) {
				violations.push(
					source[..token.start()]
						.bytes()
						.filter(|b| *b == b'\n')
						.count() + 1,
				);
			}
		}
		violations
	}
}

fn rust_sources(directory: &Path, paths: &mut Vec<PathBuf>) {
	if !directory.exists() {
		return;
	}
	for entry in std::fs::read_dir(directory).unwrap() {
		let path = entry.unwrap().path();
		if path.is_dir() {
			rust_sources(&path, paths);
		} else if path.extension().is_some_and(|extension| extension == "rs") {
			paths.push(path);
		}
	}
}

#[test]
fn secret_comparisons_do_not_use_value_printing_assertions() {
	let library = Path::new(env!("CARGO_MANIFEST_DIR"));
	let workspace = library.parent().unwrap();
	let mut paths = Vec::new();
	// Includes inline unit tests, nested test modules, integration tests, and this guard.
	// Discover files on every run: new test files cannot silently escape a hard-coded list.
	for directory in [
		library.join("src"),
		library.join("tests"),
		workspace.join("src"),
		workspace.join("tests"),
	] {
		rust_sources(&directory, &mut paths);
	}
	paths.sort();
	let guard = AssertionGuard::new();
	let mut clean = true;
	for path in paths {
		for line in guard.violations(&std::fs::read_to_string(&path).unwrap()) {
			// File and line only; never print the offending expression or diagnostic.
			eprintln!("unsafe test assertion at {}:{line}", path.display());
			clean = false;
		}
	}
	assert!(clean, "test assertions may disclose sensitive data");
}

#[test]
fn guard_rejects_reported_leaks_and_dynamic_diagnostics() {
	let guard = AssertionGuard::new();
	for source in [
		r#"assert!(!diagnostic.contains(canary), "outer diagnostic leaked {canary}: {diagnostic}");"#,
		r#"assert_eq!(password, "proxy-password-canary");"#,
		r#"assert_eq!(serialized, "shared-secret-canary");"#,
		r#"assert_eq!(account.revocation_code.expose_secret(), "R12345");"#,
		r#"assert_eq!(constructor(vec![0; 20]).expose_secret(), &[0; 20]);"#,
		r#"assert!(true, "{}", diagnostic);"#,
		r#"assert!(!text.contains("literal-canary"));"#,
		r#"assert_ne! { tokens.access_token(), other };"#,
		r#"prop_assert_eq!(secret, other);"#,
	] {
		assert!(
			!guard.violations(source).is_empty(),
			"guard missed an unsafe assertion"
		);
	}
}

#[test]
fn guard_accepts_fixed_boolean_comparisons_and_ignores_fixture_text() {
	let guard = AssertionGuard::new();
	for source in [
		r#"assert!(password == expected, "password comparison failed");"#,
		r#"assert!(!diagnostic.contains(canary), "diagnostic exposed a secret");"#,
		r#"assert_eq!(status.as_u16(), 429);"#,
		r##"let fixture = r#"assert_eq!(secret, other);"#;"##,
		r#"// assert_eq!(secret, other);"#,
	] {
		assert!(
			guard.violations(source).is_empty(),
			"guard rejected a safe assertion"
		);
	}
}
