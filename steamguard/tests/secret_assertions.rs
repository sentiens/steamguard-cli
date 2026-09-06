use regex::Regex;

#[test]
fn secret_comparisons_do_not_use_value_printing_assertions() {
	let comparisons = Regex::new(r"(?s)assert_(?:eq|ne)!\((.*?)\);").unwrap();
	let exposed = Regex::new(
		r#"expose_secret\s*\(|\.nonce\b|\["nonce"\]|\b(?:SECRETS|ACCESS|REFRESH|OLD_REFRESH)\b"#,
	)
	.unwrap();
	for source in [
		include_str!("login_poll.rs"),
		include_str!("session_responses.rs"),
		include_str!("confirmation.rs"),
		include_str!("../src/confirmation.rs"),
	] {
		for comparison in comparisons.captures_iter(source) {
			assert!(
				!exposed.is_match(&comparison[1]),
				"secret comparison can print its operands"
			);
		}
	}
}
