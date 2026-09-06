use std::sync::{Arc, Mutex};

use log::*;
use qrcode::QrCode;
use secrecy::ExposeSecret;

use crate::AccountManager;

use super::*;

#[derive(Debug, Clone, clap::ValueEnum)]
#[clap(rename_all = "lowercase")]
pub(crate) enum QrFormat {
	/// The default Steam otpauth URI
	Steam,
	/// Bitwarden-compatible format: steam://<secret>
	Bitwarden,
	/// KeePassXC-compatible otpauth URI with period, digits, and encoder parameters
	KeePassXc,
}

#[derive(Debug, Clone, Parser)]
#[clap(about = "Generate QR codes. This *will* print sensitive data to stdout.")]
pub struct QrCommand {
	#[clap(
		long,
		help = "Force using ASCII chars to generate QR codes. Useful for terminals that don't support unicode."
	)]
	pub ascii: bool,

	/// Output format for the QR code content.
	#[clap(long, value_enum, default_value = "steam")]
	pub format: QrFormat,
}

impl QrCommand {
	pub(crate) fn qr_content(&self, account: &SteamGuardAccount) -> String {
		let secret_b32 = base32_encode_unpadded(account.shared_secret.expose_secret());

		match self.format {
			QrFormat::Steam => account.uri.expose_secret().to_owned(),
			QrFormat::Bitwarden => format!("steam://{}", secret_b32),
			QrFormat::KeePassXc => {
				let username = percent_encode_username(&account.account_name);
				format!(
					"otpauth://totp/Steam:{}?secret={}&period=30&digits=5&issuer=Steam&encoder=steam",
					username, secret_b32
				)
			}
		}
	}
}

impl<T> AccountCommand<T> for QrCommand
where
	T: Transport,
{
	fn execute(
		&self,
		_transport: T,
		_manager: &mut AccountManager,
		accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
		_args: &GlobalArgs,
	) -> anyhow::Result<()> {
		use anyhow::Context;

		info!("Generating QR codes for {} accounts", accounts.len());

		for account in accounts {
			let account = account.lock().unwrap();
			let qr_content = self.qr_content(&account);

			let qr = QrCode::new(qr_content.as_bytes())
				.context(format!("generating qr code for {}", account.account_name))?;

			info!("Printing QR code for {}", account.account_name);
			let qr_string = if self.ascii {
				qr.render()
					.light_color(' ')
					.dark_color('#')
					.module_dimensions(2, 1)
					.build()
			} else {
				use qrcode::render::unicode;
				qr.render::<unicode::Dense1x2>()
					.dark_color(unicode::Dense1x2::Light)
					.light_color(unicode::Dense1x2::Dark)
					.build()
			};

			println!("{}", qr_string);
		}
		Ok(())
	}
}

/// Encode raw bytes to an unpadded Base32 string (RFC 3548 / RFC 4648).
fn base32_encode_unpadded(data: &[u8]) -> String {
	const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	let mut out = String::new();
	let mut buffer: u32 = 0;
	let mut bits: u32 = 0;

	for &byte in data {
		buffer = (buffer << 8) | (byte as u32);
		bits += 8;
		while bits >= 5 {
			bits -= 5;
			let index = ((buffer >> bits) & 0x1F) as usize;
			out.push(ALPHABET[index] as char);
		}
	}

	if bits > 0 {
		let index = ((buffer << (5 - bits)) & 0x1F) as usize;
		out.push(ALPHABET[index] as char);
	}

	out
}

/// Percent-encode characters that are unsafe in a URI path component.
///
/// Only encodes characters that would structurally break a URI (delimiters,
/// the percent escape character itself, and non-ASCII bytes). Safe unreserved
/// characters (RFC 3986) pass through unchanged.
fn percent_encode_username(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for b in s.bytes() {
		match b {
			b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
				out.push(b as char);
			}
			_ => {
				out.push('%');
				out.push_str(&format!("{:02X}", b));
			}
		}
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn percent_encode_username_passes_through_safe_chars() {
		assert_eq!(percent_encode_username("abc123_-"), "abc123_-");
	}

	#[test]
	fn percent_encode_username_encodes_reserved_chars() {
		assert_eq!(percent_encode_username("user?name"), "user%3Fname");
		assert_eq!(percent_encode_username("user&name"), "user%26name");
		assert_eq!(percent_encode_username("user#name"), "user%23name");
		assert_eq!(percent_encode_username("user:name"), "user%3Aname");
		assert_eq!(percent_encode_username("user/name"), "user%2Fname");
		assert_eq!(percent_encode_username("user%20name"), "user%2520name");
	}

	#[test]
	fn percent_encode_username_encodes_space() {
		assert_eq!(percent_encode_username("user name"), "user%20name");
	}

	#[test]
	fn percent_encode_username_encodes_non_ascii() {
		assert_eq!(percent_encode_username("usér"), "us%C3%A9r");
	}

	#[test]
	fn test_base32_encode_unpadded() {
		assert_eq!(base32_encode_unpadded(b"f"), "MY");
		assert_eq!(base32_encode_unpadded(b"fo"), "MZXQ");
		assert_eq!(base32_encode_unpadded(b"foo"), "MZXW6");
		assert_eq!(base32_encode_unpadded(b"foob"), "MZXW6YQ");
		assert_eq!(base32_encode_unpadded(b"fooba"), "MZXW6YTB");
		assert_eq!(base32_encode_unpadded(b"foobar"), "MZXW6YTBOI");
	}

	#[test]
	fn test_qr_format_secret_base32_check() {
		let account = SteamGuardAccount {
			account_name: "test_user".to_string(),
			shared_secret: steamguard::token::TwoFactorSecret::parse_shared_secret(
				"zvIayp3JPvtvX/QGHqsqKBk/44s=".to_string(),
			)
			.unwrap(),
			uri: secrecy::SecretString::from(
				"otpauth://totp/Steam:test_user?secret=ASDF&issuer=Steam".to_string(),
			),
			..Default::default()
		};

		// Bitwarden format check
		let bw_cmd = QrCommand {
			ascii: false,
			format: QrFormat::Bitwarden,
		};
		let bw_content = bw_cmd.qr_content(&account);
		let bw_secret = bw_content
			.strip_prefix("steam://")
			.expect("should start with steam://");
		let bw_is_unpadded_base32 = bw_secret
			.chars()
			.all(|c| matches!(c, 'A'..='Z' | '2'..='7'))
			&& !bw_secret.contains('=');
		assert!(bw_is_unpadded_base32, "test invariant failed");

		// KeePassXC format check
		let keepass_cmd = QrCommand {
			ascii: false,
			format: QrFormat::KeePassXc,
		};
		let keepass_content = keepass_cmd.qr_content(&account);
		let keepass_secret = keepass_content
			.split('?')
			.nth(1)
			.and_then(|query| {
				query.split('&').find_map(|pair| {
					let mut parts = pair.split('=');
					if parts.next()? == "secret" {
						parts.next().map(ToString::to_string)
					} else {
						None
					}
				})
			})
			.expect("secret parameter should be present");
		let keepass_is_unpadded_base32 = keepass_secret
			.chars()
			.all(|c| matches!(c, 'A'..='Z' | '2'..='7'))
			&& !keepass_secret.contains('=');
		assert!(keepass_is_unpadded_base32, "test invariant failed");
	}
}
