use log::*;
use secrecy::ExposeSecret;

use crate::{
	encryption::{EncryptionScheme, EntryEncryptor},
	tui, AccountManager,
};

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Encrypt all maFiles")]
pub struct EncryptCommand;

impl<T> ManifestCommand<T> for EncryptCommand
where
	T: Transport,
{
	fn execute(
		&self,
		_transport: T,
		manager: &mut AccountManager,
		_args: &GlobalArgs,
	) -> anyhow::Result<()> {
		if !manager.has_passkey() {
			let passkey: SecretString;
			loop {
				let passkey1 = tui::prompt_passkey()?;
				if passkey1.expose_secret().is_empty() {
					error!("Passkey cannot be empty, try again.");
					continue;
				}
				let passkey_confirm = rpassword::prompt_password("Confirm encryption passkey: ")
					.map(SecretString::new)?;
				if passkey1.expose_secret() == passkey_confirm.expose_secret() {
					passkey = passkey1;
					break;
				}
				error!("Passkeys do not match, try again.");
			}

			#[cfg(feature = "keyring")]
			{
				if tui::prompt_char(
					"Would you like to store the passkey in your system keyring?",
					"yn",
				) == 'y'
				{
					let keyring_id = crate::encryption::generate_keyring_id();
					let result =
						crate::encryption::store_passkey(keyring_id.clone(), passkey.clone());
					report_keyring_store(result, manager, keyring_id);
				}
			}

			manager.submit_passkey(Some(passkey));
		}
		manager.load_accounts()?;
		for entry in manager.iter_mut() {
			entry.encryption = Some(EncryptionScheme::generate());
		}
		manager.save()?;
		Ok(())
	}
}

#[cfg(feature = "keyring")]
fn report_keyring_store(
	result: keyring::Result<()>,
	manager: &mut AccountManager,
	keyring_id: String,
) {
	match result {
		Ok(()) => {
			info!("Stored passkey in keyring");
			manager.set_keyring_id(keyring_id);
		}
		Err(e) => warn!(
			"Failed to store passkey in keyring, continuing anyway: {}",
			crate::errors::safe_error(&e)
		),
	}
}

#[cfg(all(test, feature = "keyring"))]
mod tests {
	use super::*;

	#[test]
	fn encrypt_keyring_platform_error_output_is_redacted() {
		if crate::errors::tests::capture_diagnostic_test(
			"commands::encrypt::tests::encrypt_keyring_platform_error_output_is_redacted",
			"Failed to store passkey in keyring, continuing anyway",
		) {
			return;
		}
		let directory = tempfile::tempdir().unwrap();
		let mut manager = AccountManager::new(&directory.path().join("manifest.json"));
		for error in [
			keyring::Error::PlatformFailure(Box::new(std::io::Error::other(
				"platform-error-canary",
			))),
			keyring::Error::NoStorageAccess(Box::new(std::io::Error::other(
				"storage-error-canary",
			))),
		] {
			report_keyring_store(Err(error), &mut manager, "keyring-id-canary".to_owned());
		}
	}
}
