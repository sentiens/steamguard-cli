use std::sync::{Arc, Mutex};

use crossterm::tty::IsTty;
use log::*;
use steamguard::{Confirmation, Confirmer, ConfirmerError};

use crate::{tui, AccountManager};

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Interactive interface for steam mobile confirmations")]
pub struct ConfirmCommand {
	#[clap(
		short,
		long,
		help = "Accept all open mobile confirmations. Does not open interactive interface."
	)]
	pub accept_all: bool,
	#[clap(
		short,
		long,
		help = "If submitting a confirmation response fails, exit immediately."
	)]
	pub fail_fast: bool,
}

impl<T> AccountCommand<T> for ConfirmCommand
where
	T: Transport + Clone,
{
	fn execute(
		&self,
		transport: T,
		manager: &mut AccountManager,
		accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
		args: &GlobalArgs,
	) -> anyhow::Result<()> {
		for a in accounts {
			let mut account = a.lock().unwrap();

			if !account.is_logged_in() {
				info!("Account does not have tokens, logging in");
				crate::do_login(transport.clone(), &mut account, args.password.clone())?;
			}

			info!("{}: Checking for confirmations", account.account_name);
			let confirmations: Vec<Confirmation>;
			loop {
				let confirmer = Confirmer::new(transport.clone(), &account);

				match confirmer.get_confirmations() {
					Ok(confs) => {
						confirmations = confs;
						break;
					}
					Err(ConfirmerError::InvalidTokens) => {
						info!("obtaining new tokens");
						crate::do_login(transport.clone(), &mut account, args.password.clone())?;
					}
					Err(err) => {
						error!(
							"Failed to get confirmations: {}",
							crate::errors::safe_error(&err)
						);
						return Err(err.into());
					}
				}
			}

			if confirmations.is_empty() {
				info!("{}: No confirmations", account.account_name);
				continue;
			}

			let confirmer = Confirmer::new(transport.clone(), &account);
			let mut any_failed = false;

			if self.accept_all {
				info!("accepting all confirmations");
				match submit_loop(
					|| confirmer.accept_confirmations_bulk(&confirmations),
					self.fail_fast,
				) {
					Ok(_) => {}
					Err(err) => {
						warn!(
							"accept confirmation result: {}",
							crate::errors::safe_error(&err)
						);
						if self.fail_fast {
							return Err(err.into());
						}
						any_failed = true;
					}
				}
			} else if std::io::stdout().is_tty() {
				let (accept, deny) = tui::prompt_confirmation_menu(confirmations)?;
				match submit_loop(
					|| confirmer.accept_confirmations_bulk(&accept),
					self.fail_fast,
				) {
					Ok(_) => {}
					Err(err) => {
						warn!(
							"accept confirmation result: {}",
							crate::errors::safe_error(&err)
						);
						if self.fail_fast {
							return Err(err.into());
						}
						any_failed = true;
					}
				}
				match submit_loop(|| confirmer.deny_confirmations_bulk(&deny), self.fail_fast) {
					Ok(_) => {}
					Err(err) => {
						warn!(
							"deny confirmation result: {}",
							crate::errors::safe_error(&err)
						);
						if self.fail_fast {
							return Err(err.into());
						}
						any_failed = true;
					}
				}
			} else {
				warn!("not a tty, not showing menu");
				for conf in &confirmations {
					println!("{}", conf.description());
				}
			}

			if any_failed {
				error!("Failed to respond to some confirmations.");
			}
		}

		manager.save()?;
		Ok(())
	}
}

fn submit_loop(
	submit: impl Fn() -> Result<(), ConfirmerError>,
	fail_fast: bool,
) -> Result<(), ConfirmerError> {
	let mut attempts = 0;
	loop {
		match submit() {
			Ok(_) => break,
			Err(ConfirmerError::InvalidTokens) => {
				error!(
					"Invalid tokens, but they should be valid already. This is weird, stopping."
				);
				return Err(ConfirmerError::InvalidTokens);
			}
			Err(ConfirmerError::NetworkFailure(err)) => {
				error!("{}", crate::errors::safe_error(&err));
				return Err(ConfirmerError::NetworkFailure(err));
			}
			Err(err @ ConfirmerError::DeserializeError(_)) => {
				error!(
					"Failed to deserialize the response, but the submission may have succeeded: {}",
					crate::errors::safe_error(&err)
				);
				return Err(err);
			}
			Err(err) => {
				warn!(
					"submit confirmation result: {}",
					crate::errors::safe_error(&err)
				);
				if fail_fast || attempts >= 3 {
					return Err(err);
				}

				attempts += 1;
				let wait = std::time::Duration::from_secs(3 * attempts);
				info!(
					"retrying in {} seconds (attempt {})",
					wait.as_secs(),
					attempts
				);
				std::thread::sleep(wait);
			}
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	fn check_cli_diagnostics(test: &str, submit: bool) {
		const CHILD: &str = "FORK_FIX_01_CLI_DIAGNOSTIC_CHILD";
		if std::env::var_os(CHILD).is_some() {
			stderrlog::new().verbosity(5).init().unwrap();
			let malformed = || {
				ConfirmerError::from(
					serde_json::from_str::<steamguard::SendConfirmationResponse>(
						r#"{"success":"password-canary token-canary cookie-canary nonce-canary phone-canary"}"#,
					)
					.unwrap_err(),
				)
			};
			let result = if submit {
				submit_loop(|| Err(malformed()), true)
			} else {
				Err(malformed())
			};
			assert_eq!(
				crate::report_result(result.map_err(anyhow::Error::new)),
				255
			);
			return;
		}
		let output = std::process::Command::new(std::env::current_exe().unwrap())
			.args(["--exact", test, "--nocapture"])
			.env(CHILD, "1")
			.output()
			.unwrap();
		assert!(output.status.success(), "CLI diagnostic child failed");
		assert!(
			String::from_utf8_lossy(&output.stderr).contains("Failed to deserialize"),
			"CLI did not emit the expected diagnostic"
		);
		for bytes in [&output.stdout, &output.stderr] {
			assert!(
				!String::from_utf8_lossy(bytes).contains("canary"),
				"CLI output exposed a response secret"
			);
		}
	}

	#[test]
	fn cli_submission_parse_error_output_is_redacted() {
		check_cli_diagnostics(
			"commands::confirm::tests::cli_submission_parse_error_output_is_redacted",
			true,
		);
	}

	#[test]
	fn cli_anyhow_error_output_is_redacted() {
		check_cli_diagnostics(
			"commands::confirm::tests::cli_anyhow_error_output_is_redacted",
			false,
		);
	}
}
