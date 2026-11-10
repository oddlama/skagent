//! `skagent-testkey`: run the virtual security key until killed.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use clap::{Parser, ValueEnum};
use sha2::{Digest as _, Sha256};
use skagent_testkey::callbacks::{Callbacks, UndoHandle};
use skagent_testkey::catalog::Catalog;
use skagent_testkey::ctap::{
    STATUS_INVALID_CBOR, STATUS_OK, STATUS_OPERATION_DENIED, STATUS_PIN_AUTH_INVALID,
    STATUS_USER_ACTION_TIMEOUT, TouchRequirement, touch_requirement,
};
use skagent_testkey::touch::{Touch, TouchOutcome};
use soft_fido2::{Authenticator, AuthenticatorConfig, AuthenticatorOptions};
use soft_fido2_transport::{Cmd, CommandHandler, CtapHidHandler, Packet, UhidDevice};

/// COSE algorithm ids: EdDSA (ed25519-sk) and ES256 (ecdsa-sk).
const ALGORITHMS: [i32; 2] = [-8, -7];

/// Pause between polls of the uhid device when it has nothing for us.
const IDLE_POLL: Duration = Duration::from_millis(5);

/// Virtual FIDO2 security key on uhid, for skagent's VM tests.
#[derive(Debug, Parser)]
#[command(name = "skagent-testkey", version, about)]
struct Cli {
    /// Client PIN the key starts with.
    #[arg(long, env = "SKAGENT_TESTKEY_PIN")]
    pin: String,

    /// How touch requests are answered.
    #[arg(long, value_enum, default_value_t = TouchMode::Auto)]
    touch: TouchMode,

    /// With `--touch file`: a touch happens when this file appears. It is
    /// deleted again, so one file is one touch.
    #[arg(long, required_if_eq("touch", "file"))]
    touch_file: Option<PathBuf>,

    /// Product name of the HID device.
    #[arg(long, default_value = "skagent test key")]
    name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TouchMode {
    /// Every touch request is answered right away.
    Auto,
    /// Every touch request is refused.
    Deny,
    /// Wait for `--touch-file` to appear (up to 10 s).
    File,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "test key failed");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let touch = match (cli.touch, cli.touch_file) {
        (TouchMode::Auto, _) => Touch::Auto,
        (TouchMode::Deny, _) => Touch::Deny,
        (TouchMode::File, Some(path)) => Touch::File(path),
        (TouchMode::File, None) => bail!("--touch file needs --touch-file"),
    };

    // soft-fido2 takes a preset PIN as the SHA-256 of the PIN, applied to the
    // next authenticator that gets created.
    Authenticator::<Callbacks>::set_pin_hash(&Sha256::digest(cli.pin.as_bytes()));
    let config = AuthenticatorConfig::builder()
        .aaguid(*b"skagent-testkey!")
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_presence(true)
                .with_user_verification(None)
                .with_client_pin(Some(true))
                .with_pin_uv_auth_token(Some(true))
                .with_credential_management(Some(true))
                .with_make_cred_uv_not_required(Some(true)),
        )
        .extensions(vec!["credProtect".to_owned()])
        .algorithms(ALGORITHMS.to_vec())
        .force_resident_keys(false)
        .max_credentials(25)
        .max_pin_retries(8)
        .device_name(cli.name.clone())
        .build();
    let callbacks = Callbacks::default();
    let undo = callbacks.undo_handle();
    let authenticator = Authenticator::with_config(callbacks, config.clone())
        .map_err(|error| anyhow!("creating the soft-fido2 authenticator: {error}"))?;

    let device = UhidDevice::create_fido_device_with_ids(
        config.device_name.as_deref(),
        config.vendor_id,
        config.product_id,
        config.device_version,
    )
    .map_err(|error| {
        anyhow!(
            "creating the uhid device (is the uhid module loaded, /dev/uhid writable?): {error}"
        )
    })?;
    let mut handler = CtapHidHandler::new(CborHandler {
        authenticator,
        touch,
        undo,
        catalog: Catalog::default(),
    });
    tracing::info!(name = %cli.name, touch = ?cli.touch, "test key ready");

    loop {
        let mut packet = [0_u8; 64];
        let received = device
            .read_packet(&mut packet)
            .map_err(|error| anyhow!("reading from the uhid device: {error}"))?;
        if received.is_none() {
            std::thread::sleep(IDLE_POLL);
            continue;
        }
        let responses = handler
            .process_packet(Packet::from_bytes(packet))
            .map_err(|error| anyhow!("processing a CTAPHID packet: {error}"))?;
        for response in responses {
            device
                .write_packet(response.as_bytes())
                .map_err(|error| anyhow!("writing to the uhid device: {error}"))?;
        }
    }
}

/// Hands CTAP2 (CBOR) messages to the authenticator, applying the touch policy.
struct CborHandler {
    authenticator: Authenticator<Callbacks>,
    touch: Touch,
    undo: UndoHandle,
    catalog: Catalog,
}

impl CborHandler {
    fn forward(&mut self, request: &[u8]) -> soft_fido2_transport::Result<Vec<u8>> {
        let mut response = Vec::new();
        self.authenticator
            .handle(request, &mut response)
            .map_err(|error| {
                soft_fido2_transport::Error::Other(format!("CTAP2 command failed: {error}"))
            })?;
        self.catalog.repair(request, response).map_err(|error| {
            soft_fido2_transport::Error::Other(format!("completing credential listing: {error}"))
        })
    }
}

/// CTAP2 response for a touch that didn't happen.
fn touch_failure(outcome: TouchOutcome) -> Option<Vec<u8>> {
    match outcome {
        TouchOutcome::Touched => None,
        TouchOutcome::Refused => Some(vec![STATUS_OPERATION_DENIED]),
        TouchOutcome::TimedOut => Some(vec![STATUS_USER_ACTION_TIMEOUT]),
    }
}

impl CommandHandler for CborHandler {
    fn handle_command(&mut self, cmd: Cmd, data: &[u8]) -> soft_fido2_transport::Result<Vec<u8>> {
        if cmd != Cmd::Cbor {
            return Err(soft_fido2_transport::Error::InvalidCommand);
        }
        let requirement = match touch_requirement(data) {
            Ok(requirement) => requirement,
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "malformed CTAP2 request");
                return Ok(vec![STATUS_INVALID_CBOR]);
            }
        };
        match requirement {
            TouchRequirement::None => self.forward(data),
            TouchRequirement::Selection => {
                let outcome = self.touch.request("select", "");
                Ok(touch_failure(outcome).unwrap_or_else(|| vec![STATUS_PIN_AUTH_INVALID]))
            }
            TouchRequirement::AfterSuccess { operation, rp_id } => {
                let snapshot = self.undo.snapshot().map_err(|error| {
                    soft_fido2_transport::Error::Other(format!("snapshotting credentials: {error}"))
                })?;
                let response = self.forward(data)?;
                if response.first() != Some(&STATUS_OK) {
                    return Ok(response);
                }
                let Some(failure) = touch_failure(self.touch.request(operation, &rp_id)) else {
                    if operation == "makeCredential" {
                        self.catalog
                            .record(&response, |id| {
                                self.undo.protection(id).map_err(|error| {
                                    anyhow!("reading credential protection: {error}")
                                })
                            })
                            .map_err(|error| {
                                soft_fido2_transport::Error::Other(format!(
                                    "recording credential public key: {error}"
                                ))
                            })?;
                    }
                    return Ok(response);
                };
                let removed = self.undo.undo_since(&snapshot).map_err(|error| {
                    soft_fido2_transport::Error::Other(format!("undoing credentials: {error}"))
                })?;
                if removed > 0 {
                    tracing::info!(removed, "removed credentials created without a touch");
                }
                Ok(failure)
            }
        }
    }
}
