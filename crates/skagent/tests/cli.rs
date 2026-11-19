//! Command line parsing.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use clap::{CommandFactory as _, Parser as _};
use skagent::batch_tool::{exit_code, shown_command};
use skagent::cli::{AgeCommand, BatchArgs, Cli, Command, ServeArgs, parse_duration};
use skagent::prompt::PinPrompt;
use skagent::serve::pin_prompt;
use skagent::signer::DEFAULT_BATCH_LIFETIME;
use skagent_age::wire::MAX_COMMAND_BYTES;

fn serve(args: &[&str]) -> Result<ServeArgs> {
    let cli =
        Cli::try_parse_from(["skagent", "serve"].iter().chain(args)).context("parsing serve")?;
    match cli.command {
        Command::Serve(args) => Ok(args),
        Command::Forget(_)
        | Command::Load(_)
        | Command::CheckConfig(_)
        | Command::Age(_)
        | Command::Batch(_) => {
            bail!("not parsed as serve")
        }
    }
}

#[test]
fn cli_definition_is_consistent() {
    Cli::command().debug_assert();
}

#[test]
fn serve_takes_an_optional_socket() -> Result<()> {
    let args = serve(&["--socket", "/tmp/agent.sock"])?;
    ensure!(args.socket.socket.as_deref() == Some(Path::new("/tmp/agent.sock")));
    Ok(())
}

#[test]
fn log_filter_is_global_and_defaults_to_info() -> Result<()> {
    let cli = Cli::try_parse_from(["skagent", "serve"]).context("parsing serve")?;
    ensure!(cli.log == "info", "default filter is {:?}", cli.log);

    let cli = Cli::try_parse_from(["skagent", "serve", "--log", "skagent=debug"])
        .context("parsing serve --log")?;
    ensure!(cli.log == "skagent=debug");
    Ok(())
}

#[test]
fn a_subcommand_is_required() {
    assert!(Cli::try_parse_from(["skagent"]).is_err());
}

#[test]
fn pinentry_is_the_default_prompt_and_askpass_replaces_it() -> Result<()> {
    match pin_prompt(&serve(&[])?) {
        PinPrompt::Pinentry(pinentry) => ensure!(pinentry.program() == Path::new("pinentry")),
        PinPrompt::Askpass(_) => bail!("askpass by default"),
    }
    match pin_prompt(&serve(&["--askpass", "/usr/bin/ssh-askpass"])?) {
        PinPrompt::Askpass(askpass) => {
            ensure!(askpass.program() == Path::new("/usr/bin/ssh-askpass"));
        }
        PinPrompt::Pinentry(_) => bail!("pinentry despite --askpass"),
    }
    ensure!(
        serve(&["--askpass", "/a", "--pinentry", "/p"]).is_err(),
        "--askpass and --pinentry together accepted"
    );
    Ok(())
}

#[test]
fn pins_are_cached_for_eight_hours_by_default() -> Result<()> {
    let args = serve(&[])?;
    ensure!(args.pin_lifetime == Duration::from_hours(8));
    ensure!(args.pin_idle.is_none());
    let args = serve(&["--pin-lifetime", "0", "--pin-idle", "30m"])?;
    ensure!(args.pin_lifetime.is_zero());
    ensure!(args.pin_idle == Some(Duration::from_mins(30)));
    Ok(())
}

#[test]
fn durations_need_a_unit() {
    let valid = [("90s", 90), ("30m", 1800), ("8h", 28_800), ("0", 0)];
    for (text, seconds) in valid {
        assert_eq!(
            parse_duration(text),
            Ok(Duration::from_secs(seconds)),
            "{text}"
        );
    }
    for text in [
        "",
        "8",
        "h",
        "8d",
        "-1h",
        "1.5h",
        "8 h",
        "18446744073709551615h",
    ] {
        assert!(parse_duration(text).is_err(), "{text:?} accepted");
    }
}

#[test]
fn forget_takes_the_socket() -> Result<()> {
    let cli = Cli::try_parse_from(["skagent", "forget", "--socket", "/run/a.sock"])
        .context("parsing forget")?;
    let Command::Forget(args) = cli.command else {
        bail!("not parsed as forget");
    };
    ensure!(args.socket.as_deref() == Some(Path::new("/run/a.sock")));
    Ok(())
}

#[test]
fn touch_notifications_are_on_unless_switched_off() -> Result<()> {
    ensure!(!serve(&[])?.no_touch_notification);
    ensure!(serve(&["--no-touch-notification"])?.no_touch_notification);
    Ok(())
}

#[test]
fn pin_policies_need_one_selector_and_an_override() -> Result<()> {
    use skagent::cli::parse_pin_policy;
    use skagent::pin_cache::{KeyPinPolicy, KeySelector};

    let rule = parse_pin_policy("application=ssh:personal,lifetime=1h,idle=15m")
        .map_err(anyhow::Error::msg)?;
    ensure!(
        rule == KeyPinPolicy {
            selector: KeySelector::Application("ssh:personal".to_owned()),
            lifetime: Some(Duration::from_hours(1)),
            idle: Some(Duration::from_mins(15)),
        }
    );
    let rule =
        parse_pin_policy("fingerprint=SHA256:abc+/def,lifetime=0").map_err(anyhow::Error::msg)?;
    ensure!(rule.selector == KeySelector::Fingerprint("SHA256:abc+/def".to_owned()));
    ensure!(rule.lifetime == Some(Duration::ZERO) && rule.idle.is_none());

    for refused in [
        "",
        "lifetime=1h",
        "application=ssh:a",
        "application=ssh:a,fingerprint=SHA256:x,lifetime=1h",
        "application=ssh:a,application=ssh:b,lifetime=1h",
        "application=ssh:a,lifetime=1h,lifetime=2h",
        "application=,lifetime=1h",
        "application=ssh:a,lifetime=1d",
        "application=ssh:a,ttl=1h",
        "application=ssh:a,lifetime",
    ] {
        ensure!(parse_pin_policy(refused).is_err(), "accepted {refused:?}");
    }

    let args = serve(&[
        "--pin-policy",
        "application=ssh:a,lifetime=1h",
        "--pin-policy",
        "application=ssh:b,idle=0",
    ])?;
    ensure!(args.pin_policies.len() == 2);
    Ok(())
}

#[test]
fn secret_memory_is_locked_unless_memfd_secret_is_asked_for() -> Result<()> {
    use skagent::cli::SecretMemory;

    ensure!(serve(&[])?.secret_memory == SecretMemory::Locked);
    ensure!(
        serve(&["--secret-memory", "memfd-secret"])?.secret_memory == SecretMemory::MemfdSecret
    );
    ensure!(serve(&["--secret-memory", "swap"]).is_err());
    Ok(())
}

#[test]
fn the_popup_replaces_pinentry_and_askpass() -> Result<()> {
    ensure!(serve(&[])?.popup.is_none());
    let args = serve(&["--popup", "/run/skagent-pinentry"])?;
    ensure!(args.popup.as_deref() == Some(Path::new("/run/skagent-pinentry")));
    ensure!(serve(&["--popup", "/x", "--pinentry", "/y"]).is_err());
    ensure!(serve(&["--popup", "/x", "--askpass", "/y"]).is_err());
    Ok(())
}

fn age(args: &[&str]) -> Result<AgeCommand> {
    let cli = Cli::try_parse_from(["skagent", "age"].iter().chain(args)).context("parsing age")?;
    match cli.command {
        Command::Age(args) => Ok(args.command),
        _ => bail!("not parsed as age"),
    }
}

#[test]
fn serve_listens_for_age_requests_next_to_its_socket_unless_told_where() -> Result<()> {
    ensure!(serve(&[])?.age_socket.is_none());
    let args = serve(&["--age-socket", "/tmp/age.sock"])?;
    ensure!(args.age_socket.as_deref() == Some(Path::new("/tmp/age.sock")));
    Ok(())
}

#[test]
fn age_identities_are_created_listed_and_written_out() -> Result<()> {
    ensure!(matches!(
        age(&["new"])?,
        AgeCommand::New { another: false, ref socket } if socket.age_socket.is_none()
    ));
    ensure!(matches!(
        age(&["new", "--another", "--age-socket", "/tmp/age.sock"])?,
        AgeCommand::New { another: true, ref socket }
            if socket.age_socket.as_deref() == Some(Path::new("/tmp/age.sock"))
    ));
    ensure!(matches!(age(&["list"])?, AgeCommand::List(ref socket) if socket.age_socket.is_none()));
    ensure!(matches!(
        age(&["identity"])?,
        AgeCommand::Identity {
            recipient: None,
            ..
        }
    ));
    ensure!(matches!(
        age(&["identity", "age1pq1example"])?,
        AgeCommand::Identity { recipient: Some(ref recipient), .. } if recipient == "age1pq1example"
    ));
    // Nothing takes a PIN, and `age` alone does nothing.
    ensure!(age(&[]).is_err());
    ensure!(age(&["new", "--pin", "123456"]).is_err());
    Ok(())
}

fn batch(args: &[&str]) -> Result<BatchArgs> {
    let cli =
        Cli::try_parse_from(["skagent", "batch"].iter().chain(args)).context("parsing batch")?;
    match cli.command {
        Command::Batch(args) => Ok(args),
        _ => bail!("not parsed as batch"),
    }
}

#[test]
fn a_batch_runs_a_command_with_whatever_arguments() -> Result<()> {
    let args = batch(&["--", "agenix", "rekey", "-a", "--for", "1h"])?;
    ensure!(args.command == ["agenix", "rekey", "-a", "--for", "1h"]);
    ensure!(args.lasting.is_none() && args.socket.age_socket.is_none());
    // Without the dashes too, and what follows the command is the command's.
    let args = batch(&["age", "-d", "--for", "x"])?;
    ensure!(args.command == ["age", "-d", "--for", "x"] && args.lasting.is_none());

    let args = batch(&["--for", "5m", "--age-socket", "/tmp/age.sock", "--", "true"])?;
    ensure!(args.lasting == Some(Duration::from_mins(5)));
    ensure!(args.socket.age_socket.as_deref() == Some(Path::new("/tmp/age.sock")));
    ensure!(args.command == ["true"]);

    ensure!(batch(&[]).is_err(), "a batch of nothing");
    ensure!(
        batch(&["--for", "5m"]).is_err(),
        "a batch of nothing, for a while"
    );
    ensure!(
        batch(&["--for", "0", "--", "true"]).is_err(),
        "a batch for no time"
    );
    ensure!(
        batch(&["--for", "5", "--", "true"]).is_err(),
        "a duration without a unit"
    );
    ensure!(
        batch(&["--for", "2000000h", "--", "true"]).is_err(),
        "longer than fits"
    );
    Ok(())
}

#[test]
fn batches_last_ten_minutes_unless_the_agent_is_told_otherwise() -> Result<()> {
    ensure!(DEFAULT_BATCH_LIFETIME == Duration::from_mins(10));
    ensure!(serve(&[])?.batch_lifetime == DEFAULT_BATCH_LIFETIME);
    ensure!(serve(&["--batch-lifetime", "2m"])?.batch_lifetime == Duration::from_mins(2));
    ensure!(serve(&["--batch-lifetime", "0"])?.batch_lifetime.is_zero());
    Ok(())
}

#[test]
fn the_command_of_a_batch_is_shown_as_its_words_cut_to_what_fits() -> Result<()> {
    let words = |words: &[&str]| words.iter().map(Into::into).collect::<Vec<_>>();
    ensure!(shown_command(&words(&["agenix", "rekey", "-a"])) == "agenix rekey -a");
    ensure!(shown_command(&[]).is_empty());
    let long = shown_command(&words(&["x", &"ä".repeat(MAX_COMMAND_BYTES)]));
    // Cut between characters, never inside one.
    ensure!(
        long.len() == MAX_COMMAND_BYTES && long.ends_with('ä'),
        "{}",
        long.len()
    );
    Ok(())
}

#[test]
fn the_batch_tool_exits_like_its_command() -> Result<()> {
    for code in [0_u8, 1, 2, 126, 255] {
        ensure!(
            exit_code(Some(i32::from(code)), None) == code,
            "exit code {code}"
        );
    }
    // Ended by a signal: 128 plus its number, as shells have it.
    ensure!(exit_code(None, Some(15)) == 143, "SIGTERM");
    ensure!(exit_code(None, Some(2)) == 130, "SIGINT");
    ensure!(exit_code(None, None) == 1);
    Ok(())
}

#[test]
fn age_files_are_decrypted_for_forwarded_agents_only_on_request() -> Result<()> {
    ensure!(!serve(&[])?.age_forwarding);
    ensure!(serve(&["--age-forwarding"])?.age_forwarding);
    Ok(())
}
