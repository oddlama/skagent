//! `skagent-pinentry`: skagent's popup. Started by the agent (`skagent serve
//! --popup`), it speaks the protocol in `skagent-popup` on stdin and stdout.
//! `--preview <screen>` shows one of the design's screens with example data.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::process::ExitCode;

use anyhow::{Context as _, Result, bail};
use clap::{Parser, ValueEnum};
use futures::StreamExt as _;
use futures::channel::mpsc;
use gpui::{
    App, AppContext as _, AsyncApp, Bounds, Entity, WindowBackgroundAppearance, WindowBounds,
    WindowKind, WindowOptions, layer_shell, px, size,
};
use skagent_pinentry::answers::Answers;
use skagent_pinentry::assets::Assets;
use skagent_pinentry::theme::Mode;
use skagent_pinentry::ui::{Popup, SIZE};
use skagent_pinentry::{fixtures, fonts};
use skagent_popup::{Message, decode_message, ready_line};

/// skagent's popup: the PIN, the touch and the result of a request in one
/// window.
#[derive(Debug, Parser)]
#[command(name = "skagent-pinentry", version, about)]
struct Cli {
    /// Show one of the design's screens with example data instead of
    /// talking to the agent.
    #[arg(long, value_name = "SCREEN", value_parser = clap::builder::PossibleValuesParser::new(fixtures::NAMES))]
    preview: Option<String>,

    /// Light or dark, instead of following the system.
    #[arg(long, value_enum)]
    theme: Option<ThemeArg>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ThemeArg {
    Light,
    Dark,
}

/// A line from the agent, or the end of them.
enum Input {
    Message(Message),
    End,
}

fn main() -> ExitCode {
    // Colour only on a terminal, and never with NO_COLOR set
    // (<https://no-color.org>): the agent passes its own stderr on, which
    // usually ends in the journal.
    let colour = std::io::stderr().is_terminal()
        && std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty());
    let _logging = tracing_subscriber::fmt()
        .with_ansi(colour)
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SKAGENT_PINENTRY_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "skagent-pinentry: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let mode = cli.theme.map(|theme| match theme {
        ThemeArg::Light => Mode::Light,
        ThemeArg::Dark => Mode::Dark,
    });
    let app = gpui_platform::application().with_assets(Assets);
    if let Some(name) = cli.preview {
        let (state, waiting) = fixtures::fixture(&name).context("no such screen")?;
        app.run(move |cx: &mut App| {
            fonts::load_bundled(cx);
            match open(cx, Answers::Preview, mode) {
                Ok(popup) => popup.update(cx, |popup, cx| popup.show(1, state, waiting, cx)),
                Err(error) => {
                    tracing::error!(error = %format!("{error:#}"), "can't open the window");
                    cx.quit();
                }
            }
        });
        return Ok(());
    }

    let (sender, receiver) = mpsc::unbounded();
    std::thread::Builder::new()
        .name("stdin".to_owned())
        .spawn(move || read_input(&sender))
        .context("starting the input thread")?;
    app.run(move |cx: &mut App| {
        fonts::load_bundled(cx);
        Answers::Agent.send(ready_line().as_bytes());
        cx.spawn(async move |cx| serve(receiver, mode, cx).await)
            .detach();
    });
    Ok(())
}

/// Passes the agent's lines on until its input ends.
fn read_input(sender: &mpsc::UnboundedSender<Input>) {
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        match decode_message(&line) {
            Ok(message) => {
                if sender.unbounded_send(Input::Message(message)).is_err() {
                    return;
                }
            }
            Err(error) => {
                tracing::error!(error = %format!("{error:#}"), "the agent sent something else");
                break;
            }
        }
    }
    let _ = sender.unbounded_send(Input::End);
}

async fn serve(
    mut receiver: mpsc::UnboundedReceiver<Input>,
    mode: Option<Mode>,
    cx: &mut AsyncApp,
) {
    let mut popup: Option<Entity<Popup>> = None;
    while let Some(input) = receiver.next().await {
        match input {
            Input::Message(Message::Show {
                seq,
                waiting,
                state,
            }) => {
                tracing::debug!(
                    seq,
                    state = state.name(),
                    waiting = waiting.len(),
                    "showing"
                );
                if popup.is_none() {
                    match cx.update(|cx| open(cx, Answers::Agent, mode)) {
                        Ok(opened) => popup = Some(opened),
                        Err(error) => {
                            tracing::error!(error = %format!("{error:#}"), "can't open the window");
                            cx.update(|cx| cx.quit());
                            return;
                        }
                    }
                }
                if let Some(popup) = &popup {
                    popup.update(cx, |popup, cx| popup.show(seq, *state, waiting, cx));
                }
            }
            Input::Message(Message::Queue { waiting }) => {
                if let Some(popup) = &popup {
                    popup.update(cx, |popup, cx| popup.queue(waiting, cx));
                }
            }
            Input::End => {
                tracing::debug!("no more requests");
                match &popup {
                    Some(popup) => popup.update(cx, Popup::end),
                    None => cx.update(|cx| cx.quit()),
                }
                return;
            }
        }
    }
}

/// Opens the popup: a centred overlay that takes the keyboard where the
/// compositor offers layer shell, else an ordinary window.
fn open(cx: &mut App, answers: Answers, mode: Option<Mode>) -> Result<Entity<Popup>> {
    let square = size(px(SIZE), px(SIZE));
    let overlay = WindowOptions {
        titlebar: None,
        window_bounds: Some(WindowBounds::Windowed(Bounds::new(
            gpui::point(px(0.), px(0.)),
            square,
        ))),
        app_id: Some("skagent-pinentry".to_owned()),
        window_background: WindowBackgroundAppearance::Transparent,
        kind: WindowKind::LayerShell(layer_shell::LayerShellOptions {
            namespace: "skagent-pinentry".to_owned(),
            layer: layer_shell::Layer::Overlay,
            keyboard_interactivity: layer_shell::KeyboardInteractivity::Exclusive,
            ..Default::default()
        }),
        is_movable: false,
        is_resizable: false,
        is_minimizable: false,
        focus: true,
        show: true,
        ..Default::default()
    };
    let build = move |window: &mut gpui::Window, cx: &mut App| {
        let popup = cx.new(|cx| Popup::new(answers, mode, cx));
        let focus = popup.read(cx).focus_handle();
        focus.focus(window, cx);
        popup
    };
    let opened = match cx.open_window(overlay, build) {
        Ok(window) => {
            tracing::debug!("opened a layer-shell overlay");
            window
        }
        Err(error) if error.is::<layer_shell::LayerShellNotSupportedError>() => {
            tracing::info!("no layer shell, opening an ordinary window");
            let window = WindowOptions {
                titlebar: None,
                window_bounds: Some(WindowBounds::Windowed(Bounds::centered(None, square, cx))),
                app_id: Some("skagent-pinentry".to_owned()),
                window_background: WindowBackgroundAppearance::Transparent,
                is_resizable: false,
                is_minimizable: false,
                focus: true,
                show: true,
                ..Default::default()
            };
            cx.open_window(window, build)?
        }
        Err(error) => bail!(error),
    };
    opened
        .update(cx, |_, _, cx| cx.entity())
        .map_err(|error| anyhow::anyhow!("{error}"))
        .context("reading the popup's view")
}
