//! The popup window: renders a [`Screen`] in design B+ and turns keys and
//! clicks into answers for the agent.
//!
//! Every motion is computed from the time since the screen appeared, and
//! the window asks for another frame while anything moves.

use std::f32::consts::PI;
use std::time::{Duration, Instant};

use gpui::{
    AnyElement, Context, FocusHandle, FontWeight, Hsla, IntoElement, KeyDownEvent, LineCap,
    LineJoin, PathBuilder, PathStyle, Pixels, Render, SharedString, StrokeOptions, Window,
    WindowAppearance, canvas, div, point, prelude::*, px, relative, svg,
};
use skagent_popup::{Queued, State};

use crate::answers::Answers;
use crate::pin::PinInput;
use crate::screen::{
    Anchor, Badge, Body, Close, Contact, Glyph, Screen, Span, TOTAL_TRIES, Tint, Tone, glyph,
};
use crate::theme::{Mode, Theme};

/// The window is a fixed square.
pub const SIZE: f32 = 360.;

const FONT: &str = "Inter";
const MONO: &str = "JetBrains Mono";

/// How long a new screen fades in.
const CROSSFADE: Duration = Duration::from_millis(180);
/// Short motions (pop, shake, tiles) are over by then.
const INTRO: Duration = Duration::from_millis(1200);

/// What is shown right now.
struct Shown {
    seq: u64,
    screen: Screen,
    since: Instant,
}

/// The popup's one view.
pub struct Popup {
    focus: FocusHandle,
    shown: Option<Shown>,
    waiting: Vec<Queued>,
    pin: Option<PinInput>,
    /// The error ring after a wrong PIN, until the user types.
    field_error: bool,
    /// Forced light or dark; else the system's.
    mode: Option<Mode>,
    answers: Answers,
    /// A state that waits for a final screen to have had its moment.
    pending: Option<(u64, State)>,
    /// The agent closed the input: nothing follows.
    ended: bool,
}

impl Popup {
    /// An empty popup that answers through `answers`.
    pub fn new(answers: Answers, mode: Option<Mode>, cx: &mut Context<Self>) -> Self {
        let pin = match PinInput::new() {
            Ok(pin) => Some(pin),
            Err(error) => {
                tracing::error!(error = %format!("{error:#}"), "no locked memory for the PIN");
                None
            }
        };
        Self {
            focus: cx.focus_handle(),
            shown: None,
            waiting: Vec::new(),
            pin,
            field_error: false,
            mode,
            answers,
            pending: None,
            ended: false,
        }
    }

    /// The focus handle that takes the keyboard.
    #[must_use]
    pub fn focus_handle(&self) -> FocusHandle {
        self.focus.clone()
    }

    /// Whether a state was shown yet.
    #[must_use]
    pub fn showing(&self) -> bool {
        self.shown.is_some()
    }

    /// Shows `state`, unless a final screen still needs its moment: then it
    /// follows right after.
    pub fn show(&mut self, seq: u64, state: State, waiting: Vec<Queued>, cx: &mut Context<Self>) {
        self.waiting = waiting;
        match self.remaining_linger() {
            Some(remaining) => {
                let first = self.pending.is_none();
                self.pending = Some((seq, state));
                if first {
                    Self::after(remaining, cx, |this, cx| {
                        if let Some((seq, state)) = this.pending.take() {
                            this.apply(seq, &state);
                            cx.notify();
                        }
                    });
                }
            }
            None => self.apply(seq, &state),
        }
        cx.notify();
    }

    /// The waiting requests changed.
    pub fn queue(&mut self, waiting: Vec<Queued>, cx: &mut Context<Self>) {
        self.waiting = waiting;
        cx.notify();
    }

    /// The agent closed the input. Final screens stay for their moment,
    /// dead ends until the user closes them; otherwise the popup goes.
    pub fn end(&mut self, cx: &mut Context<Self>) {
        self.ended = true;
        let stays = self.shown.as_ref().is_some_and(|shown| {
            shown.screen.lingers.is_none() && shown.screen.close == Close::Close
        });
        if stays || self.pending.is_some() {
            return;
        }
        match self.remaining_linger() {
            Some(remaining) => Self::after(remaining, cx, |_, cx| cx.quit()),
            None => cx.quit(),
        }
    }

    fn apply(&mut self, seq: u64, state: &State) {
        let screen = Screen::of(state);
        let new_mistake = matches!(screen.body, Body::Pin { error: true, .. });
        self.field_error = new_mistake;
        if let Some(pin) = self.pin.as_mut() {
            pin.clear();
        }
        self.shown = Some(Shown {
            seq,
            screen,
            since: Instant::now(),
        });
    }

    /// How long the final screen shown still has to stay, if any.
    fn remaining_linger(&self) -> Option<Duration> {
        let shown = self.shown.as_ref()?;
        let lingers = shown.screen.lingers?;
        let remaining = lingers.saturating_sub(shown.since.elapsed());
        (!remaining.is_zero()).then_some(remaining)
    }

    fn after(
        delay: Duration,
        cx: &mut Context<Self>,
        then: impl FnOnce(&mut Self, &mut Context<Self>) + 'static,
    ) {
        cx.spawn(async move |this, cx| {
            cx.background_executor().timer(delay).await;
            let _gone = this.update(cx, then);
        })
        .detach();
    }

    fn submit(&mut self, cx: &mut Context<Self>) {
        let Some(shown) = self.shown.as_ref() else {
            return;
        };
        match shown.screen.body {
            Body::Pin { .. } => {
                let seq = shown.seq;
                let Some(pin) = self.pin.as_mut() else {
                    return;
                };
                if pin.is_empty() {
                    return;
                }
                match pin.take_line(seq) {
                    Ok(line) => {
                        self.answers.send(line.expose());
                        tracing::debug!(seq, "sent the PIN");
                    }
                    Err(error) => {
                        tracing::error!(error = %format!("{error:#}"), "can't hand over the PIN");
                    }
                }
            }
            Body::TryAgain => {
                self.answers
                    .send(skagent_popup::retry_line(shown.seq).as_bytes());
                tracing::debug!(seq = shown.seq, "asked to try again");
            }
            _ => return,
        }
        cx.notify();
    }

    fn close(&mut self, cx: &mut Context<Self>) {
        let Some(shown) = self.shown.as_ref() else {
            return;
        };
        match shown.screen.close {
            Close::None => {}
            Close::Cancel => {
                self.answers
                    .send(skagent_popup::cancel_line(shown.seq).as_bytes());
                tracing::debug!(seq = shown.seq, "cancelled");
            }
            Close::Close => {
                // A final screen: on to what's next, or gone.
                if let Some((seq, state)) = self.pending.take() {
                    self.apply(seq, &state);
                } else if self.ended {
                    cx.quit();
                } else {
                    self.answers
                        .send(skagent_popup::cancel_line(shown.seq).as_bytes());
                    tracing::debug!(seq = shown.seq, "closed");
                }
            }
        }
        cx.notify();
    }

    fn key_down(&mut self, event: &KeyDownEvent, cx: &mut Context<Self>) {
        let keystroke = &event.keystroke;
        match keystroke.key.as_str() {
            "escape" => self.close(cx),
            "enter" => self.submit(cx),
            "backspace" => {
                if let Some(pin) = self.pin.as_mut() {
                    pin.pop();
                }
                self.field_error = false;
                cx.notify();
            }
            _ => {
                let typing = self
                    .shown
                    .as_ref()
                    .is_some_and(|shown| matches!(shown.screen.body, Body::Pin { .. }));
                let modified = keystroke.modifiers.control
                    || keystroke.modifiers.alt
                    || keystroke.modifiers.platform;
                if let (true, false, Some(text), Some(pin)) = (
                    typing,
                    modified,
                    keystroke.key_char.as_deref(),
                    self.pin.as_mut(),
                ) && pin.push(text)
                {
                    self.field_error = false;
                    cx.notify();
                }
            }
        }
    }
}

impl Render for Popup {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let mode = self.mode.unwrap_or(match window.appearance() {
            WindowAppearance::Dark | WindowAppearance::VibrantDark => Mode::Dark,
            WindowAppearance::Light | WindowAppearance::VibrantLight => Mode::Light,
        });
        let theme = Theme::new(mode);
        let root = div()
            .id("popup")
            .track_focus(&self.focus)
            .on_key_down(cx.listener(|this, event: &KeyDownEvent, _, cx| this.key_down(event, cx)))
            .size(px(SIZE))
            .font_family(FONT)
            // CSS's `normal` for Inter, which the design was drawn with.
            .line_height(relative(1.21))
            .text_color(theme.text);
        let Some(shown) = self.shown.as_ref() else {
            return root;
        };
        let elapsed = shown.since.elapsed();
        if moves(&shown.screen) || elapsed < INTRO {
            window.request_animation_frame();
        }
        let screen = &shown.screen;
        let typed = self.pin.as_ref().map_or(0, PinInput::chars);
        let content = div()
            .size_full()
            .relative()
            .flex()
            .flex_col()
            .items_center()
            .bg(theme.surface)
            .border_1()
            .border_color(theme.border)
            .rounded(px(24.))
            .opacity(fraction(elapsed, CROSSFADE))
            // Every screen is one block, centred: anchor, title, subtitle and
            // whatever comes below them.
            .justify_center()
            .p(px(24.))
            .child(anchor(screen, &theme, elapsed))
            .child(
                div()
                    .mt(px(title_gap(screen)))
                    .text_size(px(19.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_center()
                    .child(screen.title.clone()),
            )
            .child(subtitle(screen, &theme))
            .child(body(screen, &theme, elapsed, typed, self.field_error, cx))
            .children(close_button(screen, &theme, cx))
            .children(queue_pill(&self.waiting, &theme));
        root.child(content)
    }
}

/// Whether the screen keeps moving (not just an intro).
fn moves(screen: &Screen) -> bool {
    matches!(screen.anchor, Anchor::Countdown { .. })
        || matches!(
            screen.body,
            Body::Spinner | Body::Devices(_) | Body::Closing(_)
        )
        || screen.badge == Some(Badge::Replug)
}

/// Progress of `elapsed` through `duration`, from 0 to 1.
fn fraction(elapsed: Duration, duration: Duration) -> f32 {
    if duration.is_zero() {
        return 1.;
    }
    (elapsed.as_secs_f32() / duration.as_secs_f32()).clamp(0., 1.)
}

/// Phase of a repeating motion, from 0 to 1.
fn phase(elapsed: Duration, period: Duration, offset: Duration) -> f32 {
    let period = period.as_secs_f32();
    if period <= 0. {
        return 0.;
    }
    ((elapsed.as_secs_f32() + offset.as_secs_f32()) % period) / period
}

fn ease_out(t: f32) -> f32 {
    1. - (1. - t).powi(3)
}

fn ease_in_out(t: f32) -> f32 {
    if t < 0.5 {
        4. * t * t * t
    } else {
        1. - (-2. * t + 2.).powi(3) / 2.
    }
}

/// Scale of a pop: 0 to 1.15 to 1 over 350 ms, starting after `delay`.
fn pop(elapsed: Duration, delay: Duration) -> f32 {
    let t = fraction(elapsed.saturating_sub(delay), Duration::from_millis(350));
    if t < 0.7 {
        1.15 * ease_out(t / 0.7)
    } else {
        1.15 - 0.15 * ease_out((t - 0.7) / 0.3)
    }
}

fn title_gap(screen: &Screen) -> f32 {
    match screen.anchor {
        Anchor::Countdown { pulse: true, .. } if screen.badge.is_none() => 22.,
        Anchor::Countdown { .. } => 18.,
        _ => 12.,
    }
}

fn tint(theme: &Theme, tint: Tint) -> Hsla {
    match tint {
        Tint::Key => theme.avatar_tint,
        Tint::Warning => theme.avatar_tint_warning,
        Tint::Error => theme.avatar_tint_error,
        Tint::Device => theme.device_tint,
    }
}

fn glyph_text(glyph: &Glyph) -> SharedString {
    match glyph {
        Glyph::Emoji(emoji) | Glyph::Initial(emoji) => SharedString::from(emoji.clone()),
    }
}

fn anchor(screen: &Screen, theme: &Theme, elapsed: Duration) -> AnyElement {
    match &screen.anchor {
        Anchor::Key {
            glyph,
            tint: fill,
            missing,
        } => {
            let square = div()
                .size(px(88.))
                .rounded(px(26.))
                .flex()
                .items_center()
                .justify_center()
                .text_size(px(46.))
                .child(glyph_text(glyph));
            let square = if *missing {
                square
                    .border_2()
                    .border_dashed()
                    .border_color(theme.avatar_missing_border)
                    .opacity(0.55)
            } else {
                square.bg(tint(theme, *fill))
            };
            slot(112., square, screen.badge, theme, elapsed)
        }
        Anchor::Device {
            tint: fill,
            contact,
        } => {
            let square = div()
                .size(px(88.))
                .rounded(px(26.))
                .bg(tint(theme, *fill))
                .flex()
                .items_center()
                .justify_center()
                .child(device(28., 42., *contact, theme));
            slot(112., square, screen.badge, theme, elapsed)
        }
        Anchor::Countdown {
            glyph,
            duration,
            pulse,
        } => {
            let remaining = 1. - fraction(elapsed, *duration);
            let circle = div()
                .size(px(100.))
                .rounded_full()
                .flex()
                .items_center()
                .justify_center()
                .text_size(px(50.))
                .map(|circle| match glyph {
                    Some(glyph) => circle.bg(theme.avatar_tint).child(glyph_text(glyph)),
                    None => {
                        circle
                            .bg(theme.device_tint)
                            .child(device(28., 42., Contact::Filled, theme))
                    }
                });
            let mut slot_element = div()
                .relative()
                .size(px(132.))
                .flex()
                .items_center()
                .justify_center();
            if *pulse {
                for offset in [Duration::ZERO, Duration::from_millis(900)] {
                    let t = ease_out(phase(elapsed, Duration::from_millis(1800), offset));
                    let size = 112. * (0.8 + 0.65 * t);
                    slot_element = slot_element.child(
                        div()
                            .absolute()
                            .left(px((132. - size) / 2.))
                            .top(px((132. - size) / 2.))
                            .size(px(size))
                            .rounded_full()
                            .bg(theme.accent)
                            .opacity(theme.pulse_opacity * (1. - t)),
                    );
                }
            }
            slot_element = slot_element
                .child(ring(theme, remaining))
                .child(circle)
                .children(
                    screen
                        .badge
                        .map(|badge| badge_element(badge, theme, elapsed, 6.)),
                );
            slot_element.into_any_element()
        }
    }
}

/// The anchor's square in its slot, with the badge at the corner.
fn slot(
    size: f32,
    square: gpui::Div,
    badge: Option<Badge>,
    theme: &Theme,
    elapsed: Duration,
) -> AnyElement {
    div()
        .relative()
        .size(px(size))
        .flex()
        .items_center()
        .justify_center()
        .child(square)
        .children(badge.map(|badge| badge_element(badge, theme, elapsed, 4.)))
        .into_any_element()
}

/// The countdown ring: a track and an arc from 12 o'clock that drains
/// counter-clockwise as `remaining` goes from 1 to 0.
fn ring(theme: &Theme, remaining: f32) -> impl IntoElement {
    let (track, arc) = (theme.ring_track, theme.accent);
    div()
        .absolute()
        .left(px(4.))
        .top(px(4.))
        .size(px(124.))
        .child(
            canvas(
                |_, _, _| (),
                move |bounds, (), window, _| {
                    let center = bounds.center();
                    paint_arc(window, center, 58., 0., 1., 4., track);
                    if remaining > 0. {
                        paint_arc(window, center, 58., 0., remaining, 4., arc);
                    }
                },
            )
            .size_full(),
        )
}

/// Strokes an arc around `center`, from `start` to `start + length` turns
/// (0 is 12 o'clock, clockwise).
fn paint_arc(
    window: &mut Window,
    center: gpui::Point<Pixels>,
    radius: f32,
    start: f32,
    length: f32,
    width: f32,
    color: Hsla,
) {
    /// Straight pieces in a whole circle.
    const STEPS: u8 = 96;
    let mut builder = PathBuilder::stroke(px(width)).with_style(PathStyle::Stroke(StrokeOptions {
        line_width: width,
        line_cap: LineCap::Round,
        line_join: LineJoin::Round,
        ..StrokeOptions::default()
    }));
    let (x, y) = (f32::from(center.x), f32::from(center.y));
    let points: Vec<_> = (0..=STEPS)
        .map(|step| {
            let turn = start + length * f32::from(step) / f32::from(STEPS);
            let angle = turn * 2. * PI - PI / 2.;
            point(px(x + radius * angle.cos()), px(y + radius * angle.sin()))
        })
        .collect();
    builder.add_polygon(&points, length >= 1.);
    match builder.build() {
        Ok(path) => window.paint_path(path, color),
        Err(error) => tracing::debug!(%error, "drawing an arc failed"),
    }
}

/// The YubiKey drawing, `width` by `height`.
fn device(width: f32, height: f32, contact: Contact, theme: &Theme) -> impl IntoElement {
    let diameter = width * 9. / 20.;
    let dot = div()
        .absolute()
        .left(px((width - diameter) / 2.))
        .top(px(height * 17. / 30. - diameter / 2.))
        .size(px(diameter))
        .rounded_full();
    let dot = match contact {
        Contact::Filled => dot.bg(theme.warning),
        Contact::Outline => dot.border(px(width * 1.6 / 20.)).border_color(theme.text),
    };
    div()
        .relative()
        .w(px(width))
        .h(px(height))
        .child(
            svg()
                .path("icons/device-frame.svg")
                .w(px(width))
                .h(px(height))
                .text_color(theme.text),
        )
        .child(dot)
}

/// A status badge, `inset` from the slot's corner.
fn badge_element(badge: Badge, theme: &Theme, elapsed: Duration, inset: f32) -> impl IntoElement {
    let (fill, ink, icon) = match badge {
        Badge::Swap => (theme.warning, theme.on_warning, Some("icons/swap.svg")),
        Badge::Plug => (theme.accent, theme.on_accent, Some("icons/plug.svg")),
        Badge::Replug => (theme.warning, theme.on_warning, Some("icons/replug.svg")),
        Badge::Clock => (theme.warning, theme.on_warning, Some("icons/clock.svg")),
        Badge::Pencil => (theme.warning, theme.on_warning, Some("icons/pencil.svg")),
        Badge::Lock => (theme.error, theme.on_accent, Some("icons/lock.svg")),
        Badge::Failed => (theme.error, theme.on_accent, Some("icons/failed.svg")),
        Badge::Done => (theme.success, theme.on_success, Some("icons/done.svg")),
        Badge::Again => match theme.mode {
            Mode::Light => (theme.accent, theme.on_accent, None),
            Mode::Dark => (theme.text, theme.surface, None),
        },
    };
    let scale = if badge == Badge::Done {
        pop(elapsed, Duration::ZERO)
    } else {
        1.
    };
    let lift = if badge == Badge::Replug {
        -4. * (1.
            - (2. * ease_in_out(phase(elapsed, Duration::from_millis(1600), Duration::ZERO)) - 1.)
                .abs())
    } else {
        0.
    };
    // A 32 px fill in a 3 px ring of the surface colour. The ring is a
    // second circle: as a border, the fill's edge would show through it.
    let size = 38. * scale;
    let shrink = (38. - size) / 2.;
    let ring = div()
        .absolute()
        .right(px(inset + shrink))
        .bottom(px(inset + shrink - lift))
        .flex()
        .rounded_full()
        .bg(theme.surface)
        .p(px(3. * scale));
    let fill = div()
        .flex()
        .items_center()
        .justify_center()
        .rounded_full()
        .bg(fill)
        .text_color(ink);
    match icon {
        Some(path) => ring
            .size(px(size))
            // Nothing to draw yet at the start of a pop.
            .child(fill.size_full().children(
                (scale > 0.05).then(|| svg().path(path).size(px(15. * scale)).text_color(ink)),
            ))
            .into_any_element(),
        // The design's pill is 32 px high including its ring.
        None => ring
            .h(px(32.))
            .child(
                fill.h_full()
                    .min_w(px(26.))
                    .px(px(6.))
                    .text_size(px(13.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("2×"),
            )
            .into_any_element(),
    }
}

fn subtitle(screen: &Screen, theme: &Theme) -> impl IntoElement {
    let (color, weight) = match screen.subtitle.tone {
        Tone::Muted => (theme.text_muted, FontWeight::NORMAL),
        Tone::Error => (theme.error, FontWeight::MEDIUM),
        Tone::Warning => (theme.warning, FontWeight::NORMAL),
    };
    // The lock screen's subtitle is a sentence that wraps.
    let paragraph = screen.badge == Some(Badge::Lock);
    let line = div()
        .mt(px(4.))
        .max_w(px(if paragraph { 270. } else { 312. }))
        .when(paragraph, |line| line.line_height(relative(1.45)))
        .text_size(px(14.))
        .font_weight(weight)
        .text_color(color)
        .text_center();
    if screen.subtitle.spans.iter().any(|span| span.mono) {
        line.flex()
            .flex_row()
            .justify_center()
            .children(screen.subtitle.spans.iter().map(span_element))
            .into_any_element()
    } else {
        line.child(screen.subtitle.text()).into_any_element()
    }
}

fn span_element(span: &Span) -> impl IntoElement {
    let text = div().child(span.text.clone());
    if span.mono {
        text.font_family(MONO)
    } else {
        text
    }
}

fn body(
    screen: &Screen,
    theme: &Theme,
    elapsed: Duration,
    typed: usize,
    field_error: bool,
    cx: &mut Context<Popup>,
) -> AnyElement {
    match &screen.body {
        Body::Empty => div().into_any_element(),
        Body::Pin { error, .. } => pin_field(theme, elapsed, typed, *error && field_error, cx),
        Body::TryAgain => try_again(theme, cx).into_any_element(),
        Body::Command(command) => command_box(theme, command).into_any_element(),
        Body::Spinner => spinner(theme, elapsed).into_any_element(),
        Body::Devices(count) => devices(theme, elapsed, *count).into_any_element(),
        Body::Tries(left) => tries(theme, *left).into_any_element(),
        Body::Tiles { glyphs, more } => tiles(theme, elapsed, glyphs, *more).into_any_element(),
        Body::Closing(duration) => closing(theme, elapsed, *duration).into_any_element(),
    }
}

fn try_again(theme: &Theme, cx: &mut Context<Popup>) -> impl IntoElement {
    field_shell(theme, false)
        .id("retry")
        .on_click(cx.listener(|this, _, _, cx| this.submit(cx)))
        .child(
            div()
                .flex_1()
                .text_size(px(16.))
                .font_weight(FontWeight::SEMIBOLD)
                .child("Try again"),
        )
        .child(action_square(theme, "icons/retry.svg", 1.))
}

fn command_box(theme: &Theme, command: &'static str) -> impl IntoElement {
    div()
        .mt(px(28.))
        .w_full()
        .h(px(52.))
        .rounded(px(14.))
        .bg(theme.field)
        .flex()
        .items_center()
        .justify_center()
        .font_family(MONO)
        .text_size(px(13.))
        .child(command)
}

/// The plugged-in security keys while waiting for a touch on one of them.
fn devices(theme: &Theme, elapsed: Duration, count: usize) -> impl IntoElement {
    let blink = 1.
        - 0.8
            * (1.
                - (2. * ease_in_out(phase(elapsed, Duration::from_secs(1), Duration::ZERO)) - 1.)
                    .abs());
    div()
        .mt(px(22.))
        .flex()
        .items_center()
        .gap(px(10.))
        .children((0..count).map(|_| {
            div()
                .relative()
                .w(px(20.))
                .h(px(30.))
                .child(
                    svg()
                        .path("icons/device-outline.svg")
                        .w(px(20.))
                        .h(px(30.))
                        .text_color(theme.text_muted),
                )
                .child(
                    div()
                        .absolute()
                        .left(px(5.5))
                        .top(px(12.5))
                        .size(px(9.))
                        .rounded_full()
                        .bg(theme.accent)
                        .opacity(blink),
                )
        }))
        .child(
            div()
                .ml(px(2.))
                .text_size(px(12.))
                .text_color(theme.text_muted)
                .child(format!("{count} plugged in")),
        )
}

/// The PIN tries left, as dots.
fn tries(theme: &Theme, left: u32) -> impl IntoElement {
    div()
        .mt(px(28.))
        .flex()
        .flex_col()
        .items_center()
        .child(
            div()
                .flex()
                .gap(px(5.))
                .children((0..TOTAL_TRIES).map(|index| {
                    let dot = div().size(px(8.)).rounded_full();
                    if index < left {
                        dot.bg(theme.dot_filled)
                    } else {
                        dot.border(px(1.5)).border_color(theme.dot_hollow)
                    }
                })),
        )
        .child(
            div()
                .mt(px(8.))
                .text_size(px(12.))
                .text_color(theme.text_muted)
                .child(crate::screen::tries_left(left)),
        )
}

/// The loaded keys, popping in one after another.
fn tiles(theme: &Theme, elapsed: Duration, glyphs: &[Glyph], more: usize) -> impl IntoElement {
    div()
        .mt(px(22.))
        .flex()
        .gap(px(8.))
        .children((0_u32..).zip(glyphs).map(|(index, tile)| {
            let delay = Duration::from_millis(100).saturating_mul(index);
            let size = 40. * pop(elapsed, delay);
            let fill = if index == 0 {
                theme.avatar_tint
            } else {
                theme.device_tint
            };
            div()
                .size(px(40.))
                .flex()
                .items_center()
                .justify_center()
                .child(
                    div()
                        .size(px(size))
                        .rounded(px(12. * size / 40.))
                        .bg(fill)
                        .flex()
                        .items_center()
                        .justify_center()
                        .text_size(px(22. * size / 40.))
                        .child(glyph_text(tile)),
                )
        }))
        .children((more > 0).then(|| {
            div()
                .h(px(40.))
                .flex()
                .items_center()
                .text_size(px(12.))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(theme.text_muted)
                .child(format!("+{more}"))
        }))
}

/// The bar that drains until a final screen closes.
fn closing(theme: &Theme, elapsed: Duration, duration: Duration) -> impl IntoElement {
    div()
        .mt(px(28.))
        .flex()
        .flex_col()
        .items_center()
        .child(
            div()
                .w(px(96.))
                .h(px(3.))
                .rounded(px(2.))
                .bg(theme.ring_track)
                .child(
                    div()
                        .h(px(3.))
                        .w(px(96. * (1. - fraction(elapsed, duration))))
                        .bg(theme.dot_hollow),
                ),
        )
        .child(
            div()
                .mt(px(8.))
                .text_size(px(12.))
                .text_color(theme.text_muted)
                .child("Closing"),
        )
}

/// The PIN field's shake after a wrong PIN: (progress, offset in px).
const SHAKE: [(f32, f32); 6] = [
    (0., 0.),
    (0.2, -7.),
    (0.4, 7.),
    (0.6, -4.),
    (0.8, 4.),
    (1., 0.),
];

/// The PIN field's horizontal offset `t` (0 to 1) into its shake.
fn shake_offset(t: f32) -> f32 {
    SHAKE
        .windows(2)
        .find_map(|pair| match *pair {
            [(from_t, from), (to_t, to)] if (from_t..=to_t).contains(&t) && to_t > from_t => {
                Some(from + (to - from) * (t - from_t) / (to_t - from_t))
            }
            _ => None,
        })
        .unwrap_or(0.)
}

/// The 52 px field shape with its 2 px ring.
fn field_shell(theme: &Theme, error: bool) -> gpui::Div {
    div()
        .mt(px(28.))
        .w_full()
        .h(px(52.))
        .rounded(px(14.))
        .bg(if error {
            theme.field_error
        } else {
            theme.field
        })
        .border_2()
        .border_color(if error { theme.error } else { theme.accent })
        .flex()
        .items_center()
        .pl(px(14.))
        .pr(px(4.))
}

/// The 40 px accent square with an icon, inside a field.
fn action_square(theme: &Theme, icon: &'static str, opacity: f32) -> impl IntoElement {
    div()
        .size(px(40.))
        .rounded(px(11.))
        .bg(theme.accent)
        .opacity(opacity)
        .flex()
        .items_center()
        .justify_center()
        .child(svg().path(icon).size(px(18.)).text_color(theme.on_accent))
}

fn pin_field(
    theme: &Theme,
    elapsed: Duration,
    typed: usize,
    error: bool,
    cx: &mut Context<Popup>,
) -> AnyElement {
    let shake = if error {
        shake_offset(fraction(elapsed, Duration::from_millis(400)))
    } else {
        0.
    };
    let text = if typed == 0 {
        div().text_color(theme.placeholder).child("PIN")
    } else {
        div().text_color(theme.text).child("•".repeat(typed))
    };
    field_shell(theme, error)
        .relative()
        .left(px(shake))
        .child(div().flex_1().text_size(px(17.)).child(text))
        .child(
            div()
                .id("submit")
                .on_click(cx.listener(|this, _, _, cx| this.submit(cx)))
                .child(action_square(
                    theme,
                    "icons/submit.svg",
                    if typed == 0 { 0.4 } else { 1. },
                )),
        )
        .into_any_element()
}

fn spinner(theme: &Theme, elapsed: Duration) -> impl IntoElement {
    let accent = theme.accent;
    let start = phase(elapsed, Duration::from_secs(1), Duration::ZERO);
    div().mt(px(28.)).size(px(20.)).child(
        canvas(
            |_, _, _| (),
            move |bounds, (), window, _| {
                paint_arc(
                    window,
                    bounds.center(),
                    7.5,
                    start,
                    300. / 360.,
                    2.2,
                    accent,
                );
            },
        )
        .size_full(),
    )
}

fn close_button(screen: &Screen, theme: &Theme, cx: &mut Context<Popup>) -> Option<AnyElement> {
    screen.close.label()?;
    Some(
        div()
            .id("close")
            .absolute()
            .top(px(10.))
            .right(px(10.))
            .size(px(44.))
            .rounded_full()
            .flex()
            .items_center()
            .justify_center()
            .on_click(cx.listener(|this, _, _, cx| this.close(cx)))
            .child(
                svg()
                    .path("icons/close.svg")
                    .size(px(16.))
                    .text_color(theme.text_muted),
            )
            .into_any_element(),
    )
}

/// The pill with the waiting requests' emoji and their number.
fn queue_pill(waiting: &[Queued], theme: &Theme) -> Option<AnyElement> {
    if waiting.is_empty() {
        return None;
    }
    let circles = waiting.iter().take(2).enumerate().map(|(index, queued)| {
        let circle = div()
            .size(px(24.))
            .rounded_full()
            .bg(theme.device_tint)
            .border_2()
            .border_color(theme.field)
            .flex()
            .items_center()
            .justify_center()
            .text_size(px(13.))
            .map(|circle| match &queued.key {
                Some(key) => circle.child(glyph_text(&glyph(key))),
                None => circle.child(
                    svg()
                        .path("icons/device-outline.svg")
                        .w(px(8.))
                        .h(px(12.))
                        .text_color(theme.text_muted),
                ),
            });
        if index > 0 {
            circle.ml(px(-8.))
        } else {
            circle
        }
    });
    Some(
        div()
            .absolute()
            .top(px(18.))
            .left(px(16.))
            .h(px(30.))
            .rounded(px(15.))
            .bg(theme.field)
            .flex()
            .items_center()
            .pl(px(3.))
            .pr(px(10.))
            .gap(px(6.))
            .child(div().flex().children(circles))
            .child(
                div()
                    .text_size(px(12.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(theme.text_muted)
                    .child(format!("+{}", waiting.len())),
            )
            .into_any_element(),
    )
}
