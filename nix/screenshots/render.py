# The body of the screenshot run's script (see default.nix, which puts the
# paths in front of it): every state of the popup, drawn by skagent-pinentry
# itself on a headless sway, cut out and put together.
#
# The popup speaks its protocol on stdin, so a state is one JSON line. The
# styled ones use --preview with a configuration, like a user trying a style.

import json
import shlex
import tarfile

RUNTIME = "/run/alice-wayland"
SHOTS = "/tmp/shots"
# The popup is 360 logical pixels wide, centred on the 500 px output.
REGION = "70,70 360x360"
# What the sheets are laid on, and their labels.
PAGE = {"light": "#f4f4f6", "dark": "#303036"}
INK = {"light": "#3a3a40", "dark": "#c8c8d0"}


def alice_ok(command: str) -> str:
    return machine.succeed(f"su - alice -c {shlex.quote(command)} 2>&1")


def on_display(command: str) -> str:
    return alice_ok(
        f"XDG_RUNTIME_DIR={RUNTIME} WAYLAND_DISPLAY={display}"
        f" SWAYSOCK=$(ls {RUNTIME}/sway-ipc.*.sock) {command}"
    )


def backdrop(colour: str) -> None:
    """What the output shows around the popup."""
    on_display(f"swaymsg output HEADLESS-1 bg '{colour}' solid_color")
    machine.sleep(1)


# ---------------------------------------------------------------- the data


def key(emoji: str | None, label: str) -> dict:
    return {
        "emoji": emoji,
        "label": label,
        "fingerprint": "SHA256:4NU8jDPeifwDQZBds3tPVzsluIgQ6CTN6zoxKMzxIkQ",
    }


FOX = key("🦊", "github-work")
OCTOPUS = key("🐙", "github-sign")
SATELLITE = key("🛰️", "deploy-prod")
IDENTITY = {"emoji": None, "label": "age identity", "fingerprint": "age1pq1x34nzs…fzv49zc0k"}
NEW_IDENTITY = {"emoji": None, "label": "New age identity", "fingerprint": ""}
DESK = {"name": "Desk 5C NFC"}
NANO = {"name": "Keychain 5 Nano"}
SERIAL = {"name": "YubiKey 12 345 678"}


def named(name: str) -> dict:
    return {"kind": "named", "name": name}


def host_key(fingerprint: str) -> dict:
    return {"kind": "host-key", "fingerprint": fingerprint}


UNVERIFIED = {"kind": "unverified"}
JUMP_KEY = host_key("SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU")
TARGET_KEY = host_key("SHA256:Zx0RsvKWz3HmC1Kcn+eGqvPG2Zf3M2JfXw5Yk8kq2aA")


def login(host: dict, via: dict | None = None) -> dict:
    return {"kind": "login", "user": "git", "host": host, "via": via}


def sign(namespace: str) -> dict:
    return {"kind": "sign", "namespace": namespace}


def decrypt(name: str | None) -> dict:
    return {"kind": "decrypt", "by": {"kind": "program", "name": name}}


def forwarded(host: dict, via: dict | None = None) -> dict:
    return {"kind": "decrypt", "by": {"kind": "forwarded", "host": host, "via": via}}


def batch(command: str, seconds: int = 600) -> dict:
    return {"kind": "batch", "command": command, "seconds": seconds}


GITHUB = login(named("github.com"))
GIT = sign("git")
CREATE = {"kind": "create"}
AGENIX = decrypt("agenix")
REKEY = batch("agenix rekey")


def pin(a_key: dict = FOX, request: dict = GITHUB, security_key: dict | None = DESK, tries: int | None = None) -> dict:
    mistake = None if tries is None else {"tries_left": tries}
    return {"name": "pin", "key": a_key, "request": request, "security_key": security_key, "mistake": mistake}


def load_pin(security_key: dict | None = DESK, tries: int | None = None) -> dict:
    mistake = None if tries is None else {"tries_left": tries}
    return {"name": "load-pin", "security_key": security_key, "mistake": mistake}


def touch(a_key: dict = FOX, request: dict = GITHUB, security_key: dict | None = DESK, again: bool = False) -> dict:
    return {
        "name": "touch",
        "key": a_key,
        "request": request,
        "security_key": security_key,
        "timeout_ms": 15000,
        "again": again,
    }


def signed(a_key: dict = FOX, request: dict = GITHUB) -> dict:
    return {"name": "signed", "key": a_key, "request": request}


def loaded(keys: list[dict], security_key: dict | None = DESK) -> dict:
    return {"name": "loaded", "security_key": security_key, "keys": keys}


def failed(reason: str, a_key: dict | None = FOX, security_key: dict | None = DESK, request: dict | None = None) -> dict:
    state = {"name": "failed", "key": a_key, "security_key": security_key, "reason": reason}
    if request is not None:
        state["request"] = request
    return state


def queued(count: int) -> list[dict]:
    keys = [OCTOPUS, SATELLITE, key("🦉", "night-shift"), key(None, "backup"), key("🐳", "containers")]
    return [{"key": a_key} for a_key in keys[:count]]


SEVEN = [FOX, OCTOPUS, SATELLITE, key(None, "deploy-staging"), key("🦉", "night-shift"), key("🐳", "containers"), key("🧪", "lab")]

# Every variant: its name, the state, the requests waiting behind it, and
# what to type into it. In the order of the sheets.
VARIANTS: list[tuple[str, dict, list[dict], str]] = [
    ("pin", pin(), [], ""),
    ("pin-typed", pin(), [], "12345"),
    ("pin-via-jump", pin(request=login(named("github.com"), named("jump"))), [], ""),
    ("pin-host-key", pin(request=login(JUMP_KEY)), [], ""),
    ("pin-unverified-host", pin(request=login(UNVERIFIED)), [], ""),
    ("pin-git", pin(request=GIT), [], ""),
    ("pin-sshsig-file", pin(request=sign("file")), [], ""),
    ("pin-unknown-request", pin(request={"kind": "unknown"}), [], ""),
    ("pin-no-emoji", pin(a_key=key(None, "deploy-prod")), [], ""),
    ("pin-long-label", pin(a_key=key("🦊", "infrastructure-deploy-production-eu-west-1")), [], ""),
    ("pin-queue-2", pin(), queued(2), ""),
    ("pin-queue-5", pin(), queued(5), ""),
    ("wrong-pin", pin(tries=6), [], ""),
    ("wrong-pin-1-left", pin(tries=1), [], ""),
    ("load-pin", load_pin(), [], ""),
    ("load-pin-wrong", load_pin(tries=7), [], ""),
    ("load-pin-unnamed", load_pin(security_key=None), [], ""),
    ("touch", touch(), [], ""),
    ("touch-again", touch(again=True), [], ""),
    ("touch-unnamed-yubikey", touch(security_key=SERIAL), [], ""),
    ("touch-other-security-key", touch(security_key=None), [], ""),
    ("touch-long-name", touch(security_key={"name": "Office YubiKey 5C NFC (backup, drawer)"}), [], ""),
    ("select", {"name": "select", "key": FOX, "devices": 3, "timeout_ms": 30000}, [], ""),
    ("select-load", {"name": "select", "key": None, "devices": 2, "timeout_ms": 30000}, [], ""),
    ("pair", {"name": "pair", "security_key": DESK, "timeout_ms": 15000}, [], ""),
    ("pair-unnamed", {"name": "pair", "security_key": None, "timeout_ms": 15000}, [], ""),
    ("signed", signed(), [], ""),
    ("signed-git", signed(request=GIT), [], ""),
    ("loaded-1", loaded([FOX]), [], ""),
    ("loaded-3", loaded([FOX, OCTOPUS, SATELLITE]), [], ""),
    ("loaded-7", loaded(SEVEN), [], ""),
    ("loaded-unnamed", loaded([FOX, OCTOPUS], security_key=None), [], ""),
    ("no-key-known", {"name": "no-key", "key": FOX, "security_key": DESK}, [], ""),
    ("no-key-unknown", {"name": "no-key", "key": FOX, "security_key": None}, [], ""),
    ("no-key-loading", {"name": "no-key", "key": None, "security_key": None}, [], ""),
    ("wrong-key", {"name": "wrong-key", "key": FOX, "security_key": DESK, "other": NANO}, [], ""),
    ("wrong-key-other-unnamed", {"name": "wrong-key", "key": FOX, "security_key": DESK, "other": None}, [], ""),
    ("replug", {"name": "replug", "key": FOX, "security_key": DESK, "tries_left": 5}, [], ""),
    ("replug-tries-unknown", {"name": "replug", "key": FOX, "security_key": DESK, "tries_left": None}, [], ""),
    ("locked", {"name": "locked", "key": FOX, "security_key": DESK}, [], ""),
    ("new-pin", {"name": "new-pin", "key": FOX, "security_key": DESK}, [], ""),
    ("timeout", {"name": "timeout", "key": FOX, "security_key": DESK}, [], ""),
    ("failed-unplugged", failed("unplugged"), [], ""),
    ("failed-unplugged-loading", failed("unplugged", a_key=None), [], ""),
    ("failed-refused", failed("refused"), [], ""),
    ("failed-not-on-key", failed("not-on-key"), [], ""),
    ("failed-no-pin", failed("no-pin"), [], ""),
    ("failed-not-plugged-in", failed("not-plugged-in"), [], ""),
    ("failed-not-plugged-in-unknown", failed("not-plugged-in", security_key=None), [], ""),
    ("failed-duplicate", failed("duplicate"), [], ""),
    ("failed-unrecognized", failed("unrecognized"), [], ""),
    ("failed-other", failed("other"), [], ""),
    # age: decrypting a file, for a program here or a host elsewhere.
    ("decrypt-pin", pin(IDENTITY, AGENIX), [], ""),
    ("decrypt-pin-unknown-program", pin(IDENTITY, decrypt(None)), [], ""),
    ("decrypt-pin-forwarded", pin(IDENTITY, forwarded(JUMP_KEY)), [], ""),
    ("decrypt-pin-forwarded-via", pin(IDENTITY, forwarded(TARGET_KEY, JUMP_KEY)), [], ""),
    ("decrypt-pin-unverified", pin(IDENTITY, forwarded(UNVERIFIED)), [], ""),
    ("decrypt-touch", touch(IDENTITY, AGENIX), [], ""),
    ("decrypt-touch-forwarded", touch(IDENTITY, forwarded(JUMP_KEY)), [], ""),
    ("decrypt-touch-again", touch(IDENTITY, AGENIX, again=True), [], ""),
    ("decrypted", signed(IDENTITY, AGENIX), [], ""),
    # A batch: named with the PIN and with every touch.
    ("batch-pin", pin(IDENTITY, REKEY), [], ""),
    ("batch-touch", touch(IDENTITY, REKEY), [], ""),
    ("batch-touch-again", touch(IDENTITY, REKEY, again=True), [], ""),
    ("batch-long-command", touch(IDENTITY, batch("nix run .#deploy -- --all-hosts --rekey", 90)), [], ""),
    ("batch-started", signed(IDENTITY, REKEY), [], ""),
    # A new identity: the PIN, then two touches.
    ("create-pin", pin(NEW_IDENTITY, CREATE), [], ""),
    ("create-touch", touch(NEW_IDENTITY, CREATE), [], ""),
    ("create-touch-again", touch(NEW_IDENTITY, CREATE, again=True), [], ""),
    ("created", signed(NEW_IDENTITY, CREATE), [], ""),
    # What goes wrong, in the words of what was asked.
    ("decrypt-timeout", {"name": "timeout", "key": IDENTITY, "security_key": DESK}, [], ""),
    ("decrypt-failed-unplugged", failed("unplugged", IDENTITY, request=AGENIX), [], ""),
    ("decrypt-failed-not-on-key", failed("not-on-key", IDENTITY, request=AGENIX), [], ""),
    ("decrypt-failed-not-for-identity", failed("not-for-identity", IDENTITY, request=AGENIX), [], ""),
    ("decrypt-failed-another-identity", failed("another-identity", IDENTITY, request=AGENIX), [], ""),
    ("batch-failed-refused", failed("refused", IDENTITY, request=REKEY), [], ""),
    ("create-failed-unplugged", failed("unplugged", NEW_IDENTITY, request=CREATE), [], ""),
]

# The README's picture, two rows of four. The first row: variants in the
# presets, light and dark in turn.
README_ROW = [
    ("load-pin", "light"),
    ("touch", "dark"),
    ("wrong-key", "light"),
    ("loaded-3", "dark"),
]

# The styled row under it: a configuration, light or dark, and the screen to
# show. Eight different screens in all, and no two of a kind above each
# other.
STYLED = [
    ("catppuccin-mocha", "dark", "batch-touch"),
    ("solarized-light", "light", "queue"),
    ("gruvbox-dark", "dark", "done"),
    ("terminal", "dark", "wrong-pin"),
]

# Between the popups of the README's picture, in the pixels of the shots.
GAP = 48

# ------------------------------------------------------------- the drawing

shot_number = 0


def shoot(path: str, command: str, typed: str = "") -> None:
    """Runs the popup with `command`, lets it settle, and saves its square."""
    global shot_number
    shot_number += 1
    unit = f"popup-{shot_number}"
    machine.succeed(
        f"systemd-run --unit {unit} --uid alice --setenv XDG_RUNTIME_DIR={RUNTIME}"
        f" --setenv WAYLAND_DISPLAY={display} --setenv SKAGENT_PINENTRY_LOG=skagent_pinentry=debug"
        f" --setenv PATH=/run/current-system/sw/bin /bin/sh -c {shlex.quote(command)}"
    )
    machine.wait_until_succeeds(f"journalctl -u {unit} -o cat | grep -F 'opened a layer-shell overlay' >/dev/null", timeout=60)
    # The intro and the crossfade.
    machine.sleep(2)
    if typed:
        # wtype uploads a keymap first; a Shift press and a pause let the
        # popup take it in before the keys that count.
        on_display(f"wtype -k Shift_L -s 300 {typed}")
        machine.sleep(1)
    on_display(f"grim -g '{REGION}' {path}")
    machine.succeed(f"systemctl stop {unit}")
    said = machine.succeed(f"journalctl -u {unit} -o cat")
    assert "skipped a setting" not in said and "the agent sent something else" not in said, said


def in_protocol(theme: str, state: dict, waiting: list[dict]) -> str:
    """The popup as the agent runs it, shown `state`."""
    message = {"type": "show", "seq": 1, "waiting": waiting, "state": state}
    machine.succeed(f"cat > {SHOTS}/input <<'EOF'\n{json.dumps(message, ensure_ascii=False)}\nEOF")
    return f"(cat {SHOTS}/input; sleep 600) | {PINENTRY} --theme {theme}"


def cut_out(raw: str, final: str) -> None:
    """The popup alone, on nothing: where the black behind it showed through, it goes, and the colours it dimmed get their own back."""
    mask = f"{SHOTS}/alpha.png"
    machine.succeed(
        f"magick {raw} {mask} -alpha off -compose CopyAlpha -composite -alpha disassociate"
        f" '(' {mask} -alpha off ')' -compose CopyAlpha -composite -strip PNG32:{final}"
    )


machine.wait_for_unit("multi-user.target")
machine.succeed(f"install -d -m 0700 -o alice -g users {RUNTIME} {SHOTS}")
machine.succeed(
    f"systemd-run --unit sway --uid alice --setenv XDG_RUNTIME_DIR={RUNTIME}"
    " --setenv WLR_BACKENDS=headless --setenv WLR_RENDERER=pixman"
    " --setenv WLR_HEADLESS_OUTPUTS=1 --setenv WLR_LIBINPUT_NO_DEVICES=1"
    f" --setenv PATH=/run/current-system/sw/bin {SWAY} --config {SWAY_CONFIG}"
)
machine.wait_until_succeeds(f"ls {RUNTIME} | grep -E '^wayland-[0-9]+$'", timeout=30)
display = machine.succeed(f"ls {RUNTIME} | grep -E '^wayland-[0-9]+$' | head -1").strip()
machine.wait_until_succeeds(f"ls {RUNTIME}/sway-ipc.*.sock", timeout=30)

with subtest("the popup's outline: one still screen on black and on white"):
    # What differs between the two is what shows through: the corners.
    locked = {"name": "locked", "key": FOX, "security_key": DESK}
    for colour, name in [("#ffffff", "white"), ("#000000", "black")]:
        backdrop(colour)
        shoot(f"{SHOTS}/on-{name}.png", in_protocol("light", locked, []))
    machine.succeed(
        f"magick {SHOTS}/on-white.png {SHOTS}/on-black.png -compose difference -composite"
        f" -colorspace Gray -negate {SHOTS}/alpha.png"
    )
    # Nothing of the popup in the corner, nothing behind it in the middle.
    corner, inside = machine.succeed(
        f"magick {SHOTS}/alpha.png -format '%[fx:p{{0,0}}.r] ' -write info: -gravity center -crop 600x600+0+0"
        " -format '%[fx:minima]' info:"
    ).split()
    assert float(corner) < 0.01 and float(inside) > 0.99, (corner, inside)

with subtest("every state, light and dark"):
    for theme in ["light", "dark"]:
        machine.succeed(f"install -d -o alice -g users {SHOTS}/raw-{theme} {SHOTS}/matrix/{theme}")
        for name, state, waiting, typed in VARIANTS:
            raw = f"{SHOTS}/raw-{theme}/{name}.png"
            shoot(raw, in_protocol(theme, state, waiting), typed)
            cut_out(raw, f"{SHOTS}/matrix/{theme}/{name}.png")

with subtest("styled: a configuration each, as --preview shows it"):
    machine.succeed(f"install -d -o alice -g users {SHOTS}/raw-styled {SHOTS}/styled")
    for style, theme, screen in STYLED:
        raw = f"{SHOTS}/raw-styled/{style}.png"
        shoot(raw, f"{PINENTRY} --preview {screen} --theme {theme} --config {THEMES[style]}")
        cut_out(raw, f"{SHOTS}/styled/{style}.png")

with subtest("the sheets and the README's picture"):
    machine.succeed(f"install -d {SHOTS}/readme")
    for theme in ["light", "dark"]:
        files = " ".join(f"{SHOTS}/matrix/{theme}/{name}.png" for name, _, _, _ in VARIANTS)
        machine.succeed(
            f"magick montage -background '{PAGE[theme]}' -fill '{INK[theme]}' -font {LABEL_FONT} -pointsize 20"
            f" -label '%t' {files} -tile 8x -geometry 360x360+20+14 -strip {SHOTS}/matrix/sheet-{theme}.png"
        )
    presets = " ".join(f"{SHOTS}/matrix/{theme}/{name}.png" for name, theme in README_ROW)
    styled = " ".join(f"{SHOTS}/styled/{style}.png" for style, _, _ in STYLED)
    machine.succeed(
        f"magick '(' {presets} -background none +smush {GAP} ')' '(' {styled} -background none +smush {GAP} ')'"
        f" -background none -smush {GAP} -strip {SHOTS}/readme/skagent-popup.png"
    )

machine.succeed(f"tar -C {SHOTS} -cf /tmp/screenshots.tar matrix styled readme")
machine.copy_from_machine("/tmp/screenshots.tar")
with tarfile.open(machine.out_dir / "screenshots.tar") as archive:
    archive.extractall(machine.out_dir, filter="data")
(machine.out_dir / "screenshots.tar").unlink()
