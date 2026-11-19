# skagent-pinentry with the agent, end to end: a headless sway, the real
# popup as a layer-shell overlay, a virtual key, and the PIN typed on a
# virtual keyboard. Screenshots of the steps land in the test's output
# (result/*.png) for review.
{
  pkgs,
  package,
  pinentry,
  testkey,
}:
let
  common = import ./common.nix { inherit pkgs; };
  pin = "246810";
  dir = "/run/skagent-alice";
  socket = "${dir}/agent.sock";
  # alice's XDG_RUNTIME_DIR for sway and everything talking to it.
  runtime = "/run/alice-wayland";
  touchFile = "/run/testkey-touch";
  # 500 × 500 logical pixels: the 360 px popup sits centred at 70,70.
  swayConfig = pkgs.writeText "sway.conf" ''
    output HEADLESS-1 resolution 1000x1000 scale 2
    default_border none
    xwayland disable
  '';
in
pkgs.testers.runNixOSTest {
  name = "skagent-pinentry";

  nodes.machine = {
    imports = [ common.virtualKeyMachine ];
    environment.systemPackages = [
      package
      testkey
      common.makeSkStub
      common.testAskpass
      pkgs.grim
      pkgs.imagemagick
      pkgs.libfido2
      pkgs.openssh
      pkgs.wtype
    ];
    # Mesa's software renderers for GPUI (Vulkan or GL) and the system's
    # colour emoji font, as on a desktop.
    hardware.graphics.enable = true;
    fonts.packages = [ pkgs.noto-fonts-color-emoji ];
    security.polkit.enable = true;
    users.users.alice.isNormalUser = true;
    virtualisation.memorySize = 2048;
  };

  testScript = ''
    import re
    import shlex
    import time
    from typing import Callable

    def alice(command: str) -> tuple[int, str]:
        return machine.execute(f"su - alice -c {shlex.quote(command)} 2>&1")

    def alice_ok(command: str) -> str:
        status, out = alice(command)
        assert status == 0, f"{command!r} exited {status}: {out}"
        return out

    def journal(unit: str) -> str:
        return machine.succeed(f"journalctl -u {unit} --no-pager -o cat")

    def messages(unit: str) -> str:
        # The journal without the time of day: its microseconds are six
        # digits, and now and then they spell a PIN.
        return re.sub(r"T\d\d:\d\d:\d\d\.\d+Z", "", journal(unit))

    def popup_lines() -> list[str]:
        """What the popup logged (to the agent's stderr)."""
        return [line for line in journal("skagent").splitlines() if "skagent_pinentry" in line]

    def states(since: int) -> list[str]:
        shown = [re.search(r'showing seq=\d+ state="([a-z-]+)"', line) for line in popup_lines()[since:]]
        return [match.group(1) for match in shown if match]

    def logged(since: int, text: str) -> bool:
        return any(text in line for line in popup_lines()[since:])

    def wait_for(condition: Callable[[], bool], timeout: int = 30) -> None:
        """Retries `condition`, with the agent's log when it gives up."""

        def check(last_try: bool) -> bool:
            done = condition()
            if last_try and not done:
                print(journal("skagent"))
            return done

        retry(check, timeout_seconds=timeout)

    def wait_for_state(since: int, name: str, count: int = 1) -> None:
        wait_for(lambda: states(since).count(name) >= count)

    def popup_running() -> bool:
        # By the name the process list has: its first 15 bytes.
        return machine.execute("pgrep -u alice -x skagent-pinentr")[0] == 0

    def closed() -> None:
        retry(lambda _last_try: not popup_running(), timeout_seconds=15)

    def touch() -> None:
        machine.succeed("touch ${touchFile}")

    def tries() -> str:
        device = machine.succeed("fido2-token -L | grep -F 'pinentry key' | cut -d: -f1").strip()
        return machine.succeed(f"fido2-token -I {device}")

    def start_sign(unit: str, key: str = "id_sk.pub") -> None:
        alice_ok(f"echo {unit} > ~/{unit}")
        machine.succeed(
            f"systemd-run --unit {unit} --uid alice --setenv SSH_AUTH_SOCK=${socket}"
            f" ${pkgs.openssh}/bin/ssh-keygen -Y sign -f /home/alice/{key} -n git /home/alice/{unit}"
        )

    def finished(unit: str, success: bool = True) -> None:
        machine.wait_until_succeeds(
            f"systemctl show {unit} -p ActiveState --value | grep -E '^(inactive|failed)$' >/dev/null", timeout=60
        )
        status = machine.succeed(f"systemctl show {unit} -p ExecMainStatus --value").strip()
        assert (status == "0") == success, (unit, status, journal("skagent"))

    def on_display(command: str) -> str:
        return alice_ok(f"XDG_RUNTIME_DIR=${runtime} WAYLAND_DISPLAY={display} {command}")

    def type_keys(arguments: str) -> None:
        # wtype uploads a keymap first; a Shift press and a pause let the
        # client take it in before the keys that count. Without the pause a
        # busy machine decoded a PIN with the old keymap: a wrong PIN.
        on_display(f"wtype -k Shift_L -s 300 {arguments}")

    def screenshot(name: str) -> float:
        """Saves the popup's square, returns its mean brightness (0 to 1)."""
        path = f"/tmp/shots/{name}.png"
        on_display(f"grim -g '70,70 360x360' {path}")
        machine.copy_from_machine(path)
        return float(machine.succeed(f"magick {path} -colorspace Gray -format '%[fx:mean]' info:"))

    def settle() -> None:
        """Lets the crossfade and intro animations end before a screenshot."""
        machine.sleep(2)

    machine.wait_for_unit("multi-user.target")
    machine.succeed(
        "systemd-run --unit testkey --setenv SKAGENT_TESTKEY_PIN=${pin}"
        " ${testkey}/bin/skagent-testkey --touch file --touch-file ${touchFile}"
        " --name 'pinentry key' --serial 12345678"
    )
    machine.wait_until_succeeds("fido2-token -L | grep -F 'pinentry key' >/dev/null")

    with subtest("set up a key, a compositor and the agent with the popup"):
        touch()
        alice_ok(
            "SSH_ASKPASS=test-askpass SSH_ASKPASS_REQUIRE=force SKAGENT_TEST_ANSWER=${pin}"
            " ssh-keygen -q -t ed25519-sk -O resident -O verify-required -O application=ssh:example"
            " -N ''' -C alice@virtual -f ~/id_sk"
        )
        alice_ok("echo \"alice $(cat ~/id_sk.pub)\" > ~/allowed")
        machine.succeed("install -d -m 0700 -o alice -g users ${dir} ${runtime} /tmp/shots")
        fingerprint = alice_ok("ssh-keygen -lf ~/id_sk.pub").split()[1]
        alice_ok(
            f"printf '[keys.\"%s\"]\\nemoji = \"🦊\"\\nlabel = \"github-work\"\\n"
            f"[security-keys.12345678]\\nname = \"Desk 5C NFC\"\\n' '{fingerprint}' > ${dir}/config.toml"
        )
        machine.succeed(
            "systemd-run --unit sway --uid alice --setenv XDG_RUNTIME_DIR=${runtime}"
            " --setenv WLR_BACKENDS=headless --setenv WLR_RENDERER=pixman"
            " --setenv WLR_HEADLESS_OUTPUTS=1 --setenv WLR_LIBINPUT_NO_DEVICES=1"
            # Unwrapped: the wrapper starts a dbus-daemon, which isn't there.
            " ${pkgs.sway-unwrapped}/bin/sway --config ${swayConfig}"
        )
        machine.wait_until_succeeds("ls ${runtime} | grep -E '^wayland-[0-9]+$'", timeout=30)
        display = machine.succeed("ls ${runtime} | grep -E '^wayland-[0-9]+$' | head -1").strip()
        machine.succeed(
            f"systemd-run --unit skagent --uid alice --setenv XDG_RUNTIME_DIR=${runtime}"
            f" --setenv WAYLAND_DISPLAY={display} --setenv SKAGENT_PINENTRY_LOG=skagent_pinentry=debug"
            " ${package}/bin/skagent serve --log skagent=debug --socket ${socket}"
            " --config ${dir}/config.toml --popup ${pinentry}/bin/skagent-pinentry"
        )
        machine.wait_for_file("${socket}")
        alice_ok("SSH_AUTH_SOCK=${socket} ssh-add ~/id_sk")
        assert screenshot("before") < 0.2, "the empty output isn't dark"

    with subtest("a signature goes through the popup: PIN, touch, pairing declined, signed"):
        mark = len(popup_lines())
        start_sign("first")
        wait_for_state(mark, "pin")
        wait_for(lambda: logged(mark, "opened a layer-shell overlay"))
        settle()
        assert screenshot("pin") > 0.8, "the popup isn't showing"
        # The process the PIN is typed into is hardened like the agent: no
        # core file, and not even the same user reads its memory.
        popup_pid = machine.succeed("pgrep -u alice -x skagent-pinentr").strip()
        machine.succeed(f"grep -E '^Max core file size +0 +0 ' /proc/{popup_pid}/limits")
        status, _ = alice(f"cat /proc/{popup_pid}/environ")
        assert status != 0, "alice could read the popup's environment"
        type_keys("${pin} -k Return")
        wait_for_state(mark, "touch")
        settle()
        assert screenshot("touch") > 0.8, "the popup isn't showing"
        touch()
        # The first signature on the key offers to pair; Escape declines.
        wait_for_state(mark, "pair")
        settle()
        assert screenshot("pair") > 0.8, "the popup isn't showing"
        type_keys("-k Escape")
        # "signed" shows for 900 ms, too short to catch on a screenshot.
        wait_for_state(mark, "signed")
        finished("first")
        closed()
        assert states(mark) == ["pin", "touch", "pair", "signed"], states(mark)
        assert logged(mark, "cancelled seq="), popup_lines()
        assert "pairing declined in the popup" in journal("skagent")
        out = alice_ok("ssh-keygen -Y verify -f ~/allowed -I alice -n git -s ~/first.sig < ~/first")
        assert "Good" in out, out
        assert "${pin}" not in messages("skagent"), "the PIN was logged"

    with subtest("a wrong PIN is asked for again"):
        alice_ok("skagent forget --socket ${socket}")
        mark = len(popup_lines())
        start_sign("wrong")
        wait_for_state(mark, "pin")
        settle()
        type_keys("000000 -k Return")
        wait_for_state(mark, "pin", count=2)
        time.sleep(0.5)
        screenshot("wrong-pin")
        type_keys("${pin} -k Return")
        wait_for_state(mark, "touch")
        touch()
        finished("wrong")
        closed()
        assert states(mark) == ["pin", "pin", "touch", "signed"], states(mark)
        assert "pin retries: 8" in tries(), "the right PIN didn't reset the counter"

    with subtest("Escape cancels without sending a PIN"):
        alice_ok("skagent forget --socket ${socket}")
        mark = len(popup_lines())
        start_sign("cancelled")
        wait_for_state(mark, "pin")
        settle()
        type_keys("1357 -k Escape")
        finished("cancelled", success=False)
        closed()
        assert states(mark) == ["pin"], states(mark)
        assert logged(mark, "cancelled seq="), popup_lines()
        assert not logged(mark, "sent the PIN"), popup_lines()
        assert "cancelled in the popup" in journal("skagent")
        assert "pin retries: 8" in tries()

    with subtest("a failure stays to be read, and the popup leaves by itself"):
        # A key the security key doesn't hold: the PIN is right, and the key
        # says that it has no such credential.
        alice_ok("make-sk-stub ~/missing 9 'not on the key'")
        alice_ok("SSH_AUTH_SOCK=${socket} ssh-add ~/missing")
        alice_ok("SSH_AUTH_SOCK=${socket} ssh-add -L | grep -F 'not on the key' > ~/missing.pub")
        mark = len(popup_lines())
        start_sign("missing", "missing.pub")
        wait_for_state(mark, "pin")
        settle()
        type_keys("${pin} -k Return")
        wait_for_state(mark, "failed")
        # The agent closed its input when it showed the failure, which stays
        # for five seconds. The popup goes then; the agent doesn't kill it.
        assert popup_running(), "the failure was gone before it could be read"
        settle()
        assert screenshot("failed") > 0.8, "the popup isn't showing"
        finished("missing", success=False)
        closed()
        assert (states(mark)[0], states(mark)[-1]) == ("pin", "failed"), states(mark)
        assert "the popup didn't exit after its last request" not in journal("skagent")
        alice_ok("SSH_AUTH_SOCK=${socket} ssh-add -d ~/missing.pub")

    with subtest("the popup takes colours, size and fonts from [popup]"):
        machine.succeed("systemctl stop skagent")
        machine.wait_until_fails("test -e ${socket}")
        alice_ok(
            "printf '[popup]\\nappearance = \"dark\"\\nscale = 1.25\\nfont = \"Comic Neue\"\\n"
            "[popup.dark]\\nsurface = \"#2e3440\"\\naccent = \"#88c0d0\"\\n' >> ${dir}/config.toml"
        )
        machine.succeed(
            f"systemd-run --unit skagent --uid alice --setenv XDG_RUNTIME_DIR=${runtime}"
            f" --setenv WAYLAND_DISPLAY={display} --setenv SKAGENT_PINENTRY_LOG=skagent_pinentry=debug"
            " ${package}/bin/skagent serve --log skagent=debug --socket ${socket}"
            " --config ${dir}/config.toml --popup ${pinentry}/bin/skagent-pinentry"
        )
        machine.wait_for_file("${socket}")
        mark = len(popup_lines())
        start_sign("styled")
        wait_for_state(mark, "pin")
        settle()
        # 450 px instead of 360, centred: the card's top edge, between the
        # border and the anchor, is where a 360 px popup has no window.
        path = "/tmp/shots/styled.png"
        on_display(f"grim -g '25,25 450x450' {path}")
        machine.copy_from_machine(path)
        top = machine.succeed(
            f"magick {path} -crop 200x20+350+20 +repage -scale '1x1!' -format '%[hex:p{{0,0}}]' info:"
        ).strip()
        assert top == "2E3440", top
        assert logged(mark, 'font="Comic Neue" instead="Inter"'), popup_lines()
        type_keys("-k Escape")
        finished("styled", success=False)
        closed()
  '';
}
