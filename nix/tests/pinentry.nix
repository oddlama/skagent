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
        return machine.execute("pgrep -u alice -x skagent-pinentry")[0] == 0

    def closed() -> None:
        retry(lambda _last_try: not popup_running(), timeout_seconds=15)

    def touch() -> None:
        machine.succeed("touch ${touchFile}")

    def tries() -> str:
        device = machine.succeed("fido2-token -L | grep -F 'pinentry key' | cut -d: -f1").strip()
        return machine.succeed(f"fido2-token -I {device}")

    def start_sign(unit: str) -> None:
        alice_ok(f"echo {unit} > ~/{unit}")
        machine.succeed(
            f"systemd-run --unit {unit} --uid alice --setenv SSH_AUTH_SOCK=${socket}"
            f" ${pkgs.openssh}/bin/ssh-keygen -Y sign -f /home/alice/id_sk.pub -n git /home/alice/{unit}"
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
        # wtype uploads a keymap first; a Shift press lets the client take
        # it in before the keys that count.
        on_display(f"wtype -k Shift_L {arguments}")

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
        assert "${pin}" not in journal("skagent"), "the PIN was logged"

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
  '';
}
