# skagent's own popup (--popup), end to end with a fake popup that records
# every state it is shown and answers like a user (fake-popup.py): one popup
# per request, PIN retries in place, cancelling, queued requests.
{
  pkgs,
  package,
  testkey,
}:
let
  common = import ./common.nix { inherit pkgs; };
  pin = "246810";
  dir = "/run/skagent-alice";
  socket = "${dir}/agent.sock";
  touchFile = "/run/testkey-touch";
  otherTouchFile = "/run/testkey-other-touch";
  # While these exist, the test keys are unplugged (skagent-testkey --unplugged-file).
  unpluggedFile = "/run/testkey-unplugged";
  otherUnpluggedFile = "/run/testkey-other-unplugged";
  popupLog = "${dir}/log";
  agent =
    unit: popup:
    "systemd-run --unit ${unit} --uid alice --setenv SKAGENT_TEST_POPUP_DIR=${dir}"
    + " ${package}/bin/skagent serve --log skagent=debug --socket ${socket}"
    + " --config ${dir}/config.toml --plug-in-timeout 20s --popup ${popup}";
in
pkgs.testers.runNixOSTest {
  name = "skagent-popup";

  nodes.machine = {
    imports = [ common.virtualKeyMachine ];
    environment.systemPackages = [
      package
      testkey
      common.fakePopup
      common.testAskpass
      pkgs.libfido2
      pkgs.openssh
    ];
    security.polkit.enable = true;
    users.users.alice.isNormalUser = true;
  };

  testScript = ''
    import json
    import shlex
    import time

    def alice(command: str) -> tuple[int, str]:
        return machine.execute(f"su - alice -c {shlex.quote(command)} 2>&1")

    def alice_ok(command: str) -> str:
        status, out = alice(command)
        assert status == 0, f"{command!r} exited {status}: {out}"
        return out

    def journal(unit: str) -> str:
        return machine.succeed(f"journalctl -u {unit} --no-pager -o cat")

    def touches(operation: str = "") -> int:
        return journal("testkey").count(f'touch requested operation="{operation}' if operation else "touch requested")

    def touch() -> None:
        machine.succeed("touch ${touchFile}")

    def tries() -> str:
        device = machine.succeed("fido2-token -L | grep -F 'popup key' | cut -d: -f1").strip()
        return machine.succeed(f"fido2-token -I {device}")

    def popup_log() -> list[str]:
        return machine.succeed("cat ${popupLog} 2>/dev/null || true").splitlines()

    def shown(since: int) -> list[dict]:
        """The states shown since the log had `since` lines."""
        lines = popup_log()[since:]
        messages = [json.loads(line) for line in lines if line.startswith("{")]
        return [message["state"] for message in messages if message["type"] == "show"]

    def names(since: int) -> list[str]:
        return [state["name"] for state in shown(since)]

    def queued(since: int) -> list[list[dict]]:
        """The waiting requests in every queue message since `since`."""
        lines = popup_log()[since:]
        messages = [json.loads(line) for line in lines if line.startswith("{")]
        return [message["waiting"] for message in messages if message["type"] == "queue"]

    def closed() -> None:
        """Waits until the popup exited after its last request."""
        retry(lambda _last_try: popup_log()[-1:] == ["exit"], timeout_seconds=10)

    def sign(message: str = "msg") -> tuple[int, str]:
        return alice(f"rm -f ~/{message}.sig && SSH_AUTH_SOCK=${socket} ssh-keygen -Y sign -f ~/id_sk.pub -n test ~/{message}")

    def sign_ok() -> None:
        status, out = sign()
        assert status == 0, f"signing failed: {out}"
        out = alice_ok("ssh-keygen -Y verify -f ~/allowed -I alice -n test -s ~/msg.sig < ~/msg")
        assert "Good" in out, out

    def start_sign(unit: str) -> None:
        alice_ok(f"echo {unit} > ~/{unit}")
        machine.succeed(
            f"systemd-run --unit {unit} --uid alice --setenv SSH_AUTH_SOCK=${socket}"
            f" ${pkgs.openssh}/bin/ssh-keygen -Y sign -f /home/alice/id_sk.pub -n test /home/alice/{unit}"
        )

    def unplug(name: str, flag: str) -> None:
        machine.succeed(f"touch {flag}")
        machine.wait_until_fails(f"fido2-token -L | grep -F '{name}' >/dev/null", timeout=10)

    def plug_in(name: str, flag: str) -> None:
        machine.succeed(f"rm -f {flag}")
        machine.wait_until_succeeds(f"fido2-token -L | grep -F '{name}' >/dev/null", timeout=10)

    def finished(unit: str, success: bool = True) -> None:
        machine.wait_until_succeeds(f"systemctl show {unit} -p ActiveState --value | grep -E '^(inactive|failed)$' >/dev/null")
        status = machine.succeed(f"systemctl show {unit} -p ExecMainStatus --value").strip()
        assert (status == "0") == success, (unit, status, journal("skagent"))

    machine.wait_for_unit("multi-user.target")
    machine.succeed(
        "systemd-run --unit testkey --setenv SKAGENT_TESTKEY_PIN=${pin}"
        " ${testkey}/bin/skagent-testkey --touch file --touch-file ${touchFile}"
        " --name 'popup key' --serial 12345678 --unplugged-file ${unpluggedFile}"
    )
    machine.wait_until_succeeds("fido2-token -L | grep -F 'popup key' >/dev/null")

    with subtest("set up a key, its names and the agent with a popup"):
        touch()
        alice_ok(
            "SSH_ASKPASS=test-askpass SSH_ASKPASS_REQUIRE=force SKAGENT_TEST_ANSWER=${pin}"
            " ssh-keygen -q -t ed25519-sk -O resident -O verify-required -O application=ssh:example"
            " -N ''' -C alice@virtual -f ~/id_sk"
        )
        alice_ok("echo \"alice $(cat ~/id_sk.pub)\" > ~/allowed && echo hello > ~/msg")
        machine.succeed("install -d -m 0700 -o alice -g users ${dir}")
        alice_ok("umask 077 && echo ${pin} > ${dir}/pin")
        fingerprint = alice_ok("ssh-keygen -lf ~/id_sk.pub").split()[1]
        alice_ok(
            f"printf '[keys.\"%s\"]\\nemoji = \"🦊\"\\nlabel = \"github-work\"\\n"
            f"[security-keys.12345678]\\nname = \"Desk 5C NFC\"\\n' '{fingerprint}' > ${dir}/config.toml"
        )
        machine.succeed("${agent "skagent" "/run/current-system/sw/bin/fake-popup"}")
        machine.wait_for_file("${socket}")
        retry(lambda _last_try: "machine sleeps (logind)" in journal("skagent"), timeout_seconds=10)
        alice_ok("SSH_AUTH_SOCK=${socket} ssh-add ~/id_sk")

    with subtest("a first signature shows PIN, touch and the result in one popup"):
        mark = len(popup_log())
        touch()
        sign_ok()
        closed()
        assert names(mark) == ["pin", "touch", "signed"], names(mark)
        pin_state, touch_state, _ = shown(mark)
        assert pin_state["key"] == {"emoji": "🦊", "label": "github-work", "fingerprint": fingerprint}, pin_state
        assert pin_state["request"] == {"kind": "sign", "namespace": "test"}, pin_state
        assert pin_state["security_key"] == {"name": "Desk 5C NFC"}, pin_state
        assert pin_state["mistake"] is None, pin_state
        assert touch_state["again"] is False and touch_state["timeout_ms"] > 0, touch_state
        assert popup_log()[mark:].count("start") == 1

    with subtest("a cached PIN goes straight to the touch"):
        mark = len(popup_log())
        touch()
        sign_ok()
        closed()
        assert names(mark) == ["touch", "signed"], names(mark)

    with subtest("a wrong PIN is asked for again in the same popup"):
        alice_ok("skagent forget --socket ${socket}")
        alice_ok("echo 000000 > ${dir}/answers")
        mark = len(popup_log())
        touch()
        sign_ok()
        closed()
        assert names(mark) == ["pin", "pin", "touch", "signed"], names(mark)
        first, again = shown(mark)[:2]
        assert first["mistake"] is None and again["mistake"] == {"tries_left": 7}, (first, again)
        assert popup_log()[mark:].count("start") == 1
        assert "pin retries: 8" in tries(), "the right PIN didn't reset the counter"

    with subtest("cancelling the PIN prompt sends no PIN and shows no result"):
        alice_ok("skagent forget --socket ${socket}")
        alice_ok("touch ${dir}/cancel-pin")
        mark = len(popup_log())
        status, out = sign()
        assert status != 0, out
        closed()
        assert names(mark) == ["pin"], names(mark)
        assert "cancelled in the popup" in journal("skagent")
        assert "pin retries: 8" in tries()
        alice_ok("rm ${dir}/cancel-pin")

    with subtest("cancelling during the touch stops the key and keeps the PIN"):
        touch()
        sign_ok()
        closed()
        alice_ok("touch ${dir}/cancel-touch")
        cancelled = journal("testkey").count("outcome=Cancelled")
        mark = len(popup_log())
        status, out = sign()
        assert status != 0, out
        closed()
        assert names(mark) == ["touch"], names(mark)
        retry(lambda _last_try: journal("testkey").count("outcome=Cancelled") == cancelled + 1, timeout_seconds=5)
        alice_ok("rm ${dir}/cancel-touch")
        mark = len(popup_log())
        touch()
        sign_ok()
        closed()
        assert names(mark) == ["touch", "signed"], "the PIN was dropped"

    with subtest("requests wait for the popup and reuse it"):
        mark = len(popup_log())
        requested = touches()
        start_sign("queued-one")
        retry(lambda _last_try: touches() == requested + 1, timeout_seconds=10)
        start_sign("queued-two")
        retry(lambda _last_try: [1] == [len(waiting) for waiting in queued(mark)][:1], timeout_seconds=10)
        assert queued(mark)[0][0]["key"]["label"] == "github-work", queued(mark)
        touch()
        retry(lambda _last_try: touches() == requested + 2, timeout_seconds=10)
        touch()
        finished("queued-one")
        finished("queued-two")
        closed()
        assert names(mark) == ["touch", "signed", "touch", "signed"], names(mark)
        assert popup_log()[mark:].count("start") == 1, "the popup was started again"
        assert popup_log()[mark:].count("exit") == 1, "the popup closed in between"

    with subtest("a touch timeout offers to try again with the PIN kept"):
        alice_ok("touch ${dir}/retry")
        mark = len(popup_log())
        requested = touches()
        start_sign("timed-out")
        # The test key gives up after 10 s without a touch.
        retry(lambda _last_try: "timeout" in names(mark), timeout_seconds=30)
        retry(lambda _last_try: touches() == requested + 2, timeout_seconds=10)
        touch()
        finished("timed-out")
        closed()
        assert names(mark) == ["touch", "timeout", "touch", "signed"], names(mark)
        assert shown(mark)[1]["security_key"] == {"name": "Desk 5C NFC"}, shown(mark)
        alice_ok("rm ${dir}/retry")

    with subtest("with two keys plugged in, the popup shows the selection, then a second touch"):
        machine.succeed(
            "systemd-run --unit other-key --setenv SKAGENT_TESTKEY_PIN=135790"
            " ${testkey}/bin/skagent-testkey --touch file --touch-file ${otherTouchFile} --name 'other key'"
            " --unplugged-file ${otherUnpluggedFile}"
        )
        machine.wait_until_succeeds("fido2-token -L | grep -F 'other key' >/dev/null")
        # Removing the key drops its binding (and PIN): it must be selected.
        alice_ok("SSH_AUTH_SOCK=${socket} ssh-add -d ~/id_sk && SSH_AUTH_SOCK=${socket} ssh-add ~/id_sk")
        mark = len(popup_log())
        selections, assertions = touches("select"), touches("getAssertion")
        start_sign("selected")
        retry(lambda _last_try: touches("select") == selections + 1, timeout_seconds=10)
        touch()
        retry(lambda _last_try: touches("getAssertion") == assertions + 1, timeout_seconds=10)
        touch()
        finished("selected")
        closed()
        assert names(mark) == ["select", "pin", "touch", "signed"], names(mark)
        select, _, touch_state, _ = shown(mark)
        assert select["devices"] == 2 and select["timeout_ms"] == 30000, select
        assert select["key"]["label"] == "github-work", select
        assert touch_state["again"] is True, touch_state

    with subtest("a replugged YubiKey is recognized by its serial, without a selection touch"):
        unplug("popup key", "${unpluggedFile}")
        plug_in("popup key", "${unpluggedFile}")
        mark = len(popup_log())
        selections = touches("select")
        touch()
        sign_ok()
        closed()
        # A new plug-in: its PIN is asked for again, but no key is selected.
        assert names(mark) == ["pin", "touch", "signed"], names(mark)
        assert touches("select") == selections, "selected by touch"
        assert shown(mark)[1]["again"] is False, shown(mark)

    with subtest("a request waits for its YubiKey, asking for it by name"):
        unplug("popup key", "${unpluggedFile}")
        mark = len(popup_log())
        start_sign("waiting")
        retry(lambda _last_try: "wrong-key" in names(mark), timeout_seconds=10)
        wrong = shown(mark)[0]
        assert wrong["security_key"] == {"name": "Desk 5C NFC"} and wrong["other"] is None, wrong
        assert wrong["key"]["label"] == "github-work", wrong
        unplug("other key", "${otherUnpluggedFile}")
        retry(lambda _last_try: "no-key" in names(mark), timeout_seconds=10)
        assert shown(mark)[1]["security_key"] == {"name": "Desk 5C NFC"}, shown(mark)
        touch()
        plug_in("popup key", "${unpluggedFile}")
        finished("waiting")
        closed()
        assert names(mark) == ["wrong-key", "no-key", "pin", "touch", "signed"], names(mark)
        plug_in("other key", "${otherUnpluggedFile}")

    with subtest("cancelling in the popup ends the wait"):
        unplug("popup key", "${unpluggedFile}")
        alice_ok("touch ${dir}/cancel-wait")
        mark = len(popup_log())
        status, out = sign()
        assert status != 0, out
        closed()
        assert names(mark) == ["wrong-key"], names(mark)
        alice_ok("rm ${dir}/cancel-wait")

    with subtest("a request gives up when its YubiKey isn't plugged in in time"):
        unplug("other key", "${otherUnpluggedFile}")
        mark = len(popup_log())
        started = time.monotonic()
        status, out = sign()
        waited = time.monotonic() - started
        assert status != 0, out
        assert 19 < waited < 30, f"waited {waited:.1f} s, not the 20 s plug-in timeout"
        closed()
        assert names(mark) == ["no-key", "failed"], names(mark)
        failed = shown(mark)[-1]
        assert failed["reason"] == "not-plugged-in", failed
        assert failed["security_key"] == {"name": "Desk 5C NFC"}, failed
        assert "the YubiKey with serial 12345678 wasn't plugged in" in journal("skagent")

    with subtest("the client hanging up ends the wait"):
        mark = len(popup_log())
        start_sign("hung-up")
        retry(lambda _last_try: "no-key" in names(mark), timeout_seconds=10)
        started = time.monotonic()
        machine.succeed("systemctl stop hung-up")
        closed()
        assert time.monotonic() - started < 10, "kept waiting after the client left"
        assert names(mark) == ["no-key"], names(mark)

    with subtest("which YubiKey holds a key is remembered across agent restarts"):
        remembered = alice_ok("cat ~/.local/state/skagent/bindings.toml")
        assert "serial = 12345678" in remembered, remembered
        assert alice_ok("stat -c %a ~/.local/state/skagent/bindings.toml").strip() == "600"
        machine.succeed("systemctl stop skagent")
        machine.wait_until_fails("test -e ${socket}")
        machine.succeed("${agent "skagent" "/run/current-system/sw/bin/fake-popup"}")
        machine.wait_for_file("${socket}")
        alice_ok("SSH_AUTH_SOCK=${socket} ssh-add ~/id_sk")
        mark = len(popup_log())
        start_sign("remembered")
        retry(lambda _last_try: "no-key" in names(mark), timeout_seconds=10)
        assert shown(mark)[0]["security_key"] == {"name": "Desk 5C NFC"}, shown(mark)
        touch()
        plug_in("popup key", "${unpluggedFile}")
        finished("remembered")
        closed()
        assert names(mark) == ["no-key", "pin", "touch", "signed"], names(mark)
        plug_in("other key", "${otherUnpluggedFile}")

    with subtest("a second key claiming the YubiKey's serial gets no PIN"):
        machine.succeed(
            "systemd-run --unit impostor --setenv SKAGENT_TESTKEY_PIN=111111"
            " ${testkey}/bin/skagent-testkey --touch auto --name 'impostor key' --serial 12345678"
        )
        machine.wait_until_succeeds("fido2-token -L | grep -F 'impostor key' >/dev/null", timeout=10)
        # Replugged, the real key's binding knows its serial only.
        unplug("popup key", "${unpluggedFile}")
        plug_in("popup key", "${unpluggedFile}")
        mark = len(popup_log())
        status, out = sign()
        assert status != 0, out
        closed()
        assert names(mark) == ["failed"], names(mark)
        failed = shown(mark)[-1]
        assert failed["reason"] == "duplicate", failed
        assert failed["security_key"] == {"name": "Desk 5C NFC"}, failed
        assert "one of them pretends to be it" in journal("skagent")
        assert "touch requested" not in journal("impostor"), journal("impostor")
        machine.succeed("systemctl stop impostor")
        machine.wait_until_fails("fido2-token -L | grep -F 'impostor key' >/dev/null", timeout=10)

    with subtest("a key the only security key doesn't hold fails, saying so"):
        # A key of the other security key's own; then only the popup key stays.
        machine.succeed("touch ${otherTouchFile}")
        other_device = machine.succeed("fido2-token -L | grep -F 'other key' | cut -d: -f1").strip()
        alice_ok(
            "SSH_ASKPASS=test-askpass SSH_ASKPASS_REQUIRE=force SKAGENT_TEST_ANSWER=135790"
            f" ssh-keygen -t ed25519-sk -O resident -O verify-required -O device={other_device}"
            " -O application=ssh:other -N ''' -C other -f ~/id_other"
        )
        machine.succeed("systemctl stop other-key")
        machine.wait_until_fails("fido2-token -L | grep -F 'other key'")
        alice_ok("SSH_AUTH_SOCK=${socket} ssh-add ~/id_other && echo other > ~/other")
        # Unbound, with one security key plugged in: that one is asked, with
        # its own PIN (the popup's answer), and doesn't hold the key.
        mark = len(popup_log())
        touch()
        status, out = alice("SSH_AUTH_SOCK=${socket} ssh-keygen -Y sign -f ~/id_other.pub -n test ~/other")
        assert status != 0, out
        closed()
        assert names(mark)[0] == "pin" and names(mark)[-1] == "failed", names(mark)
        failed = shown(mark)[-1]
        assert failed["reason"] == "not-on-key", failed
        assert failed["security_key"] == {"name": "Desk 5C NFC"}, failed
        assert "pin retries: 8" in tries()
        machine.succeed("rm -f ${touchFile}")

    with subtest("a security key unplugged while its PIN is asked for fails as unplugged"):
        alice_ok("skagent forget --socket ${socket}")
        alice_ok("touch ${dir}/hold-pin")
        mark = len(popup_log())
        start_sign("unplugged")
        retry(lambda _last_try: "pin" in names(mark), timeout_seconds=10)
        machine.succeed("systemctl stop testkey")
        machine.wait_until_fails("fido2-token -L | grep -F 'popup key'")
        alice_ok("rm ${dir}/hold-pin")
        finished("unplugged", success=False)
        closed()
        assert names(mark) == ["pin", "failed"], names(mark)
        assert shown(mark)[-1]["reason"] == "unplugged", shown(mark)

    with subtest("a popup that fails to start fails the request, not the agent"):
        machine.succeed("systemctl stop skagent")
        machine.wait_until_fails("test -e ${socket}")
        machine.succeed("${agent "skagent-broken" "/run/current-system/sw/bin/false"}")
        machine.wait_for_file("${socket}")
        alice_ok("SSH_AUTH_SOCK=${socket} ssh-add ~/id_sk")
        status, out = sign()
        assert status != 0, out
        assert "starting the popup" in journal("skagent-broken")
        assert "ED25519-SK" in alice_ok("SSH_AUTH_SOCK=${socket} ssh-add -l")

    with subtest("PINs reach neither the journal nor the popup log"):
        for unit in ["skagent", "skagent-broken"]:
            assert "${pin}" not in journal(unit), f"PIN in the {unit} journal"
        assert "${pin}" not in "\n".join(popup_log()), "PIN in a message to the popup"
  '';
}
