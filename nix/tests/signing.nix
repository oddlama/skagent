# Signing through skagent with a (virtual) security key, end to end: stock
# ssh-keygen and ssh as clients, a real sshd as the server, logind for screen
# lock events. Covers the PIN cache and every way a cached PIN goes away.
{
  pkgs,
  package,
  testkey,
}:
let
  common = import ./common.nix { inherit pkgs; };
  pin = "246810";
  socketDir = "/run/skagent-alice";
  socket = "${socketDir}/agent.sock";
  touchFile = "/run/testkey-touch";
  # In alice's private directory: with fs.protected_regular, root may not
  # write into another user's files in the sticky /tmp.
  answerFile = "${socketDir}/pin";
  promptLog = "${socketDir}/prompts";
  pinentryLog = "${socketDir}/pinentry";
  askpass = "SSH_ASKPASS=test-askpass SSH_ASKPASS_REQUIRE=force SKAGENT_TEST_ANSWER=${pin}";
  startTestkey =
    unit: name:
    "systemd-run --unit ${unit} --setenv SKAGENT_TESTKEY_PIN=${pin}"
    + " ${testkey}/bin/skagent-testkey --touch file --touch-file ${touchFile} --name '${name}'";
in
pkgs.testers.runNixOSTest {
  name = "skagent-signing";

  nodes.machine = {
    imports = [ common.virtualKeyMachine ];
    environment.systemPackages = [
      package
      testkey
      common.testAskpass
      common.testPinentry
      pkgs.libfido2
      pkgs.openssh
    ];
    services.openssh.enable = true;
    security.polkit.enable = true;
    # Exercise real logind PrepareForSleep without suspending the test driver.
    systemd.services.systemd-suspend.serviceConfig.ExecStart = [
      ""
      "${pkgs.coreutils}/bin/sleep 1"
    ];
    # A logind session for alice, so screen lock events have someone to lock.
    services.getty.autologinUser = "alice";
    # logind only allows Lock on graphical sessions. No compositor needed.
    security.pam.services.login.rules.session.systemd.args = [ "type=wayland" ];
    users.users.alice.isNormalUser = true;
  };

  testScript = ''
    import shlex

    def alice(command: str) -> tuple[int, str]:
        return machine.execute(f"su - alice -c {shlex.quote(command)} 2>&1")

    def alice_ok(command: str) -> str:
        status, out = alice(command)
        assert status == 0, f"{command!r} exited {status}: {out}"
        return out

    def journal(unit: str) -> str:
        return machine.succeed(f"journalctl -u {unit} --no-pager -o cat")

    def touches() -> int:
        return journal("testkey").count("touch requested")

    def prompts() -> int:
        askpass = machine.succeed("cat ${promptLog} 2>/dev/null || true").count("Enter PIN")
        pinentry = machine.succeed("cat ${pinentryLog} 2>/dev/null || true").count("GETPIN")
        return askpass + pinentry

    def touch() -> None:
        machine.succeed("touch ${touchFile}")

    def pin_retries() -> str:
        device = machine.succeed("fido2-token -L | grep -F 'test key one' | cut -d: -f1").strip()
        return machine.succeed(f"fido2-token -I {device}")

    def sign() -> tuple[int, str]:
        return alice("rm -f ~/msg.sig && SSH_AUTH_SOCK=${socket} ssh-keygen -Y sign -f ~/id_sk.pub -n test ~/msg")

    def sign_ok() -> None:
        touch()
        status, out = sign()
        assert status == 0, f"signing failed: {out}"
        out = alice_ok("ssh-keygen -Y verify -f ~/allowed -I alice -n test -s ~/msg.sig < ~/msg")
        assert "Good" in out, out

    def expect_prompt(reason: str = "") -> None:
        """One signature that must ask for the PIN (once) and use one touch."""
        before = (prompts(), touches())
        sign_ok()
        assert (prompts(), touches()) == (before[0] + 1, before[1] + 1), (reason, before, prompts(), touches())
        if reason:
            assert reason in journal("skagent"), f"{reason!r} not in the journal"

    def expect_cached() -> None:
        """One signature that must use the cached PIN: no prompt, one touch."""
        before = (prompts(), touches())
        sign_ok()
        assert (prompts(), touches()) == (before[0], before[1] + 1), (before, prompts(), touches())

    def start_agent(unit: str, *args: str) -> None:
        machine.succeed(
            f"systemd-run --unit {unit} --uid alice"
            " --setenv SKAGENT_TEST_ANSWER_FILE=${answerFile}"
            " --setenv SKAGENT_TEST_ASKPASS_LOG=${promptLog}"
            " --setenv SKAGENT_TEST_ASKPASS_GATE=${socketDir}/hold-prompt"
            " --setenv SKAGENT_TEST_PINENTRY_LOG=${pinentryLog}"
            f" ${package}/bin/skagent serve --socket ${socket} {' '.join(args)}"
        )
        machine.wait_for_file("${socket}")
        retry(lambda _last_try: "machine sleeps (logind)" in journal(unit), timeout_seconds=10)
        alice_ok("SSH_AUTH_SOCK=${socket} ssh-add ~/id_sk")

    def stop_agent(unit: str) -> None:
        machine.succeed(f"systemctl stop {unit}")
        machine.wait_until_fails("test -e ${socket}")

    def alice_session() -> str:
        session = machine.succeed("loginctl show-user alice -p Display --value").strip()
        reply = machine.succeed(
            "busctl call org.freedesktop.login1 /org/freedesktop/login1"
            f" org.freedesktop.login1.Manager GetSession s {session}"
        )
        return reply.split('"')[1]

    askpass_agent = "--askpass /run/current-system/sw/bin/test-askpass"

    machine.wait_for_unit("sshd.service")
    machine.wait_until_succeeds("loginctl show-user alice -p Sessions --value | grep . >/dev/null")
    machine.succeed("${startTestkey "testkey" "test key one"}")
    machine.wait_until_succeeds("fido2-token -L | grep -F 'test key one' >/dev/null")

    with subtest("enroll a verify-required key and authorize it for ssh"):
        touch()
        alice_ok(
            "${askpass} ssh-keygen -q -t ed25519-sk -O resident -O verify-required"
            " -O application=ssh:example -N ''' -C alice@virtual -f ~/id_sk"
        )
        # verify-required makes sshd check that the signature says the PIN was used.
        alice_ok("install -d -m 700 ~/.ssh && echo \"verify-required $(cat ~/id_sk.pub)\" > ~/.ssh/authorized_keys")
        alice_ok("echo \"alice $(cat ~/id_sk.pub)\" > ~/allowed && echo hello > ~/msg")
        machine.succeed("install -d -m 0700 -o alice -g users ${socketDir}")
        machine.succeed("install -m 0600 -o alice -g users /dev/null ${answerFile}")
        machine.succeed("echo ${pin} > ${answerFile}")

    with subtest("the first signature asks for the PIN, the next ones only need a touch"):
        start_agent("skagent", askpass_agent)
        assert "alice@virtual (ED25519-SK)" in alice_ok("SSH_AUTH_SOCK=${socket} ssh-add -l")
        expect_prompt()
        expect_cached()
        expect_cached()

    with subtest("ssh logs in with the cached PIN, and sshd sees user verification"):
        before = (prompts(), touches())
        touch()
        out = alice_ok(
            "ssh -o IdentityAgent=${socket} -o IdentitiesOnly=yes -i ~/id_sk.pub"
            " -o StrictHostKeyChecking=accept-new -o BatchMode=yes localhost echo logged-in"
        )
        assert "logged-in" in out, out
        assert (prompts(), touches()) == (before[0], before[1] + 1), (before, prompts(), touches())

    with subtest("without a touch there is no signature, and the PIN stays cached"):
        before = touches()
        status, out = sign()
        assert status != 0, f"signed without a touch: {out}"
        assert touches() == before + 1
        assert "TimedOut" in journal("testkey"), journal("testkey")
        expect_cached()

    with subtest("a wrong PIN entered elsewhere invalidates the cached PIN (retry guard)"):
        machine.succeed("echo 000000 > /tmp/wrong-pin && chmod 644 /tmp/wrong-pin")
        status, out = alice(
            "SSH_ASKPASS=test-askpass SSH_ASKPASS_REQUIRE=force SKAGENT_TEST_ANSWER=000000"
            " ssh-keygen -Y sign -f ~/id_sk -n test ~/msg"
        )
        assert status != 0, f"signed with a wrong PIN: {out}"
        assert "pin retries: 7" in pin_retries(), pin_retries()
        expect_prompt("retry counter changed from 8 to 7")
        assert "pin retries: 8" in pin_retries(), pin_retries()
        expect_cached()

    with subtest("skagent forget drops the PIN and keeps the key"):
        alice_ok("skagent forget --socket ${socket}")
        assert "alice@virtual" in alice_ok("SSH_AUTH_SOCK=${socket} ssh-add -l")
        expect_prompt()
        expect_cached()

    with subtest("locking the agent drops the PIN"):
        lock = "SSH_ASKPASS=test-askpass SSH_ASKPASS_REQUIRE=force SKAGENT_TEST_ANSWER=lock-passphrase"
        alice_ok(f"{lock} SSH_AUTH_SOCK=${socket} ssh-add -x")
        alice_ok(f"{lock} SSH_AUTH_SOCK=${socket} ssh-add -X")
        expect_prompt()

    with subtest("removing and re-adding the key drops its PIN"):
        alice_ok("SSH_AUTH_SOCK=${socket} ssh-add -d ~/id_sk")
        alice_ok("SSH_AUTH_SOCK=${socket} ssh-add ~/id_sk")
        expect_prompt()

    with subtest("remove-all drops the PIN"):
        alice_ok("SSH_AUTH_SOCK=${socket} ssh-add -D")
        alice_ok("SSH_AUTH_SOCK=${socket} ssh-add ~/id_sk")
        expect_prompt()

    with subtest("forget cancels an outstanding prompt without refilling the cache"):
        alice_ok("skagent forget --socket ${socket}")
        machine.succeed("touch ${socketDir}/hold-prompt")
        pending_prompts = prompts()
        machine.succeed(
            "systemd-run --unit pending-sign --uid alice --setenv SSH_AUTH_SOCK=${socket}"
            " ${pkgs.openssh}/bin/ssh-keygen -Y sign -f /home/alice/id_sk.pub -n test /home/alice/msg"
        )
        retry(lambda _last_try: prompts() == pending_prompts + 1, timeout_seconds=10)
        alice_ok("skagent forget --socket ${socket}")
        machine.wait_until_succeeds("test $(systemctl show pending-sign -p ExecMainStatus --value) != 0")
        machine.succeed("rm ${socketDir}/hold-prompt")
        expect_prompt()
        expect_cached()

    with subtest("an assertion finishing after forget cannot refill the cache or return a signature"):
        alice_ok("skagent forget --socket ${socket}")
        pending_touches = touches()
        machine.succeed(
            "systemd-run --unit pending-touch --uid alice --setenv SSH_AUTH_SOCK=${socket}"
            " ${pkgs.openssh}/bin/ssh-keygen -Y sign -f /home/alice/id_sk.pub -n test /home/alice/msg"
        )
        retry(lambda _last_try: touches() == pending_touches + 1, timeout_seconds=10)
        alice_ok("skagent forget --socket ${socket}")
        touch()
        machine.wait_until_succeeds("test $(systemctl show pending-touch -p ExecMainStatus --value) != 0")
        expect_prompt()
        expect_cached()

    with subtest("loginctl lock-session drops the PIN"):
        expect_cached()
        session = machine.succeed("loginctl show-user alice -p Display --value").strip()
        machine.succeed(f"loginctl lock-session {session}")
        retry(lambda _last_try: "reason=\"session locked\"" in journal("skagent"), timeout_seconds=10)
        expect_prompt()

    with subtest("a session's LockedHint (GNOME's lock) drops the PIN"):
        expect_cached()
        machine.succeed(
            f"busctl call org.freedesktop.login1 {alice_session()}"
            " org.freedesktop.login1.Session SetLockedHint b true"
        )
        retry(lambda _last_try: "LockedHint" in journal("skagent"), timeout_seconds=10)
        expect_prompt()
        machine.succeed(
            f"busctl call org.freedesktop.login1 {alice_session()}"
            " org.freedesktop.login1.Session SetLockedHint b false"
        )

    with subtest("suspend preparation drops the PIN through real logind"):
        expect_cached()
        machine.succeed("systemctl suspend")
        retry(lambda _last_try: 'reason="suspending"' in journal("skagent"), timeout_seconds=10)
        machine.wait_until_succeeds("busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager PreparingForSleep | grep 'false' >/dev/null")
        # Receipt of PrepareForSleep(false) reacquires the delay inhibitor.
        machine.wait_until_succeeds("systemd-inhibit --list --no-pager | grep skagent >/dev/null")
        expect_prompt()
        expect_cached()

    with subtest("losing logind disables caching until subscriptions are restored"):
        machine.succeed("systemctl mask --runtime --now systemd-logind.service")
        retry(lambda _last_try: "PIN caching is disabled" in journal("skagent"), timeout_seconds=10)
        expect_prompt()
        expect_prompt()
        machine.succeed("systemctl unmask --runtime systemd-logind.service && systemctl start systemd-logind.service")
        retry(lambda _last_try: journal("skagent").count("machine sleeps (logind)") == 2, timeout_seconds=40)
        expect_prompt()
        expect_cached()

    with subtest("a wrong PIN is refused, not retried, and mentioned in the next prompt"):
        alice_ok("skagent forget --socket ${socket}")
        machine.succeed("echo 000000 > ${answerFile}")
        before = prompts()
        status, out = sign()
        assert status != 0, f"signed with a wrong PIN: {out}"
        assert prompts() == before + 1, "a wrong PIN was retried without asking"
        assert "pin retries: 7" in pin_retries(), pin_retries()

        machine.succeed("echo ${pin} > ${answerFile}")
        expect_prompt()
        assert "The previous PIN was wrong" in machine.succeed("cat ${promptLog}")
        assert "pin retries: 8" in pin_retries(), pin_retries()
        expect_cached()

    with subtest("with two security keys connected skagent refuses to guess"):
        machine.succeed("${startTestkey "testkey-two" "test key two"}")
        machine.wait_until_succeeds("fido2-token -L | grep -F 'test key two' >/dev/null")
        before = prompts()
        status, out = sign()
        assert status != 0, f"signed with two keys connected: {out}"
        assert "2 FIDO security keys are connected" in journal("skagent"), journal("skagent")
        assert prompts() == before, "asked for a PIN without knowing the device"
        machine.succeed("systemctl stop testkey-two")
        machine.wait_until_fails("fido2-token -L | grep -F 'test key two' >/dev/null")
        expect_cached()

    with subtest("the PIN lifetime ends the cache"):
        stop_agent("skagent")
        start_agent("skagent-short", askpass_agent, "--pin-lifetime 3s")
        expect_prompt()
        expect_cached()
        machine.sleep(4)
        expect_prompt()
        stop_agent("skagent-short")

    with subtest("the idle timeout expires an unused PIN"):
        start_agent("skagent-idle", askpass_agent, "--pin-idle 3s")
        expect_prompt()
        expect_cached()
        machine.sleep(4)
        expect_prompt()
        stop_agent("skagent-idle")

    with subtest("zero lifetime disables caching"):
        start_agent("skagent-no-cache", askpass_agent, "--pin-lifetime 0")
        expect_prompt()
        expect_prompt()
        stop_agent("skagent-no-cache")

    with subtest("pinentry asks, shows errors, and its PIN is cached too"):
        start_agent("skagent-pinentry", "--pinentry /run/current-system/sw/bin/test-pinentry")
        expect_prompt()
        expect_cached()
        commands = machine.succeed("cat ${pinentryLog}")
        assert "SETDESC Enter the PIN of the security key holding%0Aalice@virtual" in commands, commands
        assert "SETERROR" not in commands, commands
        alice_ok("skagent forget --socket ${socket}")
        machine.succeed("echo 000000 > ${answerFile}")
        status, out = sign()
        assert status != 0, out
        machine.succeed("echo ${pin} > ${answerFile}")
        expect_prompt()
        assert "SETERROR The previous PIN was wrong" in machine.succeed("cat ${pinentryLog}")
        expect_cached()

    with subtest("a replugged key gets no cached PIN"):
        machine.succeed("systemctl stop testkey")
        machine.wait_until_fails("fido2-token -L | grep -F 'test key one' >/dev/null")
        machine.succeed("${startTestkey "testkey-replugged" "test key one"}")
        machine.wait_until_succeeds("fido2-token -L | grep -F 'test key one' >/dev/null")
        # The virtual key lost its credentials with the restart, so the
        # signature fails either way; what matters is that the PIN was asked
        # for instead of being sent to the new device.
        before = prompts()
        touch()
        status, out = sign()
        assert status != 0, f"signed with a credential the new key doesn't have: {out}"
        assert prompts() == before + 1, "the cached PIN went to a replugged device"
        assert "the security key was replugged or replaced" in journal("skagent-pinentry")

    with subtest("PINs never reach the journal"):
        for unit in ["skagent", "skagent-short", "skagent-idle", "skagent-no-cache", "skagent-pinentry"]:
            assert "${pin}" not in journal(unit), f"PIN in the journal of {unit}"
  '';
}
