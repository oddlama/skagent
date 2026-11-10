# Two distinct authenticators and PINs. A wrong-device cached PIN would cost
# a retry, which this test checks in addition to prompt/touch counts.
{
  pkgs,
  package,
  testkey,
}:
let
  common = import ./common.nix { inherit pkgs; };
  dir = "/run/skagent-alice";
  socket = "${dir}/agent.sock";
  prompts = "${dir}/prompts";
  askpass = pkgs.writeShellApplication {
    name = "multi-askpass";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      printf '%s\n' "$1" >> ${prompts}
      case "$1" in
        *personal*) cat ${dir}/personal-pin ;;
        *work*) cat ${dir}/work-pin ;;
        *) exit 1 ;;
      esac
    '';
  };
in
pkgs.testers.runNixOSTest {
  name = "skagent-multiple-keys";
  nodes.machine = {
    imports = [ common.virtualKeyMachine ];
    environment.systemPackages = [
      package
      testkey
      common.testAskpass
      pkgs.openssh
      pkgs.libfido2
    ];
    security.polkit.enable = true;
    users.users.alice.isNormalUser = true;
  };
  testScript = ''
    import shlex

    def alice(command: str) -> str:
        return machine.succeed(f"su - alice -c {shlex.quote(command)} 2>&1")

    def journal(unit: str) -> str:
        return machine.succeed(f"journalctl -u {unit} --no-pager -o cat")

    def count(key: str, operation: str, event: str = "requested") -> int:
        return journal(f"key-{key}").count(f'touch {event} operation="{operation}"')

    def prompts() -> int:
        return machine.succeed("cat ${prompts} 2>/dev/null || true").count("Enter PIN")

    def touch(key: str) -> None:
        machine.succeed(f"touch /run/{key}-touch")

    def device(key: str) -> str:
        return machine.succeed(f"fido2-token -L | grep -F 'multi-{key}' | cut -d: -f1").strip()

    def retries(key: str) -> None:
        info = machine.succeed(f"fido2-token -I {device(key)}")
        assert "pin retries: 8" in info, (key, info)

    def start_key(key: str, pin: str) -> None:
        machine.succeed(
            f"systemd-run --unit key-{key} --setenv SKAGENT_TESTKEY_PIN={pin}"
            f" ${testkey}/bin/skagent-testkey --name multi-{key} --touch file --touch-file /run/{key}-touch"
        )
        machine.wait_until_succeeds(f"fido2-token -L | grep -F multi-{key} >/dev/null")

    def start_sign(key: str, unit: str) -> None:
        alice(f"echo {unit} > ~/{unit}")
        machine.succeed(
            f"systemd-run --unit {unit} --uid alice --setenv SSH_AUTH_SOCK=${socket}"
            f" ${pkgs.openssh}/bin/ssh-keygen -Y sign -f /home/alice/{key}.pub -n test /home/alice/{unit}"
        )

    def finished(unit: str, success: bool = True) -> None:
        machine.wait_until_succeeds(
            f"systemctl show {unit} -p ActiveState --value | grep -E '^(inactive|failed)$' >/dev/null"
        )
        status = machine.succeed(f"systemctl show {unit} -p ExecMainStatus --value").strip()
        assert (status == "0") == success, (unit, status, journal(unit), journal("skagent"))

    def verify(key: str, unit: str) -> None:
        out = alice(f"ssh-keygen -Y verify -f ~/{key}.allowed -I alice -n test -s ~/{unit}.sig < ~/{unit}")
        assert "Good" in out, out

    def wait_selections_idle() -> None:
        # The test key's synchronous transport cannot consume CANCEL while
        # waiting for a touch. Unselected probes time out after 10s; production
        # devices receive fido_dev_cancel when the probe handle is dropped.
        for key in ["work", "personal"]:
            retry(lambda _last_try: count(key, "select") == count(key, "select", "answered"), timeout_seconds=15)

    def select_and_sign(key: str, unit: str) -> None:
        selections = count(key, "select")
        assertions = count(key, "getAssertion")
        asked = prompts()
        start_sign(key, unit)
        retry(lambda _last_try: count(key, "select") == selections + 1, timeout_seconds=10)
        assert prompts() == asked, "asked before the user chose a device"
        touch(key)
        retry(lambda _last_try: count(key, "getAssertion") == assertions + 1, timeout_seconds=10)
        touch(key)
        finished(unit)
        verify(key, unit)
        assert prompts() == asked + 1, "first use must ask for this device's PIN"
        wait_selections_idle()
        retries("work")
        retries("personal")

    def bound_sign(key: str, unit: str, prompt: bool = False) -> None:
        selected = count(key, "select")
        asserted = count(key, "getAssertion")
        asked = prompts()
        touch(key)
        start_sign(key, unit)
        finished(unit)
        verify(key, unit)
        assert count(key, "select") == selected, "lost a live binding"
        assert count(key, "getAssertion") == asserted + 1, "signature didn't need exactly one touch"
        assert prompts() == asked + int(prompt), (key, asked, prompts())

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("install -d -m 0700 -o alice -g users ${dir}")

    with subtest("enroll two verify-required keys with different PINs"):
        for key, pin in [("work", "246810"), ("personal", "135790")]:
            start_key(key, pin)
            alice(f"umask 077; echo {pin} > ${dir}/{key}-pin")
            touch(key)
            alice(
                f"SSH_ASKPASS=test-askpass SSH_ASKPASS_REQUIRE=force SKAGENT_TEST_ANSWER={pin}"
                f" ssh-keygen -q -t ed25519-sk -O resident -O verify-required -O device={device(key)}"
                f" -O application=ssh:{key} -N ''' -C {key} -f ~/{key}"
            )
            alice(f"echo \"alice $(cat ~/{key}.pub)\" > ~/{key}.allowed")
        machine.succeed(
            "systemd-run --unit skagent --uid alice"
            " ${package}/bin/skagent serve --socket ${socket} --askpass ${askpass}/bin/multi-askpass"
        )
        machine.wait_for_file("${socket}")
        retry(lambda _last_try: "machine sleeps (logind)" in journal("skagent"), timeout_seconds=10)
        alice("SSH_AUTH_SOCK=${socket} ssh-add ~/work ~/personal")

    with subtest("no selection touch means no PIN prompt or retry consumed"):
        asked = prompts()
        start_sign("work", "untouched-selection")
        finished("untouched-selection", success=False)
        wait_selections_idle()
        assert prompts() == asked
        retries("work")
        retries("personal")

    with subtest("unknown credentials are selected by touch before asking for a PIN"):
        select_and_sign("work", "select-work")
        select_and_sign("personal", "select-personal")

    with subtest("each cached PIN goes only to its bound device"):
        bound_sign("personal", "personal-cached")
        bound_sign("work", "work-cached")
        bound_sign("personal", "personal-cached-again")
        retries("work")
        retries("personal")

    with subtest("waiting for work's touch does not block personal"):
        waiting = count("work", "getAssertion")
        asked = prompts()
        start_sign("work", "parallel-work")
        retry(lambda _last_try: count("work", "getAssertion") == waiting + 1, timeout_seconds=5)
        bound_sign("personal", "parallel-personal")
        # Work is still waiting, personal has already signed and verified.
        assert machine.succeed("systemctl show parallel-work -p ActiveState --value").strip() == "active"
        touch("work")
        finished("parallel-work")
        verify("work", "parallel-work")
        assert prompts() == asked

    with subtest("forget evicts PINs but preserves both device bindings"):
        alice("skagent forget --socket ${socket}")
        bound_sign("work", "work-forgotten", prompt=True)
        bound_sign("personal", "personal-forgotten", prompt=True)

    with subtest("removing one identity leaves the other PIN cached"):
        alice("SSH_AUTH_SOCK=${socket} ssh-add -d ~/work && SSH_AUTH_SOCK=${socket} ssh-add ~/work")
        bound_sign("personal", "personal-unaffected")
        select_and_sign("work", "work-readded")

    with subtest("cancelling selection asks for no PIN and costs no retries"):
        alice("SSH_AUTH_SOCK=${socket} ssh-add -d ~/work && SSH_AUTH_SOCK=${socket} ssh-add ~/work")
        selecting = count("work", "select")
        asked = prompts()
        start_sign("work", "cancel-selection")
        retry(lambda _last_try: count("work", "select") == selecting + 1, timeout_seconds=10)
        alice("skagent forget --socket ${socket}")
        finished("cancel-selection", success=False)
        wait_selections_idle()
        assert prompts() == asked
        retries("work")
        retries("personal")
        select_and_sign("work", "work-after-cancel")
        bound_sign("personal", "personal-after-cancel", prompt=True)

    with subtest("remove-all clears both bindings as well as both PINs"):
        alice("SSH_AUTH_SOCK=${socket} ssh-add -D && SSH_AUTH_SOCK=${socket} ssh-add ~/work ~/personal")
        select_and_sign("personal", "personal-after-clear")
        select_and_sign("work", "work-after-clear")

    with subtest("a replacement device never receives the old device's cached PIN"):
        machine.succeed("systemctl stop key-work")
        machine.wait_until_fails("fido2-token -L | grep -F multi-work >/dev/null")
        bound_sign("personal", "personal-without-work")
        # A different PIN and no credentials after restarting the virtual key.
        alice("echo 999999 > ${dir}/work-pin")
        start_key("work", "999999")
        selecting = count("work", "select")
        asked = prompts()
        start_sign("work", "replacement")
        retry(lambda _last_try: count("work", "select") == selecting + 1, timeout_seconds=10)
        assert prompts() == asked, "prompted before selection"
        touch("work")
        finished("replacement", success=False)
        wait_selections_idle()
        assert prompts() == asked + 1, "reused a PIN from the old device"
        retries("work")
        retries("personal")
        bound_sign("personal", "personal-after-replacement")

    with subtest("PINs are absent from the agent journal"):
        for pin in ["246810", "135790", "999999"]:
            assert pin not in journal("skagent"), "PIN leaked"
  '';
}
