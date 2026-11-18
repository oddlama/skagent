# Resident loading runs entirely in the agent: no PIN argument or secret on
# the agent socket, no stub files written, and authenticated PINs prime signing.
{
  pkgs,
  package,
  testkey,
}:
let
  common = import ./common.nix { inherit pkgs; };
  dir = "/run/skagent-alice";
  socket = "${dir}/agent.sock";
  pin = "246810";
in
pkgs.testers.runNixOSTest {
  name = "skagent-loading";
  nodes.machine = {
    imports = [ common.virtualKeyMachine ];
    security.polkit.enable = true;
    environment.systemPackages = [
      package
      testkey
      common.testAskpass
      pkgs.openssh
      pkgs.libfido2
    ];
    users.users.alice.isNormalUser = true;
  };
  testScript = ''
    import shlex

    def alice(command: str) -> str:
        return machine.succeed(f"su - alice -c {shlex.quote(command)} 2>&1")

    def alice_fail(command: str) -> None:
        machine.fail(f"su - alice -c {shlex.quote(command)} 2>&1")

    def journal(unit: str) -> str:
        return machine.succeed(f"journalctl -u {unit} --no-pager -o cat")

    def prompts() -> int:
        return machine.succeed("cat ${dir}/prompts 2>/dev/null || true").count("Enter PIN")

    def touches(key: str) -> int:
        return journal(f"key-{key}").count("touch requested")

    def touch(key: str) -> None:
        machine.succeed(f"touch /run/load-{key}-touch")

    def device(key: str) -> str:
        return machine.succeed(f"fido2-token -L | grep -F 'load-{key}' | cut -d: -f1").strip()

    def retries(key: str, expected: int = 8) -> None:
        info = machine.succeed(f"fido2-token -I {device(key)}")
        assert f"pin retries: {expected}" in info, info

    def start_key(key: str, pin: str) -> None:
        machine.succeed(
            f"systemd-run --unit key-{key} --setenv SKAGENT_TESTKEY_PIN={pin}"
            f" ${testkey}/bin/skagent-testkey --name load-{key} --touch file --touch-file /run/load-{key}-touch"
        )
        machine.wait_until_succeeds(f"fido2-token -L | grep -F load-{key} >/dev/null")

    def start_agent(unit: str, extra: str = "") -> None:
        machine.succeed(
            f"systemd-run --unit {unit} --uid alice"
            " --setenv SKAGENT_TEST_ANSWER_FILE=${dir}/pin"
            " --setenv SKAGENT_TEST_ASKPASS_LOG=${dir}/prompts"
            " --setenv SKAGENT_TEST_ASKPASS_GATE=${dir}/hold-prompt"
            # No pairing: its first-use touch is vm-popup's subject.
            f" ${package}/bin/skagent serve --no-pairing --socket ${socket} --askpass /run/current-system/sw/bin/test-askpass {extra}"
        )
        machine.wait_for_file("${socket}")
        retry(lambda _last_try: "machine sleeps (logind)" in journal(unit), timeout_seconds=10)

    def enroll(name: str, rp: str, key: str = "one", pin: str = "${pin}", options: str = "-O verify-required", algorithm: str = "ed25519-sk") -> None:
        touch(key)
        alice(
            f"SSH_ASKPASS=test-askpass SSH_ASKPASS_REQUIRE=force SKAGENT_TEST_ANSWER={pin}"
            f" ssh-keygen -q -t {algorithm} -O resident {options} -O device={device(key)}"
            f" -O application={rp} -O user={name} -N ''' -C original-{name} -f ~/{name}"
        )
        alice(f"echo \"alice $(cat ~/{name}.pub)\" > ~/{name}.allowed")

    def load(expected: int) -> None:
        asked = prompts()
        out = alice("skagent load --socket ${socket}")
        assert f"Loaded {expected} resident SSH key(s)." in out, out
        assert prompts() == asked + 1, "loading should ask once for the selected device"

    def listed() -> list[str]:
        out = alice("SSH_AUTH_SOCK=${socket} ssh-add -L")
        return out.splitlines()

    def sign(name: str, key: str = "one", prompt: bool = False) -> None:
        asked, touched = prompts(), touches(key)
        touch(key)
        alice(f"echo hello > ~/msg-{name} && rm -f ~/msg-{name}.sig")
        alice(f"SSH_AUTH_SOCK=${socket} ssh-keygen -Y sign -f ~/{name}.pub -n test ~/msg-{name}")
        out = alice(f"ssh-keygen -Y verify -f ~/{name}.allowed -I alice -n test -s ~/msg-{name}.sig < ~/msg-{name}")
        assert "Good" in out, out
        assert prompts() == asked + int(prompt), (asked, prompts())
        assert touches(key) == touched + 1, "signing must need exactly one touch, not selection again"

    def start_load(unit: str) -> None:
        machine.succeed(f"systemd-run --unit {unit} --uid alice ${package}/bin/skagent load --socket ${socket}")

    def finished(unit: str, success: bool) -> None:
        machine.wait_until_succeeds(f"systemctl show {unit} -p ActiveState --value | grep -E '^(inactive|failed)$' >/dev/null")
        status = machine.succeed(f"systemctl show {unit} -p ExecMainStatus --value").strip()
        assert (status == "0") == success, (status, journal(unit), journal("skagent"))

    def select_load(unit: str, expected: int) -> None:
        touched, asked = touches("two"), prompts()
        start_load(unit)
        retry(lambda _last_try: touches("two") == touched + 1, timeout_seconds=10)
        assert prompts() == asked, "asked before selecting the device"
        touch("two")
        finished(unit, True)
        assert f"Loaded {expected} resident SSH key(s)." in journal(unit)
        assert prompts() == asked + 1
        # The synchronous test key processes CANCEL only after its 10s touch timeout.
        retry(lambda _last_try: journal("key-one").count('touch requested operation="select"') == journal("key-one").count('touch answered operation="select"'), timeout_seconds=15)

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("install -d -m 0700 -o alice -g users ${dir}")
    alice("umask 077; echo ${pin} > ${dir}/pin")
    start_agent("skagent")

    with subtest("no device fails without a PIN prompt"):
        alice_fail("skagent load --socket ${socket}")
        assert prompts() == 0
        # Loading at login (--if-connected): a missing key is no failure.
        out = alice("skagent load --if-connected --socket ${socket}")
        assert "No security key connected, nothing to load." in out, out
        assert prompts() == 0

    with subtest("load enumerates multiple credentials and relying parties, skipping ECDSA"):
        start_key("one", "${pin}")
        enroll("work", "ssh:work")
        enroll("other", "ssh:work")
        enroll("plain", "ssh:personal", options="")
        enroll("ecdsa", "ssh:ignored", algorithm="ecdsa-sk")
        load(3)
        assert len(listed()) == 3
        for name in ["work", "other", "plain"]:
            public = alice(f"cut -d' ' -f1,2 ~/{name}.pub").strip()
            assert any(entry.startswith(public + " ") for entry in listed()), name
        assert any("ssh:work openssh" in entry for entry in listed()), listed()
        retries("one")

    with subtest("loading primes both verify-required PIN caches but every signature still needs touch"):
        sign("work")
        sign("other")
        sign("plain")

    with subtest("reloading preserves existing identity lifetimes and comments"):
        alice("SSH_AUTH_SOCK=${socket} ssh-add -t 3 ~/work")
        load(3)
        assert any("original-work" in entry for entry in listed())
        machine.sleep(4)
        assert len(listed()) == 2, "load removed an existing lifetime constraint"
        load(3)

    with subtest("loading needs no stubs and writes none"):
        alice("rm ~/work ~/other ~/plain ~/ecdsa")
        alice("SSH_AUTH_SOCK=${socket} ssh-add -D")
        files = alice("find ~ -type f | sort")
        load(3)
        assert alice("find ~ -type f | sort") == files
        sign("work")

    with subtest("wrong loading PIN costs one retry, preserves identities, and evicts this device's PINs"):
        alice("echo 000000 > ${dir}/pin")
        asked = prompts()
        alice_fail("skagent load --socket ${socket}")
        assert prompts() == asked + 1
        retries("one", 7)
        assert len(listed()) == 3
        alice("echo ${pin} > ${dir}/pin")
        sign("work", prompt=True)
        sign("other", prompt=True)
        retries("one")

    with subtest("a locked agent refuses load before prompting"):
        lock = "SSH_ASKPASS=test-askpass SSH_ASKPASS_REQUIRE=force SKAGENT_TEST_ANSWER=lock-passphrase"
        alice(f"{lock} SSH_AUTH_SOCK=${socket} ssh-add -x")
        asked = prompts()
        alice_fail("skagent load --socket ${socket}")
        assert prompts() == asked
        alice(f"{lock} SSH_AUTH_SOCK=${socket} ssh-add -X")

    with subtest("remove-all during a loading prompt prevents identity resurrection"):
        machine.succeed("touch ${dir}/hold-prompt")
        pending = prompts()
        start_load("pending-load")
        retry(lambda _last_try: prompts() == pending + 1, timeout_seconds=10)
        alice("SSH_AUTH_SOCK=${socket} ssh-add -D")
        finished("pending-load", False)
        machine.succeed("rm ${dir}/hold-prompt")
        alice_fail("SSH_AUTH_SOCK=${socket} ssh-add -l")
        load(3)
        sign("work")

    with subtest("loading an empty second device uses only its PIN and leaves the first cache alone"):
        start_key("two", "135790")
        alice("echo 135790 > ${dir}/pin")
        select_load("empty-load", 0)
        assert len(listed()) == 3
        sign("work")
        retries("one")
        retries("two")

    with subtest("a second device loads with its own PIN and immediately has a signing binding"):
        enroll("second", "ssh:second", key="two", pin="135790")
        alice("rm ~/second")
        select_load("second-load", 1)
        assert len(listed()) == 4
        sign("second", key="two")
        sign("work")
        retries("one")
        retries("two")
        machine.succeed("systemctl stop key-two")
        machine.wait_until_fails("fido2-token -L | grep -F load-two >/dev/null")

    with subtest("loading respects disabled PIN caching"):
        machine.succeed("systemctl stop skagent")
        machine.wait_until_fails("test -e ${socket}")
        alice("echo ${pin} > ${dir}/pin")
        start_agent("skagent-no-cache", "--pin-lifetime 0")
        load(3)
        sign("work", prompt=True)
        sign("other", prompt=True)

    with subtest("loading PINs never enter agent logs"):
        for unit in ["skagent", "skagent-no-cache"]:
            for secret in ["${pin}", "135790", "000000"]:
                assert secret not in journal(unit), "PIN leaked"
  '';
}
