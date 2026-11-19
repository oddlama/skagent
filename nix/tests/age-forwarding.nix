# Decrypting age files through a forwarded agent (--age-forwarding): a
# client with the security key and skagent, a jump host and a target, each
# with its own host keys and with age and skagent's plugin, but no agent.
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
  ageSocket = "${dir}/agent-age.sock";
  server = {
    services.openssh.enable = true;
    users.users.alice.isNormalUser = true;
    # age and the plugin, which finds no agent of its own here and asks the
    # forwarded one.
    environment.systemPackages = [
      package
      pkgs.age
    ];
  };
in
pkgs.testers.runNixOSTest {
  name = "skagent-age-forwarding";

  nodes = {
    client = {
      imports = [ common.virtualKeyMachine ];
      environment.systemPackages = [
        package
        testkey
        common.testAskpass
        pkgs.age
        pkgs.libfido2
        pkgs.openssh
      ];
      security.polkit.enable = true;
      # A logind session for alice: without one nothing is cached, and no
      # batch keeps anything.
      services.getty.autologinUser = "alice";
      security.pam.services.login.rules.session.systemd.args = [ "type=wayland" ];
      users.users.alice.isNormalUser = true;
    };
    jump = server;
    target = server;
  };

  testScript = ''
    import re
    import shlex

    def run_as_alice(node, command: str) -> tuple[int, str]:
        return node.execute(f"su - alice -c {shlex.quote(command)} 2>&1")

    def alice(command: str) -> tuple[int, str]:
        return run_as_alice(client, command)

    def alice_ok(command: str) -> str:
        status, out = alice(command)
        assert status == 0, f"{command!r} exited {status}: {out}"
        return out

    def journal(unit: str) -> str:
        return client.succeed(f"journalctl -u {unit} --no-pager -o cat")

    def messages(unit: str) -> str:
        # The journal without the time of day: its microseconds are six
        # digits, and now and then they spell a PIN.
        return re.sub(r"T\d\d:\d\d:\d\d\.\d+Z", "", journal(unit))

    def touches() -> int:
        return journal("testkey").count("touch requested")

    def prompts() -> list[str]:
        return client.succeed("cat ${dir}/prompts 2>/dev/null || true").splitlines()

    def expect(before: tuple[int, int], asked: int, touched: int, why: str) -> None:
        now = (len(prompts()), touches())
        assert now == (before[0] + asked, before[1] + touched), (why, before, now)

    def decrypted(unit: str, purpose: str) -> int:
        """How often the agent says it decrypted for `purpose`."""
        return journal(unit).count(f"purpose={purpose} stanzas=")

    def ssh(destination: str, command: str) -> str:
        """`command` on `destination`, with the agent forwarded."""
        return (
            f"SSH_AUTH_SOCK=${socket} ssh -A -o BatchMode=yes -o StrictHostKeyChecking=yes"
            f" {destination} {shlex.quote(command)}"
        )

    # From the jump host on, with the forwarded agent forwarded once more.
    hop = "ssh -A -o BatchMode=yes -o StrictHostKeyChecking=yes"
    decrypt = "age -d -i ~/id.txt ~/secret.age"

    def start_agent(unit: str, *args: str) -> None:
        client.succeed(
            f"systemd-run --unit {unit} --uid alice"
            " --setenv SKAGENT_TEST_ANSWER_FILE=${dir}/pin"
            " --setenv SKAGENT_TEST_ASKPASS_LOG=${dir}/prompts"
            " ${package}/bin/skagent serve --no-pairing --no-touch-notification"
            " --askpass /run/current-system/sw/bin/test-askpass"
            f" --socket ${socket} {' '.join(args)}"
        )
        client.wait_for_file("${socket}")
        client.wait_for_file("${ageSocket}")
        retry(lambda _last_try: "machine sleeps (logind)" in journal(unit), timeout_seconds=10)

    def stop_agent(unit: str) -> None:
        client.succeed(f"systemctl stop {unit}")
        client.wait_until_fails("test -e ${socket}")

    start_all()
    for node in [jump, target]:
        node.wait_for_unit("sshd.service")
    client.wait_for_unit("multi-user.target")
    client.wait_until_succeeds("loginctl show-user alice -p Sessions --value | grep . >/dev/null")
    client.succeed(
        "systemd-run --unit testkey --setenv SKAGENT_TESTKEY_PIN=${pin}"
        " ${testkey}/bin/skagent-testkey --touch auto"
    )
    client.wait_until_succeeds("fido2-token -L | grep -F 'skagent test key' >/dev/null")

    with subtest("an SSH key to log in with, an age identity, and a file for it on every host"):
        alice_ok(
            "SSH_ASKPASS=test-askpass SSH_ASKPASS_REQUIRE=force SKAGENT_TEST_ANSWER=${pin}"
            " ssh-keygen -q -t ed25519-sk -O resident -O verify-required"
            " -O application=ssh:example -N ''' -C alice@example.com -f ~/.ssh/id_sk"
        )
        public_key = alice_ok("cat ~/.ssh/id_sk.pub").strip()
        for node in [jump, target]:
            node.succeed(
                "install -d -m 700 -o alice -g users /home/alice/.ssh"
                f" && echo {shlex.quote(public_key)} > /home/alice/.ssh/authorized_keys"
                " && chown alice:users /home/alice/.ssh/authorized_keys"
            )
        alice_ok("ssh-keyscan -t ed25519 jump target > ~/.ssh/known_hosts 2>/dev/null")
        status, out = run_as_alice(jump, "install -d -m 700 ~/.ssh && ssh-keyscan -t ed25519 target > ~/.ssh/known_hosts 2>/dev/null")
        assert status == 0, out
        client.succeed("install -d -m 0700 -o alice -g users ${dir}")
        alice_ok("umask 077 && echo ${pin} > ${dir}/pin")

        start_agent("skagent")
        alice_ok("SKAGENT_AGE_SOCKET=${ageSocket} skagent age new > ~/recipient")
        alice_ok("SKAGENT_AGE_SOCKET=${ageSocket} skagent age identity > ~/id.txt")
        alice_ok("echo the-secret | age -a -R ~/recipient -o ~/secret.age")
        alice_ok("SSH_AUTH_SOCK=${socket} ssh-add ~/.ssh/id_sk")
        identity = alice_ok("cat ~/id.txt")
        secret = alice_ok("cat ~/secret.age")
        for node in [jump, target]:
            node.succeed(
                f"printf %s {shlex.quote(identity)} > /home/alice/id.txt"
                f" && printf %s {shlex.quote(secret)} > /home/alice/secret.age"
                " && chown alice:users /home/alice/id.txt /home/alice/secret.age"
            )

    def host_key_fingerprint(node) -> str:
        return node.succeed("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub").split()[1]

    jump_key = host_key_fingerprint(jump)
    target_key = host_key_fingerprint(target)

    with subtest("unless told to, the agent decrypts nothing for a forwarded agent"):
        # The login itself is signed with a touch; the PIN is cached by it.
        alice_ok(ssh("jump", "hostname"))
        before = (len(prompts()), touches())
        status, out = alice(ssh("jump", decrypt))
        assert status != 0 and "the-secret" not in out, out
        assert "skagent doesn't take age requests on this connection" in out, out
        # One touch for the login, none for the decryption.
        expect(before, 0, 1, "a refused forwarded decryption")
        # Nor through the socket directly, without ssh.
        status, out = alice(f"SKAGENT_AGE_SOCKET=${socket} {decrypt}")
        assert status != 0 and "the-secret" not in out, out
        expect(before, 0, 1, "a refused decryption on the ssh-agent socket")

    with subtest("with --age-forwarding a remote host gets a file key for a touch, and the prompt names it"):
        stop_agent("skagent")
        start_agent("skagent-forwarding", "--age-forwarding")
        alice_ok("SSH_AUTH_SOCK=${socket} ssh-add ~/.ssh/id_sk")
        # The login asks for the SSH key's PIN, the decryption for the
        # identity's: two credentials, each with its own cache entry.
        before = (len(prompts()), touches())
        out = alice_ok(ssh("jump", decrypt))
        assert out.strip().splitlines()[-1] == "the-secret", out
        expect(before, 2, 2, "the first forwarded decryption")
        purpose = f"decrypt a file for the host with key {jump_key} (through your forwarded agent)"
        assert "Enter PIN for age identity (age1pq1" in prompts()[-1], prompts()
        assert f"to {purpose}, then touch the key" in prompts()[-1], prompts()
        assert decrypted("skagent-forwarding", purpose) == 1, journal("skagent-forwarding")

    with subtest("every forwarded file takes a touch"):
        before = (len(prompts()), touches())
        out = alice_ok(ssh("jump", f"{decrypt}; {decrypt}"))
        assert out.split().count("the-secret") == 2, out
        # The login and two files.
        expect(before, 0, 3, "two forwarded decryptions")

    with subtest("a host further on is named with the one the agent was forwarded to first"):
        before = (len(prompts()), touches())
        out = alice_ok(ssh("jump", f"{hop} target {shlex.quote(decrypt)}"))
        assert out.strip().splitlines()[-1] == "the-secret", out
        # Two logins and the file.
        expect(before, 0, 3, "a decryption two hops away")
        purpose = (
            f"decrypt a file for the host with key {target_key}"
            f" (through your agent forwarded to the host with key {jump_key})"
        )
        assert decrypted("skagent-forwarding", purpose) == 1, journal("skagent-forwarding")

    with subtest("whatever asks without an SSH session behind it is an unverified host"):
        before = (len(prompts()), touches())
        out = alice_ok(f"SKAGENT_AGE_SOCKET=${socket} {decrypt}")
        assert out.strip() == "the-secret", out
        expect(before, 0, 1, "a decryption on the ssh-agent socket")
        purpose = "decrypt a file for an unverified host (through your forwarded agent)"
        assert decrypted("skagent-forwarding", purpose) == 1, journal("skagent-forwarding")

    with subtest("a batch on this machine doesn't serve a forwarded request"):
        before = (len(prompts()), touches())
        script = f"{decrypt} && {ssh('jump', decrypt)} && {decrypt}"
        out = alice_ok(f"SKAGENT_AGE_SOCKET=${ageSocket} skagent batch -- sh -c {shlex.quote(script)}")
        assert out.split().count("the-secret") == 3, out
        # The batch's first file, the login and the forwarded file take a
        # touch each. The batch's own second file takes none.
        expect(before, 0, 3, "a forwarded decryption inside a batch")
        assert journal("skagent-forwarding").count("decrypted in a batch, without a touch") == 1

    with subtest("identities and batches stay this machine's business"):
        for command in ["skagent age list", "skagent age new", "skagent batch -- true"]:
            before = (len(prompts()), touches())
            status, out = alice(ssh("jump", f'SKAGENT_AGE_SOCKET="$SSH_AUTH_SOCK" {command}'))
            assert status != 0, (command, out)
            expect(before, 0, 1, command)

    with subtest("PINs never reach the journal"):
        for unit in ["skagent", "skagent-forwarding"]:
            assert "${pin}" not in messages(unit), unit
  '';
}
