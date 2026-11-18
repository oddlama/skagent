# Agent forwarding and destination constraints across real hosts: a client
# with the security key and skagent, a jump host and a target, each with
# its own host keys.
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
  server = {
    services.openssh.enable = true;
    users.users.alice.isNormalUser = true;
    # Only to send skagent's own extensions through a forwarded agent.
    environment.systemPackages = [ package ];
  };
in
pkgs.testers.runNixOSTest {
  name = "skagent-destinations";

  nodes = {
    client = {
      imports = [ common.virtualKeyMachine ];
      environment.systemPackages = [
        package
        testkey
        common.testAskpass
        pkgs.libfido2
        pkgs.openssh
      ];
      security.polkit.enable = true;
      users.users.alice.isNormalUser = true;
    };
    jump = server;
    target = server;
  };

  testScript = ''
    import shlex

    def run_as_alice(node, command: str) -> str:
        return node.succeed(f"su - alice -c {shlex.quote(command)} 2>&1")

    def alice(command: str) -> str:
        return run_as_alice(client, command)

    def alice_fails(command: str) -> str:
        status, out = client.execute(f"su - alice -c {shlex.quote(command)} 2>&1")
        assert status != 0, f"{command!r} succeeded: {out}"
        return out

    def journal(unit: str) -> str:
        return client.succeed(f"journalctl -u {unit} --no-pager -o cat")

    def touches() -> int:
        return journal("testkey").count("touch requested")

    def prompts() -> str:
        return client.succeed("cat ${dir}/prompts 2>/dev/null || true")

    def ssh(destination: str, command: str, options: str = "") -> str:
        return (
            f"SSH_AUTH_SOCK=${socket} ssh -o BatchMode=yes -o StrictHostKeyChecking=yes"
            f" {options} {destination} {shlex.quote(command)}"
        )

    # Nested ssh on the jump host uses the forwarded agent.
    hop = "ssh -o BatchMode=yes -o StrictHostKeyChecking=yes"

    start_all()
    for node in [jump, target]:
        node.wait_for_unit("sshd.service")
    client.wait_for_unit("multi-user.target")
    client.succeed(
        "systemd-run --unit testkey --setenv SKAGENT_TESTKEY_PIN=${pin}"
        " ${testkey}/bin/skagent-testkey --touch auto"
    )
    client.wait_until_succeeds("fido2-token -L | grep -F 'skagent test key' >/dev/null")

    with subtest("set up a verify-required key, the agent and the hosts"):
        alice(
            "SSH_ASKPASS=test-askpass SSH_ASKPASS_REQUIRE=force SKAGENT_TEST_ANSWER=${pin}"
            " ssh-keygen -q -t ed25519-sk -O resident -O verify-required"
            " -O application=ssh:example -N ''' -C alice@example.com -f ~/.ssh/id_sk"
        )
        public_key = alice("cat ~/.ssh/id_sk.pub").strip()
        for node in [jump, target]:
            node.succeed(
                "install -d -m 700 -o alice -g users /home/alice/.ssh"
                f" && echo {shlex.quote(public_key)} > /home/alice/.ssh/authorized_keys"
                " && chown alice:users /home/alice/.ssh/authorized_keys"
            )
        # Ed25519 host keys only, so the fingerprints below are the ones ssh uses.
        alice("ssh-keyscan -t ed25519 jump target > ~/.ssh/known_hosts 2>/dev/null")
        run_as_alice(jump, "install -d -m 700 ~/.ssh && ssh-keyscan -t ed25519 target > ~/.ssh/known_hosts 2>/dev/null")
        client.succeed("install -d -m 0700 -o alice -g users ${dir}")
        alice("umask 077 && echo ${pin} > ${dir}/pin")
        client.succeed(
            "systemd-run --unit skagent --uid alice"
            " --setenv SKAGENT_TEST_ANSWER_FILE=${dir}/pin"
            " --setenv SKAGENT_TEST_ASKPASS_LOG=${dir}/prompts"
            # No pairing: its first-use touch is vm-popup's subject.
            " ${package}/bin/skagent serve --log skagent=debug --no-pairing --socket ${socket}"
            " --askpass /run/current-system/sw/bin/test-askpass"
        )
        client.wait_for_file("${socket}")

    with subtest("ssh-add -K loads the resident key into skagent"):
        alice("SSH_ASKPASS=test-askpass SSH_ASKPASS_REQUIRE=force SKAGENT_TEST_ANSWER=${pin} SSH_AUTH_SOCK=${socket} ssh-add -K")
        listed = alice("SSH_AUTH_SOCK=${socket} ssh-add -L")
        assert public_key.split()[1] in listed, listed

    def host_key_fingerprint(node) -> str:
        return node.succeed("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub").split()[1]

    jump_key = host_key_fingerprint(jump)
    target_key = host_key_fingerprint(target)

    def signed(purpose: str) -> int:
        # The purpose is the last field of the line.
        return journal("skagent").count(f"purpose={purpose}\n")

    with subtest("direct logins: one PIN prompt naming the verified host, a touch for every login"):
        before = touches()
        assert "jump" in alice(ssh("jump", "hostname"))
        assert "target" in alice(ssh("target", "hostname"))
        assert touches() == before + 2, "every login needs a touch"
        assert prompts().count("Enter PIN") == 1, prompts()
        # The host comes from the session binding, verified by its host key.
        assert f'to log in as "alice" to the host with key {jump_key}, then touch' in prompts(), prompts()
        assert "bound the connection to an SSH session" in journal("skagent")
        assert signed(f'log in as "alice" to the host with key {target_key}') == 1

    with subtest("a forwarded agent lists the key and signs back on the client"):
        listed = alice(ssh("jump", "ssh-add -l", "-A"))
        assert "ED25519-SK" in listed, listed
        before = touches()
        out = alice(ssh("jump", f"{hop} target hostname", "-A"))
        assert "target" in out, out
        # Both logins were signed by the key on the client.
        assert touches() == before + 2, "forwarded signatures need a touch on the client"

    with subtest("ssh-add -h jump: usable on jump only, hidden everywhere else"):
        alice("SSH_AUTH_SOCK=${socket} ssh-add -h jump ~/.ssh/id_sk")
        assert "ED25519-SK" in alice("SSH_AUTH_SOCK=${socket} ssh-add -l"), "hidden on this machine"
        assert "jump" in alice(ssh("jump", "hostname"))
        assert signed('log in as "alice" to jump') == 1
        alice_fails(ssh("target", "hostname"))
        # Not a login, and not bound to a session: refused before the key.
        alice("echo hello > ~/msg")
        before = touches()
        alice_fails("SSH_AUTH_SOCK=${socket} ssh-keygen -Y sign -f ~/.ssh/id_sk.pub -n file ~/msg")
        assert touches() == before, "a refused signature reached the key"
        assert "only signs on connections bound to an SSH session" in journal("skagent")
        # Through the agent forwarded to jump the key is invisible: it may be
        # used at jump, not beyond.
        assert "no identities" in alice(ssh("jump", "ssh-add -l || true", "-A"))
        alice_fails(ssh("jump", f"{hop} target hostname", "-A"))

    with subtest("ssh-add -h jump -h 'jump>target': forwarded to target through jump"):
        alice("SSH_AUTH_SOCK=${socket} ssh-add -h jump -h 'jump>target' ~/.ssh/id_sk")
        assert "ED25519-SK" in alice(ssh("jump", "ssh-add -l", "-A"))
        before = touches()
        assert "target" in alice(ssh("jump", f"{hop} target hostname", "-A"))
        assert touches() == before + 2
        assert signed('log in as "alice" to target (through your agent forwarded to jump)') == 1
        # Forwarded once more from target, nothing allows the key there.
        listed = alice(ssh("jump", f"{hop} -A target 'ssh-add -l || true'", "-A"))
        assert "no identities" in listed, listed
        # Directly to target is still not allowed.
        alice_fails(ssh("target", "hostname"))

    with subtest("a forwarded agent can't make this machine prompt to load keys"):
        asked = prompts().count("Enter PIN")
        alice_fails(ssh("jump", 'skagent load --socket "$SSH_AUTH_SOCK"', "-A"))
        assert prompts().count("Enter PIN") == asked, "a remote host made the client prompt for a PIN"
        assert "only loaded on request from this machine" in journal("skagent")

    with subtest("a forwarded agent can't evict the PINs to time a prompt"):
        alice_fails(ssh("jump", 'skagent forget --socket "$SSH_AUTH_SOCK"', "-A"))
        assert "only on request from this machine, not through an SSH connection" in journal("skagent")

    with subtest("PINs never reach the journal"):
        assert "${pin}" not in journal("skagent")
  '';
}
