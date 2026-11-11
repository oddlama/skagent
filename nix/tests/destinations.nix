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
        alice("ssh-keyscan jump target > ~/.ssh/known_hosts 2>/dev/null")
        run_as_alice(jump, "install -d -m 700 ~/.ssh && ssh-keyscan target > ~/.ssh/known_hosts 2>/dev/null")
        client.succeed("install -d -m 0700 -o alice -g users ${dir}")
        alice("umask 077 && echo ${pin} > ${dir}/pin")
        client.succeed(
            "systemd-run --unit skagent --uid alice"
            " --setenv SKAGENT_TEST_ANSWER_FILE=${dir}/pin"
            " --setenv SKAGENT_TEST_ASKPASS_LOG=${dir}/prompts"
            " ${package}/bin/skagent serve --log skagent=debug --socket ${socket}"
            " --askpass /run/current-system/sw/bin/test-askpass"
        )
        client.wait_for_file("${socket}")

    with subtest("ssh-add -K loads the resident key into skagent"):
        alice("SSH_ASKPASS=test-askpass SSH_ASKPASS_REQUIRE=force SKAGENT_TEST_ANSWER=${pin} SSH_AUTH_SOCK=${socket} ssh-add -K")
        listed = alice("SSH_AUTH_SOCK=${socket} ssh-add -L")
        assert public_key.split()[1] in listed, listed

    with subtest("direct logins: one PIN prompt, a touch for every login"):
        before = touches()
        assert "jump" in alice(ssh("jump", "hostname"))
        assert "target" in alice(ssh("target", "hostname"))
        assert touches() == before + 2, "every login needs a touch"
        assert prompts().count("Enter PIN") == 1, prompts()

    with subtest("a forwarded agent lists the key and signs back on the client"):
        listed = alice(ssh("jump", "ssh-add -l", "-A"))
        assert "ED25519-SK" in listed, listed
        before = touches()
        out = alice(ssh("jump", f"{hop} target hostname", "-A"))
        assert "target" in out, out
        # Both logins were signed by the key on the client.
        assert touches() == before + 2, "forwarded signatures need a touch on the client"

    with subtest("PINs never reach the journal"):
        assert "${pin}" not in journal("skagent")
  '';
}
