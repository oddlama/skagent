# End to end: the real binary in a VM, driven by stock OpenSSH tools.
{ pkgs, package }:
let
  socketDir = "/run/skagent-alice";
  socket = "${socketDir}/agent.sock";
  lockPassphrase = "hunter2-lock-passphrase";
  # Every agent runs as a transient unit owned by alice. Trace logging is on,
  # so the redaction subtests prove the filter holds at the most verbose level.
  startAgent =
    unit:
    "systemd-run --unit ${unit} --uid alice --setenv SKAGENT_LOG=trace ${package}/bin/skagent serve --socket ${socket}";

  common = import ./common.nix { inherit pkgs; };
in
pkgs.testers.runNixOSTest {
  name = "skagent-agent";

  nodes.machine = {
    environment.systemPackages = [
      package
      common.makeSkStub
      common.oversizedMessage
      common.testAskpass
      pkgs.openssh
      pkgs.util-linux
    ];
    users.users = {
      alice.isNormalUser = true;
      bob.isNormalUser = true;
    };
  };

  testScript = ''
    import shlex

    def as_user(user: str, command: str) -> tuple[int, str]:
        return machine.execute(f"su - {user} -c {shlex.quote(command)} 2>&1")

    def alice(command: str) -> tuple[int, str]:
        return as_user("alice", f"SSH_AUTH_SOCK=${socket} {command}")

    def alice_ok(command: str) -> str:
        status, out = alice(command)
        assert status == 0, f"{command!r} exited {status}: {out}"
        return out

    def key_fields(line: str) -> str:
        """Key type and base64 blob, without the comment."""
        return " ".join(line.split()[:2])

    def ssh_add_list(prefix: str = "") -> tuple[int, str]:
        return machine.execute(f"{prefix} env SSH_AUTH_SOCK=${socket} ssh-add -l 2>&1")

    def has_no_identities() -> bool:
        status, out = alice("ssh-add -l")
        return status == 1 and "The agent has no identities." in out

    def assert_no_identities() -> None:
        status, out = alice("ssh-add -l")
        assert status == 1 and "The agent has no identities." in out, f"exited {status}: {out}"

    # Waiting happens in Python: the driver runs shell commands with pipefail,
    # so `cmd | grep -q` fails whenever cmd exits non-zero or gets SIGPIPE.
    def journal(unit: str) -> str:
        return machine.succeed(f"journalctl -u {unit} --no-pager -o cat")

    def wait_for_journal(unit: str, text: str) -> None:
        retry(lambda _last_try: text in journal(unit), timeout_seconds=30)

    # ssh-add -x/-X read the lock passphrase through askpass when forced to.
    lock = "SSH_ASKPASS=test-askpass SSH_ASKPASS_REQUIRE=force SKAGENT_TEST_ANSWER="

    machine.wait_for_unit("multi-user.target")
    machine.succeed("install -d -m 0700 -o alice -g users ${socketDir}")

    with subtest("the owner gets an empty identity list"):
        machine.succeed("${startAgent "skagent"}")
        machine.wait_for_file("${socket}")
        assert_no_identities()

    with subtest("the socket is private to its owner"):
        machine.succeed("test \"$(stat -c '%a %U' ${socket})\" = '600 alice'")
        status, out = as_user("bob", "SSH_AUTH_SOCK=${socket} ssh-add -l")
        assert status == 2, f"bob: ssh-add -l exited {status}: {out}"

    with subtest("root may connect, like with OpenSSH's ssh-agent"):
        status, out = ssh_add_list()
        assert status == 1, f"root: ssh-add -l exited {status}: {out}"

    with subtest("the peer check refuses other users even past the file permissions"):
        # bob with CAP_DAC_OVERRIDE gets through the socket's mode bits, so
        # only the agent's own peer credential check stands in the way.
        status, out = ssh_add_list(
            "setpriv --reuid=bob --regid=users --init-groups"
            " --inh-caps=+dac_override --ambient-caps=+dac_override"
        )
        # ssh-add exits 1 both for "no identities" and for a dropped
        # connection, so the message is what tells them apart.
        assert status != 0, f"bob with dac_override was served: {out}"
        assert "Permission denied" not in out, f"file permissions stopped bob, not the agent: {out}"
        assert "communication with agent failed" in out, f"bob with dac_override: exited {status}: {out}"
        wait_for_journal("skagent", "refused agent connection from another user")

    with subtest("sk key files are added, listed and removed with ssh-add"):
        alice_ok("make-sk-stub ~/work 1 'alice@example.com yubikey:1'")
        alice_ok("make-sk-stub ~/personal 2 'alice personal'")

        out = alice_ok("ssh-add ~/work ~/personal")
        assert out.count("Identity added") == 2, out

        listed = alice_ok("ssh-add -l").splitlines()
        expected = [
            alice_ok(f"ssh-keygen -lf ~/{name}").strip() for name in ["work", "personal"]
        ]
        assert listed == expected, f"ssh-add -l: {listed}, ssh-keygen -lf: {expected}"
        assert "alice@example.com yubikey:1 (ED25519-SK)" in listed[0], listed

        public = alice_ok("ssh-add -L").splitlines()
        derived = [alice_ok(f"ssh-keygen -y -f ~/{name}").strip() for name in ["work", "personal"]]
        assert [key_fields(line) for line in public] == [key_fields(line) for line in derived], (
            f"ssh-add -L: {public}, ssh-keygen -y: {derived}"
        )

        alice_ok("ssh-add -d ~/work")
        listed = alice_ok("ssh-add -l")
        assert "yubikey:1" not in listed and "alice personal" in listed, listed

        out = alice_ok("ssh-add -D")
        assert "All identities removed." in out, out
        assert_no_identities()

    with subtest("ssh-add -t removes the key when its lifetime ends"):
        out = alice_ok("ssh-add -t 2 ~/work")
        assert "Lifetime set to 00:00:02" in out, out
        assert "yubikey:1" in alice_ok("ssh-add -l")
        retry(lambda _last_try: has_no_identities(), timeout_seconds=15)
        assert "key lifetime ended" in journal("skagent")

    with subtest("keys added here are offered again after a restart, unless limited"):
        def restart() -> None:
            machine.succeed("systemctl stop skagent")
            machine.wait_until_fails("test -e ${socket}")
            machine.succeed("${startAgent "skagent"}")
            machine.wait_for_file("${socket}")

        alice_ok("make-sk-stub ~/limited 3 'alice limited'")
        # A host key for `ssh-add -h`, which looks hosts up in known_hosts.
        alice_ok(
            "mkdir -p ~/.ssh && ssh-keygen -q -t ed25519 -N ''' -f ~/hostkey"
            " && echo \"example.com $(cat ~/hostkey.pub)\" > ~/.ssh/known_hosts"
        )
        alice_ok("ssh-add ~/work ~/personal")
        alice_ok("ssh-add -t 600 ~/limited")
        # Added again with a destination: it mustn't come back without one.
        alice_ok("ssh-add -h example.com ~/personal")
        restart()
        listed = alice_ok("ssh-add -l")
        assert "yubikey:1" in listed, listed
        assert "alice personal" not in listed and "alice limited" not in listed, listed
        mode = machine.succeed("stat -c %a /home/alice/.local/state/skagent/keys.toml").strip()
        assert mode == "600", mode
        alice_ok("ssh-add -d ~/work")
        restart()
        assert_no_identities()
        alice_ok("ssh-add ~/work ~/personal")
        alice_ok("ssh-add -D")
        restart()
        assert_no_identities()

    with subtest("confirm constraints and non-sk keys are refused"):
        status, out = alice("ssh-add -c ~/work")
        assert status != 0 and "agent refused operation" in out, f"exited {status}: {out}"

        alice_ok("ssh-keygen -q -t ed25519 -N ''' -f ~/plain")
        status, out = alice("ssh-add ~/plain")
        assert status != 0 and "agent refused operation" in out, f"exited {status}: {out}"
        assert_no_identities()
        assert "only sk-ssh-ed25519@openssh.com keys are accepted" in journal("skagent")

    with subtest("a locked agent hides its keys until unlocked with the passphrase"):
        alice_ok("ssh-add ~/work")
        out = alice_ok(f"{lock}${lockPassphrase} ssh-add -x")
        assert "Agent locked." in out, out
        assert_no_identities()

        status, out = alice(f"{lock}wrong-guess ssh-add -X")
        assert status != 0 and "Failed to unlock agent: agent refused operation" in out, f"exited {status}: {out}"
        assert_no_identities()

        out = alice_ok(f"{lock}${lockPassphrase} ssh-add -X")
        assert "Agent unlocked." in out, out
        assert "yubikey:1" in alice_ok("ssh-add -l")
        alice_ok("ssh-add -D")

    with subtest("the agent process is hardened"):
        pid = machine.succeed("systemctl show -p MainPID --value skagent").strip()
        machine.succeed(f"grep -E '^Max core file size +0 +0 ' /proc/{pid}/limits")
        # Non-dumpable: not even the same user may read the process environment.
        status, _ = as_user("alice", f"cat /proc/{pid}/environ")
        assert status != 0, "alice could read the agent's environment"

    with subtest("secrets and protocol library debug output never reach the log"):
        agent_log = journal("skagent")
        # Positive control: the library's info output is bridged into the log...
        assert "Listening; socket" in agent_log, agent_log
        # ...but its per-request debug output is not, even at trace level.
        assert "Request:" not in agent_log, agent_log
        assert "${lockPassphrase}" not in agent_log, "lock passphrase in the journal"
        assert "wrong-guess" not in agent_log, "unlock guess in the journal"

    with subtest("an oversized message ends its connection, not the agent"):
        assert alice_ok("oversized-message ${socket}").strip() == "closed"
        wait_for_journal("skagent", "refused an agent message longer than allowed")
        alice_ok("ssh-add -l || test $? -eq 1")

    with subtest("a second agent on the same socket is refused"):
        status, out = as_user("alice", "skagent serve --socket ${socket}")
        assert status == 1, f"second agent exited {status}: {out}"
        assert "already listening" in out, out
        machine.succeed("test -S ${socket}")

    with subtest("SIGTERM shuts down cleanly and removes the socket"):
        machine.succeed("systemctl stop skagent")
        machine.fail("test -e ${socket}")
        assert "received SIGTERM, shutting down" in journal("skagent")

    with subtest("the socket of a killed agent is replaced on the next start"):
        machine.succeed("${startAgent "skagent-killed"}")
        machine.wait_for_file("${socket}")
        machine.succeed("systemctl kill --signal=KILL skagent-killed")
        machine.wait_until_fails("systemctl is-active skagent-killed")
        machine.succeed("test -S ${socket}")

        machine.succeed("${startAgent "skagent-restarted"}")
        wait_for_journal("skagent-restarted", "removing stale agent socket")
        wait_for_journal("skagent-restarted", "agent listening")
        assert_no_identities()
  '';
}
