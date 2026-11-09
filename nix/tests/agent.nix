# End to end: the real binary in a VM, driven by stock OpenSSH tools.
{ pkgs, package }:
let
  socketDir = "/run/skagent-alice";
  socket = "${socketDir}/agent.sock";
  # Every agent runs as a transient unit owned by alice. Trace logging is on,
  # so the redaction subtest proves the filter holds at the most verbose level.
  startAgent =
    unit:
    "systemd-run --unit ${unit} --uid alice --setenv SKAGENT_LOG=trace ${package}/bin/skagent serve --socket ${socket}";
in
pkgs.testers.runNixOSTest {
  name = "skagent-agent";

  nodes.machine = {
    environment.systemPackages = [
      package
      pkgs.openssh
      pkgs.util-linux
    ];
    users.users = {
      alice.isNormalUser = true;
      bob.isNormalUser = true;
    };
  };

  testScript = ''
    def as_user(user: str, command: str) -> str:
        return f"su - {user} -c '{command}'"

    def ssh_add_list(prefix: str = "") -> tuple[int, str]:
        return machine.execute(f"{prefix} env SSH_AUTH_SOCK=${socket} ssh-add -l 2>&1")

    machine.wait_for_unit("multi-user.target")
    machine.succeed("install -d -m 0700 -o alice -g users ${socketDir}")

    with subtest("the owner gets an empty identity list"):
        machine.succeed("${startAgent "skagent"}")
        machine.wait_for_file("${socket}")
        status, out = machine.execute(as_user("alice", "SSH_AUTH_SOCK=${socket} ssh-add -l"))
        assert status == 1, f"ssh-add -l exited {status}: {out}"
        assert "The agent has no identities." in out, out

    with subtest("the socket is private to its owner"):
        machine.succeed("test \"$(stat -c '%a %U' ${socket})\" = '600 alice'")
        status, out = machine.execute(as_user("bob", "SSH_AUTH_SOCK=${socket} ssh-add -l"))
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
        machine.wait_until_succeeds(
            "journalctl -u skagent --no-pager | grep -q 'refused agent connection from another user'"
        )

    with subtest("the agent process is hardened"):
        pid = machine.succeed("systemctl show -p MainPID --value skagent").strip()
        machine.succeed(f"grep -E '^Max core file size +0 +0 ' /proc/{pid}/limits")
        # Non-dumpable: not even the same user may read the process environment.
        machine.fail(as_user("alice", f"cat /proc/{pid}/environ"))

    with subtest("protocol library debug output never reaches the log"):
        journal = machine.succeed("journalctl -u skagent --no-pager -o cat")
        # Positive control: the library's info output is bridged into the log...
        assert "Listening; socket" in journal, journal
        # ...but its per-request debug output is not, even at trace level.
        assert "Request:" not in journal, journal

    with subtest("a second agent on the same socket is refused"):
        status, out = machine.execute(as_user("alice", "skagent serve --socket ${socket} 2>&1"))
        assert status == 1, f"second agent exited {status}: {out}"
        assert "already listening" in out, out
        machine.succeed("test -S ${socket}")

    with subtest("SIGTERM shuts down cleanly and removes the socket"):
        machine.succeed("systemctl stop skagent")
        machine.fail("test -e ${socket}")
        journal = machine.succeed("journalctl -u skagent --no-pager -o cat")
        assert "received SIGTERM, shutting down" in journal, journal

    with subtest("the socket of a killed agent is replaced on the next start"):
        machine.succeed("${startAgent "skagent-killed"}")
        machine.wait_for_file("${socket}")
        machine.succeed("systemctl kill --signal=KILL skagent-killed")
        machine.wait_until_fails("systemctl is-active skagent-killed")
        machine.succeed("test -S ${socket}")

        machine.succeed("${startAgent "skagent-restarted"}")
        machine.wait_until_succeeds(
            "journalctl -u skagent-restarted --no-pager | grep -q 'removing stale agent socket'"
        )
        machine.wait_until_succeeds(
            "journalctl -u skagent-restarted --no-pager | grep -q 'agent listening'"
        )
        status, out = machine.execute(as_user("alice", "SSH_AUTH_SOCK=${socket} ssh-add -l"))
        assert status == 1, f"ssh-add -l after restart exited {status}: {out}"
  '';
}
