# The virtual security key against stock OpenSSH, without skagent. This
# validates the test harness: if OpenSSH can't use skagent-testkey like a
# YubiKey, no skagent VM test that relies on it means anything.
{ pkgs, testkey }:
let
  common = import ./common.nix { inherit pkgs; };
  pin = "246810";
  askpass =
    answer: "SSH_ASKPASS=test-askpass SSH_ASKPASS_REQUIRE=force SKAGENT_TEST_ANSWER=${answer}";
in
pkgs.testers.runNixOSTest {
  name = "skagent-testkey";

  nodes.machine = {
    imports = [ common.virtualKeyMachine ];
    environment.systemPackages = [
      testkey
      common.testAskpass
      pkgs.libfido2
      pkgs.openssh
    ];
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

    def touches() -> int:
        log = machine.succeed("journalctl -u testkey --no-pager -o cat")
        return log.count("touch requested")

    machine.wait_for_unit("multi-user.target")

    with subtest("the virtual key shows up as a FIDO device"):
        machine.succeed(
            "systemd-run --unit testkey --setenv SKAGENT_TESTKEY_PIN=${pin}"
            " ${testkey}/bin/skagent-testkey --touch auto"
        )
        machine.wait_until_succeeds("fido2-token -L | grep -F 'skagent test key' >/dev/null")
        device = machine.succeed("fido2-token -L").split(":")[0]
        info = machine.succeed(f"fido2-token -I {device}")
        for expected in ["credProtect", "rk", "clientPin", "eddsa"]:
            assert expected in info, f"{expected} missing from: {info}"

    with subtest("ssh-keygen enrolls a resident verify-required ed25519-sk key"):
        before = touches()
        alice_ok(
            "${askpass pin} ssh-keygen -q -t ed25519-sk -O resident -O verify-required"
            " -O application=ssh:example -N ''' -C alice@virtual -f ~/id_sk"
        )
        assert touches() == before + 1, "enrollment did not take exactly one touch"
        machine.succeed("journalctl -u testkey --no-pager -o cat | grep -F 'cred_protect=3' >/dev/null")

    with subtest("signing needs the PIN and one touch, and verifies"):
        alice_ok("echo hello > ~/msg")
        before = touches()
        alice_ok("${askpass pin} ssh-keygen -Y sign -f ~/id_sk -n test ~/msg")
        assert touches() == before + 1, "signing did not take exactly one touch"
        alice_ok("echo \"alice $(cat ~/id_sk.pub)\" > ~/allowed")
        out = alice_ok("ssh-keygen -Y verify -f ~/allowed -I alice -n test -s ~/msg.sig < ~/msg")
        assert "Good" in out, out

    with subtest("a wrong PIN fails and costs a retry"):
        alice_ok("rm ~/msg.sig")
        status, out = alice("${askpass "000000"} ssh-keygen -Y sign -f ~/id_sk -n test ~/msg")
        assert status != 0, f"signed with a wrong PIN: {out}"
        info = machine.succeed(f"fido2-token -I {device}")
        assert "pin retries: 7" in info, info

    # Not covered: ssh-keygen -K / ssh-add -K. soft-fido2 0.17 leaves publicKey
    # and credProtect out of its credential management listing, so OpenSSH
    # sees "key type 0" and downloads nothing. See docs/research/test-key.md.

    with subtest("stock ssh-agent asks for the PIN on every signature"):
        machine.succeed(
            "systemd-run --unit ssh-agent-alice --uid alice"
            " --setenv SSH_ASKPASS=test-askpass --setenv SSH_ASKPASS_REQUIRE=force"
            " --setenv SKAGENT_TEST_ANSWER=${pin} --setenv SKAGENT_TEST_ASKPASS_LOG=/tmp/agent-prompts"
            " --setenv PATH=/run/current-system/sw/bin"
            " ssh-agent -D -a /tmp/ssh-agent.sock"
        )
        machine.wait_for_file("/tmp/ssh-agent.sock")
        alice_ok("SSH_AUTH_SOCK=/tmp/ssh-agent.sock ssh-add ~/id_sk")
        for _ in range(2):
            alice_ok("rm -f ~/msg.sig && SSH_AUTH_SOCK=/tmp/ssh-agent.sock ssh-keygen -Y sign -f ~/id_sk.pub -n test ~/msg")
            alice_ok("ssh-keygen -Y verify -f ~/allowed -I alice -n test -s ~/msg.sig < ~/msg")
        prompts = machine.succeed("cat /tmp/agent-prompts")
        assert prompts.count("Enter PIN") == 2, f"expected one PIN prompt per signature: {prompts}"
  '';
}
