# The virtual security key against stock OpenSSH, without skagent. This
# validates the test harness: if OpenSSH can't use skagent-testkey like a
# YubiKey, no skagent VM test that relies on it means anything.
{ pkgs, testkey }:
let
  common = import ./common.nix { inherit pkgs; };
  pin = "246810";
  # The check that was run against real YubiKeys (docs/research/hmac-secret.md).
  hmacSecretCheck = ../../docs/research/hmac-secret-check.sh;
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
        assert status == 0, f"{command!r} exited {status}: {out!r}"
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

    with subtest("ssh-keygen downloads the resident key with its public key and UV policy"):
        alice_ok("mkdir ~/download")
        alice_ok("cd ~/download && ${askpass pin} ssh-keygen -K -N '''")
        recovered = "~/download/id_ed25519_sk_rk_example"
        original = alice_ok("ssh-keygen -lf ~/id_sk.pub").split()[1]
        assert alice_ok(f"ssh-keygen -lf {recovered}.pub").split()[1] == original
        alice_ok(f"rm -f ~/msg.sig && ${askpass pin} ssh-keygen -Y sign -f {recovered} -n test ~/msg")
        alice_ok("ssh-keygen -Y verify -f ~/allowed -I alice -n test -s ~/msg.sig < ~/msg")

    with subtest("stock ssh-agent asks for the PIN on every signature"):
        machine.succeed(
            "systemd-run --unit ssh-agent-alice --uid alice"
            " --setenv SSH_ASKPASS=test-askpass --setenv SSH_ASKPASS_REQUIRE=force"
            " --setenv SKAGENT_TEST_ANSWER=${pin} --setenv SKAGENT_TEST_ASKPASS_LOG=/tmp/agent-prompts"
            " --setenv PATH=/run/current-system/sw/bin"
            " ssh-agent -D -a /tmp/ssh-agent.sock"
        )
        machine.wait_for_file("/tmp/ssh-agent.sock")
        alice_ok("${askpass pin} SSH_AUTH_SOCK=/tmp/ssh-agent.sock ssh-add -K")
        assert original in alice_ok("SSH_AUTH_SOCK=/tmp/ssh-agent.sock ssh-add -l")
        for _ in range(2):
            alice_ok("rm -f ~/msg.sig && SSH_AUTH_SOCK=/tmp/ssh-agent.sock ssh-keygen -Y sign -f ~/id_sk.pub -n test ~/msg")
            alice_ok("ssh-keygen -Y verify -f ~/allowed -I alice -n test -s ~/msg.sig < ~/msg")
        prompts = machine.succeed("cat /tmp/agent-prompts")
        assert prompts.count("Enter PIN") == 2, f"expected one PIN prompt per signature: {prompts}"

    with subtest("hmac-secret answers like a YubiKey: never without a touch or the PIN"):
        before = touches()
        # Without a terminal, libfido2's tools read each PIN from stdin.
        status, out = machine.execute(
            "printf '%s\\n' ${pin} ${pin} ${pin} ${pin} ${pin}"
            " | su - alice -c 'bash ${hmacSecretCheck}' 2>&1"
        )
        assert status == 0, f"the check exited {status}: {out}"
        for expected in [
            "extension hmac-secret: listed",
            "created with hmac-secret and credProtect 3 (signed by the key): yes",
            "PIN + touch: ok, secret of 32 bytes",
            "two salts in one request: ok, 64 bytes",
            "same salt gives the same secret: yes",
            "another salt gives another secret: yes",
            "without touch: refused by the key (FIDO_ERR_UP_REQUIRED)",
            "without PIN: refused (FIDO_ERR_NO_CREDENTIALS), as expected",
            "delete: ok",
        ]:
            assert expected in out, f"{expected!r} missing from: {out}"
        assert touches() == before + 3, "creating and each of the two derivations take one touch"
        machine.succeed(
            "journalctl -u testkey --no-pager -o cat | grep -F 'refused hmac-secret without a touch' >/dev/null"
        )
  '';
}
