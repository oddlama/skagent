# Signing through skagent with a (virtual) security key, end to end: stock
# ssh-keygen and ssh as clients, a real sshd as the server.
{
  pkgs,
  package,
  testkey,
}:
let
  common = import ./common.nix { inherit pkgs; };
  pin = "246810";
  socket = "/run/skagent-alice/agent.sock";
  touchFile = "/run/testkey-touch";
  # In alice's private directory: with fs.protected_regular, root may not
  # write into another user's files in the sticky /tmp.
  answerFile = "/run/skagent-alice/pin";
  promptLog = "/run/skagent-alice/prompts";
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
      pkgs.libfido2
      pkgs.openssh
    ];
    services.openssh.enable = true;
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
        return machine.succeed("cat ${promptLog} 2>/dev/null || true").count("Enter PIN")

    def touch() -> None:
        machine.succeed("touch ${touchFile}")

    def pin_retries() -> str:
        device = machine.succeed("fido2-token -L | grep -F 'test key one' | cut -d: -f1").strip()
        return machine.succeed(f"fido2-token -I {device}")

    def sign() -> tuple[int, str]:
        return alice("rm -f ~/msg.sig && SSH_AUTH_SOCK=${socket} ssh-keygen -Y sign -f ~/id_sk.pub -n test ~/msg")

    machine.wait_for_unit("sshd.service")
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

    with subtest("skagent holds the key"):
        machine.succeed("install -d -m 0700 -o alice -g users /run/skagent-alice")
        machine.succeed("install -m 0600 -o alice -g users /dev/null ${answerFile}")
        machine.succeed("echo ${pin} > ${answerFile}")
        machine.succeed(
            "systemd-run --unit skagent --uid alice"
            " --setenv SKAGENT_TEST_ANSWER_FILE=${answerFile}"
            " --setenv SKAGENT_TEST_ASKPASS_LOG=${promptLog}"
            " ${package}/bin/skagent serve --socket ${socket}"
            " --askpass /run/current-system/sw/bin/test-askpass"
        )
        machine.wait_for_file("${socket}")
        alice_ok("SSH_AUTH_SOCK=${socket} ssh-add ~/id_sk")
        assert "alice@virtual (ED25519-SK)" in alice_ok("SSH_AUTH_SOCK=${socket} ssh-add -l")

    with subtest("a signature takes the PIN and one touch, and verifies"):
        before = (prompts(), touches())
        touch()
        status, out = sign()
        assert status == 0, f"signing failed: {out}"
        out = alice_ok("ssh-keygen -Y verify -f ~/allowed -I alice -n test -s ~/msg.sig < ~/msg")
        assert "Good" in out, out
        assert (prompts(), touches()) == (before[0] + 1, before[1] + 1), (before, prompts(), touches())

    with subtest("ssh logs into sshd with the key, and sshd sees the PIN was used"):
        touch()
        out = alice_ok(
            "ssh -o IdentityAgent=${socket} -o IdentitiesOnly=yes -i ~/id_sk.pub"
            " -o StrictHostKeyChecking=accept-new -o BatchMode=yes localhost echo logged-in"
        )
        assert "logged-in" in out, out

    with subtest("without a touch there is no signature"):
        before = touches()
        status, out = sign()
        assert status != 0, f"signed without a touch: {out}"
        assert touches() == before + 1
        assert "TimedOut" in journal("testkey"), journal("testkey")

    with subtest("a wrong PIN is refused, costs one retry and is reported"):
        machine.succeed("echo 000000 > ${answerFile}")
        status, out = sign()
        assert status != 0, f"signed with a wrong PIN: {out}"
        assert "pin retries: 7" in pin_retries(), pin_retries()
        assert "wrong PIN" in journal("skagent") and "retries=7" in journal("skagent"), journal("skagent")

        machine.succeed("echo ${pin} > ${answerFile}")
        touch()
        status, out = sign()
        assert status == 0, f"signing with the right PIN failed: {out}"
        assert "pin retries: 8" in pin_retries(), pin_retries()

    with subtest("with two security keys connected skagent refuses to guess"):
        machine.succeed("${startTestkey "testkey-two" "test key two"}")
        machine.wait_until_succeeds("fido2-token -L | grep -F 'test key two' >/dev/null")
        before = prompts()
        status, out = sign()
        assert status != 0, f"signed with two keys connected: {out}"
        assert "2 FIDO security keys are connected" in journal("skagent"), journal("skagent")
        assert prompts() == before, "asked for a PIN without knowing the device"
        machine.succeed("systemctl stop testkey-two")

    with subtest("the PIN never reaches the journal"):
        assert "${pin}" not in journal("skagent"), "PIN in the skagent journal"
  '';
}
