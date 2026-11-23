# age-plugin-skagent for systems without the agent, end to end: rage and
# stock age as clients, the standalone plugin and the (virtual) security key,
# and no agent. The agent only runs to create the identities, as it would on
# the desktop they come from.
{
  pkgs,
  package,
  standalone,
  testkey,
}:
let
  common = import ./common.nix { inherit pkgs; };
  pin = "246810";
  dir = "/run/skagent-alice";
  socket = "${dir}/agent.sock";
  ageSocket = "${dir}/agent-age.sock";
  touchFile = "/run/testkey-touch";
  # The PIN the agent's askpass answers with.
  answerFile = "${dir}/pin";
  # What the age client's pinentry answers, a line per prompt, and what it
  # was asked.
  answers = "${dir}/answers";
  prompts = "${dir}/prompts";
  key = "YubiKey 12345678";
  # rage asks for secrets through a pinentry ...
  pinentry = pkgs.writers.writePython3Bin "standalone-pinentry" { } (
    builtins.readFile ./standalone-pinentry.py
  );
  # ... and age on the terminal.
  ptyAnswers = pkgs.writers.writePython3Bin "pty-answers" {
    libraries = [ pkgs.python3Packages.pexpect ];
  } (builtins.readFile ./pty-answers.py);
  # A system that has the standalone plugin and no agent: its plugin is the
  # one in PATH, and nothing names an agent's socket.
  environment = pkgs.lib.concatStringsSep " " [
    "PATH=${standalone}/bin:$PATH"
    "PINENTRY_PROGRAM=${pinentry}/bin/standalone-pinentry"
    "STANDALONE_ANSWERS=${answers}"
    "STANDALONE_PROMPTS=${prompts}"
  ];
in
pkgs.testers.runNixOSTest {
  name = "skagent-age-standalone";

  nodes.machine = {
    imports = [ common.virtualKeyMachine ];
    environment.systemPackages = [
      package
      testkey
      common.testAskpass
      ptyAnswers
      pkgs.age
      pkgs.libfido2
      pkgs.rage
    ];
    security.polkit.enable = true;
    # A logind session for alice, for the agent that creates the identities.
    services.getty.autologinUser = "alice";
    security.pam.services.login.rules.session.systemd.args = [ "type=wayland" ];
    users.users.alice.isNormalUser = true;
  };

  testScript = ''
    import re
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

    def cancels() -> int:
        return journal("testkey").count("outcome=Cancelled")

    def touch() -> None:
        machine.succeed("touch ${touchFile}")

    def asked() -> list[str]:
        """Every PIN prompt of the age client's pinentry so far, as a person read it."""
        return machine.succeed("cat ${prompts} 2>/dev/null || true").splitlines()

    def tries() -> int:
        device = machine.succeed("fido2-token -L | grep -F 'standalone key' | cut -d: -f1").strip()
        info = machine.succeed(f"fido2-token -I {device}")
        left = re.search(r"pin retries: (\d+)", info)
        assert left, info
        return int(left.group(1))

    def background(command: str) -> None:
        """Runs `command` as alice without waiting: its output goes to ~/out, its exit status to ~/status."""
        alice_ok("rm -f ~/out ~/status")
        script = f"sh -c {shlex.quote(command)} > ~/out 2>&1; echo $? > ~/status"
        machine.succeed(f"su - alice -c {shlex.quote(script)} >/dev/null 2>&1 &")

    def finished() -> tuple[int, str]:
        machine.wait_for_file("/home/alice/status")
        status = int(machine.succeed("cat /home/alice/status").strip())
        return status, machine.succeed("cat /home/alice/out")

    def touched_as_asked(command: str) -> tuple[int, str, int]:
        """Runs `command`, touching the key whenever it asks: its exit status, its output, and how many touches it took."""
        before = touches()
        given = 0
        background(command)
        while machine.execute("test -e /home/alice/status")[0] != 0:
            if touches() - before > given:
                touch()
                machine.wait_until_fails("test -e ${touchFile}", timeout=30)
                given += 1
        status, out = finished()
        return status, out, given

    def typing(*typed: str) -> None:
        """What the person types into the next PIN prompts, in order; after that they cancel."""
        lines = "".join(line + "\n" for line in typed)
        alice_ok(f"printf %s {shlex.quote(lines)} > ${answers}")

    def standalone(command: str, *typed: str) -> tuple[int, str, int, list[str]]:
        """Runs `command` where the standalone plugin is the one in PATH and no agent runs, touching the key whenever it asks. Its exit status, its output, how many touches it took and what its PIN prompts said."""
        typing(*typed)
        before = len(asked())
        status, out, touched = touched_as_asked("export ${environment}; " + command)
        assert "${pin}" not in out, out
        return status, out, touched, asked()[before:]

    def opened(out: str) -> str:
        """What a decryption printed, without the plugin's word about the touch, which rage shows."""
        return "\n".join(line for line in out.splitlines() if "when it blinks" not in line).strip()

    def start_agent() -> None:
        machine.succeed(
            "systemd-run --unit skagent --uid alice"
            " --setenv SKAGENT_TEST_ANSWER_FILE=${answerFile}"
            " ${package}/bin/skagent serve --no-pairing --no-touch-notification"
            " --askpass /run/current-system/sw/bin/test-askpass --socket ${socket}"
        )
        machine.wait_for_file("${socket}")
        machine.wait_for_file("${ageSocket}")

    def stop_agent() -> None:
        machine.succeed("systemctl stop skagent")
        machine.wait_until_fails("test -e ${socket}")
        machine.wait_until_fails("test -e ${ageSocket}")

    def new_identity(arguments: str = "") -> str:
        """Creates an age identity with the agent, which takes two touches, and returns its recipient."""
        status, out, _ = touched_as_asked(f"SKAGENT_AGE_SOCKET=${ageSocket} skagent age new {arguments}")
        assert status == 0, out
        recipient = out.splitlines()[0]
        assert re.fullmatch(r"age1pq1[a-z0-9]{1952}", recipient), recipient
        return recipient

    machine.wait_for_unit("multi-user.target")
    machine.wait_until_succeeds("loginctl show-user alice -p Sessions --value | grep . >/dev/null")
    machine.succeed(
        "systemd-run --unit testkey --setenv SKAGENT_TESTKEY_PIN=${pin}"
        " ${testkey}/bin/skagent-testkey --touch file --touch-file ${touchFile}"
        " --touch-timeout 3 --name 'standalone key' --serial 12345678"
    )
    machine.wait_until_succeeds("fido2-token -L | grep -F 'standalone key' >/dev/null")
    machine.succeed("install -d -m 0700 -o alice -g users ${dir}")
    machine.succeed("echo ${pin} > ${answerFile} && chown alice ${answerFile}")

    with subtest("on a desktop: an identity from the agent, files for it and for others"):
        start_agent()
        mine = new_identity()
        alice_ok(f"skagent age identity {mine} > ~/mine.txt")
        alice_ok(f"echo for-me | age -r {mine} -o ~/mine.age")
        # Two more people who may open a file, with keys of their own.
        others = []
        for name in ["first", "second"]:
            alice_ok(f"age-keygen -pq -o ~/{name}.key 2>/dev/null")
            other = alice_ok(f"age-keygen -y ~/{name}.key").strip()
            alice_ok(f"skagent age identity {other} > ~/{name}.txt")
            others.append(other)
        # The lines of everyone the file is for, the key's own last.
        alice_ok("cat ~/first.txt ~/second.txt ~/mine.txt > ~/everyone.txt")
        everyone = " ".join(f"-r {recipient}" for recipient in [*others, mine])
        alice_ok(f"echo for-everyone | age {everyone} -o ~/everyone.age")
        alice_ok(f"echo for-the-first | age -r {others[0]} -o ~/first.age")
        # Through the agent and its plugin, as on the desktop.
        status, out, touched = touched_as_asked("SKAGENT_AGE_SOCKET=${ageSocket} age -d -i ~/mine.txt ~/mine.age")
        assert (status, touched) == (0, 1) and out.strip().endswith("for-me"), out
        stop_agent()

    with subtest("without an agent: the same file for one PIN and one touch, with rage"):
        status, out, touched, said = standalone("rage -d -i ~/mine.txt ~/mine.age", "${pin}")
        assert (status, opened(out)) == (0, "for-me"), out
        assert touched == 1, touched
        # rage prints what the plugin says besides the prompt.
        assert out.count("touch ${key} when it blinks") == 1, out
        # The prompt is all a person may see: the key, the tries, the touch.
        assert said == ["PIN of ${key} (8 tries left), then touch it"], said
        assert machine.execute("pgrep -x skagent")[0] != 0, "an agent runs"

    with subtest("with age, which asks on the terminal"):
        status, out, touched, _ = standalone("pty-answers ${pin} -- age -d -i ~/mine.txt ~/mine.age")
        assert status == 0 and "for-me" in out, out
        assert "PIN of ${key} (8 tries left), then touch it" in out, out
        # What rage would print besides, a person at a terminal sees.
        assert "touch ${key} when it blinks" in out, out
        assert touched == 1, touched

    with subtest("the identity lines of everyone a file is for take one PIN and one touch"):
        # rage and age run the plugin once for each line, the key's own last
        # here: the first run opens the file with the key at hand.
        status, out, touched, said = standalone("rage -d -i ~/everyone.txt ~/everyone.age", "${pin}")
        assert (status, opened(out)) == (0, "for-everyone"), out
        assert (touched, len(said)) == (1, 1), (touched, said)
        status, out, touched, _ = standalone("pty-answers ${pin} -- age -d -i ~/everyone.txt ~/everyone.age")
        assert status == 0 and "for-everyone" in out, out
        assert (touched, out.count("tries left")) == (1, 1), (touched, out)
        # So a line that names somebody else doesn't keep the key from
        # opening what is encrypted to it.
        status, out, touched, said = standalone("rage -d -i ~/first.txt ~/mine.age", "${pin}")
        assert (status, opened(out)) == (0, "for-me"), out
        assert (touched, len(said)) == (1, 1), (touched, said)

    with subtest("it encrypts to an identity without a security key"):
        before = touches()
        status, out, _, said = standalone("echo by-the-plugin | rage -e -i ~/mine.txt -o ~/plugin.age")
        assert status == 0 and said == [] and touches() == before, out
        status, out, _, _ = standalone("rage -d -i ~/mine.txt ~/plugin.age", "${pin}")
        assert (status, opened(out)) == (0, "by-the-plugin"), out

    with subtest("a wrong PIN is asked for again in the same run, with the tries left"):
        status, out, touched, said = standalone("rage -d -i ~/mine.txt ~/mine.age", "000000", "${pin}")
        assert (status, opened(out)) == (0, "for-me"), out
        assert said == [
            "PIN of ${key} (8 tries left), then touch it",
            "Wrong PIN. PIN of ${key} (7 tries left), then touch it",
        ], said
        assert touched == 1, touched
        # The right one set the counter back.
        assert tries() == 8, tries()

    with subtest("an answer no PIN has the length of costs no try"):
        status, out, _, said = standalone("rage -d -i ~/mine.txt ~/mine.age", "123", "${pin}")
        assert (status, opened(out)) == (0, "for-me"), out
        assert said[1:] == ["A PIN has 4 to 63 characters. PIN of ${key} (8 tries left), then touch it"], said

    with subtest("a missed touch asks for the PIN again, and the touch after that opens the file"):
        typing("${pin}", "${pin}")
        before, touched = len(asked()), touches()
        background("export ${environment}; rage -d -i ~/mine.txt ~/mine.age")
        # Nobody touches the key: it gives up after 3 s, and the plugin asks
        # again. The touch for the second try is there when the key asks.
        retry(lambda _last_try: len(asked()) == before + 2, timeout_seconds=30)
        touch()
        status, out = finished()
        assert (status, opened(out)) == (0, "for-me"), out
        assert asked()[before:] == [
            "PIN of ${key} (8 tries left), then touch it",
            "${key} wasn't touched in time. PIN (8 tries left) to try again, then touch it",
        ], asked()[before:]
        assert touches() == touched + 2, touches() - touched

    with subtest("a missed touch and no PIN to try again end the run"):
        touched = touches()
        typing("${pin}")
        before = len(asked())
        background("export ${environment}; rage -d -i ~/mine.txt ~/mine.age")
        status, out = finished()
        assert status != 0, out
        assert "${key} wasn't touched in time, and no PIN was given to try again" in out, out
        assert len(asked()) == before + 2 and touches() == touched + 1, (asked()[before:], touches() - touched)

    with subtest("a file the key can't open ends the decryption after one PIN and one touch"):
        # Three lines: neither client runs the plugin again for the next
        # one, which would ask the same key the same.
        alice_ok("cat ~/first.txt ~/second.txt ~/first.txt > ~/others.txt")
        status, out, touched, said = standalone("rage -d -i ~/others.txt ~/first.age", "${pin}")
        assert status != 0 and "for-the-first" not in out, out
        assert "no age identity on ${key} opens this file" in out, out
        assert (touched, len(said)) == (1, 1), (touched, said)
        status, out, touched, _ = standalone("pty-answers ${pin} -- age -d -i ~/others.txt ~/first.age")
        assert status != 0 and "no age identity on ${key} opens this file" in out, out
        assert (touched, out.count("tries left")) == (1, 1), (touched, out)

    with subtest("an identity without data is refused before anyone is asked"):
        before = touches()
        status, out, _, said = standalone("rage -d -j skagent ~/mine.age", "${pin}")
        assert status != 0 and "identities that name their recipient" in out, out
        assert said == [] and touches() == before, (said, touches() - before)

    with subtest("the plugin's process is hardened, and lets go of the key when the age client goes away"):
        typing("${pin}")
        touched, cancelled = touches(), cancels()
        background("export ${environment}; exec rage -d -i ~/mine.txt ~/mine.age")
        retry(lambda _last_try: touches() == touched + 1, timeout_seconds=10)
        # By the name the process list has: its first 15 bytes.
        plugin = machine.succeed("pgrep -u alice -x age-plugin-skag").strip()
        machine.succeed(f"grep -E '^Max core file size +0 +0 ' /proc/{plugin}/limits")
        status, _ = alice(f"cat /proc/{plugin}/environ")
        assert status != 0, "alice could read the plugin's environment"
        machine.succeed("pkill -KILL -u alice -x rage")
        retry(lambda _last_try: cancels() == cancelled + 1, timeout_seconds=5)
        machine.wait_until_fails("pgrep -u alice -x age-plugin-skag", timeout=10)
        # Right away, the key isn't busy with a touch nobody waits for.
        status, out, _, _ = standalone("rage -d -i ~/mine.txt ~/mine.age", "${pin}")
        assert (status, opened(out)) == (0, "for-me"), out

    with subtest("told to end, the plugin lets go of the key first"):
        typing("${pin}")
        touched, cancelled = touches(), cancels()
        background("export ${environment}; exec rage -d -i ~/mine.txt ~/mine.age")
        retry(lambda _last_try: touches() == touched + 1, timeout_seconds=10)
        # As systemd stops a unit: every process of it at once.
        machine.succeed("pkill -TERM -u alice -x 'age-plugin-skag|rage'")
        retry(lambda _last_try: cancels() == cancelled + 1, timeout_seconds=5)
        machine.wait_until_fails("pgrep -u alice -x 'age-plugin-skag|rage'", timeout=10)
        status, out, _, _ = standalone("rage -d -i ~/mine.txt ~/mine.age", "${pin}")
        assert (status, opened(out)) == (0, "for-me"), out

    with subtest("with two security keys plugged in, no PIN is asked for"):
        machine.succeed(
            "systemd-run --unit otherkey --setenv SKAGENT_TESTKEY_PIN=135790"
            " ${testkey}/bin/skagent-testkey --name 'other key' --serial 87654321"
        )
        machine.wait_until_succeeds("fido2-token -L | grep -F 'other key' >/dev/null")
        before = touches()
        status, out, _, said = standalone("rage -d -i ~/mine.txt ~/mine.age", "${pin}")
        assert status != 0 and "several security keys are plugged in" in out, out
        assert "${key}" in out and "YubiKey 87654321" in out and "unplug all but the one to use" in out, out
        assert said == [] and touches() == before, (said, touches() - before)
        machine.succeed("systemctl stop otherkey")
        machine.wait_until_fails("fido2-token -L | grep -F 'other key' >/dev/null")

    with subtest("next to an agent it refuses, whatever it is asked"):
        before = touches()
        there = "SKAGENT_AGE_SOCKET=${ageSocket} "
        status, out, _, said = standalone(there + "rage -d -i ~/mine.txt ~/mine.age", "${pin}")
        assert status != 0 and "skagent runs here" in out and "has to be the one in PATH" in out, out
        assert said == [] and touches() == before, (said, touches() - before)
        status, out, _, _ = standalone(there + "sh -c 'echo no | rage -e -i ~/mine.txt -o ~/no.age'")
        assert status != 0 and "skagent runs here" in out, out

    with subtest("a second identity on the key: its credentials are tried in turn, a touch each"):
        start_agent()
        second = new_identity("--another")
        stop_agent()
        alice_ok(f"skagent age identity {second} > ~/also-mine.txt")
        alice_ok(f"echo for-me-too | age -r {second} -o ~/also-mine.age")
        # One of the two is the key's first credential, the other its second.
        total = 0
        for identity, file, content in [("mine", "mine", "for-me"), ("also-mine", "also-mine", "for-me-too")]:
            status, out, touched, said = standalone(f"rage -d -i ~/{identity}.txt ~/{file}.age", "${pin}")
            assert (status, opened(out)) == (0, content), out
            assert len(said) == 1, said
            total += touched
        assert total == 3, total

    with subtest("an identity that is named and opens nothing isn't the end, and has an error of its own"):
        alice_ok("cat ~/mine.txt ~/also-mine.txt > ~/both.txt")
        # Both of the key's identities are named; the file is for one.
        status, out, _, _ = standalone("rage -d -i ~/both.txt ~/also-mine.age", "${pin}")
        assert (status, opened(out)) == (0, "for-me-too"), out
        status, out, _, _ = standalone("rage -d -i ~/both.txt ~/mine.age", "${pin}")
        assert (status, opened(out)) == (0, "for-me"), out
        # And for neither.
        status, out, touched, said = standalone("rage -d -i ~/both.txt ~/first.age", "${pin}")
        assert status != 0 and "the file isn't encrypted to the identity on ${key}" in out, out
        assert "no age identity on" not in out, out
        assert (touched, len(said)) == (2, 1), (touched, said)

    with subtest("three wrong PINs in a row: the key takes no more until it is replugged"):
        before = touches()
        status, out, _, said = standalone("rage -d -i ~/mine.txt ~/mine.age", "000000", "111111", "222222", "${pin}")
        assert status != 0, out
        assert "${key} takes no more PINs after three wrong ones in a row: unplug it and plug it back in" in out, out
        assert [line.split(" PIN of ")[0] for line in said[1:]] == ["Wrong PIN.", "Wrong PIN."], said
        assert "(6 tries left)" in said[2], said
        assert touches() == before and tries() == 5, (touches() - before, tries())
  '';
}
