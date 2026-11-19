# age files with a key derived from a (virtual) security key, end to end:
# stock age and rage as clients, encrypting to the identity's recipient
# without skagent, and decrypting through age-plugin-skagent and the agent.
{
  pkgs,
  package,
  testkey,
}:
let
  common = import ./common.nix { inherit pkgs; };
  pin = "246810";
  socketDir = "/run/skagent-alice";
  socket = "${socketDir}/agent.sock";
  ageSocket = "${socketDir}/agent-age.sock";
  touchFile = "/run/testkey-touch";
  answerFile = "${socketDir}/pin";
  promptLog = "${socketDir}/prompts";
  # What the fake popup was shown; it answers with the PIN in the answer file.
  popupLog = "${socketDir}/log";
  # What alice's commands need to find the agent's socket for age requests.
  environment = "SKAGENT_AGE_SOCKET=${ageSocket}";
in
pkgs.testers.runNixOSTest {
  name = "skagent-age";

  nodes.machine = {
    imports = [ common.virtualKeyMachine ];
    environment.systemPackages = [
      package
      testkey
      common.fakePopup
      common.testAskpass
      pkgs.age
      pkgs.libfido2
      pkgs.openssh
      pkgs.rage
    ];
    security.polkit.enable = true;
    # A logind session for alice: PINs are only cached while lock and sleep
    # can be watched.
    services.getty.autologinUser = "alice";
    security.pam.services.login.rules.session.systemd.args = [ "type=wayland" ];
    users.users.alice.isNormalUser = true;
  };

  testScript = ''
    import json
    import re
    import shlex
    import time

    def alice(command: str) -> tuple[int, str]:
        return machine.execute(f"su - alice -c {shlex.quote('export ${environment}; ' + command)} 2>&1")

    def alice_ok(command: str) -> str:
        status, out = alice(command)
        assert status == 0, f"{command!r} exited {status}: {out}"
        return out

    def journal(unit: str) -> str:
        return machine.succeed(f"journalctl -u {unit} --no-pager -o cat")

    def messages(unit: str) -> str:
        # The journal without the time of day: its microseconds are six
        # digits, and now and then they spell a PIN.
        return re.sub(r"T\d\d:\d\d:\d\d\.\d+Z", "", journal(unit))

    def touches() -> int:
        return journal("testkey").count("touch requested")

    def cancels() -> int:
        return journal("testkey").count("outcome=Cancelled")

    def prompts() -> int:
        return machine.succeed("cat ${promptLog} 2>/dev/null || true").count("Enter PIN")

    def touch() -> None:
        machine.succeed("touch ${touchFile}")

    def background(command: str) -> None:
        """Runs `command` as alice without waiting: its output goes to ~/out, its exit status to ~/status."""
        alice_ok("rm -f ~/out ~/status")
        script = f"${environment} sh -c {shlex.quote(command)} > ~/out 2>&1; echo $? > ~/status"
        machine.succeed(f"su - alice -c {shlex.quote(script)} >/dev/null 2>&1 &")

    def finished() -> tuple[int, str]:
        machine.wait_for_file("/home/alice/status")
        status = int(machine.succeed("cat /home/alice/status").strip())
        return status, machine.succeed("cat /home/alice/out")

    def touching(command: str, count: int) -> tuple[int, str]:
        """Runs `command` and touches the key `count` times, each once the key took the one before."""
        background(command)
        for _ in range(count):
            touch()
            machine.wait_until_fails("test -e ${touchFile}", timeout=30)
        return finished()

    def decrypt(client: str, file: str, identity: str = "-i ~/id.txt") -> tuple[int, str]:
        """One decryption through the plugin, with one touch offered."""
        touch()
        return alice(f"{client} -d {identity} {file}")

    def expect(before: tuple[int, int], asked: int, touched: int, why: str) -> None:
        now = (prompts(), touches())
        assert now == (before[0] + asked, before[1] + touched), (why, before, now)

    def start_agent(unit: str, *args: str, popup: bool = False) -> None:
        prompt = "--popup /run/current-system/sw/bin/fake-popup" if popup else "--askpass /run/current-system/sw/bin/test-askpass"
        machine.succeed(
            f"systemd-run --unit {unit} --uid alice"
            " --setenv SKAGENT_TEST_ANSWER_FILE=${answerFile}"
            " --setenv SKAGENT_TEST_ASKPASS_LOG=${promptLog}"
            " --setenv SKAGENT_TEST_ASKPASS_GATE=${socketDir}/hold-prompt"
            " --setenv SKAGENT_TEST_POPUP_DIR=${socketDir}"
            " ${package}/bin/skagent serve --no-pairing --no-touch-notification"
            f" {prompt} --socket ${socket} {' '.join(args)}"
        )
        machine.wait_for_file("${socket}")
        machine.wait_for_file("${ageSocket}")
        retry(lambda _last_try: "machine sleeps (logind)" in journal(unit), timeout_seconds=10)

    def stop_agent(unit: str) -> None:
        machine.succeed(f"systemctl stop {unit}")
        machine.wait_until_fails("test -e ${socket}")
        machine.wait_until_fails("test -e ${ageSocket}")

    def fresh(stop: str, start: str, popup: bool = False) -> None:
        """A new machine, as far as the agent can tell: nothing remembered, and the key's two identities found by a load."""
        stop_agent(stop)
        alice_ok("rm -rf ~/.local/state/skagent")
        start_agent(start, popup=popup)
        out = alice_ok("skagent load --socket ${socket}")
        assert "Found 2 age identity(ies)." in out, out
        if popup:
            # The popup that asked for the load's PIN is gone before the next request.
            retry(lambda _last_try: popup_log()[-1:] == ["exit"], timeout_seconds=10)

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

    def popup_log() -> list[str]:
        return machine.succeed("cat ${popupLog} 2>/dev/null || true").splitlines()

    def shown(since: int) -> list[dict]:
        """The states the popup was shown since its log had `since` lines."""
        shows = [json.loads(line) for line in popup_log()[since:] if line.startswith("{")]
        return [message["state"] for message in shows if message["type"] == "show"]

    machine.wait_for_unit("multi-user.target")
    machine.wait_until_succeeds("loginctl show-user alice -p Sessions --value | grep . >/dev/null")
    machine.succeed(
        "systemd-run --unit testkey --setenv SKAGENT_TESTKEY_PIN=${pin}"
        " ${testkey}/bin/skagent-testkey --touch file --touch-file ${touchFile}"
        " --touch-timeout 3 --name 'test key one'"
    )
    machine.wait_until_succeeds("fido2-token -L | grep -F 'test key one' >/dev/null")
    machine.succeed("install -d -m 0700 -o alice -g users ${socketDir}")
    machine.succeed("install -m 0600 -o alice -g users /dev/null ${answerFile}")
    machine.succeed("echo ${pin} > ${answerFile}")
    start_agent("skagent")

    with subtest("the socket for age requests is private, like the ssh-agent socket"):
        assert machine.succeed("stat -c '%a %U' ${ageSocket}").strip() == "600 alice"
        assert "answering age requests" in journal("skagent")

    with subtest("no identity yet: nothing to list, and a file can't be decrypted"):
        status, out = alice("skagent age list")
        assert status == 0 and "No age identities known" in out, out
        alice_ok("age-keygen -pq -o ~/native.key 2>/dev/null")
        alice_ok("echo for-someone-else | age -r $(age-keygen -y ~/native.key) -o ~/other.age")
        before = (prompts(), touches())
        status, out = alice("age -d -j skagent ~/other.age")
        assert status != 0 and "knows no age identity" in out, out
        expect(before, 0, 0, "asked or touched without an identity")

    with subtest("creating an identity takes the PIN and two touches, and prints its recipient"):
        before = (prompts(), touches())
        status, out = touching("skagent age new", 2)
        assert status == 0, out
        recipient = out.splitlines()[0]
        assert re.fullmatch(r"age1pq1[a-z0-9]{1952}", recipient), recipient
        assert "Created an age identity" in out, out
        expect(before, 1, 2, "creating")
        key_log = journal("testkey")
        assert 'operation="makeCredential" rp_id="skagent:age"' in key_log, key_log
        assert "credential created rp_id=skagent:age discoverable=true cred_protect=3" in key_log, key_log
        assert alice_ok("skagent age list").strip() == recipient
        alice_ok("skagent age identity > ~/id.txt")
        identity = alice_ok("cat ~/id.txt")
        assert f"# Recipient: {recipient}\n" in identity, identity
        assert re.search(r"^AGE-PLUGIN-SKAGENT-1[A-Z0-9]+$", identity, re.MULTILINE), identity
        # The same file from the recipient alone, without the agent.
        assert alice_ok(f"SKAGENT_AGE_SOCKET=/nonexistent skagent age identity {recipient}") == identity

    with subtest("a second identity on the same key has to be asked for"):
        before = (prompts(), touches())
        status, out = alice("skagent age new")
        assert status != 0, out
        assert "holds an age identity already" in journal("skagent")
        # Like a load, creating asks for the PIN afresh; looking takes no touch.
        expect(before, 1, 0, "refusing a second identity")

    with subtest("stock age and rage encrypt to the recipient, without skagent"):
        stop_agent("skagent")
        alice_ok(f"echo from-age | age -r {recipient} -o ~/age.age")
        # rage has no native post-quantum recipient yet; age's plugin gives it one.
        alice_ok(f"echo from-rage | rage -r {recipient} -o ~/rage.age")
        alice_ok("echo from-the-identity | age -e -i ~/id.txt -o ~/identity.age")
        assert "mlkem768x25519" in alice_ok("age-inspect ~/identity.age")
        # Next to a native post-quantum recipient, never next to a classic one.
        alice_ok("echo for-both | age -e -i ~/id.txt -r $(age-keygen -y ~/native.key) -o ~/both.age")
        assert alice_ok("age -d -i ~/native.key ~/both.age").strip() == "for-both"
        # The same with rage, as agenix-rekey encrypts to a master identity
        # and a backup key.
        alice_ok("echo for-both-by-rage | rage -e -i ~/id.txt -r $(age-keygen -y ~/native.key) -o ~/rekey.age")
        assert alice_ok("age -d -i ~/native.key ~/rekey.age").strip() == "for-both-by-rage"
        alice_ok("age-keygen -o ~/classic.key 2>/dev/null")
        status, out = alice("echo no | age -e -i ~/id.txt -r $(age-keygen -y ~/classic.key) -o ~/mixed.age")
        assert status != 0 and "can't mix post-quantum and classic" in out, out
        status, out = alice("echo no | rage -e -i ~/id.txt -r $(age-keygen -y ~/classic.key) -o ~/mixed.age")
        assert status != 0 and "postquantum" in out, out
        start_agent("skagent")

    with subtest("the identity is remembered across a restart, its PIN isn't"):
        assert alice_ok("skagent age list").strip() == recipient
        before = (prompts(), touches())
        status, out = decrypt("age", "~/age.age")
        assert (status, out.strip()) == (0, "from-age"), out
        expect(before, 1, 1, "the first decryption after a restart")
        assert "Enter PIN for age identity (age1pq1" in machine.succeed("tail -n 1 ${promptLog}")
        assert "to decrypt a file for age, then touch the key" in machine.succeed("tail -n 1 ${promptLog}")

    with subtest("each further file takes one touch and no PIN, with age and with rage"):
        for client, file, content in [
            ("age", "~/rage.age", "from-rage"),
            ("rage", "~/age.age", "from-age"),
            ("rage", "~/identity.age", "from-the-identity"),
            ("age", "~/both.age", "for-both"),
            ("rage", "~/rekey.age", "for-both-by-rage"),
        ]:
            before = (prompts(), touches())
            status, out = decrypt(client, file)
            assert (status, out.strip()) == (0, content), (client, file, out)
            expect(before, 0, 1, f"{client} {file}")
        before = (prompts(), touches())
        status, out = decrypt("age", "~/age.age", "-j skagent")
        assert (status, out.strip()) == (0, "from-age"), out
        expect(before, 0, 1, "the identity at hand")
        assert journal("skagent").count("agent: decrypted") == 7

    with subtest("without a touch there is no file key"):
        touched = touches()
        status, out = alice("age -d -i ~/id.txt ~/age.age")
        assert status != 0 and "from-age" not in out, out
        assert "nobody answered in time" in out, out
        assert touches() == touched + 1

    with subtest("a file for someone else costs a touch and opens nothing"):
        before = (prompts(), touches())
        status, out = decrypt("age", "~/other.age")
        assert status != 0 and "for-someone-else" not in out, out
        expect(before, 0, 1, "a file for another recipient")
        assert "matched=false" in journal("skagent")

    with subtest("stanzas of two files in one request give one file key, for one touch"):
        # What a client would send that wanted two files for one touch: the
        # stanzas of both as if they were one file's.
        alice_ok(
            "{ echo '-> add-identity AGE-PLUGIN-SKAGENT-1W3SFA8'; echo;"
            " for file in ~/age.age ~/rage.age; do"
            "   head -n 3 $file | tail -n 2 | sed '1s/^-> /-> recipient-stanza 0 /';"
            " done; echo '-> done'; echo; printf -- '-> ok\\n\\n-> ok\\n\\n-> ok\\n\\n'; } > ~/transcript"
        )
        assert alice_ok("grep -c 'recipient-stanza 0 mlkem768x25519' ~/transcript").strip() == "2"
        before = (prompts(), touches())
        touch()
        out = alice_ok("age-plugin-skagent --age-plugin=identity-v1 < ~/transcript")
        assert out.count("-> file-key") == 1, out
        expect(before, 0, 1, "two files' stanzas")

    with subtest("forgetting the PINs during the touch ends the decryption"):
        touched, cancelled = touches(), cancels()
        background("age -d -i ~/id.txt ~/age.age")
        retry(lambda _last_try: touches() == touched + 1, timeout_seconds=10)
        alice_ok("skagent forget --socket ${socket}")
        status, out = finished()
        assert status != 0 and "the request was cancelled" in out, out
        retry(lambda _last_try: cancels() == cancelled + 1, timeout_seconds=5)
        asked = prompts()
        status, out = decrypt("age", "~/age.age")
        assert (status, out.strip()) == (0, "from-age"), out
        assert prompts() == asked + 1, "the PIN outlived skagent forget"

    with subtest("a client that goes away cancels its request on the key"):
        touched, cancelled = touches(), cancels()
        background("exec age -d -i ~/id.txt ~/age.age")
        retry(lambda _last_try: touches() == touched + 1, timeout_seconds=10)
        machine.succeed("pkill -u alice -x age")
        retry(lambda _last_try: cancels() == cancelled + 1, timeout_seconds=5)
        assert "the client disconnected" in journal("skagent")

    with subtest("a locked agent decrypts nothing"):
        lock = "SSH_ASKPASS=test-askpass SSH_ASKPASS_REQUIRE=force SKAGENT_TEST_ANSWER=lock-passphrase"
        alice_ok(f"{lock} SSH_AUTH_SOCK=${socket} ssh-add -x")
        before = (prompts(), touches())
        status, out = decrypt("age", "~/age.age")
        assert status != 0 and "skagent is locked" in out, out
        status, out = alice("skagent age list")
        assert status != 0, out
        expect(before, 0, 0, "a locked agent asked or touched")
        machine.succeed("rm -f ${touchFile}")
        alice_ok(f"{lock} SSH_AUTH_SOCK=${socket} ssh-add -X")

    with subtest("the ssh-agent socket answers no age request, the other socket nothing else"):
        status, out = alice("SKAGENT_AGE_SOCKET=${socket} age -d -i ~/id.txt ~/age.age")
        assert status != 0 and "doesn't take age requests on this connection" in out, out
        status, out = alice("SSH_AUTH_SOCK=${ageSocket} ssh-add -l")
        assert status != 0, out
        assert "the socket for age requests answers nothing else" in journal("skagent")

    with subtest("only skagent's own plugin is answered"):
        # The same program in another file isn't the plugin next to the agent.
        alice_ok("install -D ${package}/bin/age-plugin-skagent ~/copy/age-plugin-skagent")
        before = (prompts(), touches())
        status, out = alice("PATH=$HOME/copy:$PATH age -d -i ~/id.txt ~/age.age")
        assert status != 0 and "from-age" not in out, out
        assert "its program is neither skagent's plugin nor skagent itself" in journal("skagent")
        expect(before, 0, 0, "a stranger caused a prompt or a touch")

    with subtest("skagent load finds the identity on a fresh machine and takes its PIN"):
        stop_agent("skagent")
        alice_ok("rm -rf ~/.local/state/skagent")
        start_agent("skagent")
        status, out = alice("skagent age list")
        assert status == 0 and "No age identities known" in out, out
        before = (prompts(), touches())
        out = alice_ok("skagent load --socket ${socket}")
        assert "Loaded 0 resident SSH key(s)." in out and "Found 1 age identity(ies)." in out, out
        expect(before, 1, 0, "loading")
        # Known, but its recipient isn't derived on this machine yet.
        status, out = alice("skagent age list")
        assert status == 0 and "1 more identity(ies)" in out and "age1pq1" not in out, out

    with subtest("an identity file that names another key's recipient opens nothing"):
        # The key's identity could be the one named, as far as the agent
        # knows. The derivation says it isn't, and no stanza is tried.
        alice_ok("skagent age identity $(age-keygen -y ~/native.key) > ~/foreign.txt")
        status, out = decrypt("age", "~/other.age", "-i ~/foreign.txt")
        assert status != 0 and "holds another age identity" in out, out
        assert "for-someone-else" not in out, out
        expect(before, 1, 1, "the PIN the load took wasn't used")
        assert "matched=" not in journal("skagent").split("found age identities")[-1]
        # That told the agent which identity the key holds: the next request
        # for the other one fits nothing, and costs no touch.
        assert alice_ok("skagent age list").strip() == recipient
        status, out = alice("age -d -i ~/foreign.txt ~/other.age")
        assert status != 0 and "knows no age identity" in out, out
        expect(before, 1, 1, "a request that fits no identity asked or touched")
        status, out = decrypt("age", "~/age.age")
        assert (status, out.strip()) == (0, "from-age"), out
        expect(before, 1, 2, "decrypting after a load")

    with subtest("with two identities, a request has to name one"):
        before = (prompts(), touches())
        status, out = touching("skagent age new --another", 2)
        assert status == 0, out
        second = out.splitlines()[0]
        assert second != recipient and second.startswith("age1pq1"), out
        expect(before, 1, 2, "the second identity")
        assert sorted(alice_ok("skagent age list").split()) == sorted([recipient, second])
        status, out = alice("skagent age identity")
        assert status != 0 and "several age identities" in out, out
        alice_ok(f"skagent age identity {second} > ~/second.txt")
        alice_ok(f"echo for-the-second | age -r {second} -o ~/second.age")

        before = (prompts(), touches())
        status, out = alice("age -d -j skagent ~/second.age")
        assert status != 0 and "knows several age identities" in out, out
        expect(before, 0, 0, "an unnamed request asked or touched")

        status, out = decrypt("age", "~/second.age", "-i ~/second.txt")
        assert (status, out.strip()) == (0, "for-the-second"), out
        status, out = decrypt("age", "~/age.age", "-i ~/id.txt")
        assert (status, out.strip()) == (0, "from-age"), out
        # Each identity opens its own files only.
        status, out = decrypt("age", "~/second.age", "-i ~/id.txt")
        assert status != 0 and "for-the-second" not in out, out
        # Both identity files: the one that fits is used. The second touch
        # comes late, so age says meanwhile what the plugin waits for.
        before = (prompts(), touches())
        background("age -d -i ~/id.txt -i ~/second.txt ~/second.age")
        touch()
        retry(lambda _last_try: touches() == before[1] + 2, timeout_seconds=30)
        time.sleep(1.5)
        touch()
        status, out = finished()
        assert status == 0 and out.strip().splitlines()[-1] == "for-the-second", out
        assert out.count("waiting for skagent") == 1, out

    with subtest("a fresh machine finds the identity a request names among several, a touch each"):
        # Nothing tells two identities apart that were never used here but
        # the key's answers. The agent tries them in turn, and knows each
        # from then on: whichever it tries first, one of the two orders
        # below starts with the other one.
        files = {"second": ("~/second.age", "for-the-second"), "id": ("~/age.age", "from-age")}
        guesses = journal("skagent").count("is another one than the one named")
        asked = prompts()
        first_tries = []
        for one, other in [("second", "id"), ("id", "second")]:
            fresh("skagent", "skagent")
            status, out, taken = touched_as_asked(f"age -d -i ~/{one}.txt {files[one][0]}")
            assert (status, out.strip().splitlines()[-1]) == (0, files[one][1]), out
            first_tries.append(taken)
            # Whatever that took, both are known now, or the one left is.
            status, out, taken = touched_as_asked(f"age -d -i ~/{other}.txt {files[other][0]}")
            assert (status, out.strip().splitlines()[-1], taken) == (0, files[other][1], 1), (out, taken)
            assert sorted(alice_ok("skagent age list").split()) == sorted([recipient, second])
        assert sorted(first_tries) == [1, 2], first_tries
        assert journal("skagent").count("is another one than the one named") == guesses + 1
        # The PINs came with the two loads.
        assert prompts() == asked + 2, "asked for a PIN to try an identity"

    with subtest("the popup says what came of a decryption once that is known"):
        def outcome(since: int) -> list[tuple]:
            """Per state shown: its name, and what tells it from another of that name."""
            return [
                (state["name"], state["again"]) if state["name"] == "touch"
                else (state["name"], state.get("reason", state["request"]["kind"]))
                for state in shown(since)
            ]

        # Trying identities happens in one popup: "touch once more", and
        # "decrypted" only for the one that opened the file.
        sequences = []
        stop = "skagent"
        for one in ["second", "id"]:
            fresh(stop, "skagent-popup", popup=True)
            stop = "skagent-popup"
            mark = len(popup_log())
            status, out, taken = touched_as_asked(f"age -d -i ~/{one}.txt {files[one][0]}")
            assert (status, out.strip().splitlines()[-1]) == (0, files[one][1]), out
            retry(lambda _last_try: popup_log()[-1:] == ["exit"], timeout_seconds=10)
            assert popup_log()[mark:].count("start") == 1, popup_log()[mark:]
            sequences.append(outcome(mark))
        assert sorted(sequences) == [
            [("touch", False), ("signed", "decrypt")],
            [("touch", False), ("touch", True), ("signed", "decrypt")],
        ], sequences

        # A file for another identity of the key: the key does its part,
        # and nothing is decrypted.
        mark = len(popup_log())
        status, out, taken = touched_as_asked("age -d -i ~/id.txt ~/second.age")
        assert status != 0 and "for-the-second" not in out and taken == 1, (out, taken)
        retry(lambda _last_try: popup_log()[-1:] == ["exit"], timeout_seconds=10)
        assert outcome(mark) == [("touch", False), ("failed", "not-for-identity")], outcome(mark)

        # An identity no security key here holds. On a fresh machine the two
        # of this key could each be it: both are tried, and known afterwards.
        alice_ok("age-keygen -pq -o ~/foreign.key 2>/dev/null")
        foreign = alice_ok("age-keygen -y ~/foreign.key").strip()
        alice_ok(f"skagent age identity {foreign} > ~/foreign.txt")
        alice_ok(f"echo for-someone-else | age -r {foreign} -o ~/foreign.age")
        fresh("skagent-popup", "skagent-popup", popup=True)
        mark = len(popup_log())
        status, out, taken = touched_as_asked("age -d -i ~/foreign.txt ~/foreign.age")
        assert status != 0 and "for-someone-else" not in out and taken == 2, (out, taken)
        retry(lambda _last_try: popup_log()[-1:] == ["exit"], timeout_seconds=10)
        assert outcome(mark) == [("touch", False), ("touch", True), ("failed", "another-identity")], outcome(mark)
        assert sorted(alice_ok("skagent age list").split()) == sorted([recipient, second])
        # From then on such a request is refused before the key is asked.
        mark = len(popup_log())
        status, out, taken = touched_as_asked("age -d -i ~/foreign.txt ~/foreign.age")
        assert status != 0 and taken == 0, (out, taken)
        assert shown(mark) == [], shown(mark)
        # And what is this key's works as before.
        status, out, taken = touched_as_asked("age -d -i ~/id.txt ~/age.age")
        assert (status, out.strip().splitlines()[-1], taken) == (0, "from-age", 1), (out, taken)

    with subtest("PINs never reach the journal"):
        for unit in ["skagent", "skagent-popup"]:
            assert "${pin}" not in messages(unit), unit
        assert "lock-passphrase" not in messages("skagent")
        assert "${pin}" not in "\n".join(line for line in popup_log() if line.startswith("{")), "PIN in a message to the popup"
  '';
}
