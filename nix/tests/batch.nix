# Batches of decryptions (skagent batch), end to end with stock age and a
# (virtual) security key: many files for one touch, who is a member of a
# batch, every way a batch ends, and the notification that shows a running
# batch and stops it.
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
  # While this exists, the test key is unplugged (skagent-testkey --unplugged-file).
  unpluggedFile = "/run/testkey-unplugged";
  answerFile = "${socketDir}/pin";
  promptLog = "${socketDir}/prompts";
  popupLog = "${socketDir}/log";
  notifications = common.notificationSetup socketDir;
  notificationLog = "${socketDir}/notifications";
  # What alice's commands need to find the agent's socket for age requests.
  environment = "SKAGENT_AGE_SOCKET=${ageSocket}";

  # What batches run, installed in alice's home so the prompts name them
  # by short commands.
  scripts = {
    # Decrypts the files named, one after the other.
    decrypt-all = ''
      for file in "$@"; do
        age -d -i ~/id.txt ~/"$file" || exit 1
      done
    '';
    # Decrypts a file, says so, and goes on with two more once told to.
    gated = ''
      age -d -i ~/id.txt ~/f1.age || exit 1
      touch ~/first
      while [ ! -e ~/go ]; do sleep 0.1; done
      age -d -i ~/id.txt ~/f2.age || exit 1
      age -d -i ~/id.txt ~/f3.age
    '';
    # Three decryptions at once.
    at-once = ''
      for number in 1 2 3; do
        age -d -i ~/id.txt ~/f$number.age > ~/at-once-$number 2>&1 &
      done
      wait
      cat ~/at-once-1 ~/at-once-2 ~/at-once-3
    '';
    # Leaves a process behind that decrypts once this script decrypted: the
    # shell that started it exits at once, so it is nobody's child any more.
    orphan = ''
      rm -f ~/first ~/orphan-done
      echo $PPID > ~/tool-pid
      (sh -c '
        while [ ! -e ~/first ]; do sleep 0.1; done
        cut -d" " -f4 /proc/$$/stat > ~/orphan-parent
        age -d -i ~/id.txt ~/f3.age > ~/orphan-out 2>&1
        touch ~/orphan-done
      ' &)
      age -d -i ~/id.txt ~/f1.age || exit 1
      touch ~/first
      while [ ! -e ~/orphan-done ]; do sleep 0.1; done
      cat ~/orphan-out
    '';
  };
  installScripts = pkgs.lib.concatStringsSep "\n" (
    pkgs.lib.mapAttrsToList (
      name: text:
      "install -m 0755 -o alice -g users ${pkgs.writeShellScript name text} /home/alice/${name}"
    ) scripts
  );
in
pkgs.testers.runNixOSTest {
  name = "skagent-batch";

  nodes.machine = {
    imports = [ common.virtualKeyMachine ];
    environment.systemPackages = [
      package
      testkey
      common.fakeNotifications
      common.fakePopup
      common.testAskpass
      pkgs.age
      pkgs.libfido2
      pkgs.openssh
    ];
    security.polkit.enable = true;
    # A logind session for alice: nothing is kept, PINs or a batch's key,
    # unless lock and sleep can be watched. Lock needs a graphical session.
    services.getty.autologinUser = "alice";
    security.pam.services.login.rules.session.systemd.args = [ "type=wayland" ];
    users.users.alice.isNormalUser = true;
  };

  testScript = ''
    import json
    import re
    import shlex
    from collections.abc import Callable

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

    def prompts() -> int:
        return machine.succeed("cat ${promptLog} 2>/dev/null || true").count("Enter PIN")

    def last_prompt() -> str:
        return machine.succeed("tail -n 1 ${promptLog}")

    def touch() -> None:
        machine.succeed("touch ${touchFile}")

    def touch_times(count: int) -> None:
        """Touches the key `count` times, each once it took the one before."""
        for _ in range(count):
            touch()
            machine.wait_until_fails("test -e ${touchFile}", timeout=30)

    def background(command: str) -> None:
        """Runs `command` as alice without waiting: its output goes to ~/out, its exit status to ~/status."""
        alice_ok("rm -f ~/out ~/status ~/first ~/go")
        script = f"${environment} sh -c {shlex.quote(command)} > ~/out 2>&1; echo $? > ~/status"
        machine.succeed(f"su - alice -c {shlex.quote(script)} >/dev/null 2>&1 &")

    def finished() -> tuple[int, str]:
        machine.wait_for_file("/home/alice/status")
        status = int(machine.succeed("cat /home/alice/status").strip())
        return status, machine.succeed("cat /home/alice/out")

    def decrypted(out: str) -> list[str]:
        """The files in a command's output, without what age says while the plugin waits for a late touch."""
        return [line for line in out.splitlines() if line.startswith("file-")]

    def expect(before: tuple[int, int], asked: int, touched: int, why: str) -> None:
        now = (prompts(), touches())
        assert now == (before[0] + asked, before[1] + touched), (why, before, now)

    def kept_keys(unit: str) -> int:
        """How many secrets the agent keeps in memfd_secret memory: with its PINs in locked memory, the keys batches keep."""
        pid = machine.succeed(f"systemctl show {unit} -p MainPID --value").strip()
        return int(machine.succeed(f"grep -c secretmem /proc/{pid}/smaps || true").strip())

    def ended(unit: str, reason: str) -> int:
        return journal(unit).count(f"reason={reason}")

    def notified() -> list[str]:
        return machine.succeed("cat ${notificationLog} 2>/dev/null || true").splitlines()

    def notification_of(command: str) -> str:
        """The number of the notification that shows the batch for `command` last."""
        shown = [line.split()[1] for line in notified() if line.startswith("notify ") and f" skagent batch: {command} | " in line]
        assert shown, (command, notified())
        return shown[-1]

    def untouched(file: str, why: str) -> None:
        """A decryption that isn't a batch's waits for a touch, and gets no file key without it."""
        before = (prompts(), touches())
        status, out = alice(f"age -d -i ~/id.txt ~/{file}")
        assert status != 0 and "nobody answered in time" in out, (why, out)
        expect(before, 0, 1, why)

    def unplug() -> None:
        machine.succeed("touch ${unpluggedFile}")
        machine.wait_until_fails("fido2-token -L | grep -F 'batch key' >/dev/null", timeout=10)

    def plug_in() -> None:
        machine.succeed("rm -f ${unpluggedFile}")
        machine.wait_until_succeeds("fido2-token -L | grep -F 'batch key' >/dev/null", timeout=10)

    def start_agent(unit: str, *args: str) -> None:
        machine.succeed(
            f"systemd-run --unit {unit} --uid alice"
            " --setenv SKAGENT_TEST_ANSWER_FILE=${answerFile}"
            " --setenv SKAGENT_TEST_ASKPASS_LOG=${promptLog}"
            " --setenv SKAGENT_TEST_POPUP_DIR=${socketDir}"
            " --setenv DBUS_SESSION_BUS_ADDRESS=${notifications.address}"
            " ${package}/bin/skagent serve --no-pairing"
            f" --socket ${socket} {' '.join(args)}"
        )
        machine.wait_for_file("${socket}")
        machine.wait_for_file("${ageSocket}")
        retry(lambda _last_try: "machine sleeps (logind)" in journal(unit), timeout_seconds=10)

    def stop_agent(unit: str) -> None:
        machine.succeed(f"systemctl stop {unit}")
        machine.wait_until_fails("test -e ${socket}")
        machine.wait_until_fails("test -e ${ageSocket}")

    def interrupted(evict: Callable[[], None], reason: str, pins: int) -> None:
        """A batch decrypts a file. Then `evict` ends it for `reason`: its key is wiped while its command still runs, and the command's two further files take a touch each, and `pins` PINs."""
        was = ended("skagent", reason)
        background("skagent batch -- ./gated")
        touch()
        machine.wait_for_file("/home/alice/first")
        assert kept_keys("skagent") == 1, reason
        evict()
        retry(lambda _last_try: kept_keys("skagent") == 0, timeout_seconds=40)
        retry(lambda _last_try: ended("skagent", reason) == was + 1, timeout_seconds=10)
        before = (prompts(), touches())
        alice_ok("touch ~/go")
        touch_times(2)
        status, out = finished()
        assert status == 0 and decrypted(out) == ["file-1", "file-2", "file-3"], (reason, out)
        expect(before, pins, 2, reason)
        if pins:
            # Asked like for any single file: the batch is over for good.
            assert "to decrypt a file for gated, then touch the key" in last_prompt(), last_prompt()

    machine.wait_for_unit("multi-user.target")
    machine.wait_until_succeeds("loginctl show-user alice -p Sessions --value | grep . >/dev/null")
    machine.succeed(
        "systemd-run --unit testkey --setenv SKAGENT_TESTKEY_PIN=${pin}"
        " ${testkey}/bin/skagent-testkey --touch file --touch-file ${touchFile}"
        " --touch-timeout 3 --name 'batch key' --serial 12345678"
        " --unplugged-file ${unpluggedFile}"
    )
    machine.wait_until_succeeds("fido2-token -L | grep -F 'batch key' >/dev/null")
    machine.succeed("install -d -m 0700 -o alice -g users ${socketDir}")
    machine.succeed("install -m 0600 -o alice -g users /dev/null ${answerFile}")
    machine.succeed("echo ${pin} > ${answerFile}")
    machine.succeed("""
    ${installScripts}
    """)
    machine.succeed("${builtins.elemAt notifications.start 0}")
    machine.wait_for_file("${socketDir}/bus")
    machine.succeed("${builtins.elemAt notifications.start 1}")
    machine.wait_until_succeeds("${notifications.ready}")
    # Notifications for touches are off; a batch has its own.
    askpass = "--no-touch-notification --askpass /run/current-system/sw/bin/test-askpass"
    start_agent("skagent", askpass)

    with subtest("an identity, and five files encrypted to it"):
        background("skagent age new")
        touch_times(2)
        status, out = finished()
        assert status == 0, out
        recipient = out.splitlines()[0]
        alice_ok("skagent age identity > ~/id.txt")
        for number in range(1, 6):
            alice_ok(f"echo file-{number} | age -r {recipient} -o ~/f{number}.age")
        assert kept_keys("skagent") == 0

    with subtest("a batch decrypts many files for one PIN and one touch, and says so when it asks"):
        alice_ok("skagent forget --socket ${socket}")
        before = (prompts(), touches())
        touch()
        out = alice_ok("skagent batch -- ./decrypt-all f1.age f2.age f3.age f4.age f5.age")
        assert out.split() == [f"file-{number}" for number in range(1, 6)], out
        expect(before, 1, 1, "five files in a batch")
        asked = last_prompt()
        assert "Enter PIN for age identity (age1pq1" in asked, asked
        assert (
            'to decrypt the files "./decrypt-all f1.age f2.age f3.age f4.age f5.age" asks for,'
            " without another touch, for up to 10 minutes (a batch), then touch the key"
        ) in asked, asked
        agent_log = journal("skagent")
        assert "opened a batch" in agent_log and "the batch started" in agent_log, agent_log
        assert agent_log.count("decrypted in a batch, without a touch") == 4, agent_log
        retry(lambda _last_try: "closed the batch: its command is done" in journal("skagent"), timeout_seconds=5)
        assert "files=5" in journal("skagent")

    with subtest("a notification shows the batch while it runs, with a button to stop it"):
        command = "./decrypt-all f1.age f2.age f3.age f4.age f5.age"
        number = notification_of(command)
        shown = notified()
        first = [line for line in shown if line.startswith(f"notify {number} ")][0]
        assert re.fullmatch(
            rf"notify {number} skagent batch: {re.escape(command)} \| \d files? decrypted without a touch\."
            r" Ends with the command, or in 10 minutes at most\.",
            first,
        ), first
        assert f"actions {number} stop=Stop" in shown, shown
        # Not before the touch: until then the prompt says what is asked for.
        assert not [line for line in shown if "No file decrypted" in line], shown
        retry(lambda _last_try: f"close {number}" in notified(), timeout_seconds=5)

    with subtest("after the command, a file takes a touch again and no key is kept"):
        retry(lambda _last_try: kept_keys("skagent") == 0, timeout_seconds=5)
        untouched("f1.age", "after the batch")

    with subtest("the tool exits like its command, and runs nothing without a batch"):
        status, out = alice("skagent batch -- sh -c 'exit 7'")
        assert status == 7, (status, out)
        status, out = alice("skagent batch -- sh -c 'kill -TERM $$'")
        assert status == 143, (status, out)
        status, out = alice("skagent batch -- ./no-such-command")
        assert status == 127 and "can't run ./no-such-command" in out, (status, out)
        status, out = alice("SKAGENT_AGE_SOCKET=/nonexistent skagent batch -- touch ~/ran")
        assert status != 0 and "is skagent running?" in out, (status, out)
        alice_ok("test ! -e ~/ran")
        # Its command finds the agent the batch is with.
        out = alice_ok("env -u SKAGENT_AGE_SOCKET skagent batch --age-socket ${ageSocket} -- sh -c 'echo $SKAGENT_AGE_SOCKET'")
        assert out.strip() == "${ageSocket}", out

    with subtest("while a batch runs its key is kept in memfd_secret memory, for its command alone"):
        background("skagent batch -- ./gated")
        touch()
        machine.wait_for_file("/home/alice/first")
        assert kept_keys("skagent") == 1
        # Another program of alice's, started by something else.
        untouched("f4.age", "outside a running batch")
        number = notification_of("./gated")
        before = (prompts(), touches())
        alice_ok("touch ~/go")
        status, out = finished()
        assert status == 0 and out.split() == ["file-1", "file-2", "file-3"], out
        expect(before, 0, 0, "the batch's further files")
        retry(lambda _last_try: kept_keys("skagent") == 0, timeout_seconds=5)
        # The same notification counted on, and went with the batch.
        assert [line for line in notified() if re.match(rf"notify {number} skagent batch: ./gated \| [23] files decrypted", line)], notified()
        retry(lambda _last_try: f"close {number}" in notified(), timeout_seconds=5)

    with subtest("what the command leaves behind is handed to the tool, and stays in the batch"):
        before = (prompts(), touches())
        touch()
        out = alice_ok("skagent batch -- ./orphan")
        assert out.split() == ["file-1", "file-3"], out
        expect(before, 0, 1, "an orphaned process of the batch")
        assert alice_ok("cat ~/orphan-parent") == alice_ok("cat ~/tool-pid")

    with subtest("decryptions asked for at once wait for the one touch"):
        before = (prompts(), touches())
        touch()
        out = alice_ok("skagent batch -- ./at-once")
        assert out.split() == ["file-1", "file-2", "file-3"], out
        expect(before, 0, 1, "three decryptions at once")

    with subtest("a batch ends when its time is up, also while nobody asks"):
        alice_ok("skagent forget --socket ${socket}")
        was = ended("skagent", "its time is up")
        background("skagent batch --for 6s -- ./gated")
        touch()
        machine.wait_for_file("/home/alice/first")
        # What is left of it when it asks.
        assert re.search(r"for up to [3-6] seconds \(a batch\)", last_prompt()), last_prompt()
        retry(lambda _last_try: kept_keys("skagent") == 0, timeout_seconds=20)
        assert ended("skagent", "its time is up") == was + 1
        before = (prompts(), touches())
        alice_ok("touch ~/go")
        touch_times(2)
        status, out = finished()
        assert status == 0 and decrypted(out) == ["file-1", "file-2", "file-3"], out
        # The PIN is still cached: a batch's end isn't an eviction.
        expect(before, 0, 2, "after the batch's time")

    with subtest("locking the session ends a batch"):
        def lock() -> None:
            session = machine.succeed("loginctl show-user alice -p Display --value").strip()
            machine.succeed(f"loginctl lock-session {session}")
        interrupted(lock, "PINs", 1)

    with subtest("skagent forget ends a batch"):
        def forget() -> None:
            alice_ok("skagent forget --socket ${socket}")
        interrupted(forget, "PINs", 1)
        # The notification says why the command asks for touches again, and
        # isn't closed with the batch.
        number = notification_of("./gated")
        last = [line for line in notified() if line.startswith(f"notify {number} ")][-1]
        assert "| Ended: PINs were dropped (lock, sleep or a request to forget them). 1 file decrypted;" in last, last
        assert f"close {number}" not in notified(), notified()

    with subtest("the button in the notification stops a batch"):
        def press_stop() -> None:
            retry(lambda _last_try: "| 1 file decrypted" in notified()[-2], timeout_seconds=5)
            machine.succeed("echo stop > ${notificationLog}.press")
        def stopped() -> None:
            """A batch is stopped by its button, and a notification says so."""
            presses = len([line for line in notified() if line.startswith("pressed ")])
            # The PIN stays: stopping a batch evicts nothing else.
            interrupted(press_stop, "stopped by the user", 0)
            pressed = [line for line in notified() if line.startswith("pressed ")]
            assert len(pressed) == presses + 1 and pressed[-1].endswith(" stop"), notified()
            # The press was the end of that notification. What says why the
            # command asks for touches again is a new one, without a button.
            number = notification_of("./gated")
            assert number != pressed[-1].split()[1], notified()
            said = [line for line in notified() if line.startswith(f"notify {number} ")]
            assert len(said) == 1 and "| Ended: stopped by the user. 1 file decrypted;" in said[0], said
            assert not any(line.startswith(f"actions {number} ") for line in notified()), notified()

        # The service closes a notification whose button was pressed, like
        # the ones on desktops do: pressed, then closed, one right after
        # the other. Several times: which of the two the agent took first
        # was a matter of luck once, and a batch went on after its Stop.
        for _ in range(4):
            stopped()
        # Some say it the other way around.
        machine.succeed("touch ${notificationLog}.closes-first")
        stopped()
        machine.succeed("rm ${notificationLog}.closes-first")

    with subtest("a notification the user closed isn't shown again, and the batch goes on"):
        closed = journal("skagent").count("closed the batch")
        background("skagent batch -- ./gated")
        touch()
        machine.wait_for_file("/home/alice/first")
        retry(lambda _last_try: "| 1 file decrypted" in notified()[-2], timeout_seconds=5)
        machine.succeed("touch ${notificationLog}.dismiss")
        retry(lambda _last_try: notified()[-1].startswith("dismissed "), timeout_seconds=5)
        before = (prompts(), touches())
        alice_ok("touch ~/go")
        status, out = finished()
        assert status == 0 and out.split() == ["file-1", "file-2", "file-3"], out
        expect(before, 0, 0, "after closing the notification")
        retry(lambda _last_try: journal("skagent").count("closed the batch") == closed + 1, timeout_seconds=5)
        machine.sleep(1)
        assert notified()[-1].startswith("dismissed "), notified()

    with subtest("an unplugged security key ends a batch, also while nobody asks"):
        def replug() -> None:
            unplug()
            # The sweep notices it within 15 s, without a request.
            retry(lambda _last_try: kept_keys("skagent") == 0, timeout_seconds=40)
            plug_in()
        interrupted(replug, "the security key was unplugged", 1)

    with subtest("a file asked for while the security key is unplugged isn't decrypted without it"):
        was = ended("skagent", "the security key was unplugged")
        background("skagent batch -- ./gated")
        touch()
        machine.wait_for_file("/home/alice/first")
        unplug()
        before = (prompts(), touches())
        alice_ok("touch ~/go")
        # The request finds the key gone and waits for it to be plugged in.
        retry(lambda _last_try: ended("skagent", "the security key was unplugged") == was + 1, timeout_seconds=10)
        assert kept_keys("skagent") == 0
        machine.succeed("test ! -e /home/alice/status")
        plug_in()
        touch_times(2)
        status, out = finished()
        assert status == 0 and decrypted(out) == ["file-1", "file-2", "file-3"], out
        expect(before, 1, 2, "after the unplug")

    with subtest("while lock and sleep can't be watched, a batch keeps nothing"):
        machine.succeed("systemctl mask --runtime --now systemd-logind.service")
        retry(lambda _last_try: "PIN caching is disabled" in journal("skagent"), timeout_seconds=10)
        before = (prompts(), touches())
        background("skagent batch -- ./decrypt-all f1.age f2.age")
        touch_times(2)
        status, out = finished()
        assert status == 0 and decrypted(out) == ["file-1", "file-2"], out
        # Like the PIN: asked for with every file, and so is the touch.
        expect(before, 2, 2, "a batch without monitoring")
        assert "to decrypt a file for decrypt-all, then touch the key" in last_prompt(), last_prompt()
        assert "not using a batch" in journal("skagent")
        machine.succeed("systemctl unmask --runtime systemd-logind.service && systemctl start systemd-logind.service")
        retry(lambda _last_try: journal("skagent").count("machine sleeps (logind)") == 2, timeout_seconds=40)

    with subtest("the popup names the batch with the PIN and with the touch"):
        stop_agent("skagent")
        # The fake popup answers with the PIN in the same file as askpass.
        start_agent("skagent-popup", "--popup /run/current-system/sw/bin/fake-popup")
        touch()
        out = alice_ok("skagent batch --for 2m -- ./decrypt-all f1.age f2.age")
        assert out.split() == ["file-1", "file-2"], out
        lines = machine.succeed("cat ${popupLog}").splitlines()
        shown = [json.loads(line) for line in lines if line.startswith("{")]
        states = [message["state"] for message in shown if message["type"] == "show"]
        assert [state["name"] for state in states] == ["pin", "touch", "signed"], states
        for state in states:
            request = state["request"]
            assert (request["kind"], request["command"]) == ("batch", "./decrypt-all f1.age f2.age"), state
            # What is left of the two minutes when the request asks.
            assert 100 <= request["seconds"] <= 120, state
            assert state["key"]["label"] == "age identity", state
        # The popup is gone after the touch; the notification shows the batch.
        notification_of("./decrypt-all f1.age f2.age")

    with subtest("PINs never reach the journal"):
        for unit in ["skagent", "skagent-popup"]:
            assert "${pin}" not in messages(unit), unit
  '';
}
