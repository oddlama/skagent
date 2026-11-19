# The guided check for real security keys (`nix run .#age-check`), run
# against the virtual one by a script that plays the person: so that the
# check itself keeps working, and still reads the agent's log right.
{
  pkgs,
  ageCheck,
  testkey,
}:
let
  common = import ./common.nix { inherit pkgs; };
  pin = "246810";
  dir = "/run/skagent-alice";
  # In alice's directory: the script that plays her touches and unplugs.
  touchFile = "${dir}/touch";
  unpluggedFile = "${dir}/unplugged";
  notifications = common.notificationSetup dir;
  user = pkgs.writers.writePython3Bin "age-check-user" {
    libraries = [ pkgs.python3Packages.pexpect ];
  } (builtins.readFile ./age-check-user.py);
  # fido2-token as on a machine that runs pcscd: libfido2 lists a YubiKey
  # once more there, over PC/SC. skagent only uses the HID device, and the
  # check has to tell the two apart.
  fidoToolsWithPcsc = pkgs.writeShellScriptBin "fido2-token" ''
    if [ "$*" = "-L" ]; then
      echo "pcsc://slot0: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID 00 00)"
    fi
    exec ${pkgs.libfido2}/bin/fido2-token "$@"
  '';
  check = ageCheck { fidoTools = fidoToolsWithPcsc; };
in
pkgs.testers.runNixOSTest {
  name = "skagent-age-check";

  nodes.machine = {
    imports = [ common.virtualKeyMachine ];
    environment.systemPackages = [
      check
      testkey
      user
      common.fakeNotifications
      common.testAskpass
      pkgs.libfido2
    ];
    security.polkit.enable = true;
    # A logind session for alice: without one nothing is kept, and the
    # check's batches would take a touch per file.
    services.getty.autologinUser = "alice";
    security.pam.services.login.rules.session.systemd.args = [ "type=wayland" ];
    users.users.alice.isNormalUser = true;
  };

  testScript = ''
    import re
    import shlex

    machine.wait_for_unit("multi-user.target")
    machine.wait_until_succeeds("loginctl show-user alice -p Sessions --value | grep . >/dev/null")
    machine.succeed("install -d -m 0700 -o alice -g users ${dir}")
    machine.succeed(
        "systemd-run --unit testkey --setenv SKAGENT_TESTKEY_PIN=${pin}"
        " ${testkey}/bin/skagent-testkey --touch file --touch-file ${touchFile}"
        " --touch-timeout 3 --name 'check key' --serial 12345678"
        " --unplugged-file ${unpluggedFile}"
    )
    machine.wait_until_succeeds("fido2-token -L | grep -F 'check key' >/dev/null")
    machine.succeed("${builtins.elemAt notifications.start 0}")
    machine.wait_for_file("${dir}/bus")
    machine.succeed("${builtins.elemAt notifications.start 1}")
    machine.wait_until_succeeds("${notifications.ready}")

    with subtest("the check passes against the virtual key, touched exactly as it says"):
        command = (
            "DBUS_SESSION_BUS_ADDRESS=${notifications.address} SKAGENT_TEST_ANSWER=${pin}"
            " age-check-user ${pin} ${touchFile} ${unpluggedFile} ${dir}/notifications.press --"
            " skagent-age-check --askpass /run/current-system/sw/bin/test-askpass --files 8"
        )
        status, out = machine.execute(f"su - alice -c {shlex.quote(command)} 2>&1", timeout=600)
        # As a terminal got it: without the carriage returns and the colours.
        out = re.sub(r"\x1b\[[0-9;]*m", "", out.replace("\r", ""))
        print(out)
        assert status == 0, out
        report = out.split("Results (paste these)")[-1]
        assert "\n0 failed" in report, report
        assert "FAIL" not in report, report
        # No screen is locked here: the check goes on by forgetting the PINs.
        skipped = [line for line in report.splitlines() if line.startswith("skip")]
        assert len(skipped) == 1 and "locking the screen" in skipped[0], skipped
        for line in [
            "ok    [3] a file is decrypted",
            "ok    [3] with the cached PIN",
            "ok    [3] a file for another recipient costs a touch and opens nothing",
            "ok    [4] without a touch nothing is decrypted (",
            "nobody answered in time",
            "time  [4] the key waits",
            "ok    [5] all 8 files are decrypted",
            "ok    [5] all but the first without the key",
            "seed  [5] kept in Secretmem memory",
            "ok    [6] by the key, not from a kept one",
            "ok    [6] a program outside the batch is asked for a touch",
            "ok    [6] and gets nothing from the batch",
            "ok    [6] the batch's own further files need no touch",
            "ok    [7] Stop ended the batch",
            "ok    [7] each by the key",
            "ok    [8] the agent noticed and ended the batch",
            "note  [8] after the replug the key was recognized without a touch of its own",
            "ok    [9] skagent forget ended the batch",
            "ok    [10] for an unverified host, as the log has it",
            "ok    [11] the identity's recipient is the one from the start",
            "ok    [12] the PIN retry counter is where it was (8)",
            "ok    [12] the test credential is deleted",
        ]:
            assert line in report, (line, report)

    with subtest("no PIN is in what the check printed, or in the log it keeps"):
        assert "${pin}" not in out, "the PIN is in the check's output"
        logs = machine.succeed("cat /run/user/*/skagent-check.*/agent.log /tmp/skagent-check.*/agent.log 2>/dev/null || true")
        assert "decrypted in a batch" in logs, "the check's agent log wasn't found"
        # Without the time of day: its microseconds are six digits, and now
        # and then they spell a PIN.
        assert "${pin}" not in re.sub(r"T\d\d:\d\d:\d\d\.\d+Z", "", logs), "the PIN is in the check's agent log"
  '';
}
