# Helpers shared by the VM tests.
{ pkgs }:
{
  # Writes OpenSSH sk stub key files without a device.
  makeSkStub = pkgs.writers.writePython3Bin "make-sk-stub" { } (builtins.readFile ./make-sk-stub.py);

  # skagent's popup protocol, answered like a user would; see the script.
  fakePopup = pkgs.writers.writePython3Bin "fake-popup" { } (builtins.readFile ./fake-popup.py);

  # Announces a 4 GiB agent message to the socket in $1 and prints whether
  # the agent hung up ("closed") or waited for the rest ("open").
  oversizedMessage = pkgs.writers.writePython3Bin "oversized-message" { } (
    builtins.readFile ./oversized-message.py
  );

  # Answers every askpass prompt (PIN, lock passphrase) with the content of
  # $SKAGENT_TEST_ANSWER_FILE, or else $SKAGENT_TEST_ANSWER, and records each
  # prompt in $SKAGENT_TEST_ASKPASS_LOG, if set, so tests can count how often
  # the user would have been asked. The file lets a test change the answer
  # while the asking process keeps running.
  testAskpass = pkgs.writeShellApplication {
    name = "test-askpass";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      if [[ -n ''${SKAGENT_TEST_ASKPASS_LOG:-} ]]; then
        printf '%s\n' "''${1:-}" >>"$SKAGENT_TEST_ASKPASS_LOG"
      fi
      while [[ -n ''${SKAGENT_TEST_ASKPASS_GATE:-} && -e $SKAGENT_TEST_ASKPASS_GATE ]]; do
        sleep 0.05
      done
      if [[ -n ''${SKAGENT_TEST_ANSWER_FILE:-} ]]; then
        cat "$SKAGENT_TEST_ANSWER_FILE"
      else
        printf '%s\n' "$SKAGENT_TEST_ANSWER"
      fi
    '';
  };

  # A pinentry speaking just enough Assuan: answers GETPIN with the content
  # of $SKAGENT_TEST_ANSWER_FILE and logs every command (SETERROR, GETPIN, ...)
  # to $SKAGENT_TEST_PINENTRY_LOG.
  testPinentry = pkgs.writeShellApplication {
    name = "test-pinentry";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      echo "OK Pleased to meet you"
      while IFS= read -r line; do
        printf '%s\n' "$line" >>"$SKAGENT_TEST_PINENTRY_LOG"
        case "$line" in
          GETPIN)
            printf 'D %s\n' "$(cat "$SKAGENT_TEST_ANSWER_FILE")"
            echo OK
            ;;
          BYE)
            echo "OK closing connection"
            exit 0
            ;;
          *) echo OK ;;
        esac
      done
    '';
  };

  # A notification service on the session bus that records every call.
  fakeNotifications = pkgs.writers.writePython3Bin "fake-notifications" {
    libraries = [ pkgs.python3Packages.dbus-next ];
    # dbus-next takes D-Bus signatures as annotations, like "a{sv}".
    flakeIgnore = [
      "F722"
      "F821"
    ];
  } (builtins.readFile ./fake-notifications.py);

  # A private session bus plus the fake notification service on it, owned
  # by alice. The returned shell commands are for systemd-run in a test.
  notificationSetup =
    dir:
    let
      bus = "unix:path=${dir}/bus";
    in
    {
      address = bus;
      start = [
        "systemd-run --unit session-bus --uid alice ${pkgs.dbus}/bin/dbus-daemon --session --nofork --address=${bus}"
        "systemd-run --unit notifications --uid alice --setenv DBUS_SESSION_BUS_ADDRESS=${bus} /run/current-system/sw/bin/fake-notifications ${dir}/notifications"
      ];
      ready = "su alice -c '${pkgs.systemd}/bin/busctl --address=${bus} call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s org.freedesktop.Notifications' | grep -F 'b true'";
    };

  # The virtual key appears as a hidraw device; make it usable by test users.
  virtualKeyMachine = {
    boot.kernelModules = [ "uhid" ];
    services.udev.extraRules = ''
      KERNEL=="hidraw*", SUBSYSTEM=="hidraw", MODE="0666"
    '';
  };
}
