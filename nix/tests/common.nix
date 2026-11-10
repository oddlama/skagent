# Helpers shared by the VM tests.
{ pkgs }:
{
  # Writes OpenSSH sk stub key files without a device.
  makeSkStub = pkgs.writers.writePython3Bin "make-sk-stub" { } (builtins.readFile ./make-sk-stub.py);

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

  # The virtual key appears as a hidraw device; make it usable by test users.
  virtualKeyMachine = {
    boot.kernelModules = [ "uhid" ];
    services.udev.extraRules = ''
      KERNEL=="hidraw*", SUBSYSTEM=="hidraw", MODE="0666"
    '';
  };
}
