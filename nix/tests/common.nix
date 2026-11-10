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
      if [[ -n ''${SKAGENT_TEST_ANSWER_FILE:-} ]]; then
        cat "$SKAGENT_TEST_ANSWER_FILE"
      else
        printf '%s\n' "$SKAGENT_TEST_ANSWER"
      fi
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
