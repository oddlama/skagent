# The home-manager module's prompt options, checked at evaluation: what
# `skagent serve` gets, and which combinations are refused. The VM tests run
# the arguments themselves (home-manager.nix, pinentry.nix).
{
  lib,
  pkgs,
  homeManagerConfiguration,
  skagentModule,
}:
let
  home =
    settings:
    (homeManagerConfiguration {
      inherit pkgs;
      modules = [
        skagentModule
        {
          home = {
            username = "alice";
            homeDirectory = "/home/alice";
            stateVersion = "26.05";
          };
          services.skagent = {
            enable = true;
          }
          // settings;
        }
      ];
    }).config;

  # The command line (a list once merged), as text: comparing it needs no
  # program built.
  execStart =
    settings:
    builtins.unsafeDiscardStringContext (
      lib.concatStringsSep "\n" (
        lib.toList (home settings).systemd.user.services.skagent.Service.ExecStart
      )
    );
  # home-manager throws on failed assertions when the configuration is read.
  evaluates = settings: (builtins.tryEval (builtins.deepSeq (execStart settings) true)).success;

  popupExe = builtins.unsafeDiscardStringContext (
    lib.getExe (home { }).services.skagent.popup.package
  );

  checks = {
    "pinentry by default" =
      lib.hasInfix ''"--pinentry"'' (execStart { }) && !lib.hasInfix ''"--popup"'' (execStart { });
    "the popup replaces pinentry" =
      lib.hasInfix ''"--popup" "${popupExe}"'' (execStart {
        popup.enable = true;
      })
      && !lib.hasInfix ''"--pinentry"'' (execStart {
        popup.enable = true;
      });
    "the popup defaults to this flake's skagent-pinentry" =
      lib.hasSuffix "/bin/skagent-pinentry" popupExe;
    "requests wait 15 s for their security key by default" =
      lib.hasInfix ''"--plug-in-timeout" "15s"''
        (execStart { });
    "the plug-in timeout reaches the agent" = lib.hasInfix ''"--plug-in-timeout" "0"'' (execStart {
      plugInTimeout = "0";
    });
    "askpass replaces pinentry" = lib.hasInfix ''"--askpass" "/bin/askpass"'' (execStart {
      askpass = "/bin/askpass";
    });
    # Each works alone (above), so it's the combination that is refused.
    "the popup and askpass are refused together" =
      !evaluates {
        popup.enable = true;
        askpass = "/bin/askpass";
      };
  };
  failed = lib.attrNames (lib.filterAttrs (_: passed: !passed) checks);
in
pkgs.runCommand "home-manager-options" { } (
  if failed == [ ] then
    ''
      echo "${toString (lib.length (lib.attrNames checks))} checks passed"
      touch $out
    ''
  else
    ''
      echo "failed: ${lib.concatStringsSep "; " failed}" >&2
      exit 1
    ''
)
