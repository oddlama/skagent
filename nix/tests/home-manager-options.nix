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

  # Every style setting, so the generated file goes through `skagent
  # check-config` with all of them.
  styled = {
    popup = {
      enable = true;
      appearance = "dark";
      font = "IBM Plex Sans";
      monospaceFont = "Iosevka";
      fontFeatures = {
        cv11 = true;
        ss01 = 1;
      };
      monospaceFontFeatures.zero = true;
      scale = 1.25;
      light.accent = "#2f6feb";
      dark = lib.genAttrs [
        "surface"
        "text"
        "accent"
        "success"
        "warning"
        "error"
        "muted-text"
        "placeholder"
        "border"
        "field"
        "field-error"
        "on-accent"
        "on-success"
        "on-warning"
        "avatar"
        "avatar-warning"
        "avatar-error"
        "avatar-missing"
        "device"
        "ring-track"
        "dot"
        "dot-hollow"
      ] (_: "#88c0d0");
    };
  };
  styledConfig = (home styled).xdg.configFile."skagent/config.toml".source;

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
    # Built by the check below: `skagent check-config` passes on the result.
    "the popup style lands in the configuration file" =
      lib.hasInfix "skagent-config.toml" (execStart styled)
      && (home styled).xdg.configFile."skagent/config.toml".source == styledConfig;
    "colour names are checked when evaluating" =
      !evaluates {
        popup.dark.acent = "#88c0d0";
      };
    "colours are checked when evaluating" =
      !evaluates {
        popup.dark.accent = "88c0d0";
      };
    "age requests get a socket of their own, by the name the agent knows" =
      let
        units = (home { }).systemd.user;
      in
      units.sockets.skagent-age.Socket.FileDescriptorName == "age"
      && units.sockets.skagent-age.Socket.ListenStream == "%t/skagent-age.sock"
      && units.sockets.skagent-age.Socket.Service == "skagent.service"
      &&
        units.services.skagent.Unit.Requires == [
          "skagent.socket"
          "skagent-age.socket"
        ];
    "without age, the agent gets its ssh-agent socket alone" =
      let
        units = (home { age.enable = false; }).systemd.user;
      in
      !(units.sockets ? skagent-age) && units.services.skagent.Unit.Requires == [ "skagent.socket" ];
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
      # Building ${styledConfig} ran `skagent check-config` on it.
      grep -qx 'scale = 1.25' ${styledConfig}
      grep -qx 'appearance = "dark"' ${styledConfig}
      grep -qx 'muted-text = "#88c0d0"' ${styledConfig}
      echo "${toString (lib.length (lib.attrNames checks))} checks passed"
      touch $out
    ''
  else
    ''
      echo "failed: ${lib.concatStringsSep "; " failed}" >&2
      exit 1
    ''
)
