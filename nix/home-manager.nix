# home-manager module: skagent as a socket-activated systemd user service.
#
# The socket exists from login on; the agent starts with the first client,
# with the user manager's environment at that moment (WAYLAND_DISPLAY,
# DISPLAY, the session bus), which pinentry and the touch notification use.
# It stops with the graphical session, taking cached PINs and keys along.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.skagent;
  inherit (lib) mkOption types;

  socketName = "skagent.sock";
  exe = lib.getExe cfg.package;

  duration = types.strMatching "0|[0-9]+[smh]";

  # Quoted for Exec* lines, like nixpkgs' utils.escapeSystemdExecArg: JSON
  # strings are valid systemd quoting; % and $ are doubled so no specifier or
  # variable gets expanded.
  execArgs = lib.concatMapStringsSep " " (
    arg: lib.replaceStrings [ "%" "$" ] [ "%%" "$$" ] (builtins.toJSON arg)
  );

  selectors =
    policy:
    lib.filter (name: policy.${name} != null) [
      "application"
      "fingerprint"
    ];
  rule =
    policy:
    lib.concatStringsSep "," (
      map (name: "${name}=${policy.${name}}") (
        lib.filter (name: policy.${name} != null) [
          "application"
          "fingerprint"
          "lifetime"
          "idle"
        ]
      )
    );

  # Only what's set: the agent refuses unknown or empty settings.
  configFile = (pkgs.formats.toml { }).generate "skagent-config.toml" {
    keys = lib.mapAttrs (_: key: lib.filterAttrs (_: value: value != null) key) cfg.keys;
    security-keys = cfg.securityKeys;
  };

  serveArgs = [
    "serve"
    "--config"
    "${configFile}"
  ]
  ++ (
    if cfg.popup.enable then
      [
        "--popup"
        (lib.getExe cfg.popup.package)
      ]
    else if cfg.askpass != null then
      [
        "--askpass"
        "${cfg.askpass}"
      ]
    else
      [
        "--pinentry"
        (lib.getExe cfg.pinentry.package)
      ]
  )
  ++ [
    "--pin-lifetime"
    cfg.pinLifetime
  ]
  ++ lib.optionals (cfg.pinIdle != null) [
    "--pin-idle"
    cfg.pinIdle
  ]
  ++ lib.concatMap (policy: [
    "--pin-policy"
    (rule policy)
  ]) cfg.pinPolicies
  ++ [
    "--secret-memory"
    cfg.secretMemory
  ]
  ++ lib.optional (!cfg.touchNotification) "--no-touch-notification"
  ++ cfg.extraArgs;
in
{
  options.services.skagent = {
    enable = lib.mkEnableOption "skagent, an ssh-agent for FIDO2 security keys that caches the PIN and still requires a touch per signature";

    package = mkOption {
      type = types.package;
      description = "The skagent package.";
    };

    pinentry.package = lib.mkPackageOption pkgs "pinentry-qt" {
      extraDescription = ''
        It runs without a terminal, so it must be a graphical one, e.g.
        `pkgs.pinentry-gnome3` on GNOME.
      '';
    };

    popup = {
      enable = lib.mkEnableOption ''
        skagent's own popup (`skagent-pinentry`): PIN, touch and result of a
        request in one window, instead of pinentry and the touch
        notification. An overlay that takes the keyboard on Wayland
        compositors with layer shell (sway, Hyprland, niri, KDE), an ordinary
        window elsewhere
      '';
      package = mkOption {
        type = types.package;
        description = "The skagent-pinentry package.";
      };
    };

    askpass = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = lib.literalExpression ''"''${pkgs.lxqt.lxqt-openssh-askpass}/bin/lxqt-openssh-askpass"'';
      description = ''
        Ask for PINs with this askpass program instead of pinentry, like
        OpenSSH's {env}`SSH_ASKPASS`.
      '';
    };

    pinLifetime = mkOption {
      type = duration;
      default = "8h";
      example = "2h";
      description = ''
        How long a PIN stays cached after it was entered (`90s`, `30m`,
        `8h`). Using it doesn't extend it. `0` disables caching.
      '';
    };

    pinIdle = mkOption {
      type = types.nullOr duration;
      default = null;
      example = "30m";
      description = "Also drop a cached PIN that wasn't used for this long; `0` means no idle timeout.";
    };

    pinPolicies = mkOption {
      type = types.listOf (
        types.submodule {
          options = {
            application = mkOption {
              type = types.nullOr types.str;
              default = null;
              example = "ssh:personal";
              description = "Keys created with this application (`ssh-keygen -O application=`).";
            };
            fingerprint = mkOption {
              type = types.nullOr types.str;
              default = null;
              example = "SHA256:...";
              description = "The key with this fingerprint, as `ssh-add -l` shows it.";
            };
            lifetime = mkOption {
              type = types.nullOr duration;
              default = null;
              description = "PIN lifetime for these keys; `0` never caches their PIN.";
            };
            idle = mkOption {
              type = types.nullOr duration;
              default = null;
              description = "Idle timeout for these keys; `0` switches it off.";
            };
          };
        }
      );
      default = [ ];
      example = [
        {
          application = "ssh:personal";
          lifetime = "1h";
          idle = "15m";
        }
      ];
      description = ''
        Cache the PINs of some keys differently. Each rule names keys by
        `application` or `fingerprint` and overrides `lifetime` and/or
        `idle`; the first rule matching a key wins.
      '';
    };

    keys = mkOption {
      type = types.attrsOf (
        types.submodule {
          options = {
            emoji = mkOption {
              type = types.nullOr types.str;
              default = null;
              example = "🦊";
              description = "Shown for the key in skagent's popup.";
            };
            label = mkOption {
              type = types.nullOr types.str;
              default = null;
              example = "github-work";
              description = "Shown instead of the key's comment in prompts and logs.";
            };
          };
        }
      );
      default = { };
      example = lib.literalExpression ''
        {
          "SHA256:4NU8jDPeifwDQZBds3tPVzsluIgQ6CTN6zoxKMzxIkQ" = {
            emoji = "🦊";
            label = "github-work";
          };
        }
      '';
      description = ''
        How SSH keys are shown, by their fingerprint as `ssh-add -l` shows
        it.
      '';
    };

    securityKeys = mkOption {
      type = types.attrsOf (
        types.submodule {
          options.name = mkOption {
            type = types.str;
            example = "Desk 5C NFC";
            description = "The YubiKey's name.";
          };
        }
      );
      default = { };
      example = {
        "12345678".name = "Desk 5C NFC";
      };
      description = ''
        Names for YubiKeys, by serial number (`ykman list --serials`).
      '';
    };

    secretMemory = mkOption {
      type = types.enum [
        "locked"
        "memfd-secret"
      ];
      default = "locked";
      description = ''
        Where cached PINs live. `memfd-secret` uses {manpage}`memfd_secret(2)`
        memory, also removed from the kernel's direct map; the system can't
        hibernate while the agent holds any.
      '';
    };

    touchNotification = mkOption {
      type = types.bool;
      default = true;
      description = "Show a desktop notification while a security key waits for a touch.";
    };

    loadAtLogin = lib.mkEnableOption ''
      loading the resident SSH keys of a plugged-in security key when the
      graphical session starts (`skagent load`, one PIN prompt). Needs a
      session that starts {file}`graphical-session.target`
    '';

    setSshAuthSock = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Point {env}`SSH_AUTH_SOCK` at skagent in shells, systemd and D-Bus
        activation, unless it comes from agent forwarding. Switch it off to
        use skagent only for some hosts, with `IdentityAgent
        ~/.../skagent.sock` in {file}`ssh_config`.
      '';
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [
        "--log"
        "skagent=debug"
      ];
      description = "Further arguments for `skagent serve`.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      (lib.hm.assertions.assertPlatform "services.skagent" pkgs lib.platforms.linux)
      {
        assertion = !(cfg.popup.enable && cfg.askpass != null);
        message = "services.skagent: popup.enable and askpass exclude each other.";
      }
    ]
    ++ lib.concatMap (policy: [
      {
        assertion = lib.length (selectors policy) == 1;
        message = "services.skagent.pinPolicies: each rule needs exactly one of application and fingerprint.";
      }
      {
        assertion = policy.lifetime != null || policy.idle != null;
        message = "services.skagent.pinPolicies: each rule needs lifetime and/or idle.";
      }
    ]) cfg.pinPolicies
    ++ map (fingerprint: {
      assertion = builtins.match "SHA256:[A-Za-z0-9+/]{43}" fingerprint != null;
      message = "services.skagent.keys: \"${fingerprint}\" is not a SHA256:… fingerprint as `ssh-add -l` shows it.";
    }) (lib.attrNames cfg.keys)
    ++ map (serial: {
      assertion = builtins.match "[0-9]+" serial != null;
      message = "services.skagent.securityKeys: \"${serial}\" is not a serial number.";
    }) (lib.attrNames cfg.securityKeys);

    # `skagent load` and `skagent forget` in shells.
    home.packages = [ cfg.package ];

    sshAuthSock = lib.mkIf cfg.setSshAuthSock {
      enable = true;
      initialization = {
        bash = ''export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/${socketName}"'';
        fish = ''set -x SSH_AUTH_SOCK "$XDG_RUNTIME_DIR/${socketName}"'';
        nushell = ''$env.SSH_AUTH_SOCK = $"($env.XDG_RUNTIME_DIR)/${socketName}"'';
      };
      systemd.socketProviderUnit = "skagent.socket";
    };

    systemd.user.sockets.skagent = {
      Unit.Description = "skagent socket (ssh-agent for FIDO2 security keys)";
      Socket = {
        ListenStream = "%t/${socketName}";
        SocketMode = "0600";
        DirectoryMode = "0700";
        Service = "skagent.service";
      };
      Install.WantedBy = [ "sockets.target" ];
    };

    systemd.user.services.skagent = {
      Unit = {
        Description = "skagent: ssh-agent for FIDO2 security keys";
        Requires = [ "skagent.socket" ];
        After = [ "skagent.socket" ];
        # Logging out drops PINs and keys; the next session's first client
        # starts a fresh agent with that session's display variables.
        PartOf = [ "graphical-session.target" ];
      };
      Service = {
        Type = "simple";
        ExecStart = "${exe} ${execArgs serveArgs}";
        # Seccomp-based restrictions that work in a user manager and that the
        # prompts it spawns (graphical pinentries, askpass) don't need either:
        # no privilege gain through setuid binaries, no setuid/setgid files,
        # no realtime scheduling, no personality changes, native syscalls
        # only. The agent itself also disables core dumps and ptrace.
        NoNewPrivileges = true;
        RestrictSUIDSGID = true;
        RestrictRealtime = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
        UMask = "0077";
      };
    };

    systemd.user.services.skagent-load = lib.mkIf cfg.loadAtLogin {
      Unit = {
        Description = "Load the resident SSH keys of a security key into skagent";
        Requires = [ "skagent.socket" ];
        After = [
          "skagent.socket"
          "graphical-session.target"
        ];
        PartOf = [ "graphical-session.target" ];
      };
      Service = {
        Type = "oneshot";
        # Logging in without a security key plugged in is no failure.
        ExecStart = "${exe} load --if-connected";
        # Touch selection (several keys), the PIN prompt and waiting for a
        # busy agent each have their own, shorter limits.
        TimeoutStartSec = "5min";
      };
      Install.WantedBy = [ "graphical-session.target" ];
    };
  };
}
