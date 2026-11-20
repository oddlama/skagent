# home-manager module: skagent as a socket-activated systemd user service.
#
# The socket exists from login on; the agent starts with the first client,
# with the user manager's environment at that moment (WAYLAND_DISPLAY,
# DISPLAY, the session bus), which pinentry and the touch notification use.
# It stops with the graphical session, taking cached PINs along; the keys it
# had are remembered and offered again by the next session's agent.
{
  config,
  lib,
  options,
  pkgs,
  ...
}:
let
  cfg = config.services.skagent;
  inherit (lib) mkOption types;

  # Whether the configuration names a pinentry itself: then that one asks,
  # not the popup. The option's own default has the lowest priority there is.
  pinentryChosen =
    options.services.skagent.pinentry.package.highestPrio < (lib.mkOptionDefault null).priority;

  socketName = "skagent.sock";
  ageSocketName = "skagent-age.sock";
  sockets = [ "skagent.socket" ] ++ lib.optional cfg.age.enable "skagent-age.socket";
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

  # The colours of `[popup.light]` and `[popup.dark]`, as skagent_popup's
  # `Token::name` spells them; `skagent check-config` below fails the build
  # if they ever drift apart.
  colorNames = [
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
  ];
  color = types.strMatching "#([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})";
  colorsOption =
    mode:
    mkOption {
      type = types.submodule {
        options = lib.genAttrs colorNames (
          name:
          mkOption {
            type = types.nullOr color;
            default = null;
            description = "The ${mode} theme's `${name}` colour.";
          }
        );
      };
      default = { };
      example = {
        surface = "#2e3440";
        accent = "#88c0d0";
      };
      description = ''
        Colours of the ${mode} theme, over the design's: `#rgb`, `#rrggbb`
        or `#rrggbbaa`. A colour you leave unset stays the design's, unless
        a colour it's made from changed: then it's mixed anew (borders and
        tints from `surface` and `text`, icons on `accent` in whichever of
        them stands out). The six base colours are `surface`, `text`,
        `accent`, `success`, `warning` and `error`.
      '';
    };
  features = types.attrsOf (types.either types.bool types.ints.unsigned);

  popupSettings = lib.filterAttrs (_: value: value != null && value != { }) {
    appearance = if cfg.popup.appearance == "system" then null else cfg.popup.appearance;
    inherit (cfg.popup) font scale;
    monospace-font = cfg.popup.monospaceFont;
    font-features = cfg.popup.fontFeatures;
    monospace-font-features = cfg.popup.monospaceFontFeatures;
    light = lib.filterAttrs (_: value: value != null) cfg.popup.light;
    dark = lib.filterAttrs (_: value: value != null) cfg.popup.dark;
  };

  # Only what's set: the agent refuses unknown or empty settings.
  generatedConfig = (pkgs.formats.toml { }).generate "skagent-config.toml" (
    {
      keys = lib.mapAttrs (_: key: lib.filterAttrs (_: value: value != null) key) cfg.keys;
      security-keys = cfg.securityKeys;
    }
    // lib.optionalAttrs (popupSettings != { }) { popup = popupSettings; }
  );

  # Checked while home-manager builds: anything `skagent serve` would refuse
  # or skip (a feature tag that isn't one, ...) fails the switch instead.
  configFile = pkgs.runCommand "skagent-config.toml" { } ''
    ${exe} check-config --config ${generatedConfig} > /dev/null
    cp ${generatedConfig} $out
  '';

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
  ++ lib.optional (!cfg.pairing) "--no-pairing"
  ++ [
    "--plug-in-timeout"
    cfg.plugInTimeout
    "--batch-lifetime"
    cfg.age.batchLifetime
  ]
  ++ lib.optional cfg.age.forwarding "--age-forwarding"
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
        Setting it makes this pinentry ask for PINs instead of skagent's
        popup; so does `popup.enable = false`, with pinentry-qt. It runs
        without a terminal, so it must be a graphical one, e.g.
        `pkgs.pinentry-gnome3` on GNOME.
      '';
    };

    popup = {
      enable = mkOption {
        type = types.bool;
        default = cfg.askpass == null && !pinentryChosen;
        defaultText = lib.literalMD "`true`, unless `askpass` or `pinentry.package` is set";
        example = false;
        description = ''
          Whether to use skagent's own popup (`skagent-pinentry`): PIN, touch
          and result of a request in one window, instead of pinentry and the
          touch notification. An overlay that takes the keyboard on Wayland
          compositors with layer shell (sway, Hyprland, niri, KDE), an
          ordinary window elsewhere.

          On unless the configuration names another prompt: with `askpass` or
          `pinentry.package` set, that one asks.
        '';
      };
      package = mkOption {
        type = types.package;
        description = "The skagent-pinentry package.";
      };
      appearance = mkOption {
        type = types.enum [
          "system"
          "light"
          "dark"
        ];
        default = "system";
        description = "Light, dark, or whichever the desktop prefers.";
      };
      font = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "IBM Plex Sans";
        description = ''
          Font family for text. Unset, or not installed: the bundled Inter.
        '';
      };
      monospaceFont = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "Iosevka";
        description = ''
          Font family for commands and fingerprints. Unset, or not
          installed: the bundled JetBrains Mono.
        '';
      };
      fontFeatures = mkOption {
        type = features;
        default = { };
        example = {
          cv11 = true;
          ss01 = 1;
        };
        description = "OpenType features of `font`.";
      };
      monospaceFontFeatures = mkOption {
        type = features;
        default = { };
        example = {
          zero = true;
        };
        description = "OpenType features of `monospaceFont`.";
      };
      scale = mkOption {
        type = types.nullOr (types.numbers.between 0.5 3);
        default = null;
        example = 1.25;
        description = ''
          Size of the whole popup, text included; 1 is the design's.
        '';
      };
      light = colorsOption "light";
      dark = colorsOption "dark";
    };

    askpass = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = lib.literalExpression ''"''${pkgs.lxqt.lxqt-openssh-askpass}/bin/lxqt-openssh-askpass"'';
      description = ''
        Ask for PINs with this askpass program instead of the popup or
        pinentry, like OpenSSH's {env}`SSH_ASKPASS`.
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

    pairing = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Pair with each security key on first use: one more touch, once per
        key, after which skagent checks the key's pairing before a PIN goes
        there, so a device claiming to be it gets none. Pairings made before
        are checked either way.
      '';
    };

    plugInTimeout = mkOption {
      type = duration;
      default = "15s";
      example = "1m";
      description = ''
        How long a request waits for its security key to be plugged in,
        asking for it by name once skagent knows which YubiKey holds the key.
        `0` fails right away.
      '';
    };

    loadAtLogin = lib.mkEnableOption ''
      loading the resident SSH keys of a plugged-in security key when the
      graphical session starts (`skagent load`, one PIN prompt). Needs a
      session that starts {file}`graphical-session.target`
    '';

    age.enable = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Answer requests about age identities on a socket of their own,
        {file}`$XDG_RUNTIME_DIR/skagent-age.sock`: `skagent age` creates and
        lists identities on security keys, and `age-plugin-skagent` (in the
        same package) decrypts age files with them. The socket answers these
        two programs only.
      '';
    };

    age.batchLifetime = mkOption {
      type = duration;
      default = "10m";
      example = "2m";
      description = ''
        The longest a batch of decryptions lasts (`skagent batch -- command`).
        After one PIN and one touch, the key of an age identity stays in the
        agent's memory for the command's further files, until the command is
        done or this time is up. `0` turns batches off.
      '';
    };

    age.forwarding = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Decrypt age files for other machines too, through a forwarded agent
        (`ssh -A`). Each file takes a touch on this machine, and the prompt
        names the host by its host key. What it can't say is which file the
        host wants opened.
      '';
    };

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
      {
        assertion = cfg.age.enable || !cfg.age.forwarding;
        message = "services.skagent: age.forwarding needs age.enable.";
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

    # `skagent load`, `skagent forget` and `skagent check-config` in shells,
    # and `skagent-pinentry --preview` to try a style.
    home.packages = [ cfg.package ] ++ lib.optional cfg.popup.enable cfg.popup.package;

    # The file `serve` gets, also where `check-config` and the preview look.
    xdg.configFile."skagent/config.toml".source = configFile;

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

    # Passed to the same agent, under the name it knows it by. Either socket's
    # first client starts the agent, with both.
    systemd.user.sockets.skagent-age = lib.mkIf cfg.age.enable {
      Unit.Description = "skagent socket for age requests";
      Socket = {
        ListenStream = "%t/${ageSocketName}";
        FileDescriptorName = "age";
        SocketMode = "0600";
        DirectoryMode = "0700";
        Service = "skagent.service";
      };
      Install.WantedBy = [ "sockets.target" ];
    };

    systemd.user.services.skagent = {
      Unit = {
        Description = "skagent: ssh-agent for FIDO2 security keys";
        Requires = sockets;
        After = sockets;
        # Logging out drops the PINs; the next session's first client starts
        # a fresh agent with that session's display variables (and the
        # remembered keys).
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
