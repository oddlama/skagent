# Pictures of the popup, drawn by skagent-pinentry itself in a VM: every
# state in light and dark (`matrix/`, with a sheet of each), a few styles
# (`styled/`, from `themes/`) and the README's picture (`readme/`): four
# light popups above four dark ones, presets and styles.
#
#   nix build .#screenshots
#
# The popups are cut out: what shows around their corners is transparent.
{
  pkgs,
  lib,
  pinentry,
}:
let
  # 500 × 500 logical pixels at twice the size: the 360 px popup sits
  # centred at 70,70 and comes out 720 px wide.
  swayConfig = pkgs.writeText "sway.conf" ''
    output HEADLESS-1 resolution 1000x1000 scale 2
    output HEADLESS-1 bg #000000 solid_color
    default_border none
    xwayland disable
  '';
  themes = lib.mapAttrs' (
    file: _: lib.nameValuePair (lib.removeSuffix ".toml" file) "${./themes}/${file}"
  ) (builtins.readDir ./themes);
in
pkgs.testers.runNixOSTest {
  name = "skagent-screenshots";

  nodes.machine = {
    environment.systemPackages = [
      pkgs.grim
      pkgs.imagemagick
      pkgs.sway-unwrapped
      # Draws what the output shows around the popup.
      pkgs.swaybg
      pkgs.wtype
    ];
    # Mesa's software renderers for GPUI, the system's colour emoji font as
    # on a desktop, and the fonts the styles ask for.
    hardware.graphics.enable = true;
    fonts.packages = [
      pkgs.ibm-plex
      pkgs.noto-fonts-color-emoji
    ];
    users.users.alice.isNormalUser = true;
    virtualisation = {
      cores = 4;
      memorySize = 4096;
    };
  };

  testScript = ''
    PINENTRY = "${lib.getExe pinentry}"
    SWAY = "${pkgs.sway-unwrapped}/bin/sway"
    SWAY_CONFIG = "${swayConfig}"
    LABEL_FONT = "${pkgs.inter}/share/fonts/truetype/InterVariable.ttf"
    THEMES = ${builtins.toJSON themes}
  ''
  + builtins.readFile ./render.py;
}
