# skagent-pinentry, the popup. Its Cargo workspace (pinentry/) reaches into
# the agent's for the protocol and the secret buffer, which nci's per-project
# builds can't, so this is a plain buildRustPackage with the same toolchain.
{
  lib,
  rustPlatform,
  stdenv,
  pkg-config,
  python3,
  fontconfig,
  freetype,
  inter,
  jetbrains-mono,
  libGL,
  libxcb,
  libxkbcommon,
  vulkan-loader,
  wayland,
}:
let
  # Only what the popup builds from: agent-only changes don't rebuild GPUI.
  # The root manifest is there for the shared crates' workspace inheritance,
  # clippy.toml for the clippy check.
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../clippy.toml
      ../crates/skagent-popup
      ../crates/skagent-secret
      ../pinentry/Cargo.lock
      ../pinentry/Cargo.toml
      ../pinentry/src
      ../pinentry/tests
    ];
  };
in
rustPlatform.buildRustPackage (
  finalAttrs:
  let
    # Runs `script` in pinentry/ with the package's vendored dependencies,
    # instead of building it.
    cargoCheck =
      name: script:
      finalAttrs.finalPackage.overrideAttrs (old: {
        pname = "skagent-pinentry-${name}";
        nativeBuildInputs = old.nativeBuildInputs ++ [ python3 ];
        dontCargoBuild = true;
        dontCargoInstall = true;
        doCheck = false;
        buildPhase = ''
          runHook preBuild
          cd pinentry
          ${script}
          runHook postBuild
        '';
        installPhase = "touch $out";
      });
  in
  {
    pname = "skagent-pinentry";
    version = "0.1.0";
    inherit src;
    cargoRoot = "pinentry";
    buildAndTestSubdir = "pinentry";
    # Every dependency of pinentry/Cargo.lock, Zed's git checkout included.
    # Update it whenever the lockfile changes.
    cargoHash = "sha256-XS+S81TJ4Coz9p0fNmkykAN1DwRJ3C1nwuiqlERhhcY=";

    nativeBuildInputs = [ pkg-config ];
    buildInputs = [
      fontconfig
      freetype
      libxcb
      libxkbcommon
      wayland
    ];

    env = {
      # Warnings fail the build, as for the agent. Cargo caps the lints of
      # dependencies, so this only applies to this repository's crates.
      RUSTFLAGS = "-D warnings";
      # The design's fonts, read at startup (`src/fonts.rs`).
      SKAGENT_PINENTRY_FONTS = lib.concatStringsSep ":" [
        "${inter}/share/fonts/truetype/Inter.ttc"
        "${jetbrains-mono}/share/fonts/truetype/JetBrainsMono-Regular.ttf"
      ];
      # GPUI loads the GPU driver loaders and the Wayland client at runtime.
      NIX_LDFLAGS = "-rpath ${
        lib.makeLibraryPath [
          libGL
          vulkan-loader
          wayland
          libxkbcommon
        ]
      }";
    };
    # Keeps those rpaths: patchelf would drop them as unused.
    dontPatchELF = true;

    passthru = {
      # The workspace's lints over every target, warnings denied as above.
      clippy = cargoCheck "clippy" ''
        cargo clippy --all-targets --offline --locked
      '';
      # Every crate linked into the popup is permissively licensed.
      licenses = cargoCheck "licenses" ''
        cargo metadata --offline --locked --format-version 1 \
          --filter-platform ${stdenv.hostPlatform.rust.rustcTarget} > metadata.json
        python3 -I ${./pinentry-licenses.py} < metadata.json
      '';
    };

    meta = {
      description = "skagent's popup: PIN, touch and errors of a request in one window";
      license = lib.licenses.mit;
      mainProgram = "skagent-pinentry";
      platforms = lib.platforms.linux;
    };
  }
)
