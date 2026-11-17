{
  description = "skagent: ssh-agent for FIDO2 (sk) keys that caches the PIN and still requires a touch per signature";

  inputs = {
    devshell = {
      url = "github:numtide/devshell";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-parts.url = "github:hercules-ci/flake-parts";
    # The home-manager module's VM test, and the typed `homeModules` output.
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nci = {
      url = "github:90-008/nix-cargo-integration";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.devshell.flakeModule
        inputs.home-manager.flakeModules.home-manager
        inputs.nci.flakeModule
        inputs.treefmt-nix.flakeModule
      ];

      # The package defaults to this flake's build for the host platform.
      flake.homeModules.default =
        { lib, pkgs, ... }:
        {
          imports = [ ./nix/home-manager.nix ];
          services.skagent.package =
            lib.mkDefault
              inputs.self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        };

      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      perSystem =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        let
          # The project is named apart from its crates: nci exposes both under
          # `nci.outputs`, and a project called `skagent` would collide with the
          # `skagent` crate.
          projectName = "workspace";
          crateOutputs = lib.filterAttrs (name: _: name != projectName) config.nci.outputs;

          fidoBuildInputs = {
            nativeBuildInputs = [
              pkgs.pkg-config
              pkgs.rustPlatform.bindgenHook
            ];
            buildInputs = [
              pkgs.libfido2
              pkgs.openssl
              pkgs.zlib
            ];
          };
          inherit (pkgs.llvmPackages) libclang;

          # skagent-pinentry (GPUI): linked against at build time ...
          pinentryLibraries = [
            pkgs.fontconfig
            pkgs.freetype
            pkgs.libxcb
            pkgs.libxkbcommon
          ];
          # ... and loaded at runtime (dlopen).
          pinentryRuntimeLibraries = [
            pkgs.libGL
            pkgs.vulkan-loader
            pkgs.wayland
          ];
        in
        {
          nci = {
            toolchainConfig = ./rust-toolchain.toml;
            projects.${projectName} = {
              path = ./.;
              # Outputs are selected below instead of exported wholesale.
              export = false;
              numtideDevshell = "default";
              # Warnings fail every nix build of our crates, including the clippy
              # check. Registry dependencies cap their own lints, so this only
              # applies to code in this repository. Both derivations get the same
              # flags and inputs so cargo can reuse the prebuilt dependencies.
              # libfido2-sys runs bindgen against the system libfido2 headers.
              drvConfig = {
                env.RUSTFLAGS = "-D warnings";
                mkDerivation = fidoBuildInputs;
              };
              depsDrvConfig = {
                env.RUSTFLAGS = "-D warnings";
                mkDerivation = fidoBuildInputs;
              };
            };
          };

          packages = {
            default = lib.addMetaAttrs {
              mainProgram = "skagent";
            } config.nci.outputs.skagent.packages.release;
            # Test-only virtual security key (links AGPL-3.0 soft-fido2).
            testkey = lib.addMetaAttrs {
              mainProgram = "skagent-testkey";
            } config.nci.outputs.skagent-testkey.packages.release;
          };

          # Every crate contributes its test suite and its clippy run. The VM
          # tests drive the release binary with stock OpenSSH tools.
          checks =
            lib.mapAttrs' (name: output: lib.nameValuePair "tests-${name}" output.check) crateOutputs
            // lib.mapAttrs' (name: output: lib.nameValuePair "clippy-${name}" output.clippy) crateOutputs
            // {
              vm-agent = import ./nix/tests/agent.nix {
                inherit pkgs;
                package = config.packages.default;
              };
              vm-popup = import ./nix/tests/popup.nix {
                inherit pkgs;
                package = config.packages.default;
                testkey = config.packages.testkey;
              };
              vm-signing = import ./nix/tests/signing.nix {
                inherit pkgs;
                package = config.packages.default;
                testkey = config.packages.testkey;
              };
              vm-destinations = import ./nix/tests/destinations.nix {
                inherit pkgs;
                package = config.packages.default;
                testkey = config.packages.testkey;
              };
              vm-home-manager = import ./nix/tests/home-manager.nix {
                inherit pkgs;
                inherit (config.packages) testkey;
                homeManager = inputs.home-manager.nixosModules.home-manager;
                skagentModule = inputs.self.homeModules.default;
              };
              vm-loading = import ./nix/tests/loading.nix {
                inherit pkgs;
                package = config.packages.default;
                testkey = config.packages.testkey;
              };
              vm-multiple-keys = import ./nix/tests/multiple-keys.nix {
                inherit pkgs;
                package = config.packages.default;
                testkey = config.packages.testkey;
              };
              vm-testkey = import ./nix/tests/testkey.nix {
                inherit pkgs;
                testkey = config.packages.testkey;
              };
              license-boundary = pkgs.callPackage ./nix/license-boundary.nix {
                cargoLock = ./Cargo.lock;
                shippedCrates = [
                  "skagent"
                  "skagent-fido"
                  "skagent-fds"
                  "skagent-popup"
                  "skagent-secret"
                ];
                forbiddenPrefixes = [
                  "soft-fido2"
                  "skagent-testkey"
                ];
              };
            };

          devshells.default = {
            packages = [
              config.treefmt.build.wrapper
              # ssh-add / ssh-keygen to poke at a running agent
              pkgs.openssh
              pkgs.libfido2
              pkgs.pkg-config
            ]
            # skagent-pinentry's own workspace in pinentry/.
            ++ map lib.getDev pinentryLibraries;
            env = [
              {
                # Some of GPUI's -sys crates link by name, without pkg-config.
                name = "LIBRARY_PATH";
                value = lib.makeLibraryPath pinentryLibraries;
              }
              {
                # The design's fonts, built into skagent-pinentry as in the package.
                name = "SKAGENT_PINENTRY_FONTS";
                value = "${pkgs.inter}/share/fonts/truetype/Inter.ttc:${pkgs.jetbrains-mono}/share/fonts/truetype/JetBrainsMono-Regular.ttf";
              }
              {
                # For running skagent-pinentry from pinentry/target.
                name = "SKAGENT_PINENTRY_LIBRARY_PATH";
                value = lib.makeLibraryPath (pinentryLibraries ++ pinentryRuntimeLibraries);
              }
              # What rustPlatform.bindgenHook sets up inside nix builds, for
              # cargo builds of libfido2-sys in the shell.
              {
                name = "LIBCLANG_PATH";
                value = "${lib.getLib libclang}/lib";
              }
              {
                name = "BINDGEN_EXTRA_CLANG_ARGS";
                value = "-isystem ${lib.getLib libclang}/lib/clang/${lib.versions.major libclang.version}/include -isystem ${lib.getDev pkgs.stdenv.cc.libc}/include -isystem ${lib.getDev pkgs.openssl}/include";
              }
            ];
          };

          treefmt = {
            projectRootFile = "flake.nix";
            programs = {
              deadnix.enable = true;
              nixfmt.enable = true;
              statix.enable = true;
              taplo.enable = true;
              rustfmt = {
                enable = true;
                edition = "2024";
              };
            };
          };
        };
    };
}
