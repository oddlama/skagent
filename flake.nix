{
  description = "skagent: ssh-agent for FIDO2 (sk) keys that caches the PIN and still requires a touch per signature";

  inputs = {
    devshell = {
      url = "github:numtide/devshell";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-parts.url = "github:hercules-ci/flake-parts";
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
        inputs.nci.flakeModule
        inputs.treefmt-nix.flakeModule
      ];

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
              # flags so cargo can reuse the prebuilt dependencies.
              drvConfig.env.RUSTFLAGS = "-D warnings";
              depsDrvConfig.env.RUSTFLAGS = "-D warnings";
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
              vm-testkey = import ./nix/tests/testkey.nix {
                inherit pkgs;
                testkey = config.packages.testkey;
              };
            };

          devshells.default = {
            packages = [
              config.treefmt.build.wrapper
              # ssh-add / ssh-keygen to poke at a running agent
              pkgs.openssh
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
