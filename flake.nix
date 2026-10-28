# SPDX-License-Identifier: Apache-2.0
#
# Development shell for bench/: the two cross toolchains and the two emulators
# the measurements run on. Copied from pqsca and trimmed to what bench/ uses.

{
  description = "SNOVA bench";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
  };

  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      perSystem = { pkgs, config, ... }: {
        packages = {
          riscv32-esp-elf = pkgs.callPackage ./nix/riscv32-esp-elf.nix { };
        };

        # pkgs.qemu supplies both qemu-system-arm (mps2-an386) and
        # qemu-system-riscv32 (virt). pqsca strips the latter to make room for
        # Espressif's fork; bench/ runs no ESP32 machine, so mainline is enough.
        devShells.default = pkgs.mkShellNoCC {
          packages = [
            pkgs.gnumake
            pkgs.gcc-arm-embedded
            config.packages.riscv32-esp-elf
            pkgs.qemu
          ];
        };
      };
    };
}
