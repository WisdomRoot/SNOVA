# SPDX-License-Identifier: Apache-2.0
#
# Espressif RISC-V GCC toolchain (riscv32-esp-elf-*), pre-built binary.
# Used for bare-metal ESP32-C3/C6 builds (CROSS_PREFIX = riscv32-esp-elf-).
# Source: https://github.com/espressif/crosstool-NG
{ stdenv
, fetchurl
, autoPatchelfHook
, zlib
, libgcc
, ncurses5
, python3
, lib
}:

let
  version = "14.2.0_20251107";
  tag = "esp-${version}";
  baseUrl = "https://github.com/espressif/crosstool-NG/releases/download/${tag}";

  srcs = {
    "x86_64-linux" = {
      url = "${baseUrl}/riscv32-esp-elf-${version}-x86_64-linux-gnu.tar.xz";
      hash = "sha256:1d3a1b6a064686d9b77c4db7731f82e26c072e312e27969c45fe96410ecb2671";
    };
    "aarch64-linux" = {
      url = "${baseUrl}/riscv32-esp-elf-${version}-aarch64-linux-gnu.tar.xz";
      hash = "sha256:072a553453691fbd98fe82b6efa9a2fa6beb7d2c90aed4463353bc33378e83bf";
    };
    "aarch64-darwin" = {
      url = "${baseUrl}/riscv32-esp-elf-${version}-aarch64-apple-darwin.tar.xz";
      hash = "sha256:cedfcdaf8f165bd3e11ca4ee46b71d5b561fab93407eb8203812f9c14b1c7714";
    };
    "x86_64-darwin" = {
      url = "${baseUrl}/riscv32-esp-elf-${version}-x86_64-apple-darwin.tar.xz";
      hash = "sha256:d413836fa000f095d041a35950a45f82e2ff669995c8d6a09fa4d05e5c4ed258";
    };
  };

  sysKey =
    if stdenv.isLinux && stdenv.isx86_64 then "x86_64-linux"
    else if stdenv.isLinux && stdenv.isAarch64 then "aarch64-linux"
    else if stdenv.isDarwin && stdenv.isAarch64 then "aarch64-darwin"
    else if stdenv.isDarwin && stdenv.isx86_64 then "x86_64-darwin"
    else throw "riscv32-esp-elf: unsupported system ${stdenv.hostPlatform.system}";

  srcInfo = srcs.${sysKey};
in

stdenv.mkDerivation {
  pname = "riscv32-esp-elf";
  inherit version;

  src = fetchurl {
    inherit (srcInfo) url hash;
  };

  nativeBuildInputs = lib.optionals stdenv.isLinux [ autoPatchelfHook ];
  buildInputs = lib.optionals stdenv.isLinux [ zlib libgcc ncurses5 python3 ];

  dontBuild = true;
  dontConfigure = true;

  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp -r * $out/
    runHook postInstall
  '';

  meta = {
    description = "Espressif RISC-V GCC toolchain for ESP32-C3/C6 bare-metal builds";
    homepage = "https://github.com/espressif/crosstool-NG";
    platforms = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
  };
}
