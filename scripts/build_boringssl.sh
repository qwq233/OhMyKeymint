#!/usr/bin/env bash
# Build BoringSSL for OhMyKeymint Android targets (arm64-v8a and/or x86_64).
#
# Produces the per-ABI BoringSSL build directories that build.py expects:
#
#   ~/.cargo/boringssl/build           <- aarch64-linux-android
#   ~/.cargo/boringssl/build-x86_64    <- x86_64-linux-android
#
# Each build directory contains libcrypto.a, libssl.a, librust_wrapper.a and
# the bindgen-generated `rust/bssl-sys/wrapper_<triple>.rs` bindings file
# (generated because of -DRUST_BINDINGS). The bssl-sys crate is a placeholder
# on crates.io, so the BoringSSL source tree must also be kept around and
# patched into Cargo with:
#
#   [patch.crates-io]
#   bssl-sys = { path = "<BORINGSSL_SRC>/rust/bssl-sys" }
#
# This script can append that patch to .cargo/config.toml automatically
# (default behaviour, disable with --no-config-write).
#
# Usage:
#   scripts/build_boringssl.sh [options]
#
# Options:
#   --abi <abi>         arm64-v8a | x86_64 | all   (default: all)
#   --ndk-root <dir>    Android NDK root (default: $ANDROID_NDK_ROOT)
#   --src-dir <dir>     BoringSSL source clone (default: ~/.cargo/boringssl/src)
#   --sdk-cmake <bin>   Path to SDK cmake binary (default: cmake from PATH)
#   --platform <api>    Android platform level for the NDK build (default: 33)
#   --no-config-write   Do not touch .cargo/config.toml
#   --skip-clone        Reuse an existing BoringSSL clone without fetching
#
# Requirements: cmake, ninja, clang from the NDK, bindgen (cargo install
# bindgen-cli), python3.
set -euo pipefail

ABI="all"
NDK_ROOT="${ANDROID_NDK_ROOT:-}"
SRC_DIR="$HOME/.cargo/boringssl/src"
SDK_CMAKE="cmake"
PLATFORM="33"
CONFIG_WRITE=1
SKIP_CLONE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --abi) ABI="${2:?--abi requires a value}"; shift 2 ;;
    --ndk-root) NDK_ROOT="${2:?--ndk-root requires a value}"; shift 2 ;;
    --src-dir) SRC_DIR="${2:?--src-dir requires a value}"; shift 2 ;;
    --sdk-cmake) SDK_CMAKE="${2:?--sdk-cmake requires a value}"; shift 2 ;;
    --platform) PLATFORM="${2:?--platform requires a value}"; shift 2 ;;
    --no-config-write) CONFIG_WRITE=0; shift ;;
    --skip-clone) SKIP_CLONE=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$NDK_ROOT" ] || [ ! -d "$NDK_ROOT" ]; then
  echo "ERROR: Android NDK root not found. Pass --ndk-root or set ANDROID_NDK_ROOT." >&2
  exit 1
fi

if ! command -v ninja >/dev/null 2>&1; then
  echo "ERROR: ninja not found in PATH (apt install ninja-build)." >&2
  exit 1
fi

if ! command -v bindgen >/dev/null 2>&1; then
  echo "ERROR: bindgen not found in PATH (cargo install bindgen-cli)." >&2
  exit 1
fi

# bindgen pipes its output through rustfmt; when rustfmt is missing some
# bindgen releases silently write an almost-empty bindings file. Refuse to
# continue rather than producing broken bindings.
if ! command -v rustfmt >/dev/null 2>&1; then
  echo "ERROR: rustfmt not found in PATH (rustup component add rustfmt)." >&2
  echo "       bindgen requires it; without it the generated bindings are empty." >&2
  exit 1
fi

BSSL_BASE="$HOME/.cargo/boringssl"
TOOLCHAIN_FILE="$NDK_ROOT/build/cmake/android.toolchain.cmake"
SYSROOT="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/sysroot"

if [ ! -f "$TOOLCHAIN_FILE" ]; then
  echo "ERROR: NDK toolchain file not found at $TOOLCHAIN_FILE" >&2
  exit 1
fi

if [ "$SKIP_CLONE" -ne 1 ] || [ ! -d "$SRC_DIR" ]; then
  mkdir -p "$(dirname "$SRC_DIR")"
  if [ -d "$SRC_DIR" ]; then
    echo "==> Updating existing BoringSSL clone at $SRC_DIR"
    git -C "$SRC_DIR" fetch --depth 1 origin main
    git -C "$SRC_DIR" reset --hard FETCH_HEAD
  else
    echo "==> Cloning BoringSSL to $SRC_DIR"
    git clone --depth 1 https://boringssl.googlesource.com/boringssl "$SRC_DIR"
  fi
fi

build_one() {
  local abi="$1" build_dir="$2" rust_bindings="$3" outline_cflags="$4"

  echo "==> Building BoringSSL for $abi (target $rust_bindings) in $BSSL_BASE/$build_dir"

  # BoringSSL's bindgen invocation ends with a possibly-empty trailing include
  # entry that swallows the following `--target=` flag, so the bindings would
  # silently be generated for the HOST triple. Re-assert the target triple,
  # the NDK sysroot and the clang resource directory explicitly so the
  # generated bindings always match $rust_bindings, and so bindgen works even
  # when the host libclang ships without bundled resource headers.
  local clang_resource_dir
  clang_resource_dir="$(ls -d "$NDK_ROOT"/toolchains/llvm/prebuilt/*/lib/clang/*/include 2>/dev/null | head -n1 || true)"
  local bindgen_args="--target=$rust_bindings --sysroot=$SYSROOT"
  if [ -n "$clang_resource_dir" ]; then
    bindgen_args="$bindgen_args -resource-dir=${clang_resource_dir%/include} -isystem$clang_resource_dir"
  fi
  export BINDGEN_EXTRA_CLANG_ARGS="$bindgen_args"

  local cmake_flags=(-GNinja -B "$BSSL_BASE/$build_dir" -S "$SRC_DIR")
  cmake_flags+=(
    -DRUST_BINDINGS="$rust_bindings"
    -DCMAKE_SYSROOT="$SYSROOT"
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE"
    -DANDROID_ABI="$abi"
    -DANDROID_PLATFORM="android-$PLATFORM"
  )
  if [ -n "$outline_cflags" ]; then
    cmake_flags+=(-DCMAKE_C_FLAGS="$outline_cflags" -DCMAKE_CXX_FLAGS="$outline_cflags")
  fi

  "$SDK_CMAKE" "${cmake_flags[@]}"
  ninja -j"$(nproc)" -C "$BSSL_BASE/$build_dir"

  local wrapper="$BSSL_BASE/$build_dir/rust/bssl-sys/wrapper_${rust_bindings}.rs"
  if [ ! -f "$wrapper" ]; then
    echo "ERROR: expected bindgen bindings missing: $wrapper" >&2
    exit 1
  fi
  echo "==> $abi done: bindings at $wrapper"
}

case "$ABI" in
  arm64-v8a|arm64)
    build_one arm64-v8a build aarch64-linux-android -mno-outline-atomics
    ;;
  x86_64|x64)
    build_one x86_64 build-x86_64 x86_64-linux-android ""
    ;;
  all)
    build_one arm64-v8a build aarch64-linux-android -mno-outline-atomics
    build_one x86_64 build-x86_64 x86_64-linux-android ""
    ;;
  *)
    echo "ERROR: unknown ABI '$ABI' (expected arm64-v8a, x86_64 or all)" >&2
    exit 2
    ;;
esac

# Wire the bssl-sys patch into the local Cargo configuration so that
# `python build.py --abi <abi>` can resolve the real bssl-sys crate.
if [ "$CONFIG_WRITE" -eq 1 ]; then
  CONFIG_FILE="$(cd "$(dirname "$0")/.." && pwd)/.cargo/config.toml"
  PATCH_LINE="bssl-sys = { path = \"$SRC_DIR/rust/bssl-sys\" }"
  mkdir -p "$(dirname "$CONFIG_FILE")"
  touch "$CONFIG_FILE"
  if ! grep -qF "$PATCH_LINE" "$CONFIG_FILE"; then
    {
      echo ""
      echo "[patch.crates-io]"
      echo "$PATCH_LINE"
    } >> "$CONFIG_FILE"
    echo "==> Appended bssl-sys patch to $CONFIG_FILE"
  else
    echo "==> bssl-sys patch already present in $CONFIG_FILE"
  fi
fi

echo ""
echo "BoringSSL build complete."
echo "Next steps:"
echo "  python scripts/setup_cargo_config.py --ndk-root \"$NDK_ROOT\" --force"
echo "  python build.py --release --abi x86_64   # and/or --abi arm64-v8a"