#!/usr/bin/env python3
"""
Build, deploy, verify, and optionally run the injector binary on an Android device.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SERIAL = "emulator-5554"
DEFAULT_REMOTE_PATH = "/data/adb/inject"
DEFAULT_STAGING_PATH = "/data/local/tmp/inject.deploy"
DEFAULT_PLATFORM = 24

ABI_TO_TARGET = {
    "x86_64": "x86_64-linux-android",
    "arm64-v8a": "aarch64-linux-android",
}


def run(cmd: list[str], *, check: bool = True, capture_output: bool = False) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(cmd))
    return subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        check=check,
        text=True,
        capture_output=capture_output,
    )


def sha256sum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_injector(abi: str, release: bool, platform: int) -> Path:
    cargo_cmd = ["cargo", "ndk", "-t", abi, "--platform", str(platform), "build", "-p", "injector"]
    if release:
        cargo_cmd.append("--release")
    run(cargo_cmd)

    target = ABI_TO_TARGET[abi]
    profile = "release" if release else "debug"
    binary = REPO_ROOT / "target" / target / profile / "inject"
    if not binary.exists():
        raise FileNotFoundError(f"built injector not found: {binary}")
    return binary


def adb(serial: str, *args: str, capture_output: bool = False) -> subprocess.CompletedProcess[str]:
    return run(["adb", "-s", serial, *args], capture_output=capture_output)


def adb_shell(serial: str, command: str, *, capture_output: bool = False) -> subprocess.CompletedProcess[str]:
    return adb(serial, "shell", command, capture_output=capture_output)


def verify_remote_binary(serial: str, remote_path: str) -> None:
    remote_checks = (
        f"su -c '"
        f"file {remote_path} && "
        f"sha256sum {remote_path} && "
        f"ls -lZ {remote_path}"
        f"'"
    )
    adb_shell(serial, remote_checks)


def remote_sha256sum(serial: str, remote_path: str) -> str:
    output = adb_shell(
        serial,
        f"su -c 'sha256sum {remote_path}'",
        capture_output=True,
    ).stdout.strip()
    if not output:
        raise RuntimeError(f"sha256sum produced no output for {remote_path}")
    return output.split()[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and deploy the injector binary")
    parser.add_argument("--abi", choices=sorted(ABI_TO_TARGET), default="x86_64")
    parser.add_argument("--platform", type=int, default=DEFAULT_PLATFORM)
    parser.add_argument("--serial", default=DEFAULT_SERIAL)
    parser.add_argument("--remote-path", default=DEFAULT_REMOTE_PATH)
    parser.add_argument("--staging-path", default=DEFAULT_STAGING_PATH)
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--run", action="store_true", help="execute the deployed injector via su -c")
    parser.add_argument(
        "--clear-log",
        action="store_true",
        help="truncate /data/misc/keystore/omk/injector.log before running",
    )
    args = parser.parse_args()

    if args.skip_build:
        target = ABI_TO_TARGET[args.abi]
        profile = "release" if args.release else "debug"
        binary = REPO_ROOT / "target" / target / profile / "inject"
    else:
        binary = build_injector(args.abi, args.release, args.platform)

    if not binary.exists():
        raise FileNotFoundError(f"injector binary not found: {binary}")

    local_sha = sha256sum(binary)
    print(f"Local injector: {binary}")
    print(f"Local SHA-256: {local_sha}")

    adb(args.serial, "push", os.fspath(binary), args.staging_path)
    adb_shell(
        args.serial,
        (
            "su -c '"
            f"mkdir -p {Path(args.remote_path).parent.as_posix()} && "
            f"cp {args.staging_path} {args.remote_path}"
            "'"
        ),
    )
    adb_shell(args.serial, f"su -c 'chmod 0755 {args.remote_path}'")
    adb_shell(args.serial, f"su -c 'chcon u:object_r:system_file:s0 {args.remote_path}'")
    verify_remote_binary(args.serial, args.remote_path)

    remote_sha = remote_sha256sum(args.serial, args.remote_path)
    if remote_sha != local_sha:
        raise RuntimeError(
            f"remote SHA-256 mismatch for {args.remote_path}: local={local_sha} remote={remote_sha}"
        )

    if args.clear_log:
        adb_shell(args.serial, "su -c ': > /data/misc/keystore/omk/injector.log'")

    if args.run:
        adb_shell(args.serial, f"su -c '{args.remote_path}'")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover
        print(f"deploy_injector.py failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
