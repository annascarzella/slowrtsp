#!/usr/bin/env python3
"""Extract first FIN relative times from CNR timeout captures."""

from __future__ import annotations

import argparse
import math
import re
import shutil
import subprocess
import sys
from decimal import Decimal, ROUND_DOWN
from pathlib import Path

ENV_FILE = Path(__file__).resolve().parents[4] / ".env"
ENV_PROFILE = "bosch"


SRC_IP = ""
DST_IP = ""
DEFAULT_GLOB = "../../[0-9]*/1_find-server-timeout/output/capture.pcap"
THREE_DECIMALS = Decimal("0.001")


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = dict()
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip(chr(34)).strip(chr(39))
    return values


def profile_prefix(profile: str) -> str:
    return "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in profile.upper())


def env_value(env: dict[str, str], profile: str, key: str, default: str) -> str:
    prefix = profile_prefix(profile)
    return env.get(f"{prefix}_{key}") or env.get(key) or default


def natural_key(path: Path) -> list[int | str]:
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", str(path))]


def format_decimal(value: Decimal, decimal_comma: bool) -> str:
    text = f"{value:.3f}"
    return text.replace(".", ",") if decimal_comma else text


def first_fin_time(capture: Path, src_ip: str, dst_ip: str) -> Decimal | None:
    display_filter = (
        f"ip.src == {src_ip} && ip.dst == {dst_ip} && tcp.flags.fin == 1"
    )
    command = [
        "tshark",
        "-n",
        "-r",
        str(capture),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-e",
        "frame.time_relative",
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"tshark failed for {capture}")

    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped:
            return Decimal(stripped)
    return None


def sample_stddev(values: list[Decimal]) -> Decimal:
    if len(values) < 2:
        return Decimal("0")

    mean = sum(values) / Decimal(len(values))
    variance = sum((value - mean) ** 2 for value in values) / Decimal(len(values) - 1)
    return Decimal(str(math.sqrt(float(variance))))


def main() -> int:
    env = load_env(ENV_FILE)
    default_src_ip = env_value(env, ENV_PROFILE, "RTSP_SERVER", SRC_IP)
    default_dst_ip = env_value(env, ENV_PROFILE, "RTSP_SOURCE_IP", DST_IP)

    parser = argparse.ArgumentParser(
        description=(
            "Print the first FIN relative time from each "
            "[0-9]*/1_find-server-timeout capture, then average "
            "and sample standard deviation."
        )
    )
    parser.add_argument(
        "--glob",
        default=DEFAULT_GLOB,
        help=f"capture glob to scan, relative to this script directory (default: {DEFAULT_GLOB})",
    )
    parser.add_argument("--src-ip", default=default_src_ip)
    parser.add_argument("--dst-ip", default=default_dst_ip)
    parser.add_argument(
        "--decimal-comma",
        action="store_true",
        help="print numbers with a comma as the decimal separator",
    )
    args = parser.parse_args()

    if not args.src_ip or not args.dst_ip:
        print("error: --src-ip and --dst-ip are required unless configured in .env", file=sys.stderr)
        return 1

    if shutil.which("tshark") is None:
        print("error: tshark is required but was not found in PATH", file=sys.stderr)
        return 1

    script_dir = Path(__file__).resolve().parent
    captures = sorted(script_dir.glob(args.glob), key=natural_key)
    if not captures:
        print(f"error: no captures matched {args.glob}", file=sys.stderr)
        return 1

    values: list[Decimal] = []
    missing: list[Path] = []

    for capture in captures:
        raw_time = first_fin_time(capture, args.src_ip, args.dst_ip)
        if raw_time is None:
            missing.append(capture)
            continue

        truncated_time = raw_time.quantize(THREE_DECIMALS, rounding=ROUND_DOWN)
        values.append(truncated_time)
        print(f"{capture}: {format_decimal(truncated_time, args.decimal_comma)}")

    if missing:
        print("\nNo matching FIN packet found in:", file=sys.stderr)
        for capture in missing:
            print(f"  {capture}", file=sys.stderr)

    if not values:
        print("error: no matching FIN packets found", file=sys.stderr)
        return 1

    average = (sum(values) / Decimal(len(values))).quantize(
        THREE_DECIMALS, rounding=ROUND_DOWN
    )
    stddev = sample_stddev(values).quantize(THREE_DECIMALS, rounding=ROUND_DOWN)

    print()
    print(f"count: {len(values)}")
    print(f"average: {format_decimal(average, args.decimal_comma)}")
    print(f"standard deviation: {format_decimal(stddev, args.decimal_comma)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
