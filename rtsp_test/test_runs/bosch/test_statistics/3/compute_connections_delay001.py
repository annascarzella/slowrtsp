#!/usr/bin/env python3
"""Count first RTSP/TCP outcomes for the max-options CNR captures."""

from __future__ import annotations

import argparse
import math
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ENV_FILE = Path(__file__).resolve().parents[4] / ".env"
ENV_PROFILE = "bosch"


SERVER_IP = ""
CLIENT_IP = ""
SERVER_PORT = "554"
DEFAULT_GLOB = (
    "../../[0-9]*/3_find-max-n-options/"
    "c_delay001_100conn/output/capture.pcap"
)


@dataclass
class StreamState:
    saw_options: bool = False
    first_server_outcome: str | None = None


@dataclass
class CaptureCounts:
    status_401_after_options: int = 0
    rst_immediate: int = 0
    status_503: int = 0
    unclassified: int = 0
    total: int = 0


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


def format_float(value: float, decimal_comma: bool) -> str:
    text = f"{value:.3f}"
    return text.replace(".", ",") if decimal_comma else text


def sample_stddev(values: list[int]) -> float:
    if len(values) < 2:
        return 0.0

    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values) / (len(values) - 1)
    return math.sqrt(variance)


def run_tshark(capture: Path, server_port: str) -> str:
    display_filter = (
        f"tcp.port == {server_port} && "
        "(tcp.flags.syn == 1 || rtsp || tcp.flags.reset == 1)"
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
        "-E",
        "separator=\t",
        "-e",
        "frame.number",
        "-e",
        "tcp.stream",
        "-e",
        "ip.src",
        "-e",
        "tcp.srcport",
        "-e",
        "ip.dst",
        "-e",
        "tcp.dstport",
        "-e",
        "tcp.flags.syn",
        "-e",
        "tcp.flags.reset",
        "-e",
        "rtsp.method",
        "-e",
        "rtsp.status",
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"tshark failed for {capture}")
    return result.stdout


def count_capture(
    capture: Path,
    client_ip: str,
    server_ip: str,
    server_port: str,
) -> CaptureCounts:
    streams: dict[int, StreamState] = {}

    for line in run_tshark(capture, server_port).splitlines():
        fields = line.split("	")
        fields += [""] * (10 - len(fields))
        (
            _frame,
            stream_text,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            _syn,
            reset,
            method,
            status,
        ) = fields[:10]

        if not stream_text:
            continue

        stream = int(stream_text)
        state = streams.setdefault(stream, StreamState())
        client_to_server = (
            src_ip == client_ip and dst_ip == server_ip and dst_port == server_port
        )
        server_to_client = (
            src_ip == server_ip and src_port == server_port and dst_ip == client_ip
        )

        if client_to_server and method == "OPTIONS":
            state.saw_options = True

        if not server_to_client or state.first_server_outcome is not None:
            continue

        if status:
            if status == "401" and state.saw_options:
                state.first_server_outcome = "401_after_options"
            elif status == "503":
                state.first_server_outcome = "503"
            else:
                state.first_server_outcome = f"other_status_{status}"
        elif reset in {"1", "True", "true"}:
            state.first_server_outcome = "rst_immediate"

    counts = CaptureCounts(total=len(streams))
    for state in streams.values():
        if state.first_server_outcome == "401_after_options":
            counts.status_401_after_options += 1
        elif state.first_server_outcome == "rst_immediate":
            counts.rst_immediate += 1
        elif state.first_server_outcome == "503":
            counts.status_503 += 1
        else:
            counts.unclassified += 1

    return counts


def print_stats(label: str, values: list[int], decimal_comma: bool) -> None:
    average = sum(values) / len(values)
    stddev = sample_stddev(values)
    print(
        f"{label}: avg={format_float(average, decimal_comma)}, "
        f"stddev={format_float(stddev, decimal_comma)}"
    )


def main() -> int:
    env = load_env(ENV_FILE)
    default_client_ip = env_value(env, ENV_PROFILE, "RTSP_SOURCE_IP", CLIENT_IP)
    default_server_ip = env_value(env, ENV_PROFILE, "RTSP_SERVER", SERVER_IP)
    default_server_port = env_value(env, ENV_PROFILE, "RTSP_PORT", SERVER_PORT)

    parser = argparse.ArgumentParser(
        description=(
            "For each max-options capture, count connections whose first server "
            "outcome is 401 after OPTIONS, immediate RST, or 503; then print "
            "averages and sample standard deviations."
        )
    )
    parser.add_argument(
        "--glob",
        default=DEFAULT_GLOB,
        help=f"capture glob relative to this script directory (default: {DEFAULT_GLOB})",
    )
    parser.add_argument("--client-ip", default=default_client_ip)
    parser.add_argument("--server-ip", default=default_server_ip)
    parser.add_argument("--server-port", default=default_server_port)
    parser.add_argument(
        "--decimal-comma",
        action="store_true",
        help="print averages and standard deviations with a comma decimal separator",
    )
    args = parser.parse_args()

    if not args.client_ip or not args.server_ip:
        print("error: --client-ip and --server-ip are required unless configured in .env", file=sys.stderr)
        return 1

    if shutil.which("tshark") is None:
        print("error: tshark is required but was not found in PATH", file=sys.stderr)
        return 1

    script_dir = Path(__file__).resolve().parent
    captures = sorted(script_dir.glob(args.glob), key=natural_key)
    if not captures:
        print(f"error: no captures matched {args.glob}", file=sys.stderr)
        return 1

    all_counts: list[CaptureCounts] = []
    for capture in captures:
        counts = count_capture(
            capture=capture,
            client_ip=args.client_ip,
            server_ip=args.server_ip,
            server_port=args.server_port,
        )
        all_counts.append(counts)
        print(
            f"{capture.relative_to(script_dir)}: "
            f"401_after_options={counts.status_401_after_options}, "
            f"rst_immediate={counts.rst_immediate}, "
            f"503={counts.status_503}, "
            f"unclassified={counts.unclassified}, "
            f"total={counts.total}"
        )

    print()
    print(f"captures: {len(all_counts)}")
    print_stats(
        "401_after_options",
        [counts.status_401_after_options for counts in all_counts],
        args.decimal_comma,
    )
    print_stats(
        "rst_immediate",
        [counts.rst_immediate for counts in all_counts],
        args.decimal_comma,
    )
    print_stats(
        "503",
        [counts.status_503 for counts in all_counts],
        args.decimal_comma,
    )
    print_stats(
        "unclassified",
        [counts.unclassified for counts in all_counts],
        args.decimal_comma,
    )
    print_stats("total", [counts.total for counts in all_counts], args.decimal_comma)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
