#!/usr/bin/env python3
"""Count OPTIONS-open and RST-closed connections for all CNR PLAY-loop delays."""

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
DEFAULT_DELAY_FOLDERS = (
    "a_delay0001",
    "b_delay01",
    "c_delay1",
    "d_delay3",
    "e_delay4",
    "f_delay5-OK",
)
DEFAULT_GLOB = (
    "../../[0-9]*/6_attack-play-loop-64conn/"
    "{delay_folder}/output/capture.pcap"
)


@dataclass
class StreamState:
    first_client_method: str | None = None
    first_server_status: str | None = None
    open_after_first_options: bool = False
    closed_with_rst: bool = False


@dataclass
class CaptureCounts:
    open_after_first_options: int = 0
    closed_with_rst: int = 0
    total_streams: int = 0


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
    stddev = math.sqrt(variance)
    return max(stddev, 0.0)


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


def flag_is_set(value: str) -> bool:
    return value in {"1", "True", "true"}


def count_capture(
    capture: Path,
    client_ip: str,
    server_ip: str,
    server_port: str,
) -> CaptureCounts:
    streams: dict[int, StreamState] = {}

    for line in run_tshark(capture, server_port).splitlines():
        fields = line.split("\t")
        fields += [""] * (9 - len(fields))
        (
            _frame,
            stream_text,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            reset,
            method,
            status,
        ) = fields[:9]

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

        if flag_is_set(reset):
            state.closed_with_rst = True

        if client_to_server and method and state.first_client_method is None:
            state.first_client_method = method

        if (
            server_to_client
            and status
            and state.first_client_method is not None
            and state.first_server_status is None
        ):
            state.first_server_status = status
            state.open_after_first_options = (
                state.first_client_method == "OPTIONS" and status == "401"
            )

    counts = CaptureCounts(total_streams=len(streams))
    for state in streams.values():
        if state.open_after_first_options:
            counts.open_after_first_options += 1
        if state.closed_with_rst:
            counts.closed_with_rst += 1

    return counts


def print_stats(label: str, values: list[int], decimal_comma: bool) -> None:
    average = sum(values) / len(values)
    stddev = sample_stddev(values)
    if stddev < 0:
        stddev = 0.0
    print(
        f"{label}: avg={format_float(average, decimal_comma)}, "
        f"stddev={format_float(stddev, decimal_comma)}"
    )


def parse_delay_folders(value: str) -> list[str]:
    return [folder.strip() for folder in value.split(",") if folder.strip()]


def main() -> int:
    env = load_env(ENV_FILE)
    default_client_ip = env_value(env, ENV_PROFILE, "RTSP_SOURCE_IP", CLIENT_IP)
    default_server_ip = env_value(env, ENV_PROFILE, "RTSP_SERVER", SERVER_IP)
    default_server_port = env_value(env, ENV_PROFILE, "RTSP_PORT", SERVER_PORT)

    parser = argparse.ArgumentParser(
        description=(
            "For each CNR PLAY-loop capture, count connections as open only when "
            "the first RTSP request is OPTIONS and the first server response is "
            "401, and count connections closed with RST; then print averages "
            "and sample standard deviations grouped by delay folder."
        )
    )
    parser.add_argument(
        "--glob",
        default=DEFAULT_GLOB,
        help=(
            "capture glob relative to this script directory. Use {delay_folder} "
            f"as the delay folder placeholder (default: {DEFAULT_GLOB})"
        ),
    )
    parser.add_argument(
        "--delay-folders",
        default=",".join(DEFAULT_DELAY_FOLDERS),
        help=(
            "comma-separated delay folders to process "
            f"(default: {','.join(DEFAULT_DELAY_FOLDERS)})"
        ),
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
    delay_folders = parse_delay_folders(args.delay_folders)
    if not delay_folders:
        print("error: --delay-folders must contain at least one folder", file=sys.stderr)
        return 1

    matched_any = False
    for delay_folder in delay_folders:
        capture_glob = args.glob.format(delay_folder=delay_folder)
        captures = sorted(script_dir.glob(capture_glob), key=natural_key)
        if not captures:
            print(f"{delay_folder}: no captures matched {capture_glob}")
            continue

        matched_any = True
        all_counts: list[CaptureCounts] = []
        print(f"{delay_folder}:")
        for capture in captures:
            counts = count_capture(
                capture=capture,
                client_ip=args.client_ip,
                server_ip=args.server_ip,
                server_port=args.server_port,
            )
            all_counts.append(counts)
            print(
                f"  {capture.relative_to(script_dir)}: "
                f"open_after_first_options_401={counts.open_after_first_options}, "
                f"closed_with_rst={counts.closed_with_rst}, "
                f"total_streams={counts.total_streams}"
            )

        print()
        print(f"{delay_folder} captures: {len(all_counts)}")
        print_stats(
            f"{delay_folder} open_after_first_options_401",
            [counts.open_after_first_options for counts in all_counts],
            args.decimal_comma,
        )
        print_stats(
            f"{delay_folder} closed_with_rst",
            [counts.closed_with_rst for counts in all_counts],
            args.decimal_comma,
        )
        print_stats(
            f"{delay_folder} total_streams",
            [counts.total_streams for counts in all_counts],
            args.decimal_comma,
        )
        print()

    if not matched_any:
        print(
            f"error: no captures matched {args.glob} for {','.join(delay_folders)}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
