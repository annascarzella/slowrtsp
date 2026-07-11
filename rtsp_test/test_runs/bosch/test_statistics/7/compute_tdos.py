#!/usr/bin/env python3
"""Compute the time when the 64th TCP handshake completes for CNR captures."""

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
    "../../[0-9]*/7_attack-getparam-loop-nostream/"
    "output/capture.pcap"
)
DEFAULT_TARGET_CONNECTION = 64


@dataclass
class StreamState:
    saw_client_syn: bool = False
    saw_server_syn_ack: bool = False
    handshake_complete_time: float | None = None


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


def sample_stddev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0

    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values) / (len(values) - 1)
    stddev = math.sqrt(variance)
    return max(stddev, 0.0)


def run_tshark(capture: Path, server_port: str) -> str:
    command = [
        "tshark",
        "-n",
        "-r",
        str(capture),
        "-Y",
        f"tcp.port == {server_port} && (tcp.flags.syn == 1 || tcp.flags.ack == 1)",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "frame.time_relative",
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
        "tcp.flags.ack",
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"tshark failed for {capture}")
    return result.stdout


def flag_is_set(value: str) -> bool:
    return value in {"1", "True", "true"}


def handshake_completion_times(
    capture: Path,
    client_ip: str,
    server_ip: str,
    server_port: str,
) -> list[float]:
    streams: dict[int, StreamState] = {}

    for line in run_tshark(capture, server_port).splitlines():
        fields = line.split("\t")
        fields += [""] * (8 - len(fields))
        (
            time_text,
            stream_text,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            syn,
            ack,
        ) = fields[:8]

        if not stream_text or not time_text:
            continue

        stream = int(stream_text)
        timestamp = float(time_text)
        state = streams.setdefault(stream, StreamState())

        client_to_server = (
            src_ip == client_ip and dst_ip == server_ip and dst_port == server_port
        )
        server_to_client = (
            src_ip == server_ip and src_port == server_port and dst_ip == client_ip
        )

        syn_seen = flag_is_set(syn)
        ack_seen = flag_is_set(ack)

        if client_to_server and syn_seen and not ack_seen:
            state.saw_client_syn = True
        elif server_to_client and syn_seen and ack_seen and state.saw_client_syn:
            state.saw_server_syn_ack = True
        elif (
            client_to_server
            and ack_seen
            and not syn_seen
            and state.saw_client_syn
            and state.saw_server_syn_ack
            and state.handshake_complete_time is None
        ):
            state.handshake_complete_time = timestamp

    return sorted(
        state.handshake_complete_time
        for state in streams.values()
        if state.handshake_complete_time is not None
    )


def print_stats(label: str, values: list[float], decimal_comma: bool) -> None:
    average = sum(values) / len(values)
    stddev = sample_stddev(values)
    if stddev < 0:
        stddev = 0.0
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
            "For each CNR delay-5 PLAY-loop capture, print when the 64th TCP "
            "three-way handshake completes, then print average and sample "
            "standard deviation."
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
        "--target-connection",
        type=int,
        default=DEFAULT_TARGET_CONNECTION,
        help="Which completed handshake time to report. Default: 64",
    )
    parser.add_argument(
        "--absolute",
        action="store_true",
        help=(
            "Print frame.time_relative for the target handshake. By default, "
            "prints time relative to the first completed handshake in that capture."
        ),
    )
    parser.add_argument(
        "--decimal-comma",
        action="store_true",
        help="print values with a comma decimal separator",
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

    target_times: list[float] = []
    for capture in captures:
        completions = handshake_completion_times(
            capture=capture,
            client_ip=args.client_ip,
            server_ip=args.server_ip,
            server_port=args.server_port,
        )
        if len(completions) < args.target_connection:
            print(
                f"{capture.relative_to(script_dir)}: "
                f"completed_handshakes={len(completions)}, "
                f"connection_{args.target_connection}_time=NA"
            )
            continue

        raw_time = completions[args.target_connection - 1]
        first_time = completions[0]
        reported_time = raw_time if args.absolute else raw_time - first_time
        target_times.append(reported_time)
        print(
            f"{capture.relative_to(script_dir)}: "
            f"completed_handshakes={len(completions)}, "
            f"connection_{args.target_connection}_time="
            f"{format_float(reported_time, args.decimal_comma)}"
        )

    print()
    print(f"captures_with_{args.target_connection}_handshakes: {len(target_times)}")
    if not target_times:
        print(f"error: no capture had {args.target_connection} completed handshakes")
        return 1

    print_stats(
        f"connection_{args.target_connection}_time",
        target_times,
        args.decimal_comma,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
