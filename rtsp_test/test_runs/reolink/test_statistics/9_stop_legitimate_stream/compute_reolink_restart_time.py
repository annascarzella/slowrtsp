#!/usr/bin/env python3
"""Compute Reolink restart time after legitimate stream closures.

For each 9_reolink_stop_streaming_and_dos capture, the measured value is:

    first Phase 2 server 200 OK time - last Phase 0/1 server FIN time before it

Phase 2 is detected as the first RTSP 200 OK on a TCP stream that is not part
of the initial Phase 0 connection attempts.

Phase 0/1 closures are detected as server-to-client FIN packets only on the
first 1016 TCP streams, because Phase 1 reuses those initial Phase 0
connections.
"""

from __future__ import annotations

import argparse
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


ENV_FILE = Path(__file__).resolve().parents[4] / ".env"
ENV_PROFILE = "reolink"
DEFAULT_SERVER_IP = ""
DEFAULT_CLIENT_IP = ""
DEFAULT_SERVER_PORT = "554"
DEFAULT_PHASE0_CONNECTIONS = 1016
DEFAULT_GLOB = "../../[0-9]*/9_reolink_stop_streaming_and_dos/output/capture.pcap"


@dataclass(frozen=True)
class CaptureMeasurement:
    capture: Path
    last_closure_time: float
    phase2_200_time: float
    restart_time: float
    phase2_stream: int
    phase0_streams_seen: int
    phase0_server_fins_before_phase2: int


def natural_key(path: Path) -> list[int | str]:
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", str(path))]


def parse_test_numbers(value: str) -> set[int]:
    tests: set[int] = set()
    for part in re.split(r"[,\s]+", value.strip()):
        if not part:
            continue
        try:
            tests.add(int(part))
        except ValueError as error:
            raise argparse.ArgumentTypeError(
                f"invalid test number {part!r}; use values like 11,12"
            ) from error
    return tests


def capture_test_number(capture: Path) -> int | None:
    match = re.search(
        r"(?:^|[/\\])reolink[/\\](\d+)(?:[/\\])", str(capture)
    )
    return int(match.group(1)) if match else None


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'")
    return values


def profile_prefix(profile: str) -> str:
    return "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in profile.upper())


def env_value(env: dict[str, str], profile: str, key: str, default: str) -> str:
    prefix = profile_prefix(profile)
    return env.get(f"{prefix}_{key}") or env.get(key) or default


def format_float(value: float, decimal_comma: bool) -> str:
    text = f"{value:.6f}"
    return text.replace(".", ",") if decimal_comma else text


def average(values: Sequence[float]) -> float:
    return sum(values) / len(values)


def sample_stddev(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0

    mean = average(values)
    variance = sum((value - mean) ** 2 for value in values) / (len(values) - 1)
    return math.sqrt(variance)


def run_tshark(capture: Path, server_port: str) -> str:
    capture = capture.resolve()
    display_filter = (
        f"tcp.port == {server_port} && "
        "(tcp.flags.syn == 1 || tcp.flags.fin == 1 || tcp.flags.reset == 1 || rtsp.status == 200)"
    )
    command = [
        "tshark",
        "-n",
        "-r",
        "",
        "-Y",
        display_filter,
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
        "tcp.flags.fin",
        "-e",
        "tcp.flags.reset",
        "-e",
        "rtsp.status",
    ]
    env = os.environ.copy()
    env.setdefault("WIRESHARK_CONFIG_DIR", "/tmp")
    temp_path = ""

    try:
        with tempfile.NamedTemporaryFile(
            dir="/tmp", prefix="reolink_restart_capture_", suffix=".pcap", delete=False
        ) as temp_capture:
            temp_path = temp_capture.name
            with capture.open("rb") as capture_file:
                shutil.copyfileobj(capture_file, temp_capture)

        command[3] = temp_path
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
    finally:
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"tshark failed for {capture}")

    return result.stdout


def is_true(value: str) -> bool:
    return value in {"1", "True", "true"}


def measure_capture(
    capture: Path,
    client_ip: str,
    server_ip: str,
    server_port: str,
    phase0_connections: int,
) -> CaptureMeasurement:
    phase0_streams: set[int] = set()
    phase0_stream_order: list[int] = []
    last_closure_time: float | None = None
    phase0_server_fins_before_phase2 = 0

    for line in run_tshark(capture, server_port).splitlines():
        fields = line.split("\t")
        fields += [""] * (10 - len(fields))
        (
            time_text,
            stream_text,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            syn,
            fin,
            reset,
            status,
        ) = fields[:10]

        if not time_text or not stream_text:
            continue

        timestamp = float(time_text)
        stream = int(stream_text)
        client_to_server = (
            src_ip == client_ip and dst_ip == server_ip and dst_port == server_port
        )
        server_to_client = (
            src_ip == server_ip and src_port == server_port and dst_ip == client_ip
        )

        if (
            client_to_server
            and is_true(syn)
            and stream not in phase0_streams
            and len(phase0_stream_order) < phase0_connections
        ):
            phase0_streams.add(stream)
            phase0_stream_order.append(stream)

        close_seen = (
            server_to_client
            and stream in phase0_streams
            and is_true(fin)
        )
        if close_seen:
            last_closure_time = timestamp
            phase0_server_fins_before_phase2 += 1

        if (
            server_to_client
            and status == "200"
            and len(phase0_stream_order) >= phase0_connections
            and stream not in phase0_streams
        ):
            if last_closure_time is None:
                raise RuntimeError(
                    f"{capture}: found Phase 2 200 OK before any TCP closure"
                )

            return CaptureMeasurement(
                capture=capture,
                last_closure_time=last_closure_time,
                phase2_200_time=timestamp,
                restart_time=timestamp - last_closure_time,
                phase2_stream=stream,
                phase0_streams_seen=len(phase0_stream_order),
                phase0_server_fins_before_phase2=phase0_server_fins_before_phase2,
            )

    raise RuntimeError(
        f"{capture}: no Phase 2 200 OK found after "
        f"{len(phase0_stream_order)}/{phase0_connections} Phase 0 streams"
    )


def print_results(
    measurements: Sequence[CaptureMeasurement],
    script_dir: Path,
    decimal_comma: bool,
) -> None:
    for measurement in measurements:
        print(
            f"{measurement.capture.relative_to(script_dir)}: "
            "last_closure_at="
            f"{format_float(measurement.last_closure_time, decimal_comma)}, "
            "phase2_200_at="
            f"{format_float(measurement.phase2_200_time, decimal_comma)}, "
            "restart_time="
            f"{format_float(measurement.restart_time, decimal_comma)}, "
            f"phase2_stream={measurement.phase2_stream}, "
            f"phase0_server_fins_before_phase2={measurement.phase0_server_fins_before_phase2}"
        )

    values = [measurement.restart_time for measurement in measurements]
    print()
    print(f"captures={len(values)}")
    print(f"avg={format_float(average(values), decimal_comma)}")
    print(f"stddev={format_float(sample_stddev(values), decimal_comma)}")


def main() -> int:
    env = load_env(ENV_FILE)
    default_client_ip = env_value(env, ENV_PROFILE, "RTSP_SOURCE_IP", DEFAULT_CLIENT_IP)
    default_server_ip = env_value(env, ENV_PROFILE, "RTSP_SERVER", DEFAULT_SERVER_IP)
    default_server_port = env_value(env, ENV_PROFILE, "RTSP_PORT", DEFAULT_SERVER_PORT)

    parser = argparse.ArgumentParser(
        description=(
            "Measure time from the last TCP closure to the first Phase 2 "
            "server RTSP 200 OK in Reolink stop-streaming captures."
        )
    )
    parser.add_argument(
        "--glob",
        default=DEFAULT_GLOB,
        help=f"capture glob relative to this script (default: {DEFAULT_GLOB})",
    )
    parser.add_argument(
        "--phase0-connections",
        type=int,
        default=DEFAULT_PHASE0_CONNECTIONS,
        help=f"initial Phase 0 connection attempts (default: {DEFAULT_PHASE0_CONNECTIONS})",
    )
    parser.add_argument(
        "--exclude-tests",
        type=parse_test_numbers,
        default=set(),
        help="comma- or space-separated test numbers to skip, for example: 11,12",
    )
    parser.add_argument("--client-ip", default=default_client_ip)
    parser.add_argument("--server-ip", default=default_server_ip)
    parser.add_argument("--server-port", default=default_server_port)
    parser.add_argument(
        "--decimal-comma",
        action="store_true",
        help="print numeric values with a comma decimal separator",
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
    if args.exclude_tests:
        captures = [
            capture
            for capture in captures
            if capture_test_number(capture) not in args.exclude_tests
        ]
    if not captures:
        print(f"error: no captures matched {args.glob}", file=sys.stderr)
        return 1

    measurements = [
        measure_capture(
            capture=capture,
            client_ip=args.client_ip,
            server_ip=args.server_ip,
            server_port=args.server_port,
            phase0_connections=args.phase0_connections,
        )
        for capture in captures
    ]

    print_results(measurements, script_dir, args.decimal_comma)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
