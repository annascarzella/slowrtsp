#!/usr/bin/env python3
"""Count RTSP sessions established by SETUP CSeq 4 responses."""

from __future__ import annotations

import argparse
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


ENV_FILE = Path(__file__).resolve().parents[4] / ".env"
ENV_PROFILE = "reolink"
DEFAULT_SERVER_IP = ""
DEFAULT_CLIENT_IP = ""
DEFAULT_SERVER_PORT = "554"
DEFAULT_ATTEMPTED_CONNECTIONS = 1016
DEFAULT_GLOB_PREFIX = "../../[0-9]*/6_attack-play-loop-1016conn"
SETUP_CSEQ = "4"


@dataclass(frozen=True)
class DelayConfig:
    label: str
    td: str
    directory: str


@dataclass
class StreamState:
    first_frame: int | None = None
    saw_client_syn: bool = False
    saw_setup_cseq4: bool = False
    setup_cseq4_status: str | None = None


@dataclass
class CaptureCounts:
    established: int = 0
    not_established: int = 0
    observed_total: int = 0


@dataclass(frozen=True)
class SummaryRow:
    delay: str
    captures: int
    established_average: float
    established_stddev: float
    not_established_average: float
    not_established_stddev: float


DELAY_CONFIGS = (
    DelayConfig("delay0", "0", "i_delay0"),
    DelayConfig("delay0001", "0.001", "a_delay0001"),
    DelayConfig("delay01", "0.1", "b_delay01"),
    DelayConfig("delay1", "1", "c_delay1"),
    DelayConfig("delay3", "3", "d_delay3"),
    DelayConfig("delay4", "4", "e_delay4"),
    DelayConfig("delay5", "5", "f_delay5-OK"),
)


def natural_key(path: Path) -> list[int | str]:
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", str(path))]


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
    text = f"{value:.3f}"
    return text.replace(".", ",") if decimal_comma else text


def sample_stddev(values: list[int]) -> float:
    if len(values) < 2:
        return 0.0

    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values) / (len(values) - 1)
    return math.sqrt(variance)


def run_tshark(capture: Path, server_port: str) -> str:
    capture = capture.resolve()
    display_filter = (
        f"tcp.port == {server_port} && "
        "(tcp.flags.syn == 1 || rtsp)"
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
        "rtsp.method",
        "-e",
        "rtsp.status",
        "-e",
        "rtsp.cseq",
    ]
    env = os.environ.copy()
    env.setdefault("WIRESHARK_CONFIG_DIR", "/tmp")
    temp_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            dir="/tmp", prefix="session_capture_", suffix=".pcap", delete=False
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


def count_capture(
    capture: Path,
    client_ip: str,
    server_ip: str,
    server_port: str,
    attempted_connections: int,
) -> CaptureCounts:
    streams: dict[int, StreamState] = {}

    for line in run_tshark(capture, server_port).splitlines():
        fields = line.split("\t")
        fields += [""] * (10 - len(fields))
        (
            frame,
            stream_text,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            syn,
            method,
            status,
            cseq,
        ) = fields[:10]

        if not stream_text:
            continue

        stream = int(stream_text)
        state = streams.setdefault(stream, StreamState())
        if state.first_frame is None:
            state.first_frame = int(frame)

        client_to_server = (
            src_ip == client_ip and dst_ip == server_ip and dst_port == server_port
        )
        server_to_client = (
            src_ip == server_ip and src_port == server_port and dst_ip == client_ip
        )

        if client_to_server and syn in {"1", "True", "true"}:
            state.saw_client_syn = True

        if client_to_server and method == "SETUP" and cseq == SETUP_CSEQ:
            state.saw_setup_cseq4 = True

        if (
            server_to_client
            and state.saw_setup_cseq4
            and cseq == SETUP_CSEQ
            and status
            and state.setup_cseq4_status is None
        ):
            state.setup_cseq4_status = status

    attempted_streams = sorted(
        (
            state
            for state in streams.values()
            if state.saw_client_syn and state.first_frame is not None
        ),
        key=lambda state: state.first_frame or 0,
    )[:attempted_connections]

    counts = CaptureCounts(observed_total=len(attempted_streams))
    for state in attempted_streams:
        if state.setup_cseq4_status == "200":
            counts.established += 1

    counts.not_established = max(attempted_connections - counts.established, 0)
    return counts


def summarize(delay: str, all_counts: list[CaptureCounts]) -> SummaryRow:
    def average(values: list[int]) -> float:
        return sum(values) / len(values)

    established = [counts.established for counts in all_counts]
    not_established = [counts.not_established for counts in all_counts]
    return SummaryRow(
        delay=delay,
        captures=len(all_counts),
        established_average=average(established),
        established_stddev=sample_stddev(established),
        not_established_average=average(not_established),
        not_established_stddev=sample_stddev(not_established),
    )


def print_summary_table(rows: list[SummaryRow], decimal_comma: bool) -> None:
    header_groups = ["T_d", "Established", "", "Not established", ""]
    headers = ["", "mu", "sigma", "mu", "sigma"]
    table = [header_groups, headers]
    for row in rows:
        table.append(
            [
                row.delay,
                format_float(row.established_average, decimal_comma),
                format_float(row.established_stddev, decimal_comma),
                format_float(row.not_established_average, decimal_comma),
                format_float(row.not_established_stddev, decimal_comma),
            ]
        )

    widths = [max(len(row[index]) for row in table) for index in range(len(headers))]
    separator = "-+-".join("-" * width for width in widths)
    for index, row in enumerate(table):
        print(" | ".join(cell.ljust(widths[column]) for column, cell in enumerate(row)))
        if index in {0, 1}:
            print(separator)


def capture_glob(config: DelayConfig) -> str:
    return f"{DEFAULT_GLOB_PREFIX}/{config.directory}/output/capture.pcap"


def selected_configs(delay: str) -> list[DelayConfig]:
    if delay == "all":
        return list(DELAY_CONFIGS)
    return [config for config in DELAY_CONFIGS if config.label == delay]


def main() -> int:
    env = load_env(ENV_FILE)
    default_client_ip = env_value(env, ENV_PROFILE, "RTSP_SOURCE_IP", DEFAULT_CLIENT_IP)
    default_server_ip = env_value(env, ENV_PROFILE, "RTSP_SERVER", DEFAULT_SERVER_IP)
    default_server_port = env_value(env, ENV_PROFILE, "RTSP_PORT", DEFAULT_SERVER_PORT)

    parser = argparse.ArgumentParser(
        description=(
            "For each PLAY-loop capture, count RTSP sessions established when "
            "the first SETUP request with CSeq 4 receives a 200 OK response."
        )
    )
    parser.add_argument(
        "--delay",
        choices=["all", *(config.label for config in DELAY_CONFIGS)],
        default="all",
        help="delay group to process (default: all)",
    )
    parser.add_argument(
        "--attempted-connections",
        type=int,
        default=DEFAULT_ATTEMPTED_CONNECTIONS,
        help=f"attempted sessions per capture (default: {DEFAULT_ATTEMPTED_CONNECTIONS})",
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
    summary_rows: list[SummaryRow] = []
    for config in selected_configs(args.delay):
        glob_pattern = capture_glob(config)
        captures = sorted(script_dir.glob(glob_pattern), key=natural_key)
        if not captures:
            print(f"error: no captures matched {glob_pattern}", file=sys.stderr)
            return 1

        print(f"{config.label}:")
        all_counts: list[CaptureCounts] = []
        for capture in captures:
            counts = count_capture(
                capture=capture,
                client_ip=args.client_ip,
                server_ip=args.server_ip,
                server_port=args.server_port,
                attempted_connections=args.attempted_connections,
            )
            all_counts.append(counts)
            print(
                f"  {capture.relative_to(script_dir)}: "
                f"established={counts.established}, "
                f"not_established={counts.not_established}, "
                f"observed_total={counts.observed_total}"
            )
        print()
        summary_rows.append(summarize(config.td, all_counts))

    print("summary:")
    print_summary_table(summary_rows, args.decimal_comma)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
