#!/usr/bin/env python3
"""Count correctly opened connections that close after sending SETUP CSeq 4."""

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
DEFAULT_ATTEMPTED_CONNECTIONS = 1016
DEFAULT_GLOB_PREFIX = "../../[0-9]*/6_attack-play-loop-1016conn"
OPTIONS_CSEQ = "1"
SETUP_CSEQ = "4"

# TODO: rerun these tests and rerun this script, then remove this exclusion so
# they are included in the analysis again.
EXCLUDED_CAPTURE_PARTS = (
    # "test_runs/reolink/1/6_attack-play-loop-1016conn/d_delay3/output/capture.pcap",
    # "test_runs/reolink/1/6_attack-play-loop-1016conn/e_delay4/output/capture.pcap",
    # "test_runs/reolink/5/6_attack-play-loop-1016conn/b_delay01/output/capture.pcap",
    # "test_runs/reolink/6/6_attack-play-loop-1016conn/a_delay0001/output/capture.pcap",
    # "test_runs/reolink/7/6_attack-play-loop-1016conn/f_delay5-OK/output/capture.pcap",
    # "test_runs/reolink/8/6_attack-play-loop-1016conn/a_delay0001/output/capture.pcap",
    # "test_runs/reolink/12/6_attack-play-loop-1016conn/c_delay1/output/capture.pcap",
)


@dataclass(frozen=True)
class DelayConfig:
    label: str
    td: str
    directory: str


@dataclass
class StreamState:
    first_frame: int | None = None
    saw_client_syn: bool = False
    saw_options_cseq1: bool = False
    options_cseq1_200_frame: int | None = None
    setup_cseq4_frame: int | None = None
    close_after_setup_cseq4: bool = False
    server_close_after_setup_time: float | None = None


@dataclass
class CaptureCounts:
    options_200: int = 0
    closed_after_setup: int = 0
    observed_total: int = 0
    first_server_close_time: float | None = None
    last_server_close_time: float | None = None


@dataclass(frozen=True)
class SummaryRow:
    delay: str
    captures: int
    options_200_average: float
    options_200_stddev: float
    closed_average: float
    closed_stddev: float
    first_closed_average: float | None
    first_closed_stddev: float | None
    last_closed_average: float | None
    last_closed_stddev: float | None


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


def format_optional_float(value: float | None, decimal_comma: bool) -> str:
    if value is None:
        return "n/a"
    return format_float(value, decimal_comma)


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
        "(tcp.flags.syn == 1 || tcp.flags.fin == 1 || tcp.flags.reset == 1 || rtsp)"
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
            dir="/tmp", prefix="session_closure_capture_", suffix=".pcap", delete=False
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
        fields += [""] * (13 - len(fields))
        (
            frame_text,
            time_text,
            stream_text,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            syn,
            fin,
            reset,
            method,
            status,
            cseq,
        ) = fields[:13]

        if not stream_text:
            continue

        frame = int(frame_text)
        stream = int(stream_text)
        state = streams.setdefault(stream, StreamState())
        if state.first_frame is None:
            state.first_frame = frame

        client_to_server = (
            src_ip == client_ip and dst_ip == server_ip and dst_port == server_port
        )
        server_to_client = (
            src_ip == server_ip and src_port == server_port and dst_ip == client_ip
        )

        if client_to_server and syn in {"1", "True", "true"}:
            state.saw_client_syn = True

        if client_to_server and method == "OPTIONS" and cseq == OPTIONS_CSEQ:
            state.saw_options_cseq1 = True

        if (
            client_to_server
            and method == "SETUP"
            and cseq == SETUP_CSEQ
            and state.options_cseq1_200_frame is not None
            and state.setup_cseq4_frame is None
        ):
            state.setup_cseq4_frame = frame

        if (
            server_to_client
            and state.saw_options_cseq1
            and cseq == OPTIONS_CSEQ
            and status == "200"
            and state.options_cseq1_200_frame is None
        ):
            state.options_cseq1_200_frame = frame

        close_seen = fin in {"1", "True", "true"} or reset in {"1", "True", "true"}
        if (
            close_seen
            and state.setup_cseq4_frame is not None
            and frame > state.setup_cseq4_frame
        ):
            state.close_after_setup_cseq4 = True
            if server_to_client and state.server_close_after_setup_time is None:
                state.server_close_after_setup_time = float(time_text)

    attempted_streams = sorted(
        (
            state
            for state in streams.values()
            if state.saw_client_syn and state.first_frame is not None
        ),
        key=lambda state: state.first_frame or 0,
    )[:attempted_connections]

    counts = CaptureCounts(observed_total=len(attempted_streams))
    server_close_times: list[float] = []
    for state in attempted_streams:
        if state.options_cseq1_200_frame is not None:
            counts.options_200 += 1
            if state.close_after_setup_cseq4:
                counts.closed_after_setup += 1
            if state.server_close_after_setup_time is not None:
                server_close_times.append(state.server_close_after_setup_time)

    if server_close_times:
        counts.first_server_close_time = min(server_close_times)
        counts.last_server_close_time = max(server_close_times)

    return counts


def summarize(delay: str, all_counts: list[CaptureCounts]) -> SummaryRow:
    options_200 = [counts.options_200 for counts in all_counts]
    closed = [counts.closed_after_setup for counts in all_counts]
    first_closed = [
        counts.first_server_close_time
        for counts in all_counts
        if counts.first_server_close_time is not None
    ]
    last_closed = [
        counts.last_server_close_time
        for counts in all_counts
        if counts.last_server_close_time is not None
    ]
    return SummaryRow(
        delay=delay,
        captures=len(all_counts),
        options_200_average=average(options_200),
        options_200_stddev=sample_stddev(options_200),
        closed_average=average(closed),
        closed_stddev=sample_stddev(closed),
        first_closed_average=average(first_closed) if first_closed else None,
        first_closed_stddev=sample_stddev(first_closed) if first_closed else None,
        last_closed_average=average(last_closed) if last_closed else None,
        last_closed_stddev=sample_stddev(last_closed) if last_closed else None,
    )


def print_summary_table(rows: list[SummaryRow], decimal_comma: bool) -> None:
    header_groups = [
        "T_d",
        "OPTIONS 200",
        "",
        "Closed after SETUP CSeq 4",
        "",
        "First connection closed at",
        "",
        "Last connection closed at",
        "",
    ]
    headers = ["", "mu", "sigma", "mu", "sigma", "mu", "sigma", "mu", "sigma"]
    table = [header_groups, headers]
    for row in rows:
        table.append(
            [
                row.delay,
                format_float(row.options_200_average, decimal_comma),
                format_float(row.options_200_stddev, decimal_comma),
                format_float(row.closed_average, decimal_comma),
                format_float(row.closed_stddev, decimal_comma),
                format_optional_float(row.first_closed_average, decimal_comma),
                format_optional_float(row.first_closed_stddev, decimal_comma),
                format_optional_float(row.last_closed_average, decimal_comma),
                format_optional_float(row.last_closed_stddev, decimal_comma),
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


def is_excluded_capture(capture: Path) -> bool:
    normalized = capture.resolve().as_posix()
    return any(part in normalized for part in EXCLUDED_CAPTURE_PARTS)


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
            "For each PLAY-loop capture, count TCP streams opened correctly by "
            "OPTIONS CSeq 1 200 OK that later close after sending SETUP CSeq 4."
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
    summary_rows: list[SummaryRow] = []
    for config in selected_configs(args.delay):
        glob_pattern = capture_glob(config)
        captures = sorted(
            (
                capture
                for capture in script_dir.glob(glob_pattern)
                if not is_excluded_capture(capture)
            ),
            key=natural_key,
        )
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
                f"options_200={counts.options_200}, "
                f"closed_after_setup_cseq4={counts.closed_after_setup}, "
                "first_connection_closed_at="
                f"{format_optional_float(counts.first_server_close_time, args.decimal_comma)}, "
                "last_connection_closed_at="
                f"{format_optional_float(counts.last_server_close_time, args.decimal_comma)}, "
                f"observed_total={counts.observed_total}"
            )
        print()
        summary_rows.append(summarize(config.td, all_counts))

    print("summary:")
    print_summary_table(summary_rows, args.decimal_comma)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
