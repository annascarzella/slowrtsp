#!/usr/bin/env python3
"""Count first RTSP/TCP outcomes for all max-options DIBRIS delay captures."""

from __future__ import annotations

import argparse
import math
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ENV_FILE = Path(__file__).resolve().parents[4] / ".env"
ENV_PROFILE = "reolink"
DEFAULT_SERVER_IP = ""
DEFAULT_CLIENT_IP = ""
DEFAULT_SERVER_PORT = "554"
DEFAULT_ATTEMPTED_CONNECTIONS = 1200
DEFAULT_GLOB_PREFIX = "../../[0-9]*/3_find-max-n-options"


@dataclass(frozen=True)
class DelayConfig:
    label: str
    td: str
    directory_patterns: tuple[str, ...]


@dataclass
class StreamState:
    saw_options: bool = False
    first_server_outcome: str | None = None


@dataclass
class CaptureCounts:
    status_200_after_options: int = 0
    rst_immediate: int = 0
    status_503: int = 0
    no_answer: int = 0
    unclassified: int = 0
    total: int = 0


@dataclass(frozen=True)
class SummaryRow:
    delay: str
    captures: int
    status_200_average: float
    status_200_stddev: float
    rst_average: float
    rst_stddev: float
    status_503_average: float
    status_503_stddev: float
    no_answer_average: float
    no_answer_stddev: float
    total_average: float
    total_stddev: float


DELAY_CONFIGS = (
    DelayConfig("delay0", "0", ("a_delay0_*conn",)),
    DelayConfig("delay0001", "0.001", ("b_delay0001_*conn",)),
    DelayConfig("delay001", "0.01", ("c_delay001_*conn", "c_delay01_*conn")),
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
        "(tcp.flags.syn == 1 || rtsp || tcp.flags.reset == 1)"
    )
    command = [
        "tshark",
        "-n",
        "-r",
        "-",
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
    env = os.environ.copy()
    env.setdefault("WIRESHARK_CONFIG_DIR", "/tmp")
    with capture.open("rb") as capture_file:
        result = subprocess.run(
            command,
            stdin=capture_file,
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
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
        fields = line.split("\t")
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
            if status == "200" and state.saw_options:
                state.first_server_outcome = "200_after_options"
            elif status == "503":
                state.first_server_outcome = "503"
            else:
                state.first_server_outcome = f"other_status_{status}"
        elif reset in {"1", "True", "true"}:
            state.first_server_outcome = "rst_immediate"

    counts = CaptureCounts(total=len(streams))
    for state in streams.values():
        if state.first_server_outcome == "200_after_options":
            counts.status_200_after_options += 1
        elif state.first_server_outcome == "rst_immediate":
            counts.rst_immediate += 1
        elif state.first_server_outcome == "503":
            counts.status_503 += 1
        else:
            counts.unclassified += 1

    return counts


def summarize(delay: str, all_counts: list[CaptureCounts]) -> SummaryRow:
    def average(values: list[int]) -> float:
        return sum(values) / len(values)

    status_200 = [counts.status_200_after_options for counts in all_counts]
    rst = [counts.rst_immediate for counts in all_counts]
    status_503 = [counts.status_503 for counts in all_counts]
    no_answer = [counts.no_answer for counts in all_counts]
    totals = [counts.total for counts in all_counts]
    return SummaryRow(
        delay=delay,
        captures=len(all_counts),
        status_200_average=average(status_200),
        status_200_stddev=sample_stddev(status_200),
        rst_average=average(rst),
        rst_stddev=sample_stddev(rst),
        status_503_average=average(status_503),
        status_503_stddev=sample_stddev(status_503),
        no_answer_average=average(no_answer),
        no_answer_stddev=sample_stddev(no_answer),
        total_average=average(totals),
        total_stddev=sample_stddev(totals),
    )


def print_summary_table(rows: list[SummaryRow], decimal_comma: bool) -> None:
    header_groups = [
        "T_d",
        "200",
        "",
        "RST",
        "",
        "503",
        "",
        "No answer",
        "",
    ]
    headers = ["", "mu", "sigma", "mu", "sigma", "mu", "sigma", "mu", "sigma"]
    table = [header_groups, headers]
    for row in rows:
        table.append(
            [
                row.delay,
                format_float(row.status_200_average, decimal_comma),
                format_float(row.status_200_stddev, decimal_comma),
                format_float(row.rst_average, decimal_comma),
                format_float(row.rst_stddev, decimal_comma),
                format_float(row.status_503_average, decimal_comma),
                format_float(row.status_503_stddev, decimal_comma),
                format_float(row.no_answer_average, decimal_comma),
                format_float(row.no_answer_stddev, decimal_comma),
            ]
        )

    widths = [max(len(row[index]) for row in table) for index in range(len(headers))]
    separator = "-+-".join("-" * width for width in widths)
    for index, row in enumerate(table):
        print(" | ".join(cell.ljust(widths[column]) for column, cell in enumerate(row)))
        if index in {0, 1}:
            print(separator)


def capture_globs(config: DelayConfig) -> list[str]:
    return [
        f"{DEFAULT_GLOB_PREFIX}/{directory}/output/capture.pcap"
        for directory in config.directory_patterns
    ]


def selected_configs(delay: str) -> list[DelayConfig]:
    if delay == "all":
        return list(DELAY_CONFIGS)
    return [config for config in DELAY_CONFIGS if config.label == delay]


def fill_no_answer(counts: CaptureCounts, attempted_connections: int) -> None:
    answered = (
        counts.status_200_after_options + counts.rst_immediate + counts.status_503
    )
    counts.no_answer = max(attempted_connections - answered, 0)


def main() -> int:
    env = load_env(ENV_FILE)
    default_client_ip = env_value(env, ENV_PROFILE, "RTSP_SOURCE_IP", DEFAULT_CLIENT_IP)
    default_server_ip = env_value(env, ENV_PROFILE, "RTSP_SERVER", DEFAULT_SERVER_IP)
    default_server_port = env_value(env, ENV_PROFILE, "RTSP_PORT", DEFAULT_SERVER_PORT)

    parser = argparse.ArgumentParser(
        description=(
            "For each max-options capture, count connections whose first server "
            "outcome is 200 OK after OPTIONS, immediate RST, or 503; then print a "
            "summary table grouped by delay."
        )
    )
    parser.add_argument(
        "--delay",
        choices=["all", *(config.label for config in DELAY_CONFIGS)],
        default="all",
        help="delay group to process (default: all)",
    )
    parser.add_argument("--client-ip", default=default_client_ip)
    parser.add_argument("--server-ip", default=default_server_ip)
    parser.add_argument("--server-port", default=default_server_port)
    parser.add_argument(
        "--attempted-connections",
        type=int,
        default=DEFAULT_ATTEMPTED_CONNECTIONS,
        help=f"attempted connections per capture (default: {DEFAULT_ATTEMPTED_CONNECTIONS})",
    )
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
        glob_patterns = capture_globs(config)
        captures = sorted(
            {
                capture
                for glob_pattern in glob_patterns
                for capture in script_dir.glob(glob_pattern)
            },
            key=natural_key,
        )
        if not captures:
            print(
                f"error: no captures matched any pattern for {config.label}: "
                f"{', '.join(glob_patterns)}",
                file=sys.stderr,
            )
            return 1

        print(f"{config.label}:")
        all_counts: list[CaptureCounts] = []
        for capture in captures:
            counts = count_capture(
                capture=capture,
                client_ip=args.client_ip,
                server_ip=args.server_ip,
                server_port=args.server_port,
            )
            fill_no_answer(counts, args.attempted_connections)
            all_counts.append(counts)
            print(
                f"  {capture.relative_to(script_dir)}: "
                f"200_after_options={counts.status_200_after_options}, "
                f"rst_immediate={counts.rst_immediate}, "
                f"503={counts.status_503}, "
                f"no_answer={counts.no_answer}, "
                f"observed_unclassified={counts.unclassified}, "
                f"observed_total={counts.total}"
            )
        print()
        summary_rows.append(summarize(config.td, all_counts))

    print("summary:")
    print_summary_table(summary_rows, args.decimal_comma)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
