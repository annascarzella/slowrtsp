#!/usr/bin/env python3
"""Measure the PLAY-loop recovery interval around the short RST window.

The measured period starts at the first server FIN that closes an established
connection before the RST rejection window, and ends at the first later RTSP
200 OK after connections stop being immediately rejected.
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
DEFAULT_ATTEMPTED_CONNECTIONS = 1016
DEFAULT_START_CONNECTION_ID = 565
DEFAULT_GLOB_PREFIX = "../../[0-9]*/6_attack-play-loop-1016conn"


@dataclass(frozen=True)
class DelayConfig:
    label: str
    td: str
    directory: str


@dataclass
class StreamState:
    first_syn_frame: int | None = None
    first_syn_time: float | None = None
    server_close_time: float | None = None
    server_close_type: str | None = None
    first_rtsp_200_time: float | None = None


@dataclass(frozen=True)
class CaptureWindow:
    capture: Path
    observed_total: int
    first_pre_restart_close_connection_id: int
    first_pre_restart_close_time: float
    first_pre_restart_close_type: str
    first_rst_connection_id: int
    first_rst_time: float
    last_rst_connection_id: int
    last_rst_time: float
    first_success_after_restart_connection_id: int
    first_success_after_restart_time: float
    period: float
    rst_connections: int
    first_non_rst_connection_id: int | None


@dataclass(frozen=True)
class CaptureError:
    capture: Path
    observed_total: int
    reason: str


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


def is_true(value: str) -> bool:
    return value in {"1", "True", "true"}


def format_float(value: float, decimal_comma: bool, digits: int = 3) -> str:
    text = f"{value:.{digits}f}"
    return text.replace(".", ",") if decimal_comma else text


def format_optional_int(value: int | None) -> str:
    return "n/a" if value is None else str(value)


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
        "tcp.flags.ack",
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
            dir="/tmp", prefix="play_loop_rst_period_", suffix=".pcap", delete=False
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


def read_attempts(
    capture: Path,
    client_ip: str,
    server_ip: str,
    server_port: str,
    attempted_connections: int,
) -> list[StreamState]:
    streams: dict[int, StreamState] = {}

    for line in run_tshark(capture, server_port).splitlines():
        fields = line.split("\t")
        fields += [""] * (12 - len(fields))
        (
            frame_text,
            time_text,
            stream_text,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            syn,
            ack,
            fin,
            reset,
            status,
        ) = fields[:12]

        if not frame_text or not time_text or not stream_text:
            continue

        frame = int(frame_text)
        timestamp = float(time_text)
        stream = int(stream_text)
        state = streams.setdefault(stream, StreamState())

        client_to_server = (
            src_ip == client_ip and dst_ip == server_ip and dst_port == server_port
        )
        server_to_client = (
            src_ip == server_ip and src_port == server_port and dst_ip == client_ip
        )

        if (
            client_to_server
            and is_true(syn)
            and not is_true(ack)
            and state.first_syn_frame is None
        ):
            state.first_syn_frame = frame
            state.first_syn_time = timestamp

        if server_to_client and status == "200" and state.first_rtsp_200_time is None:
            state.first_rtsp_200_time = timestamp

        if server_to_client and (is_true(reset) or is_true(fin)):
            close_type = "RST" if is_true(reset) else "FIN"
            if state.server_close_time is None:
                state.server_close_time = timestamp
                state.server_close_type = close_type

    attempts = sorted(
        (
            state
            for state in streams.values()
            if state.first_syn_frame is not None
        ),
        key=lambda state: state.first_syn_frame or 0,
    )
    return attempts[:attempted_connections]


def find_window(
    capture: Path,
    attempts: list[StreamState],
    start_connection_id: int,
) -> CaptureWindow | CaptureError:
    observed_total = len(attempts)
    if observed_total < start_connection_id:
        return CaptureError(
            capture=capture,
            observed_total=observed_total,
            reason=(
                f"only {observed_total} attempted connections observed; "
                f"need connection {start_connection_id}"
            ),
        )

    start_index = start_connection_id - 1
    first_rst_index = None
    for index in range(start_index, observed_total):
        if attempts[index].server_close_type == "RST":
            first_rst_index = index
            break

        if index == start_index:
            break

    if first_rst_index is None:
        state = attempts[start_index]
        close_type = state.server_close_type or "not closed"
        return CaptureError(
            capture=capture,
            observed_total=observed_total,
            reason=f"connection {start_connection_id} was {close_type}, not server-RST",
        )

    last_rst_index = first_rst_index
    for index in range(first_rst_index + 1, observed_total):
        if attempts[index].server_close_type != "RST":
            break
        last_rst_index = index

    first_rst = attempts[first_rst_index]
    last_rst = attempts[last_rst_index]
    if first_rst.server_close_time is None or last_rst.server_close_time is None:
        return CaptureError(
            capture=capture,
            observed_total=observed_total,
            reason="internal error: RST block is missing close timestamps",
        )

    first_pre_restart_close_index = None
    for index, attempt in enumerate(attempts[:first_rst_index]):
        if attempt.server_close_type == "FIN" and attempt.server_close_time is not None:
            if (
                first_pre_restart_close_index is None
                or attempt.server_close_time
                < attempts[first_pre_restart_close_index].server_close_time
            ):
                first_pre_restart_close_index = index

    if first_pre_restart_close_index is None:
        return CaptureError(
            capture=capture,
            observed_total=observed_total,
            reason="no server FIN found before the RST window",
        )

    first_success_after_restart_index = None
    for index in range(last_rst_index + 1, observed_total):
        if attempts[index].first_rtsp_200_time is not None:
            first_success_after_restart_index = index
            break

    if first_success_after_restart_index is None:
        return CaptureError(
            capture=capture,
            observed_total=observed_total,
            reason="no RTSP 200 OK found after the RST window",
        )

    first_non_rst_connection_id = (
        last_rst_index + 2 if last_rst_index + 1 < observed_total else None
    )
    first_pre_restart_close = attempts[first_pre_restart_close_index]
    first_success_after_restart = attempts[first_success_after_restart_index]

    return CaptureWindow(
        capture=capture,
        observed_total=observed_total,
        first_pre_restart_close_connection_id=first_pre_restart_close_index + 1,
        first_pre_restart_close_time=first_pre_restart_close.server_close_time,
        first_pre_restart_close_type=first_pre_restart_close.server_close_type or "unknown",
        first_rst_connection_id=first_rst_index + 1,
        first_rst_time=first_rst.server_close_time,
        last_rst_connection_id=last_rst_index + 1,
        last_rst_time=last_rst.server_close_time,
        first_success_after_restart_connection_id=first_success_after_restart_index + 1,
        first_success_after_restart_time=first_success_after_restart.first_rtsp_200_time,
        period=(
            first_success_after_restart.first_rtsp_200_time
            - first_pre_restart_close.server_close_time
        ),
        rst_connections=last_rst_index - first_rst_index + 1,
        first_non_rst_connection_id=first_non_rst_connection_id,
    )


def capture_glob(glob_prefix: str, config: DelayConfig) -> str:
    return f"{glob_prefix}/{config.directory}/output/capture.pcap"


def selected_configs(delay: str) -> list[DelayConfig]:
    if delay == "all":
        return list(DELAY_CONFIGS)
    return [config for config in DELAY_CONFIGS if config.label == delay]


def print_window(
    window: CaptureWindow,
    script_dir: Path,
    decimal_comma: bool,
) -> None:
    print(
        f"  {window.capture.relative_to(script_dir)}: "
        "first_pre_restart_close_connection="
        f"{window.first_pre_restart_close_connection_id}, "
        "first_pre_restart_close_type="
        f"{window.first_pre_restart_close_type}, "
        "first_pre_restart_close_at="
        f"{format_float(window.first_pre_restart_close_time, decimal_comma, 6)}, "
        "first_success_after_restart_connection="
        f"{window.first_success_after_restart_connection_id}, "
        "first_success_after_restart_at="
        f"{format_float(window.first_success_after_restart_time, decimal_comma, 6)}, "
        f"period={format_float(window.period, decimal_comma, 6)}, "
        f"first_rst_connection={window.first_rst_connection_id}, "
        f"first_rst_at={format_float(window.first_rst_time, decimal_comma, 6)}, "
        f"last_rst_connection={window.last_rst_connection_id}, "
        f"last_rst_at={format_float(window.last_rst_time, decimal_comma, 6)}, "
        f"rst_connections={window.rst_connections}, "
        "first_non_rst_connection="
        f"{format_optional_int(window.first_non_rst_connection_id)}, "
        f"observed_total={window.observed_total}"
    )


def print_error(error: CaptureError, script_dir: Path) -> None:
    print(
        f"  {error.capture.relative_to(script_dir)}: "
        f"period=n/a, reason={error.reason}, observed_total={error.observed_total}"
    )


def print_summary_table(
    rows: Sequence[tuple[str, list[CaptureWindow], list[CaptureError]]],
    decimal_comma: bool,
) -> None:
    header_groups = [
        "T_d",
        "captures",
        "valid",
        "recovery period",
        "",
        "first pre-restart close",
        "",
        "first success after restart",
        "",
        "RST block size",
        "",
    ]
    headers = ["", "", "", "mu", "sigma", "mu", "sigma", "mu", "sigma", "mu", "sigma"]
    table = [header_groups, headers]

    for td, windows, errors in rows:
        if windows:
            periods = [window.period for window in windows]
            rst_counts = [float(window.rst_connections) for window in windows]
            first_close_times = [window.first_pre_restart_close_time for window in windows]
            first_success_times = [window.first_success_after_restart_time for window in windows]
            row = [
                td,
                str(len(windows) + len(errors)),
                str(len(windows)),
                format_float(average(periods), decimal_comma),
                format_float(sample_stddev(periods), decimal_comma),
                format_float(average(first_close_times), decimal_comma),
                format_float(sample_stddev(first_close_times), decimal_comma),
                format_float(average(first_success_times), decimal_comma),
                format_float(sample_stddev(first_success_times), decimal_comma),
                format_float(average(rst_counts), decimal_comma),
                format_float(sample_stddev(rst_counts), decimal_comma),
            ]
        else:
            row = [td, str(len(errors)), "0", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a"]
        table.append(row)

    widths = [max(len(row[index]) for row in table) for index in range(len(headers))]
    separator = "-+-".join("-" * width for width in widths)
    for index, row in enumerate(table):
        print(" | ".join(cell.ljust(widths[column]) for column, cell in enumerate(row)))
        if index in {0, 1}:
            print(separator)


def main() -> int:
    env = load_env(ENV_FILE)
    default_client_ip = env_value(env, ENV_PROFILE, "RTSP_SOURCE_IP", DEFAULT_CLIENT_IP)
    default_server_ip = env_value(env, ENV_PROFILE, "RTSP_SERVER", DEFAULT_SERVER_IP)
    default_server_port = env_value(env, ENV_PROFILE, "RTSP_PORT", DEFAULT_SERVER_PORT)

    parser = argparse.ArgumentParser(
        description=(
            "Measure the recovery interval from the first pre-restart server FIN "
            "to the first later RTSP 200 OK after the RST window."
        )
    )
    parser.add_argument(
        "--delay",
        choices=["all", *(config.label for config in DELAY_CONFIGS)],
        default="delay5",
        help="delay group to process (default: delay5, the t_c ~= 2815 s case)",
    )
    parser.add_argument(
        "--glob-prefix",
        default=DEFAULT_GLOB_PREFIX,
        help=f"capture glob prefix relative to this script (default: {DEFAULT_GLOB_PREFIX})",
    )
    parser.add_argument(
        "--attempted-connections",
        type=int,
        default=DEFAULT_ATTEMPTED_CONNECTIONS,
        help=f"attempted sessions per capture (default: {DEFAULT_ATTEMPTED_CONNECTIONS})",
    )
    parser.add_argument(
        "--start-connection-id",
        type=int,
        default=DEFAULT_START_CONNECTION_ID,
        help=f"connection id where the RST window starts (default: {DEFAULT_START_CONNECTION_ID})",
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
    summary_rows: list[tuple[str, list[CaptureWindow], list[CaptureError]]] = []
    for config in selected_configs(args.delay):
        glob_pattern = capture_glob(args.glob_prefix, config)
        captures = sorted(script_dir.glob(glob_pattern), key=natural_key)
        if not captures:
            print(f"error: no captures matched {glob_pattern}", file=sys.stderr)
            return 1

        print(f"{config.label}:")
        windows: list[CaptureWindow] = []
        errors: list[CaptureError] = []
        for capture in captures:
            attempts = read_attempts(
                capture=capture,
                client_ip=args.client_ip,
                server_ip=args.server_ip,
                server_port=args.server_port,
                attempted_connections=args.attempted_connections,
            )
            result = find_window(
                capture=capture,
                attempts=attempts,
                start_connection_id=args.start_connection_id,
            )
            if isinstance(result, CaptureWindow):
                windows.append(result)
                print_window(result, script_dir, args.decimal_comma)
            else:
                errors.append(result)
                print_error(result, script_dir)
        print()
        summary_rows.append((config.td, windows, errors))

    print("summary:")
    print_summary_table(summary_rows, args.decimal_comma)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
