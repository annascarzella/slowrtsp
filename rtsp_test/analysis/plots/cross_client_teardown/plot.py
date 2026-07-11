#!/usr/bin/env python3
"""
Extract RTP bandwidth received by Connection A and annotate:
  - Connection A SETUP
  - Connection A PLAY
  - First received RTP packet
  - Connection B TEARDOWN

Assumptions:
  - Connection A is tcp.stream 0
  - Connection B is tcp.stream 1
  - The RTSP server listens on TCP port 554
  - Connection A receives RTP over UDP on the specified client RTP port

Requirements:
  - tshark
  - Python 3
  - matplotlib

Example:
python extract_cross_teardown.py capture.pcapng \
    --camera-profile bosch \
    --rtp-port 20000 \
    --output-dir teardown_output
"""

from __future__ import annotations

import argparse
import csv
import io
import math
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import matplotlib.pyplot as plt


ENV_FILE = Path(__file__).resolve().parents[3] / ".env"
DEFAULT_CAMERA_PROFILE = "bosch"


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


def env_value(env: dict[str, str], profile: str, key: str, default: str = "") -> str:
    prefix = profile_prefix(profile)
    return env.get(f"{prefix}_{key}") or env.get(key) or default


# Fixed stream identifiers for this experiment.
CONNECTION_A_STREAM = 0
CONNECTION_B_STREAM = 1

# Different tshark/Wireshark versions expose the RTSP request method under
# different field names.
RTSP_METHOD_FIELDS = ("rtsp.method", "rtsp.request.method")


@dataclass
class Event:
    timestamp: float
    label: str


def run_tshark(
    pcap_path: Path,
    display_filter: str,
    fields: list[str],
    decode_rtsp: bool = False,
) -> list[list[str]]:
    """Run tshark and return tab-separated output rows."""
    tshark_path = shutil.which("tshark")
    if tshark_path is None:
        raise RuntimeError(
            "tshark was not found. Install Wireshark/tshark and ensure it is in PATH."
        )

    command = [
        tshark_path,
        "-n",
        "-r",
        str(pcap_path),
    ]

    if decode_rtsp:
        command += ["-d", "tcp.port==554,rtsp"]

    command += [
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=/t",
        "-E",
        "quote=n",
        "-E",
        "occurrence=f",
    ]

    for field in fields:
        command += ["-e", field]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"tshark failed:\n{result.stderr.strip() or result.stdout.strip()}"
        )

    rows: list[list[str]] = []

    for row in csv.reader(io.StringIO(result.stdout), delimiter="\t"):
        row += [""] * (len(fields) - len(row))
        rows.append(row[: len(fields)])

    return rows


def is_invalid_tshark_field_error(error: RuntimeError) -> bool:
    """Return True when tshark failed because a field name is unsupported."""
    message = str(error)
    return (
        "Some fields aren't valid" in message
        or "is neither a field nor a protocol name" in message
        or "not a valid field" in message
    )


def extract_rtp_packets(
    pcap_path: Path,
    camera_ip: str,
    client_ip: str,
    rtp_port: int,
) -> list[tuple[float, int, int]]:
    """
    Extract UDP packets sent from the camera to Connection A's RTP port.

    Returns:
        (timestamp, frame_bytes, udp_payload_bytes)
    """
    display_filter = (
        f"ip.src == {camera_ip} && "
        f"ip.dst == {client_ip} && "
        f"udp.dstport == {rtp_port}"
    )

    rows = run_tshark(
        pcap_path=pcap_path,
        display_filter=display_filter,
        fields=["frame.time_epoch", "frame.len", "udp.length"],
    )

    packets: list[tuple[float, int, int]] = []

    for timestamp, frame_length, udp_length in rows:
        if not timestamp:
            continue

        try:
            timestamp_value = float(timestamp)
            frame_bytes = int(frame_length)
            udp_total_bytes = int(udp_length)
        except ValueError:
            continue

        # udp.length includes the 8-byte UDP header.
        udp_payload_bytes = max(udp_total_bytes - 8, 0)
        packets.append((timestamp_value, frame_bytes, udp_payload_bytes))

    return sorted(packets, key=lambda packet: packet[0])


def extract_rtsp_events(
    pcap_path: Path,
    rtsp_port: int = 554,
) -> list[Event]:
    """Extract relevant RTSP events from stream 0 and stream 1."""
    rows: list[list[str]] | None = None
    field_errors: list[str] = []

    for method_field in RTSP_METHOD_FIELDS:
        try:
            rows = run_tshark(
                pcap_path=pcap_path,
                display_filter=f"tcp.port == {rtsp_port} && {method_field}",
                fields=[
                    "frame.time_epoch",
                    "tcp.stream",
                    method_field,
                ],
                decode_rtsp=True,
            )
            break
        except RuntimeError as error:
            if not is_invalid_tshark_field_error(error):
                raise

            field_errors.append(str(error))

    if rows is None:
        tried_fields = ", ".join(RTSP_METHOD_FIELDS)
        raise RuntimeError(
            "Unable to extract RTSP request methods with this tshark build. "
            f"Tried fields: {tried_fields}.\n\n" + "\n\n".join(field_errors)
        )

    events: list[Event] = []
    found_events: set[str] = set()

    for timestamp, stream, method in rows:
        if not timestamp or not stream or not method:
            continue

        try:
            timestamp_value = float(timestamp)
            stream_id = int(stream)
        except ValueError:
            continue

        method = method.upper()
        label: str | None = None

        if stream_id == CONNECTION_A_STREAM and method == "SETUP":
            label = "Connection A SETUP"
        elif stream_id == CONNECTION_A_STREAM and method == "PLAY":
            label = "Connection A PLAY"
        elif stream_id == CONNECTION_B_STREAM and method == "TEARDOWN":
            label = "Connection B TEARDOWN"

        if label is not None and label not in found_events:
            events.append(Event(timestamp_value, label))
            found_events.add(label)

    return sorted(events, key=lambda event: event.timestamp)


def create_bandwidth_data(
    packets: list[tuple[float, int, int]],
    events: list[Event],
    bin_seconds: float,
    seconds_after_teardown: float,
) -> tuple[float, list[dict[str, float | int]]]:
    """Aggregate UDP packets into fixed-width time bins."""
    if not packets:
        raise RuntimeError(
            "No UDP packets were found for the specified camera IP, client IP, "
            "and RTP destination port."
        )

    setup_times = [
        event.timestamp
        for event in events
        if event.label == "Connection A SETUP"
    ]

    origin = setup_times[0] if setup_times else packets[0][0]

    teardown_times = [
        event.timestamp
        for event in events
        if event.label == "Connection B TEARDOWN"
    ]

    last_packet_time = packets[-1][0]

    if teardown_times:
        end_time = max(
            last_packet_time,
            teardown_times[0] + seconds_after_teardown,
        )
    else:
        end_time = last_packet_time

    number_of_bins = max(
        1,
        math.ceil((end_time - origin) / bin_seconds) + 1,
    )

    bins = [
        {
            "frame_bytes": 0,
            "udp_payload_bytes": 0,
            "packet_count": 0,
        }
        for _ in range(number_of_bins)
    ]

    for timestamp, frame_bytes, udp_payload_bytes in packets:
        index = int((timestamp - origin) // bin_seconds)

        if 0 <= index < number_of_bins:
            bins[index]["frame_bytes"] += frame_bytes
            bins[index]["udp_payload_bytes"] += udp_payload_bytes
            bins[index]["packet_count"] += 1

    rows: list[dict[str, float | int]] = []

    for index, current_bin in enumerate(bins):
        start_time = index * bin_seconds
        end_time = start_time + bin_seconds

        rows.append(
            {
                "time_start_s": round(start_time, 6),
                "time_end_s": round(end_time, 6),
                "packet_count": current_bin["packet_count"],
                "frame_bytes": current_bin["frame_bytes"],
                "udp_payload_bytes": current_bin["udp_payload_bytes"],
                "captured_bandwidth_bps": (
                    current_bin["frame_bytes"] * 8 / bin_seconds
                ),
                "udp_payload_bitrate_bps": (
                    current_bin["udp_payload_bytes"] * 8 / bin_seconds
                ),
                "captured_bandwidth_mbps": (
                    current_bin["frame_bytes"] * 8 / bin_seconds / 1_000_000
                ),
                "udp_payload_bitrate_mbps": (
                    current_bin["udp_payload_bytes"] * 8 / bin_seconds / 1_000_000
                ),
            }
        )

    return origin, rows


def write_csv(
    output_path: Path,
    rows: list[dict[str, float | int | str]],
) -> None:
    """Write dictionaries to CSV."""
    if not rows:
        return

    with output_path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=list(rows[0].keys()),
        )
        writer.writeheader()
        writer.writerows(rows)


def create_plot(
    output_path: Path,
    bandwidth_rows: list[dict[str, float | int]],
    events: list[Event],
    origin: float,
) -> None:
    """Create the bandwidth figure with RTSP-event markers."""
    x_values = [
        float(row["time_start_s"])
        for row in bandwidth_rows
    ]

    y_values = [
        float(row["captured_bandwidth_mbps"])
        for row in bandwidth_rows
    ]

    figure = plt.figure(figsize=(16, 10))

    plt.plot(
        x_values,
        y_values,
        color="grey",
        linewidth=2,
    )

    maximum_bandwidth = max(y_values) if y_values else 1.0
    teardown_label_height = maximum_bandwidth * 0.04

    for event in events:
        if event.label != "Connection B TEARDOWN":
            continue

        relative_time = event.timestamp - origin

        plt.axvline(relative_time, color="grey", linestyle="--", linewidth=2)

        plt.text(
            relative_time,
            teardown_label_height,
            event.label,
            rotation=90,
            verticalalignment="bottom",
            horizontalalignment="right",
            fontsize=24,
            color="grey",
        )

    plt.xlim(0, 60)
    plt.ylim(bottom=0)
    plt.xticks(fontsize=24)
    plt.yticks(fontsize=24)

    plt.xlabel("t", fontsize=24, fontstyle="italic")
    plt.ylabel("Bandwidth of connection A stream (Mbps)", fontsize=24)
    figure.suptitle(
        "Bandwidth of connection A stream before and after\n"
        "Connection B TEARDOWN",
        fontsize=28,
        x=0.5,
        horizontalalignment="center",
    )
    plt.grid(True)
    plt.tight_layout(rect=(0, 0, 1, 0.92))
    plt.savefig(output_path, dpi=150)
    plt.close()


def main() -> None:
    env = load_env(ENV_FILE)

    parser = argparse.ArgumentParser(
        description=(
            "Extract RTP bandwidth and RTSP event timestamps from a PCAP "
            "containing Connection A (tcp.stream 0) and Connection B "
            "(tcp.stream 1)."
        )
    )

    parser.add_argument(
        "pcap",
        type=Path,
        default=Path("capture.pcap"),
        help="Input PCAP or PCAPNG file.",
    )

    parser.add_argument(
        "--camera-profile",
        default=env.get("RTSP_CAMERA_PROFILE") or DEFAULT_CAMERA_PROFILE,
        help="Camera profile to read from .env when --camera-ip or --client-ip is omitted.",
    )

    parser.add_argument(
        "--camera-ip",
        default=None,
        help="IP address of the camera / RTSP server.",
    )

    parser.add_argument(
        "--client-ip",
        default=None,
        help="IP address of the client host receiving Connection A's RTP stream.",
    )

    parser.add_argument(
        "--rtp-port",
        type=int,
        default=20000,
        help="UDP destination port used by Connection A for RTP, e.g. 20000.",
    )

    parser.add_argument(
        "--rtsp-port",
        type=int,
        default=554,
        help="RTSP TCP server port. Default: 554.",
    )

    parser.add_argument(
        "--bin-ms",
        type=float,
        default=1000.0,
        help="Bandwidth bin width in milliseconds. Default: 1000.",
    )

    parser.add_argument(
        "--seconds-after-teardown",
        type=float,
        default=5.0,
        help=(
            "How many seconds of zero bandwidth to retain after Connection B "
            "sends TEARDOWN. Default: 5."
        ),
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("."),
        help="Directory in which to save CSV files and the plot. Default: current directory.",
    )

    args = parser.parse_args()

    args.camera_ip = args.camera_ip or env_value(env, args.camera_profile, "RTSP_SERVER")
    args.client_ip = args.client_ip or env_value(env, args.camera_profile, "RTSP_SOURCE_IP")
    if not args.camera_ip or not args.client_ip:
        sys.exit("camera/client IPs are required. Configure them in .env or pass --camera-ip and --client-ip.")

    if not args.pcap.is_file():
        sys.exit(f"PCAP file not found: {args.pcap}")

    if args.bin_ms <= 0:
        sys.exit("--bin-ms must be greater than zero.")

    if args.seconds_after_teardown < 0:
        sys.exit("--seconds-after-teardown cannot be negative.")

    args.output_dir.mkdir(parents=True, exist_ok=True)

    rtp_packets = extract_rtp_packets(
        pcap_path=args.pcap,
        camera_ip=args.camera_ip,
        client_ip=args.client_ip,
        rtp_port=args.rtp_port,
    )

    if not rtp_packets:
        sys.exit(
            "No RTP UDP packets matched this filter: "
            f"ip.src == {args.camera_ip} && "
            f"ip.dst == {args.client_ip} && "
            f"udp.dstport == {args.rtp_port}. "
            "No new plot was generated; any existing bandwidth.png is from "
            "a previous successful run."
        )

    events = extract_rtsp_events(
        pcap_path=args.pcap,
        rtsp_port=args.rtsp_port,
    )

    # Add the observed first RTP packet as the practical beginning of streaming.
    if rtp_packets:
        events.append(
            Event(
                timestamp=rtp_packets[0][0],
                label="RTP stream begins",
            )
        )
        events.sort(key=lambda event: event.timestamp)

    origin, bandwidth_rows = create_bandwidth_data(
        packets=rtp_packets,
        events=events,
        bin_seconds=args.bin_ms / 1000.0,
        seconds_after_teardown=args.seconds_after_teardown,
    )

    event_rows = [
        {
            "time_s": round(event.timestamp - origin, 6),
            "event": event.label,
        }
        for event in events
    ]

    bandwidth_csv_path = args.output_dir / "bandwidth.csv"
    events_csv_path = args.output_dir / "events.csv"
    plot_path = args.output_dir / "bandwidth.png"

    write_csv(bandwidth_csv_path, bandwidth_rows)
    write_csv(events_csv_path, event_rows)

    create_plot(
        output_path=plot_path,
        bandwidth_rows=bandwidth_rows,
        events=events,
        origin=origin,
    )

    print(f"Wrote: {bandwidth_csv_path}")
    print(f"Wrote: {events_csv_path}")
    print(f"Wrote: {plot_path}")


if __name__ == "__main__":
    main()
