#!/usr/bin/env python3

import argparse
from dataclasses import dataclass

import pandas as pd
import matplotlib.pyplot as plt
import pyshark


@dataclass
class Conn:
    stream_id: str
    first_options_time: float | None = None
    first_200_time: float | None = None
    close_time: float | None = None
    close_type: str | None = None


def layer_names(pkt):
    return [layer.layer_name.lower() for layer in pkt.layers]


def has_layer(pkt, name):
    return name.lower() in layer_names(pkt)


def packet_time(pkt):
    return float(pkt.sniff_timestamp)


def tcp_stream(pkt):
    try:
        return str(pkt.tcp.stream)
    except AttributeError:
        return None


def tcp_payload_as_text(pkt):
    """
    Fallback parser in case tshark does not decode RTSP fields.
    """
    try:
        payload_hex = pkt.tcp.payload.replace(":", "")
        return bytes.fromhex(payload_hex).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def flag_is_set(value):
    """
    Pyshark/tshark may return TCP flags as:
    - "1" / "0"
    - "True" / "False"
    - True / False
    """
    return str(value).lower() in {"1", "true"}


def is_options_request(pkt):
    """
    Detect RTSP OPTIONS request.
    """
    if has_layer(pkt, "rtsp"):
        try:
            return pkt.rtsp.request_method.upper() == "OPTIONS"
        except AttributeError:
            pass

    payload = tcp_payload_as_text(pkt)
    return payload.startswith("OPTIONS ")


def is_200_ok(pkt):
    """
    Detect RTSP 200 OK response.
    """
    if has_layer(pkt, "rtsp"):
        try:
            return str(pkt.rtsp.status_code) == "200"
        except AttributeError:
            pass

    payload = tcp_payload_as_text(pkt)
    return (
        payload.startswith("RTSP/1.0 200")
        or payload.startswith("RTSP/2.0 200")
    )


def close_type(pkt):
    """
    Detect TCP connection close event.
    """
    try:
        if flag_is_set(pkt.tcp.flags_reset):
            return "RST"
    except AttributeError:
        pass

    try:
        if flag_is_set(pkt.tcp.flags_fin):
            return "FIN"
    except AttributeError:
        pass

    return None


def analyze_pcap(pcap_path, rtsp_port=554):
    cap = pyshark.FileCapture(
        pcap_path,
        display_filter=f"tcp.port == {rtsp_port}",
        keep_packets=False,
    )

    conns: dict[str, Conn] = {}
    first_capture_time = None

    for pkt in cap:
        if not has_layer(pkt, "tcp"):
            continue

        t = packet_time(pkt)

        if first_capture_time is None:
            first_capture_time = t

        sid = tcp_stream(pkt)
        if sid is None:
            continue

        if sid not in conns:
            conns[sid] = Conn(stream_id=sid)

        conn = conns[sid]

        if is_options_request(pkt) and conn.first_options_time is None:
            conn.first_options_time = t

        # Count only the first 200 OK after the first OPTIONS request.
        # This is considered the connection "start" for the plot.
        if (
            conn.first_options_time is not None
            and conn.first_200_time is None
            and is_200_ok(pkt)
        ):
            conn.first_200_time = t

        ctype = close_type(pkt)

        # Record the first observed FIN/RST after the OPTIONS received 200 OK.
        if (
            conn.first_200_time is not None
            and conn.close_time is None
            and ctype is not None
        ):
            conn.close_time = t
            conn.close_type = ctype

    cap.close()

    if first_capture_time is None:
        raise RuntimeError("No TCP packets found in the capture.")

    rows = []

    for conn in conns.values():
        # Keep only connections where OPTIONS received 200 OK.
        if conn.first_options_time is None or conn.first_200_time is None:
            continue

        rows.append(
            {
                "stream_id": conn.stream_id,
                "start_time": conn.first_200_time - first_capture_time,
                "close_time": (
                    conn.close_time - first_capture_time
                    if conn.close_time is not None
                    else None
                ),
                "close_type": conn.close_type,
            }
        )

    df = pd.DataFrame(rows)

    if df.empty:
        return df

    # Sort by start time so connection_id represents the order in which
    # connections successfully received 200 OK after OPTIONS.
    df = df.sort_values("start_time").reset_index(drop=True)
    df["connection_id"] = df.index + 1

    return df


def make_plot(df, output_path, duration=5200, expected_connections=1016):
    plt.figure(figsize=(16, 7))

    # Plot starts first, very small and transparent.
    plt.scatter(
        df["connection_id"],
        df["start_time"],
        marker="o",
        s=6,
        alpha=0.35,
        label="Start: first OPTIONS received 200 OK",
        zorder=2,
    )

    closed = df[df["close_time"].notna()].copy()

    # Plot closures on top, slightly larger.
    plt.scatter(
        closed["connection_id"],
        closed["close_time"],
        marker="x",
        s=22,
        alpha=0.9,
        label="End: TCP FIN/RST observed",
        zorder=3,
    )

    plt.xlabel("Connection ID")
    plt.ylabel("Time since beginning of capture [s]")
    plt.ylim(0, duration)
    plt.xlim(0, expected_connections)

    plt.legend(loc="upper left")
    plt.grid(True, linewidth=0.25, alpha=0.35)
    plt.tight_layout()

    plt.savefig(output_path, dpi=600)
    plt.close()

def main():
    parser = argparse.ArgumentParser(
        description="Plot RTSP connection start/end times from a pcap."
    )

    parser.add_argument(
        "pcap",
        help="Input .pcap or .pcapng file",
    )

    parser.add_argument(
        "--rtsp-port",
        type=int,
        default=554,
        help="RTSP TCP port. Default: 554",
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=5200,
        help="Experiment duration shown on y-axis. Default: 5200",
    )

    parser.add_argument(
        "--expected-connections",
        type=int,
        default=1016,
        help="Expected number of attack connections shown on x-axis. Default: 1016",
    )

    parser.add_argument(
        "--out",
        default="rtsp_connection_start_end.png",
        help="Output plot filename",
    )

    parser.add_argument(
        "--csv",
        default="rtsp_connections.csv",
        help="Output CSV filename",
    )

    args = parser.parse_args()

    df = analyze_pcap(args.pcap, rtsp_port=args.rtsp_port)

    if df.empty:
        print("No connections found where OPTIONS received 200 OK.")
        return

    df.to_csv(args.csv, index=False)

    make_plot(
        df,
        args.out,
        duration=args.duration,
        expected_connections=args.expected_connections,
    )

    total = len(df)
    closed = int(df["close_time"].notna().sum())
    still_open = total - closed

    print(f"Successful OPTIONS connections: {total}")
    print(f"Closed connections: {closed}")
    print(f"Still open at end of capture: {still_open}")
    print(f"CSV written to: {args.csv}")
    print(f"Plot written to: {args.out}")


if __name__ == "__main__":
    main()