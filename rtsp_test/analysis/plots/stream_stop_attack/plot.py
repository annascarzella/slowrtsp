#!/usr/bin/env python3

import argparse
from collections import defaultdict
from datetime import datetime, timezone

import matplotlib.pyplot as plt
from scapy.all import PcapReader, IP, IPv6, TCP


TITLE_FONTSIZE = 24
LABEL_FONTSIZE = 22
TICK_FONTSIZE = 22


def packet_timestamp(pkt):
    return float(pkt.time)


def packet_len_bytes(pkt):
    return len(bytes(pkt))


def extract_ip_pair(pkt):
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return None, None


def compute_bandwidth(pcap_path, bin_size):
    """
    Returns:
        times_relative: seconds from first packet of this pcap
        bandwidth_mbps: Mbps values, computed only from this pcap
        first_ts: first packet timestamp of this pcap
    """
    bins = defaultdict(int)
    first_ts = None

    with PcapReader(pcap_path) as packets:
        for pkt in packets:
            ts = packet_timestamp(pkt)

            if first_ts is None:
                first_ts = ts

            bin_index = int((ts - first_ts) // bin_size)
            bins[bin_index] += packet_len_bytes(pkt)

    if first_ts is None:
        raise ValueError(f"No packets found in {pcap_path}")

    times_relative = []
    bandwidth_mbps = []

    for bin_index in sorted(bins):
        relative_time = bin_index * bin_size
        bits = bins[bin_index] * 8
        mbps = bits / bin_size / 1_000_000

        times_relative.append(relative_time)
        bandwidth_mbps.append(mbps)

    return times_relative, bandwidth_mbps, first_ts


def canonical_connection_key(src, sport, dst, dport):
    """
    Direction-independent TCP connection key.
    This lets us group packets from both directions into the same connection.
    """
    a = (src, sport)
    b = (dst, dport)
    return tuple(sorted([a, b]))


def find_first_packet_time(pcap_path):
    with PcapReader(pcap_path) as packets:
        for pkt in packets:
            return packet_timestamp(pkt)

    raise ValueError(f"No packets found in {pcap_path}")


def find_last_completed_handshake(pcap_path):
    """
    Detects completed TCP three-way handshakes in pcap2.

    A completed handshake is:
        1. client -> server: SYN
        2. server -> client: SYN-ACK
        3. client -> server: ACK

    Returns info for the last completed handshake by completion time.
    """

    connections = {}
    completed = []

    with PcapReader(pcap_path) as packets:
        for pkt_number, pkt in enumerate(packets, start=1):
            if TCP not in pkt:
                continue

            src, dst = extract_ip_pair(pkt)
            if src is None or dst is None:
                continue

            tcp = pkt[TCP]
            sport = tcp.sport
            dport = tcp.dport
            flags = int(tcp.flags)
            ts = packet_timestamp(pkt)

            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)
            rst = bool(flags & 0x04)

            if rst:
                continue

            conn_key = canonical_connection_key(src, sport, dst, dport)

            # Step 1: SYN, not ACK
            if syn and not ack:
                connections[conn_key] = {
                    "state": "SYN_SEEN",
                    "client": (src, sport),
                    "server": (dst, dport),
                    "client_isn": tcp.seq,
                    "syn_time": ts,
                    "syn_packet": pkt_number,
                }

            # Step 2: SYN-ACK
            elif syn and ack and conn_key in connections:
                conn = connections[conn_key]

                if conn["state"] != "SYN_SEEN":
                    continue

                if (src, sport) != conn["server"]:
                    continue

                expected_ack = conn["client_isn"] + 1

                if tcp.ack != expected_ack:
                    continue

                conn["state"] = "SYN_ACK_SEEN"
                conn["server_isn"] = tcp.seq
                conn["syn_ack_time"] = ts
                conn["syn_ack_packet"] = pkt_number

            # Step 3: final ACK
            elif ack and not syn and conn_key in connections:
                conn = connections[conn_key]

                if conn["state"] != "SYN_ACK_SEEN":
                    continue

                if (src, sport) != conn["client"]:
                    continue

                expected_ack = conn["server_isn"] + 1

                if tcp.ack != expected_ack:
                    continue

                conn["state"] = "ESTABLISHED"
                conn["established_time"] = ts
                conn["established_packet"] = pkt_number

                completed.append(conn.copy())

    if not completed:
        return None

    return max(completed, key=lambda c: c["established_time"])


def format_seconds(seconds):
    """
    Converts seconds to a readable label like:
        45.2s
        2m 10.5s
    """
    if seconds < 60:
        return f"{seconds:.2f}s"

    minutes = int(seconds // 60)
    remaining_seconds = seconds % 60
    return f"{minutes}m {remaining_seconds:.2f}s"


def plot_bandwidth_with_markers(
    pcap1,
    pcap2,
    output,
    bin_size,
    minutes,
    title=None,
):
    times, bandwidth_mbps, pcap1_first_ts = compute_bandwidth(pcap1, bin_size)

    x_start = 0
    x_end = minutes * 60

    pcap2_start_ts = find_first_packet_time(pcap2)
    pcap2_start_relative = pcap2_start_ts - pcap1_first_ts

    last_handshake = find_last_completed_handshake(pcap2)
    end_relative = None

    fig, ax = plt.subplots(figsize=(16, 10))

    ax.plot(
        times,
        bandwidth_mbps,
        color="grey",
        label="Bandwidth of legitimate client",
    )

    ax.axvline(
        pcap2_start_relative,
        linestyle=":",
        linewidth=2,
        color="#303030",
        label="Attack start",
    )

    ax.annotate(
        "Attack start",
        xy=(pcap2_start_relative, max(bandwidth_mbps) * 0.98),
        xytext=(8, 0),
        textcoords="offset points",
        rotation=90,
        va="top",
        color="#303030",
        fontsize=LABEL_FONTSIZE,
    )

    if last_handshake is not None:
        end_relative = last_handshake["established_time"] - pcap1_first_ts

        client_ip, client_port = last_handshake["client"]
        server_ip, server_port = last_handshake["server"]

        conn_id = (
            f"{client_ip}:{client_port} -> "
            f"{server_ip}:{server_port}"
        )

        ax.axvline(
            end_relative,
            color="#303030",
            linestyle="--",
            linewidth=2,
            label="Attack end",
        )

        ax.annotate(
            "$t_c$",
            xy=(end_relative, max(bandwidth_mbps) * 0.85),
            xytext=(8, 0),
            textcoords="offset points",
            rotation=90,
            va="top",
            fontsize=LABEL_FONTSIZE,
        )

        print("Last completed TCP handshake:")
        print(f"  Connection ID: {conn_id}")
        print(f"  Established relative time: {format_seconds(end_relative)}")
        print(
            "  Established absolute UTC:",
            datetime.fromtimestamp(
                last_handshake["established_time"],
                tz=timezone.utc,
            ).isoformat(),
        )
        print(f"  Final ACK packet number: {last_handshake['established_packet']}")
        print(f"  SYN packet number: {last_handshake['syn_packet']}")
        print(f"  SYN-ACK packet number: {last_handshake['syn_ack_packet']}")
        

    else:
        print("No completed TCP three-way handshake found in pcap2.")

    print(f"Attack start relative time: {format_seconds(pcap2_start_relative)}")
    if end_relative is not None:
        print(f"Attack end relative time: {format_seconds(end_relative)}")

    if title is None:
        title = "Bandwidth of legitimate client streaming with attack start and end timeline markers"

    ax.set_title(title, fontsize=TITLE_FONTSIZE)
    ax.set_xlabel("t", fontsize=LABEL_FONTSIZE, fontstyle="italic")
    ax.set_ylabel("Bandwidth of legitimate client (Mbps)", fontsize=LABEL_FONTSIZE)

    ax.set_xlim(x_start, x_end)
    ax.set_ylim(bottom=0)

    ax.tick_params(axis="both", labelsize=TICK_FONTSIZE)
    ax.grid(True)
    # ax.legend(fontsize=LABEL_FONTSIZE)
    plt.tight_layout()

    plt.savefig(output, dpi=150)
    print(f"Saved plot to: {output}")


def main():
    parser = argparse.ArgumentParser(
        description="Plot bandwidth from pcap1 and mark events from pcap2."
    )

    parser.add_argument("pcap1", help="First pcap: used for bandwidth")
    parser.add_argument("pcap2", help="Second pcap: used for start/end markers")

    parser.add_argument(
        "-b",
        "--bin-size",
        type=float,
        default=1.0,
        help="Bandwidth bin size in seconds. Default: 1.0",
    )

    parser.add_argument(
        "-m",
        "--minutes",
        type=float,
        default=5.0,
        help="Number of minutes to show on the x-axis. Default: 5",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="pcap_timeline_bandwidth.png",
        help="Output image path. Default: pcap_timeline_bandwidth.png",
    )

    parser.add_argument(
        "--title",
        default=None,
        help="Plot title.",
    )

    args = parser.parse_args()

    plot_bandwidth_with_markers(
        pcap1=args.pcap1,
        pcap2=args.pcap2,
        output=args.output,
        bin_size=args.bin_size,
        minutes=args.minutes,
        title=args.title,
    )


if __name__ == "__main__":
    main()