#!/usr/bin/env python3

# run it with python3 plot_compute_avg_bandwidth.py legitimate.pcap

import argparse
from collections import defaultdict

from scapy.all import PcapReader


DEFAULT_ATTACK_START_SECONDS = 15.95
DEFAULT_SPLIT_SECONDS = 60.0


def packet_timestamp(pkt):
    return float(pkt.time)


def packet_len_bytes(pkt):
    return len(bytes(pkt))


def compute_bandwidth(pcap_path, bin_size):
    """
    Computes bandwidth over time from a pcap.

    Returns:
        times_relative: list of seconds from first packet
        bandwidth_mbps: list of Mbps values
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

    return times_relative, bandwidth_mbps


def average(values):
    if not values:
        return None
    return sum(values) / len(values)


def values_in_window(times, values, start_seconds, end_seconds=None):
    selected = []

    for time, value in zip(times, values):
        if time < start_seconds:
            continue

        if end_seconds is not None and time >= end_seconds:
            continue

        selected.append(value)

    return selected


def format_seconds(seconds):
    if seconds < 60:
        return f"{seconds:.2f}s"

    minutes = int(seconds // 60)
    remaining_seconds = seconds % 60
    return f"{minutes}m {remaining_seconds:.2f}s"


def analyze_bandwidth(pcap_path, bin_size, attack_start, split_second):
    times, bandwidth = compute_bandwidth(pcap_path, bin_size)

    if not bandwidth:
        raise ValueError("No bandwidth data found.")

    attack_to_split = values_in_window(
        times,
        bandwidth,
        start_seconds=attack_start,
        end_seconds=split_second,
    )
    split_to_end = values_in_window(
        times,
        bandwidth,
        start_seconds=split_second,
    )

    avg_attack_to_split = average(attack_to_split)
    avg_split_to_end = average(split_to_end)

    print("Bandwidth analysis")
    print("==================")
    print(f"PCAP: {pcap_path}")
    print(f"Bin size: {bin_size} seconds")
    print(f"Attack start: {format_seconds(attack_start)}")
    print(f"Split second: {format_seconds(split_second)}")
    print()

    print("Average from attack start to split second")
    print("-----------------------------------------")

    if avg_attack_to_split is None:
        print("Not available: no bandwidth bins in this interval.")
    else:
        print(f"Window: {format_seconds(attack_start)} to {format_seconds(split_second)}")
        print(f"Average: {avg_attack_to_split:.6f} Mbps")
        print(f"Number of bins: {len(attack_to_split)}")

    print()
    print("Average from split second until end")
    print("-----------------------------------")

    if avg_split_to_end is None:
        print("Not available: no bandwidth bins in this interval.")
    else:
        print(f"Window: {format_seconds(split_second)} to end")
        print(f"Average: {avg_split_to_end:.6f} Mbps")
        print(f"Number of bins: {len(split_to_end)}")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Compute average legitimate client bandwidth from attack start "
            "to a split second, then from the split second to the end."
        )
    )

    parser.add_argument(
        "pcap",
        help="Legitimate client pcap file",
    )

    parser.add_argument(
        "-b",
        "--bin-size",
        type=float,
        default=1.0,
        help="Bandwidth bin size in seconds. Default: 1.0",
    )

    parser.add_argument(
        "--attack-start",
        type=float,
        default=DEFAULT_ATTACK_START_SECONDS,
        help=f"Attack start second. Default: {DEFAULT_ATTACK_START_SECONDS}",
    )

    parser.add_argument(
        "--split-second",
        type=float,
        default=DEFAULT_SPLIT_SECONDS,
        help=f"Second where the two averages are split. Default: {DEFAULT_SPLIT_SECONDS}",
    )

    args = parser.parse_args()

    analyze_bandwidth(
        pcap_path=args.pcap,
        bin_size=args.bin_size,
        attack_start=args.attack_start,
        split_second=args.split_second,
    )


if __name__ == "__main__":
    main()