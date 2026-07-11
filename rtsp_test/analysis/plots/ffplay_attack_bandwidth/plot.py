#!/usr/bin/env python3

import argparse
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
from scapy.utils import PcapReader


TITLE_FONTSIZE = 24
LABEL_FONTSIZE = 22
TICK_FONTSIZE = 22
X_AXIS_SECONDS = 600


def texttt(text):
    escaped_text = text.replace("_", "\\_").replace(" ", "\\ ")
    return "$\\mathtt{" + escaped_text + "}$"


def format_attack_name(attack_name):
    loop_suffix = "-loop"
    if loop_suffix not in attack_name:
        return attack_name

    method, rest = attack_name.split(loop_suffix, 1)
    if not method.isupper():
        return attack_name

    return f"{texttt(method)}{loop_suffix}{rest}"


def packet_timestamp(pkt):
    return float(pkt.time)


def packet_len_bytes(pkt):
    return len(bytes(pkt))


def compute_bandwidth(pcap_path, bin_size):
    """
    Returns:
        times_relative: seconds from first packet of this pcap
        bandwidth_mbps: Mbps values, computed only from this pcap
    """
    bins = defaultdict(int)
    first_ts = None

    with PcapReader(str(pcap_path)) as packets:
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


def plot_bandwidth_comparison(
    ffplay_pcap,
    attack_pcap,
    output,
    bin_size,
    attack_name,
    title=None,
):
    ffplay_times, ffplay_bandwidth = compute_bandwidth(ffplay_pcap, bin_size)
    attack_times, attack_bandwidth = compute_bandwidth(attack_pcap, bin_size)

    fig, ax = plt.subplots(figsize=(16, 10))

    ax.plot(
        ffplay_times,
        ffplay_bandwidth,
        color="grey",
        linewidth=2,
        label=f"{texttt('ffplay')} capture",
    )

    ax.plot(
        attack_times,
        attack_bandwidth,
        color="#303030",
        linewidth=2,
        linestyle="--",
        label=format_attack_name(attack_name),
    )

    if title is None:
        title = (
            f"Bandwidth comparison between {texttt('ffplay')} "
            f"and {format_attack_name(attack_name)}"
        )

    ax.set_title(title, fontsize=TITLE_FONTSIZE)
    ax.set_xlabel("t", fontsize=LABEL_FONTSIZE, fontstyle="italic")
    ax.set_ylabel("Bandwidth (Mbps)", fontsize=LABEL_FONTSIZE)

    ax.set_xlim(0, X_AXIS_SECONDS)
    ax.set_yscale("log")

    ax.tick_params(axis="both", labelsize=TICK_FONTSIZE)
    ax.grid(True)
    ax.legend(fontsize=LABEL_FONTSIZE)
    plt.tight_layout()

    plt.savefig(output, dpi=150)
    plt.close(fig)
    print(f"Saved plot to: {output}")


def main():
    script_dir = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(
        description="Plot bandwidth over time for ffplay and attack pcaps."
    )

    parser.add_argument(
        "ffplay_pcap",
        nargs="?",
        type=Path,
        default=script_dir / "ffplay.pcap",
        help="ffplay pcap file. Default: ffplay.pcap next to this script",
    )

    parser.add_argument(
        "attack_pcap",
        nargs="?",
        type=Path,
        default=script_dir / "attack.pcap",
        help="attack pcap file. Default: attack.pcap next to this script",
    )

    parser.add_argument(
        "-b",
        "--bin-size",
        type=float,
        default=1.0,
        help="Bandwidth bin size in seconds. Default: 1.0",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=script_dir / "ffplay_attack_bandwidth.png",
        help=(
            "Output image path. Default: ffplay_attack_bandwidth.png "
            "next to this script"
        ),
    )

    parser.add_argument(
        "--title",
        default=None,
        help="Plot title.",
    )

    parser.add_argument(
        "--attack-name",
        default="attack capture",
        help=(
            "Name to use for the attack trace in the legend and default title. "
            "Example: 'Play Loop Scenario'"
        ),
    )

    args = parser.parse_args()

    if args.bin_size <= 0:
        parser.error("--bin-size must be greater than 0")

    plot_bandwidth_comparison(
        ffplay_pcap=args.ffplay_pcap,
        attack_pcap=args.attack_pcap,
        output=args.output,
        bin_size=args.bin_size,
        attack_name=args.attack_name,
        title=args.title,
    )


if __name__ == "__main__":
    main()
