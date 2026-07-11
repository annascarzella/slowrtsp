#!/usr/bin/env python3

import argparse
import math
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
from scapy.all import IP, IPv6, TCP, Raw, PcapReader


SCRIPT_DIR = Path(__file__).resolve().parent
RTSP_TEST_DIR = SCRIPT_DIR.parents[2]
DEFAULT_PCAPS = [
    RTSP_TEST_DIR
    / "test_runs"
    / "bosch"
    / str(idx)
    / "3_find-max-n-options"
    / "b_delay0001_100conn"
    / "output"
    / "capture.pcap"
    for idx in range(1, 13)
]


def ip_layer(pkt):
    if IP in pkt:
        return pkt[IP]
    if IPv6 in pkt:
        return pkt[IPv6]
    return None


def payload_text(pkt):
    if Raw not in pkt:
        return ""
    try:
        return bytes(pkt[Raw].load).decode("latin1", errors="ignore")
    except Exception:
        return ""


def normalize_flow(src, sport, dst, dport):
    """
    Direction-independent TCP flow key.
    """
    a = (src, sport)
    b = (dst, dport)
    return tuple(sorted([a, b]))


def is_rtsp_401_response(text):
    """
    Return True only for RTSP 401 Unauthorized responses.
    """
    text = text.lstrip()

    if not text:
        return False

    first_line = text.splitlines()[0]
    parts = first_line.split()

    if len(parts) < 2:
        return False

    version = parts[0]
    status_code = parts[1]

    return version in ("RTSP/1.0", "RTSP/2.0") and status_code == "401"


def analyze_pcap(pcap_path):
    flows = {}

    with PcapReader(str(pcap_path)) as packets:
        for pkt in packets:
            ip = ip_layer(pkt)
            if ip is None or TCP not in pkt:
                continue

            tcp = pkt[TCP]
            src = ip.src
            dst = ip.dst
            sport = int(tcp.sport)
            dport = int(tcp.dport)
            ts = float(pkt.time)

            flow_key = normalize_flow(src, sport, dst, dport)

            if flow_key not in flows:
                flows[flow_key] = {
                    "request_time": None,
                    "response_time": None,
                    "client_ip": None,
                    "client_port": None,
                    "server_ip": None,
                    "server_port": None,
                    "closed_by_fin": False,
                    "closed_by_rst": False,
                    "close_time": None,
                }

            flow = flows[flow_key]

            flags = int(tcp.flags)
            fin_seen = bool(flags & 0x01)
            rst_seen = bool(flags & 0x04)

            if fin_seen or rst_seen:
                if flow["close_time"] is None:
                    flow["close_time"] = ts
                if fin_seen:
                    flow["closed_by_fin"] = True
                if rst_seen:
                    flow["closed_by_rst"] = True

            text = payload_text(pkt).lstrip()

            # Client -> server RTSP OPTIONS request
            if text.startswith("OPTIONS "):
                if flow["request_time"] is None:
                    flow["request_time"] = ts
                    flow["client_ip"] = src
                    flow["client_port"] = sport
                    flow["server_ip"] = dst
                    flow["server_port"] = dport

            # Server -> client RTSP 401 Unauthorized response only
            elif is_rtsp_401_response(text):
                if flow["request_time"] is not None and flow["response_time"] is None:
                    if src == flow["server_ip"] and sport == flow["server_port"]:
                        flow["response_time"] = ts

    rows = []
    request_flows = [
        f for f in flows.values()
        if f["request_time"] is not None
    ]
    request_flows.sort(key=lambda f: f["request_time"])

    first_request_time = request_flows[0]["request_time"] if request_flows else 0.0

    for idx, flow in enumerate(request_flows, start=1):
        if flow["response_time"] is not None:
            delay = flow["response_time"] - flow["request_time"]
            status = "rtsp_401_unauthorized"
        else:
            delay = math.nan
            status = "no_rtsp_401_response"

        rows.append({
            "connection_id": idx,
            "client": f'{flow["client_ip"]}:{flow["client_port"]}',
            "server": f'{flow["server_ip"]}:{flow["server_port"]}',
            "request_time_relative": flow["request_time"] - first_request_time,
            "response_time_relative": (
                flow["response_time"] - first_request_time
                if flow["response_time"] is not None else math.nan
            ),
            "response_delay_seconds": delay,
            "status": status,
            "closed_by_fin": flow["closed_by_fin"],
            "closed_by_rst": flow["closed_by_rst"],
            "close_time_relative": (
                flow["close_time"] - first_request_time
                if flow["close_time"] is not None else math.nan
            ),
        })

    return pd.DataFrame(rows)


def full_run_dataframe(df, attempted_connections, run_id, pcap_path):
    full = pd.DataFrame({
        "connection_id": range(1, attempted_connections + 1)
    })

    if not df.empty:
        full = full.merge(
            df[["connection_id", "response_delay_seconds", "status"]],
            on="connection_id",
            how="left",
        )
    else:
        full["response_delay_seconds"] = math.nan
        full["status"] = "not_seen_in_pcap"

    full["run_id"] = run_id
    full["pcap"] = str(pcap_path)
    full["status"] = full["status"].fillna("not_seen_in_pcap")
    full["has_rtsp_401_response"] = full["status"] == "rtsp_401_unauthorized"

    # Match plot_server_options_response.py: anything without a 401 response is plotted as 0.
    full["plot_delay_seconds"] = full["response_delay_seconds"].fillna(0)

    return full


def aggregate_runs(run_frames):
    all_runs = pd.concat(run_frames, ignore_index=True)
    grouped = all_runs.groupby("connection_id", as_index=False)

    summary = grouped.agg(
        mean_response_delay_seconds=("plot_delay_seconds", "mean"),
        stddev_response_delay_seconds=("plot_delay_seconds", "std"),
        min_response_delay_seconds=("plot_delay_seconds", "min"),
        max_response_delay_seconds=("plot_delay_seconds", "max"),
        runs_count=("plot_delay_seconds", "count"),
        responses_401_count=("has_rtsp_401_response", "sum"),
    )
    summary["stddev_response_delay_seconds"] = (
        summary["stddev_response_delay_seconds"].fillna(0)
    )
    summary.loc[
        summary["stddev_response_delay_seconds"] < 0,
        "stddev_response_delay_seconds",
    ] = 0

    return summary, all_runs


def make_plot(summary, output_png, attempted_connections, title=None):
    plt.figure(figsize=(16, 10))

    plt.errorbar(
        summary["connection_id"],
        summary["mean_response_delay_seconds"],
        yerr=summary["stddev_response_delay_seconds"],
        fmt="o",
        color="grey",
        ecolor="grey",
        elinewidth=2,
        capsize=5,
        capthick=2,
        markersize=8,
        markerfacecolor="none",
        markeredgewidth=2,
    )

    plt.axhline(0, linewidth=1)
    plt.xlim(0, attempted_connections)
    plt.ylim(bottom=0)
    plt.xticks(range(0, attempted_connections + 1, 10), fontsize=24)
    plt.yticks(fontsize=24)

    plt.xlabel("i", fontsize=24)
    plt.ylabel("$T_r$", fontsize=24)
    if title is None:
        title = f"Response times $T_r$ when opening $N_a$ = {attempted_connections} connections"
    plt.title(title, fontsize=28)
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(output_png, dpi=150)
    plt.close()


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Analyze RTSP OPTIONS 401 Unauthorized response times across 12 PCAPs "
            "and plot mean response time with standard deviation."
        )
    )
    parser.add_argument(
        "pcaps",
        nargs="*",
        help=(
            "Input PCAP or PCAPNG files. If omitted, uses "
            "test_runs/bosch/1..12/3_find-max-n-options/"
            "b_delay0001_100conn/output/capture.pcap."
        ),
    )
    parser.add_argument(
        "--attempted-connections",
        type=int,
        default=100,
        help="Number of RTSP connections that were attempted. Default: 100",
    )
    parser.add_argument(
        "--csv",
        default="rtsp_response_times_avg_std.csv",
        help="Output aggregate CSV file. Default: rtsp_response_times_avg_std.csv",
    )
    parser.add_argument(
        "--runs-csv",
        default="rtsp_response_times_all_runs.csv",
        help="Output per-run CSV file. Default: rtsp_response_times_all_runs.csv",
    )
    parser.add_argument(
        "--plot",
        default="rtsp_response_times_avg_std.png",
        help="Output plot PNG file. Default: rtsp_response_times_avg_std.png",
    )
    parser.add_argument(
        "--title",
        default=None,
        help="Plot title. Example: 'PLAY-based strategy' or 'GET_PARAMETER-based strategy'",
    )

    args = parser.parse_args()
    pcaps = [Path(pcap) for pcap in args.pcaps] if args.pcaps else DEFAULT_PCAPS

    missing_pcaps = [pcap for pcap in pcaps if not pcap.exists()]
    if missing_pcaps:
        missing = "\n".join(f"  {pcap}" for pcap in missing_pcaps)
        raise FileNotFoundError(f"Missing PCAP file(s):\n{missing}")

    if not pcaps:
        raise FileNotFoundError("No PCAP files found to analyze.")

    run_frames = []
    for run_id, pcap_path in enumerate(pcaps, start=1):
        df = analyze_pcap(pcap_path)
        run_frames.append(
            full_run_dataframe(
                df=df,
                attempted_connections=args.attempted_connections,
                run_id=run_id,
                pcap_path=pcap_path,
            )
        )

    summary, all_runs = aggregate_runs(run_frames)
    summary.to_csv(args.csv, index=False)
    all_runs.to_csv(args.runs_csv, index=False)

    make_plot(
        summary=summary,
        output_png=args.plot,
        attempted_connections=args.attempted_connections,
        title=args.title,
    )

    print(f"Analyzed {len(pcaps)} PCAPs")
    print(f"Wrote aggregate CSV: {args.csv}")
    print(f"Wrote per-run CSV: {args.runs_csv}")
    print(f"Wrote plot: {args.plot}")


if __name__ == "__main__":
    main()
