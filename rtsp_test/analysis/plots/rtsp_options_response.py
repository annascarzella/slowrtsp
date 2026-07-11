#!/usr/bin/env python3

from scapy.all import PcapReader, TCP, IP, IPv6, Raw
import matplotlib.pyplot as plt
import pandas as pd
import math
import argparse


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

    Accepts:
      RTSP/1.0 401 Unauthorized
      RTSP/1.0 401
      RTSP/2.0 401 Unauthorized
      RTSP/2.0 401

    Ignores:
      RTSP/1.0 200 OK
      RTSP/1.0 404 Not Found
      RTSP/1.0 500 Internal Server Error
      anything else
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

    with PcapReader(pcap_path) as packets:
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
                    # Make sure the packet is from the server side of the flow
                    if src == flow["server_ip"] and sport == flow["server_port"]:
                        flow["response_time"] = ts

    rows = []

    # Keep only flows where we actually saw an OPTIONS request
    request_flows = [
        f for f in flows.values()
        if f["request_time"] is not None
    ]

    # Assign connection IDs by request timestamp
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


def make_plot(df, output_png, attempted_connections, title=None):
    # Create one row for every attempted connection ID:
    # 1, 2, 3, ..., attempted_connections
    full = pd.DataFrame({
        "connection_id": range(1, attempted_connections + 1)
    })

    # Merge actual measured RTSP 401 response times onto the full connection list
    if not df.empty:
        full = full.merge(
            df[["connection_id", "response_delay_seconds", "status"]],
            on="connection_id",
            how="left"
        )
    else:
        full["response_delay_seconds"] = math.nan
        full["status"] = "not_seen_in_pcap"

    # For anything without an RTSP 401 response, plot 0
    full["plot_delay_seconds"] = full["response_delay_seconds"].fillna(0)

    plt.figure(figsize=(16, 10))

    plt.plot(
        full["connection_id"],
        full["plot_delay_seconds"],
        color="grey"
    )

    plt.axhline(0, linewidth=1)

    # Make x-axis go from 0 to attempted_connections
    plt.xlim(0, attempted_connections)
    plt.ylim(bottom=0)

    # Show ticks as 0, 10, 20, 30, ...
    plt.xticks(range(0, attempted_connections + 1, 10), fontsize=24)
    plt.yticks(fontsize=24)

    plt.xlabel("i", fontsize=24)
    plt.ylabel("$T_r$", fontsize=24)
    if title is None:
        title = f"Obtained response times $T_r$ when sending $N_a$ = {attempted_connections} connections"
    plt.title(title, fontsize=28)
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(output_png, dpi=150)




def main():
    parser = argparse.ArgumentParser(
        description="Analyze RTSP OPTIONS 401 Unauthorized responses per TCP connection in a PCAP."
    )

    parser.add_argument(
        "pcap",
        help="Input PCAP or PCAPNG file",
    )

    parser.add_argument(
        "--attempted-connections",
        type=int,
        default=100,
        help="Number of RTSP connections that were attempted. Default: 100",
    )

    parser.add_argument(
        "--csv",
        default="rtsp_connections.csv",
        help="Output CSV file. Default: rtsp_connections.csv",
    )

    parser.add_argument(
        "--plot",
        default="rtsp_response_times.png",
        help="Output plot PNG file. Default: rtsp_response_times.png",
    )
    
    parser.add_argument(
        "--title",
        default=None,
        help="Plot title. Example: 'PLAY-based strategy' or 'GET_PARAMETER-based strategy'",
    )

    args = parser.parse_args()

    df = analyze_pcap(args.pcap)

    # total_options_seen = len(df)
    # responded_401 = (
    #     (df["status"] == "rtsp_401_unauthorized").sum()
    #     if not df.empty else 0
    # )
    # no_401_response_seen = (
    #     (df["status"] == "no_rtsp_401_response").sum()
    #     if not df.empty else 0
    # )
    # missing_from_pcap = max(args.attempted_connections - total_options_seen, 0)
    # rst_closed = df["closed_by_rst"].sum() if not df.empty else 0
    # fin_closed = df["closed_by_fin"].sum() if not df.empty else 0

    # print(f"Attempted connections: {args.attempted_connections}")
    # print(f"OPTIONS connections seen in PCAP: {total_options_seen}")
    # print(f"Connections with RTSP 401 Unauthorized response: {responded_401}")
    # print(f"Connections without RTSP 401 Unauthorized response, but OPTIONS seen: {no_401_response_seen}")
    # print(f"Attempted connections not seen as OPTIONS in PCAP: {missing_from_pcap}")
    # print(f"Connections with TCP RST: {rst_closed}")
    # print(f"Connections with TCP FIN: {fin_closed}")

    df.to_csv(args.csv, index=False)
    make_plot(
        df=df,
        output_png=args.plot,
        attempted_connections=args.attempted_connections,
        title=args.title,
    )

    print(f"Wrote CSV: {args.csv}")
    print(f"Wrote plot: {args.plot}")


if __name__ == "__main__":
    main()