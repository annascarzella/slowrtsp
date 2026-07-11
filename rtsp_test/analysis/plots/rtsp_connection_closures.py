#!/usr/bin/env python3

import argparse
import re
from dataclasses import dataclass, field

import pandas as pd
import matplotlib.pyplot as plt
import pyshark


SPLIT_CONNECTIONS = True

RTSP_METHODS = {
    "OPTIONS",
    "DESCRIBE",
    "SETUP",
    "PLAY",
    "PAUSE",
    "TEARDOWN",
    "GET_PARAMETER",
    "SET_PARAMETER",
    "ANNOUNCE",
    "RECORD",
}


@dataclass
class Conn:
    connection_hash: str

    # TCP-level connection start.
    syn_time: float | None = None

    # RTSP response times.
    options_200_time: float | None = None
    setup_200_time: float | None = None
    second_describe_404_time: float | None = None

    # TCP-level close.
    close_time: float | None = None
    close_type: str | None = None

    # Internal RTSP state.
    describe_count: int = 0
    has_setup_request: bool = False

    # CSeq -> (method, describe_ordinal)
    pending_by_cseq: dict[str, tuple[str, int | None]] = field(default_factory=dict)

    # Fallback when CSeq is missing.
    pending_without_cseq: list[tuple[str, int | None]] = field(default_factory=list)

    # Track FIN per direction so we do not remove active mapping too early.
    fin_from_k1: bool = False
    fin_from_k2: bool = False


def layer_names(pkt):
    return [layer.layer_name.lower() for layer in pkt.layers]


def has_layer(pkt, name):
    return name.lower() in layer_names(pkt)


def packet_time(pkt):
    return float(pkt.sniff_timestamp)


def flag_is_set(value):
    """
    PyShark/tshark may return TCP flags as:
    - "1" / "0"
    - "True" / "False"
    - True / False
    """
    return str(value).lower() in {"1", "true"}


def get_layer3_protocol(pkt):
    for name in ["ip", "ipv6", "arp"]:
        if has_layer(pkt, name):
            return name
    return None


def get_layer4_protocol(pkt):
    for name in ["tcp", "udp", "icmp"]:
        if has_layer(pkt, name):
            return name
    return None


def tcp_flag(pkt, flag_name):
    """
    Return True if a TCP flag is set.
    flag_name can be: SYN, ACK, FIN, RST.
    """
    if get_layer4_protocol(pkt) != "tcp":
        return False

    try:
        if flag_name == "SYN":
            return flag_is_set(pkt.tcp.flags_syn)
        if flag_name == "ACK":
            return flag_is_set(pkt.tcp.flags_ack)
        if flag_name == "FIN":
            return flag_is_set(pkt.tcp.flags_fin)
        if flag_name == "RST":
            return flag_is_set(pkt.tcp.flags_reset)
    except AttributeError:
        return False

    return False


def get_src(pkt):
    l3 = get_layer3_protocol(pkt)

    try:
        if l3 == "ip":
            return pkt.ip.src
        if l3 == "ipv6":
            return pkt.ipv6.src
        if l3 == "arp":
            return pkt.arp.src_proto_ipv4
    except AttributeError:
        pass

    try:
        return pkt.eth.src
    except AttributeError:
        return None


def get_dst(pkt):
    l3 = get_layer3_protocol(pkt)

    try:
        if l3 == "ip":
            return pkt.ip.dst
        if l3 == "ipv6":
            return pkt.ipv6.dst
        if l3 == "arp":
            return pkt.arp.dst_proto_ipv4
    except AttributeError:
        pass

    try:
        return pkt.eth.dst
    except AttributeError:
        return None


def get_sport(pkt):
    l4 = get_layer4_protocol(pkt)

    try:
        if l4 == "tcp":
            return pkt.tcp.srcport
        if l4 == "udp":
            return pkt.udp.srcport
    except AttributeError:
        return None

    return None


def get_dport(pkt):
    l4 = get_layer4_protocol(pkt)

    try:
        if l4 == "tcp":
            return pkt.tcp.dstport
        if l4 == "udp":
            return pkt.udp.dstport
    except AttributeError:
        return None

    return None


def make_hash_pair(pkt):
    """
    Generate the two possible base hashes for a bidirectional connection.

    Example:
        TCP 10.0.0.1:12345_10.0.0.2:554
        TCP 10.0.0.2:554_10.0.0.1:12345
    """
    l3 = get_layer3_protocol(pkt)
    l4 = get_layer4_protocol(pkt)

    src = get_src(pkt)
    dst = get_dst(pkt)

    if src is None or dst is None:
        return None, None

    if l3 is None:
        return f"OTHER {src}_{dst}", f"OTHER {dst}_{src}"

    if l3 == "arp":
        return f"ARP {src}_{dst}", f"ARP {dst}_{src}"

    if l3 in {"ip", "ipv6"}:
        if l4 is None:
            proto = l3.upper()
            return f"{proto} {src}_{dst}", f"{proto} {dst}_{src}"

        if l4 == "icmp":
            return f"ICMP {src}_{dst}", f"ICMP {dst}_{src}"

        sport = get_sport(pkt)
        dport = get_dport(pkt)

        if sport is None or dport is None:
            proto = l4.upper()
            return f"{proto} {src}_{dst}", f"{proto} {dst}_{src}"

        proto = l4.upper()

        k1 = f"{proto} {src}:{sport}_{dst}:{dport}"
        k2 = f"{proto} {dst}:{dport}_{src}:{sport}"

        return k1, k2

    return None, None


def getcount(base_hash, counters):
    counters[base_hash] = counters.get(base_hash, 0) + 1
    return counters[base_hash]


def gethash(pkt, conns, counters, active_connections):
    """
    Return a unique connection identifier.

    Correctly handles reused ports:
    - SYN without ACK creates a new numbered connection.
    - Normal packets attach to the currently active numbered connection.
    - If capture starts mid-connection, fall back to #1.
    """
    k1, k2 = make_hash_pair(pkt)

    if k1 is None or k2 is None:
        return None

    is_new_tcp_connection = (
        SPLIT_CONNECTIONS
        and tcp_flag(pkt, "SYN")
        and not tcp_flag(pkt, "ACK")
    )

    if is_new_tcp_connection:
        count = getcount(k1, counters)
        numbered_hash = f"{k1}#{count}"

        active_connections[k1] = numbered_hash
        active_connections[k2] = numbered_hash

        return numbered_hash

    if k1 in active_connections:
        return active_connections[k1]

    if k2 in active_connections:
        return active_connections[k2]

    fallback_k1 = f"{k1}#1"
    fallback_k2 = f"{k2}#1"

    if fallback_k1 in conns:
        return fallback_k1

    if fallback_k2 in conns:
        return fallback_k2

    return fallback_k1


def remove_active_connection(pkt, active_connections):
    k1, k2 = make_hash_pair(pkt)

    if k1 is not None:
        active_connections.pop(k1, None)

    if k2 is not None:
        active_connections.pop(k2, None)


def tcp_payload_as_text(pkt):
    """
    Fallback parser in case tshark does not decode RTSP fields.
    """
    try:
        payload_hex = pkt.tcp.payload.replace(":", "")
        return bytes.fromhex(payload_hex).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def parse_rtsp_messages_from_payload(payload):
    """
    Parse RTSP request/response messages from a TCP payload.

    Returns examples:
        {"type": "request", "method": "SETUP", "cseq": "4"}
        {"type": "response", "status_code": 200, "reason": "OK", "cseq": "4"}
    """
    if not payload:
        return []

    start_line_pattern = (
        r"(?=(?:"
        r"OPTIONS|DESCRIBE|SETUP|PLAY|PAUSE|TEARDOWN|GET_PARAMETER|SET_PARAMETER|ANNOUNCE|RECORD"
        r")\s+\S+\s+RTSP/\d\.\d|RTSP/\d\.\d\s+\d{3})"
    )

    parts = re.split(start_line_pattern, payload)
    messages = []

    for part in parts:
        part = part.strip("\x00\r\n ")
        if not part:
            continue

        lines = part.replace("\r\n", "\n").split("\n")
        if not lines:
            continue

        start = lines[0].strip()

        cseq = None
        for line in lines[1:]:
            m = re.match(r"^\s*CSeq\s*:\s*(\S+)", line, flags=re.IGNORECASE)
            if m:
                cseq = m.group(1).strip()
                break

        request_match = re.match(
            r"^(OPTIONS|DESCRIBE|SETUP|PLAY|PAUSE|TEARDOWN|GET_PARAMETER|SET_PARAMETER|ANNOUNCE|RECORD)\s+",
            start,
            flags=re.IGNORECASE,
        )

        if request_match:
            method = request_match.group(1).upper()
            messages.append(
                {
                    "type": "request",
                    "method": method,
                    "cseq": cseq,
                }
            )
            continue

        response_match = re.match(
            r"^RTSP/\d\.\d\s+(\d{3})(?:\s+(.*))?$",
            start,
            flags=re.IGNORECASE,
        )

        if response_match:
            status_code = int(response_match.group(1))
            reason = (response_match.group(2) or "").strip()

            messages.append(
                {
                    "type": "response",
                    "status_code": status_code,
                    "reason": reason,
                    "cseq": cseq,
                }
            )

    return messages


def rtsp_messages(pkt):
    """
    Extract RTSP messages from a packet.

    Prefer parsing the TCP payload because it lets us match SETUP/DESCRIBE
    requests with responses using CSeq. If payload parsing fails, fall back to
    PyShark's decoded RTSP fields.
    """
    messages = parse_rtsp_messages_from_payload(tcp_payload_as_text(pkt))

    if messages:
        return messages

    if not has_layer(pkt, "rtsp"):
        return []

    try:
        method = pkt.rtsp.request_method.upper()
        cseq = getattr(pkt.rtsp, "cseq", None)
        return [
            {
                "type": "request",
                "method": method,
                "cseq": str(cseq) if cseq is not None else None,
            }
        ]
    except AttributeError:
        pass

    try:
        status_code = int(pkt.rtsp.status_code)
        reason = getattr(pkt.rtsp, "response_phrase", "")
        cseq = getattr(pkt.rtsp, "cseq", None)
        return [
            {
                "type": "response",
                "status_code": status_code,
                "reason": str(reason) if reason is not None else "",
                "cseq": str(cseq) if cseq is not None else None,
            }
        ]
    except AttributeError:
        pass

    return []


def record_rtsp_request(conn, method, cseq):
    """
    Store RTSP request state.

    DESCRIBE is counted internally only so that we can detect:
        second DESCRIBE -> 404 Stream Not Found
    """
    method = method.upper()
    describe_ordinal = None

    if method == "DESCRIBE":
        conn.describe_count += 1
        describe_ordinal = conn.describe_count

    elif method == "SETUP":
        conn.has_setup_request = True

    if cseq is not None:
        conn.pending_by_cseq[str(cseq)] = (method, describe_ordinal)
    else:
        conn.pending_without_cseq.append((method, describe_ordinal))


def pop_matching_request(conn, cseq):
    """
    Find the request corresponding to an RTSP response.

    Prefer CSeq matching. If CSeq is missing, use FIFO fallback.
    """
    if cseq is not None:
        cseq = str(cseq)
        if cseq in conn.pending_by_cseq:
            return conn.pending_by_cseq.pop(cseq)

    if conn.pending_without_cseq:
        return conn.pending_without_cseq.pop(0)

    return None, None


def record_rtsp_response(conn, status_code, reason, cseq, t):
    """
    Store RTSP response state.

    options_200:
        OPTIONS request -> 200 OK response

    successful_rtsp:
        SETUP request -> 200 OK response

    received_404_stream_not_found:
        second DESCRIBE request -> 404 response
    """
    method, describe_ordinal = pop_matching_request(conn, cseq)

    if method == "OPTIONS" and status_code == 200:
        if conn.options_200_time is None:
            conn.options_200_time = t

    elif method == "SETUP" and status_code == 200:
        if conn.setup_200_time is None:
            conn.setup_200_time = t

    elif (
        method == "DESCRIBE"
        and describe_ordinal == 2
        and status_code == 404
    ):
        if conn.second_describe_404_time is None:
            conn.second_describe_404_time = t


def update_rtsp_state(conn, pkt, t):
    for msg in rtsp_messages(pkt):
        if msg["type"] == "request":
            record_rtsp_request(
                conn=conn,
                method=msg["method"],
                cseq=msg.get("cseq"),
            )

        elif msg["type"] == "response":
            record_rtsp_response(
                conn=conn,
                status_code=msg["status_code"],
                reason=msg.get("reason", ""),
                cseq=msg.get("cseq"),
                t=t,
            )


def close_type(pkt):
    """
    Detect TCP connection close event.
    """
    if tcp_flag(pkt, "RST"):
        return "RST"

    if tcp_flag(pkt, "FIN"):
        return "FIN"

    return None


def update_fin_state(conn, pkt):
    """
    Mark which direction sent FIN.

    Returns True when both sides have sent FIN.
    """
    k1, k2 = make_hash_pair(pkt)

    if k1 is None or k2 is None:
        return False

    base_conn_hash = conn.connection_hash.split("#")[0]

    if k1 == base_conn_hash:
        conn.fin_from_k1 = True
    elif k2 == base_conn_hash:
        conn.fin_from_k2 = True
    else:
        conn.fin_from_k1 = True

    return conn.fin_from_k1 and conn.fin_from_k2


def analyze_pcap(pcap_path, rtsp_port=554):
    cap = pyshark.FileCapture(
        pcap_path,
        display_filter=f"tcp.port == {rtsp_port}",
        keep_packets=False,
    )

    conns: dict[str, Conn] = {}
    counters: dict[str, int] = {}
    active_connections: dict[str, str] = {}

    first_capture_time = None

    for pkt in cap:
        if not has_layer(pkt, "tcp"):
            continue

        t = packet_time(pkt)

        if first_capture_time is None:
            first_capture_time = t

        h = gethash(pkt, conns, counters, active_connections)

        if h is None:
            continue

        ctype = close_type(pkt)

        is_new_tcp_connection = (
            tcp_flag(pkt, "SYN")
            and not tcp_flag(pkt, "ACK")
        )

        if h not in conns:
            # If capture starts with a closing packet for an unknown connection,
            # ignore it.
            if ctype is not None and not is_new_tcp_connection:
                remove_active_connection(pkt, active_connections)
                continue

            conns[h] = Conn(connection_hash=h)

        conn = conns[h]

        if is_new_tcp_connection and conn.syn_time is None:
            conn.syn_time = t

        update_rtsp_state(conn, pkt, t)

        if ctype is not None:
            if conn.close_time is None:
                conn.close_time = t
                conn.close_type = ctype

            if ctype == "RST":
                remove_active_connection(pkt, active_connections)

            elif ctype == "FIN":
                both_sides_finished = update_fin_state(conn, pkt)

                if both_sides_finished:
                    remove_active_connection(pkt, active_connections)

    cap.close()

    if first_capture_time is None:
        raise RuntimeError("No TCP packets found in the capture.")

    rows = []

    for conn in conns.values():
        if conn.syn_time is None:
            continue

        options_200 = conn.options_200_time is not None
        successful_rtsp = conn.setup_200_time is not None
        received_404_stream_not_found = conn.second_describe_404_time is not None

        rows.append(
            {
                "connection_hash": conn.connection_hash,

                # TCP-level timing.
                "start_time": conn.syn_time - first_capture_time,

                # OPTIONS success timing.
                "options_200_time": (
                    conn.options_200_time - first_capture_time
                    if conn.options_200_time is not None
                    else None
                ),

                # SETUP success timing.
                "setup_200_time": (
                    conn.setup_200_time - first_capture_time
                    if conn.setup_200_time is not None
                    else None
                ),

                # Second DESCRIBE 404 timing.
                "second_describe_404_time": (
                    conn.second_describe_404_time - first_capture_time
                    if conn.second_describe_404_time is not None
                    else None
                ),

                # Boolean columns.
                "options_200": options_200,
                "has_setup": conn.has_setup_request,
                "has_setup_200": successful_rtsp,

                # Correct definition:
                # successful RTSP means SETUP received 200 OK.
                "successful_rtsp": successful_rtsp,

                # Second DESCRIBE received 404.
                "received_404_stream_not_found": received_404_stream_not_found,

                # TCP close.
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

    # Connection ID represents the order in which TCP connections started.
    df = df.sort_values("start_time").reset_index(drop=True)
    df["connection_id"] = df.index + 1

    return df


def make_plot(
    df,
    output_path,
    duration=5200,
    expected_connections=1016,
    title=None,
):
    plt.figure(figsize=(16, 7))

    df_thinned = df[::10]

    plt.scatter(
        df_thinned["connection_id"],
        df_thinned["start_time"],
        marker="o",
        s=40,
        alpha=0.7,
        color="darkslategray",
        label="Start: TCP SYN observed",
    )

    closed = df[df["close_time"].notna()].copy()
    closed_thinned = closed[::10]

    plt.scatter(
        closed_thinned["connection_id"],
        closed_thinned["close_time"],
        marker="x",
        s=60,
        alpha=0.9,
        color="darkgray",
        label="End: TCP FIN/RST observed",
    )

    failed_setup = df[~df["successful_rtsp"]].copy()
    failed_setup_thinned = failed_setup[::10]

    if not failed_setup_thinned.empty:
        plt.scatter(
            failed_setup_thinned["connection_id"],
            failed_setup_thinned["start_time"],
            marker="^",
            s=70,
            alpha=0.9,
            color="black",
            label="No SETUP 200 OK",
        )

    stream_not_found = df[df["received_404_stream_not_found"]].copy()
    stream_not_found_thinned = stream_not_found[::10]

    if not stream_not_found_thinned.empty:
        plt.scatter(
            stream_not_found_thinned["connection_id"],
            stream_not_found_thinned["start_time"],
            marker="s",
            s=70,
            alpha=0.9,
            color="dimgray",
            label="Second DESCRIBE received 404",
        )

    if title:
        plt.title(title, fontsize=24)

    plt.xlabel("Connection ID", fontsize=18)
    plt.ylabel("Time since beginning of capture [s]", fontsize=18)

    plt.xlim(0, expected_connections)
    plt.ylim(0, duration)

    plt.legend(loc="upper left", fontsize=18)
    plt.grid(True, linewidth=0.5, alpha=0.3, color="gray")
    plt.xticks(fontsize=18)
    plt.yticks(fontsize=18)
    plt.tight_layout()

    plt.savefig(output_path, dpi=600)
    plt.close()


def main():
    parser = argparse.ArgumentParser(
        description="Plot RTSP TCP connection start/end times from a pcap."
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
        type=float,
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
        "--title",
        default=None,
        help="Plot title, for example: 'PLAY-based strategy'",
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
        print("No TCP connections found.")
        return

    df.to_csv(args.csv, index=False)

    make_plot(
        df=df,
        output_path=args.out,
        duration=args.duration,
        expected_connections=args.expected_connections,
        title=args.title,
    )

    total = len(df)
    options_200 = int(df["options_200"].sum())
    with_setup = int(df["has_setup"].sum())
    successful_rtsp = int(df["successful_rtsp"].sum())
    stream_not_found = int(df["received_404_stream_not_found"].sum())
    closed = int(df["close_time"].notna().sum())
    still_open = total - closed

    print(f"TCP connections started: {total}")
    print(f"Connections with OPTIONS 200 OK: {options_200}")
    print(f"Connections with SETUP request: {with_setup}")
    print(f"Successful RTSP connections, SETUP + 200 OK: {successful_rtsp}")
    print(f"Received 404 Stream Not Found on second DESCRIBE: {stream_not_found}")
    print(f"Closed connections: {closed}")
    print(f"Still open at end of capture: {still_open}")
    print(f"CSV written to: {args.csv}")
    print(f"Plot written to: {args.out}")


if __name__ == "__main__":
    main()