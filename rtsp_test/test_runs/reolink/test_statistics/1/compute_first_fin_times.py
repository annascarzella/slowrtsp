#!/usr/bin/env python3
"""Extract first FIN relative times from DIBRIS timeout captures."""

from __future__ import annotations

import argparse
import math
import re
from decimal import Decimal, ROUND_DOWN
from ipaddress import IPv4Address
from pathlib import Path
import sys

ENV_FILE = Path(__file__).resolve().parents[4] / ".env"
ENV_PROFILE = "reolink"
DEFAULT_SRC_IP = ""
DEFAULT_DST_IP = ""
DEFAULT_GLOB = "../../[0-9]*/1_find-server-timeout/output/capture.pcap"
THREE_DECIMALS = Decimal("0.001")
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN_TAGS = {0x8100, 0x88A8, 0x9100}
LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276
PCAP_GLOBAL_HEADER_LEN = 24
PCAP_PACKET_HEADER_LEN = 16
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("little", Decimal("1000000")),
    b"\xa1\xb2\xc3\xd4": ("big", Decimal("1000000")),
    b"\x4d\x3c\xb2\xa1": ("little", Decimal("1000000000")),
    b"\xa1\xb2\x3c\x4d": ("big", Decimal("1000000000")),
}


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


def natural_key(path: Path) -> list[int | str]:
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", str(path))]


def format_decimal(value: Decimal, decimal_comma: bool) -> str:
    text = f"{value:.3f}"
    return text.replace(".", ",") if decimal_comma else text


def network_payload(packet: bytes, linktype: int) -> tuple[int, bytes] | None:
    if linktype == LINKTYPE_ETHERNET:
        if len(packet) < 14:
            return None

        offset = 14
        ethertype = int.from_bytes(packet[12:14], "big")
        while ethertype in ETHERTYPE_VLAN_TAGS:
            if len(packet) < offset + 4:
                return None
            ethertype = int.from_bytes(packet[offset + 2 : offset + 4], "big")
            offset += 4

        return ethertype, packet[offset:]

    if linktype == LINKTYPE_LINUX_SLL:
        if len(packet) < 16:
            return None
        return int.from_bytes(packet[14:16], "big"), packet[16:]

    if linktype == LINKTYPE_LINUX_SLL2:
        if len(packet) < 20:
            return None
        return int.from_bytes(packet[0:2], "big"), packet[20:]

    raise RuntimeError(f"unsupported pcap link type {linktype}")


def packet_is_matching_fin(
    packet: bytes, linktype: int, src_ip_bytes: bytes, dst_ip_bytes: bytes
) -> bool:
    payload = network_payload(packet, linktype)
    if payload is None:
        return False

    ethertype, ip_header = payload
    if ethertype != ETHERTYPE_IPV4 or len(ip_header) < 20:
        return False

    version = ip_header[0] >> 4
    ihl = (ip_header[0] & 0x0F) * 4
    if version != 4 or ihl < 20 or len(ip_header) < ihl:
        return False

    total_length = int.from_bytes(ip_header[2:4], "big")
    if total_length < ihl or len(ip_header) < total_length:
        return False

    protocol = ip_header[9]
    src_ip = ip_header[12:16]
    dst_ip = ip_header[16:20]
    if protocol != 6 or src_ip != src_ip_bytes or dst_ip != dst_ip_bytes:
        return False

    tcp_header = ip_header[ihl:total_length]
    if len(tcp_header) < 14:
        return False

    return bool(tcp_header[13] & 0x01)


def first_fin_time(capture: Path, src_ip_bytes: bytes, dst_ip_bytes: bytes) -> Decimal | None:
    data = capture.read_bytes()
    if len(data) < PCAP_GLOBAL_HEADER_LEN:
        raise RuntimeError(f"{capture} is too short to be a pcap file")

    pcap_format = PCAP_MAGIC.get(data[:4])
    if pcap_format is None:
        raise RuntimeError(f"{capture} is not a supported pcap file")

    byte_order, fractional_scale = pcap_format
    linktype = int.from_bytes(data[20:24], byte_order)

    offset = PCAP_GLOBAL_HEADER_LEN
    first_timestamp: Decimal | None = None
    while offset + PCAP_PACKET_HEADER_LEN <= len(data):
        packet_header = data[offset : offset + PCAP_PACKET_HEADER_LEN]
        offset += PCAP_PACKET_HEADER_LEN

        ts_sec = int.from_bytes(packet_header[0:4], byte_order)
        ts_frac = int.from_bytes(packet_header[4:8], byte_order)
        captured_length = int.from_bytes(packet_header[8:12], byte_order)
        packet = data[offset : offset + captured_length]
        offset += captured_length

        timestamp = Decimal(ts_sec) + (Decimal(ts_frac) / fractional_scale)
        if first_timestamp is None:
            first_timestamp = timestamp

        try:
            is_matching_fin = packet_is_matching_fin(
                packet, linktype, src_ip_bytes, dst_ip_bytes
            )
        except RuntimeError as exc:
            raise RuntimeError(f"{capture} has {exc}") from exc

        if is_matching_fin:
            return timestamp - first_timestamp

    if offset != len(data):
        raise RuntimeError(f"{capture} has a truncated packet record")

    return None


def sample_stddev(values: list[Decimal]) -> Decimal:
    if len(values) < 2:
        return Decimal("0")

    mean = sum(values) / Decimal(len(values))
    variance = sum((value - mean) ** 2 for value in values) / Decimal(len(values) - 1)
    return Decimal(str(math.sqrt(float(variance))))


def main() -> int:
    env = load_env(ENV_FILE)
    default_src_ip = env_value(env, ENV_PROFILE, "RTSP_SOURCE_IP", DEFAULT_SRC_IP)
    default_dst_ip = env_value(env, ENV_PROFILE, "RTSP_SERVER", DEFAULT_DST_IP)

    parser = argparse.ArgumentParser(
        description=(
            "Print the first FIN relative time from each "
            "DIBRIS 1_find-server-timeout capture, then average "
            "and sample standard deviation."
        )
    )
    parser.add_argument(
        "--glob",
        default=DEFAULT_GLOB,
        help=f"capture glob to scan, relative to this script directory (default: {DEFAULT_GLOB})",
    )
    parser.add_argument(
        "--decimal-comma",
        action="store_true",
        help="print numbers with a comma as the decimal separator",
    )
    parser.add_argument(
        "--src-ip",
        default=default_src_ip,
        help=f"source IP for the FIN packet filter (default: {default_src_ip})",
    )
    parser.add_argument(
        "--dst-ip",
        default=default_dst_ip,
        help=f"destination IP for the FIN packet filter (default: {default_dst_ip})",
    )
    args = parser.parse_args()

    if not args.src_ip or not args.dst_ip:
        print("error: --src-ip and --dst-ip are required unless configured in .env", file=sys.stderr)
        return 1

    try:
        src_ip_bytes = IPv4Address(args.src_ip).packed
        dst_ip_bytes = IPv4Address(args.dst_ip).packed
    except ValueError as exc:
        print(f"error: invalid IP address: {exc}", file=sys.stderr)
        return 1

    script_dir = Path(__file__).resolve().parent
    captures = sorted(script_dir.glob(args.glob), key=natural_key)
    if not captures:
        print(f"error: no captures matched {args.glob}", file=sys.stderr)
        return 1

    values: list[Decimal] = []
    missing: list[Path] = []

    for capture in captures:
        raw_time = first_fin_time(capture, src_ip_bytes, dst_ip_bytes)
        if raw_time is None:
            missing.append(capture)
            continue

        truncated_time = raw_time.quantize(THREE_DECIMALS, rounding=ROUND_DOWN)
        values.append(truncated_time)
        print(f"{capture}: {format_decimal(truncated_time, args.decimal_comma)}")

    if missing:
        print("\nNo matching FIN packet found in:", file=sys.stderr)
        for capture in missing:
            print(f"  {capture}", file=sys.stderr)

    if not values:
        print("error: no matching FIN packets found", file=sys.stderr)
        return 1

    average = (sum(values) / Decimal(len(values))).quantize(
        THREE_DECIMALS, rounding=ROUND_DOWN
    )
    stddev = sample_stddev(values).quantize(THREE_DECIMALS, rounding=ROUND_DOWN)

    print()
    print(f"count: {len(values)}")
    print(f"average: {format_decimal(average, args.decimal_comma)}")
    print(f"standard deviation: {format_decimal(stddev, args.decimal_comma)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
