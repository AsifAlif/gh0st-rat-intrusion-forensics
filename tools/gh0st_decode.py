#!/usr/bin/env python3
"""
gh0st_decode.py - Reassemble TCP streams from a PCAP and decode Gh0st RAT traffic.

Gh0st RAT frames every message as:

    +---------+-----------------+--------------------+---------------------------+
    | "Gh0st" | total_len (u32) | uncompressed (u32) | zlib-compressed payload   |
    | 5 bytes | little-endian   | little-endian      | (total_len - 13 bytes)    |
    +---------+-----------------+--------------------+---------------------------+

In control channels the first decompressed byte is a command / response token;
in the remote-shell channel the payload is raw console text. This script prints every decoded message per TCP stream, which reveals the
operator's shell commands, their output, and file-manager transfers.

Usage:
    pip install dpkt
    python3 tools/gh0st_decode.py challenge.pcap [--magic Gh0st] [--max 0]
"""
import argparse
import collections
import re
import socket
import zlib

import dpkt

HEADER_LEN = 13  # 5-byte magic + 4-byte total length + 4-byte uncompressed length


def reassemble(pcap_path):
    """Return {(src, sport, dst, dport): bytes} with duplicate segments removed."""
    streams = collections.OrderedDict()
    seen = set()
    with open(pcap_path, "rb") as fh:
        for _, buf in dpkt.pcap.Reader(fh):
            ip = dpkt.ethernet.Ethernet(buf).data
            if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data
            if not tcp.data:
                continue
            key = (socket.inet_ntoa(ip.src), tcp.sport, socket.inet_ntoa(ip.dst), tcp.dport)
            if (key, tcp.seq) in seen:  # skip retransmissions / keep-alives
                continue
            seen.add((key, tcp.seq))
            streams.setdefault(key, bytearray()).extend(tcp.data)
    return streams


def decode_stream(data, magic):
    """Yield decompressed Gh0st messages found in one reassembled stream."""
    i = 0
    while True:
        j = data.find(magic, i)
        if j < 0:
            return
        total = int.from_bytes(data[j + len(magic):j + len(magic) + 4], "little")
        body = bytes(data[j + HEADER_LEN:j + total])
        try:
            yield zlib.decompress(body)
        except zlib.error:
            yield None
        i = j + max(total, len(magic))


def printable(b, limit):
    text = re.sub(rb"[^\x20-\x7e\r\n\t]", b".", b if limit == 0 else b[:limit]).decode()
    return text.replace("\r\n", "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--magic", default="Gh0st", help="5-byte packet flag (variants change it)")
    ap.add_argument("--max", type=int, default=600, help="max bytes shown per message (0 = all)")
    args = ap.parse_args()
    magic = args.magic.encode()

    for (src, sport, dst, dport), data in reassemble(args.pcap).items():
        if magic not in data:
            continue
        msgs = list(decode_stream(data, magic))
        print(f"\n===== {src}:{sport} -> {dst}:{dport}  ({len(msgs)} messages, {len(data)} bytes)")
        for m in msgs:
            if m is None:
                print("  [!] zlib error")
                continue
            # Control messages start with a 1-byte token; shell-channel messages are raw
            # console text, so the full payload is printed and the first byte shown in hex.
            print(f"  [0x{m[0]:02x}] " + printable(m, args.max).replace("\n", "\n         "))


if __name__ == "__main__":
    main()
