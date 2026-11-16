#!/usr/bin/env python3
"""Decode /proc/net/{tcp,tcp6,udp,udp6} snapshots into readable connections.

Usage: decode_sockets.py <volatile-dir>   (reads net-*.raw written by collect-evidence.sh)
"""
import ipaddress
import os
import sys

TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
              "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
              "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}


def addr(hexaddr: str) -> str:
    ip_hex, port_hex = hexaddr.split(":")
    raw = bytes.fromhex(ip_hex)
    if len(raw) == 4:
        ip = ipaddress.IPv4Address(raw[::-1])
    else:  # IPv6: four little-endian 32-bit words
        ip = ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
    return f"{ip}:{int(port_hex, 16)}"


def main(d: str):
    print(f"{'proto':6} {'local':45} {'remote':45} {'state':12} uid inode")
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        path = os.path.join(d, f"net-{proto}.raw")
        if not os.path.exists(path):
            continue
        for line in open(path).read().splitlines()[1:]:
            f = line.split()
            if len(f) < 10:
                continue
            state = TCP_STATES.get(f[3], f[3]) if proto.startswith("tcp") else "-"
            print(f"{proto:6} {addr(f[1]):45} {addr(f[2]):45} {state:12} {f[7]:>3} {f[9]}")


if __name__ == "__main__":
    main(sys.argv[1])
