"""
generate_pcap.py
Generates synthetic PCAP files (valid libpcap format) with a specified number
of Ethernet/IP/TCP packets - no Scapy or Wireshark required.
"""

import struct
import os
import random
import socket
import time

STUDENT_ID = "23040700108"

PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4,
    2, 4,
    0,
    0,
    65535,
    1,
)


def make_eth_ip_tcp_packet(seq: int) -> bytes:
    dst_mac = bytes([0x00, 0x0c, 0x29, 0xab, 0xcd, seq % 256])
    src_mac = bytes([0x00, 0x50, 0x56, 0x10, 0x20, seq % 256])
    ethertype = struct.pack(">H", 0x0800)
    eth = dst_mac + src_mac + ethertype

    version_ihl = 0x45
    dscp_ecn    = 0x00
    total_len   = 40
    ip_id       = seq & 0xFFFF
    flags_frag  = 0x4000
    ttl         = 64
    protocol    = 6
    src_ip      = socket.inet_aton(f"192.168.{(seq//256) % 256}.{seq % 256}")
    dst_ip      = socket.inet_aton("10.0.0.1")
    ip_checksum = 0

    ip_header_no_csum = struct.pack(
        ">BBHHHBBH4s4s",
        version_ihl, dscp_ecn, total_len, ip_id, flags_frag,
        ttl, protocol, ip_checksum,
        src_ip, dst_ip,
    )

    def checksum(data):
        if len(data) % 2:
            data += b'\x00'
        s = sum(struct.unpack(f">{len(data)//2}H", data))
        s  = (s >> 16) + (s & 0xFFFF)
        s += (s >> 16)
        return ~s & 0xFFFF

    ip_csum = checksum(ip_header_no_csum)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        version_ihl, dscp_ecn, total_len, ip_id, flags_frag,
        ttl, protocol, ip_csum,
        src_ip, dst_ip,
    )

    sport    = 1024 + (seq % 60000)
    dport    = 80
    tcp_seq  = seq * 1000
    tcp_ack  = 0
    data_off = 0x50
    flags    = 0x02
    window   = 65535
    tcp_checksum = 0
    urgent   = 0
    tcp = struct.pack(
        ">HHIIBBHHH",
        sport, dport, tcp_seq, tcp_ack,
        data_off, flags, window, tcp_checksum, urgent,
    )

    frame = eth + ip + tcp
    return frame


def write_pcap(filepath: str, num_packets: int):
    base_ts = int(time.time()) - num_packets

    with open(filepath, "wb") as f:
        f.write(PCAP_GLOBAL_HEADER)
        for i in range(num_packets):
            pkt = make_eth_ip_tcp_packet(i + 1)
            ts_sec  = base_ts + i
            ts_usec = random.randint(0, 999999)
            cap_len = orig_len = len(pkt)
            pkt_header = struct.pack("<IIII", ts_sec, ts_usec, cap_len, orig_len)
            f.write(pkt_header)
            f.write(pkt)


def main():
    pcap_specs = [
        ("PCAP01", 30),
        ("PCAP02", 50),
        ("PCAP03", 70),
        ("PCAP04", 90),
        ("PCAP05", 100),
    ]

    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
    os.makedirs(out_dir, exist_ok=True)

    for name, count in pcap_specs:
        filename = f"{name}_{STUDENT_ID}.pcap"
        filepath = os.path.join(out_dir, filename)
        write_pcap(filepath, count)
        size_kb = os.path.getsize(filepath) / 1024
        print(f"[OK] {filename}  ({count} packets, {size_kb:.1f} KB)")


if __name__ == "__main__":
    main()