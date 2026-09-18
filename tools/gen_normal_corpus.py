#!/usr/bin/env python3
"""生成 tcpdump 样本 TC-001 的正常输入语料（纯标准库，确定性）。

用于采集侧采集正常基线 trace。语料包含多样的良性报文
（UDP/TCP/ICMP，不同端口、长度、内容形态），不含触发 magic
"CFIBENCH1"，确保不会触发注入漏洞。

用法:
  ./gen_normal_corpus.py --out ../../build/tcpdump-cfi-bench/normal-corpus \
                         --files 20 --packets 50 --seed 42
"""
import argparse
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

MAGIC = b"CFIBENCH1"  # 触发门控，语料中必须避免


def ipv4_checksum(hdr: bytes) -> int:
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) | hdr[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def eth_ip(proto: int, src: bytes, dst: bytes, payload: bytes) -> bytes:
    eth = bytes.fromhex("001122334455") + bytes.fromhex("66778899aabb") + b"\x08\x00"
    total = 20 + len(payload)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack(">H", ipv4_checksum(ip)) + ip[12:]
    return eth + ip + payload


def udp_packet(rng: random.Random) -> bytes:
    payload_pool = [
        bytes(rng.randrange(256) for _ in range(rng.choice([8, 16, 64, 128]))),
        b"GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n"[:rng.choice([20, 40, 54])],
        b"hello world " * rng.choice([1, 2, 4]),
        b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # DNS 查询形态
    ]
    payload = rng.choice(payload_pool)
    while payload[:9] == MAGIC[:9] and len(payload) >= 9:  # 避免触发前缀
        payload = payload[1:] + bytes([rng.randrange(256)])
    sport = rng.randint(1024, 65535)
    dport = rng.choice([53, 123, 161, 514, 1900, 5060, 11211, rng.randint(1024, 65535)])
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    return eth_ip(17, bytes([10, 0, 0, rng.randint(1, 254)]),
                  bytes([10, 0, 0, rng.randint(1, 254)]), udp)


def tcp_packet(rng: random.Random) -> bytes:
    sport, dport = rng.randint(1024, 65535), rng.choice([80, 443, 22, rng.randint(1024, 65535)])
    seq, ack = rng.getrandbits(32), rng.getrandbits(32)
    flags = rng.choice([0x02, 0x12, 0x10, 0x18])  # SYN/SYN-ACK/ACK/PSH-ACK
    payload = b"" if flags != 0x18 else b"payload-" + str(rng.getrandbits(16)).encode()
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 8192, 0, 0)
    tcp += payload
    return eth_ip(6, bytes([10, 0, 0, rng.randint(1, 254)]),
                  bytes([10, 0, 0, rng.randint(1, 254)]), tcp)


def icmp_packet(rng: random.Random) -> bytes:
    body = b"normal-icmp-payload-" * rng.choice([1, 2, 4])
    icmp = struct.pack(">BBHHH", 8, 0, 0, rng.randint(1, 65535), 1) + body
    icmp = icmp[:2] + struct.pack(">H", ipv4_checksum(icmp)) + icmp[4:]
    return eth_ip(1, bytes([10, 0, 0, rng.randint(1, 254)]),
                  bytes([10, 0, 0, rng.randint(1, 254)]), icmp)


def write_pcap(path: Path, packets: list[bytes]) -> None:
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, pkt in enumerate(packets):
            f.write(struct.pack("<IIII", 1700000000 + i, i % 1000000, len(pkt), len(pkt)))
            f.write(pkt)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True)
    ap.add_argument("--files", type=int, default=20)
    ap.add_argument("--packets", type=int, default=50)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    manifest = []
    for fi in range(args.files):
        rng = random.Random(args.seed * 1000 + fi)
        packets = []
        for _ in range(args.packets):
            packets.append(rng.choice([udp_packet, tcp_packet, icmp_packet])(rng))
        path = out / f"normal_{fi:03d}.pcap"
        write_pcap(path, packets)
        manifest.append({
            "file": path.name,
            "packets": len(packets),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"[+] {args.files} 个正常语料文件 -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
