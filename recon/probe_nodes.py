#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Thunder VPN 真实节点连通性探测 (TCP/UDP)"""
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

NODES = [
    ("51.38.114.253", "DE"), ("51.195.43.172", "DE"), ("51.195.47.52", "DE"),
    ("57.129.118.197", "DE"), ("51.195.235.194", "GB"), ("57.128.221.85", "PL"),
    ("107.189.10.67", "CH"), ("104.244.72.212", "CH"), ("104.244.77.124", "CH"),
    ("104.244.74.148", "CH"), ("5.34.179.83", "US"), ("5.34.179.131", "US"),
]
TCP_PORTS = [443, 465, 802]


def tcp_probe(ip, port, timeout=4.0):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return "open"
    except socket.timeout:
        return "timeout"
    except ConnectionRefusedError:
        return "refused"
    except OSError as e:
        return f"err:{e.errno}"
    finally:
        s.close()


def udp_probe(ip, port=443, timeout=3.0):
    """发送 20 字节随机负载，观察是否有回包"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(b"\x00" * 20, (ip, port))
        data, _ = s.recvfrom(2048)
        return f"resp:{len(data)}B"
    except socket.timeout:
        return "no-resp"
    except OSError as e:
        return f"err:{e.errno}"
    finally:
        s.close()


def one(node):
    ip, cc = node
    tcp = {p: tcp_probe(ip, p) for p in TCP_PORTS}
    udp = udp_probe(ip)
    return ip, cc, tcp, udp


def main():
    print(f"{'IP':<16}{'CC':<4}{'443':<10}{'465':<10}{'802':<10}UDP443")
    with ThreadPoolExecutor(max_workers=12) as ex:
        for ip, cc, tcp, udp in ex.map(one, NODES):
            print(f"{ip:<16}{cc:<4}{tcp[443]:<10}{tcp[465]:<10}{tcp[802]:<10}{udp}")


if __name__ == "__main__":
    main()
