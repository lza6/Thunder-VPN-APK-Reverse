#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Thunder VPN (SignalLab) API 客户端 —— 逆向复刻版
=================================================
协议来源：静态分析 + frida 动态抓包（详见 逆向报告.md）

用法:
    python thunder_api.py register          # 注册设备，输出 auth_id/auth_token
    python thunder_api.py list              # 拉取节点列表
    python thunder_api.py probe             # 探测节点连通性
    python thunder_api.py harvest --rounds 5  # 多轮收割

要点:
  * 注册接口接受**明文 JSON**，无风控、无图形验证
  * 列表接口需 5 个 s-* 请求头，其中 s-req-token = md5(有序明文串)
  * ⚠️ 匿名/明文客户端只能拿到 169.254.x 兜底池（不可路由）
    真实公网节点池需 native 加密态（见报告 §5「待验证」）
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Any

import requests

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ---------------------------------------------------------------- 常量（逆向所得）
PKG = "com.fast.free.unblock.thunder.vpn"
VER_CODE = 202604131
VER_NAME = "5.4.1"
# md5(签名证书 DER)，由 frida hook SignalHelper.getMd5 实测得到
APP_SIGNATURE_MD5 = "0e172a34eae0258e55505b93c9e7c4d8"
API_HOSTS = [f"https://t{i}.free-signal.com/" for i in range(1, 7)]
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "state.json")

# ---------------------------------------------------------------- 会话
# 关键：必须绕过系统 HTTP_PROXY，否则出口 IP 变化会导致下发不同分组
SESSION = requests.Session()
SESSION.trust_env = False


# ---------------------------------------------------------------- 数据模型
@dataclass
class Device:
    auth_id: int
    auth_token: int
    dev_id: str
    created_at: float = field(default_factory=time.time)

    @property
    def alive_hours(self) -> float:
        return (time.time() - self.created_at) / 3600


@dataclass
class Node:
    ip: str
    country: str
    obs_key: str
    obs_algo: int
    is_vip: bool
    is_running: bool
    area: str = ""
    load: int = 0
    group: str = "0"
    # 探测结果
    tcp: dict[int, str] = field(default_factory=dict)
    udp443: str = ""
    latency_ms: int = -1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------- 签名
def build_headers(auth_id: int = 0, auth_token: int = 0) -> dict[str, str]:
    """复刻 m6.b.z() —— 5 个 s-* 请求头"""
    raw = (f"auth_id={auth_id}&auth_token={auth_token}"
           f"&app_package={PKG}&app_ver_code={VER_CODE}"
           f"&app_signature={APP_SIGNATURE_MD5}")
    return {
        "s-auth-id": str(auth_id),
        "s-auth-token": str(auth_token),
        "s-app-package": PKG,
        "s-app-ver-code": str(VER_CODE),
        "s-req-token": hashlib.md5(raw.encode()).hexdigest(),
    }


# ---------------------------------------------------------------- 状态持久化
def save_device(dev: Device) -> None:
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(asdict(dev), f)


def load_device() -> Device | None:
    if not os.path.exists(STATE_FILE):
        return None
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            d = json.load(f)
        return Device(**d)
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------- API
def register(host: str | None = None) -> Device:
    """设备注册 (POST /v2/device/) —— 明文 JSON 即可，返回 auth_id/auth_token"""
    body = {
        "dev_id": os.urandom(8).hex(),
        "dev_model": "sdk_gphone_x86_64_arm64",
        "dev_manufacturer": "Google",
        "dev_lang": "en_US",
        "dev_os": "Android 11",
        "dev_country": "us",
        "app_package": PKG,
        "app_ver_name": VER_NAME,
        "app_ver_code": VER_CODE,
        "dev_imsi": "310260",
    }
    last_err: Exception | None = None
    for base in ([host] if host else API_HOSTS):
        try:
            h = build_headers()
            h["Content-Type"] = "application/json; charset=utf-8"
            r = SESSION.post(base + "v2/device/", headers=h,
                             data=json.dumps(body).encode(), timeout=15)
            if r.status_code != 200:
                last_err = RuntimeError(f"{base} -> HTTP {r.status_code}: {r.text[:120]}")
                continue
            j = r.json()
            dev = Device(auth_id=int(j["auth_id"]), auth_token=int(j["auth_token"]),
                         dev_id=body["dev_id"])
            save_device(dev)
            return dev
        except Exception as e:  # noqa: BLE001
            last_err = e
    raise RuntimeError(f"注册失败: {last_err}")


def my_exit_ip(base: str) -> str | None:
    try:
        return SESSION.get(base + "ip/", timeout=10).text.strip().split("=", 1)[1]
    except Exception:  # noqa: BLE001
        return None


def fetch_servers(dev: Device | None = None, imsi: str = "310260",
                  lang: str = "en_US") -> dict[str, Any]:
    """拉取节点列表 (GET /v2/server/) —— 响应为明文 JSON"""
    dev = dev or load_device()
    aid = dev.auth_id if dev else 0
    atok = dev.auth_token if dev else 0
    out: dict[str, Any] = {"nodes": [], "config": {}, "list": "", "exit_ip": None,
                           "host": None, "raw": None}
    for base in API_HOSTS:
        ip = my_exit_ip(base)
        if not ip:
            continue
        q = f"v2/server/?dev_imsi={imsi}&dev_lang={lang}&isp_ip={ip}"
        try:
            r = SESSION.get(base + q, headers=build_headers(aid, atok), timeout=15)
            if r.status_code != 200:
                continue
            j = r.json()
        except Exception:  # noqa: BLE001
            continue
        nodes = []
        for grp, key in (("0", "server"), ("vip", "vip"), ("video", "video"), ("ext", "ext")):
            sec = j.get(key)
            arr = sec.get("server") if isinstance(sec, dict) else sec
            for s in (arr or []):
                nodes.append(Node(
                    ip=s.get("ip", ""), country=s.get("country", ""),
                    obs_key=s.get("obs_key", ""), obs_algo=int(s.get("obs_algo", 0)),
                    is_vip=bool(s.get("is_vip", key == "vip")),
                    is_running=bool(s.get("is_running", True)),
                    area=s.get("area", ""), load=int(s.get("load", 0)), group=grp,
                ))
        cfg = j.get("config") or (j.get("vip") or {}).get("config") or {}
        out.update(nodes=nodes, config=cfg, list=j.get("list", ""),
                   exit_ip=ip, host=base, raw=j)
        return out
    return out


# ---------------------------------------------------------------- 探测
def tcp_probe(ip: str, port: int, timeout: float = 4.0) -> tuple[str, int]:
    t0 = time.time()
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return "open", int((time.time() - t0) * 1000)
    except socket.timeout:
        return "timeout", -1
    except ConnectionRefusedError:
        return "refused", -1
    except OSError as e:
        return f"err{e.errno}", -1
    finally:
        s.close()


def udp_probe(ip: str, port: int = 443, timeout: float = 3.0) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(b"\x00" * 20, (ip, port))
        d, _ = s.recvfrom(2048)
        return f"resp:{len(d)}B"
    except socket.timeout:
        return "no-resp"
    except OSError as e:
        return f"err{e.errno}"
    finally:
        s.close()


def probe_node(node: Node, ports: list[int] = (443, 465, 802)) -> Node:
    for p in ports:
        st, ms = tcp_probe(node.ip, p)
        node.tcp[p] = st
        if p == 443 and st == "open":
            node.latency_ms = ms
    node.udp443 = udp_probe(node.ip)
    return node


def probe_nodes(nodes: list[Node], workers: int = 16) -> list[Node]:
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(probe_node, nodes))


# ---------------------------------------------------------------- CLI
def cmd_register(args: argparse.Namespace) -> None:
    dev = register()
    print(json.dumps(asdict(dev), indent=2))


def cmd_list(args: argparse.Namespace) -> None:
    res = fetch_servers()
    nodes: list[Node] = res["nodes"]
    print(f"网关     : {res['host']}")
    print(f"出口 IP  : {res['exit_ip']}")
    print(f"分组 list: {res['list']}   config={res['config']}")
    print(f"节点数   : {len(nodes)}")
    print(f"{'IP':<17}{'CC':<5}{'algo':<6}{'vip':<6}{'run':<6}obs_key")
    for n in nodes:
        print(f"{n.ip:<17}{n.country:<5}{n.obs_algo:<6}{str(n.is_vip):<6}{str(n.is_running):<6}{n.obs_key}")
    if args.json:
        with open("nodes.json", "w", encoding="utf-8") as f:
            json.dump([n.to_dict() for n in nodes], f, ensure_ascii=False, indent=1)
        print("\n-> nodes.json")


def cmd_probe(args: argparse.Namespace) -> None:
    if os.path.exists("nodes.json"):
        with open("nodes.json", encoding="utf-8") as f:
            nodes = [Node(**d) for d in json.load(f)]
    else:
        nodes = fetch_servers()["nodes"]
    t0 = time.time()
    nodes = probe_nodes(nodes)
    print(f"{'IP':<17}{'CC':<5}{'443':<10}{'465':<10}{'802':<10}{'UDP443':<10}latency")
    ok = 0
    for n in nodes:
        if n.tcp.get(443) == "open":
            ok += 1
        print(f"{n.ip:<17}{n.country:<5}{n.tcp.get(443,''):<10}{n.tcp.get(465,''):<10}"
              f"{n.tcp.get(802,''):<10}{n.udp443:<10}{n.latency_ms if n.latency_ms >= 0 else '-'}")
    print(f"\n可用(443 open): {ok}/{len(nodes)}   耗时 {time.time() - t0:.1f}s")


def cmd_harvest(args: argparse.Namespace) -> None:
    seen: dict[str, Node] = {}
    for i in range(args.rounds):
        res = fetch_servers()
        for n in res["nodes"]:
            seen.setdefault(n.ip, n)
        print(f"[{i + 1}/{args.rounds}] 新增 {len(res['nodes'])} 条, 累计唯一 {len(seen)}")
        time.sleep(args.interval)
    with open("nodes_harvest.json", "w", encoding="utf-8") as f:
        json.dump([n.to_dict() for n in seen.values()], f, ensure_ascii=False, indent=1)
    print(f"\n-> nodes_harvest.json ({len(seen)} 唯一节点)")


def main() -> None:
    ap = argparse.ArgumentParser(description="Thunder VPN API 客户端")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("register", help="注册设备").set_defaults(func=cmd_register)
    p_list = sub.add_parser("list", help="拉取节点列表")
    p_list.add_argument("--json", action="store_true", help="同时导出 nodes.json")
    p_list.set_defaults(func=cmd_list)
    sub.add_parser("probe", help="探测节点连通性").set_defaults(func=cmd_probe)
    p_h = sub.add_parser("harvest", help="多轮收割去重")
    p_h.add_argument("--rounds", type=int, default=5)
    p_h.add_argument("--interval", type=float, default=3.0)
    p_h.set_defaults(func=cmd_harvest)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
