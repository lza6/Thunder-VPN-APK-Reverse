#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Thunder VPN 节点池 Demo 面板 (标准库实现，零额外依赖)

启动: python demo_server.py [--port 8951]
访问: http://127.0.0.1:8951/
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import thunder_api as api  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SNAPSHOT = os.path.join(HERE, "data", "real_nodes_full.json")
SNAPSHOT_LEGACY = os.path.join(HERE, "data", "real_nodes.json")
STARTED_AT = time.time()


def load_snapshot() -> dict:
    """优先返回全量抓包快照，统一成 {meta, nodes} 结构"""
    if os.path.exists(SNAPSHOT):
        with open(SNAPSHOT, encoding="utf-8") as f:
            d = json.load(f)
        if "nodes" in d:
            return d
    with open(SNAPSHOT_LEGACY, encoding="utf-8") as f:
        d = json.load(f)
    nodes = d["free"] + d["vip_partial"]
    return {"meta": {"captured_at": d["meta"]["captured_at"],
                     "list": d["meta"].get("list_tag"),
                     "config": d["meta"].get("config")}, "nodes": nodes}


class Handler(BaseHTTPRequestHandler):
    server_version = "ThunderDemo/1.0"

    # ---------------- helpers
    def _json(self, obj: dict, code: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, path: str) -> None:
        try:
            with open(path, encoding="utf-8") as f:
                body = f.read().encode()
        except FileNotFoundError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:  # 静音
        return

    # ---------------- routes
    def do_GET(self) -> None:
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            self._html(os.path.join(HERE, "demo.html"))
        elif u.path == "/api/state":
            dev = api.load_device()
            self._json({
                "uptime_s": int(time.time() - STARTED_AT),
                "device": {
                    "auth_id": dev.auth_id,
                    "auth_token": dev.auth_token,
                    "dev_id": dev.dev_id,
                    "alive_hours": round(dev.alive_hours, 2),
                } if dev else None,
                "signature": api.APP_SIGNATURE_MD5,
                "hosts": api.API_HOSTS,
            })
        elif u.path == "/api/snapshot":
            self._json(load_snapshot())
        elif u.path == "/api/servers":
            try:
                res = api.fetch_servers()
                self._json({
                    "ok": True,
                    "host": res["host"],
                    "exit_ip": res["exit_ip"],
                    "list": res["list"],
                    "config": res["config"],
                    "nodes": [n.to_dict() for n in res["nodes"]],
                })
            except Exception as e:  # noqa: BLE001
                self._json({"ok": False, "error": f"{type(e).__name__}: {e}"}, 500)
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            payload = json.loads(raw or b"{}")
        except Exception:  # noqa: BLE001
            payload = {}

        if u.path == "/api/register":
            try:
                dev = api.register()
                self._json({"ok": True, "auth_id": dev.auth_id,
                            "auth_token": dev.auth_token, "dev_id": dev.dev_id})
            except Exception as e:  # noqa: BLE001
                self._json({"ok": False, "error": f"{type(e).__name__}: {e}"}, 500)
        elif u.path == "/api/probe":
            ips = payload.get("ips") or []
            try:
                nodes = []
                if ips:
                    snap = load_snapshot()
                    idx = {x["ip"]: x for x in snap["nodes"]}
                    for ip in ips:
                        if ip in idx:
                            d = idx[ip]
                            nodes.append(api.Node(ip=d["ip"], country=d["country"],
                                                  obs_key=d["obs_key"],
                                                  obs_algo=d.get("obs_algo", 0),
                                                  is_vip=d.get("is_vip", False),
                                                  is_running=True, area=d.get("area", "")))
                else:
                    nodes = api.fetch_servers()["nodes"]
                t0 = time.time()
                nodes = api.probe_nodes(nodes)
                self._json({"ok": True, "elapsed": round(time.time() - t0, 2),
                            "nodes": [n.to_dict() for n in nodes]})
            except Exception as e:  # noqa: BLE001
                self._json({"ok": False, "error": f"{type(e).__name__}: {e}"}, 500)
        else:
            self.send_error(404)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8951)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    print(f"[*] Thunder VPN Demo -> http://{a.host}:{a.port}/", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] bye")


if __name__ == "__main__":
    main()
