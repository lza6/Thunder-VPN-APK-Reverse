#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Thunder VPN 节点压测 —— TCP 端口存活率 / 延迟分布 / 轮次稳定性

只做 TCP 三次握手抽样，不发送任何应用层载荷，不构成对服务端的攻击。
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, ".")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import thunder_api as api  # noqa: E402

PORTS = [443, 465, 802]


def one(ip: str, port: int, timeout: float) -> tuple[str, int, str]:
    st, ms = api.tcp_probe(ip, port, timeout=timeout)
    return ip, port, st if st == "open" else f"{st}|{ms}"


def run_round(nodes: list[str], timeout: float, workers: int) -> dict:
    """单轮：所有节点 × 所有端口并发探测"""
    t0 = time.time()
    jobs = [(ip, p) for ip in nodes for p in PORTS]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(api.tcp_probe, ip, p, timeout) for ip, p in jobs]
        results = []
        for (ip, p), f in zip(jobs, futs):
            st, ms = f.result()
            results.append((ip, p, st, ms))
    elapsed = time.time() - t0
    per = {}
    for ip, p, st, ms in results:
        per.setdefault(ip, {})[p] = {"st": st, "ms": ms}
    return {"elapsed": round(elapsed, 2), "per": per}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--interval", type=float, default=2.0, help="轮间隔秒")
    ap.add_argument("--timeout", type=float, default=4.0)
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--nodes", default=None, help="逗号分隔 IP，默认取 data/real_nodes.json")
    ap.add_argument("--out", default="stress_report.json")
    a = ap.parse_args()

    if a.nodes:
        nodes = [x.strip() for x in a.nodes.split(",") if x.strip()]
    else:
        import os
        if os.path.exists("data/real_nodes_full.json"):
            with open("data/real_nodes_full.json", encoding="utf-8") as f:
                nodes = [n["ip"] for n in json.load(f)["nodes"]]
        else:
            with open("data/real_nodes.json", encoding="utf-8") as f:
                snap = json.load(f)
            nodes = [n["ip"] for n in snap["free"] + snap["vip_partial"]]

    print(f"[*] 目标 {len(nodes)} 节点 × {len(PORTS)} 端口 × {a.rounds} 轮 "
          f"(并发 {a.workers}, 超时 {a.timeout}s)\n", flush=True)

    stats: dict[str, dict[int, list[int]]] = {ip: {p: [] for p in PORTS} for ip in nodes}
    fail: dict[str, dict[int, int]] = {ip: {p: 0 for p in PORTS} for ip in nodes}
    rounds = []

    for r in range(a.rounds):
        res = run_round(nodes, a.timeout, a.workers)
        rounds.append(res)
        for ip, pd in res["per"].items():
            for p, v in pd.items():
                if v["st"] == "open":
                    stats[ip][p].append(v["ms"])
                else:
                    fail[ip][p] += 1
        ok = sum(1 for ip in nodes for p in PORTS if res["per"][ip][p]["st"] == "open")
        print(f"[轮 {r + 1}/{a.rounds}] {res['elapsed']}s  "
              f"open {ok}/{len(nodes) * len(PORTS)}", flush=True)
        if r + 1 < a.rounds:
            time.sleep(a.interval)

    print(f"\n{'IP':<17}{'443 成功率':<12}{'443 中位':<10}{'465':<8}{'802':<8}{'综合'}")
    total_open = total_try = 0
    summary = {}
    for ip in nodes:
        cells, okn, tryn = [], 0, 0
        for p in PORTS:
            got = len(stats[ip][p])
            tryn += a.rounds
            okn += got
            cells.append(f"{got}/{a.rounds}")
        total_open += okn
        total_try += tryn
        med = (f"{int(statistics.median(stats[ip][443]))}ms"
               if stats[ip][443] else "-")
        rate = okn / tryn * 100
        summary[ip] = {
            "port": {str(p): {"ok": len(stats[ip][p]), "tries": a.rounds,
                              "median_ms": int(statistics.median(stats[ip][p])) if stats[ip][p] else None}
                     for p in PORTS},
            "overall_rate": round(rate, 1),
        }
        print(f"{ip:<17}{cells[0]:<12}{med:<10}{cells[1]:<8}{cells[2]:<8}{rate:.0f}%")

    print(f"\n总成功率 {total_open}/{total_try} = {total_open / total_try * 100:.1f}%")
    report = {"rounds": a.rounds, "nodes": nodes, "ports": PORTS,
              "overall": round(total_open / total_try * 100, 1), "summary": summary,
              "per_round": rounds}
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)
    print(f"-> {a.out}")


if __name__ == "__main__":
    main()
