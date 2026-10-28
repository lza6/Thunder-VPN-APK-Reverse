#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""抓取 App 完整真实节点列表（frida 16.5.9, attach 模式）"""
import json
import subprocess
import sys
import time

sys.path.insert(0, "pylibs")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import frida  # noqa: E402

ADB = r"C:\Users\Administrator.DESKTOP-EGNE9ND\Downloads\Compressed\platform-tools\adb.exe"
PKG = "com.fast.free.unblock.thunder.vpn"
PORT = 27400

JS = r"""
Java.perform(function () {
    var HC = Java.use("com.signallab.lib.utils.net.HttpClients");
    var OV = HC.request.overload("java.lang.String", "java.util.Map", "[B", "java.lang.String");
    OV.implementation = function (url, hdrs, body, ctype) {
        var r = OV.call(this, url, hdrs, body, ctype);
        var u = String(url), s = r === null ? "" : String(r);
        if (u.indexOf("v2/server") >= 0) {
            send({ t: "SERVERLIST", url: u, body: s });
        } else {
            send({ t: "OTHER", url: u, len: s.length });
        }
        return r;
    };
    send({ t: "log", m: "hooked" });
});
"""


def sh(*a, t=40):
    return subprocess.run([ADB, "-s", "emulator-5554", "shell", *a],
                          capture_output=True, timeout=t).stdout.decode(errors="replace")


def main():
    sh("setenforce 0")
    sh("cd /data/local/tmp && (setsid ./fs1659 -l 0.0.0.0:27400 >/data/local/tmp/g.log 2>&1 </dev/null &)")
    time.sleep(4)
    subprocess.run([ADB, "-s", "emulator-5554", "forward", f"tcp:{PORT}", f"tcp:{PORT}"],
                   capture_output=True, timeout=20)
    dev = frida.get_device_manager().add_remote_device(f"127.0.0.1:{PORT}")
    print("[*] access:", dev.query_system_parameters().get("access"), flush=True)

    # 删掉 native 加密的节点缓存，强制 App 重新请求（保留 ToS/设备态，避免 pm clear 的 disable 问题）
    sh("rm -f /data/data/com.fast.free.unblock.thunder.vpn/files/cache_original_v2 "
       "/data/data/com.fast.free.unblock.thunder.vpn/files/cache_morph_v2")
    sh(f"am force-stop {PKG}")
    sh(f"pm clear {PKG}")
    time.sleep(3)
    sh(f"pm enable {PKG}")
    sh(f"pm enable --user 0 {PKG}")
    time.sleep(2)
    print("[*] 数据已清空（走全新注册流程）", flush=True)
    for _ in range(10):
        time.sleep(1)
        sh(f"pm enable {PKG}")
        sh(f"pm enable --user 0 {PKG}")
        sh(f"am start -n {PKG}/com.signallab.thunder.activity.SplashActivity")
        time.sleep(3)
        pid = sh(f"pidof {PKG}").strip()
        if pid:
            break
    if not pid:
        raise SystemExit("app 起不来")
    pid = int(pid.split()[0])
    print(f"[*] pid={pid}", flush=True)

    session = dev.attach(pid)
    script = session.create_script(JS)
    got = {}

    def on_msg(msg, data):
        if msg["type"] != "send":
            print("[non-send]", str(msg)[:120], flush=True)
            return
        p = msg["payload"]
        t = p.get("t")
        if t == "SERVERLIST":
            got["url"] = p["url"]
            got["body"] = p["body"]
            print(f"[*] 抓到节点列表 {len(p['body'])} 字节", flush=True)
        elif t == "OTHER":
            print(f"    [http] {p['url']} len={p['len']}", flush=True)
        else:
            print(f"[{t}] {p}", flush=True)

    script.on("message", on_msg)
    script.load()
    print("[*] attach 完成，推进 UI", flush=True)

    import re
    def click_text(txts):
        sh("uiautomator dump /sdcard/u.xml >/dev/null 2>&1")
        x = sh("cat /sdcard/u.xml")
        for m in re.finditer(r'text="([^"]*)"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', x):
            t, x1, y1, x2, y2 = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))
            if t.strip() in txts:
                cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
                print(f"    [tap] {t!r} -> ({cx},{cy})", flush=True)
                sh(f"input tap {cx} {cy}")
                return True
        return False

    for i in range(18):
        if got:
            break
        sh("uiautomator dump /sdcard/u.xml >/dev/null 2>&1")
        x = sh("cat /sdcard/u.xml")
        texts = [m.group(1) for m in re.finditer(r'text="([^"]{2,40})"', x)][:6]
        print(f"    [ui{i+1}] {texts}", flush=True)
        if not click_text(["Accept", "CONNECT", "DISMISS", "RETRY"]):
            pass
        time.sleep(5)
    time.sleep(6)

    if got:
        with open("recon/full_serverlist.json", "w", encoding="utf-8") as f:
            json.dump(got, f, ensure_ascii=False, indent=1)
        # 合并进长期节点池（按 IP 去重，保留历史）
        import os, datetime
        pool_path = "data/real_nodes_full.json"
        pool = {"meta": {}, "nodes": []}
        if os.path.exists(pool_path):
            try:
                pool = json.load(open(pool_path, encoding="utf-8"))
            except Exception:  # noqa: BLE001
                pass
        idx = {n["ip"]: n for n in pool.get("nodes", [])}
        try:
            jj = json.loads(got["body"])
            add = 0
            for grp, key in (("free", "server"), ("vip", "vip")):
                sec = jj.get(key)
                arr = sec.get("server") if isinstance(sec, dict) else sec
                for s2 in (arr or []):
                    s3 = dict(s2)
                    s3["group"] = grp
                    s3["seen_at"] = datetime.datetime.now().isoformat(timespec="seconds")
                    if s3["ip"] not in idx:
                        add += 1
                    idx[s3["ip"]] = s3
            pool["meta"] = {"captured_at": datetime.datetime.now().isoformat(timespec="seconds"),
                            "list": jj.get("list"), "config": jj.get("config"),
                            "url": got["url"], "source": "frida hook App 实际响应"}
            pool["nodes"] = list(idx.values())
            json.dump(pool, open(pool_path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
            print(f"[+] 池已更新: +{add} 新增, 共 {len(pool['nodes'])} 节点 -> {pool_path}", flush=True)
        except Exception as e:  # noqa: BLE001
            print("[!] 池合并失败", e, flush=True)
        try:
            d = json.loads(got["body"])
            free = [s for s in (d.get("server") or []) if not s.get("is_vip")]
            vip = [s for s in (d.get("vip") or {}).get("server") or []]
            print(f"[+] 免费 {len(free)} / VIP {len(vip)} / list={d.get('list')}")
            for s in free + vip:
                print(f"    {s['ip']:<16}{s.get('country',''):<4}algo={s.get('obs_algo')} "
                      f"vip={s.get('is_vip')} {s.get('obs_key')}")
        except Exception as e:  # noqa: BLE001
            print("[!] 解析失败", e, flush=True)
    else:
        print("[!] 未抓到，可能仍在 ToS/加载中", flush=True)


if __name__ == "__main__":
    main()
