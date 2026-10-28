#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Thunder VPN 最终侦察：完整请求头 + connect 参数 + 真实远端 IP"""
import subprocess
import sys
import time

sys.path.insert(0, "recon")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import fsutil  # noqa: E402

ADB = fsutil.ADB
PKG = "com.fast.free.unblock.thunder.vpn"
THUNDER_MAIN = f"{PKG}/com.signallab.thunder.activity.MainActivity"

JS = r"""
Java.perform(function () {
    var HC = Java.use("com.signallab.lib.utils.net.HttpClients");
    var OV = HC.request.overload("java.lang.String", "java.util.Map", "[B", "java.lang.String");
    OV.implementation = function (url, hdrs, body, ctype) {
        var hs = "null";
        try {
            hs = JSON.stringify(Java.use("java.util.HashMap").$new(hdrs).toString());
        } catch (e1) {
            try { hs = String(hdrs); } catch (e2) { hs = "ERR"; }
        }
        send({ t: "REQ", url: String(url), hdr: hs });
        var r = OV.call(this, url, hdrs, body, ctype);
        var rs = r === null ? "null" : String(r);
        send({ t: "RESP", url: String(url), len: rs.length, head: rs.substring(0, 900) });
        return r;
    };
    send({ t: "log", m: "http hooked" });

    var SH = Java.use("com.signallab.lib.SignalHelper");
    SH.connect.implementation = function (fd, host, udp, tcp, uid, tok, key, bt, algo) {
        var f = function (a) {
            if (a === null) return "null";
            var o = []; for (var i = 0; i < a.length; i++) o.push(a[i]); return o.join(",");
        };
        send({ t: "CONNECT", host: String(host), udp: f(udp), tcp: f(tcp),
               uid: String(uid), tok: String(tok), key: String(key), bt: String(bt), algo: String(algo) });
        return SH.connect.call(this, fd, host, udp, tcp, uid, tok, key, bt, algo);
    };
    send({ t: "log", m: "connect hooked" });
});
"""


def sh(*args):
    return subprocess.run([ADB, "-s", "emulator-5554", "shell", *args],
                          capture_output=True, timeout=30).stdout.decode(errors="replace")


def top():
    out = sh("dumpsys activity activities | grep mResumedActivity")
    for tok in out.split():
        if "/" in tok and "." in tok:
            return tok.strip()
    return "?"


def main():
    dev = fsutil.ensure()
    pid, dev = fsutil.spawn_retry(dev, PKG)
    print(f"[*] spawned {pid}", flush=True)
    session = dev.attach(pid)
    script = session.create_script(JS)

    def on_msg(msg, data):
        if msg["type"] != "send":
            print("[non-send]", str(msg)[:200], flush=True)
            return
        p = msg["payload"]
        t = p.pop("t", "?")
        if t == "REQ":
            print(f"\n[REQ] {p['url']}\n  hdr: {p.get('hdr')}", flush=True)
        elif t == "RESP":
            print(f"[RESP] len={p.get('len')} {p.get('head','')[:400]}", flush=True)
        else:
            print(f"[{t}] " + " | ".join(f"{k}={v}" for k, v in p.items()), flush=True)

    script.on("message", on_msg)
    script.load()
    dev.resume(pid)
    print("[*] resumed", flush=True)

    # 推进 UI: 等首页 -> DISMISS 弹窗 -> CONNECT -> 授权
    time.sleep(10)
    for attempt in range(8):
        t = top()
        print(f"[*] {attempt} top={t}", flush=True)
        if "vpndialogs" in t:
            sh("input tap 800 1330")
            time.sleep(3)
            continue
        if PKG not in t:
            sh(f"am start -n {THUNDER_MAIN}")
            time.sleep(4)
            continue
        sh("input tap 319 1622")   # DISMISS 弹窗（若有）
        time.sleep(1)
        sh("input tap 537 2040")   # CONNECT
        time.sleep(4)

    print("[*] 观察连接", flush=True)
    for _ in range(6):
        out = sh("cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '$4==\"01\"{print $3}' | head -12")
        print("[tcp-est]", out.replace("\n", " "), flush=True)
        iface = sh("ip addr show tun0 2>/dev/null | head -4")
        if iface.strip():
            print("[tun0]", iface.strip(), flush=True)
        time.sleep(4)
    print("[*] done", flush=True)


if __name__ == "__main__":
    main()
