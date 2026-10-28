#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""抓 native encode 的明文->密文对照 + 完整请求头 (frida 16.5.9)"""
import subprocess
import sys
import time

sys.path.insert(0, "pylibs")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import frida  # noqa: E402

ADB = r"C:\Users\Administrator.DESKTOP-EGNE9ND\Downloads\Compressed\platform-tools\adb.exe"
PKG = "com.fast.free.unblock.thunder.vpn"
PORT = 27400


def sh(*args, t=30):
    return subprocess.run([ADB, "-s", "emulator-5554", "shell", *args],
                          capture_output=True, timeout=t).stdout.decode(errors="replace")


JS = r"""
Java.perform(function () {
    var hex = function (b) {
        if (b === null) return null;
        var a = Java.array('byte', b), o = [];
        for (var i = 0; i < a.length && i < 400; i++) {
            var v = (a[i] & 0xff).toString(16);
            o.push(v.length === 1 ? "0" + v : v);
        }
        return o.join("");
    };
    var HC = Java.use("com.signallab.lib.utils.net.HttpClients");
    var OV = HC.request.overload("java.lang.String", "java.util.Map", "[B", "java.lang.String");
    OV.implementation = function (url, hdrs, body, ctype) {
        var hs = "null";
        try { hs = String(hdrs); } catch (e) { hs = "ERR"; }
        var plain = body === null ? null : hex(body);
        var r = OV.call(this, url, hdrs, body, ctype);
        var cipher = body === null ? null : hex(body);
        send({ t: "PAIR", url: String(url), hdr: hs, plain: plain, cipher: cipher,
               resp: r === null ? "null" : String(r).substring(0, 600) });
        return r;
    };
    send({ t: "log", m: "hooked frida16" });
});
"""


def main():
    print("[*] 起 fs1659 :27400", flush=True)
    sh("cd /data/local/tmp && (setsid ./fs1659 -l 0.0.0.0:27400 >/data/local/tmp/e.log 2>&1 </dev/null &)")
    time.sleep(4)
    subprocess.run([ADB, "-s", "emulator-5554", "forward", f"tcp:{PORT}", f"tcp:{PORT}"],
                   capture_output=True, timeout=20)
    dev = frida.get_device_manager().add_remote_device(f"127.0.0.1:{PORT}")
    print("[*] access:", dev.query_system_parameters().get("access"), flush=True)
    sh(f"pm clear {PKG}")
    time.sleep(1)
    sh(f"pm enable {PKG}")
    sh(f"pm enable --user 0 {PKG}")
    out = ""
    for _ in range(6):
        sh(f"pm enable {PKG}")
        sh(f"pm enable --user 0 {PKG}")
        sh(f"am start -n {PKG}/com.signallab.thunder.activity.SplashActivity")
        time.sleep(3)
        out = sh(f"pidof {PKG}").strip()
        if out:
            break
        print("[!] 未启动，重试", flush=True)
    if not out:
        print("[!] am start 输出:", sh(f"am start -n {PKG}/com.signallab.thunder.activity.SplashActivity"), flush=True)
        raise SystemExit("app 起不来")
    pid = int(out.split()[0])
    print(f"[*] attach pid={pid}", flush=True)
    session = dev.attach(pid)
    script = session.create_script(JS)

    def on_msg(msg, data):
        if msg["type"] != "send":
            print("[non-send]", str(msg)[:160], flush=True)
            return
        p = msg["payload"]
        t = p.pop("t", "?")
        if t == "PAIR":
            print(f"\n[[PAIR]] {p['url']}", flush=True)
            print(f"  hdr: {p['hdr']}", flush=True)
            print(f"  plain : {p['plain']}", flush=True)
            print(f"  cipher: {p['cipher']}", flush=True)
            print(f"  resp  : {p['resp']}", flush=True)
        else:
            print(f"[{t}] {p}", flush=True)

    script.on("message", on_msg)
    script.load()
    print("[*] resumed", flush=True)
    time.sleep(12)
    sh("input tap 537 1987")   # Accept ToS
    time.sleep(20)
    print("[*] done", flush=True)


if __name__ == "__main__":
    main()
