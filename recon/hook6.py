#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""精确 dump 请求头 + 完整响应"""
import subprocess
import sys
import time

import frida

sys.path.insert(0, "recon")
import fsutil

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ADB = r"C:\Users\Administrator.DESKTOP-EGNE9ND\Downloads\Compressed\platform-tools\adb.exe"
PKG = "com.fast.free.unblock.thunder.vpn"

JS = r"""
Java.perform(function () {
    var HC = Java.use("com.signallab.lib.utils.net.HttpClients");
    var OV = HC.request.overload("java.lang.String", "java.util.Map", "[B", "java.lang.String");
    OV.implementation = function (url, hdrs, body, ctype) {
        var hs = "null";
        try { hs = String(hdrs); } catch (e) { hs = "str-err:" + e; }
        send({ t: "REQ", url: String(url), hdr: hs, ct: String(ctype) });
        var r = OV.call(this, url, hdrs, body, ctype);
        var rs = r === null ? "null" : String(r);
        send({ t: "RESP", url: String(url), len: rs.length, body: rs.substring(0, 1200) });
        return r;
    };
    send({ t: "log", m: "hooked" });
});
"""


def adb(*args):
    return subprocess.run([ADB, "-s", "emulator-5554", "shell", *args],
                          capture_output=True, timeout=30)


def main():
    dev = fsutil.ensure()
    pid, dev = fsutil.spawn_retry(dev, PKG)
    print(f"[*] spawned {pid}", flush=True)
    session = dev.attach(pid)
    script = session.create_script(JS)

    def on_msg(msg, data):
        if msg["type"] != "send":
            return
        p = msg["payload"]
        t = p.pop("t", "?")
        print(f"\n===== {t} =====", flush=True)
        for k, v in p.items():
            print(f"{k}: {v}", flush=True)

    script.on("message", on_msg)
    script.load()
    dev.resume(pid)
    for d in (12, 20, 30):
        time.sleep(8 if d == 12 else 8)
        adb("input", "tap", "537", "1987")
    time.sleep(40)
    print("[*] done", flush=True)


if __name__ == "__main__":
    main()
