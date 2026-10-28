#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Thunder VPN: 抓设备注册报文（body 明文 + 解密后响应）"""
import subprocess
import sys
import time

import frida

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

PKG = "com.fast.free.unblock.thunder.vpn"
ADB = r"C:\Users\Administrator.DESKTOP-EGNE9ND\Downloads\Compressed\platform-tools\adb.exe"

JS = r"""
Java.perform(function () {
    var b2s = function (b) {
        try {
            var J = Java.array('byte', b);
            var out = [];
            for (var i = 0; i < J.length && i < 4000; i++) out.push(J[i]);
            var s = "";
            for (var j = 0; j < out.length; j++) {
                var c = out[j] & 0xff;
                s += (c >= 32 && c < 127) ? String.fromCharCode(c) : ".";
            }
            return s;
        } catch (e) { return "b2s-err:" + e; }
    };
    var HC = Java.use("com.signallab.lib.utils.net.HttpClients");
    var OV = HC.request.overload("java.lang.String", "java.util.Map", "[B", "java.lang.String");
    OV.implementation = function (url, hdrs, body, ctype) {
        var h = "null";
        try { h = String(hdrs); } catch (e) { h = "ERR:" + e; }
        send({ t: "REQ", url: String(url), hdr: h, body: body === null ? "" : b2s(body) });
        var r = OV.call(this, url, hdrs, body, ctype);
        send({ t: "RESP", url: String(url), body: r === null ? "null" : String(r) });
        return r;
    };
    send({ t: "log", m: "[ok] hooked" });
});
"""


def adb(*args):
    return subprocess.run([ADB, "-s", "emulator-5554", "shell", *args],
                          capture_output=True, timeout=30)


def probe():
    try:
        d = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
        return d.query_system_parameters().get("access") == "full"
    except Exception:  # noqa: BLE001
        return False


def restart_frida():
    """确保 frida-server 以 full 权限在 27042 监听"""
    subprocess.run([ADB, "-s", "emulator-5554", "forward", "tcp:27042", "tcp:27042"],
                   capture_output=True, timeout=20)
    if probe():
        print("[*] frida-server alive (full)", flush=True)
        return
    for attempt in range(4):
        adb("setenforce", "0")
        adb("pkill", "-f", "fs1659")
        time.sleep(2)
        adb("cd /data/local/tmp && (setsid ./fs1659 -l 0.0.0.0:27042 >/data/local/tmp/fsz.log 2>&1 < /dev/null &)")
        for _ in range(10):
            time.sleep(2)
            if probe():
                print(f"[*] frida-server up (attempt {attempt + 1})", flush=True)
                return
    raise SystemExit("frida-server 起不来")


def main():
    restart_frida()
    print("[*] frida-server restarted", flush=True)
    print("[*] pm clear", flush=True)
    adb("pm", "clear", PKG)
    time.sleep(1)
    dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
    pid = None
    for attempt in range(4):
        try:
            pid = dev.spawn([PKG])
            break
        except Exception as e:  # noqa: BLE001
            print(f"[!] spawn 失败({attempt + 1}): {e}", flush=True)
            restart_frida()
            dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
            time.sleep(2)
    if pid is None:
        raise SystemExit("spawn 失败")
    print(f"[*] spawned {pid}", flush=True)
    session = dev.attach(pid)
    script = session.create_script(JS)

    def on_msg(msg, data):
        if msg["type"] != "send":
            print("[non-send]", str(msg)[:200], flush=True)
            return
        p = msg["payload"]
        t = p.pop("t", "?")
        print(f"\n===== {t} =====", flush=True)
        for k, v in p.items():
            print(f"{k}: {v}", flush=True)

    script.on("message", on_msg)
    script.load()
    dev.resume(pid)
    for i, d in enumerate([20, 26, 32, 40]):
        time.sleep(d - (0 if i == 0 else [20, 26, 32, 40][i - 1]))
        adb("input", "tap", "537", "1987")
        r = adb("dumpsys activity activities | grep -o 'com.signallab.thunder.activity.[A-Za-z]*' | head -1")
        print(f"[*] tap#{i+1} top={r.stdout.decode(errors='replace').strip()}", flush=True)
    time.sleep(40)
    print("[*] done", flush=True)


if __name__ == "__main__":
    main()
