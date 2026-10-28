#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Thunder VPN: spawn + 自动推进 UI + 全量 hook"""
import subprocess
import sys
import time

import frida

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

PKG = "com.fast.free.unblock.thunder.vpn"
ADB = r"C:\Users\Administrator.DESKTOP-EGNE9ND\Downloads\Compressed\platform-tools\adb.exe"


def adb(*args):
    subprocess.run([ADB, "-s", "emulator-5554", "shell", *args],
                   capture_output=True, timeout=30)


JS = r"""
Java.perform(function () {
    var log = function (s) { send({ t: "log", m: String(s) }); };
    function arr(a) {
        if (a === null) return "null";
        var s = []; for (var i = 0; i < a.length; i++) s.push(a[i]); return s.join(",");
    }

    try {
        var HC = Java.use("com.signallab.lib.utils.net.HttpClients");
        var OV = HC.request.overload("java.lang.String", "java.util.Map", "[B", "java.lang.String");
        OV.implementation = function (url, hdrs, body, ctype) {
            var h = "null";
            try {
                if (hdrs !== null) {
                    var it = hdrs.entrySet().iterator(), out = [];
                    while (it.hasNext()) { var e = it.next(); out.push(e.getKey() + "=" + e.getValue()); }
                    h = out.join("&");
                }
            } catch (e) { h = "ERR"; }
            send({ t: "HTTP_REQ", url: String(url), hdr: h, blen: body === null ? -1 : Java.array('byte', body).length, ct: String(ctype) });
            var r = OV.call(this, url, hdrs, body, ctype);
            send({ t: "HTTP_RESP", url: String(url), len: r === null ? 0 : String(r).length, head: r === null ? "null" : String(r).substring(0, 3000) });
            return r;
        };
        log("[ok] HttpClients.request");
    } catch (e) { log("[fail] request " + e); }

    try {
        var SH = Java.use("com.signallab.lib.SignalHelper");
        SH.connect.implementation = function (fd, host, udp, tcp, uid, token, key, bt, algo) {
            send({ t: "CONNECT", host: String(host), udp: arr(udp), tcp: arr(tcp), uid: String(uid), token: String(token), key: String(key), bt: bt, algo: algo });
            return SH.connect.call(this, fd, host, udp, tcp, uid, token, key, bt, algo);
        };
        log("[ok] SignalHelper.connect");
    } catch (e) { log("[fail] connect " + e); }

    try {
        var SH2 = Java.use("com.signallab.lib.SignalHelper");
        SH2.getMd5.implementation = function (b) {
            var r = SH2.getMd5.call(this, b);
            send({ t: "MD5", inLen: b === null ? 0 : b.length, out: String(r) });
            return r;
        };
        log("[ok] getMd5");
    } catch (e) { log("[fail] getMd5 " + e); }
});

function hookConnect() {
    var m = Process.findModuleByName("libc.so");
    if (!m) { setTimeout(hookConnect, 200); return; }
    var p = m.findExportByName("connect");
    if (!p) { setTimeout(hookConnect, 200); return; }
    Interceptor.attach(p, {
        onEnter: function (args) {
            try {
                var sa = args[1], fam = sa.readU16();
                if (fam === 2) {
                    var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                    var ip = sa.add(4).readU8() + "." + sa.add(5).readU8() + "." + sa.add(6).readU8() + "." + sa.add(7).readU8();
                    if (ip.indexOf("127.") !== 0) send({ t: "TCP4", ip: ip, port: port });
                } else if (fam === 10) {
                    var port6 = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                    var b = []; for (var i = 0; i < 16; i++) b.push(sa.add(8 + i).readU8());
                    if (!(b[0] === 0 && b[15] === 1)) send({ t: "TCP6", ip: b.join("."), port: port6 });
                }
            } catch (e) { }
        }
    });
    send({ t: "log", m: "[ok] libc connect" });
}
setTimeout(hookConnect, 100);
"""

# 自动点击脚本：每一步 (延迟秒, 动作)
STEPS = [
    (11.0, "tap_accept"),
    (22.0, "tap_connect"),
    (27.0, "tap_ok"),
]


def main():
    dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
    pid = dev.spawn([PKG])
    print(f"[*] spawned pid={pid}", flush=True)
    session = dev.attach(pid)
    script = session.create_script(JS)
    seen = set()

    def on_msg(msg, data):
        if msg["type"] != "send":
            print("[non-send]", str(msg)[:300], flush=True)
            return
        p = msg["payload"]
        t = p.get("t", "?")
        line = f"[{t}] " + " | ".join(f"{k}={v}" for k, v in p.items() if k != "t")
        if t in ("TCP4", "TCP6"):
            if line in seen:
                return
            seen.add(line)
        print(line, flush=True)

    script.on("message", on_msg)
    script.load()
    dev.resume(pid)

    t0 = time.time()
    done = set()
    while time.time() - t0 < 100:
        el = time.time() - t0
        for delay, act in STEPS:
            if el >= delay and act not in done:
                done.add(act)
                if act == "tap_accept":
                    adb("input", "tap", "537", "1987")
                elif act == "tap_connect":
                    adb("input", "tap", "540", "1590")
                elif act == "tap_ok":
                    adb("input", "tap", "778", "1340")
                print(f"[*] action {act} at {el:.0f}s", flush=True)
        time.sleep(0.5)

    print("[*] loop done", flush=True)
    time.sleep(2)


if __name__ == "__main__":
    main()
