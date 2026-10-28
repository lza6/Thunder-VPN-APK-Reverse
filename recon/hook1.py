#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Thunder VPN 动态侦察: hook HTTP 栈 + SignalHelper.connect + libc connect"""
import sys
import time

import frida

PKG = "com.fast.free.unblock.thunder.vpn"

JS = r"""
Java.perform(function () {
    var log = function (s) { send({ t: "log", m: String(s) }); };

    // ---- 1. HttpClients.request(String,Map,byte[],String) ----
    try {
        var HC = Java.use("com.signallab.lib.utils.net.HttpClients");
        var req = HC.request.overload("java.lang.String", "java.util.Map", "[B", "java.lang.String");
        req.implementation = function (url, hdrs, body, ctype) {
            var h = "null";
            try {
                if (hdrs !== null) {
                    var it = hdrs.entrySet().iterator();
                    var arr = [];
                    while (it.hasNext()) { var e = it.next(); arr.push(e.getKey() + "=" + e.getValue()); }
                    h = arr.join("&");
                }
            } catch (e) { h = "ERR:" + e; }
            var b = body === null ? "null" : Java.array('byte', body).length + " bytes";
            send({ t: "http_req", url: url, hdr: h, body: b, ct: ctype });
            var t0 = Date.now();
            var r = req.call(this, url, hdrs, body, ctype);
            send({ t: "http_resp", url: url, ms: Date.now() - t0, len: r === null ? 0 : String(r).length, head: r === null ? "null" : String(r).substring(0, 600) });
            return r;
        };
        log("[ok] hook HttpClients.request");
    } catch (e) { log("[fail] HttpClients.request " + e); }

    // ---- 2. SignalHelper.connect ----
    try {
        var SH = Java.use("com.signallab.lib.SignalHelper");
        SH.connect.implementation = function (fd, host, udp, tcp, uid, token, key, bt, algo) {
            var show = function (a) {
                if (a === null) return "null";
                var s = []; for (var i = 0; i < a.length; i++) s.push(a[i]); return s.join(",");
            };
            send({ t: "connect", host: host, udp: show(udp), tcp: show(tcp), uid: String(uid), token: String(token), key: key, bt: bt, algo: algo });
            return SH.connect.call(this, fd, host, udp, tcp, uid, token, key, bt, algo);
        };
        log("[ok] hook SignalHelper.connect");
    } catch (e) { log("[fail] SignalHelper.connect " + e); }

    // ---- 3. getMd5 ----
    try {
        var SH2 = Java.use("com.signallab.lib.SignalHelper");
        SH2.getMd5.implementation = function (b) {
            var r = SH2.getMd5.call(this, b);
            send({ t: "md5", inLen: b === null ? 0 : b.length, out: String(r) });
            return r;
        };
        log("[ok] hook getMd5");
    } catch (e) { log("[fail] getMd5 " + e); }
});

// ---- 4. libc connect (native 层真实目的地址) ----
function hookConnect() {
    var m = Process.findModuleByName("libc.so");
    if (!m) { setTimeout(hookConnect, 200); return; }
    var p = m.findExportByName("connect");
    if (!p) { setTimeout(hookConnect, 200); return; }
    Interceptor.attach(p, {
        onEnter: function (args) {
            try {
                var sa = args[1];
                var fam = sa.readU16();
                if (fam === 2) {
                    var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                    var ip = sa.add(4).readU8() + "." + sa.add(5).readU8() + "." + sa.add(6).readU8() + "." + sa.add(7).readU8();
                    if (ip.indexOf("127.") !== 0) send({ t: "tcp4", ip: ip, port: port });
                } else if (fam === 10) {
                    var port6 = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                    var bytes = [];
                    for (var i = 0; i < 16; i++) bytes.push(sa.add(8 + i).readU8());
                    if (!(bytes[0] === 0 && bytes[15] === 1)) send({ t: "tcp6", ip: bytes.join("."), port: port6 });
                }
            } catch (e) { }
        }
    });
    send({ t: "log", m: "[ok] hook libc connect" });
}
setTimeout(hookConnect, 100);
"""


def main():
    dev = frida.get_usb_device(timeout=10)
    pid = dev.spawn([PKG])
    print(f"[*] spawned pid={pid}")
    session = dev.attach(pid)
    script = session.create_script(JS)
    seen = set()

    def on_msg(msg, data):
        if msg["type"] != "send":
            print("[non-send]", msg)
            return
        p = msg["payload"]
        t = p.get("t")
        line = f"[{t}] " + " | ".join(f"{k}={v}" for k, v in p.items() if k != "t")
        key = line[:200]
        if t in ("tcp4", "tcp6"):
            if key in seen:
                return
            seen.add(key)
        print(line)

    script.on("message", on_msg)
    script.load()
    dev.resume(pid)
    print("[*] resumed, collecting 75s ...")
    time.sleep(75)
    print("[*] done")


if __name__ == "__main__":
    main()
