#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""frida-server 生命周期管理（Thunder VPN 逆向专用）"""
import subprocess
import sys
import time

import frida

ADB = r"C:\Users\Administrator.DESKTOP-EGNE9ND\Downloads\Compressed\platform-tools\adb.exe"
DEV = "emulator-5554"


def adb(*args):
    return subprocess.run([ADB, "-s", DEV, "shell", *args], capture_output=True, timeout=30)


def probe():
    try:
        d = frida.get_device_manager().add_remote_device("127.0.0.1:27300")
        return d.query_system_parameters().get("access") == "full"
    except Exception:  # noqa: BLE001
        return False


def ensure():
    """返回可用的 remote device；必要重启 frida-server"""
    subprocess.run([ADB, "-s", DEV, "forward", "tcp:27300", "tcp:27300"],
                   capture_output=True, timeout=20)
    for attempt in range(5):
        if probe():
            return frida.get_device_manager().add_remote_device("127.0.0.1:27300")
        adb("setenforce", "0")
        adb("cd /data/local/tmp && (setsid ./fs17 -l 0.0.0.0:27300 >/data/local/tmp/fs17.log 2>&1 </dev/null &)")
        for _ in range(12):
            time.sleep(2)
            if probe():
                print(f"[*] frida-server up (try {attempt + 1})", file=sys.stderr, flush=True)
                return frida.get_device_manager().add_remote_device("127.0.0.1:27300")
    raise SystemExit("frida-server 起不来")


def spawn_retry(dev, pkg):
    for attempt in range(4):
        try:
            return dev.spawn([pkg]), dev
        except Exception as e:  # noqa: BLE001
            print(f"[!] spawn fail {attempt + 1}: {e}", file=sys.stderr, flush=True)
            dev = ensure()
            time.sleep(2)
    raise SystemExit("spawn 失败")
