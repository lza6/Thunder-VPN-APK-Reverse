#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Thunder VPN UI 自动化：启动 -> CONNECT -> 授权 -> 校验连接"""
import subprocess
import sys
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ADB = r"C:\Users\Administrator.DESKTOP-EGNE9ND\Downloads\Compressed\platform-tools\adb.exe"
THUNDER = "com.fast.free.unblock.thunder.vpn"
SHUTTLE = "com.shuttlevpn.free.proxy.gaming"


def sh(*args, timeout=30):
    return subprocess.run([ADB, "-s", "emulator-5554", "shell", *args],
                          capture_output=True, timeout=timeout).stdout.decode(errors="replace")


def top():
    out = sh("dumpsys activity activities | grep mResumedActivity")
    for tok in out.split():
        if "/" in tok and "." in tok:
            return tok.strip()
    return out.strip()


def shot(name):
    with open(f"recon/{name}.png", "wb") as f:
        f.write(subprocess.run([ADB, "-s", "emulator-5554", "exec-out", "screencap", "-p"],
                               capture_output=True, timeout=60).stdout)
    print(f"[*] shot recon/{name}.png", flush=True)


def main():
    print("[*] 隔离 ShuttleVPN", flush=True)
    sh(f"am force-stop {SHUTTLE}")
    sh(f"pm disable-user --user 0 {SHUTTLE}")
    sh(f"pm enable {THUNDER}")
    sh(f"pm enable --user 0 {THUNDER}")

    print("[*] 启动 Thunder", flush=True)
    sh(f"monkey -p {THUNDER} -c android.intent.category.LAUNCHER 1")
    time.sleep(9)
    print("[*] top:", top(), flush=True)

    for attempt in range(6):
        t = top()
        if "vpndialogs" in t:
            shot(f"dialog_{attempt}")
            print("[*] 检测到 VPN 授权对话框，点击 OK", flush=True)
            sh("input tap 800 1330")
            time.sleep(3)
            continue
        if THUNDER not in t:
            print(f"[!] 前台不是 Thunder ({t})，重新拉起", flush=True)
            sh(f"am start -n {THUNDER}/com.signallab.thunder.activity.MainActivity")
            time.sleep(4)
            continue
        print(f"[*] 点击 CONNECT (attempt {attempt})", flush=True)
        sh("input tap 537 2040")
        time.sleep(5)
        shot(f"ui_{attempt}")
        t2 = top()
        print("[*] after tap top:", t2, flush=True)
        if "vpndialogs" in t2:
            continue
        if "ConnectedActivity" in t2 or "Loading" in t2:
            print("[*] 已进入连接流程", flush=True)
            break

    time.sleep(10)
    shot("final")
    print("[*] final top:", top(), flush=True)
    print("[*] VPN 接口:", sh("ip addr show tun0 2>/dev/null | head -4"), flush=True)
    print("[*] ip rule:", sh("ip rule | head -6"), flush=True)


if __name__ == "__main__":
    main()
