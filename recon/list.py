#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""纯 Python 复刻 Thunder VPN 节点列表拉取（无需注册/无需 native）"""
import hashlib
import json
import sys

import requests

S = requests.Session()
S.trust_env = False  # 关键：绕过系统 HTTP_PROXY=127.0.0.1:10808

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PKG = "com.fast.free.unblock.thunder.vpn"
VER_CODE = 202604131
APP_SIG_MD5 = "19366c1a2cb68d76d6d8d2017a9780e1"
BASES = [f"https://t{i}.free-signal.com/" for i in range(1, 7)]


def headers(auth_id=0, auth_token=0):
    raw = (f"auth_id={auth_id}&auth_token={auth_token}&app_package={PKG}"
           f"&app_ver_code={VER_CODE}&app_signature={APP_SIG_MD5}")
    return {
        "s-auth-id": str(auth_id),
        "s-auth-token": str(auth_token),
        "s-app-package": PKG,
        "s-app-ver-code": str(VER_CODE),
        "s-req-token": hashlib.md5(raw.encode()).hexdigest(),
    }


def my_ip(base):
    try:
        r = S.get(base + "ip/", timeout=10)
        return r.text.strip().split("=", 1)[1]
    except Exception:  # noqa: BLE001
        return None


def main():
    imsi = sys.argv[1] if len(sys.argv) > 1 else "310260"
    out = {}
    for base in BASES:
        tag = base.split("//")[1].split(".")[0]
        ip = my_ip(base)
        if not ip:
            print(f"[{tag}] /ip/ 失败")
            continue
        url = f"{base}v2/server/?dev_imsi={imsi}&dev_lang=en_US&isp_ip={ip}"
        try:
            r = S.get(url, headers=headers(), timeout=15)
            d = r.json()
        except Exception as e:  # noqa: BLE001
            print(f"[{tag}] 失败 {type(e).__name__}: {e}")
            continue
        srv = d.get("server") or []
        vips = [s for s in srv if s.get("is_vip")]
        free = [s for s in srv if not s.get("is_vip")]
        print(f"[{tag}] ip={ip} total={len(srv)} free={len(free)} vip={len(vips)} cfg={d.get('config')}")
        for s in srv:
            print(f"   {s['ip']:<16} {s.get('country'):<4} algo={s.get('obs_algo')} "
                  f"vip={s.get('is_vip')} run={s.get('is_running')} key={s.get('obs_key')}")
        out[tag] = d
    with open("recon/raw_lists.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print("\n保存 recon/raw_lists.json")


if __name__ == "__main__":
    main()
