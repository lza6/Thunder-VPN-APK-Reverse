#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Thunder VPN API 探针 - 只读，仅拉取服务器列表"""
import hashlib
import json
import sys

import requests

PKG = "com.fast.free.unblock.thunder.vpn"
VER_CODE = 202604131
APP_SIG_MD5 = "19366c1a2cb68d76d6d8d2017a9780e1"
BASES = [f"https://t{i}.free-signal.com/" for i in range(1, 7)]


def headers(auth_id=0, auth_token=0):
    raw = (
        f"auth_id={auth_id}&auth_token={auth_token}"
        f"&app_package={PKG}&app_ver_code={VER_CODE}&app_signature={APP_SIG_MD5}"
    )
    req_token = hashlib.md5(raw.encode()).hexdigest()
    return {
        "s-auth-id": str(auth_id),
        "s-auth-token": str(auth_token),
        "s-app-package": PKG,
        "s-app-ver-code": str(VER_CODE),
        "s-req-token": req_token,
    }


def main():
    q = "?dev_imsi=&dev_lang=en_US"
    for base in BASES:
        url = base + "v2/server/" + q
        try:
            r = requests.get(url, headers=headers(), timeout=15)
            body = r.text
            print(f"[{r.status_code}] {url} len={len(body)}")
            print("   ", body[:400].replace("\n", " "))
            if r.status_code == 200 and body.strip().startswith("{"):
                with open(f"recon/serverlist_{base.split('//')[1].split('.')[0]}.json", "w", encoding="utf-8") as f:
                    f.write(body)
                print("    -> saved")
        except Exception as e:  # noqa: BLE001
            print(f"[ERR] {url} {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
