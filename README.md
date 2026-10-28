# Thunder VPN 逆向产物

SignalLab「Thunder VPN」v5.4.1 (Mod by ElaMods) 的协议还原 + 节点池收割工具。

- 📄 完整分析：[`逆向报告.md`](./逆向报告.md)
- 🔌 **对接怎么接**：[`docs/new-api对接指南.md`](./docs/new-api对接指南.md)
- 🎯 目标：把它变成可长期维护的节点/IP 池，供线上代理池评估

## 快速开始

```bash
pip install requests

# 1) 协议客户端
python thunder_api.py register     # 注册设备（明文 JSON，无风控）
python thunder_api.py list         # 拉节点（匿名态 → 169.254 兜底池）
python thunder_api.py probe        # 端口连通性探测
python thunder_api.py harvest --rounds 5

# 2) 压测（71 个真实节点 × 3 端口 × N 轮）
python stress.py --rounds 3 --workers 40

# 3) Demo 面板
python demo_server.py --port 8962
# → http://127.0.0.1:8962/
```

## 文件说明

| 文件 | 作用 |
|---|---|
| `thunder_api.py` | 协议 SDK：注册 / 列表 / 探测 / 收割（零依赖，requests only） |
| `demo_server.py` + `demo.html` | 可视化面板：设备态、节点表、一键探测 |
| `stress.py` | TCP 端口存活率 / 延迟分布 / 轮次稳定性压测 |
| `data/real_nodes_full.json` | **71 个真实公网节点**（19 国，抓包所得） |
| `data/real_nodes.json` | 抓包快照（含兜底池 12 个说明） |
| `recon/hook*.py` | frida 动态抓包脚本（协议取证过程） |
| `recon/probe_nodes.py` `recon/list.py` | 早期探针脚本 |
| `docs/new-api对接指南.md` | **给对接会话的落地文档**（含 socks5 转换层约定与验收命令） |
| `apktool_out/` `jadx_out/` | 反编译产物（不入库，自行重建） |

## 关键结论（TL;DR）

1. API 完全开放：**免密注册 + 明文列表**，无验证码、无风控、无限注册。
2. 但匿名客户端只发 `169.254.x` 兜底池（假地址）；真实池（71 个公网 IP）只发给 **native 加密态**客户端。
3. 隧道是**私有协议**（`SignalLinkClient` + AES-GCM + `SignalObfuscator`），443 端口非 TLS，
   不能像 WG/Hysteria2 那样直接转 SOCKS5。
4. 71 个节点里 **25 个（35%）3 轮×3 端口全通**，延迟 179–410 ms；
   免费组 6 个几乎不可用（0–33%），VIP 组（Mod 解锁）质量明显更好。
5. 想真正当代理出口：走 **模拟器 TUN 桥**（2-3 天）或 **复刻 SignalLinkClient**（1-2 周）。

## 免责

仅用于对自有样本的安全研究与互通性评估；节点池数据为抓包快照，服务端 IP/密钥会轮换。
