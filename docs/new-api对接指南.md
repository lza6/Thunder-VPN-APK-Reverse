# Thunder VPN → new-api 对接指南

> 面向：负责对接的会话/工程师
> 前提：本仓库已完成协议逆向与节点池收割，**但没有可用的代理出口协议**。
> 请务必先读 §1 再动手，否则会浪费时间。

---

## 1. 结论先行：能不能直接对接？

**不能直接对接。** 原因不是没拿到凭证，而是**协议层不兼容**：

| new-api 代理池期望 | Thunder VPN 实际 |
|---|---|
| `socks5://host:port` / `http://user:pass@host:port` | 私有 L3 隧道（`SignalLinkClient`） |
| 标准握手 | `SignalObfuscator(obs_key)` + AES-GCM + 自定义 `SignalPackage` |
| 端口上跑 SOCKS/HTTP | **443/465/802 上非 TLS、非 HTTP**（实测 TLS 握手 RST、明文 GET 无响应） |

所以 `output/candidates_full.txt` 里那些 `IP:443` **不能**直接写进 `TRYINGOPEN_PROXY_FILE` ——
写进去只会全部无法拨通，白白污染代理池健康度。

---

## 2. 我们已经有什么

### 2.1 节点池

| 文件 | 内容 |
|---|---|
| `data/real_nodes_full.json` | **71 个唯一公网节点 / 19 国**（App native 加密态实收） |
| `output/thunder_nodes.json` | 带压测成功率/延迟的加工版 |
| `output/candidates_full.txt` | 25 个「3 轮 × 3 端口全通」节点，`ip:443` 每行一个 |
| `output/all_nodes.txt` | 全部 71 个 |

节点字段语义（**关键，别猜**）：

```jsonc
{
  "ip":       "51.81.210.250",     // 隧道对端公网地址
  "country":  "US",
  "area":     "US Oregon",
  "obs_key":  "j4QSaJkaiPWixanefrXXdd",  // 22 字符 base64url，隧道混淆密钥，必须成对使用
  "obs_algo": 1,                    // 混淆算法版本（0/1 两套，不要混用）
  "is_vip":   true,                 // Mod 破解后 VIP 池也可见
  "load":     15
}
```

> ⚠️ `ip` 单用没有意义 —— 必须和 `obs_key` + `obs_algo` 一起用才能建隧道。
> 这一点和 Hysteria2（user:pass@host）不同。

### 2.2 可跑的协议客户端

```bash
python thunder_api.py register   # 注册设备（零门槛）
python thunder_api.py list       # ⚠️ 匿名态只返回 169.254.x 兜底池
python thunder_api.py probe      # 端口连通性
```

**重要限制**：纯 Python/HTTP 客户端拿不到真实节点池，只有 App（native 加密态 + 已激活设备）才行。
真实池快照是 `recon/hook9.py` 从运行中的 App 里 hook 出来的（见 §5）。

---

## 3. 对接路线 A：做一层「协议转换」暴露 SOCKS5（推荐）

new-api 侧的 `TRYINGOPEN_PROXY_FILE` **已经支持「本地协议转换层」**（代码注释里就写了
`SuperVPN 的 hysteria2 → socks5 端口列表` 的先例），所以只要转换层把 Thunder 隧道
变成 `socks5://127.0.0.1:<port>`，对接就是**零改动**。

### 3.1 转换层需要做到的事

```
[Thunder 私有隧道]  <-- libchannel.so / 复刻客户端 -->  [转换层进程]
                                                          |  监听 127.0.0.1:9101
                                                          v
                                            socks5://127.0.0.1:9101  → 出口 = 节点 IP
```

两种实现：

| 实现 | 做法 | 工期 | 密度 |
|---|---|---|---|
| **A1. 模拟器 TUN 桥** | 模拟器内 App 建隧道 → frida hook `SignalService` 拿 TUN fd → 把 IP 包导出到 PC → PC 用 `hev-socks5-tunnel` 包回 SOCKS5 | 2–3 天 | 1 模拟器 = 1 出口 |
| **A2. 复刻 SignalLinkClient** | 逆向 `SignalPackage`/`SignalObfuscator`/AES-GCM，用 Go/C++ 重写客户端 | 1–2 周 | 单机可跑几十出口 |

> `libchannel.so` 符号未混淆（`SignalLinkClient::connect`、`SignalObfuscator`、`aes_gcm_*`
> 全部可见），A2 的静态分析成本比想象低。

### 3.2 转换层输出格式（硬约定）

转换层必须输出一个**每行一个 URL** 的文件，例如 `output/thunder_socks.txt`：

```
# Thunder VPN 转换层 · 生成于 2026-10-29
socks5://127.0.0.1:9101
socks5://127.0.0.1:9102
socks5://127.0.0.1:9103
```

规则（与 `relay/channel/tryingopen/proxy_pool.go` 一致）：

- 一行一个 URL，`#` 开头为注释
- scheme 只允许 `http` / `https` / `socks5` / `socks5h`
- 带认证写 `socks5://user:pass@host:port`
- 端口必须 1–65535

### 3.3 new-api 侧配置（一行）

```bash
# 多文件用逗号分隔，各自在后台成为独立卡片，便于看哪张池子健康
TRYINGOPEN_PROXY_FILE=/etc/new-api/proxies_residential.txt,/etc/new-api/output/thunder_socks.txt
```

重启后到 **后台 → 渠道 → 代理池** 应看到新卡片（origin = 文件名 `thunder_socks.txt`）。

### 3.4 验收（必须做，别只看进程在跑）

```bash
# 1) 确认转换层端口在听
ss -lntp | grep 9101

# 2) 确认走代理时出口 IP == 节点 IP（这是唯一有效判据）
curl -s -x socks5h://127.0.0.1:9101 https://t1.free-signal.com/ip/
# 期望：ip=<节点所在国的公网 IP>，而不是你本机出口

# 3) 让 new-api 拨测一轮，看该卡片成功率
#    后台 → 代理池 → 点卡片刷新
```

---

## 4. 对接路线 B：只把 IP 当资产（0 成本，今天就能用）

如果当前目标不是「API 出口 IP」，而是**风控测试 / IP 多样性**：

- 71 个节点 IP 来自 OVH / Contabo / Leaseweb / 40.160.x(Azure) 等机房段，19 国
- 直接作为「IP 库」入库即可，**不要**放进 `TRYINGOPEN_PROXY_FILE`

适用场景：注册限流验证、地域分布测试、日志分析比对。

---

## 5. 节点池怎么刷新（长期维护）

真实池只对「App 已激活设备」下发，所以刷新必须借 App：

```bash
# 一键刷新（需模拟器 + frida 16.5.9 server）
python recon/hook9.py
#   → recon/full_serverlist.json（原始响应）
#   → data/real_nodes_full.json（合并去重，保留历史节点）
```

脚本内部做的三件事：

1. `rm files/cache_original_v2 files/cache_morph_v2` —— 删掉 native 加密的节点缓存，强制重拉
2. `am force-stop` + `am start` —— 重启 App（缓存删了不重启不会重拉）
3. frida hook `HttpClients.request`，把 `v2/server/` 的**解密后响应**整段存下来

已验证的坑：
- **新注册设备拿不到真实池**（只给 `169.254.x` 兜底池，界面会卡在 `Testing connection speed…`）
  → 需要先「养号」（同设备多跑几次、建立 VIP 破解态）
- `pm clear` 后包会变 disabled，必须重新 `pm enable` 才能 `am start`
- frida client 版本必须与设备端 server 一致（本机曾出现 client 17.24.3 vs server 16.5.9 → `ProtocolError`）

---

## 6. 已知限制（对接前必须知道）

| 限制 | 影响 |
|---|---|
| 私有协议 | 无法用现成工具（xray/v2ray/clash）直连 |
| `obs_key` 会轮换 | 池快照有时效性，需要定期重抓 |
| 免费组（6 个）几乎不可用 | 443 成功率 0–33%，别放进生产池 |
| VIP 组部分节点 33% 成功率 | 疑似端口敲门（port knocking）或 SYN 限速，不是网络抖动 |
| 每出口 1 模拟器（方案 A1） | 密度低，适合做「精品出口」而非大池 |
| 合规 | 运营商自有基础设施 + 破解版客户端，不建议生产直连 |

---

## 7. 一页速查

```
能不能直接塞进 TRYINGOPEN_PROXY_FILE？  → 不能（非 socks5/http）
我有什么？                              → 71 节点（ip+obs_key+obs_algo）+ 压测数据
差什么？                                → 一层 socks5 转换（A1 模拟器桥 / A2 复刻协议）
转换层输出什么？                        → 每行 socks5://127.0.0.1:<port>
new-api 怎么配？                        → TRYINGOPEN_PROXY_FILE=a.txt,thunder_socks.txt
怎么验收？                              → curl -x socks5h://127.0.0.1:9101 https://t1.free-signal.com/ip/
                                       出口 IP 应等于节点 IP
```
