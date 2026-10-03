# PPPoE-Hijack v2.1 ── Python 3 移植 + 现代光猫/路由器适配版

> 上游原版：[`zhengwuji/PPPoE-hijack`](https://github.com/zhengwuji/PPPoE-hijack)（2016-02-27，单个 commit `2f7aa53`，
> 178 行 Python 2 脚本）。本仓库在这份原版基础上做了**完整 Python 3 移植 + 两轮优化 + 当代光猫/路由器适配**，
> 原版文件原样留档在 [`legacy/scapy-pppoe.py`](legacy/scapy-pppoe.py)。
>
> ⚠️ **仅用于你自己拥有或已获书面授权的线路与设备**。抢答（冒充 BRAS）成功会让对方设备掉线重拨。

---

## 一、它干什么

伪造一台 PPPoE 接入服务器（BRAS），在 PPPoE 发现阶段抢先应答受害客户端的 `PADI`（回 `PADO`/`PADS`），
然后参与 LCP 协商，把认证协议**诱导到 PAP（明文）**，或记录 CHAP/MS-CHAPv2 挑战应答，
从而拿到拨号账号口令：

```
客户端                                  本工具（伪 BRAS）            真 BRAS
  │  PADI (广播) ───────────────────────►│                            │
  │◄─────────────────────────  PADO ─────│  ← 抢在真 BRAS 之前回      │  PADO（慢了）
  │  PADR ──────────────────────────────►│                            │
  │◄─────────────────────────  PADS ─────│  sessionid 建立
  │  LCP-Config-Req ────────────────────►│
  │◄──────────────── LCP Nak（塞认证选项）│
  │  LCP-Config-Req（Accept 我们的认证）►│
  │  PAP: 账号 + 明文口令 ───────────────►│  ★ 落盘
```

## 二、原版为什么「不能直接用」（实测三道门槛）

| 门槛 | 实测报错 | 本次处理 |
| --- | --- | --- |
| Python 2 语法 | `SyntaxError: Missing parentheses in call to 'print'`（`scapy-pppoe.py:61`） | 全量移植到 Python 3 |
| scapy API 断代（2.2 → 2.7） | `pkt.load` 读写均 `AttributeError: load`；`haslayer(PPPoE)` / `pkt[PPPoE]` 因**精确类匹配**恒为假（嗅探到的是子类 `PPPoED`）→ `IndexError: Layer [PPPoE] not found` | 放弃「改嗅探包首字节」的老套路，改为**显式重建整帧**发送；匹配一律沿 payload 链 `isinstance()` |
| 缺少 Npcap | `RuntimeError: Sniffing and sending packets is not available at layer 2: winpcap is not installed` | 给出人话报错 + `--replay` 离线回放路径（Linux/OpenWrt 走 AF_PACKET，**不需要 Npcap**） |

另修掉原版三个真实缺陷：**自环发包风暴**（自己发的 LCP-Req 会被自己嗅到并当成新客户端，导致无限循环）、
`uuid.getnode()` 在多网卡机器上返回随机值、`sendp()` 不绑定网卡。详细取证见 [`评估报告.md`](评估报告.md)。

## 三、本次中文更新内容

### v2.1 ─ 现代光猫/路由器适配（13 项）

| # | 能力 | 开关 / 说明 |
| --- | --- | --- |
| 1 | **VLAN / QinQ 感知** | `--vlan off\|auto\|0-4095`、`--vlan-prio 0-7`；单层 `0x8100` 与双层 `0x88A8` 都能跟随客户端 |
| 2 | **一键预设** | `--profile legacy`（2016 原版字节行为）/ `modern`（家用双栈）/ `ont`（光猫桥接） |
| 3 | **Service-Name 匹配** | `--service-name a,b,c` 回显客户端请求名；`--service-strict` 时不在列表内回 `PADS + Service-Name-Error(0x0201)` |
| 4 | **Relay-Session-Id(0x0110)** | 默认原样回显（`--no-relay-sid` 关），适配中继/汇聚组网 |
| 5 | **AC-Cookie(0x0104)** | `--ac-cookie`：PADO 下发 cookie 并校验 PADR 是否回带（更逼真，不匹配时宽容处理） |
| 6 | **PPP-Max-Payload(0x0120)** | `--max-payload 1500` 支持 RFC 4638 全速 1500；`--mru` 单独调我方 MRU（默认 1480 = 原版字节） |
| 7 | **IPv6CP(0x8057)** | `--ipv6cp auto\|on\|off`，双栈光猫会协商它；`--ipv6cp-iid` 指定我方接口标识（缺省按 MAC 生成 EUI-64） |
| 8 | **多拨 / 多会话** | 同一 MAC 允许多条会话（键 `(MAC, sessionid)`），`--max-sessions` 限并发，PADR 重传窗口内复用会话 |
| 9 | **802.1X 指纹** | `--eapol log` 旁听 EAP-Response/Identity（往往就是宽带账号），**从不回应** |
| 10 | **DHCP 设备指纹** | `--dhcp log` 记录 Option 12 主机名 / 60 厂商类 / 61 客户端标识 / 77 用户类 + 客户端 MAC |
| 11 | **OUI 厂商识别** | 内置 OUI 表 + `--oui-file oui.txt`（每行 `aa:bb:cc,厂商`），凭据里直接标注设备厂商 |
| 12 | **落盘扩到 28 字段** | 新增 kind/vendor/vlan/ipv6_iid/service_name/relay_sid/eapol_identity/hostname/vendor_class/client_id/max_payload 等；老库自动 `ALTER TABLE` 迁移 |
| 13 | **BPF 与日志增强** | BPF 覆盖 VLAN 子句、`0x888e`、DHCP 端口；新增 `-v/--verbose`（DEBUG：每条报文的协议与选项细节） |

### v2.0 ─ 一轮完整优化（清单全部落地）

- **认证诱导**：`--auth-order pap,mschapv2,chap,mschapv1`（首选 PAP，客户端拒绝则按序切换）、`--auth-retry`；
  CHAP（MD5）与 MS-CHAPv1/v2 全链路记录 `peer_challenge / auth_challenge / nt_response / raw`。
- **LCP 状态机**：`--lcp-mode nak|reject`、`--lcp-retry/--lcp-maxretry`（原版从不重传，丢包即卡死）、
  重传去重、`--session-ttl` 空闲回收（原版 `clientMap` 永不清理）。
- **留住会话**：`--pap-mode ack` + `--ipcp on --ipcp-local 10.0.0.1 --ipcp-peer 10.0.0.2`
  会让客户端以为认证通过、继续做 IPCP，从而长时间停在会话里。
- **性能与稳定**：复用二层 socket、预构造模板帧、收/发解耦（`AsyncSniffer` + 发送线程）、
  `--rate 200` 令牌桶限速、BPF 加 `ether dst`、`conf.verb=0` 静音。
- **工程化**：TOML 配置（`-c config.toml`，优先级 `CLI > TOML > 默认值`）、
  结构化落盘（JSONL / SQLite 按扩展名自动选择）、`--list-ifaces`、
  `--dry-run`（不发包只打印/存 pcap）、`--replay`（离线回放 pcap）、`--pcap-out`、`--stats`。
- **隐蔽性**：`--learn-ac` 从真 BRAS 的 PADO/PADS 学它的 MAC 与 AC-Name 再冒充它。

## 四、环境要求与安装

| 平台 | 依赖 | 二层收发 |
| --- | --- | --- |
| Windows | Python 3.11+、scapy（2.7.0 实测通过）、**Npcap** | 安装 Npcap 时勾选 *Install Npcap in WinPcap API-compatible Mode*，并以管理员运行 |
| Linux | Python 3.11+、scapy | 原生 AF_PACKET，**无需任何额外驱动** |
| OpenWrt 软路由 | `opkg install python3-pip` 再 `pip install scapy` | 同上（见 [`OpenWrt部署.md`](OpenWrt部署.md)） |

```bash
# Python 3.11+（标准库 tomllib 需要 3.11）
python -m venv .venv
# Windows: .\.venv\Scripts\python.exe -m pip install -r requirements.txt
# Linux  : ./.venv/bin/python -m pip install -r requirements.txt
```

## 五、怎么用

### 0) 先看网卡（不需要 Npcap）

```bash
python pppoe_hijack_py3.py --list-ifaces
```

### 1) 离线回放：不需要 Npcap，最安全的入门路径

拿任意一个客户端侧的 pcap（或先在那台设备上抓一个），跑完整流水线：
引擎只「干跑」并把回包写成 pcap，同时把凭据落盘，**一个包都不发**。

```bash
python pppoe_hijack_py3.py --replay client.pcap --pcap-out our-replies.pcap -o creds.jsonl -v
```

### 2) 实机（先确认能看到 PPPoE 发现帧）

```bash
# Windows（管理员，且已装 Npcap）；Linux 直接跑
python pppoe_hijack_py3.py -i "以太网" --learn-ac \
       --auth-order pap,mschapv2,chap,mschapv1 -o creds.sqlite -v

# 只想观察、不抢答（不打扰任何设备）：加 --dry-run
python pppoe_hijack_py3.py -i eth0 --dry-run -v --stats 10
```

看到 `[PADI]`/`[PADR]` 日志并且凭据落盘才算成功；看不到 PPPoE 帧说明**网口不在「光猫 ↔ 拨号设备」那段二层里**
（这是最常见的失败原因，见下面第 5 节）。

### 3) 现代光猫 / 家用路由器

```bash
# 光猫桥接 + 运营商 VLAN（VLAN 跟随客户端，并学真 BRAS 的 MAC/名字）
python pppoe_hijack_py3.py -i eth1 --profile ont -v

# 家用双栈路由器：VLAN 随客户端 + IPv6CP + 802.1X/DHCP 指纹，MRU 1492
python pppoe_hijack_py3.py -i "以太网" --profile modern -v

# 已知运营商 VLAN，强制插入（例：VLAN 43、优先级 3）
python pppoe_hijack_py3.py -i eth1 --vlan 43 --vlan-prio 3 --mru 1492

# 完整对照 2016 原版行为（字节级）
python pppoe_hijack_py3.py -i eth0 --profile legacy
```

> VLAN 跟随依赖网卡/驱动不把 tag 剥掉（部分 Windows 驱动会），首次使用建议先
> `--vlan auto --dry-run -v` 看日志里有没有 `vlan=`。

### 4) 独占发现阶段（软路由透明桥玩法）

把软路由做成透明桥串在「光猫 ↔ 拨号路由器」之间，然后在桥上丢掉上游 PADO，抢答就必成：

```sh
ebtables -A FORWARD -p 0x8863 -j DROP      # 只挡发现帧（会让拨号重连，需提前知情）
python3 pppoe_hijack_py3.py -i br-wan --vlan auto -o /root/creds.jsonl
```

只想被动看（连 PAP 单播都可见）时，在桥上直接抓包，把 pcap 拉回来用 `--replay` 离线解，全程不发一个包。
完整接线与避坑见 [`OpenWrt部署.md`](OpenWrt部署.md)。

### 5) 抓不到？先查这三条硬条件

1. **在不在同一个二层广播域**：网口必须能看到客户端的 `PADI`（广播）。
   拨号设备若是**光猫路由模式**，PPPoE 完全不出现在 LAN 侧；无线/5G 也不承载 PPPoE 发现帧。
2. **回得去吗**：`PADO` 要能送到客户端（不少光猫 LAN 口做了隔离/端口保护，会直接失败）。
3. **抢得过真 BRAS 吗**：RFC 2516 只认**第一个** `PADO` —— 慢了就没戏，用上面的 `ebtables` 或透明桥保证。

### 6) 凭据落盘与查询

`-o` 按扩展名自动选格式：`*.db/*.sqlite/*.sqlite3` = SQLite，其它 = JSONL（一行一条）。

```bash
# JSONL
python -m json.tool --json-lines < creds.jsonl

# SQLite：只看明文 PAP 账号
sqlite3 creds.sqlite "SELECT ts,mac,vendor,auth,username,password,vlan FROM creds WHERE kind='pap';"
# CHAP / MS-CHAPv2（挑战应答原样留档，需离线还原）
sqlite3 creds.sqlite "SELECT ts,mac,username,peer_challenge,auth_challenge,nt_response FROM creds WHERE auth LIKE 'mschap%';"
# 设备指纹
sqlite3 creds.sqlite "SELECT ts,mac,vendor,hostname,vendor_class,eapol_identity FROM creds WHERE kind='dhcp' OR kind='eapol';"
```

### 7) 常用参数速查

| 参数 | 作用 |
| --- | --- |
| `-i/--iface` | 监听网卡（`--list-ifaces` 查名字） |
| `-m/--mac` | 伪装源 MAC（缺省 `0a:0a:0a:0a:0a:0a`，`--learn-ac` 时改用真 BRAS 的） |
| `--learn-ac` | 从真 BRAS 的 PADO/PADS 学 MAC 与 AC-Name 并冒充它 |
| `--profile` | `legacy` / `modern` / `ont` 一键组合 |
| `--vlan` / `--vlan-prio` | VLAN 跟随或强制插入 |
| `--service-name` / `--service-strict` | 服务名白名单与拒绝行为 |
| `--auth-order` / `--auth-retry` | 认证协议优先序与切换上限 |
| `--pap-mode ack` + `--ipcp on` | 留住客户端会话（PAP 假通过 + 下发假地址） |
| `--mru` / `--max-payload` | 我方 MRU（默认 1480）/ RFC 4638 大包宣告 |
| `--eapol log` / `--dhcp log` | 旁听 802.1X / DHCP 设备指纹 |
| `--oui-file` | 自定义 OUI 厂商表 |
| `--rate` | 发包限速（包/秒，0 = 不限） |
| `--session-ttl` / `--max-sessions` | 会话回收与并发上限 |
| `--replay` / `--dry-run` / `--pcap-out` | 离线回放 / 干跑 / 导出我方回包 |
| `-q` / `-v` / `--stats` | 静音 / DEBUG / 统计间隔 |

完整说明（含中文段落）见 `--help`。

## 六、目录结构

```
pppoe_hijack_py3.py            主程序（v2.1）：协议引擎 + 嗅探/发送/落盘管线 + 现代设备适配
config.example.toml            全量配置示例（注释版，等价于 CLI 参数）
requirements.txt               scapy
README.md                      本文
评估报告.md                    可用性取证：三道门槛、scapy 2.7 断点对照、原版缺陷
优化实施说明.md                v2.0 优化清单逐项 → 代码落点 → 验证用例
现代设备适配.md                v2.1 十三个新方法、现网 VLAN 参考、落盘字段、存疑项
OpenWrt部署.md                 OpenWrt/软路由部署、透明桥、抓不到时的排查表
tests/test_offline.py          离线回归：构造报文喂引擎、逐字节断言回包（128 条断言）
tests/test_replay.py           端到端：pcap → main(--replay) → 出包 pcap + 两种存储（12 条断言）
tools/router_sniff.py          OpenWrt 免依赖抓包（AF_PACKET 原始套接字，绕开坏掉的 tcpdump）
tools/ssh_run.py               远程执行 / SFTP 小工具（凭据只从环境变量读，不含默认口令）
tools/probe_*.py               环境探测：scapy 类名/字段、Ether↔PPP 绑定、Npcap 可用性
legacy/scapy-pppoe.py          2016 原版留档（未改动，对照用）
legacy/pppoe_hijack_py3.v1.py  v1 最小移植（仅修语法/API，行为与原版一致）
legacy/test_offline.v1.py      v1 的离线用例（历史留档）
```

## 七、验证状态

```
tests/test_offline.py   128 PASS / 0 FAIL（34 组用例 A–AH）
tests/test_replay.py     12 PASS / 0 FAIL（含 VLAN 端到端场景）
pyflakes                 clean
实机冒烟（本机无 Npcap）  退出码 2 + 安装提示（--dry-run / --profile 路径同样验证过）
```

离线用例覆盖：发现阶段 tag 回显与 sessionid 分配、LCP 三分支、PAP 截获与 id 回显、CHAP/MS-CHAPv2 全链、
Echo/Terminate/TTL/重传去重、IPCP、IPv6CP、VLAN 单/双标签与强制插入、Service-Name 严格模式、
Relay-Session-Id、AC-Cookie、PPP-Max-Payload、多拨双会话、MRU、EAPOL、DHCP、OUI、SQLite 老库迁移、
配置优先级（CLI/TOML）、限速、自环与 BPF。

## 八、限制与已知问题

- 本项目实机验证是在**无 Npcap** 的 Windows 上做的，二层真实收发路径未经真机核对
  （离线帧级与 pcap 回放已覆盖）；Windows 上跑请先装 Npcap（勾 WinPcap 兼容模式）。
- **MS-CHAPv2 只能记录**：hashcat **没有**原生 MS-CHAPv2 模式（`-m 5500` 是 NetNTLMv1），
  要爆破需先离线还原 NT hash（chapcrack / asleap 路线）。
- 默认模式下**刻意保留**原版那个「LCP-Config-Req 长度字段写 18」的怪癖，以保持与原版逐字节一致；
  `--strict-rfc` 才按 RFC 1661 写 18（真实长度 4+14）并去掉 4 个悬空 `\x00`。
- 现网 VLAN 值（北京联通 3961/3964/3969/4000、浙江电信 IPTV 43、上海电信 1045、四川 b41 等）
  属**地区实测经验，不是全国规范**，务必以自己线路上抓到的为准。
- 旁路指纹（802.1X / DHCP）在**家宽**场景基本抓不到，主要出现在校园网与企业网。
- 用 `ebtables` 挡发现帧、或抢答成功，都会让**对方设备掉线**（一般几秒到几十秒后自动重拨）。

## 九、合规

本项目是网络协议研究与教学工具。请只在你**自己拥有**或**已获明确书面授权**的线路、设备、实验环境里使用；
用它去截获他人的拨号凭据在许多司法辖区是违法的。作者不对任何滥用负责。
