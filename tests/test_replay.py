# -*- coding: utf-8 -*-
"""--replay 回归：用 pcap 驱动整条流水线（不需要网卡、不需要 Npcap）

流程: 造一个 pcap → main(--replay) 跑一遍 → 检查 1) 出包写了 pcap 2) 凭据落了盘
这条路径就是为了在没有 Npcap 的机器上也能验证/回归。
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pppoe_hijack_py3 as H
from scapy.utils import PcapReader, PcapWriter

CLI = "11:22:33:44:55:66"
SRV = "0a:0a:0a:0a:0a:0a"
WORK = tempfile.mkdtemp(prefix="pppoe_replay_")
SRC = os.path.join(WORK, "client.pcap")
TX = os.path.join(WORK, "our-replies.pcap")
CREDS = os.path.join(WORK, "creds.jsonl")

FAILED = []


def hexmac(mac):
    return mac.replace(":", "").lower()


def disc(code, tags_hex, src=CLI, dst="ff:ff:ff:ff:ff:ff"):
    body = "%02x" % code + "0000" + ("%04x" % (len(tags_hex) // 2)) + tags_hex
    return H.Ether(bytes.fromhex(hexmac(dst) + hexmac(src) + "8863" + "11" + body))


def sess(proto, payload_hex, src=CLI, sid=1, dst=SRV):
    plen = len(payload_hex) // 2
    body = "00" + "%04x" % sid + "%04x" % (plen + 2) + "%04x" % proto + payload_hex
    return H.Ether(bytes.fromhex(hexmac(dst) + hexmac(src) + "8864" + "11" + body))


def decode(frame: bytes) -> dict:
    et = int.from_bytes(frame[12:14], "big")
    sid = int.from_bytes(frame[16:18], "big")
    plen = int.from_bytes(frame[18:20], "big")
    body = frame[20:20 + plen]
    proto = int.from_bytes(body[:2], "big") if et == 0x8864 else None
    return {"et": et, "code": frame[15], "sid": sid,
            "proto": proto, "payload": body[2:] if et == 0x8864 else body}


def check(label, cond, detail=""):
    print(("  [PASS] " if cond else "  [FAIL] ") + label + (("   " + str(detail)) if detail else ""))
    if not cond:
        FAILED.append(label)


print("工作目录:", WORK)

# ---------------------------------------------------------------- 造客户端 pcap
OUR_OPTS = "010405c80304c02305065e630ab800000000"
user, passwd = b"user01", b"pass123"
pap_body = ("01" + "08" + "%04x" % (5 + len(user) + len(passwd))
            + "%02x" % len(user) + user.hex() + "%02x" % len(passwd) + passwd.hex())

frames = [
    disc(0x09, "0101000001030004aabbccdd"),          # PADI
    disc(0x19, "0101000001030004aabbccdd"),          # PADR
    sess(0xC021, "0107000e010405dc05065e630ab8"),    # 客户端 LCP Config-Req
    sess(0xC021, "02010012" + OUR_OPTS),             # 客户端 Ack 我方 Req → LCP up
    sess(0xC023, pap_body),                          # PAP Auth-Req（明文账号密码）
]
w = PcapWriter(SRC, linktype=1, sync=True)
for f in frames:
    w.write(f)
w.close()
print("输入 pcap: %d 帧" % len(frames))

# ---------------------------------------------------------------- 跑 --replay
rc = H.main(["--replay", SRC, "--pcap-out", TX, "--store", CREDS, "-q"])
check("main(--replay) 退出码 0", rc == 0, "rc=%s" % rc)

# ---------------------------------------------------------------- 看出包
out_frames = []
with PcapReader(TX) as r:
    for pkt in r:
        out_frames.append(decode(bytes(pkt)))
print("出包 pcap: %d 帧" % len(out_frames))
for i, d in enumerate(out_frames, 1):
    print("  #%d eth=%#06x code=%#04x sid=%#06x proto=%s payload=%s"
          % (i, d["et"], d["code"], d["sid"],
             ("%#06x" % d["proto"]) if d["proto"] else "-", d["payload"].hex()))
check("出包数量 = PADO + PADS + (Ack+Nak+我方Req) + PAP Nak = 6", len(out_frames) == 6)
check("第1个出包 = PADO(0x07)",
      out_frames[0]["et"] == 0x8863 and out_frames[0]["code"] == 0x07)
check("第2个出包 = PADS(0x65) 且带 sessionid",
      out_frames[1]["code"] == 0x65 and out_frames[1]["sid"] == 1)
last = out_frames[-1]
check("最后一个出包 = PAP Nak 且回显客户端 id 0x08",
      last["proto"] == 0xC023 and last["payload"].hex() == "030800060100")

# ---------------------------------------------------------------- 看落盘
with open(CREDS, encoding="utf-8") as fh:
    lines = [ln for ln in fh.read().splitlines() if ln.strip()]
print("凭据文件:", lines)
check("只落 1 条凭据", len(lines) == 1)
rec = json.loads(lines[0]) if lines else {}
check("字段完整（时间/sessionid/BRAS MAC/认证类型/原始 hex/网卡）",
      rec.get("username") == "user01" and rec.get("password") == "pass123"
      and rec.get("auth") == "pap" and rec.get("sessionid") == "0x0001"
      and rec.get("bras_mac") == SRV and rec.get("ac_name") == "^_^"
      and rec.get("raw") == pap_body and rec.get("ts"))

# ---------------------------------------------------------------- 再跑一次 SQLite + --ipcp
DB = os.path.join(WORK, "creds.db")
rc2 = H.main(["--replay", SRC, "--store", DB, "--pap-mode", "ack", "--ipcp", "on", "-q"])
import sqlite3
conn = sqlite3.connect(DB)
row = conn.execute("SELECT username, password, auth FROM creds").fetchone()
conn.close()
print("sqlite 行:", row)
check("SQLite 落盘同样成功", rc2 == 0 and row == ("user01", "pass123", "pap"))

# ---------------------------------------------------------------- VLAN 场景（v2.1）
TXV = os.path.join(WORK, "our-replies-vlan.pcap")
CREDSV = os.path.join(WORK, "creds-vlan.jsonl")
SRCV = os.path.join(WORK, "client-vlan.pcap")
TAG = "8100" + "002b"                                   # 802.1Q, pcp=0, vid=43


def with_vlan(frame):
    """把一层 802.1Q tag 插到以太类型之前"""
    return H.Ether(bytes(frame)[:12] + bytes.fromhex(TAG) + bytes(frame)[12:])


vf = [with_vlan(f) for f in frames]
w = PcapWriter(SRCV, linktype=1, sync=True)
for f in vf:
    w.write(f)
w.close()

rc3 = H.main(["--replay", SRCV, "--pcap-out", TXV, "--store", CREDSV,
              "--vlan", "auto", "-q"])
check("VLAN 场景 main(--replay) 退出码 0", rc3 == 0, "rc=%s" % rc3)

vout = []
with PcapReader(TXV) as r:
    for pkt in r:
        vout.append(bytes(pkt))
check("带 VLAN 的输入也能出 6 帧", len(vout) == 6, "n=%d" % len(vout))
check("每个出包都带回同一个 tag（跟随客户端）",
      all(f[12:16].hex() == TAG for f in vout) and vout[0][16:18].hex() == "8863",
      vout[0][:20].hex() if vout else "-")
with open(CREDSV, encoding="utf-8") as fh:
    vrec = json.loads([ln for ln in fh.read().splitlines() if ln.strip()][0])
check("凭据里记下了 VLAN", vrec.get("vlan") == "43", vrec.get("vlan"))

# ---------------------------------------------------------------- 收尾

print()
if FAILED:
    print("失败 %d 项: %s" % (len(FAILED), FAILED))
    sys.exit(1)
print("--replay 流水线全部通过。")
