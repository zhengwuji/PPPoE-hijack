# -*- coding: utf-8 -*-
"""Probe 2 (fixed): how does a *sniffed* frame dissect in scapy 2.7, and does the
   script's byte-patching trick (raw.load = ...) still reach the wire?"""
import struct
from scapy.all import Ether, Raw, conf
from scapy.layers.ppp import *

def D(hexstr):
    return Ether(bytes.fromhex(hexstr))

# ---- 1. LCP Config-Req as captured: Ether/PPPoE(session)/PPP(0xc021)/LCP --------------
lcp_req = ("112233445566 0a0a0a0a0a0a 8864"
           "1100 0001 0014"
           "c021 0101 000e 0104 05dc 0506 5e630ab8")
p = D(lcp_req)
print("=== LCP Config-Req ===")
print("class chain :", p.summary())
print("p.type      :", hex(p.type))
print("has PPPoE   :", p.haslayer(PPPoE), "| code =", hex(p[PPPoE].code), "| sessionid =", hex(p[PPPoE].sessionid))
print("has PPP     :", p.haslayer(PPP), "| proto =", hex(p[PPP].proto))
print("has LCP     :", p.haslayer(PPP_LCP))
for attr in ("load", "code"):
    try:
        print("  getattr .%-5s ->" % attr, repr(getattr(p, attr)))
    except Exception as e:
        print("  getattr .%-5s -> FAIL: %s: %s" % (attr, type(e).__name__, e))

print("\n--- old trick: p.load = b'\\x02' + p.load[1:] ---")
try:
    p.load = b"\x02" + p.load[1:]
    print("setattr OK; p.load now", repr(p.load))
except Exception as e:
    print("setattr FAIL:", type(e).__name__, e)
print("re-serialized       :", bytes(p).hex())
print("identical to wire?  :", bytes(p).hex() == lcp_req.replace(" ", ""))

print("\n--- correct modern equivalent: rewrite the LCP field, then re-serialize ---")
p2 = D(lcp_req)
p2[PPP_LCP].code = 2          # Ack
print("code now            :", p2[PPP_LCP].code)
print("byte 0x0f/0x14 area :", bytes(p2)[-16:].hex())

# ---- 2. PAP Authenticate-Request, the packet that carries the credentials --------------
pap = ("112233445566 0a0a0a0a0a0a 8864"
       "1100 0001 001a"
       "c023 0101 0016 04 757365723031 06 70617373313233")
q = D(pap)
print("\n=== PAP Auth-Req ===")
print("class chain :", q.summary())
print("PPP proto   :", hex(q[PPP].proto))
print("has PPP_PAP :", q.haslayer(PPP_PAP))
for attr in ("load", "code", "data"):
    try:
        print("  getattr .%-5s ->" % attr, repr(getattr(q, attr)))
    except Exception as e:
        print("  getattr .%-5s -> FAIL: %s: %s" % (attr, type(e).__name__, e))
try:
    print("  q['Raw']  ->", repr(bytes(q[Raw].load)))
except Exception as e:
    print("  q['Raw']  -> FAIL:", type(e).__name__, e)

# ---- 3. PADI ------------------------------------------------------------------------
padi = ("ffffffffffff 112233445566 8863"
        "1109 0000 000c"
        "0101 0000 0103 0004 aabbccdd")
d = D(padi)
print("\n=== PADI ===")
print("class chain :", d.summary())
print("d.type      :", hex(d.type))
for attr in ("code", "sessionid", "len", "load"):
    try:
        print("  getattr .%-9s ->" % attr, repr(getattr(d, attr)))
    except Exception as e:
        print("  getattr .%-9s -> FAIL: %s: %s" % (attr, type(e).__name__, e))

print("\n--- old trick on the discovery frame ---")
raw_bytes = bytes(d[Raw].load) if d.haslayer(Raw) else None
print("  padi_find_hostuniq would search:", repr(raw_bytes))
_key = b"\x01\x03"
if raw_bytes and _key in raw_bytes:
    i = raw_bytes.index(_key)
    n = struct.unpack("!H", raw_bytes[i + 2:i + 4])[0]
    print("  host-uniq found, payload half =", (_key + raw_bytes[i + 2:i + 4 + n]).hex())

# ---- 4. build forged PADO the modern way --------------------------------------------
print("\n=== forged PADO (layers, modern equivalent) ===")
pay = b"\x01\x01\x00\x00" + b"\x01\x03\x00\x04" + b"\xaa\xbb\xcc\xdd"
pado = (Ether(src="0a:0a:0a:0a:0a:0a", dst="11:22:33:44:55:66", type=0x8863)
        / PPPoE(version=1, type=1, code=0x07, sessionid=0)
        / Raw(load=pay))
pado.len = len(pay)
print("bytes        :", bytes(pado).hex(" "))
back = Ether(bytes(pado))
print("re-dissects  :", back.summary(), "| len field =", back.len)

# ---- 5. plumbing --------------------------------------------------------------------
print("\n=== datalink plumbing ===")
print("conf.use_pcap :", getattr(conf, "use_pcap", None))
print("conf.iface    :", conf.iface)
try:
    from scapy.arch.windows import NPCAP_PATH
    print("NPCAP_PATH    :", NPCAP_PATH)
except Exception as e:
    print("NPCAP_PATH    : n/a")
import os
print("wpcap.dll in System32:", os.path.exists(r"C:\Windows\System32\wpcap.dll"))
print("Packet.dll in System32:", os.path.exists(r"C:\Windows\System32\Packet.dll"))
