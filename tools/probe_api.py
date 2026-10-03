# -*- coding: utf-8 -*-
"""Probe: does the 2016 script's scapy API surface still exist in scapy 2.7.0 / Python 3.12?"""
import os, sys, struct, traceback

print("python", sys.version.split()[0])

print("\n[1] compile original source as-is")
_HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(_HERE, "..", "legacy", "scapy-pppoe.py"), "rb").read()
try:
    compile(src, "scapy-pppoe.py", "exec")
    print("   compiled OK")
except SyntaxError as e:
    print("   SyntaxError:", e.msg, "line", e.lineno)

print("\n[2] scapy layer imports")
try:
    from scapy.layers.ppp import *
    print("   from scapy.layers.ppp import *  -> OK")
except Exception as e:
    print("   FAIL:", e)

for name in ("PPPoE", "PPPoED", "PPP", "PAP", "PPP_LCP", "CHAP"):
    print("   %-8s %s" % (name, "present" if name in globals() else "MISSING"))

print("\n[3] PPPoE field names")
print("   PPPoE fields:", [f.name for f in PPPoE.fields_desc])
print("   PPP  fields:", [f.name for f in PPP.fields_desc])
print("   PAP  fields:", [f.name for f in PAP.fields_desc])

print("\n[4] build a PADI like the script sniffs, then exercise .type/.code/.load")
padi = (Ether(src="11:22:33:44:55:66", dst="ff:ff:ff:ff:ff:ff", type=0x8863)
        / PPPoE(version=0x1, type=0x1, code=0x09, sessionid=0x0000)
        / Raw(load=b"\x01\x01\x00\x00\x01\x03\x00\x04\xaa\xbb\xcc\xdd"))
print("   raw.type =", hex(padi.type))
print("   raw.code =", hex(padi.code))
try:
    print("   raw.load (get) =", padi.load)
except Exception as e:
    print("   raw.load (get) FAIL:", type(e).__name__, e)

print("\n[5] try old-style write:  raw.load = b'...'")
try:
    padi.load = b"\x01\x01\x00\x00"
    print("   setattr OK ->", repr(padi.load))
    print("   does it reach the wire? bytes(padi) tail =", bytes(padi)[-12:])
except Exception as e:
    print("   setattr FAIL:", type(e).__name__, e)

print("\n[6] py2 idiom struct.unpack('!B', bytes[4])")
s = b"\x01\x02\x00\x06\x01\x00"
try:
    print("   struct.unpack('!B', s[4]) =", struct.unpack("!B", s[4]))
except Exception as e:
    print("   FAIL:", type(e).__name__, e)

print("\n[7] PAP parse arithmetic on py3 (user len at [4], pass len at [5+n])")
pap = b"\x01\x01\x00\x16\x04u123\x06passwd"
try:
    nlen = pap[4]
    print("   pap[4] =", nlen, type(nlen).__name__, "-> \x05+n index needs int math")
except Exception as e:
    print("   FAIL:", e)

print("\n[8] session-stage packet: PPPoE code field on a session frame")
sess = (Ether(src="11:22:33:44:55:66", dst="0a:0a:0a:0a:0a:0a", type=0x8864)
        / PPPoE(version=0x1, type=0x1, code=0x00, sessionid=0x0001)
        / PPP(proto=0xc023) / PAP(code=0x01))
print("   sess.type =", hex(sess.type), " sess[PPPoE].code =", hex(sess[PPPoE].code))
print("   sess proto  =", hex(sess[PPP].proto) if sess.haslayer(PPP) else "no PPP")
print("   bytes(sess) head =", bytes(sess)[:20].hex(" "))

print("\n[9] scapy.sniff signature has lfilter?")
import inspect
print("   ", "lfilter" in inspect.signature(__import__("scapy.all", fromlist=["sniff"]).sniff).parameters)
