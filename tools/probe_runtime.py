# -*- coding: utf-8 -*-
"""探测本机能否真正做二层收发（sniff/sendp），不发送任何报文。"""
import os, traceback
from scapy.all import conf, get_working_ifaces, sniff

print("scapy      :", __import__("scapy").__version__)
print("conf.use_pcap :", getattr(conf, "use_pcap", None))
print("conf.use_npcap:", getattr(conf, "use_npcap", None))
print("conf.iface    :", conf.iface)
print("wpcap.dll  :", os.path.exists(r"C:\Windows\System32\wpcap.dll"))
print("Packet.dll :", os.path.exists(r"C:\Windows\System32\Packet.dll"))
print("\n可用网卡:")
try:
    for i in get_working_ifaces():
        print("   %-24s %s" % (getattr(i, "name", "?"), getattr(i, "description", "")))
except Exception as e:
    print("   FAIL:", type(e).__name__, e)

print("\n尝试打开二层抓包句柄（timeout=1s）：")
try:
    pkts = sniff(iface="以太网", timeout=1, count=0, store=False)
    print("   OK，抓到", len(pkts) if pkts else 0, "个（0 也正常，说明句柄能开）")
except Exception as e:
    print("   FAIL:", type(e).__name__, ":", e)
    traceback.print_exc(limit=2)

print("\n尝试构造 L2 发送套接字（不发包）：")
try:
    from scapy.arch.windows import NetworkInterface
    from scapy.sendrecv import L2Socket
    s = L2Socket(iface="以太网")
    print("   OK:", s)
    s.close()
except Exception as e:
    print("   FAIL:", type(e).__name__, ":", e)
