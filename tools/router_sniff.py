#!/usr/bin/env python3
"""纯 AF_PACKET 嗅探器（不依赖 scapy / libpcap）

用途：在软路由上确认到底能不能看到 PPPoE(0x8863/0x8864)、802.1X(0x888e)
和带 VLAN 标签的帧，并把命中的帧写成 pcap 便于回传到 PC 用 --replay 离线解。

用法:  python3 -u sniff.py <iface> <秒数> [输出.pcap]
"""
import collections
import socket
import struct
import sys
import time

VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)
WATCH = (0x8863, 0x8864, 0x888E)
# 有些精简版 python3（OpenWrt）没有导出这些常量，用字面值兜底
AF_PACKET = getattr(socket, "AF_PACKET", 17)
ETH_P_ALL = 0x0003
SOL_PACKET = getattr(socket, "SOL_PACKET", 263)
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1


def parse_ethertype(frame):
    """返回 (最内层以太类型, 是否带 VLAN, 标签数)"""
    off = 12
    tags = 0
    if len(frame) < 14:
        return None, False, 0
    et = struct.unpack("!H", frame[off:off + 2])[0]
    while et in VLAN_TPIDS and len(frame) >= off + 6:
        et = struct.unpack("!H", frame[off + 4:off + 6])[0]
        off += 4
        tags += 1
    return et, tags > 0, tags


def mac(b):
    return ":".join("%02x" % x for x in b)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    iface = sys.argv[1]
    dur = float(sys.argv[2])
    out = sys.argv[3] if len(sys.argv) > 3 else None

    s = socket.socket(AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((iface, 0))
    # 打开混杂模式（socket 关闭时自动还原，不改接口配置持久状态）
    try:
        mreq = struct.pack("IHH8s", socket.if_nametoindex(iface), PACKET_MR_PROMISC, 0, b"")
        s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
    except (OSError, AttributeError) as exc:
        print("  (混杂模式设置失败，忽略: %s)" % exc)
    s.settimeout(0.5)

    fh = None
    if out:
        fh = open(out, "wb")
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # linktype=EN10MB

    hist = collections.Counter()
    hits = 0
    total = 0
    t0 = time.time()
    print("[*] %s 上嗅探 %.0f 秒（混杂模式已开）…" % (iface, dur))
    while time.time() - t0 < dur:
        try:
            frame = s.recv(65535)
        except socket.timeout:
            continue
        except OSError as exc:
            print("  recv 出错: %s" % exc)
            break
        if len(frame) < 14:
            continue
        total += 1
        et, tagged, ntags = parse_ethertype(frame)
        hist[et] += 1
        if et in WATCH or tagged:
            hits += 1
            tagtxt = (" VLANx%d" % ntags) if tagged else ""
            print("%7.2fs len=%4d et=0x%04x%s  %s -> %s" % (
                time.time() - t0, len(frame), et, tagtxt, mac(frame[6:12]), mac(frame[0:6])))
            if fh:
                ts = time.time()
                fh.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame)))
                fh.write(frame)
            if hits >= 500:
                break
    s.close()
    if fh:
        fh.close()
        print("[*] 命中帧已写入 %s" % out)
    print("--- %s 以太类型直方图（前 15）---" % iface)
    for k, v in hist.most_common(15):
        if k is None:
            continue
        print("  0x%04x  %d" % (k, v))
    print("[=] 总帧=%d  命中(PPPoE/EAPOL/VLAN)=%d" % (total, hits))
    return 0


if __name__ == "__main__":
    sys.exit(main())
