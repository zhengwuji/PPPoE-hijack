#!/usr/bin/env python3
"""通过 SSH 在软路由上执行命令（一次性探测用）

用法:
    python ssh_run.py "命令"                 # 直接跑一条命令
    python ssh_run.py -f script.sh           # 跑脚本文件里的全部命令
    python ssh_run.py --get /path/local /remote   # 拉文件（SFTP）
    python ssh_run.py --put /path/local /remote   # 推文件（SFTP）
环境变量: ROUTER_HOST（必填）、ROUTER_PASS（必填）、ROUTER_PORT（默认 22）、ROUTER_USER（默认 root）
注意: 本脚本不含任何默认地址或口令，凭据一律从环境变量读取，勿写进代码。
"""
import os
import sys

import paramiko

HOST = os.environ.get("ROUTER_HOST", "")
PORT = int(os.environ.get("ROUTER_PORT", "22"))
USER = os.environ.get("ROUTER_USER", "root")
PASS = os.environ.get("ROUTER_PASS", "")

if not HOST or not PASS:
    sys.exit("必须用环境变量提供目标地址与口令：\n"
             "  ROUTER_HOST=<路由器IP>  ROUTER_PASS=<口令>\n"
             "可选: ROUTER_PORT（默认 22）、ROUTER_USER（默认 root）\n"
             "示例（PowerShell）: $env:ROUTER_HOST='192.168.1.1'; $env:ROUTER_PASS='***';\n"
             "                    python tools/ssh_run.py \"ubus call system board\"")


def connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS,
              timeout=15, banner_timeout=20, auth_timeout=20,
              look_for_keys=False, allow_agent=False)
    return c


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 2

    if args[0] == "--get":
        local, remote = args[1], args[2]
        c = connect()
        sf = c.open_sftp()
        sf.get(remote, local)
        sf.close()
        c.close()
        print("已取回 %s -> %s (%d 字节)" % (remote, local, os.path.getsize(local)))
        return 0

    if args[0] == "--put":
        local, remote = args[1], args[2]
        c = connect()
        sf = c.open_sftp()
        sf.put(local, remote)
        sf.close()
        c.close()
        print("已上传 %s -> %s" % (local, remote))
        return 0

    if args[0] == "-f":
        with open(args[1], encoding="utf-8") as fh:
            cmd = fh.read()
    else:
        cmd = args[0]

    c = connect()
    stdin, stdout, stderr = c.exec_command(cmd, timeout=180, get_pty=False)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    rc = stdout.channel.recv_exit_status()
    sys.stdout.write(out)
    if err.strip():
        sys.stdout.write("\n--- stderr ---\n" + err)
    print("[rc=%d]" % rc)
    c.close()
    return 0 if rc == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
