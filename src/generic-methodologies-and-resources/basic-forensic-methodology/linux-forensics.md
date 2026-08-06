# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Початковий збір інформації

### Базова інформація

Перш за все рекомендується мати **USB** з **перевіреними бінарними файлами та бібліотеками** (можна просто взяти ubuntu і скопіювати папки _/bin_, _/sbin_, _/lib,_ та _/lib64_), потім підключити USB і змінити змінні середовища, щоб використовувати ці бінарні файли:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Після налаштування системи для використання надійних і відомих бінарних файлів можна почати **отримувати базову інформацію**:
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### Підозріла інформація

Під час отримання базової інформації слід перевіряти дивні речі, наприклад:

- **Root processes** зазвичай запускаються з низькими PIDS, тому, якщо ви знайдете root process із великим PID, це може викликати підозру
- Перевірте **зареєстровані логіни** користувачів без shell у `/etc/passwd`
- Перевірте наявність **хешів паролів** у `/etc/shadow` для користувачів без shell

### Дамп пам'яті

Щоб отримати пам'ять запущеної системи, рекомендується використовувати [**LiME**](https://github.com/504ensicsLabs/LiME).\
Щоб його **скомпілювати**, потрібно використовувати **те саме ядро**, яке використовується на машині жертви.

> [!TIP]
> Пам'ятайте, що ви **не можете встановлювати LiME або будь-що інше** на машині жертви, оскільки це внесе до неї кілька змін

Отже, якщо у вас є ідентична версія Ubuntu, ви можете використати `apt-get install lime-forensics-dkms`\
В інших випадках потрібно завантажити [**LiME**](https://github.com/504ensicsLabs/LiME) з github і скомпілювати його з правильними заголовками ядра. Щоб **отримати точні заголовки ядра** машини жертви, можна просто **скопіювати директорію** `/lib/modules/<kernel version>` на свою машину, а потім **скомпілювати** LiME, використовуючи їх:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME підтримує 3 **формати**:

- Raw (кожен сегмент об'єднано разом)
- Padded (те саме, що й raw, але з нулями у правих бітах)
- Lime (рекомендований формат із метаданими

LiME також можна використовувати для **надсилання дампа через мережу**, замість його зберігання в системі, використовуючи щось на кшталт: `path=tcp:4444`

### Створення образу диска

#### Вимкнення

Перш за все, вам потрібно буде **вимкнути систему**. Це не завжди можливо, оскільки іноді система є production-сервером, який компанія не може дозволити собі вимкнути.\
Існує **2 способи** вимкнути систему: **звичайне вимкнення** та вимкнення шляхом **«висмикування штекера»**. Перший спосіб дозволить **процесам завершитися як зазвичай**, а **файловій системі** — **синхронізуватися**, але водночас він дасть можливому **malware** змогу **знищити докази**. Підхід із «висмикуванням штекера» може призвести до **певної втрати інформації** (втратиться не так багато інформації, оскільки ми вже створили образ пам'яті), а **malware не матиме жодної можливості** щось із цим зробити. Тому, якщо ви **підозрюєте**, що може бути **malware**, просто виконайте **команду** **`sync`** у системі та висмикніть штекер.

#### Створення образу диска

Важливо зазначити, що **перед підключенням комп'ютера до будь-чого, пов'язаного зі справою**, потрібно переконатися, що його буде **змонтовано лише для читання**, щоб уникнути зміни будь-якої інформації.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Попередній аналіз образу диска

Створення образу диска без додаткових даних.
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
## Пошук відомого Malware

### Змінені системні файли

Linux пропонує інструменти для перевірки цілісності системних компонентів, що має вирішальне значення для виявлення потенційно проблемних файлів.<sup>[[1]](#references)</sup>

- **Системи на базі RedHat**: використовуйте `rpm -Va` для комплексної перевірки.
- **Системи на базі Debian**: використовуйте `dpkg --verify` для первинної перевірки, а потім `debsums | grep -v "OK$"` (після встановлення `debsums` за допомогою `apt-get install debsums`), щоб виявити будь-які проблеми.

### Засоби виявлення Malware/Rootkit

Прочитайте наведену нижче сторінку, щоб дізнатися про інструменти, які можуть бути корисними для пошуку Malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Пошук встановлених програм

Для ефективного пошуку встановлених програм у системах Debian і RedHat розгляньте можливість використання системних журналів і баз даних разом із ручними перевірками у стандартних каталогах.<sup>[[1]](#references)</sup>

- Для Debian перевірте _**`/var/lib/dpkg/status`**_ і _**`/var/log/dpkg.log`**_, щоб отримати відомості про встановлення пакетів, використовуючи `grep` для фільтрації конкретної інформації.
- Користувачі RedHat можуть виконати запит до RPM database за допомогою `rpm -qa --root=/mntpath/var/lib/rpm`, щоб переглянути список встановлених пакетів.

Щоб виявити програмне забезпечення, встановлене вручну або поза межами цих package manager, перевірте такі каталоги, як _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ і _**`/sbin`**_. Поєднуйте перегляд вмісту каталогів із системними командами, щоб ідентифікувати виконувані файли, не пов'язані з відомими пакетами, розширюючи пошук усіх встановлених програм.
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
## Відновлення видалених запущених бінарних файлів

Уявімо процес, який було запущено з `/tmp/exec`, а потім видалено. Його можна витягти
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Тріаж трасування системних викликів за допомогою SQLite та FTS5

Якщо процес усе ще працює або його можна повторно запустити в лабораторному середовищі, **`strace`** може швидко надати поведінкове трасування без потреби в kernel modules або повній телеметрії EDR. Для великих трас не читайте сирий лог безпосередньо й не вставляйте його в LLM: збережіть його в базі даних **SQLite** і запитуйте лише мінімальну потрібну підмножину.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> Підключення `strace` змінює часове виконання процесу й може вплинути на race conditions або інші нестабільні bugs. За можливості відтворюйте їх у копії або лабораторній системі.

### Збір

Для нового процесу:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Для запущеного процесу:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Корисні параметри:

- `-ff`: відстежувати fork/thread і зберігати окремі результати для кожного процесу
- `-ttt`: часові мітки epoch для зручного зіставлення в timeline
- `-yy`: за можливості визначати шляхи або сокети, що відповідають файловим дескрипторам
- `-s 4096`: запобігати обрізанню довгих аргументів шляхів і буферів

### Нормалізація

Практична схема передбачає один рядок на кожен syscall і один рядок на кожен аргумент:
```sql
CREATE TABLE syscalls (
id        INTEGER PRIMARY KEY,
pid       INTEGER NOT NULL,
timestamp REAL    NOT NULL,
name      TEXT    NOT NULL,
ret_val   INTEGER,
errno     TEXT
);

CREATE TABLE syscall_args (
id         INTEGER PRIMARY KEY,
syscall_id INTEGER NOT NULL REFERENCES syscalls(id),
position   INTEGER NOT NULL,
raw        TEXT    NOT NULL,
type       INTEGER NOT NULL
);
```
Це уникає спроб звести різнорідні рядки syscall до однієї широкої таблиці та забезпечує передбачувані об'єднання під час triage.

### Індексуйте текстові аргументи за допомогою FTS5

Наївний пошук шляхів за допомогою `LIKE "%...%"` стає дуже повільним на великих трасуваннях. Створіть індекс FTS5 для тексту аргументів і виконуйте пошук у ньому:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Приклад: відновити файлову активність у `/tmp`, не скануючи кожен рядок:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Розслідування з високою інформативністю

- **PATH hijacking / fake sudo**: шукайте операції запису та `chmod`/`rename` у `~/.local/bin/`, а потім зіставляйте їх із подальшими викликами `execve` для назв, що виглядають привілейованими, наприклад `sudo`.
- **TOCTOU on temporary files**: відстежуйте той самий шлях `/tmp/...` у викликах `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` і `execve`, щоб виявити розриви між перевіркою та використанням.
- **Причина збою**: зіставте `mmap` файлу із записом або обрізанням того самого inode/шляху іншим процесом, а потім перевірте послідовність сигналів/завершення процесу на наявність `SIGBUS`.
- **Відновлення мережевого призначення**: фільтруйте `connect`, `sendto`, `sendmsg`, `recvfrom` і аргументи, пов’язані із сокетами, щоб отримати IP-адреси та порти вузлів-партнерів.

### Аналіз trace за допомогою LLM

Якщо ви хочете залучити LLM, надайте йому **read-only** дескриптор SQLite і повну схему. Дозвольте йому виконувати необроблений SQL замість обгортання бази даних вузькими допоміжними функціями. Зазвичай це краще працює для об’єднань, часової кореляції та пошуку FTS.

Практичні правила:

- Зробіть базу даних read-only, наприклад за допомогою `sqlite3 'file:trace.db?mode=ro'`.
- Надайте моделі приклади коректних запитів `JOIN` і `FTS5 MATCH`.
- **Не** вставляйте необроблені багатогігабайтні логи `strace` у prompt.
- Ставте сфокусовані запитання, наприклад:
- "List persistent files written by this program."
- "Did it create or replace executables in user-controlled PATH directories?"
- "Explain why this trace ends in SIGBUS."

## Перевірка розташувань Autostart

### Заплановані завдання
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
#### Пошук: зловживання Cron/Anacron через 0anacron і підозрілі заглушки
Зловмисники часто редагують заглушку 0anacron, наявну в кожному каталозі /etc/cron.*/, щоб забезпечити періодичне виконання.<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Полювання: відкат hardening SSH і backdoor shells
Зміни до sshd_config і оболонок системних облікових записів є поширеним способом збереження доступу після post-exploitation.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Пошук: ознаки Cloud C2 (Dropbox/Cloudflare Tunnel)
- Dropbox API-маяки зазвичай використовують api.dropboxapi.com або content.dropboxapi.com через HTTPS із токенами Authorization: Bearer.
- Виконуйте пошук у proxy/Zeek/NetFlow неочікуваного вихідного трафіку Dropbox із серверів.
- Cloudflare Tunnel (`cloudflared`) забезпечує резервний C2 через вихідний порт 443.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Сервіси

Шляхи, де malware може бути встановлено як сервіс:

- **/etc/inittab**: Викликає скрипти ініціалізації, як-от rc.sysinit, які надалі спрямовують виконання до скриптів запуску.
- **/etc/rc.d/** та **/etc/rc.boot/**: Містять скрипти запуску сервісів; останній каталог зустрічається у старіших версіях Linux.
- **/etc/init.d/**: Використовується в певних версіях Linux, наприклад Debian, для зберігання скриптів запуску.
- Сервіси також можуть активуватися через **/etc/inetd.conf** або **/etc/xinetd/**, залежно від варіанта Linux.
- **/etc/systemd/system**: Каталог для скриптів system і service manager.
- **/etc/systemd/system/multi-user.target.wants/**: Містить посилання на сервіси, які мають запускатися на багатокористувацькому runlevel.
- **/usr/local/etc/rc.d/**: Для власних або сторонніх сервісів.
- **\~/.config/autostart/**: Для автоматичного запуску застосунків, специфічних для користувача; може бути місцем приховування malware, націленого на користувача.
- **/lib/systemd/system/**: Загальносистемні стандартні unit files, надані встановленими пакетами.

#### Пошук: systemd timers і transient units

Persistence у systemd не обмежується файлами `.service`. Досліджуйте `.timer` units, units на рівні користувача та **transient units**, створені під час виконання.
```bash
# Enumerate timers and inspect referenced services
systemctl list-timers --all
systemctl cat <name>.timer
systemctl cat <name>.service

# Search common system and user paths
find /etc/systemd/system /run/systemd/system /usr/lib/systemd/system -maxdepth 3 \( -name '*.service' -o -name '*.timer' \) -ls
find /home -path '*/.config/systemd/user/*' -type f \( -name '*.service' -o -name '*.timer' \) -ls

# Transient units created via systemd-run often land here
find /run/systemd/transient -maxdepth 2 -type f -ls 2>/dev/null

# Pull execution history for a suspicious unit
journalctl -u <name>.service
journalctl _SYSTEMD_UNIT=<name>.service
```
Тимчасові units легко пропустити, оскільки `/run/systemd/transient/` є **непостійним**. Якщо ви збираєте live image, скопіюйте його до завершення роботи системи.

### Kernel Modules

Модулі ядра Linux, які часто використовуються malware як компоненти rootkit, завантажуються під час запуску системи. Критично важливі для цих модулів каталоги та файли:

- **/lib/modules/$(uname -r)**: Містить модулі для версії ядра, що працює.
- **/etc/modprobe.d**: Містить конфігураційні файли для керування завантаженням модулів.
- **/etc/modprobe** та **/etc/modprobe.conf**: Файли глобальних налаштувань модулів.

### Other Autostart Locations

Linux використовує різні файли для автоматичного запуску програм після входу користувача в систему; у них потенційно може міститися malware:

- **/etc/profile.d/**\*, **/etc/profile** та **/etc/bash.bashrc**: Виконуються під час входу будь-якого користувача.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile** та **\~/.config/autostart**: Файли конкретного користувача, які запускаються під час його входу в систему.
- **/etc/rc.local**: Запускається після старту всіх системних служб, позначаючи завершення переходу до багатокористувацького середовища.

## Examine Logs

Системи Linux відстежують активність користувачів і системні події за допомогою різних log-файлів. Ці log-файли мають ключове значення для виявлення несанкціонованого доступу, malware infections та інших інцидентів безпеки.<sup>[[2]](#references)</sup> Основні log-файли:

- **/var/log/syslog** (Debian) або **/var/log/messages** (RedHat): Фіксують загальносистемні повідомлення та активність.
- **/var/log/auth.log** (Debian) або **/var/log/secure** (RedHat): Фіксують спроби автентифікації, успішні та невдалі входи в систему.
- Використовуйте `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log`, щоб відфільтрувати відповідні події автентифікації.
- **/var/log/boot.log**: Містить повідомлення про запуск системи.
- **/var/log/maillog** або **/var/log/mail.log**: Фіксують активність email-сервера та допомагають відстежувати пов’язані з email служби.
- **/var/log/kern.log**: Зберігає повідомлення ядра, зокрема помилки та попередження.
- **/var/log/dmesg**: Містить повідомлення драйверів пристроїв.
- **/var/log/faillog**: Фіксує невдалі спроби входу в систему, допомагаючи під час розслідувань порушень безпеки.
- **/var/log/cron**: Фіксує виконання cron jobs.
- **/var/log/daemon.log**: Відстежує активність фонових служб.
- **/var/log/btmp**: Документує невдалі спроби входу в систему.
- **/var/log/httpd/**: Містить журнали помилок і доступу Apache HTTPD.
- **/var/log/mysqld.log** або **/var/log/mysql.log**: Фіксують активність бази даних MySQL.
- **/var/log/xferlog**: Фіксує передавання файлів через FTP.
- **/var/log/**: Завжди перевіряйте наявність тут неочікуваних log-файлів.

> [!TIP]
> Системні log-файли Linux і підсистеми аудиту можуть бути вимкнені або видалені під час intrusion чи malware incident. Оскільки log-файли в системах Linux зазвичай містять одні з найкорисніших відомостей про malicious activity, intruders регулярно їх видаляють. Тому під час перевірки доступних log-файлів важливо шукати пропуски або записи не в хронологічному порядку, які можуть свідчити про видалення чи втручання.

### Journald triage (`journalctl`)

На сучасних Linux hosts **systemd journal** зазвичай є найціннішим джерелом відомостей про **виконання служб**, **події автентифікації**, **операції з пакетами** та **повідомлення ядра й user-space**. Під час live response намагайтеся зберегти як **persistent** journal (`/var/log/journal/`), так і **runtime** journal (`/run/log/journal/`), оскільки короткочасна активність attacker може існувати лише в останньому.<sup>[[5]](#references)</sup>
```bash
# List available boots and pivot around the suspicious one
journalctl --list-boots
journalctl -b -1

# Review a mounted image or copied journal directory offline
journalctl --directory /mnt/image/var/log/journal --list-boots
journalctl --directory /mnt/image/var/log/journal -b -1

# Inspect a single journal file and check integrity/corruption
journalctl --file system.journal --header
journalctl --file system.journal --verify

# High-signal filters
journalctl -u ssh.service
journalctl _SYSTEMD_UNIT=cron.service
journalctl _UID=0
journalctl _EXE=/usr/sbin/useradd
```
Корисні поля журналу для triage включають `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` і `MESSAGE`. Якщо journald було налаштовано без постійного зберігання, очікуйте лише нещодавні дані в `/run/log/journal/`.

### Triage фреймворку аудиту (`auditd`)

Якщо `auditd` увімкнено, надавайте йому перевагу, коли потрібна **атрибуція процесів** для змін файлів, виконання команд, активності входу або встановлення пакетів.<sup>[[6]](#references)</sup>
```bash
# Fast summaries
aureport --start today --summary -i
aureport --start today --login --failed -i
aureport --start today --executable -i

# Search raw events
ausearch --start today -m EXECVE -i
ausearch --start today -ua 1000 -m USER_CMD,EXECVE -i
ausearch --start today -m SERVICE_START,SERVICE_STOP -i

# Software installation/update events (especially useful on RHEL-like systems)
ausearch -m SOFTWARE_UPDATE -i
```
Коли правила розгорталися з ключами, виконуйте pivoting від них, а не grep сирих логів:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux веде історію команд для кожного користувача**, яка зберігається в:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Крім того, команда `last -Faiwx` надає список входів користувачів у систему. Перевірте його на наявність невідомих або неочікуваних входів.

Перевірте файли, які можуть надавати додаткові привілеї:

- Перегляньте `/etc/sudoers` на предмет непередбачених привілеїв користувачів, які могли бути надані.
- Перегляньте `/etc/sudoers.d/` на предмет непередбачених привілеїв користувачів, які могли бути надані.
- Перевірте `/etc/groups`, щоб виявити незвичне членство в групах або дозволи.
- Перевірте `/etc/passwd`, щоб виявити незвичне членство в групах або дозволи.

Деякі програми також створюють власні журнали:

- **SSH**: Перевірте _\~/.ssh/authorized_keys_ і _\~/.ssh/known_hosts_ на наявність несанкціонованих віддалених підключень.
- **Gnome Desktop**: Перегляньте _\~/.recently-used.xbel_, щоб перевірити нещодавно відкриті файли через програми Gnome.
- **Firefox/Chrome**: Перевірте історію браузера та завантаження в _\~/.mozilla/firefox_ або _\~/.config/google-chrome_ на наявність підозрілої активності.
- **VIM**: Перегляньте _\~/.viminfo_ для отримання відомостей про використання, зокрема шляхи до відкритих файлів та історію пошуку.
- **Open Office**: Перевірте нещодавній доступ до документів, який може вказувати на скомпрометовані файли.
- **FTP/SFTP**: Перегляньте журнали в _\~/.ftp_history_ або _\~/.sftp_history_ на наявність потенційно несанкціонованих передавань файлів.
- **MySQL**: Дослідіть _\~/.mysql_history_ на наявність виконаних MySQL-запитів, які потенційно можуть розкрити несанкціоновані дії з базою даних.
- **Less**: Проаналізуйте _\~/.lesshst_ для перегляду історії використання, зокрема відкритих файлів і виконаних команд.
- **Git**: Перевірте _\~/.gitconfig_ і _.git/logs_ проєкту на наявність змін у репозиторіях.

### Журнали USB

[**usbrip**](https://github.com/snovvcrash/usbrip) — це невелика програма, написана на чистому Python 3, яка аналізує журнали Linux (`/var/log/syslog*` або `/var/log/messages*`, залежно від дистрибутива) для створення таблиць історії подій USB.

Важливо **знати всі USB-пристрої, які використовувалися**. Ще корисніше мати авторизований список USB-пристроїв, щоб знаходити «події порушення» (використання USB-пристроїв, яких немає в цьому списку).

### Встановлення
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Приклади
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Більше прикладів та інформації всередині github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Перевірка облікових записів користувачів і активності входу

Перевірте _**/etc/passwd**_, _**/etc/shadow**_ і **журнали безпеки** на наявність незвичних імен або облікових записів, створених та/або використаних приблизно в той самий час, що й відомі несанкціоновані події. Також перевірте можливі атаки методом brute-force проти sudo.\
Крім того, перевірте такі файли, як _**/etc/sudoers**_ і _**/etc/groups**_, на наявність неочікуваних привілеїв, наданих користувачам.\
Нарешті, шукайте облікові записи **без паролів** або з **паролями, які легко вгадати**.<sup>[[1]](#references)</sup>

## Дослідження файлової системи

### Аналіз структур файлової системи під час розслідування malware

Під час розслідування інцидентів, пов’язаних із malware, структура файлової системи є важливим джерелом інформації, оскільки розкриває як послідовність подій, так і вміст malware. Однак автори malware розробляють методи, що ускладнюють цей аналіз, наприклад змінюють часові мітки файлів або уникають використання файлової системи для зберігання даних.<sup>[[1]](#references)</sup>

Щоб протидіяти цим anti-forensic методам, важливо:

- **Провести ретельний аналіз часової шкали** за допомогою таких інструментів, як **Autopsy**, для візуалізації часових шкал подій, або `mactime` з **Sleuth Kit** для отримання детальних даних часової шкали.
- **Дослідити неочікувані скрипти** у системному $PATH, які можуть містити shell- або PHP-скрипти, використані атакувальниками.
- **Перевірити `/dev` на наявність нетипових файлів**, оскільки зазвичай цей каталог містить спеціальні файли, але в ньому можуть зберігатися файли, пов’язані з malware.
- **Здійснити пошук прихованих файлів або каталогів** з іменами на кшталт ".. " (дві крапки та пробіл) або "..^G" (дві крапки та control-G), які можуть приховувати шкідливий вміст.
- **Виявити файли setuid root** за допомогою команди: `find / -user root -perm -04000 -print` Ця команда знаходить файли з підвищеними дозволами, які можуть бути використані атакувальниками.
- **Переглянути часові мітки видалення** в таблицях inode, щоб виявити масове видалення файлів, що може свідчити про наявність rootkit або троянів.
- **Перевірити послідовні inode** на наявність сусідніх шкідливих файлів після виявлення одного з них, оскільки їх могли розмістити разом.
- **Перевірити поширені каталоги з бінарними файлами** (_/bin_, _/sbin_) на наявність нещодавно змінених файлів, оскільки вони могли бути змінені malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Зверніть увагу, що **атакер** може **змінити** **час**, щоб **файли виглядали** **легітимними**, але він **не може** змінити **inode**. Якщо ви виявили, що **файл** вказує на те, що його було створено та змінено **в той самий час**, що й решту файлів у тій самій папці, але **inode** є **неочікувано більшим**, то **часові мітки цього файлу було змінено**.

### Швидкий тріаж із фокусом на inode

Якщо ви підозрюєте anti-forensics, на ранньому етапі виконайте ці перевірки з фокусом на inode:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Якщо підозрілий inode знаходиться на образі/пристрої файлової системи EXT, безпосередньо перевірте метадані inode:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Корисні поля:
- **Links**: якщо значення дорівнює `0`, жоден запис каталогу наразі не посилається на inode.
- **dtime**: мітка часу видалення, що встановлюється, коли inode було від’єднано.
- **ctime/mtime**: допомагають зіставити зміни метаданих або вмісту з часовою шкалою інциденту.

### Capabilities, xattrs та preload-based userland rootkits

Сучасні механізми persistence у Linux часто уникають очевидних бінарних файлів **setuid** і натомість зловживають **file capabilities**, **extended attributes** та dynamic loader.
```bash
# Enumerate file capabilities (think cap_setuid, cap_sys_admin, cap_dac_override)
getcap -r / 2>/dev/null

# Inspect extended attributes on suspicious binaries and libraries
getfattr -d -m - /path/to/suspicious/file 2>/dev/null

# Global preload hook affecting every dynamically linked binary
cat /etc/ld.so.preload 2>/dev/null
stat /etc/ld.so.preload 2>/dev/null

# If a suspicious library is referenced, inspect its metadata and links
ls -lah /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib 2>/dev/null | grep -E '\\.so(\\.|$)'
ldd /bin/ls
```
Приділіть особливу увагу бібліотекам, на які посилаються з **доступних для запису** шляхів, таких як `/tmp`, `/dev/shm`, `/var/tmp` або нетипових розташувань у `/usr/local/lib`. Також перевірте бінарні файли з capabilities поза межами звичайного володіння пакетами та зіставте їх із результатами перевірки пакетів (`rpm -Va`, `dpkg --verify`, `debsums`).

## Порівняння файлів різних версій файлової системи

### Підсумок порівняння версій файлової системи

Щоб порівняти версії файлової системи та точно визначити зміни, ми використовуємо спрощені команди `git diff`:<sup>[[3]](#references)</sup>

- **Щоб знайти нові файли**, порівняйте два каталоги:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Для зміненого вмісту** перелічіть зміни, ігноруючи конкретні рядки:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Щоб виявити видалені файли**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Параметри фільтрації** (`--diff-filter`) допомагають обмежити результати певними змінами, як-от додані (`A`), видалені (`D`) або змінені (`M`) файли.
- `A`: Додані файли
- `C`: Скопійовані файли
- `D`: Видалені файли
- `M`: Змінені файли
- `R`: Перейменовані файли
- `T`: Зміни типу (наприклад, файл на symlink)
- `U`: Файли без злиття
- `X`: Невідомі файли
- `B`: Пошкоджені файли

## Посилання

- [1] [Посібник із forensic-аналізу malware для Linux-систем: Digital Forensics Field Guides — Розділ 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Пояснення Linux-логів](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [Документація git diff — параметр --diff-filter](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary — Patching for persistence: як Linux-malware DripDropper переміщується через cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Forensic-аналіз Linux-журналів](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 — аудит системи](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Привіт, Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [Розширення SQLite FTS5](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
