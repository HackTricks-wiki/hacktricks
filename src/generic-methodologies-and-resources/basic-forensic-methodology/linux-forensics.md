# Форензика Linux

## Початковий збір інформації

### Базова інформація

Перш за все, рекомендується мати **USB** із **завідомо справними бінарними файлами та бібліотеками** (можна просто взяти Ubuntu і скопіювати папки _/bin_, _/sbin_, _/lib,_ та _/lib64_), потім підключити USB і змінити змінні середовища, щоб використовувати ці бінарні файли:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Після того як ви налаштували систему на використання надійних і відомих бінарних файлів, можна розпочати **збирання базової інформації**:
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

- **Root-процеси** зазвичай запускаються з низькими значеннями PID, тому якщо ви знайдете root-процес із великим PID, це може бути підозріло
- Перевірте **зареєстровані логіни** користувачів без shell у `/etc/passwd`
- Перевірте наявність **хешів паролів** у `/etc/shadow` для користувачів без shell

### Дамп пам'яті

Для отримання пам'яті запущеної системи рекомендується використовувати [**LiME**](https://github.com/504ensicsLabs/LiME).\
Щоб його **скомпілювати**, потрібно використовувати **те саме ядро**, яке працює на машині жертви.

> [!TIP]
> Пам'ятайте, що **не можна встановлювати LiME або будь-що інше** на машині жертви, оскільки це внесе до неї кілька змін

Отже, якщо у вас є ідентична версія Ubuntu, можна виконати `apt-get install lime-forensics-dkms`\
В інших випадках потрібно завантажити [**LiME**](https://github.com/504ensicsLabs/LiME) із github і скомпілювати його з правильними заголовками ядра. Щоб **отримати точні заголовки ядра** машини жертви, можна просто **скопіювати каталог** `/lib/modules/<kernel version>` на свою машину, а потім **скомпілювати** LiME, використовуючи їх:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME підтримує 3 **формати**:

- Raw (усі сегменти об'єднано разом)
- Padded (те саме, що й raw, але з нулями у правих бітах)
- Lime (рекомендований формат із метаданими

LiME також можна використовувати для **надсилання дампа через мережу**, замість його збереження в системі, за допомогою чогось на кшталт: `path=tcp:4444`

### Створення образу диска

#### Вимкнення системи

Перш за все, вам потрібно буде **вимкнути систему**. Це не завжди можливо, оскільки іноді система може бути production-сервером, який компанія не може дозволити собі вимкнути.\
Існує **2 способи** вимкнути систему: **звичайне вимкнення** та вимкнення шляхом **"висмикування штекера"**. Перший спосіб дозволить **процесам завершитися як зазвичай**, а **файловій системі** — **синхронізуватися**, але водночас він також дозволить можливому **malware** **знищити докази**. Підхід із **"висмикуванням штекера"** може спричинити **певну втрату інформації** (багато інформації не буде втрачено, оскільки ми вже створили образ пам'яті), а **malware не матиме жодної можливості** щось із цим зробити. Тому, якщо ви **підозрюєте**, що може бути присутнє **malware**, просто виконайте **команду** **`sync`** у системі та висмикніть штекер.

#### Створення образу диска

Важливо зазначити, що **перш ніж підключати комп'ютер до будь-чого, пов'язаного зі справою**, потрібно переконатися, що він буде **змонтований лише для читання**, щоб уникнути зміни будь-якої інформації.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Попередній аналіз образу диска

Створення образу диска, що більше не містить даних.
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
- **Системи на базі Debian**: використовуйте `dpkg --verify` для початкової перевірки, а потім `debsums | grep -v "OK$"` (після встановлення `debsums` за допомогою `apt-get install debsums`), щоб виявити будь-які проблеми.

### Засоби виявлення Malware/Rootkit

Прочитайте наведену нижче сторінку, щоб дізнатися про інструменти, які можуть бути корисними для пошуку Malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Пошук встановлених програм

Для ефективного пошуку встановлених програм у системах Debian і RedHat розгляньте можливість використання системних журналів і баз даних разом із ручною перевіркою поширених каталогів.<sup>[[1]](#references)</sup>

- У Debian перевірте _**`/var/lib/dpkg/status`**_ і _**`/var/log/dpkg.log`**_, щоб отримати відомості про встановлення пакетів, використовуючи `grep` для фільтрації потрібної інформації.
- Користувачі RedHat можуть запитати базу даних RPM за допомогою `rpm -qa --root=/mntpath/var/lib/rpm`, щоб отримати список встановлених пакетів.

Щоб виявити програмне забезпечення, встановлене вручну або поза межами цих менеджерів пакетів, перевірте такі каталоги, як _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ і _**`/sbin`**_. Поєднуйте списки каталогів із системними командами, специфічними для конкретної системи, щоб ідентифікувати виконувані файли, не пов’язані з відомими пакетами, і таким чином покращити пошук усіх встановлених програм.
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

Уявімо процес, який було запущено з `/tmp/exec`, а потім видалено. Його можна витягти.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Тріаж трасування Syscall за допомогою SQLite та FTS5

Якщо процес усе ще виконується або його можна повторно запустити в лабораторному середовищі, **`strace`** може швидко надати поведінкове трасування без потреби в модулях ядра або повній телеметрії EDR. Для великих трас уникайте безпосереднього читання необробленого журналу або вставлення його в LLM: збережіть його в базі даних **SQLite** і запитуйте лише мінімальну потрібну підмножину.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> Підключення `strace` змінює час виконання процесу та може вплинути на умови виникнення станів гонки або інші нестабільні помилки. За можливості відтворюйте проблему в копії або лабораторній системі.

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

- `-ff`: відстежувати fork-и/потоки та зберігати окремі результати для кожного процесу
- `-ttt`: часові мітки в епохальному форматі для зручного зіставлення часової шкали
- `-yy`: за можливості визначати шляхи/сокети, що відповідають дескрипторам файлів
- `-s 4096`: запобігати обрізанню довгих аргументів шляхів і буферів

### Нормалізація

Практична схема: один рядок на системний виклик і один рядок на кожен аргумент:
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
Це дає змогу уникнути спроб звести різнорідні рядки syscall до однієї широкої таблиці та забезпечує передбачуваність об’єднань під час triage.

### Індексуйте текстові аргументи за допомогою FTS5

Наївний пошук шляхів за допомогою `LIKE "%...%"` стає дуже повільним у великих трасуваннях. Створіть індекс FTS5 для тексту аргументів і виконуйте пошук у ньому:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Приклад: відновити активність файлів у `/tmp` без сканування кожного рядка:
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

- **PATH hijacking / fake sudo**: шукайте операції запису та `chmod`/`rename` у `~/.local/bin/`, а потім зіставляйте їх із подальшими викликами `execve` для назв, схожих на привілейовані, наприклад `sudo`.
- **TOCTOU on temporary files**: відстежуйте той самий шлях `/tmp/...` через `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` і `execve`, щоб виявити проміжки між перевіркою та використанням.
- **Причина збою**: зіставте `mmap` файлу із записом або усіканням того самого inode/шляху іншим процесом, а потім перевірте послідовність сигналу/завершення на наявність `SIGBUS`.
- **Відновлення мережевого призначення**: фільтруйте аргументи, пов’язані з `connect`, `sendto`, `sendmsg`, `recvfrom` і socket, щоб отримати IP-адреси та порти вузлів-партнерів.

### Аналіз trace за допомогою LLM

Якщо ви хочете залучити LLM, надайте йому **read-only** дескриптор SQLite і повну схему. Дозвольте йому виконувати raw SQL замість обгортання database за допомогою вузьких helper functions. Зазвичай це краще працює для `JOIN`, часової кореляції та FTS-пошуку.

Практичні правила:

- Залишайте database доступною лише для читання, наприклад за допомогою `sqlite3 'file:trace.db?mode=ro'`.
- Надайте моделі приклади коректних запитів `JOIN` і `FTS5 MATCH`.
- **Не** вставляйте в prompt необроблені багатогігабайтні логи `strace`.
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
#### Пошук: відкат посилення SSH і бекдорні оболонки
Зміни у `sshd_config` та оболонках системних облікових записів є поширеними діями після експлуатації для збереження доступу.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Пошук: маркери Cloud C2 (Dropbox/Cloudflare Tunnel)
- Dropbox API beacons зазвичай використовують api.dropboxapi.com або content.dropboxapi.com через HTTPS із токенами Authorization: Bearer.
- Шукайте в proxy/Zeek/NetFlow неочікуваний вихідний трафік Dropbox із серверів.
- Cloudflare Tunnel (`cloudflared`) забезпечує резервний C2 через вихідний порт 443.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Сервіси

Шляхи, де шкідливе програмне забезпечення може бути встановлене як сервіс:

- **/etc/inittab**: Викликає скрипти ініціалізації, як-от rc.sysinit, які своєю чергою спрямовують виконання до скриптів запуску.
- **/etc/rc.d/** та **/etc/rc.boot/**: Містять скрипти запуску сервісів; останній каталог зустрічається у старіших версіях Linux.
- **/etc/init.d/**: Використовується в деяких версіях Linux, наприклад Debian, для зберігання скриптів запуску.
- Сервіси також можуть активуватися через **/etc/inetd.conf** або **/etc/xinetd/**, залежно від варіанта Linux.
- **/etc/systemd/system**: Каталог для скриптів system і service manager.
- **/etc/systemd/system/multi-user.target.wants/**: Містить посилання на сервіси, які мають запускатися на багатокористувацькому рівні запуску.
- **/usr/local/etc/rc.d/**: Для власних або сторонніх сервісів.
- **\~/.config/autostart/**: Для автоматичного запуску застосунків, специфічних для користувача; може бути місцем приховування malware, націленого на користувачів.
- **/lib/systemd/system/**: Загальносистемні файли unit за замовчуванням, що надаються встановленими пакетами.

#### Пошук: systemd timers і transient units

Persistence у systemd не обмежується файлами `.service`. Досліджуйте units `.timer`, units на рівні користувача та **transient units**, створені під час виконання.
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
Transient units легко пропустити, оскільки `/run/systemd/transient/` є **непостійним**. Якщо ви збираєте live image, скопіюйте його до завершення роботи системи.

### Kernel Modules

Linux kernel modules, які malware часто використовує як компоненти rootkit, завантажуються під час запуску системи. Критично важливі для цих модулів каталоги та файли:

- **/lib/modules/$(uname -r)**: Містить модулі для версії запущеного kernel.
- **/etc/modprobe.d**: Містить конфігураційні файли для керування завантаженням модулів.
- **/etc/modprobe** та **/etc/modprobe.conf**: Файли глобальних налаштувань модулів.

### Other Autostart Locations

Linux використовує різні файли для автоматичного запуску програм після входу користувача, у яких потенційно може міститися malware:

- **/etc/profile.d/**\*, **/etc/profile** та **/etc/bash.bashrc**: Виконуються під час входу будь-якого користувача.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile** та **\~/.config/autostart**: Файли конкретного користувача, які запускаються під час його входу.
- **/etc/rc.local**: Виконується після запуску всіх системних служб, позначаючи завершення переходу до багатокористувацького середовища.

## Examine Logs

Linux-системи відстежують активність користувачів і системні події за допомогою різних log-файлів. Ці logs мають ключове значення для виявлення несанкціонованого доступу, malware-інфекцій та інших інцидентів безпеки.<sup>[[2]](#references)</sup> Основні log-файли:

- **/var/log/syslog** (Debian) або **/var/log/messages** (RedHat): Фіксують загальносистемні повідомлення та активність.
- **/var/log/auth.log** (Debian) або **/var/log/secure** (RedHat): Реєструють спроби автентифікації, успішні та невдалі входи.
- Використовуйте `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log`, щоб відфільтрувати релевантні події автентифікації.
- **/var/log/boot.log**: Містить повідомлення про запуск системи.
- **/var/log/maillog** або **/var/log/mail.log**: Реєструють активність email-сервера, що корисно для відстеження служб, пов’язаних з email.
- **/var/log/kern.log**: Зберігає повідомлення kernel, зокрема помилки та попередження.
- **/var/log/dmesg**: Містить повідомлення драйверів пристроїв.
- **/var/log/faillog**: Реєструє невдалі спроби входу, допомагаючи під час розслідувань порушень безпеки.
- **/var/log/cron**: Реєструє виконання cron-завдань.
- **/var/log/daemon.log**: Відстежує активність фонових служб.
- **/var/log/btmp**: Документує невдалі спроби входу.
- **/var/log/httpd/**: Містить logs помилок і доступу Apache HTTPD.
- **/var/log/mysqld.log** або **/var/log/mysql.log**: Реєструє активність бази даних MySQL.
- **/var/log/xferlog**: Реєструє передавання файлів через FTP.
- **/var/log/**: Завжди перевіряйте цей каталог на наявність несподіваних logs.

> [!TIP]
> Системні logs Linux і підсистеми аудиту можуть бути вимкнені або видалені під час intrusion чи інциденту з malware. Оскільки logs у Linux-системах зазвичай містять одні з найкорисніших відомостей про шкідливу активність, intruders регулярно їх видаляють. Тому під час перевірки доступних log-файлів важливо шукати пропуски або записи не в хронологічному порядку, які можуть свідчити про видалення чи втручання.

### Journald triage (`journalctl`)

На сучасних Linux-хостах **systemd journal** зазвичай є найціннішим джерелом інформації про **виконання служб**, **події автентифікації**, **операції з пакетами** та **повідомлення kernel/user-space**. Під час live response намагайтеся зберегти як **постійний** journal (`/var/log/journal/`), так і **runtime** journal (`/run/log/journal/`), оскільки короткочасна активність attacker може існувати лише в останньому.<sup>[[5]](#references)</sup>
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
Корисні поля журналу для первинного аналізу включають `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` і `MESSAGE`. Якщо journald було налаштовано без постійного зберігання, очікуйте лише нещодавні дані в `/run/log/journal/`.

### Первинний аналіз audit framework (`auditd`)

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
Коли правила розгорталися за допомогою keys, виконуйте pivot через них замість grep сирих логів:
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

- Перегляньте `/etc/sudoers` на наявність непередбачених привілеїв користувачів, які могли бути надані.
- Перегляньте `/etc/sudoers.d/` на наявність непередбачених привілеїв користувачів, які могли бути надані.
- Перевірте `/etc/groups`, щоб виявити незвичне членство в групах або дозволи.
- Перевірте `/etc/passwd`, щоб виявити незвичне членство в групах або дозволи.

Деякі застосунки також створюють власні журнали:

- **SSH**: Перевірте _\~/.ssh/authorized_keys_ і _\~/.ssh/known_hosts_ на наявність несанкціонованих віддалених підключень.
- **Gnome Desktop**: Перевірте _\~/.recently-used.xbel_ на наявність нещодавно відкритих файлів через застосунки Gnome.
- **Firefox/Chrome**: Перевірте історію браузера та завантаження в _\~/.mozilla/firefox_ або _\~/.config/google-chrome_ на наявність підозрілої активності.
- **VIM**: Перегляньте _\~/.viminfo_ для отримання відомостей про використання, зокрема шляхи до відкритих файлів та історію пошуку.
- **Open Office**: Перевірте нещодавній доступ до документів, який може вказувати на скомпрометовані файли.
- **FTP/SFTP**: Перегляньте журнали в _\~/.ftp_history_ або _\~/.sftp_history_ на наявність потенційно несанкціонованих передавань файлів.
- **MySQL**: Перевірте _\~/.mysql_history_ на наявність виконаних MySQL-запитів, які можуть розкрити несанкціоновані дії з базою даних.
- **Less**: Проаналізуйте _\~/.lesshst_ для вивчення історії використання, зокрема переглянутих файлів і виконаних команд.
- **Git**: Перевірте _\~/.gitconfig_ і _.git/logs_ проєктів на наявність змін у репозиторіях.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) — це невеликий програмний засіб, написаний на чистому Python 3, який аналізує файли журналів Linux (`/var/log/syslog*` або `/var/log/messages*`, залежно від дистрибутива) для створення таблиць історії подій USB.

Корисно **знати всі USB-пристрої, які використовувалися**, а ще корисніше — мати авторизований список USB-пристроїв, щоб знаходити «події порушення» (використання USB-пристроїв, яких немає в цьому списку).

### Installation
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
Більше прикладів та інформації можна знайти на github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Перевірка облікових записів користувачів і активності входу

Перевірте _**/etc/passwd**_, _**/etc/shadow**_ і **журнали безпеки** на наявність незвичних імен або облікових записів, створених і/або використаних незадовго до чи після відомих несанкціонованих подій. Також перевірте можливі атаки методом brute-force на sudo.\
Крім того, перевірте такі файли, як _**/etc/sudoers**_ і _**/etc/groups**_, на наявність неочікуваних привілеїв, наданих користувачам.\
Насамкінець, шукайте облікові записи **без паролів** або з **паролями, які легко вгадати**.<sup>[[1]](#references)</sup>

## Дослідження файлової системи

### Аналіз структур файлової системи під час розслідування malware

Під час розслідування інцидентів, пов’язаних із malware, структура файлової системи є важливим джерелом інформації, оскільки розкриває як послідовність подій, так і вміст malware. Однак автори malware розробляють методи, що ускладнюють такий аналіз, зокрема змінюють часові мітки файлів або уникають використання файлової системи для зберігання даних.<sup>[[1]](#references)</sup>

Щоб протидіяти цим anti-forensic методам, необхідно:

- **Провести ретельний аналіз часової шкали** за допомогою таких інструментів, як **Autopsy**, для візуалізації часових шкал подій, або `mactime` з **Sleuth Kit** для отримання детальних даних часової шкали.
- **Дослідити неочікувані скрипти** у системному $PATH, які можуть містити shell- або PHP-скрипти, використані атакувальниками.
- **Перевірити `/dev` на наявність нетипових файлів**, оскільки зазвичай цей каталог містить спеціальні файли, але в ньому можуть зберігатися файли, пов’язані з malware.
- **Шукати приховані файли або каталоги** з такими іменами, як ".. " (дві крапки та пробіл) або "..^G" (дві крапки та control-G), які можуть приховувати шкідливий вміст.
- **Виявити файли setuid root** за допомогою команди: `find / -user root -perm -04000 -print` Ця команда знаходить файли з підвищеними дозволами, якими можуть зловживати атакувальники.
- **Перевірити часові мітки видалення** в таблицях inode, щоб виявити масове видалення файлів, що може свідчити про наявність rootkits або trojans.
- **Перевірити послідовні inode** на наявність розташованих поруч шкідливих файлів після виявлення одного з них, оскільки їх могли розмістити разом.
- **Перевірити поширені каталоги з бінарними файлами** (_/bin_, _/sbin_) на наявність нещодавно змінених файлів, оскільки malware могло їх змінити.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Зверніть увагу, що **зловмисник** може **змінити** **час**, щоб **файли виглядали** **легітимними**, але він **не може** змінити **inode**. Якщо ви виявили, що **файл** показує, що його було створено та змінено в **той самий час**, що й решту файлів у тій самій папці, але **inode** є **неочікувано більшим**, то **часові мітки цього файлу було змінено**.

### Швидке сортування за inode

Якщо ви підозрюєте anti-forensics, рано виконайте такі перевірки, орієнтовані на inode:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Коли підозрілий inode знаходиться на образі/пристрої файлової системи EXT, безпосередньо перевірте метадані inode:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Корисні поля:
- **Links**: якщо значення дорівнює `0`, жоден запис каталогу наразі не посилається на inode.
- **dtime**: timestamp видалення, встановлений, коли inode було відв’язано.
- **ctime/mtime**: допомагає зіставити зміни метаданих/вмісту з часовою шкалою інциденту.

### Capabilities, xattrs та preload-based userland rootkits

Сучасна persistence в Linux часто уникає очевидних `setuid`-бінарних файлів і натомість зловживає **file capabilities**, **extended attributes** та dynamic loader.
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
Звертайте особливу увагу на бібліотеки, на які посилаються з **доступних для запису** шляхів, таких як `/tmp`, `/dev/shm`, `/var/tmp` або нетипові розташування в `/usr/local/lib`. Також перевіряйте бінарні файли з capability поза межами звичайного володіння пакетами та зіставляйте їх із результатами перевірки пакетів (`rpm -Va`, `dpkg --verify`, `debsums`).

## Порівняння файлів різних версій файлової системи

### Підсумок порівняння версій файлової системи

Щоб порівняти версії файлової системи та визначити зміни, ми використовуємо спрощені команди `git diff`:<sup>[[3]](#references)</sup>

- **Щоб знайти нові файли**, порівняйте два каталоги:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Для зміненого вмісту** перелічіть зміни, ігноруючи конкретні рядки:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Для виявлення видалених файлів**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) допомагають звузити результати до певних змін, наприклад доданих (`A`), видалених (`D`) або змінених (`M`) файлів.
- `A`: Додані файли
- `C`: Скопійовані файли
- `D`: Видалені файли
- `M`: Змінені файли
- `R`: Перейменовані файли
- `T`: Зміни типу (наприклад, файл на symlink)
- `U`: Файли без злиття
- `X`: Невідомі файли
- `B`: Пошкоджені файли

## References

- [1] [Польовий посібник із криміналістики шкідливого ПЗ для Linux-систем: польові посібники з цифрової криміналістики – розділ 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Пояснення журналів Linux](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [Документація git diff – параметр --diff-filter](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – Виправлення для забезпечення persistence: як Linux malware DripDropper переміщується через cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Криміналістичний аналіз Linux-журналів](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 – Аудит системи](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Привіт, Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [Розширення SQLite FTS5](https://www.sqlite.org/fts5.html)
{{#include ../../banners/hacktricks-training.md}}
