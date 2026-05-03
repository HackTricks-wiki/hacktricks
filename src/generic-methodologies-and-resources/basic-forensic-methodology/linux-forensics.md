# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Початковий збір інформації

### Базова інформація

Перш за все, рекомендується мати **USB** з **перевіреними бінарними файлами та бібліотеками** на ньому (можна просто взяти ubuntu і скопіювати теки _/bin_, _/sbin_, _/lib,_ і _/lib64_), потім змонтувати USB і змінити змінні середовища, щоб використовувати ці бінарні файли:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Після того, як ви налаштували систему на використання хороших і відомих binaries, ви можете почати **витягувати деяку базову інформацію**:
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

- **Root processes** зазвичай працюють із низькими PID, тож якщо ви знайдете root process із великим PID, це може викликати підозру
- Перевірте **registered logins** користувачів без shell у `/etc/passwd`
- Перевірте наявність **password hashes** у `/etc/shadow` для користувачів без shell

### Memory Dump

Щоб отримати пам’ять запущеної системи, рекомендується використовувати [**LiME**](https://github.com/504ensicsLabs/LiME).\
Щоб **скомпілювати** його, вам потрібно використовувати **той самий kernel**, що й на машині жертви.

> [!TIP]
> Пам’ятайте, що ви **не можете встановлювати LiME або будь-що інше** на машині жертви, оскільки це внесе в неї кілька змін

Тож, якщо у вас є ідентична версія Ubuntu, ви можете використати `apt-get install lime-forensics-dkms`\
В інших випадках вам потрібно завантажити [**LiME**](https://github.com/504ensicsLabs/LiME) з github і скомпілювати його з правильними kernel headers. Щоб **отримати точні kernel headers** машини жертви, ви можете просто **скопіювати директорію** `/lib/modules/<kernel version>` на свою машину, а потім **скомпілювати** LiME, використовуючи їх:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME підтримує 3 **formats**:

- Raw (кожен сегмент, об’єднаний разом)
- Padded (те саме, що й raw, але з нулями в правих бітах)
- Lime (рекомендований format з metadata)

LiME також можна використовувати, щоб **надсилати dump через network** замість зберігання його в системі, використовуючи щось на кшталт: `path=tcp:4444`

### Disk Imaging

#### Shutting down

Перш за все, вам потрібно буде **завершити роботу system**. Це не завжди можливо, оскільки інколи system може бути production server, який компанія не може дозволити собі вимкнути.\
Існує **2 способи** завершення роботи system: **normal shutdown** і **"plug the plug" shutdown**. Перший дозволить **processes завершитися як зазвичай** і **filesystem** буде **synchronized**, але також він дасть змогу можливому **malware** **знищити evidence**. Підхід "pull the plug" може спричинити **деяку втрату information** (не так багато info буде втрачено, оскільки ми вже зробили image memory ) і **malware не матиме жодної можливості** щось із цим зробити. Тому, якщо ви **suspect**, що там може бути **malware**, просто виконайте на system **`sync`** **command** і висмикніть вилку.

#### Taking an image of the disk

Важливо зазначити, що **before connecting your computer to anything related to the case**, вам потрібно переконатися, що це буде **mounted as read only** щоб уникнути зміни будь-якої information.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Попередній аналіз disk image

Створення disk image без додаткових даних.
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

### Modified System Files

Linux пропонує інструменти для перевірки цілісності системних компонентів, що є критично важливим для виявлення потенційно проблемних файлів.

- **RedHat-based systems**: Використовуйте `rpm -Va` для комплексної перевірки.
- **Debian-based systems**: `dpkg --verify` для початкової перевірки, а потім `debsums | grep -v "OK$"` (після встановлення `debsums` за допомогою `apt-get install debsums`) для виявлення будь-яких проблем.

### Malware/Rootkit Detectors

Прочитайте наступну сторінку, щоб дізнатися про інструменти, які можуть бути корисними для виявлення malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Search installed programs

Щоб ефективно шукати встановлені програми як на Debian, так і на RedHat системах, варто поєднувати system logs і бази даних із ручними перевірками в поширених каталогах.

- Для Debian перевірте _**`/var/lib/dpkg/status`**_ і _**`/var/log/dpkg.log`**_ щоб отримати деталі про встановлення пакетів, використовуючи `grep` для фільтрації за конкретною інформацією.
- Користувачі RedHat можуть запитувати RPM database за допомогою `rpm -qa --root=/mntpath/var/lib/rpm`, щоб отримати список встановлених пакетів.

Щоб виявити software, встановлене вручну або поза межами цих package managers, досліджуйте каталоги на кшталт _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ і _**`/sbin`**_. Поєднуйте списки каталогів із system-specific commands, щоб ідентифікувати executables, не пов’язані з відомими пакетами, посилюючи пошук усіх встановлених програм.
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
## Відновлення видалених запущених бінарників

Уявіть процес, який було запущено з /tmp/exec, а потім видалено. Його можна витягнути
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Тріаж Syscall Trace за допомогою SQLite та FTS5

Коли процес ще виконується або його можна повторно запустити в lab, **`strace`** може швидко надати behavioral trace без потреби в kernel modules або повній EDR telemetry. Для великих trace уникайте прямого читання raw log або вставляння його в LLM: збережіть його в **SQLite** database і запитуйте лише мінімальний підмножину, яка вам потрібна.

> [!WARNING]
> Додавання `strace` змінює process timing і може вплинути на race conditions або інші fragile bugs. По можливості віддавайте перевагу відтворенню на копії/lab system.

### Capture

Для нового процесу:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Для live process:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Корисні опції:

- `-ff`: слідувати за forks/threads і зберігати окремі виводи для кожного process
- `-ttt`: epoch timestamps для легкого зіставлення timeline
- `-yy`: resolve file descriptors до backing paths/sockets, коли це можливо
- `-s 4096`: не давати довгим path і buffer arguments обрізатися

### Normalize

Практична schema — це один рядок на syscall і один рядок на argument:
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
Це дозволяє уникнути спроб розплющити гетерогенні syscall-рядки в одну широку таблицю і робить joins передбачуваними під час triage.

### Індексуйте текстові аргументи за допомогою FTS5

Наївний пошук шляхів через `LIKE "%...%"` стає дуже повільним на великих трасах. Натомість створіть FTS5 index для тексту аргументів і шукайте по ньому:
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
### Високосигнальні розслідування

- **PATH hijacking / fake sudo**: шукайте записи та активність `chmod`/`rename` у `~/.local/bin/`, потім корелюйте це з подальшим `execve` привілейовано виглядаючих назв, таких як `sudo`.
- **TOCTOU on temporary files**: переходьте на той самий шлях `/tmp/...` через `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` і `execve`, щоб виявити розриви між перевіркою та використанням.
- **Crash root cause**: корелюйте `mmap` файлу із записами або truncation того самого inode/path іншим процесом, потім перевірте послідовність сигналу/виходу на `SIGBUS`.
- **Network destination recovery**: фільтруйте `connect`, `sendto`, `sendmsg`, `recvfrom` і socket-related arguments, щоб витягти peer IPs і ports.

### LLM-assisted trace analysis

If you want an LLM to assist, expose a **read-only** SQLite handle and give it the full schema. Let it issue raw SQL instead of wrapping the database behind narrow helper functions. This usually works better for joins, temporal correlation, and FTS lookups.

Practical rules:

- Keep the database read-only, for example with `sqlite3 'file:trace.db?mode=ro'`.
- Give the model examples of valid `JOIN` and `FTS5 MATCH` queries.
- Do **not** paste raw multi-GB `strace` logs into the prompt.
- Ask focused questions such as:
- "List persistent files written by this program."
- "Did it create or replace executables in user-controlled PATH directories?"
- "Explain why this trace ends in SIGBUS."

## Inspect Autostart locations

### Scheduled Tasks
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
#### Полювання: зловживання Cron/Anacron через 0anacron і підозрілі stubs
Зловмисники часто редагують stub 0anacron, наявний у кожному каталозі /etc/cron.*/, щоб забезпечити періодичне виконання.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Полювання: відкат hardening SSH і backdoor shells
Зміни в sshd_config і shells системних облікових записів є поширеними після exploitation, щоб зберегти доступ.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API beacons typically use api.dropboxapi.com or content.dropboxapi.com over HTTPS with Authorization: Bearer tokens.
- Hunt in proxy/Zeek/NetFlow for unexpected Dropbox egress from servers.
- Cloudflare Tunnel (`cloudflared`) provides backup C2 over outbound 443.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Шляхи, де malware може бути встановлено як service:

- **/etc/inittab**: Викликає initialization scripts, такі як rc.sysinit, спрямовуючи далі до startup scripts.
- **/etc/rc.d/** and **/etc/rc.boot/**: Містять scripts для service startup, останній зустрічається в older Linux versions.
- **/etc/init.d/**: Використовується в певних Linux versions, як-от Debian, для зберігання startup scripts.
- Services також можуть активуватися через **/etc/inetd.conf** або **/etc/xinetd/**, залежно від Linux variant.
- **/etc/systemd/system**: Каталог для system і service manager scripts.
- **/etc/systemd/system/multi-user.target.wants/**: Містить links до services, які мають запускатися в multi-user runlevel.
- **/usr/local/etc/rc.d/**: Для custom або third-party services.
- **\~/.config/autostart/**: Для user-specific automatic startup applications, що може бути сховищем для user-targeted malware.
- **/lib/systemd/system/**: System-wide default unit files, надані installed packages.

#### Hunt: systemd timers and transient units

Systemd persistence не обмежується `.service` files. Досліджуйте `.timer` units, user-level units і **transient units**, створені під час runtime.
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
Transient units легко пропустити, тому що `/run/systemd/transient/` є **non-persistent**. Якщо ви збираєте live image, заберіть його до shutdown.

### Kernel Modules

Linux kernel modules, часто використовувані malware як rootkit components, завантажуються під час system boot. Каталоги та файли, критичні для цих modules, включають:

- **/lib/modules/$(uname -r)**: Містить modules для поточної версії kernel.
- **/etc/modprobe.d**: Містить configuration files для керування loading modules.
- **/etc/modprobe** і **/etc/modprobe.conf**: Files для global module settings.

### Other Autostart Locations

Linux використовує різні files для автоматичного запуску programs під час user login, де може ховатися malware:

- **/etc/profile.d/**\*, **/etc/profile**, і **/etc/bash.bashrc**: Виконуються для будь-якого user login.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, і **\~/.config/autostart**: User-specific files, що запускаються під час їхнього login.
- **/etc/rc.local**: Запускається після старту всіх system services, позначаючи кінець transition до multiuser environment.

## Examine Logs

Linux systems відстежують user activities і system events через різні log files. Ці logs є ключовими для виявлення unauthorized access, malware infections та інших security incidents. Основні log files включають:

- **/var/log/syslog** (Debian) або **/var/log/messages** (RedHat): Захоплюють system-wide messages і activities.
- **/var/log/auth.log** (Debian) або **/var/log/secure** (RedHat): Записують authentication attempts, successful і failed logins.
- Використайте `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` для фільтрації relevant authentication events.
- **/var/log/boot.log**: Містить system startup messages.
- **/var/log/maillog** або **/var/log/mail.log**: Logs email server activities, корисні для tracking email-related services.
- **/var/log/kern.log**: Зберігає kernel messages, включно з errors і warnings.
- **/var/log/dmesg**: Містить device driver messages.
- **/var/log/faillog**: Записує failed login attempts, допомагаючи в security breach investigations.
- **/var/log/cron**: Logs cron job executions.
- **/var/log/daemon.log**: Відстежує background service activities.
- **/var/log/btmp**: Документує failed login attempts.
- **/var/log/httpd/**: Містить Apache HTTPD error і access logs.
- **/var/log/mysqld.log** або **/var/log/mysql.log**: Logs MySQL database activities.
- **/var/log/xferlog**: Записує FTP file transfers.
- **/var/log/**: Завжди перевіряйте тут unexpected logs.

> [!TIP]
> Linux system logs і audit subsystems можуть бути disabled або deleted під час intrusion або malware incident. Оскільки logs на Linux systems зазвичай містять одні з найкорисніших відомостей про malicious activities, intruders регулярно видаляють їх. Тому, під час огляду доступних log files, важливо шукати gaps або out of order entries, що можуть бути ознакою deletion або tampering.

### Journald triage (`journalctl`)

На сучасних Linux hosts, **systemd journal** зазвичай є найціннішим джерелом для **service execution**, **auth events**, **package operations** та **kernel/user-space messages**. Під час live response намагайтеся зберегти і **persistent** journal (`/var/log/journal/`), і **runtime** journal (`/run/log/journal/`), тому що короткоживуча attacker activity може існувати лише в останньому.
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
Корисні поля journal для triage включають `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, і `MESSAGE`. Якщо `journald` було налаштовано без persistent storage, очікуйте лише недавні дані в `/run/log/journal/`.

### Audit framework triage (`auditd`)

Якщо `auditd` увімкнено, надавайте йому перевагу щоразу, коли вам потрібна **process attribution** для змін файлів, виконання команд, activity входу або встановлення пакетів.
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
Коли правила були розгорнуті з ключами, pivot від них замість grep по сирих логах:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux maintains a command history for each user**, stored in:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Moreover, the `last -Faiwx` command provides a list of user logins. Check it for unknown or unexpected logins.

Check files that can grant extra rprivileges:

- Review `/etc/sudoers` for unanticipated user privileges that may have been granted.
- Review `/etc/sudoers.d/` for unanticipated user privileges that may have been granted.
- Examine `/etc/groups` to identify any unusual group memberships or permissions.
- Examine `/etc/passwd` to identify any unusual group memberships or permissions.

Some apps alse generates its own logs:

- **SSH**: Examine _\~/.ssh/authorized_keys_ and _\~/.ssh/known_hosts_ for unauthorized remote connections.
- **Gnome Desktop**: Look into _\~/.recently-used.xbel_ for recently accessed files via Gnome applications.
- **Firefox/Chrome**: Check browser history and downloads in _\~/.mozilla/firefox_ or _\~/.config/google-chrome_ for suspicious activities.
- **VIM**: Review _\~/.viminfo_ for usage details, such as accessed file paths and search history.
- **Open Office**: Check for recent document access that may indicate compromised files.
- **FTP/SFTP**: Review logs in _\~/.ftp_history_ or _\~/.sftp_history_ for file transfers that might be unauthorized.
- **MySQL**: Investigate _\~/.mysql_history_ for executed MySQL queries, potentially revealing unauthorized database activities.
- **Less**: Analyze _\~/.lesshst_ for usage history, including viewed files and commands executed.
- **Git**: Examine _\~/.gitconfig_ and project _.git/logs_ for changes to repositories.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) is a small piece of software written in pure Python 3 which parses Linux log files (`/var/log/syslog*` or `/var/log/messages*` depending on the distro) for constructing USB event history tables.

It is interesting to **know all the USBs that have been used** and it will be more useful if you have an authorized list of USBs to find "violation events" (the use of USBs that aren't inside that list).

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
More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Огляд облікових записів користувачів і активностей входу

Перевірте _**/etc/passwd**_, _**/etc/shadow**_ та **security logs** на наявність незвичних імен або облікових записів, створених та/або використаних близько до відомих несанкціонованих подій. Також перевірте можливі sudo brute-force attacks.\
Крім того, перевірте файли на кшталт _**/etc/sudoers**_ та _**/etc/groups**_ на наявність неочікуваних привілеїв, наданих користувачам.\
Нарешті, шукайте облікові записи з **no passwords** або **easily guessed** passwords.

## Дослідження файлової системи

### Аналіз структур файлової системи під час розслідування malware

Під час розслідування інцидентів з malware структура файлової системи є критично важливим джерелом інформації, оскільки вона розкриває як послідовність подій, так і вміст malware. Однак автори malware розробляють техніки, щоб ускладнити такий аналіз, наприклад, змінюючи часові мітки файлів або уникаючи файлової системи для зберігання даних.

Щоб протидіяти цим антифорензичним методам, важливо:

- **Провести ретельний аналіз таймлайну** за допомогою таких інструментів, як **Autopsy** для візуалізації таймлайнів подій або `mactime` з **Sleuth Kit** для детальних даних таймлайну.
- **Дослідити неочікувані скрипти** у $PATH системи, які можуть включати shell- або PHP-скрипти, використані атакувальниками.
- **Перевірити `/dev` на нетипові файли**, оскільки він традиційно містить спеціальні файли, але може приховувати файли, пов’язані з malware.
- **Шукати приховані файли або каталоги** з іменами на кшталт ".. " (dot dot space) або "..^G" (dot dot control-G), які можуть приховувати шкідливий вміст.
- **Ідентифікувати setuid root файли** за допомогою команди: `find / -user root -perm -04000 -print` Це знаходить файли з підвищеними правами, якими можуть зловживати атакувальники.
- **Перевіряти часові мітки видалення** в inode tables, щоб виявити масові видалення файлів, що може вказувати на наявність rootkits або trojans.
- **Оглядати послідовні inode** на предмет розташованих поруч шкідливих файлів після виявлення одного, оскільки їх могли розмістити разом.
- **Перевіряти поширені каталоги бінарників** (_/bin_, _/sbin_) на наявність нещодавно змінених файлів, оскільки вони могли бути змінені malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Зауважте, що **attacker** може **змінювати** **time**, щоб **files appear** **legitimate**, але він **cannot** змінити **inode**. Якщо ви виявите, що **file** вказує на те, що він був створений і змінений у **same time** as решта файлів у тій самій папці, але **inode** є **unexpectedly bigger**, тоді **timestamps of that file were modified**.

### Inode-focused quick triage

If you suspect anti-forensics, run these inode-focused checks early:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Коли підозрілий inode знаходиться на образі/пристрої EXT filesystem, перевіряйте метадані inode напряму:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Корисні поля:
- **Links**: якщо `0`, жоден запис у каталозі наразі не посилається на inode.
- **dtime**: мітка часу видалення, яка встановлюється, коли inode було від’єднано.
- **ctime/mtime**: допомагає співвіднести зміни метаданих/вмісту з таймлайном інциденту.

### Capabilities, xattrs, and preload-based userland rootkits

Сучасна стійкість у Linux часто уникає очевидних `setuid` binaries і натомість зловживає **file capabilities**, **extended attributes** та dynamic loader.
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
Зверніть особливу увагу на libraries, на які посилаються з **writable** шляхів, таких як `/tmp`, `/dev/shm`, `/var/tmp`, або незвичних розташувань під `/usr/local/lib`. Також перевірте binaries з capability поза звичайною належністю package і зіставте їх із результатами перевірки package (`rpm -Va`, `dpkg --verify`, `debsums`).

## Порівняння files різних filesystem versions

### Підсумок порівняння filesystem version

Щоб порівняти filesystem version і точно визначити зміни, ми використовуємо спрощені команди `git diff`:

- **Щоб знайти new files**, порівняйте два directories:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Для зміненого вмісту**, перелічіть зміни, ігноруючи конкретні рядки:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Щоб виявити видалені файли**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Опції фільтрації** (`--diff-filter`) допомагають звузити вибір до конкретних змін, таких як додані (`A`), видалені (`D`) або змінені (`M`) файли.
- `A`: Додані файли
- `C`: Скопійовані файли
- `D`: Видалені файли
- `M`: Змінені файли
- `R`: Перейменовані файли
- `T`: Зміни типу (наприклад, файл на symlink)
- `U`: Не об’єднані файли
- `X`: Невідомі файли
- `B`: Пошкоджені файли

## References

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Book: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [Say hi to Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [strace](https://strace.io/)
- [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
