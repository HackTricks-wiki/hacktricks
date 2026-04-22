# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Початковий збір інформації

### Основна інформація

Перш за все, рекомендується мати якийсь **USB** з **добре відомими бінарними файлами та бібліотеками** на ньому (ви можете просто взяти ubuntu і скопіювати папки _/bin_, _/sbin_, _/lib,_ і _/lib64_), потім змонтувати USB і змінити змінні env, щоб використовувати ці бінарні файли:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Після того як ви налаштували систему на використання good і known binaries, ви можете почати **extraction some basic information**:
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

Щоб отримати memory працюючої системи, рекомендовано використовувати [**LiME**](https://github.com/504ensicsLabs/LiME).\
Щоб його **compile**-нути, вам потрібно використовувати **той самий kernel**, що й на машині жертви.

> [!TIP]
> Пам’ятайте, що ви **не можете встановлювати LiME або будь-що інше** на машині жертви, оскільки це внесе в неї кілька змін

Тож, якщо у вас є ідентична версія Ubuntu, ви можете використати `apt-get install lime-forensics-dkms`\
В інших випадках вам потрібно завантажити [**LiME**](https://github.com/504ensicsLabs/LiME) з github і compile-нути його з правильними kernel headers. Щоб **отримати точні kernel headers** машини жертви, ви можете просто **скопіювати директорію** `/lib/modules/<kernel version>` на свою машину, а потім **compile**-нути LiME, використовуючи їх:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME підтримує 3 **formats**:

- Raw (усі сегменти, з’єднані разом)
- Padded (як raw, але з нулями в правих бітах)
- Lime (рекомендований format з metadata)

LiME також можна використовувати, щоб **відправити dump через network** замість збереження його в системі, використовуючи щось на кшталт: `path=tcp:4444`

### Disk Imaging

#### Shutting down

Перш за все, вам потрібно **shut down the system**. Це не завжди можливо, оскільки інколи system може бути production server, який компанія не може собі дозволити вимкнути.\
Існують **2 ways** вимкнення system: **normal shutdown** і **"plug the plug" shutdown**. Перший дозволить **processes** завершитися як зазвичай, а **filesystem** буде **synchronized**, але також це дасть можливість **malware** **destroy evidence**. Підхід "pull the plug" може спричинити **some information loss** (не так багато info буде втрачено, оскільки ми вже зробили image memory ) і **malware won't have any opportunity** щось із цим зробити. Тому, якщо ви **suspect**, що там може бути **malware**, просто виконайте **`sync`** **command** у system і висмикніть вилку.

#### Taking an image of the disk

Важливо зазначити, що **before connecting your computer to anything related to the case**, вам потрібно переконатися, що воно буде **mounted as read only**, щоб уникнути зміни будь-якої інформації.
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

### Зміненi системні файли

Linux пропонує інструменти для забезпечення цілісності системних компонентів, що є критично важливим для виявлення потенційно проблемних файлів.

- **Системи на базі RedHat**: Використовуйте `rpm -Va` для комплексної перевірки.
- **Системи на базі Debian**: `dpkg --verify` для початкової перевірки, а потім `debsums | grep -v "OK$"` (після встановлення `debsums` за допомогою `apt-get install debsums`) для виявлення будь-яких проблем.

### Детектори Malware/Rootkit

Прочитайте таку сторінку, щоб дізнатися про інструменти, які можуть бути корисні для пошуку malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Пошук встановлених програм

Щоб ефективно шукати встановлені програми на системах Debian і RedHat, варто використовувати системні журнали й бази даних разом із ручною перевіркою у типових каталогах.

- Для Debian перевіряйте _**`/var/lib/dpkg/status`**_ і _**`/var/log/dpkg.log`**_ для отримання деталей про встановлення пакетів, використовуючи `grep` для фільтрації конкретної інформації.
- Користувачі RedHat можуть робити запити до бази даних RPM за допомогою `rpm -qa --root=/mntpath/var/lib/rpm`, щоб вивести список встановлених пакетів.

Щоб виявити програмне забезпечення, встановлене вручну або поза цими менеджерами пакетів, досліджуйте такі каталоги, як _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, і _**`/sbin`**_. Поєднуйте перелік вмісту каталогів із системно-специфічними командами, щоб виявити виконувані файли, не пов’язані з відомими пакетами, посилюючи пошук усіх встановлених програм.
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

Уявіть процес, який було запущено з /tmp/exec, а потім видалено. Його можна витягти
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Перевірте розташування Autostart

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
#### Полювання: зловживання Cron/Anacron через 0anacron і підозрілі stubs
Зловмисники часто редагують stub 0anacron, що знаходиться в кожному каталозі /etc/cron.*/, щоб забезпечити періодичне виконання.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Полювання: відкат hardening SSH і backdoor shells
Зміни в sshd_config та shells системних облікових записів є поширеними після exploitation, щоб зберегти доступ.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Полювання: маркери Cloud C2 (Dropbox/Cloudflare Tunnel)
- Dropbox API beacons зазвичай використовують api.dropboxapi.com або content.dropboxapi.com через HTTPS з Authorization: Bearer tokens.
- Шукай у proxy/Zeek/NetFlow несподіваний Dropbox egress із серверів.
- Cloudflare Tunnel (`cloudflared`) забезпечує резервний C2 через outbound 443.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Шляхи, де malware може бути встановлено як service:

- **/etc/inittab**: Викликає scripts ініціалізації, як-от rc.sysinit, спрямовуючи далі до startup scripts.
- **/etc/rc.d/** і **/etc/rc.boot/**: Містять scripts для startup service, останній трапляється в старіших версіях Linux.
- **/etc/init.d/**: Використовується в певних версіях Linux, як-от Debian, для зберігання startup scripts.
- Services також можуть активуватися через **/etc/inetd.conf** або **/etc/xinetd/**, залежно від варіанту Linux.
- **/etc/systemd/system**: Директорія для scripts system і service manager.
- **/etc/systemd/system/multi-user.target.wants/**: Містить links до services, які мають запускатися в multi-user runlevel.
- **/usr/local/etc/rc.d/**: Для custom або third-party services.
- **\~/.config/autostart/**: Для user-specific automatic startup applications, що може бути місцем приховування malware, націленого на user.
- **/lib/systemd/system/**: System-wide default unit files, надані встановленими packages.

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
Transient units are easy to miss because `/run/systemd/transient/` is **non-persistent**. If you are collecting a live image, grab it before shutdown.

### Kernel Modules

Linux kernel modules, often utilized by malware as rootkit components, are loaded at system boot. The directories and files critical for these modules include:

- **/lib/modules/$(uname -r)**: Містить модулі для поточної версії ядра.
- **/etc/modprobe.d**: Містить конфігураційні файли для керування завантаженням модулів.
- **/etc/modprobe** and **/etc/modprobe.conf**: Файли для глобальних налаштувань модулів.

### Other Autostart Locations

Linux employs various files for automatically executing programs upon user login, potentially harboring malware:

- **/etc/profile.d/**\*, **/etc/profile**, and **/etc/bash.bashrc**: Виконуються для будь-якого входу користувача.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, and **\~/.config/autostart**: Користувацькі файли, що запускаються під час входу.
- **/etc/rc.local**: Запускається після того, як усі системні служби стартували, позначаючи кінець переходу до багатокористувацького середовища.

## Examine Logs

Linux systems track user activities and system events through various log files. These logs are pivotal for identifying unauthorized access, malware infections, and other security incidents. Key log files include:

- **/var/log/syslog** (Debian) or **/var/log/messages** (RedHat): Фіксують загальносистемні повідомлення та події.
- **/var/log/auth.log** (Debian) or **/var/log/secure** (RedHat): Записують спроби автентифікації, успішні та невдалі входи.
- Use `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` to filter relevant authentication events.
- **/var/log/boot.log**: Містить повідомлення запуску системи.
- **/var/log/maillog** or **/var/log/mail.log**: Логує активність поштового сервера, корисно для відстеження сервісів, пов’язаних з email.
- **/var/log/kern.log**: Зберігає повідомлення ядра, включно з помилками та попередженнями.
- **/var/log/dmesg**: Містить повідомлення драйверів пристроїв.
- **/var/log/faillog**: Записує невдалі спроби входу, допомагаючи в розслідуванні порушень безпеки.
- **/var/log/cron**: Логує виконання cron job.
- **/var/log/daemon.log**: Відстежує активність фонових служб.
- **/var/log/btmp**: Документує невдалі спроби входу.
- **/var/log/httpd/**: Містить error та access logs Apache HTTPD.
- **/var/log/mysqld.log** or **/var/log/mysql.log**: Логує активність бази даних MySQL.
- **/var/log/xferlog**: Записує FTP file transfers.
- **/var/log/**: Завжди перевіряйте тут наявність неочікуваних logs.

> [!TIP]
> Linux system logs and audit subsystems may be disabled or deleted in an intrusion or malware incident. Because logs on Linux systems generally contain some of the most useful information about malicious activities, intruders routinely delete them. Therefore, when examining available log files, it is important to look for gaps or out of order entries that might be an indication of deletion or tampering.

### Journald triage (`journalctl`)

On modern Linux hosts, the **systemd journal** is usually the highest-value source for **service execution**, **auth events**, **package operations**, and **kernel/user-space messages**. During live response, try to preserve both the **persistent** journal (`/var/log/journal/`) and the **runtime** journal (`/run/log/journal/`) because short-lived attacker activity may only exist in the latter.
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
Корисні поля journal для triage включають `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, і `MESSAGE`. Якщо `journald` було налаштовано без persistent storage, очікуйте лише нещодавні дані в `/run/log/journal/`.

### Audit framework triage (`auditd`)

Якщо `auditd` увімкнено, надавайте йому перевагу щоразу, коли вам потрібна **process attribution** для змін файлів, виконання команд, активності входу або встановлення пакетів.
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
Коли правила було розгорнуто з ключами, pivot from them instead of grepping raw logs:
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
Більше прикладів і інформації є в github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Перевірка облікових записів користувачів і дій входу

Перегляньте _**/etc/passwd**_, _**/etc/shadow**_ і **security logs** на наявність незвичних імен або облікових записів, створених і/або використаних поблизу відомих несанкціонованих подій. Також перевірте можливі brute-force атаки на sudo.\
Крім того, перевірте файли на кшталт _**/etc/sudoers**_ і _**/etc/groups**_ на наявність неочікуваних привілеїв, наданих користувачам.\
Нарешті, шукайте облікові записи з **no passwords** або **easily guessed** паролями.

## Дослідження файлової системи

### Аналіз структур файлової системи під час розслідування malware

Під час розслідування інцидентів malware структура файлової системи є критично важливим джерелом інформації, оскільки вона показує як послідовність подій, так і вміст malware. Однак автори malware розробляють техніки, щоб ускладнити цей аналіз, наприклад змінюючи часові мітки файлів або уникаючи файлової системи для зберігання даних.

Щоб протидіяти цим anti-forensic методам, важливо:

- **Провести ретельний аналіз timeline** за допомогою таких інструментів, як **Autopsy** для візуалізації таймлайнів подій або **Sleuth Kit's** `mactime` для детальних даних таймлайну.
- **Дослідити неочікувані скрипти** в $PATH системи, які можуть містити shell або PHP-скрипти, використані атакувальниками.
- **Перевірити `/dev` на нетипові файли**, оскільки традиційно там містяться спеціальні файли, але там можуть бути й файли, пов’язані з malware.
- **Шукати приховані файли або каталоги** з іменами на кшталт ".. " (крапка крапка пробіл) або "..^G" (крапка крапка control-G), які можуть приховувати шкідливий вміст.
- **Виявити setuid root файли** за допомогою команди: `find / -user root -perm -04000 -print` Це знаходить файли з підвищеними дозволами, які можуть бути використані атакувальниками.
- **Перевірити часові мітки видалення** в inode-таблицях, щоб помітити масові видалення файлів, що може вказувати на наявність rootkits або trojans.
- **Оглянути послідовні inode** на наявність поруч розміщених шкідливих файлів після виявлення одного, оскільки їх могли розмістити разом.
- **Перевірити поширені бінарні каталоги** (_/bin_, _/sbin_) на наявність нещодавно змінених файлів, оскільки вони могли бути змінені malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Зауважте, що **attacker** може **змінити** **time**, щоб **files appear** **legitimate**, але він **cannot** змінити **inode**. Якщо ви виявите, що **file** вказує на те, що його було створено й змінено в **same time** as the rest of the files in the same folder, але **inode** є **unexpectedly bigger**, тоді **timestamps of that file were modified**.

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
Коли на образі/пристрої EXT filesystem є підозрілий inode, перевіряйте inode metadata безпосередньо:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Корисні поля:
- **Links**: якщо `0`, жоден запис каталогу зараз не посилається на inode.
- **dtime**: мітка часу видалення, встановлена, коли inode було відв’язано.
- **ctime/mtime**: допомагає зіставляти зміни метаданих/вмісту з часовою шкалою інциденту.

### Capabilities, xattrs, and preload-based userland rootkits

Сучасна persistence у Linux часто уникає очевидних бінарників `setuid` і натомість зловживає **file capabilities**, **extended attributes** та dynamic loader.
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
Зверніть особливу увагу на бібліотеки, на які посилаються з **writable** шляхів, таких як `/tmp`, `/dev/shm`, `/var/tmp`, або дивних розташувань під `/usr/local/lib`. Також перевіряйте binaries з capability поза межами звичайного володіння package і зіставляйте їх із результатами перевірки package (`rpm -Va`, `dpkg --verify`, `debsums`).

## Compare files of different filesystem versions

### Filesystem Version Comparison Summary

Щоб порівняти версії filesystem і визначити зміни, ми використовуємо спрощені команди `git diff`:

- **Щоб знайти нові files**, порівняйте два directories:
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
- **Filter options** (`--diff-filter`) допомагають звузити вибір до конкретних змін, як-от додані (`A`), видалені (`D`) або змінені (`M`) файли.
- `A`: Added files
- `C`: Copied files
- `D`: Deleted files
- `M`: Modified files
- `R`: Renamed files
- `T`: Type changes (e.g., file to symlink)
- `U`: Unmerged files
- `X`: Unknown files
- `B`: Broken files

## References

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Book: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)

{{#include ../../banners/hacktricks-training.md}}
