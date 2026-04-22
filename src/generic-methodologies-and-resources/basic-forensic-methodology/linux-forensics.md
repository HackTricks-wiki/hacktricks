# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Początkowe zbieranie informacji

### Podstawowe informacje

Przede wszystkim zaleca się mieć jakiś **USB** z **dobrze znanymi binary i libraries** na nim (możesz po prostu pobrać ubuntu i skopiować foldery _/bin_, _/sbin_, _/lib,_ oraz _/lib64_), następnie zamontować USB i zmodyfikować zmienne env, aby używać tych binary:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Gdy skonfigurujesz system tak, aby używał dobrych i znanych binariów, możesz zacząć **wyciągać kilka podstawowych informacji**:
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
#### Podejrzane informacje

Podczas zbierania podstawowych informacji powinieneś sprawdzać dziwne rzeczy, takie jak:

- **Procesy root** zwykle działają z niskimi PID-ami, więc jeśli znajdziesz proces root z dużym PID-em, możesz coś podejrzewać
- Sprawdź **zarejestrowane logowania** użytkowników bez shell w `/etc/passwd`
- Sprawdź **hashes haseł** w `/etc/shadow` dla użytkowników bez shell

### Memory Dump

Aby pobrać pamięć działającego systemu, zaleca się użycie [**LiME**](https://github.com/504ensicsLabs/LiME).\
Aby go **skompilować**, musisz użyć **tego samego kernel** co maszyna ofiary.

> [!TIP]
> Pamiętaj, że **nie możesz zainstalować LiME ani niczego innego** na maszynie ofiary, ponieważ spowoduje to wiele zmian w systemie

Jeśli więc masz identyczną wersję Ubuntu, możesz użyć `apt-get install lime-forensics-dkms`\
W innych przypadkach musisz pobrać [**LiME**](https://github.com/504ensicsLabs/LiME) z github i skompilować go z poprawnymi nagłówkami kernel. Aby **uzyskać dokładne nagłówki kernel** maszyny ofiary, możesz po prostu **skopiować katalog** `/lib/modules/<kernel version>` na swoją maszynę, a następnie **skompilować** LiME, używając ich:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME obsługuje 3 **formats**:

- Raw (każdy segment sklejony razem)
- Padded (tak samo jak raw, ale z zerami w prawych bitach)
- Lime (zalecany format z metadanymi)

LiME może być również używany do **wysyłania dumpu przez network** zamiast zapisywania go w systemie, używając czegoś takiego: `path=tcp:4444`

### Disk Imaging

#### Shutting down

Przede wszystkim będziesz musiał **wyłączyć system**. Nie zawsze jest to możliwe, ponieważ czasami system będzie serwerem produkcyjnym, którego firma nie może sobie pozwolić wyłączyć.\
Istnieją **2 sposoby** wyłączania systemu, **normalne shutdown** oraz **"plug the plug" shutdown**. Pierwsza opcja pozwoli **procesom zakończyć się jak zwykle** i **filesystem** zostanie **zsynchronizowany**, ale jednocześnie umożliwi potencjalnemu **malware** **zniszczenie dowodów**. Podejście "pull the plug" może spowodować **pewną utratę informacji** (niewiele informacji zostanie utraconych, ponieważ wykonaliśmy już obraz pamięci) i **malware nie będzie miało żadnej możliwości**, aby cokolwiek z tym zrobić. Dlatego jeśli **podejrzewasz**, że może być tam **malware**, po prostu wykonaj **`sync`** **command** na systemie i wyciągnij wtyczkę.

#### Taking an image of the disk

Ważne jest, aby pamiętać, że **przed podłączeniem komputera do czegokolwiek związanego ze sprawą**, musisz upewnić się, że dysk zostanie **zamontowany tylko do odczytu** aby uniknąć modyfikowania jakichkolwiek informacji.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Wstępna analiza obrazu dysku

Tworzenie obrazu dysku bez dalszych danych.
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
## Szukaj znanego Malware

### Zmodyfikowane pliki systemowe

Linux oferuje narzędzia do zapewnienia integralności komponentów systemowych, co jest kluczowe do wykrywania potencjalnie problematycznych plików.

- **Systemy oparte na RedHat**: Użyj `rpm -Va` do kompleksowej weryfikacji.
- **Systemy oparte na Debian**: `dpkg --verify` do wstępnej weryfikacji, a następnie `debsums | grep -v "OK$"` (po zainstalowaniu `debsums` za pomocą `apt-get install debsums`) aby zidentyfikować wszelkie problemy.

### Detektory Malware/Rootkit

Przeczytaj następującą stronę, aby dowiedzieć się o narzędziach, które mogą być przydatne do znalezienia malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Szukaj zainstalowanych programów

Aby skutecznie wyszukiwać zainstalowane programy zarówno na systemach Debian, jak i RedHat, rozważ wykorzystanie logów i baz danych systemowych wraz z ręcznymi sprawdzeniami w typowych katalogach.

- W Debianie sprawdź _**`/var/lib/dpkg/status`**_ oraz _**`/var/log/dpkg.log`**_, aby pobrać szczegóły dotyczące instalacji pakietów, używając `grep` do filtrowania konkretnych informacji.
- Użytkownicy RedHat mogą odpytywać bazę danych RPM za pomocą `rpm -qa --root=/mntpath/var/lib/rpm`, aby wyświetlić listę zainstalowanych pakietów.

Aby wykryć oprogramowanie zainstalowane ręcznie lub poza tymi menedżerami pakietów, przeszukaj katalogi takie jak _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, oraz _**`/sbin`**_. Połącz listowania katalogów z poleceniami specyficznymi dla systemu, aby zidentyfikować pliki wykonywalne niepowiązane ze znanymi pakietami, wzmacniając swoje poszukiwania wszystkich zainstalowanych programów.
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
## Odzyskiwanie usuniętych działających binariów

Wyobraź sobie proces, który został uruchomiony z /tmp/exec, a następnie usunięty. Możliwe jest jego wyodrębnienie
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Sprawdź lokalizacje autostartu

### Zaplanowane zadania
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
#### Polowanie: nadużycie Cron/Anacron przez 0anacron i podejrzane stuby
Atakujący często edytują stub 0anacron obecny w każdym katalogu /etc/cron.*/ aby zapewnić okresowe wykonywanie.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Polowanie: cofnięcie hardeningu SSH i backdoor shelli
Zmiany w sshd_config i shellach kont systemowych są częste po exploitation, aby zachować dostęp.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Beacony Dropbox API zazwyczaj używają api.dropboxapi.com lub content.dropboxapi.com przez HTTPS z tokenami Authorization: Bearer.
- Szukaj w proxy/Zeek/NetFlow nieoczekiwanego ruchu wychodzącego do Dropbox z serwerów.
- Cloudflare Tunnel (`cloudflared`) zapewnia zapasowy C2 przez wychodzący port 443.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Ścieżki, w których malware może zostać zainstalowany jako usługa:

- **/etc/inittab**: Wywołuje skrypty inicjalizacyjne, takie jak rc.sysinit, kierując dalej do skryptów startowych.
- **/etc/rc.d/** i **/etc/rc.boot/**: Zawierają skrypty do uruchamiania usług; ten drugi katalog występuje w starszych wersjach Linux.
- **/etc/init.d/**: Używany w niektórych wersjach Linux, takich jak Debian, do przechowywania skryptów startowych.
- Usługi mogą być też aktywowane przez **/etc/inetd.conf** lub **/etc/xinetd/**, zależnie od wariantu Linux.
- **/etc/systemd/system**: Katalog dla skryptów systemowych i menedżera usług.
- **/etc/systemd/system/multi-user.target.wants/**: Zawiera linki do usług, które powinny zostać uruchomione w wieloużytkownikowym runlevel.
- **/usr/local/etc/rc.d/**: Dla usług niestandardowych lub firm trzecich.
- **\~/.config/autostart/**: Dla aplikacji automatycznie uruchamianych specyficznych dla użytkownika, co może być miejscem ukrycia malware ukierunkowanego na użytkownika.
- **/lib/systemd/system/**: Domyślne pliki jednostek dla całego systemu dostarczane przez zainstalowane pakiety.

#### Hunt: systemd timers and transient units

Persistence w systemd nie ogranicza się do plików `.service`. Sprawdź jednostki `.timer`, jednostki na poziomie użytkownika oraz **transient units** tworzone w czasie działania.
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

Moduły jądra Linux, często wykorzystywane przez malware jako komponenty rootkit, są ładowane podczas startu systemu. Katalogi i pliki kluczowe dla tych modułów obejmują:

- **/lib/modules/$(uname -r)**: Zawiera moduły dla uruchomionej wersji jądra.
- **/etc/modprobe.d**: Zawiera pliki konfiguracyjne sterujące ładowaniem modułów.
- **/etc/modprobe** and **/etc/modprobe.conf**: Pliki globalnych ustawień modułów.

### Other Autostart Locations

Linux wykorzystuje różne pliki do automatycznego uruchamiania programów po zalogowaniu użytkownika, co może skrywać malware:

- **/etc/profile.d/**\*, **/etc/profile**, and **/etc/bash.bashrc**: Wykonywane przy każdym logowaniu użytkownika.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, and **\~/.config/autostart**: Pliki specyficzne dla użytkownika, uruchamiane przy jego logowaniu.
- **/etc/rc.local**: Uruchamiany po starcie wszystkich usług systemowych, oznaczając koniec przejścia do środowiska wieloużytkownikowego.

## Examine Logs

Systemy Linux śledzą aktywność użytkowników i zdarzenia systemowe za pomocą różnych plików logów. Logi te są kluczowe do identyfikacji nieautoryzowanego dostępu, infekcji malware i innych incydentów bezpieczeństwa. Najważniejsze pliki logów obejmują:

- **/var/log/syslog** (Debian) or **/var/log/messages** (RedHat): Zawierają komunikaty i aktywności obejmujące cały system.
- **/var/log/auth.log** (Debian) or **/var/log/secure** (RedHat): Rejestrują próby uwierzytelnienia, udane i nieudane logowania.
- Use `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` to filter relevant authentication events.
- **/var/log/boot.log**: Zawiera komunikaty startowe systemu.
- **/var/log/maillog** or **/var/log/mail.log**: Logi aktywności serwera poczty, przydatne do śledzenia usług związanych z e-mail.
- **/var/log/kern.log**: Przechowuje komunikaty jądra, w tym błędy i ostrzeżenia.
- **/var/log/dmesg**: Zawiera komunikaty sterowników urządzeń.
- **/var/log/faillog**: Rejestruje nieudane próby logowania, pomagając w badaniach naruszeń bezpieczeństwa.
- **/var/log/cron**: Loguje wykonania zadań cron.
- **/var/log/daemon.log**: Śledzi aktywność usług działających w tle.
- **/var/log/btmp**: Dokumentuje nieudane próby logowania.
- **/var/log/httpd/**: Zawiera logi błędów i dostępu Apache HTTPD.
- **/var/log/mysqld.log** or **/var/log/mysql.log**: Logi aktywności bazy danych MySQL.
- **/var/log/xferlog**: Rejestruje transfery plików FTP.
- **/var/log/**: Zawsze sprawdzaj tutaj pod kątem nieoczekiwanych logów.

> [!TIP]
> Logi systemowe Linux i podsystemy audytu mogą być wyłączone lub usunięte podczas włamania albo incydentu z malware. Ponieważ logi w systemach Linux zwykle zawierają jedne z najbardziej użytecznych informacji o złośliwej aktywności, intruzi rutynowo je usuwają. Dlatego podczas analizowania dostępnych plików logów ważne jest szukanie luk lub wpisów w nieprawidłowej kolejności, które mogą wskazywać na usunięcie albo manipulację.

### Journald triage (`journalctl`)

Na nowoczesnych hostach Linux, **systemd journal** jest zwykle najcenniejszym źródłem informacji o **wykonywaniu usług**, **zdarzeniach auth**, **operacjach na pakietach** oraz komunikatach **kernel/user-space**. Podczas live response postaraj się zachować zarówno **persistent** journal (`/var/log/journal/`), jak i **runtime** journal (`/run/log/journal/`), ponieważ krótkotrwała aktywność atakującego może istnieć tylko w tym drugim.
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
Przydatne pola journal do triage obejmują `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` oraz `MESSAGE`. Jeśli journald był skonfigurowany bez trwałego storage, spodziewaj się tylko najnowszych danych w `/run/log/journal/`.

### Triage frameworku audytu (`auditd`)

Jeśli `auditd` jest włączony, preferuj go zawsze, gdy potrzebujesz **process attribution** dla zmian plików, wykonania poleceń, aktywności logowania lub instalacji pakietów.
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
Gdy reguły zostały wdrożone z kluczami, pivotuj od nich zamiast przeszukiwać surowe logi:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux utrzymuje historię poleceń dla każdego użytkownika**, przechowywaną w:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Ponadto polecenie `last -Faiwx` udostępnia listę logowań użytkowników. Sprawdź je pod kątem nieznanych lub nieoczekiwanych logowań.

Sprawdź pliki, które mogą nadawać dodatkowe uprawnienia:

- Przejrzyj `/etc/sudoers` pod kątem nieoczekiwanych uprawnień użytkowników, które mogły zostać przyznane.
- Przejrzyj `/etc/sudoers.d/` pod kątem nieoczekiwanych uprawnień użytkowników, które mogły zostać przyznane.
- Sprawdź `/etc/groups`, aby zidentyfikować nietypowe członkostwa w grupach lub uprawnienia.
- Sprawdź `/etc/passwd`, aby zidentyfikować nietypowe członkostwa w grupach lub uprawnienia.

Niektóre aplikacje również generują własne logi:

- **SSH**: Sprawdź _\~/.ssh/authorized_keys_ i _\~/.ssh/known_hosts_ pod kątem nieautoryzowanych połączeń zdalnych.
- **Gnome Desktop**: Zajrzyj do _\~/.recently-used.xbel_ w poszukiwaniu ostatnio otwieranych plików przez aplikacje Gnome.
- **Firefox/Chrome**: Sprawdź historię przeglądarki i pobrane pliki w _\~/.mozilla/firefox_ lub _\~/.config/google-chrome_ pod kątem podejrzanej aktywności.
- **VIM**: Przejrzyj _\~/.viminfo_ pod kątem szczegółów użycia, takich jak ścieżki do otwieranych plików i historia wyszukiwania.
- **Open Office**: Sprawdź ostatni dostęp do dokumentów, który może wskazywać na przejęte pliki.
- **FTP/SFTP**: Przejrzyj logi w _\~/.ftp_history_ lub _\~/.sftp_history_ pod kątem transferów plików, które mogły być nieautoryzowane.
- **MySQL**: Przeanalizuj _\~/.mysql_history_ pod kątem wykonanych zapytań MySQL, co może ujawniać nieautoryzowane działania na bazie danych.
- **Less**: Przeanalizuj _\~/.lesshst_ pod kątem historii użycia, w tym przeglądanych plików i wykonywanych poleceń.
- **Git**: Sprawdź _\~/.gitconfig_ oraz _.git/logs_ projektów pod kątem zmian w repozytoriach.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) to niewielki program napisany w czystym Pythonie 3, który analizuje pliki logów Linuxa (`/var/log/syslog*` lub `/var/log/messages*` w zależności od dystrybucji), aby tworzyć tabele historii zdarzeń USB.

Warto **znać wszystkie USB, które były używane**, a będzie to jeszcze bardziej przydatne, jeśli masz autoryzowaną listę USB, aby znaleźć „violation events” (użycie USB, których nie ma na tej liście).

### Installation
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Przykłady
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Więcej przykładów i informacji znajdziesz na githubie: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Review User Accounts and Logon Activities

Sprawdź _**/etc/passwd**_, _**/etc/shadow**_ oraz **security logs** pod kątem nietypowych nazw lub kont utworzonych i/lub używanych blisko w czasie znanych nieautoryzowanych zdarzeń. Sprawdź też możliwe ataki brute-force na sudo.\
Ponadto sprawdź pliki takie jak _**/etc/sudoers**_ i _**/etc/groups**_ pod kątem nieoczekiwanych uprawnień nadanych użytkownikom.\
Na koniec poszukaj kont z **brakiem haseł** lub **łatwymi do odgadnięcia** hasłami.

## Examine File System

### Analyzing File System Structures in Malware Investigation

Podczas badania incydentów malware, struktura systemu plików jest kluczowym źródłem informacji, ujawniając zarówno sekwencję zdarzeń, jak i zawartość malware. Jednak autorzy malware rozwijają techniki utrudniające taką analizę, takie jak modyfikowanie znaczników czasu plików lub unikanie systemu plików do przechowywania danych.

Aby przeciwdziałać tym metodom anti-forensic, warto:

- **Conduct a thorough timeline analysis** using tools like **Autopsy** for visualizing event timelines or **Sleuth Kit's** `mactime` for detailed timeline data.
- **Investigate unexpected scripts** in the system's $PATH, which might include shell or PHP scripts used by attackers.
- **Examine `/dev` for atypical files**, as it traditionally contains special files, but may house malware-related files.
- **Search for hidden files or directories** with names like ".. " (dot dot space) or "..^G" (dot dot control-G), which could conceal malicious content.
- **Identify setuid root files** using the command: `find / -user root -perm -04000 -print` This finds files with elevated permissions, which could be abused by attackers.
- **Review deletion timestamps** in inode tables to spot mass file deletions, possibly indicating the presence of rootkits or trojans.
- **Inspect consecutive inodes** for nearby malicious files after identifying one, as they may have been placed together.
- **Check common binary directories** (_/bin_, _/sbin_) for recently modified files, as these could be altered by malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Zauważ, że **atakujący** może **zmodyfikować** **czas**, aby **pliki wyglądały** na **legalne**, ale nie może zmodyfikować **inode**. Jeśli stwierdzisz, że **plik** wskazuje, iż został utworzony i zmodyfikowany w **tym samym czasie** co reszta plików w tym samym folderze, ale **inode** jest **nieoczekiwanie większy**, to **timestampy tego pliku zostały zmodyfikowane**.

### Szybka triage skoncentrowana na inode

Jeśli podejrzewasz anti-forensics, uruchom wcześnie te kontrole skoncentrowane na inode:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Gdy podejrzany inode znajduje się na obrazie/urządzeniu systemu plików EXT, sprawdź metadane inode bezpośrednio:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Przydatne pola:
- **Links**: jeśli `0`, żaden wpis katalogu obecnie nie odwołuje się do inode.
- **dtime**: znacznik czasu usunięcia ustawiany, gdy inode został odłączony.
- **ctime/mtime**: pomaga skorelować zmiany metadanych/zawartości z osią czasu incydentu.

### Capabilities, xattrs, and preload-based userland rootkits

Nowoczesna persystencja w Linux często unika oczywistych binarek `setuid` i zamiast tego nadużywa **file capabilities**, **extended attributes** oraz dynamicznego loadera.
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
Zwróć szczególną uwagę na biblioteki odwoływane z **zapisywalnych** ścieżek takich jak `/tmp`, `/dev/shm`, `/var/tmp` lub nietypowych lokalizacji w `/usr/local/lib`. Sprawdź też binaria z capability poza normalnym ownership pakietów i skoreluj je z wynikami weryfikacji pakietów (`rpm -Va`, `dpkg --verify`, `debsums`).

## Porównywanie plików różnych wersji systemu plików

### Podsumowanie porównania wersji systemu plików

Aby porównywać wersje systemu plików i wskazywać zmiany, używamy uproszczonych poleceń `git diff`:

- **Aby znaleźć nowe pliki**, porównaj dwa katalogi:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Dla zmodyfikowanej treści**, wypisz zmiany, ignorując określone linie:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Aby wykryć usunięte pliki**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Opcje filtrowania** (`--diff-filter`) pomagają zawęzić wyniki do konkretnych zmian, takich jak dodane (`A`), usunięte (`D`) lub zmodyfikowane (`M`) pliki.
- `A`: Dodane pliki
- `C`: Skopiowane pliki
- `D`: Usunięte pliki
- `M`: Zmodyfikowane pliki
- `R`: Zmienione nazwy plików
- `T`: Zmiany typu (np. plik na symlink)
- `U`: Niezłączone pliki
- `X`: Nieznane pliki
- `B`: Uszkodzone pliki

## References

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Book: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)

{{#include ../../banners/hacktricks-training.md}}
