# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Początkowe zbieranie informacji

### Podstawowe informacje

Przede wszystkim zaleca się mieć jakieś **USB** z **dobrze znanymi binariami i bibliotekami** (możesz po prostu pobrać ubuntu i skopiować foldery _/bin_, _/sbin_, _/lib,_ oraz _/lib64_), a następnie zamontować USB i zmodyfikować zmienne środowiskowe, aby używać tych binariów:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Gdy skonfigurujesz system tak, aby używał dobrych i znanych binary, możesz zacząć **wyodrębniać podstawowe informacje**:
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

- **Procesy root** zwykle działają z niskimi PIDami, więc jeśli znajdziesz proces root z dużym PID, możesz coś podejrzewać
- Sprawdź **zarejestrowane logowania** użytkowników bez shell w `/etc/passwd`
- Sprawdź **hashes haseł** w `/etc/shadow` dla użytkowników bez shell

### Memory Dump

Aby pobrać pamięć działającego systemu, zaleca się użycie [**LiME**](https://github.com/504ensicsLabs/LiME).\
Aby go **skompilować**, musisz użyć **tego samego kernel** co maszyna ofiary.

> [!TIP]
> Pamiętaj, że **nie możesz zainstalować LiME ani niczego innego** na maszynie ofiary, ponieważ wprowadzi to do niej kilka zmian

Jeśli więc masz identyczną wersję Ubuntu, możesz użyć `apt-get install lime-forensics-dkms`\
W innych przypadkach musisz pobrać [**LiME**](https://github.com/504ensicsLabs/LiME) z github i skompilować go z poprawnymi kernel headers. Aby **uzyskać dokładne kernel headers** maszyny ofiary, możesz po prostu **skopiować katalog** `/lib/modules/<kernel version>` na swoją maszynę, a następnie **skompilować** LiME, używając ich:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME obsługuje 3 **formaty**:

- Raw (każdy segment połączony razem)
- Padded (jak raw, ale z zerami w prawych bitach)
- Lime (zalecany format z metadanymi)

LiME może być również używany do **wysyłania dumpa przez sieć** zamiast zapisywania go w systemie, używając czegoś takiego jak: `path=tcp:4444`

### Disk Imaging

#### Shutting down

Przede wszystkim będziesz musiał **wyłączyć system**. Nie zawsze jest to możliwe, ponieważ czasem system może być serwerem produkcyjnym, którego firma nie może sobie pozwolić wyłączyć.\
Istnieją **2 sposoby** wyłączania systemu, **normalne zamknięcie** oraz **"pull the plug" shutdown**. Pierwszy pozwoli na **zakończenie procesów jak zwykle** i **zsynchronizowanie systemu plików**, ale jednocześnie umożliwi możliwemu **malware** **zniszczenie dowodów**. Podejście "pull the plug" może wiązać się z **pewną utratą informacji** (niewiele informacji zostanie utraconych, ponieważ i tak wykonaliśmy już obraz pamięci ) i **malware nie będzie miało żadnej możliwości** nic z tym zrobić. Dlatego jeśli **podejrzewasz**, że może tam być **malware**, po prostu wykonaj na systemie **polecenie** **`sync`** i wyciągnij wtyczkę.

#### Taking an image of the disk

Ważne jest, aby zauważyć, że **zanim podłączysz swój komputer do czegokolwiek związanego ze sprawą**, musisz upewnić się, że zostanie on **zamontowany tylko do odczytu**, aby uniknąć modyfikacji jakichkolwiek informacji.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Wstępna analiza obrazu dysku

Tworzenie obrazu dysku bez żadnych dodatkowych danych.
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

- **Systemy oparte na RedHat**: Użyj `rpm -Va` do kompleksowej kontroli.
- **Systemy oparte na Debian**: `dpkg --verify` do wstępnej weryfikacji, a następnie `debsums | grep -v "OK$"` (po zainstalowaniu `debsums` za pomocą `apt-get install debsums`) w celu zidentyfikowania wszelkich problemów.

### Detektory Malware/Rootkit

Przeczytaj następującą stronę, aby dowiedzieć się o narzędziach, które mogą być przydatne do wykrywania malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Szukaj zainstalowanych programów

Aby skutecznie wyszukiwać zainstalowane programy zarówno na systemach Debian, jak i RedHat, rozważ wykorzystanie logów systemowych i baz danych wraz z ręcznymi sprawdzeniami w typowych katalogach.

- W Debian, sprawdź _**`/var/lib/dpkg/status`**_ oraz _**`/var/log/dpkg.log`**_, aby pobrać szczegóły dotyczące instalacji pakietów, używając `grep` do filtrowania konkretnych informacji.
- Użytkownicy RedHat mogą odpytać bazę danych RPM poleceniem `rpm -qa --root=/mntpath/var/lib/rpm`, aby wyświetlić listę zainstalowanych pakietów.

Aby wykryć oprogramowanie zainstalowane ręcznie lub poza tymi menedżerami pakietów, przejrzyj katalogi takie jak _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ oraz _**`/sbin`**_. Połącz listowanie katalogów z poleceniami specyficznymi dla systemu, aby zidentyfikować pliki wykonywalne niepowiązane ze znanymi pakietami, co usprawni wyszukiwanie wszystkich zainstalowanych programów.
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
## Odzyskiwanie usuniętych uruchomionych binariów

Wyobraź sobie proces, który został uruchomiony z /tmp/exec, a następnie usunięty. Możliwe jest go wyodrębnienie
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Syscall Trace Triage with SQLite and FTS5

Gdy proces nadal działa lub można go ponownie uruchomić w labie, **`strace`** może zapewnić szybki trace behawioralny bez potrzeby używania modułów kernel ani pełnej telemetryki EDR. W przypadku dużych trace’ów unikaj bezpośredniego czytania surowego logu lub wklejania go do LLM: zapisz go w bazie danych **SQLite** i odpytywać tylko minimalny podzbiór, którego potrzebujesz.

> [!WARNING]
> Dołączanie `strace` zmienia timing procesu i może wpływać na race conditions lub inne kruche bugs. Gdy to możliwe, preferuj odtworzenie na kopii/systemie labowym.

### Capture

Dla nowego procesu:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Dla aktywnego procesu:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Przydatne opcje:

- `-ff`: śledź forki/wątki i zachowuj oddzielne wyniki dla każdego procesu
- `-ttt`: znaczniki czasu epoch do łatwej korelacji osi czasu
- `-yy`: rozwiązuj deskryptory plików do odpowiadających im ścieżek/socketów, gdy to możliwe
- `-s 4096`: zapobiegaj obcinaniu długich ścieżek i argumentów bufora

### Normalize

Praktyczny schemat to jeden wiersz na syscall i jeden wiersz na argument:
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
To unika próby spłaszczenia heterogenicznych linii syscall do jednej szerokiej tabeli i utrzymuje przewidywalne joiny podczas triage.

### Indeksuj argumenty z dużą ilością tekstu za pomocą FTS5

Naive path hunting z `LIKE "%...%"` staje się bardzo wolne na dużych śladach. Utwórz indeks FTS5 dla tekstu argumentów i wyszukuj za jego pomocą:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Przykład: odzyskaj aktywność plików w `/tmp` bez skanowania każdego wiersza:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Wysokosygnałowe dochodzenia

- **PATH hijacking / fake sudo**: szukaj zapisów i aktywności `chmod`/`rename` w `~/.local/bin/`, a potem skoreluj to z późniejszym `execve` nazw brzmiących uprzywilejowanie, takich jak `sudo`.
- **TOCTOU on temporary files**: oprzyj analizę na tej samej ścieżce `/tmp/...` w `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` i `execve`, aby wykryć luki typu check/use.
- **Crash root cause**: skoreluj `mmap` pliku z zapisami lub truncation tego samego inode/ścieżki przez inny proces, a następnie sprawdź sekwencję sygnału/wyjścia pod kątem `SIGBUS`.
- **Network destination recovery**: filtruj `connect`, `sendto`, `sendmsg`, `recvfrom` oraz argumenty związane z socketami, aby wyodrębnić adresy IP i porty peerów.

### LLM-assisted trace analysis

Jeśli chcesz, aby LLM pomógł, udostępnij **read-only** uchwyt SQLite i przekaż mu pełny schema. Pozwól mu wykonywać raw SQL zamiast zamykać bazę za wąskimi funkcjami pomocniczymi. Zwykle działa to lepiej przy joinach, korelacji czasowej i wyszukiwaniach FTS.

Praktyczne zasady:

- Utrzymuj bazę w trybie read-only, na przykład z `sqlite3 'file:trace.db?mode=ro'`.
- Daj modelowi przykłady poprawnych zapytań `JOIN` i `FTS5 MATCH`.
- Nie wklejaj surowych logów `strace` o rozmiarze wielu GB do promptu.
- Zadawaj precyzyjne pytania, takie jak:
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
#### Polowanie: nadużycie Cron/Anacron poprzez 0anacron i podejrzane stuby
Atakujący często edytują stub 0anacron znajdujący się w każdym katalogu /etc/cron.*/ aby zapewnić okresowe wykonywanie.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Polowanie: rollback hardeningu SSH i backdoor shells
Zmiany w sshd_config i shells kont systemowych są częste po exploitation, aby zachować dostęp.
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

Ścieżki, w których malware może zostać zainstalowany jako usługa:

- **/etc/inittab**: Wywołuje skrypty inicjalizacyjne, takie jak rc.sysinit, przekazując dalej do skryptów startowych.
- **/etc/rc.d/** i **/etc/rc.boot/**: Zawierają skrypty do uruchamiania usług, przy czym ten drugi występuje w starszych wersjach Linux.
- **/etc/init.d/**: Używane w niektórych wersjach Linux, takich jak Debian, do przechowywania skryptów startowych.
- Usługi mogą być też aktywowane przez **/etc/inetd.conf** lub **/etc/xinetd/**, w zależności od wariantu Linux.
- **/etc/systemd/system**: Katalog dla skryptów system i service manager.
- **/etc/systemd/system/multi-user.target.wants/**: Zawiera linki do usług, które powinny być uruchamiane w wieloużytkownikowym runlevel.
- **/usr/local/etc/rc.d/**: Dla usług niestandardowych lub firm trzecich.
- **\~/.config/autostart/**: Dla aplikacji automatycznie uruchamianych dla konkretnego użytkownika, co może być miejscem ukrycia malware ukierunkowanego na użytkownika.
- **/lib/systemd/system/**: Domyślne pliki unit dla całego systemu dostarczane przez zainstalowane pakiety.

#### Hunt: systemd timers and transient units

Systemd persistence nie ogranicza się do plików `.service`. Sprawdź jednostki `.timer`, jednostki na poziomie użytkownika oraz **transient units** tworzone w czasie działania.
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

Moduły jądra Linux, często wykorzystywane przez malware jako składniki rootkit, są ładowane przy starcie systemu. Katalogi i pliki kluczowe dla tych modułów obejmują:

- **/lib/modules/$(uname -r)**: Zawiera moduły dla uruchomionej wersji jądra.
- **/etc/modprobe.d**: Zawiera pliki konfiguracyjne do kontrolowania ładowania modułów.
- **/etc/modprobe** i **/etc/modprobe.conf**: Pliki globalnych ustawień modułów.

### Other Autostart Locations

Linux używa różnych plików do automatycznego uruchamiania programów podczas logowania użytkownika, co może skrywać malware:

- **/etc/profile.d/**\*, **/etc/profile**, i **/etc/bash.bashrc**: Wykonywane przy każdym logowaniu użytkownika.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, i **\~/.config/autostart**: Pliki specyficzne dla użytkownika, uruchamiane przy jego logowaniu.
- **/etc/rc.local**: Uruchamiany po starcie wszystkich usług systemowych, oznaczając koniec przejścia do środowiska wieloużytkownikowego.

## Examine Logs

Systemy Linux śledzą aktywność użytkowników i zdarzenia systemowe za pomocą różnych plików logów. Te logi są kluczowe do identyfikacji nieautoryzowanego dostępu, infekcji malware i innych incydentów bezpieczeństwa. Główne pliki logów obejmują:

- **/var/log/syslog** (Debian) lub **/var/log/messages** (RedHat): Przechwytują komunikaty i aktywność całego systemu.
- **/var/log/auth.log** (Debian) lub **/var/log/secure** (RedHat): Rejestrują próby uwierzytelnienia, udane i nieudane logowania.
- Użyj `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log`, aby filtrować istotne zdarzenia uwierzytelniania.
- **/var/log/boot.log**: Zawiera komunikaty uruchamiania systemu.
- **/var/log/maillog** lub **/var/log/mail.log**: Logują aktywność serwera poczty, przydatne do śledzenia usług związanych z email.
- **/var/log/kern.log**: Przechowuje komunikaty jądra, w tym błędy i ostrzeżenia.
- **/var/log/dmesg**: Zawiera komunikaty sterowników urządzeń.
- **/var/log/faillog**: Rejestruje nieudane próby logowania, pomagając w dochodzeniach dotyczących naruszeń bezpieczeństwa.
- **/var/log/cron**: Loguje wykonywanie zadań cron.
- **/var/log/daemon.log**: Śledzi aktywność usług działających w tle.
- **/var/log/btmp**: Dokumentuje nieudane próby logowania.
- **/var/log/httpd/**: Zawiera logi błędów i dostępu Apache HTTPD.
- **/var/log/mysqld.log** lub **/var/log/mysql.log**: Logują aktywność bazy danych MySQL.
- **/var/log/xferlog**: Rejestruje transfery plików FTP.
- **/var/log/**: Zawsze sprawdzaj tutaj nietypowe logi.

> [!TIP]
> Systemowe logi Linux i podsystemy audytu mogą zostać wyłączone lub usunięte podczas włamania lub incydentu z malware. Ponieważ logi na systemach Linux zazwyczaj zawierają jedne z najbardziej użytecznych informacji o złośliwych działaniach, intruzi rutynowo je usuwają. Dlatego podczas analizy dostępnych plików logów ważne jest szukanie luk lub wpisów poza kolejnością, które mogą wskazywać na usunięcie lub manipulację.

### Journald triage (`journalctl`)

Na nowoczesnych hostach Linux **systemd journal** jest zwykle źródłem o najwyższej wartości dla **wykonywania usług**, **zdarzeń auth**, **operacji pakietowych** oraz **komunikatów jądra/przestrzeni użytkownika**. Podczas live response spróbuj zachować zarówno **persistent** journal (`/var/log/journal/`), jak i **runtime** journal (`/run/log/journal/`), ponieważ krótkotrwała aktywność atakującego może istnieć tylko w tym drugim.
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
Przydatne pola dziennika do triage obejmują `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` i `MESSAGE`. Jeśli `journald` był skonfigurowany bez trwałego przechowywania, spodziewaj się tylko najnowszych danych w `/run/log/journal/`.

### Triaging frameworku audit (`auditd`)

Jeśli `auditd` jest włączony, preferuj go zawsze, gdy potrzebujesz **atrybucji procesu** dla zmian plików, wykonywania poleceń, aktywności logowania lub instalacji pakietów.
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
Gdy reguły zostały wdrożone z kluczami, pivotuj od nich zamiast grepować surowe logi:
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

Ponadto, polecenie `last -Faiwx` zwraca listę logowań użytkowników. Sprawdź je pod kątem nieznanych lub nieoczekiwanych logowań.

Sprawdź pliki, które mogą przyznać dodatkowe rprivileges:

- Przejrzyj `/etc/sudoers` pod kątem nieoczekiwanych uprawnień użytkowników, które mogły zostać nadane.
- Przejrzyj `/etc/sudoers.d/` pod kątem nieoczekiwanych uprawnień użytkowników, które mogły zostać nadane.
- Sprawdź `/etc/groups`, aby zidentyfikować nietypowe członkostwa w grupach lub uprawnienia.
- Sprawdź `/etc/passwd`, aby zidentyfikować nietypowe członkostwa w grupach lub uprawnienia.

Niektóre aplikacje także generują własne logi:

- **SSH**: Sprawdź _\~/.ssh/authorized_keys_ i _\~/.ssh/known_hosts_ pod kątem nieautoryzowanych połączeń zdalnych.
- **Gnome Desktop**: Zajrzyj do _\~/.recently-used.xbel_ pod kątem ostatnio używanych plików przez aplikacje Gnome.
- **Firefox/Chrome**: Sprawdź historię przeglądarki i pobrane pliki w _\~/.mozilla/firefox_ lub _\~/.config/google-chrome_ pod kątem podejrzanych działań.
- **VIM**: Przejrzyj _\~/.viminfo_ pod kątem szczegółów użycia, takich jak ścieżki dostępu do plików i historia wyszukiwania.
- **Open Office**: Sprawdź ostatnio otwierane dokumenty, które mogą wskazywać na skompromitowane pliki.
- **FTP/SFTP**: Przejrzyj logi w _\~/.ftp_history_ lub _\~/.sftp_history_ pod kątem transferów plików, które mogły być nieautoryzowane.
- **MySQL**: Zbadaj _\~/.mysql_history_ pod kątem wykonanych zapytań MySQL, potencjalnie ujawniających nieautoryzowane działania w bazie danych.
- **Less**: Przeanalizuj _\~/.lesshst_ pod kątem historii użycia, w tym przeglądanych plików i wykonanych poleceń.
- **Git**: Sprawdź _\~/.gitconfig_ oraz project _.git/logs_ pod kątem zmian w repozytoriach.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) to niewielkie oprogramowanie napisane w czystym Pythonie 3, które parsuje pliki logów Linuxa (`/var/log/syslog*` lub `/var/log/messages*` w zależności od dystrybucji) w celu tworzenia tabel historii zdarzeń USB.

Warto **znać wszystkie USB, które były używane**, a będzie to bardziej przydatne, jeśli masz autoryzowaną listę USB, aby wykrywać „violation events” (użycie USB, których nie ma na tej liście).

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
Więcej przykładów i informacji w github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Przejrzyj konta użytkowników i aktywności logowania

Sprawdź _**/etc/passwd**_, _**/etc/shadow**_ oraz **security logs** pod kątem nietypowych nazw lub kont utworzonych i/lub używanych w bliskim sąsiedztwie znanych nieautoryzowanych zdarzeń. Sprawdź też możliwe ataki brute-force na sudo.\
Ponadto sprawdź pliki takie jak _**/etc/sudoers**_ i _**/etc/groups**_ pod kątem nieoczekiwanych uprawnień przyznanych użytkownikom.\
Na koniec poszukaj kont z **brakiem haseł** lub **łatwymi do odgadnięcia** hasłami.

## Zbadaj system plików

### Analiza struktur systemu plików w dochodzeniu malware

Podczas badania incydentów malware struktura systemu plików jest kluczowym źródłem informacji, ujawniając zarówno sekwencję zdarzeń, jak i zawartość malware. Jednak autorzy malware rozwijają techniki utrudniające tę analizę, takie jak modyfikowanie znaczników czasu plików albo unikanie systemu plików przy przechowywaniu danych.

Aby przeciwdziałać tym metodom antyforensycznym, ważne jest, aby:

- **Przeprowadzić dokładną analizę osi czasu** przy użyciu narzędzi takich jak **Autopsy** do wizualizacji osi czasu zdarzeń lub `mactime` z **Sleuth Kit** do szczegółowych danych osi czasu.
- **Zbadać nieoczekiwane skrypty** w systemowym $PATH, które mogą obejmować skrypty shell lub PHP używane przez atakujących.
- **Sprawdzić `/dev` pod kątem nietypowych plików**, ponieważ tradycyjnie zawiera on pliki specjalne, ale może też przechowywać pliki związane z malware.
- **Wyszukać ukryte pliki lub katalogi** o nazwach takich jak ".. " (kropka kropka spacja) lub "..^G" (kropka kropka znak kontrolny-G), które mogą ukrywać złośliwą zawartość.
- **Zidentyfikować pliki setuid root** za pomocą polecenia: `find / -user root -perm -04000 -print` To znajduje pliki z podwyższonymi uprawnieniami, które mogą być nadużyte przez atakujących.
- **Sprawdzić znaczniki czasu usunięcia** w tabelach inode, aby wykryć masowe usuwanie plików, co może wskazywać na obecność rootkits lub trojans.
- **Przeanalizować kolejne inodes** pod kątem pobliskich złośliwych plików po zidentyfikowaniu jednego, ponieważ mogły zostać umieszczone razem.
- **Sprawdzić typowe katalogi binarne** (_/bin_, _/sbin_) pod kątem ostatnio zmodyfikowanych plików, ponieważ mogły zostać zmienione przez malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Zauważ, że **atakujący** może **zmodyfikować** **czas**, aby **pliki wydawały się** **legalne**, ale **nie może** zmodyfikować **inode**. Jeśli zauważysz, że **plik** wskazuje, iż został utworzony i zmodyfikowany w **tym samym czasie** co pozostałe pliki w tym samym folderze, ale **inode** jest **nieoczekiwanie większy**, to **znaczniki czasu tego pliku zostały zmodyfikowane**.

### Szybka triage skupiona na inode

Jeśli podejrzewasz anti-forensics, uruchom wcześnie te kontrole skupione na inode:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Gdy podejrzany inode znajduje się na obrazie/urządzeniu systemu plików EXT, sprawdź bezpośrednio metadane inode:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Przydatne pola:
- **Links**: jeśli `0`, żaden wpis katalogu nie odwołuje się obecnie do inode.
- **dtime**: znacznik czasu usunięcia ustawiany, gdy inode został odlinkowany.
- **ctime/mtime**: pomaga skorelować zmiany metadanych/zawartości z harmonogramem incydentu.

### Capabilities, xattrs i userland rootkity oparte na preload

Nowoczesna trwałość w Linux często unika oczywistych binariów `setuid` i zamiast tego nadużywa **file capabilities**, **extended attributes** oraz dynamicznego loadera.
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
Zwróć szczególną uwagę na biblioteki odwoływane z **zapisowalnych** ścieżek, takich jak `/tmp`, `/dev/shm`, `/var/tmp` lub nietypowe lokalizacje pod `/usr/local/lib`. Sprawdź też binaria z capability poza normalną własnością pakietów i skoreluj je z wynikami weryfikacji pakietów (`rpm -Va`, `dpkg --verify`, `debsums`).

## Porównaj pliki z różnych wersji systemu plików

### Podsumowanie porównania wersji systemu plików

Aby porównać wersje systemu plików i wskazać zmiany, używamy uproszczonych komend `git diff`:

- **Aby znaleźć nowe pliki**, porównaj dwa katalogi:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Dla zmodyfikowanej treści**, wypisz zmiany, ignorując konkretne linie:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Aby wykryć usunięte pliki**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Opcje filtrowania** (`--diff-filter`) pomagają zawęzić wyniki do określonych zmian, takich jak dodane (`A`), usunięte (`D`) lub zmodyfikowane (`M`) pliki.
- `A`: Dodane pliki
- `C`: Skopiowane pliki
- `D`: Usunięte pliki
- `M`: Zmodyfikowane pliki
- `R`: Zmienione nazwy plików
- `T`: Zmiany typu (np. plik na symlink)
- `U`: Niezmergowane pliki
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
- [Say hi to Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [strace](https://strace.io/)
- [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
