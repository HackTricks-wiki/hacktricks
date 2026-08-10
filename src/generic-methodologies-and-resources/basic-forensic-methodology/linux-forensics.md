# Forensics systemu Linux

## Wstępne zbieranie informacji

### Podstawowe informacje

Przede wszystkim zaleca się posiadanie **USB** z **dobrze znanymi plikami binarnymi i bibliotekami** (możesz po prostu pobrać ubuntu i skopiować foldery _/bin_, _/sbin_, _/lib,_ oraz _/lib64_), a następnie zamontować USB i zmodyfikować zmienne środowiskowe, aby używać tych plików binarnych:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Po skonfigurowaniu systemu tak, aby korzystał z dobrych i znanych plików binarnych, możesz rozpocząć **wydobywanie podstawowych informacji**:
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

Podczas uzyskiwania podstawowych informacji należy sprawdzić nietypowe rzeczy, takie jak:

- Procesy **root** zwykle działają z niskimi wartościami PID, więc jeśli znajdziesz proces **root** z dużym PID, możesz nabrać podejrzeń
- Sprawdź **zarejestrowane logowania** użytkowników bez shell w `/etc/passwd`
- Sprawdź **hashe haseł** w `/etc/shadow` dla użytkowników bez shell

### Zrzut pamięci

Aby uzyskać pamięć uruchomionego systemu, zaleca się użycie [**LiME**](https://github.com/504ensicsLabs/LiME).\
Aby go **skompilować**, musisz użyć **tego samego kernela**, którego używa maszyna ofiary.

> [!TIP]
> Pamiętaj, że **nie możesz zainstalować LiME ani niczego innego** na maszynie ofiary, ponieważ spowoduje to wprowadzenie w niej kilku zmian

Jeśli więc masz identyczną wersję Ubuntu, możesz użyć `apt-get install lime-forensics-dkms`\
W innych przypadkach musisz pobrać [**LiME**](https://github.com/504ensicsLabs/LiME) z github i skompilować go z prawidłowymi nagłówkami kernela. Aby **uzyskać dokładne nagłówki kernela** maszyny ofiary, możesz po prostu **skopiować katalog** `/lib/modules/<kernel version>` na swoją maszynę, a następnie **skompilować** LiME z ich użyciem:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME obsługuje 3 **formaty**:

- Raw (każdy segment połączony ze sobą)
- Padded (tak jak raw, ale z zerami w prawidłowych bitach)
- Lime (zalecany format z metadanymi

LiME może być również używany do **wysyłania dumpa przez sieć** zamiast przechowywania go w systemie, na przykład za pomocą: `path=tcp:4444`

### Obrazowanie dysku

#### Wyłączanie systemu

Przede wszystkim należy **wyłączyć system**. Nie zawsze jest to możliwe, ponieważ czasami system będzie serwerem produkcyjnym, którego firma nie może sobie pozwolić wyłączyć.\
Istnieją **2 sposoby** wyłączenia systemu: **normalne wyłączenie** oraz wyłączenie poprzez **„odłączenie wtyczki”**. Pierwszy sposób pozwoli **procesom zakończyć działanie w zwykły sposób**, a **systemowi plików** na **synchronizację**, ale umożliwi również potencjalnemu **malware** **zniszczenie dowodów**. Podejście polegające na **„odłączeniu zasilania”** może spowodować **pewną utratę informacji** (nie powinno utracić się wiele informacji, ponieważ obraz pamięci został już utworzony), a **malware nie będzie miał żadnej możliwości**, aby cokolwiek z tym zrobić. Dlatego jeśli **podejrzewasz**, że może istnieć **malware**, po prostu wykonaj w systemie **polecenie** **`sync`**, a następnie odłącz zasilanie.

#### Tworzenie obrazu dysku

Należy pamiętać, że **przed podłączeniem komputera do czegokolwiek związanego ze sprawą** trzeba upewnić się, że zostanie on **zamontowany tylko do odczytu**, aby uniknąć modyfikowania jakichkolwiek informacji.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Wstępna analiza obrazu dysku

Tworzenie obrazu dysku bez dodatkowych danych.
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
## Wyszukiwanie znanego Malware

### Zmodyfikowane pliki systemowe

Linux oferuje narzędzia do sprawdzania integralności komponentów systemu, co ma kluczowe znaczenie dla wykrywania potencjalnie problematycznych plików.<sup>[[1]](#references)</sup>

- **Systemy bazujące na RedHat**: użyj `rpm -Va` w celu przeprowadzenia kompleksowego sprawdzenia.
- **Systemy bazujące na Debianie**: użyj `dpkg --verify` do wstępnej weryfikacji, a następnie `debsums | grep -v "OK$"` (po zainstalowaniu `debsums` za pomocą `apt-get install debsums`), aby zidentyfikować ewentualne problemy.

### Detektory Malware/Rootkitów

Przeczytaj poniższą stronę, aby dowiedzieć się więcej o narzędziach, które mogą być przydatne do wykrywania Malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Wyszukiwanie zainstalowanych programów

Aby skutecznie wyszukiwać zainstalowane programy zarówno w systemach Debian, jak i RedHat, warto wykorzystać logi systemowe i bazy danych oraz przeprowadzić ręczne sprawdzenie typowych katalogów.<sup>[[1]](#references)</sup>

- W systemie Debian sprawdź _**`/var/lib/dpkg/status`**_ oraz _**`/var/log/dpkg.log`**_, aby uzyskać szczegółowe informacje o instalacjach pakietów, używając `grep` do filtrowania konkretnych informacji.
- Użytkownicy RedHat mogą wyszukiwać informacje w bazie danych RPM za pomocą `rpm -qa --root=/mntpath/var/lib/rpm`, aby wyświetlić listę zainstalowanych pakietów.

Aby znaleźć oprogramowanie zainstalowane ręcznie lub poza tymi menedżerami pakietów, sprawdź katalogi takie jak _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ oraz _**`/sbin`**_. Połącz listowanie katalogów z poleceniami właściwymi dla danego systemu, aby zidentyfikować pliki wykonywalne niepowiązane ze znanymi pakietami, usprawniając wyszukiwanie wszystkich zainstalowanych programów.
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
## Odzyskiwanie usuniętych uruchomionych plików binarnych

Wyobraź sobie proces, który został uruchomiony z `/tmp/exec`, a następnie usunięty. Można go wyodrębnić
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Triaging śladów syscalli za pomocą SQLite i FTS5

Gdy proces nadal działa lub można go ponownie uruchomić w środowisku laboratoryjnym, **`strace`** może szybko dostarczyć ślad behawioralny bez potrzeby używania modułów jądra ani pełnej telemetrii EDR. W przypadku dużych śladów unikaj bezpośredniego odczytywania surowego logu lub wklejania go do LLM: przechowuj go w bazie danych **SQLite** i wykonuj zapytania tylko dla minimalnego potrzebnego podzbioru.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> Podłączenie `strace` zmienia synchronizację procesu i może wpływać na warunki wyścigu lub inne podatne na zakłócenia błędy. Jeśli to możliwe, preferuj odtwarzanie problemu na kopii/systemie laboratoryjnym.

### Przechwytywanie

Dla nowego procesu:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Dla aktywnego procesu:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Przydatne opcje:

- `-ff`: śledzenie forków/wątków i zachowywanie oddzielnych danych wyjściowych dla każdego procesu
- `-ttt`: znaczniki czasu epoki ułatwiające korelację na osi czasu
- `-yy`: rozwiązywanie deskryptorów plików do ścieżek bazowych/gniazd, gdy jest to możliwe
- `-s 4096`: zapobieganie obcinaniu długich ścieżek i argumentów buforów

### Normalizacja

Praktyczny schemat to jeden wiersz na każde wywołanie systemowe i jeden wiersz na każdy argument:
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
Pozwala to uniknąć prób spłaszczania heterogenicznych wierszy syscalli do jednej szerokiej tabeli i zapewnia przewidywalne złączenia podczas triage.

### Indeksuj argumenty tekstowe za pomocą FTS5

Na dużych śladach naiwne wyszukiwanie ścieżek za pomocą `LIKE "%...%"` staje się bardzo wolne. Utwórz indeks FTS5 dla tekstu argumentów i wyszukuj za jego pomocą:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Przykład: odtworzenie aktywności plików w katalogu `/tmp` bez skanowania każdego wiersza:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Investigacje o wysokiej wartości sygnału

- **PATH hijacking / fake sudo**: wyszukaj operacje zapisu oraz aktywność `chmod`/`rename` w `~/.local/bin/`, a następnie skoreluj je z późniejszymi wywołaniami `execve` nazw wyglądających na uprzywilejowane, takich jak `sudo`.
- **TOCTOU on temporary files**: śledź tę samą ścieżkę `/tmp/...` w wywołaniach `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` i `execve`, aby zidentyfikować luki między sprawdzeniem a użyciem.
- **Przyczyna awarii**: skoreluj `mmap` pliku z zapisem lub obcięciem tego samego inode'u/tej samej ścieżki przez inny proces, a następnie przeanalizuj sekwencję sygnału/zakończenia pod kątem `SIGBUS`.
- **Odzyskiwanie celu sieciowego**: filtruj argumenty związane z `connect`, `sendto`, `sendmsg`, `recvfrom` i socketami, aby wyodrębnić adresy IP peerów oraz porty.

### Analiza trace z pomocą LLM

Jeśli chcesz skorzystać z pomocy LLM, udostępnij uchwyt SQLite w trybie **read-only** i przekaż pełny schemat. Pozwól mu wykonywać surowe zapytania SQL zamiast opakowywać bazę w wąskie funkcje pomocnicze. Zwykle lepiej sprawdza się to w przypadku JOIN-ów, korelacji czasowej i wyszukiwania FTS.

Praktyczne zasady:

- Utrzymuj bazę w trybie read-only, na przykład za pomocą `sqlite3 'file:trace.db?mode=ro'`.
- Przekaż modelowi przykłady poprawnych zapytań `JOIN` i `FTS5 MATCH`.
- **Nie** wklejaj do promptu surowych logów `strace` o rozmiarze wielu GB.
- Zadawaj konkretne pytania, takie jak:
- „Wymień trwałe pliki zapisane przez ten program.”
- „Czy utworzył lub zastąpił pliki wykonywalne w kontrolowanych przez użytkownika katalogach PATH?”
- „Wyjaśnij, dlaczego ten trace kończy się błędem SIGBUS.”

## Sprawdzanie lokalizacji Autostart

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
#### Wyszukiwanie: nadużycie Cron/Anacron za pośrednictwem 0anacron i podejrzanych stubów
Atakujący często modyfikują stub 0anacron znajdujący się w każdym katalogu /etc/cron.*/, aby zapewnić okresowe wykonywanie.<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: rollback hardeningu SSH i backdoor shells
Zmiany w sshd_config i powłokach kont systemowych są częstą techniką post-exploitation służącą do zachowania dostępu.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Huntowanie: wskaźniki Cloud C2 (Dropbox/Cloudflare Tunnel)
- Beacony Dropbox API zwykle używają api.dropboxapi.com lub content.dropboxapi.com przez HTTPS z tokenami Authorization: Bearer.
- Szukaj w proxy/Zeek/NetFlow nieoczekiwanego ruchu wychodzącego Dropbox z serwerów.
- Cloudflare Tunnel (`cloudflared`) zapewnia zapasowy C2 przez wychodzący port 443.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Usługi

Ścieżki, w których malware może zostać zainstalowane jako usługa:

- **/etc/inittab**: Wywołuje skrypty inicjalizacyjne, takie jak rc.sysinit, przekazując dalsze wykonanie skryptom startowym.
- **/etc/rc.d/** i **/etc/rc.boot/**: Zawierają skrypty uruchamiania usług; ten drugi katalog występuje w starszych wersjach Linuxa.
- **/etc/init.d/**: Używany w niektórych wersjach Linuxa, takich jak Debian, do przechowywania skryptów startowych.
- Usługi mogą być również aktywowane za pośrednictwem **/etc/inetd.conf** lub **/etc/xinetd/**, zależnie od wariantu Linuxa.
- **/etc/systemd/system**: Katalog zawierający skrypty menedżera systemu i usług.
- **/etc/systemd/system/multi-user.target.wants/**: Zawiera linki do usług, które powinny zostać uruchomione w trybie wieloużytkownikowym.
- **/usr/local/etc/rc.d/**: Przeznaczony dla niestandardowych usług i usług firm trzecich.
- **\~/.config/autostart/**: Przeznaczony dla aplikacji uruchamianych automatycznie przez konkretnego użytkownika; może służyć jako miejsce ukrycia malware ukierunkowanego na użytkownika.
- **/lib/systemd/system/**: Zawiera domyślne, systemowe pliki jednostek dostarczane przez zainstalowane pakiety.

#### Poszukiwanie: timery systemd i jednostki przejściowe

Persistence w systemd nie ogranicza się do plików `.service`. Zbadaj jednostki `.timer`, jednostki na poziomie użytkownika oraz **jednostki przejściowe** tworzone w czasie działania.
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
Jednostki tymczasowe łatwo przeoczyć, ponieważ `/run/systemd/transient/` jest **nietrwały**. Jeśli zbierasz obraz systemu na żywo, skopiuj go przed wyłączeniem systemu.

### Moduły jądra

Moduły jądra Linux, często wykorzystywane przez malware jako komponenty rootkitów, są ładowane podczas uruchamiania systemu. Kluczowe dla tych modułów katalogi i pliki obejmują:

- **/lib/modules/$(uname -r)**: Zawiera moduły dla aktualnie uruchomionej wersji jądra.
- **/etc/modprobe.d**: Zawiera pliki konfiguracyjne kontrolujące ładowanie modułów.
- **/etc/modprobe** oraz **/etc/modprobe.conf**: Pliki zawierające globalne ustawienia modułów.

### Inne lokalizacje autostartu

Linux korzysta z różnych plików do automatycznego uruchamiania programów po zalogowaniu użytkownika, które mogą zawierać malware:

- **/etc/profile.d/**\*, **/etc/profile** oraz **/etc/bash.bashrc**: Są wykonywane podczas logowania dowolnego użytkownika.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile** oraz **\~/.config/autostart**: Pliki specyficzne dla użytkownika, uruchamiane podczas jego logowania.
- **/etc/rc.local**: Uruchamiany po uruchomieniu wszystkich usług systemowych, wyznaczając koniec przejścia do środowiska wieloużytkownikowego.

## Analiza logów

Systemy Linux śledzą aktywność użytkowników i zdarzenia systemowe za pomocą różnych plików logów. Logi te mają kluczowe znaczenie przy wykrywaniu nieautoryzowanego dostępu, infekcji malware i innych incydentów bezpieczeństwa.<sup>[[2]](#references)</sup> Najważniejsze pliki logów obejmują:

- **/var/log/syslog** (Debian) lub **/var/log/messages** (RedHat): Rejestrują komunikaty i aktywność całego systemu.
- **/var/log/auth.log** (Debian) lub **/var/log/secure** (RedHat): Rejestrują próby uwierzytelnienia oraz udane i nieudane logowania.
- Użyj `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log`, aby odfiltrować istotne zdarzenia uwierzytelniania.
- **/var/log/boot.log**: Zawiera komunikaty uruchamiania systemu.
- **/var/log/maillog** lub **/var/log/mail.log**: Rejestrują aktywność serwera pocztowego, co jest przydatne do śledzenia usług związanych z pocztą elektroniczną.
- **/var/log/kern.log**: Przechowuje komunikaty jądra, w tym błędy i ostrzeżenia.
- **/var/log/dmesg**: Zawiera komunikaty sterowników urządzeń.
- **/var/log/faillog**: Rejestruje nieudane próby logowania, pomagając w badaniu naruszeń bezpieczeństwa.
- **/var/log/cron**: Rejestruje wykonywanie zadań cron.
- **/var/log/daemon.log**: Śledzi aktywność usług działających w tle.
- **/var/log/btmp**: Dokumentuje nieudane próby logowania.
- **/var/log/httpd/**: Zawiera logi błędów i dostępu Apache HTTPD.
- **/var/log/mysqld.log** lub **/var/log/mysql.log**: Rejestrują aktywność baz danych MySQL.
- **/var/log/xferlog**: Rejestruje transfery plików FTP.
- **/var/log/**: Zawsze sprawdzaj, czy nie ma tu nieoczekiwanych logów.

> [!TIP]
> Logi systemu Linux i podsystemy audytowe mogą zostać wyłączone lub usunięte podczas włamania albo incydentu związanego z malware. Ponieważ logi w systemach Linux zazwyczaj zawierają jedne z najbardziej użytecznych informacji o złośliwej aktywności, intruzi rutynowo je usuwają. Dlatego podczas analizowania dostępnych plików logów należy szukać luk lub wpisów w niewłaściwej kolejności, które mogą wskazywać na usunięcie lub manipulację.

### Wstępna analiza Journald (`journalctl`)

Na współczesnych hostach Linux **journal systemd** jest zwykle najcenniejszym źródłem informacji o **wykonywaniu usług**, **zdarzeniach uwierzytelniania**, **operacjach na pakietach** oraz **komunikatach jądra i przestrzeni użytkownika**. Podczas reakcji na żywo spróbuj zachować zarówno dziennik **trwały** (`/var/log/journal/`), jak i dziennik **uruchomieniowy** (`/run/log/journal/`), ponieważ krótkotrwała aktywność atakującego może istnieć wyłącznie w tym drugim.<sup>[[5]](#references)</sup>
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
Przydatne pola journal do triage obejmują `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` oraz `MESSAGE`. Jeśli journald skonfigurowano bez trwałego przechowywania, należy oczekiwać jedynie najnowszych danych w `/run/log/journal/`.

### Triage frameworka audytowego (`auditd`)

Jeśli `auditd` jest włączony, należy preferować go zawsze, gdy potrzebne jest **przypisanie procesu** do zmian plików, wykonywania poleceń, aktywności logowania lub instalacji pakietów.<sup>[[6]](#references)</sup>
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
Gdy reguły zostały wdrożone z użyciem kluczy, wykonaj pivot na ich podstawie zamiast grepowania surowych logów:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux przechowuje historię poleceń dla każdego użytkownika** w:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Ponadto polecenie `last -Faiwx` udostępnia listę logowań użytkowników. Sprawdź ją pod kątem nieznanych lub nieoczekiwanych logowań.

Sprawdź pliki, które mogą przyznawać dodatkowe uprawnienia:

- Przejrzyj `/etc/sudoers` pod kątem nieoczekiwanych uprawnień użytkowników, które mogły zostać przyznane.
- Przejrzyj `/etc/sudoers.d/` pod kątem nieoczekiwanych uprawnień użytkowników, które mogły zostać przyznane.
- Przeanalizuj `/etc/groups`, aby zidentyfikować nietypowe członkostwa w grupach lub uprawnienia.
- Przeanalizuj `/etc/passwd`, aby zidentyfikować nietypowe członkostwa w grupach lub uprawnienia.

Niektóre aplikacje również generują własne logi:

- **SSH**: Przeanalizuj _\~/.ssh/authorized_keys_ i _\~/.ssh/known_hosts_ pod kątem nieautoryzowanych połączeń zdalnych.
- **Gnome Desktop**: Sprawdź _\~/.recently-used.xbel_ pod kątem ostatnio otwieranych plików za pomocą aplikacji Gnome.
- **Firefox/Chrome**: Sprawdź historię przeglądarki i pobrane pliki w _\~/.mozilla/firefox_ lub _\~/.config/google-chrome_ pod kątem podejrzanej aktywności.
- **VIM**: Przejrzyj _\~/.viminfo_ w celu ustalenia sposobu użycia, na przykład ścieżek otwieranych plików i historii wyszukiwania.
- **Open Office**: Sprawdź ostatnio otwierane dokumenty, które mogą wskazywać na przejęte pliki.
- **FTP/SFTP**: Przejrzyj logi w _\~/.ftp_history_ lub _\~/.sftp_history_ pod kątem transferów plików, które mogą być nieautoryzowane.
- **MySQL**: Przeanalizuj _\~/.mysql_history_ pod kątem wykonywanych zapytań MySQL, które mogą ujawnić nieautoryzowane działania na bazie danych.
- **Less**: Przeanalizuj _\~/.lesshst_ pod kątem historii użycia, w tym przeglądanych plików i wykonywanych poleceń.
- **Git**: Przeanalizuj _\~/.gitconfig_ oraz _.git/logs_ projektu pod kątem zmian w repozytoriach.

### Logi USB

[**usbrip**](https://github.com/snovvcrash/usbrip) to niewielkie oprogramowanie napisane w czystym Python 3, które analizuje pliki logów Linuxa (`/var/log/syslog*` lub `/var/log/messages*`, zależnie od dystrybucji) w celu tworzenia tabel historii zdarzeń USB.

Warto **wiedzieć, jakie urządzenia USB były używane**. Jeszcze bardziej przydatne będzie posiadanie autoryzowanej listy urządzeń USB, aby wykrywać „zdarzenia naruszeń” (użycie urządzeń USB, których nie ma na tej liście).

### Instalacja
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
Więcej przykładów i informacji znajduje się na githubie: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Przegląd kont użytkowników i aktywności logowania

Przeanalizuj pliki _**/etc/passwd**_, _**/etc/shadow**_ oraz **dzienniki bezpieczeństwa** pod kątem nietypowych nazw lub kont utworzonych lub używanych w bezpośrednim sąsiedztwie czasowym znanych nieautoryzowanych zdarzeń. Sprawdź również możliwe ataki sudo brute-force.\
Ponadto sprawdź pliki takie jak _**/etc/sudoers**_ i _**/etc/groups**_ pod kątem nieoczekiwanych uprawnień przyznanych użytkownikom.\
Na koniec poszukaj kont z **brakiem haseł** lub hasłami **łatwymi do odgadnięcia**.<sup>[[1]](#references)</sup>

## Analiza systemu plików

### Analiza struktur systemu plików podczas badania malware

Podczas badania incydentów związanych z malware struktura systemu plików jest kluczowym źródłem informacji, ujawniającym zarówno sekwencję zdarzeń, jak i zawartość malware. Autorzy malware opracowują jednak techniki utrudniające tę analizę, takie jak modyfikowanie znaczników czasu plików lub unikanie systemu plików do przechowywania danych.<sup>[[1]](#references)</sup>

Aby przeciwdziałać tym metodom anti-forensic, należy:

- **Przeprowadzić dokładną analizę osi czasu** za pomocą narzędzi takich jak **Autopsy** do wizualizacji osi czasu zdarzeń lub `mactime` z **Sleuth Kit** do uzyskania szczegółowych danych osi czasu.
- **Zbadać nieoczekiwane skrypty** znajdujące się w systemowym $PATH, które mogą obejmować skrypty shell lub PHP używane przez attackerów.
- **Przeanalizować `/dev` pod kątem nietypowych plików**, ponieważ tradycyjnie zawiera on pliki specjalne, ale może również przechowywać pliki powiązane z malware.
- **Wyszukać ukryte pliki lub katalogi** o nazwach takich jak ".. " (kropka kropka spacja) lub "..^G" (kropka kropka control-G), które mogą ukrywać złośliwą zawartość.
- **Zidentyfikować pliki setuid root** za pomocą polecenia: `find / -user root -perm -04000 -print` Polecenie to wyszukuje pliki z podwyższonymi uprawnieniami, które mogą zostać wykorzystane przez attackerów.
- **Przeanalizować znaczniki czasu usunięcia** w tabelach inode, aby wykryć masowe usuwanie plików, co może wskazywać na obecność rootkits lub trojans.
- **Sprawdzić kolejne inode'y** pod kątem znajdujących się w pobliżu złośliwych plików po zidentyfikowaniu jednego z nich, ponieważ mogły zostać umieszczone razem.
- **Sprawdzić typowe katalogi plików binarnych** (_/bin_, _/sbin_) pod kątem ostatnio zmodyfikowanych plików, ponieważ mogły zostać zmienione przez malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Pamiętaj, że **attacker** może **modify** **time**, aby **files appear** **legitimate**, ale nie może zmodyfikować **inode**. Jeśli zauważysz, że **file** wskazuje, iż został utworzony i zmodyfikowany w **same time** co pozostałe pliki w tym samym folderze, ale jego **inode** jest **unexpectedly bigger**, oznacza to, że **timestamps of that file were modified**.

### Szybki triage skoncentrowany na inode

Jeśli podejrzewasz anti-forensics, wykonaj te kontrole skoncentrowane na inode na wczesnym etapie:
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
- **dtime**: znacznik czasu usunięcia ustawiany po odłączeniu inode.
- **ctime/mtime**: pomagają skorelować zmiany metadanych/zawartości z osią czasu incydentu.

### Capabilities, xattrs i rootkity userland oparte na preload

Współczesna persistence w Linux często unika oczywistych plików binarnych **setuid** i zamiast tego nadużywa **file capabilities**, **extended attributes** oraz dynamic loadera.
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
Zwróć szczególną uwagę na biblioteki odwołujące się do **zapisywalnych** ścieżek, takich jak `/tmp`, `/dev/shm`, `/var/tmp` lub nietypowych lokalizacji w `/usr/local/lib`. Sprawdź również pliki binarne z capabilities znajdujące się poza normalnym zakresem własności pakietów i skoreluj je z wynikami weryfikacji pakietów (`rpm -Va`, `dpkg --verify`, `debsums`).

## Porównywanie plików z różnych wersji systemu plików

### Podsumowanie porównywania wersji systemu plików

Aby porównać wersje systemu plików i wskazać zmiany, używamy uproszczonych poleceń `git diff`:<sup>[[3]](#references)</sup>

- **Aby znaleźć nowe pliki**, porównaj dwa katalogi:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **W przypadku zmodyfikowanej zawartości wypisz zmiany, pomijając określone wiersze:**
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Aby wykrywać usunięte pliki**:
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
- `U`: Niezscalone pliki
- `X`: Nieznane pliki
- `B`: Uszkodzone pliki

## References

- [1] [Przewodnik terenowy po analizie kryminalistycznej malware dla systemów Linux: Przewodniki terenowe po analizie cyfrowej – rozdział 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Wyjaśnienie logów Linux](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [Dokumentacja git diff – opcja --diff-filter](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – Aktualizowanie w celu utrzymania persistence: jak Linux malware DripDropper porusza się w cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Analiza kryminalistyczna journali Linux](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 – Audytowanie systemu](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Przywitaj się z Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [Rozszerzenie SQLite FTS5](https://www.sqlite.org/fts5.html)
{{#include ../../banners/hacktricks-training.md}}
