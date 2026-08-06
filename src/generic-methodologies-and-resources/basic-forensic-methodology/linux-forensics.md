# Analiza śledcza systemu Linux

{{#include ../../banners/hacktricks-training.md}}

## Wstępne gromadzenie informacji

### Podstawowe informacje

Przede wszystkim zaleca się posiadanie **USB** z **zaufanymi binariami i bibliotekami** (możesz po prostu pobrać Ubuntu i skopiować foldery _/bin_, _/sbin_, _/lib,_ oraz _/lib64_), a następnie zamontować USB i zmodyfikować zmienne środowiskowe, aby korzystać z tych binariów:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Po skonfigurowaniu systemu tak, aby używał sprawdzonych i znanych plików binarnych, możesz rozpocząć **wydobywanie podstawowych informacji**:
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

Podczas uzyskiwania podstawowych informacji należy sprawdzać nietypowe rzeczy, takie jak:

- **Procesy root** zwykle działają z niskimi wartościami PID, więc jeśli znajdziesz proces root z wysokim PID, może to wzbudzać podejrzenia
- Sprawdź **zarejestrowane logowania** użytkowników bez shellu w `/etc/passwd`
- Sprawdź **hashe haseł** w `/etc/shadow` użytkowników bez shellu

### Zrzut pamięci

Aby uzyskać zawartość pamięci działającego systemu, zaleca się użycie [**LiME**](https://github.com/504ensicsLabs/LiME).\
Aby go **skompilować**, musisz użyć **tego samego kernela**, którego używa zaatakowana maszyna.

> [!TIP]
> Pamiętaj, że **nie możesz zainstalować LiME ani żadnego innego oprogramowania** na zaatakowanej maszynie, ponieważ spowoduje to wprowadzenie w niej kilku zmian

Jeśli więc masz identyczną wersję Ubuntu, możesz użyć `apt-get install lime-forensics-dkms`\
W pozostałych przypadkach musisz pobrać [**LiME**](https://github.com/504ensicsLabs/LiME) z github i skompilować je przy użyciu właściwych nagłówków kernela. Aby **uzyskać dokładne nagłówki kernela** zaatakowanej maszyny, możesz po prostu **skopiować katalog** `/lib/modules/<kernel version>` na swoją maszynę, a następnie **skompilować** LiME, używając tych nagłówków:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME obsługuje 3 **formats**:

- Raw (każdy segment połączony razem)
- Padded (tak jak raw, ale z zerami w prawych bitach)
- Lime (zalecany format z metadanymi

LiME może być również używany do **wysyłania dump przez sieć** zamiast przechowywania go w systemie, na przykład za pomocą: `path=tcp:4444`

### Obrazowanie dysku

#### Wyłączanie

Przede wszystkim należy **wyłączyć system**. Nie zawsze jest to możliwe, ponieważ czasami system będzie serwerem produkcyjnym, którego firma nie może sobie pozwolić wyłączyć.\
Istnieją **2 sposoby** wyłączenia systemu: **normalne wyłączenie** oraz wyłączenie poprzez **„wyciągnięcie wtyczki”**. Pierwszy sposób pozwoli **procesom zakończyć działanie w zwykły sposób**, a **system plików** zostanie **zsynchronizowany**, ale umożliwi również potencjalnemu **malware** **zniszczenie dowodów**. Podejście polegające na **wyciągnięciu wtyczki** może spowodować **utratę części informacji** (nie zostanie utracona duża ilość informacji, ponieważ wcześniej wykonaliśmy obraz pamięci), a **malware nie będzie mieć żadnej możliwości**, aby cokolwiek z tym zrobić. Dlatego jeśli **podejrzewasz**, że może występować **malware**, po prostu wykonaj w systemie **polecenie** **`sync`**, a następnie wyciągnij wtyczkę.

#### Wykonywanie obrazu dysku

Należy pamiętać, że **przed podłączeniem komputera do czegokolwiek związanego ze sprawą** trzeba upewnić się, że zostanie on **zamontowany tylko do odczytu**, aby uniknąć modyfikowania jakichkolwiek informacji.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Analiza obrazu dysku przed badaniem

Tworzenie obrazu dysku, na którym nie ma już więcej danych.
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

Linux oferuje narzędzia do sprawdzania integralności komponentów systemu, co ma kluczowe znaczenie przy wykrywaniu potencjalnie problematycznych plików.<sup>[[1]](#references)</sup>

- **Systemy oparte na RedHat**: użyj `rpm -Va` w celu przeprowadzenia kompleksowego sprawdzenia.
- **Systemy oparte na Debianie**: użyj `dpkg --verify` do wstępnej weryfikacji, a następnie `debsums | grep -v "OK$"` (po zainstalowaniu `debsums` za pomocą `apt-get install debsums`), aby zidentyfikować wszelkie problemy.

### Detektory Malware/Rootkitów

Przeczytaj poniższą stronę, aby dowiedzieć się więcej o narzędziach, które mogą być przydatne do wykrywania malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Wyszukiwanie zainstalowanych programów

Aby skutecznie wyszukiwać zainstalowane programy w systemach Debian i RedHat, rozważ wykorzystanie logów systemowych i baz danych wraz z ręcznym sprawdzaniem typowych katalogów.<sup>[[1]](#references)</sup>

- W systemie Debian sprawdź _**`/var/lib/dpkg/status`**_ oraz _**`/var/log/dpkg.log`**_, aby uzyskać szczegółowe informacje o instalacjach pakietów, używając `grep` do filtrowania określonych informacji.
- Użytkownicy RedHat mogą odpytać bazę danych RPM za pomocą `rpm -qa --root=/mntpath/var/lib/rpm`, aby wyświetlić listę zainstalowanych pakietów.

Aby znaleźć oprogramowanie zainstalowane ręcznie lub poza tymi menedżerami pakietów, sprawdź katalogi takie jak _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ oraz _**`/sbin`**_. Połącz listowanie zawartości katalogów z poleceniami specyficznymi dla danego systemu, aby zidentyfikować pliki wykonywalne niepowiązane ze znanymi pakietami, rozszerzając wyszukiwanie wszystkich zainstalowanych programów.
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

Wyobraź sobie proces, który został uruchomiony z `/tmp/exec`, a następnie usunięty. Możliwe jest jego wyodrębnienie.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Triaging śladów syscalli za pomocą SQLite i FTS5

Gdy proces nadal działa lub można go ponownie uruchomić w laboratorium, **`strace`** może dostarczyć szybkiego śladu zachowania bez potrzeby korzystania z modułów jądra ani pełnej telemetrii EDR. W przypadku dużych śladów unikaj bezpośredniego odczytywania surowego logu lub wklejania go do LLM: zapisz go w bazie danych **SQLite** i odpyty­wuj wyłącznie minimalny potrzebny podzbiór.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> Podłączanie `strace` zmienia czas wykonywania procesu i może wpływać na warunki wyścigu lub inne wrażliwe błędy. Jeśli to możliwe, preferuj odtwarzanie problemu w kopii/systemie laboratoryjnym.

### Przechwytywanie

Dla nowego procesu:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Dla działającego procesu:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Przydatne opcje:

- `-ff`: śledzenie forków/wątków i zachowanie osobnych wyników dla każdego procesu
- `-ttt`: znaczniki czasu epoch ułatwiające korelację na osi czasu
- `-yy`: rozwiązywanie deskryptorów plików do odpowiadających im ścieżek/gniazd, gdy jest to możliwe
- `-s 4096`: zapobieganie obcinaniu długich ścieżek i argumentów buforów

### Normalizacja

Praktyczny schemat to jeden wiersz na wywołanie systemowe i jeden wiersz na argument:
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

Naive wyszukiwanie ścieżek za pomocą `LIKE "%...%"` staje się bardzo powolne w przypadku dużych śladów. Utwórz indeks FTS5 dla tekstu argumentów i wyszukuj za jego pomocą:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Przykład: odtworzenie aktywności plików w `/tmp` bez skanowania każdego wiersza:
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
- **TOCTOU on temporary files**: prześledź tę samą ścieżkę `/tmp/...` w wywołaniach `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` i `execve`, aby zidentyfikować luki między sprawdzeniem a użyciem.
- **Crash root cause**: skoreluj `mmap` pliku z zapisem lub obcięciem tego samego inode/tej samej ścieżki przez inny proces, a następnie przeanalizuj sekwencję sygnału/wyjścia pod kątem `SIGBUS`.
- **Network destination recovery**: filtruj `connect`, `sendto`, `sendmsg`, `recvfrom` oraz argumenty związane z socketami, aby wyodrębnić adresy IP peerów i porty.

### Analiza śladów z pomocą LLM

Jeśli chcesz, aby LLM pomógł, udostępnij mu uchwyt SQLite **read-only** i przekaż pełny schemat. Pozwól mu wykonywać surowe zapytania SQL zamiast opakowywać bazę za pomocą wąskich funkcji pomocniczych. Zwykle lepiej sprawdza się to w przypadku złączeń, korelacji czasowej i wyszukiwania FTS.

Praktyczne zasady:

- Utrzymuj bazę w trybie read-only, na przykład za pomocą `sqlite3 'file:trace.db?mode=ro'`.
- Przekaż modelowi przykłady poprawnych zapytań `JOIN` i `FTS5 MATCH`.
- **Nie** wklejaj do promptu surowych logów `strace` o rozmiarze wielu GB.
- Zadawaj konkretne pytania, takie jak:
- "Wymień trwałe pliki zapisane przez ten program."
- "Czy utworzył lub zastąpił pliki wykonywalne w katalogach PATH kontrolowanych przez użytkownika?"
- "Wyjaśnij, dlaczego ten ślad kończy się błędem SIGBUS."

## Sprawdzanie lokalizacji Autostart

### Zadania zaplanowane
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
#### Hunt: Cron/Anacron abuse via 0anacron and suspicious stubs
Napastnicy często edytują stub 0anacron znajdujący się w każdym katalogu `/etc/cron.*/`, aby zapewnić okresowe wykonywanie.<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: Wycofanie hardeningu SSH i backdoored shells
Zmiany w sshd_config i powłokach kont systemowych są częstą techniką post-exploitation służącą do utrzymania dostępu.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: znaczniki Cloud C2 (Dropbox/Cloudflare Tunnel)
- Beacony Dropbox API zazwyczaj korzystają z api.dropboxapi.com lub content.dropboxapi.com przez HTTPS, używając tokenów Authorization: Bearer.
- Przeszukaj proxy/Zeek/NetFlow pod kątem nieoczekiwanego ruchu wychodzącego z serwerów do Dropbox.
- Cloudflare Tunnel (`cloudflared`) zapewnia zapasowy C2 przez wychodzące połączenie 443.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Usługi

Ścieżki, w których malware może zostać zainstalowane jako usługa:

- **/etc/inittab**: Wywołuje skrypty inicjalizacyjne, takie jak rc.sysinit, przekazując dalsze wykonywanie skryptom startowym.
- **/etc/rc.d/** i **/etc/rc.boot/**: Zawierają skrypty uruchamiania usług; ten drugi katalog występuje w starszych wersjach Linuxa.
- **/etc/init.d/**: Używany w niektórych wersjach Linuxa, takich jak Debian, do przechowywania skryptów startowych.
- Usługi mogą być również aktywowane za pośrednictwem **/etc/inetd.conf** lub **/etc/xinetd/**, zależnie od wariantu Linuxa.
- **/etc/systemd/system**: Katalog zawierający skrypty menedżera systemu i usług.
- **/etc/systemd/system/multi-user.target.wants/**: Zawiera linki do usług, które powinny zostać uruchomione na poziomie uruchomienia dla wielu użytkowników.
- **/usr/local/etc/rc.d/**: Przeznaczony dla niestandardowych usług i usług firm trzecich.
- **\~/.config/autostart/**: Przeznaczony dla automatycznie uruchamianych aplikacji użytkownika, może być miejscem ukrycia malware ukierunkowanego na użytkownika.
- **/lib/systemd/system/**: Domyślne pliki jednostek dla całego systemu, dostarczane przez zainstalowane pakiety.

#### Poszukiwanie: timery systemd i jednostki przejściowe

Persistence systemd nie ogranicza się do plików `.service`. Zbadaj jednostki `.timer`, jednostki na poziomie użytkownika oraz **jednostki przejściowe** tworzone w czasie działania.
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
Jednostki przejściowe łatwo przeoczyć, ponieważ `/run/systemd/transient/` jest **nietrwały**. Jeśli zbierasz obraz systemu na żywo, pobierz go przed zamknięciem systemu.

### Moduły kernela

Moduły kernela Linux, często wykorzystywane przez malware jako komponenty rootkitów, są ładowane podczas uruchamiania systemu. Krytyczne dla tych modułów katalogi i pliki obejmują:

- **/lib/modules/$(uname -r)**: Przechowuje moduły dla aktualnie uruchomionej wersji kernela.
- **/etc/modprobe.d**: Zawiera pliki konfiguracyjne sterujące ładowaniem modułów.
- **/etc/modprobe** oraz **/etc/modprobe.conf**: Pliki zawierające globalne ustawienia modułów.

### Inne lokalizacje autostartu

Linux wykorzystuje różne pliki do automatycznego uruchamiania programów po zalogowaniu użytkownika, które mogą potencjalnie zawierać malware:

- **/etc/profile.d/**\*, **/etc/profile** oraz **/etc/bash.bashrc**: Są wykonywane podczas logowania dowolnego użytkownika.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile** oraz **\~/.config/autostart**: Pliki specyficzne dla użytkownika, uruchamiane podczas jego logowania.
- **/etc/rc.local**: Uruchamiany po uruchomieniu wszystkich usług systemowych, oznaczając zakończenie przejścia do środowiska wieloużytkownikowego.

## Analiza logów

Systemy Linux śledzą aktywność użytkowników i zdarzenia systemowe za pomocą różnych plików logów. Logi te mają kluczowe znaczenie przy identyfikowaniu nieautoryzowanego dostępu, infekcji malware oraz innych incydentów bezpieczeństwa.<sup>[[2]](#references)</sup> Kluczowe pliki logów obejmują:

- **/var/log/syslog** (Debian) lub **/var/log/messages** (RedHat): Rejestrują komunikaty i aktywność całego systemu.
- **/var/log/auth.log** (Debian) lub **/var/log/secure** (RedHat): Rejestrują próby uwierzytelniania oraz udane i nieudane logowania.
- Użyj `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log`, aby odfiltrować istotne zdarzenia uwierzytelniania.
- **/var/log/boot.log**: Zawiera komunikaty dotyczące uruchamiania systemu.
- **/var/log/maillog** lub **/var/log/mail.log**: Rejestrują aktywność serwera pocztowego, co jest przydatne przy śledzeniu usług związanych z pocztą elektroniczną.
- **/var/log/kern.log**: Przechowuje komunikaty kernela, w tym błędy i ostrzeżenia.
- **/var/log/dmesg**: Zawiera komunikaty sterowników urządzeń.
- **/var/log/faillog**: Rejestruje nieudane próby logowania, pomagając w dochodzeniach dotyczących naruszeń bezpieczeństwa.
- **/var/log/cron**: Rejestruje wykonywanie zadań cron.
- **/var/log/daemon.log**: Śledzi aktywność usług działających w tle.
- **/var/log/btmp**: Dokumentuje nieudane próby logowania.
- **/var/log/httpd/**: Zawiera logi błędów i dostępu Apache HTTPD.
- **/var/log/mysqld.log** lub **/var/log/mysql.log**: Rejestrują aktywność baz danych MySQL.
- **/var/log/xferlog**: Rejestruje transfery plików FTP.
- **/var/log/**: Zawsze sprawdzaj, czy nie ma tu nieoczekiwanych logów.

> [!TIP]
> Logi systemowe Linux oraz podsystemy audytu mogą zostać wyłączone lub usunięte podczas włamania albo incydentu związanego z malware. Ponieważ logi w systemach Linux zazwyczaj zawierają jedne z najbardziej użytecznych informacji o złośliwej aktywności, intruzi rutynowo je usuwają. Dlatego podczas analizowania dostępnych plików logów należy szukać luk lub wpisów w niewłaściwej kolejności, które mogą wskazywać na usunięcie albo modyfikację danych.

### Wstępna analiza Journald (`journalctl`)

Na współczesnych hostach Linux **dziennik systemd** jest zazwyczaj źródłem o najwyższej wartości w zakresie **wykonywania usług**, **zdarzeń uwierzytelniania**, **operacji na pakietach** oraz **komunikatów kernela i przestrzeni użytkownika**. Podczas reagowania na żywo spróbuj zachować zarówno dziennik **trwały** (`/var/log/journal/`), jak i dziennik **uruchomieniowy** (`/run/log/journal/`), ponieważ krótkotrwała aktywność atakującego może istnieć wyłącznie w tym drugim.<sup>[[5]](#references)</sup>
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
Przydatne pola journal do triage obejmują `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` oraz `MESSAGE`. Jeśli journald skonfigurowano bez persistent storage, należy oczekiwać jedynie najnowszych danych w `/run/log/journal/`.

### Triage frameworka audytowego (`auditd`)

Jeśli `auditd` jest włączony, należy preferować go zawsze, gdy potrzebne jest **ustalenie procesu** odpowiedzialnego za zmiany plików, wykonywanie poleceń, aktywność logowania lub instalowanie pakietów.<sup>[[6]](#references)</sup>
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
Gdy reguły zostały wdrożone z kluczami, wykonaj pivot na ich podstawie zamiast przeszukiwać surowe logi:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux przechowuje historię poleceń dla każdego użytkownika**, zapisaną w:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Ponadto polecenie `last -Faiwx` udostępnia listę logowań użytkowników. Sprawdź ją pod kątem nieznanych lub nieoczekiwanych logowań.

Sprawdź pliki, które mogą przyznawać dodatkowe uprawnienia:

- Przejrzyj `/etc/sudoers` pod kątem nieoczekiwanych uprawnień użytkowników, które mogły zostać przyznane.
- Przejrzyj `/etc/sudoers.d/` pod kątem nieoczekiwanych uprawnień użytkowników, które mogły zostać przyznane.
- Sprawdź `/etc/groups`, aby zidentyfikować nietypową przynależność do grup lub uprawnienia.
- Sprawdź `/etc/passwd`, aby zidentyfikować nietypową przynależność do grup lub uprawnienia.

Niektóre aplikacje generują również własne logi:

- **SSH**: Sprawdź _\~/.ssh/authorized_keys_ i _\~/.ssh/known_hosts_ pod kątem nieautoryzowanych połączeń zdalnych.
- **Gnome Desktop**: Sprawdź _\~/.recently-used.xbel_ pod kątem ostatnio uzyskiwanych za pomocą aplikacji Gnome plików.
- **Firefox/Chrome**: Sprawdź historię przeglądania i pobierane pliki w _\~/.mozilla/firefox_ lub _\~/.config/google-chrome_ pod kątem podejrzanej aktywności.
- **VIM**: Przejrzyj _\~/.viminfo_ w celu uzyskania informacji o użyciu, takich jak ścieżki otwieranych plików i historia wyszukiwania.
- **Open Office**: Sprawdź ostatni dostęp do dokumentów, który może wskazywać na naruszenie bezpieczeństwa plików.
- **FTP/SFTP**: Przejrzyj logi w _\~/.ftp_history_ lub _\~/.sftp_history_ pod kątem potencjalnie nieautoryzowanych transferów plików.
- **MySQL**: Zbadaj _\~/.mysql_history_ pod kątem wykonywanych zapytań MySQL, które mogą ujawnić nieautoryzowaną aktywność w bazie danych.
- **Less**: Przeanalizuj _\~/.lesshst_ pod kątem historii użycia, w tym wyświetlanych plików i wykonywanych poleceń.
- **Git**: Sprawdź _\~/.gitconfig_ i _.git/logs_ projektu pod kątem zmian w repozytoriach.

### Logi USB

[**usbrip**](https://github.com/snovvcrash/usbrip) to niewielkie oprogramowanie napisane w Python 3, które analizuje pliki logów Linuxa (`/var/log/syslog*` lub `/var/log/messages*`, zależnie od dystrybucji) w celu tworzenia tabel historii zdarzeń USB.

Warto **wiedzieć, jakie urządzenia USB były używane**, a jeszcze bardziej przydatne jest posiadanie autoryzowanej listy urządzeń USB w celu wykrywania „zdarzeń naruszenia” (użycia urządzeń USB, których nie ma na tej liście).

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

Przeanalizuj pliki _**/etc/passwd**_, _**/etc/shadow**_ oraz **security logs** pod kątem nietypowych nazw lub kont utworzonych i lub używanych w krótkim odstępie czasu od znanych nieautoryzowanych zdarzeń. Sprawdź również możliwe ataki brute-force na sudo.\
Ponadto sprawdź pliki takie jak _**/etc/sudoers**_ i _**/etc/groups**_ pod kątem nieoczekiwanych uprawnień przyznanych użytkownikom.\
Na koniec poszukaj kont z **brakiem haseł** lub **łatwymi do odgadnięcia** hasłami.<sup>[[1]](#references)</sup>

## Analiza systemu plików

### Analizowanie struktur systemu plików podczas badania malware

Podczas badania incydentów związanych z malware struktura systemu plików jest kluczowym źródłem informacji, ujawniającym zarówno sekwencję zdarzeń, jak i zawartość malware. Autorzy malware opracowują jednak techniki utrudniające tę analizę, takie jak modyfikowanie znaczników czasu plików lub unikanie systemu plików do przechowywania danych.<sup>[[1]](#references)</sup>

Aby przeciwdziałać tym metodom anti-forensic, należy:

- **Przeprowadzić dokładną analizę osi czasu** przy użyciu narzędzi takich jak **Autopsy** do wizualizacji osi czasu zdarzeń lub `mactime` z **Sleuth Kit** do uzyskania szczegółowych danych osi czasu.
- **Zbadać nieoczekiwane skrypty** znajdujące się w systemowym $PATH, które mogą obejmować skrypty powłoki lub PHP używane przez atakujących.
- **Przeanalizować `/dev` pod kątem nietypowych plików**, ponieważ tradycyjnie zawiera on pliki specjalne, ale może również przechowywać pliki powiązane z malware.
- **Wyszukać ukryte pliki lub katalogi** o nazwach takich jak ".. " (dwie kropki i spacja) lub "..^G" (dwie kropki i control-G), które mogą ukrywać złośliwą zawartość.
- **Zidentyfikować pliki setuid root** za pomocą polecenia: `find / -user root -perm -04000 -print` Polecenie to wyszukuje pliki z podwyższonymi uprawnieniami, które mogą zostać wykorzystane przez atakujących.
- **Przejrzeć znaczniki czasu usunięcia** w tabelach inode, aby wykryć masowe usuwanie plików, co może wskazywać na obecność rootkits lub trojans.
- **Przeanalizować kolejne inode'y** pod kątem znajdujących się w pobliżu złośliwych plików po zidentyfikowaniu jednego z nich, ponieważ mogły zostać umieszczone razem.
- **Sprawdzić typowe katalogi plików binarnych** (_/bin_, _/sbin_) pod kątem niedawno zmodyfikowanych plików, ponieważ mogły zostać zmienione przez malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Należy pamiętać, że **atakujący** może **zmodyfikować** **czas**, aby **pliki wyglądały** na **legalne**, ale nie może zmodyfikować **inode**. Jeśli zauważysz, że **plik** wskazuje, iż został utworzony i zmodyfikowany w **tym samym czasie** co pozostałe pliki w tym samym folderze, ale jego **inode** jest **nieoczekiwanie większy**, oznacza to, że **znaczniki czasu tego pliku zostały zmodyfikowane**.

### Szybka analiza wstępna skoncentrowana na inode

Jeśli podejrzewasz antyforensics, wcześnie wykonaj te kontrole skoncentrowane na inode:
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
- **ctime/mtime**: pomaga powiązać zmiany metadanych/zawartości z osią czasu incydentu.

### Capabilities, xattrs i userland rootkits oparte na preload

Współczesna persistence w Linux często unika oczywistych plików binarnych `setuid`, a zamiast tego wykorzystuje **file capabilities**, **extended attributes** oraz dynamic loader.
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
Zwróć szczególną uwagę na biblioteki wskazywane ze **ścieżek z prawem zapisu**, takich jak `/tmp`, `/dev/shm`, `/var/tmp` lub nietypowe lokalizacje w `/usr/local/lib`. Sprawdź również pliki binarne z capabilities znajdujące się poza standardową własnością pakietów i skoreluj je z wynikami weryfikacji pakietów (`rpm -Va`, `dpkg --verify`, `debsums`).

## Porównywanie plików z różnych wersji systemu plików

### Podsumowanie porównywania wersji systemu plików

Aby porównywać wersje systemu plików i wskazywać zmiany, używamy uproszczonych poleceń `git diff`:<sup>[[3]](#references)</sup>

- **Aby znaleźć nowe pliki**, porównaj dwa katalogi:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **W przypadku zmodyfikowanej zawartości** wymień zmiany, pomijając określone wiersze:
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
- `T`: Zmiany typu (np. plik na dowiązanie symboliczne)
- `U`: Niezmergowane pliki
- `X`: Nieznane pliki
- `B`: Uszkodzone pliki

## Odnośniki

- [1] [Przewodnik terenowy po analizie śledczej malware dla systemów Linux: Przewodniki terenowe po analizie cyfrowej – rozdział 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Wyjaśnienie logów Linux](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [Dokumentacja `git diff` – opcja `--diff-filter`](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – Łatanie w celu utrzymania persistence: Jak malware DripDropper dla Linuxa porusza się w cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Analiza śledcza dzienników Linux](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 – Audytowanie systemu](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Przywitaj się z Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [Rozszerzenie SQLite FTS5](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
