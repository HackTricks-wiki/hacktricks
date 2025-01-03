# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Wstępne zbieranie informacji

### Podstawowe informacje

Przede wszystkim zaleca się posiadanie **USB** z **dobrze znanymi binariami i bibliotekami** (możesz po prostu pobrać ubuntu i skopiować foldery _/bin_, _/sbin_, _/lib,_ i _/lib64_), następnie zamontować USB i zmodyfikować zmienne środowiskowe, aby używać tych binariów:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Gdy skonfigurujesz system do używania dobrych i znanych binarek, możesz zacząć **wyciągać podstawowe informacje**:
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

Podczas uzyskiwania podstawowych informacji powinieneś sprawdzić dziwne rzeczy, takie jak:

- **Procesy root** zazwyczaj działają z niskimi PID, więc jeśli znajdziesz proces root z dużym PID, możesz podejrzewać
- Sprawdź **zarejestrowane loginy** użytkowników bez powłoki w `/etc/passwd`
- Sprawdź **hasła** w `/etc/shadow` dla użytkowników bez powłoki

### Zrzut pamięci

Aby uzyskać pamięć działającego systemu, zaleca się użycie [**LiME**](https://github.com/504ensicsLabs/LiME).\
Aby **skompilować** go, musisz użyć **tego samego jądra**, które używa maszyna ofiary.

> [!NOTE]
> Pamiętaj, że **nie możesz zainstalować LiME ani niczego innego** na maszynie ofiary, ponieważ wprowadzi to wiele zmian w systemie

Więc, jeśli masz identyczną wersję Ubuntu, możesz użyć `apt-get install lime-forensics-dkms`\
W innych przypadkach musisz pobrać [**LiME**](https://github.com/504ensicsLabs/LiME) z githuba i skompilować go z odpowiednimi nagłówkami jądra. Aby **uzyskać dokładne nagłówki jądra** maszyny ofiary, możesz po prostu **skopiować katalog** `/lib/modules/<kernel version>` na swoją maszynę, a następnie **skompilować** LiME używając ich:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME obsługuje 3 **formaty**:

- Surowy (wszystkie segmenty połączone razem)
- Wypełniony (taki sam jak surowy, ale z zerami w prawych bitach)
- Lime (zalecany format z metadanymi)

LiME może być również używany do **wysyłania zrzutu przez sieć** zamiast przechowywania go w systemie, używając czegoś takiego jak: `path=tcp:4444`

### Obrazowanie dysku

#### Wyłączanie

Przede wszystkim musisz **wyłączyć system**. Nie zawsze jest to opcja, ponieważ czasami system będzie serwerem produkcyjnym, którego firma nie może sobie pozwolić na wyłączenie.\
Istnieją **2 sposoby** na wyłączenie systemu, **normalne wyłączenie** i **wyłączenie "wyciągnięciem wtyczki"**. Pierwsze pozwoli na **normalne zakończenie procesów** i **synchronizację** **systemu plików**, ale również umożliwi potencjalnemu **złośliwemu oprogramowaniu** **zniszczenie dowodów**. Podejście "wyciągnięcia wtyczki" może wiązać się z **utrata niektórych informacji** (nie wiele informacji zostanie utraconych, ponieważ już zrobiliśmy obraz pamięci) i **złośliwe oprogramowanie nie będzie miało żadnej możliwości** działania w tej sprawie. Dlatego, jeśli **podejrzewasz**, że może być **złośliwe oprogramowanie**, po prostu wykonaj **komendę** **`sync`** w systemie i wyciągnij wtyczkę.

#### Robienie obrazu dysku

Ważne jest, aby zauważyć, że **przed podłączeniem swojego komputera do czegokolwiek związanego z sprawą**, musisz upewnić się, że będzie on **zamontowany jako tylko do odczytu**, aby uniknąć modyfikacji jakichkolwiek informacji.
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
## Szukaj znanego złośliwego oprogramowania

### Zmodyfikowane pliki systemowe

Linux oferuje narzędzia do zapewnienia integralności komponentów systemowych, co jest kluczowe dla wykrywania potencjalnie problematycznych plików.

- **Systemy oparte na RedHat**: Użyj `rpm -Va` do kompleksowego sprawdzenia.
- **Systemy oparte na Debianie**: `dpkg --verify` do wstępnej weryfikacji, a następnie `debsums | grep -v "OK$"` (po zainstalowaniu `debsums` za pomocą `apt-get install debsums`), aby zidentyfikować wszelkie problemy.

### Detektory złośliwego oprogramowania/rootkitów

Przeczytaj następującą stronę, aby dowiedzieć się o narzędziach, które mogą być przydatne do znajdowania złośliwego oprogramowania:

{{#ref}}
malware-analysis.md
{{#endref}}

## Szukaj zainstalowanych programów

Aby skutecznie wyszukiwać zainstalowane programy zarówno w systemach Debian, jak i RedHat, rozważ wykorzystanie dzienników systemowych i baz danych obok ręcznych kontroli w typowych katalogach.

- Dla Debiana sprawdź _**`/var/lib/dpkg/status`**_ i _**`/var/log/dpkg.log`**_, aby uzyskać szczegóły dotyczące instalacji pakietów, używając `grep` do filtrowania konkretnych informacji.
- Użytkownicy RedHat mogą zapytać bazę danych RPM za pomocą `rpm -qa --root=/mntpath/var/lib/rpm`, aby wylistować zainstalowane pakiety.

Aby odkryć oprogramowanie zainstalowane ręcznie lub poza tymi menedżerami pakietów, przeszukaj katalogi takie jak _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ i _**`/sbin`**_. Połącz listy katalogów z poleceniami specyficznymi dla systemu, aby zidentyfikować pliki wykonywalne, które nie są związane z znanymi pakietami, co zwiększy twoje możliwości wyszukiwania wszystkich zainstalowanych programów.
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
## Przywracanie usuniętych działających binarek

Wyobraź sobie proces, który został uruchomiony z /tmp/exec, a następnie usunięty. Możliwe jest jego wyodrębnienie.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Inspekcja lokalizacji autostartu

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
### Usługi

Ścieżki, w których złośliwe oprogramowanie może być zainstalowane jako usługa:

- **/etc/inittab**: Wywołuje skrypty inicjalizacyjne, takie jak rc.sysinit, kierując dalej do skryptów uruchamiających.
- **/etc/rc.d/** i **/etc/rc.boot/**: Zawierają skrypty do uruchamiania usług, z których drugi znajduje się w starszych wersjach Linuksa.
- **/etc/init.d/**: Używane w niektórych wersjach Linuksa, takich jak Debian, do przechowywania skryptów uruchamiających.
- Usługi mogą być również aktywowane za pomocą **/etc/inetd.conf** lub **/etc/xinetd/**, w zależności od wariantu Linuksa.
- **/etc/systemd/system**: Katalog dla skryptów menedżera systemu i usług.
- **/etc/systemd/system/multi-user.target.wants/**: Zawiera linki do usług, które powinny być uruchamiane w poziomie uruchamiania wieloużytkownikowego.
- **/usr/local/etc/rc.d/**: Dla usług niestandardowych lub firm trzecich.
- **\~/.config/autostart/**: Dla aplikacji uruchamiających się automatycznie specyficznych dla użytkownika, które mogą być miejscem ukrycia złośliwego oprogramowania skierowanego na użytkownika.
- **/lib/systemd/system/**: Domyślne pliki jednostek w systemie dostarczane przez zainstalowane pakiety.

### Moduły jądra

Moduły jądra Linuksa, często wykorzystywane przez złośliwe oprogramowanie jako komponenty rootkit, są ładowane podczas uruchamiania systemu. Katalogi i pliki krytyczne dla tych modułów obejmują:

- **/lib/modules/$(uname -r)**: Zawiera moduły dla uruchamianej wersji jądra.
- **/etc/modprobe.d**: Zawiera pliki konfiguracyjne do kontrolowania ładowania modułów.
- **/etc/modprobe** i **/etc/modprobe.conf**: Pliki dla globalnych ustawień modułów.

### Inne lokalizacje autostartu

Linux wykorzystuje różne pliki do automatycznego uruchamiania programów po zalogowaniu użytkownika, co może sprzyjać ukrywaniu złośliwego oprogramowania:

- **/etc/profile.d/**\*, **/etc/profile**, i **/etc/bash.bashrc**: Wykonywane dla każdego logowania użytkownika.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, i **\~/.config/autostart**: Pliki specyficzne dla użytkownika, które uruchamiają się po ich logowaniu.
- **/etc/rc.local**: Uruchamia się po uruchomieniu wszystkich usług systemowych, co oznacza koniec przejścia do środowiska wieloużytkownikowego.

## Sprawdź logi

Systemy Linux śledzą aktywności użytkowników i zdarzenia systemowe za pomocą różnych plików logów. Logi te są kluczowe do identyfikacji nieautoryzowanego dostępu, infekcji złośliwym oprogramowaniem i innych incydentów bezpieczeństwa. Kluczowe pliki logów obejmują:

- **/var/log/syslog** (Debian) lub **/var/log/messages** (RedHat): Zapisują wiadomości i aktywności w całym systemie.
- **/var/log/auth.log** (Debian) lub **/var/log/secure** (RedHat): Rejestrują próby uwierzytelnienia, udane i nieudane logowania.
- Użyj `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log`, aby filtrować odpowiednie zdarzenia uwierzytelnienia.
- **/var/log/boot.log**: Zawiera wiadomości o uruchamianiu systemu.
- **/var/log/maillog** lub **/var/log/mail.log**: Rejestrują aktywności serwera pocztowego, przydatne do śledzenia usług związanych z pocztą.
- **/var/log/kern.log**: Przechowuje wiadomości jądra, w tym błędy i ostrzeżenia.
- **/var/log/dmesg**: Zawiera wiadomości o sterownikach urządzeń.
- **/var/log/faillog**: Rejestruje nieudane próby logowania, co pomaga w dochodzeniach dotyczących naruszeń bezpieczeństwa.
- **/var/log/cron**: Rejestruje wykonania zadań cron.
- **/var/log/daemon.log**: Śledzi aktywności usług w tle.
- **/var/log/btmp**: Dokumentuje nieudane próby logowania.
- **/var/log/httpd/**: Zawiera logi błędów i dostępu Apache HTTPD.
- **/var/log/mysqld.log** lub **/var/log/mysql.log**: Rejestrują aktywności bazy danych MySQL.
- **/var/log/xferlog**: Rejestruje transfery plików FTP.
- **/var/log/**: Zawsze sprawdzaj nieoczekiwane logi tutaj.

> [!NOTE]
> Logi systemowe Linuksa i podsystemy audytowe mogą być wyłączone lub usunięte w przypadku incydentu włamania lub złośliwego oprogramowania. Ponieważ logi w systemach Linux zazwyczaj zawierają niektóre z najbardziej użytecznych informacji o złośliwych działaniach, intruzi rutynowo je usuwają. Dlatego, przeglądając dostępne pliki logów, ważne jest, aby szukać luk lub nieuporządkowanych wpisów, które mogą wskazywać na usunięcie lub manipulację.

**Linux utrzymuje historię poleceń dla każdego użytkownika**, przechowywaną w:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Ponadto, polecenie `last -Faiwx` dostarcza listę logowań użytkowników. Sprawdź je pod kątem nieznanych lub nieoczekiwanych logowań.

Sprawdź pliki, które mogą przyznać dodatkowe uprawnienia:

- Przejrzyj `/etc/sudoers` w poszukiwaniu nieprzewidzianych uprawnień użytkowników, które mogły zostać przyznane.
- Przejrzyj `/etc/sudoers.d/` w poszukiwaniu nieprzewidzianych uprawnień użytkowników, które mogły zostać przyznane.
- Zbadaj `/etc/groups`, aby zidentyfikować wszelkie nietypowe członkostwa grupowe lub uprawnienia.
- Zbadaj `/etc/passwd`, aby zidentyfikować wszelkie nietypowe członkostwa grupowe lub uprawnienia.

Niektóre aplikacje również generują własne logi:

- **SSH**: Sprawdź _\~/.ssh/authorized_keys_ i _\~/.ssh/known_hosts_ w poszukiwaniu nieautoryzowanych połączeń zdalnych.
- **Gnome Desktop**: Zajrzyj do _\~/.recently-used.xbel_ w poszukiwaniu ostatnio otwieranych plików za pomocą aplikacji Gnome.
- **Firefox/Chrome**: Sprawdź historię przeglądarki i pobierania w _\~/.mozilla/firefox_ lub _\~/.config/google-chrome_ w poszukiwaniu podejrzanych działań.
- **VIM**: Przejrzyj _\~/.viminfo_ w poszukiwaniu szczegółów użycia, takich jak ścieżki do otwieranych plików i historia wyszukiwania.
- **Open Office**: Sprawdź dostęp do ostatnich dokumentów, co może wskazywać na skompromitowane pliki.
- **FTP/SFTP**: Przejrzyj logi w _\~/.ftp_history_ lub _\~/.sftp_history_ w poszukiwaniu transferów plików, które mogą być nieautoryzowane.
- **MySQL**: Zbadaj _\~/.mysql_history_ w poszukiwaniu wykonanych zapytań MySQL, co może ujawnić nieautoryzowane działania w bazie danych.
- **Less**: Analizuj _\~/.lesshst_ w poszukiwaniu historii użycia, w tym przeglądanych plików i wykonanych poleceń.
- **Git**: Sprawdź _\~/.gitconfig_ i projekt _.git/logs_ w poszukiwaniu zmian w repozytoriach.

### Logi USB

[**usbrip**](https://github.com/snovvcrash/usbrip) to mały program napisany w czystym Pythonie 3, który analizuje pliki logów Linuksa (`/var/log/syslog*` lub `/var/log/messages*`, w zależności od dystrybucji) w celu skonstruowania tabel historii zdarzeń USB.

Interesujące jest **znalezienie wszystkich używanych USB** i będzie to bardziej przydatne, jeśli masz autoryzowaną listę USB, aby znaleźć "zdarzenia naruszenia" (użycie USB, które nie znajduje się na tej liście).

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
Więcej przykładów i informacji w repozytorium github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Przegląd kont użytkowników i aktywności logowania

Sprawdź _**/etc/passwd**_, _**/etc/shadow**_ oraz **dzienniki zabezpieczeń** pod kątem nietypowych nazw lub kont utworzonych i/lub używanych w bliskiej odległości od znanych nieautoryzowanych zdarzeń. Sprawdź również możliwe ataki brute-force na sudo.\
Ponadto, sprawdź pliki takie jak _**/etc/sudoers**_ i _**/etc/groups**_ pod kątem nieoczekiwanych uprawnień przyznanych użytkownikom.\
Na koniec, poszukaj kont z **brakującymi hasłami** lub **łatwymi do odgadnięcia** hasłami.

## Zbadaj system plików

### Analiza struktur systemu plików w badaniach nad złośliwym oprogramowaniem

Podczas badania incydentów związanych z złośliwym oprogramowaniem, struktura systemu plików jest kluczowym źródłem informacji, ujawniającym zarówno sekwencję zdarzeń, jak i zawartość złośliwego oprogramowania. Jednak autorzy złośliwego oprogramowania opracowują techniki, aby utrudnić tę analizę, takie jak modyfikowanie znaczników czasowych plików lub unikanie systemu plików do przechowywania danych.

Aby przeciwdziałać tym metodom antyforensycznym, istotne jest:

- **Przeprowadzenie dokładnej analizy osi czasu** przy użyciu narzędzi takich jak **Autopsy** do wizualizacji osi czasu zdarzeń lub `mactime` z **Sleuth Kit** do szczegółowych danych osi czasu.
- **Badanie nieoczekiwanych skryptów** w $PATH systemu, które mogą obejmować skrypty shell lub PHP używane przez atakujących.
- **Sprawdzenie `/dev` pod kątem nietypowych plików**, ponieważ tradycyjnie zawiera pliki specjalne, ale może zawierać pliki związane z złośliwym oprogramowaniem.
- **Wyszukiwanie ukrytych plików lub katalogów** o nazwach takich jak ".. " (kropka kropka spacja) lub "..^G" (kropka kropka kontrola-G), które mogą ukrywać złośliwą zawartość.
- **Identyfikacja plików setuid root** za pomocą polecenia: `find / -user root -perm -04000 -print` To znajduje pliki z podwyższonymi uprawnieniami, które mogą być nadużywane przez atakujących.
- **Przegląd znaczników czasowych usunięcia** w tabelach inode, aby dostrzec masowe usunięcia plików, co może wskazywać na obecność rootkitów lub trojanów.
- **Inspekcja kolejnych inode** w poszukiwaniu pobliskich złośliwych plików po zidentyfikowaniu jednego, ponieważ mogły zostać umieszczone razem.
- **Sprawdzenie wspólnych katalogów binarnych** (_/bin_, _/sbin_) pod kątem niedawno zmodyfikowanych plików, ponieważ mogły zostać zmienione przez złośliwe oprogramowanie.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!NOTE]
> Zauważ, że **atakujący** może **zmienić** **czas**, aby **pliki wyglądały** **na legalne**, ale **nie może** zmienić **inode**. Jeśli odkryjesz, że **plik** wskazuje, że został utworzony i zmodyfikowany w **tym samym czasie** co pozostałe pliki w tym samym folderze, ale **inode** jest **niespodziewanie większy**, to **znaczniki czasu tego pliku zostały zmodyfikowane**.

## Porównaj pliki różnych wersji systemu plików

### Podsumowanie porównania wersji systemu plików

Aby porównać wersje systemu plików i zidentyfikować zmiany, używamy uproszczonych poleceń `git diff`:

- **Aby znaleźć nowe pliki**, porównaj dwa katalogi:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Dla zmodyfikowanej treści**, wymień zmiany, ignorując konkretne linie:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Aby wykryć usunięte pliki**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Opcje filtru** (`--diff-filter`) pomagają zawęzić do konkretnych zmian, takich jak dodane (`A`), usunięte (`D`) lub zmodyfikowane (`M`) pliki.
- `A`: Dodane pliki
- `C`: Skopiowane pliki
- `D`: Usunięte pliki
- `M`: Zmodyfikowane pliki
- `R`: Zmienione nazwy plików
- `T`: Zmiany typu (np. plik na symlink)
- `U`: Niezłączone pliki
- `X`: Nieznane pliki
- `B`: Uszkodzone pliki

## Odniesienia

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Książka: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

{{#include ../../banners/hacktricks-training.md}}
