# macOS Pliki, Foldery, Binaries i Pamięć

{{#include ../../../banners/hacktricks-training.md}}

## Układ hierarchii plików

- **/Applications**: Zainstalowane aplikacje powinny być tutaj. Wszyscy użytkownicy będą mieli do nich dostęp.
- **/bin**: Binaries wiersza poleceń
- **/cores**: Jeśli istnieje, jest używane do przechowywania zrzutów rdzenia
- **/dev**: Wszystko jest traktowane jako plik, więc możesz zobaczyć urządzenia sprzętowe przechowywane tutaj.
- **/etc**: Pliki konfiguracyjne
- **/Library**: Można tutaj znaleźć wiele podkatalogów i plików związanych z preferencjami, pamięciami podręcznymi i dziennikami. Folder Library istnieje w katalogu głównym i w katalogu każdego użytkownika.
- **/private**: Nieudokumentowane, ale wiele z wymienionych folderów to dowiązania symboliczne do katalogu prywatnego.
- **/sbin**: Niezbędne systemowe binaries (związane z administracją)
- **/System**: Plik do uruchamiania OS X. Powinieneś znaleźć tutaj głównie pliki specyficzne dla Apple (nie stron trzecich).
- **/tmp**: Pliki są usuwane po 3 dniach (to jest dowiązanie symboliczne do /private/tmp)
- **/Users**: Katalog domowy dla użytkowników.
- **/usr**: Pliki konfiguracyjne i systemowe binaries
- **/var**: Pliki dzienników
- **/Volumes**: Zamontowane dyski będą się tutaj pojawiać.
- **/.vol**: Uruchamiając `stat a.txt` otrzymujesz coś takiego jak `16777223 7545753 -rw-r--r-- 1 username wheel ...`, gdzie pierwsza liczba to identyfikator woluminu, w którym znajduje się plik, a druga to numer inode. Możesz uzyskać dostęp do zawartości tego pliku przez /.vol/ używając tej informacji uruchamiając `cat /.vol/16777223/7545753`

### Foldery aplikacji

- **Aplikacje systemowe** znajdują się w `/System/Applications`
- **Zainstalowane** aplikacje są zazwyczaj zainstalowane w `/Applications` lub w `~/Applications`
- **Dane aplikacji** można znaleźć w `/Library/Application Support` dla aplikacji działających jako root oraz `~/Library/Application Support` dla aplikacji działających jako użytkownik.
- Daemony aplikacji stron trzecich, które **muszą działać jako root**, zazwyczaj znajdują się w `/Library/PrivilegedHelperTools/`
- **Aplikacje w piaskownicy** są mapowane do folderu `~/Library/Containers`. Każda aplikacja ma folder nazwany zgodnie z identyfikatorem pakietu aplikacji (`com.apple.Safari`).
- **Jądro** znajduje się w `/System/Library/Kernels/kernel`
- **Rozszerzenia jądra Apple** znajdują się w `/System/Library/Extensions`
- **Rozszerzenia jądra stron trzecich** są przechowywane w `/Library/Extensions`

### Pliki z wrażliwymi informacjami

MacOS przechowuje informacje takie jak hasła w kilku miejscach:

{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Wrażliwe instalatory pkg

{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Specyficzne rozszerzenia OS X

- **`.dmg`**: Pliki obrazu dysku Apple są bardzo częste dla instalatorów.
- **`.kext`**: Musi mieć określoną strukturę i jest wersją sterownika dla OS X. (to jest pakiet)
- **`.plist`**: Znane również jako lista właściwości, przechowuje informacje w formacie XML lub binarnym.
- Może być w formacie XML lub binarnym. Pliki binarne można odczytać za pomocą:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Aplikacje Apple, które przestrzegają struktury katalogów (to jest pakiet).
- **`.dylib`**: Biblioteki dynamiczne (jak pliki DLL w Windows)
- **`.pkg`**: Są takie same jak xar (eXtensible Archive format). Komenda instalatora może być użyta do zainstalowania zawartości tych plików.
- **`.DS_Store`**: Ten plik znajduje się w każdym katalogu, zapisuje atrybuty i dostosowania katalogu.
- **`.Spotlight-V100`**: Ten folder pojawia się w katalogu głównym każdego woluminu w systemie.
- **`.metadata_never_index`**: Jeśli ten plik znajduje się w katalogu głównym woluminu, Spotlight nie będzie indeksować tego woluminu.
- **`.noindex`**: Pliki i foldery z tym rozszerzeniem nie będą indeksowane przez Spotlight.
- **`.sdef`**: Pliki wewnątrz pakietów określające, jak można wchodzić w interakcję z aplikacją z AppleScript.

### Pakiety macOS

Pakiet to **katalog**, który **wygląda jak obiekt w Finderze** (przykładem pakietu są pliki `*.app`).

{{#ref}}
macos-bundles.md
{{#endref}}

## Cache współdzielonej biblioteki Dyld (SLC)

W macOS (i iOS) wszystkie współdzielone biblioteki systemowe, takie jak frameworki i dyliby, są **połączone w jeden plik**, zwany **cache współdzielonym dyld**. To poprawia wydajność, ponieważ kod może być ładowany szybciej.

Znajduje się to w macOS w `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` i w starszych wersjach możesz znaleźć **cache współdzielony** w **`/System/Library/dyld/`**.\
W iOS możesz je znaleźć w **`/System/Library/Caches/com.apple.dyld/`**.

Podobnie jak cache współdzielony dyld, jądro i rozszerzenia jądra są również kompilowane do cache jądra, które jest ładowane podczas uruchamiania.

Aby wyodrębnić biblioteki z pojedynczego pliku cache współdzielonego dylib, można było użyć binarnego [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip), który może już nie działać, ale możesz również użyć [**dyldextractor**](https://github.com/arandomdev/dyldextractor):
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Zauważ, że nawet jeśli narzędzie `dyld_shared_cache_util` nie działa, możesz przekazać **wspólny binarny dyld do Hopper** i Hopper będzie w stanie zidentyfikować wszystkie biblioteki i pozwoli ci **wybrać, którą** chcesz zbadać:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Niektóre ekstraktory nie będą działać, ponieważ dyliby są wstępnie powiązane z twardo zakodowanymi adresami, przez co mogą skakać do nieznanych adresów.

> [!TIP]
> Możliwe jest również pobranie Shared Library Cache z innych urządzeń \*OS w macos, używając emulatora w Xcode. Zostaną one pobrane w: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, jak: `$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapowanie SLC

**`dyld`** używa wywołania systemowego **`shared_region_check_np`**, aby sprawdzić, czy SLC został zamapowany (co zwraca adres) oraz **`shared_region_map_and_slide_np`**, aby zamapować SLC.

Zauważ, że nawet jeśli SLC jest przesunięty przy pierwszym użyciu, wszystkie **procesy** używają **tej samej kopii**, co **eliminowało ochronę ASLR**, jeśli atakujący był w stanie uruchomić procesy w systemie. To było w rzeczywistości wykorzystywane w przeszłości i naprawione z użyciem pagera regionu współdzielonego.

Pule gałęzi to małe dyliby Mach-O, które tworzą małe przestrzenie między mapowaniami obrazów, co uniemożliwia wstawianie funkcji.

### Nadpisywanie SLC

Używając zmiennych środowiskowych:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> To pozwoli na załadowanie nowej pamięci podręcznej biblioteki współdzielonej.
- **`DYLD_SHARED_CACHE_DIR=avoid`** i ręczne zastąpienie bibliotek dowiązaniami do pamięci podręcznej z rzeczywistymi (będziesz musiał je wyodrębnić).

## Specjalne uprawnienia plików

### Uprawnienia folderów

W **folderze**, **odczyt** pozwala na **wyświetlenie go**, **zapis** pozwala na **usunięcie** i **zapisanie** plików w nim, a **wykonanie** pozwala na **przechodzenie** przez katalog. Na przykład, użytkownik z **uprawnieniami do odczytu pliku** w katalogu, w którym **nie ma uprawnień do wykonania**, **nie będzie mógł odczytać** pliku.

### Modyfikatory flag

Istnieją pewne flagi, które mogą być ustawione w plikach, co sprawi, że plik będzie zachowywał się inaczej. Możesz **sprawdzić flagi** plików w katalogu za pomocą `ls -lO /path/directory`

- **`uchg`**: Znana jako flaga **uchange**, będzie **zapobiegać jakiejkolwiek akcji** zmieniającej lub usuwającej **plik**. Aby ją ustawić, użyj: `chflags uchg file.txt`
- Użytkownik root może **usunąć flagę** i zmodyfikować plik.
- **`restricted`**: Ta flaga sprawia, że plik jest **chroniony przez SIP** (nie możesz dodać tej flagi do pliku).
- **`Sticky bit`**: Jeśli katalog ma bit sticky, **tylko** właściciel **katalogu lub root mogą zmieniać nazwy lub usuwać** pliki. Zazwyczaj jest to ustawiane w katalogu /tmp, aby zapobiec zwykłym użytkownikom w usuwaniu lub przenoszeniu plików innych użytkowników.

Wszystkie flagi można znaleźć w pliku `sys/stat.h` (znajdź go używając `mdfind stat.h | grep stat.h`) i są:

- `UF_SETTABLE` 0x0000ffff: Maska flag zmiennych przez właściciela.
- `UF_NODUMP` 0x00000001: Nie zrzucaj pliku.
- `UF_IMMUTABLE` 0x00000002: Plik nie może być zmieniany.
- `UF_APPEND` 0x00000004: Zapis do pliku może być tylko dołączany.
- `UF_OPAQUE` 0x00000008: Katalog jest nieprzezroczysty w odniesieniu do unii.
- `UF_COMPRESSED` 0x00000020: Plik jest skompresowany (niektóre systemy plików).
- `UF_TRACKED` 0x00000040: Brak powiadomień o usunięciach/zmianach nazw dla plików z tą flagą.
- `UF_DATAVAULT` 0x00000080: Wymagana uprawnienie do odczytu i zapisu.
- `UF_HIDDEN` 0x00008000: Wskazówka, że ten element nie powinien być wyświetlany w GUI.
- `SF_SUPPORTED` 0x009f0000: Maska flag wspieranych przez superużytkownika.
- `SF_SETTABLE` 0x3fff0000: Maska flag zmiennych przez superużytkownika.
- `SF_SYNTHETIC` 0xc0000000: Maska systemowych flag tylko do odczytu.
- `SF_ARCHIVED` 0x00010000: Plik jest zarchiwizowany.
- `SF_IMMUTABLE` 0x00020000: Plik nie może być zmieniany.
- `SF_APPEND` 0x00040000: Zapis do pliku może być tylko dołączany.
- `SF_RESTRICTED` 0x00080000: Wymagana uprawnienie do zapisu.
- `SF_NOUNLINK` 0x00100000: Element nie może być usunięty, zmieniony ani zamontowany.
- `SF_FIRMLINK` 0x00800000: Plik jest firmlink.
- `SF_DATALESS` 0x40000000: Plik jest obiektem bezdanych.

### **ACL plików**

ACL pliku **zawierają** **ACE** (Wpisy Kontroli Dostępu), gdzie można przypisać bardziej **szczegółowe uprawnienia** różnym użytkownikom.

Możliwe jest przyznanie **katalogowi** tych uprawnień: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
A dla **pliku**: `read`, `write`, `append`, `execute`.

Gdy plik zawiera ACL, **znajdziesz "+" przy wyświetlaniu uprawnień, jak w**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Możesz **przeczytać ACL** pliku za pomocą:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Możesz znaleźć **wszystkie pliki z ACL** za pomocą (to jest bardzo wolne):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Atrybuty rozszerzone

Atrybuty rozszerzone mają nazwę i dowolną wartość, a ich zawartość można zobaczyć za pomocą `ls -@` i manipulować nimi za pomocą polecenia `xattr`. Niektóre powszechne atrybuty rozszerzone to:

- `com.apple.resourceFork`: Zgodność z forkami zasobów. Widoczne również jako `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS: mechanizm kwarantanny Gatekeepera (III/6)
- `metadata:*`: MacOS: różne metadane, takie jak `_backup_excludeItem` lub `kMD*`
- `com.apple.lastuseddate` (#PS): Data ostatniego użycia pliku
- `com.apple.FinderInfo`: MacOS: Informacje o Finderze (np. kolorowe tagi)
- `com.apple.TextEncoding`: Określa kodowanie tekstu plików ASCII
- `com.apple.logd.metadata`: Używane przez logd w plikach w `/var/db/diagnostics`
- `com.apple.genstore.*`: Przechowywanie generacyjne (`/.DocumentRevisions-V100` w katalogu głównym systemu plików)
- `com.apple.rootless`: MacOS: Używane przez System Integrity Protection do oznaczania pliku (III/10)
- `com.apple.uuidb.boot-uuid`: oznaczenia logd epok rozruchowych z unikalnym UUID
- `com.apple.decmpfs`: MacOS: Przezroczysta kompresja plików (II/7)
- `com.apple.cprotect`: \*OS: Dane szyfrowania per-pliku (III/11)
- `com.apple.installd.*`: \*OS: Metadane używane przez installd, np. `installType`, `uniqueInstallID`

### Forki zasobów | macOS ADS

To sposób na uzyskanie **Alternatywnych Strumieni Danych w MacOS**. Możesz zapisać zawartość w atrybucie rozszerzonym o nazwie **com.apple.ResourceFork** wewnątrz pliku, zapisując go w **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Możesz **znaleźć wszystkie pliki zawierające ten rozszerzony atrybut** za pomocą:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Rozszerzony atrybut `com.apple.decmpfs` wskazuje, że plik jest przechowywany w zaszyfrowanej formie, `ls -l` zgłosi **rozmiar 0**, a skompresowane dane znajdują się w tym atrybucie. Kiedy plik jest otwierany, jest on odszyfrowywany w pamięci.

Ten atrybut można zobaczyć za pomocą `ls -lO`, oznaczony jako skompresowany, ponieważ skompresowane pliki są również oznaczone flagą `UF_COMPRESSED`. Jeśli skompresowany plik zostanie usunięty z tą flagą za pomocą `chflags nocompressed </path/to/file>`, system nie będzie wiedział, że plik był skompresowany i dlatego nie będzie w stanie go dekompresować i uzyskać dostępu do danych (pomyśli, że jest on w rzeczywistości pusty).

Narzędzie afscexpand może być użyte do wymuszenia dekompresji pliku.

## **Binarne uniwersalne &** Format Mach-o

Binarne pliki Mac OS są zazwyczaj kompilowane jako **binarne uniwersalne**. **Binarne uniwersalne** mogą **obsługiwać wiele architektur w tym samym pliku**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}

## Pamięć procesów macOS

## Zrzut pamięci macOS

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Kategoria ryzyka plików Mac OS

Katalog `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` to miejsce, w którym przechowywane są informacje o **ryzyku związanym z różnymi rozszerzeniami plików**. Katalog ten klasyfikuje pliki w różne poziomy ryzyka, co wpływa na to, jak Safari obsługuje te pliki po ich pobraniu. Kategorie są następujące:

- **LSRiskCategorySafe**: Pliki w tej kategorii są uważane za **całkowicie bezpieczne**. Safari automatycznie otworzy te pliki po ich pobraniu.
- **LSRiskCategoryNeutral**: Te pliki nie mają żadnych ostrzeżeń i **nie są automatycznie otwierane** przez Safari.
- **LSRiskCategoryUnsafeExecutable**: Pliki w tej kategorii **wywołują ostrzeżenie**, wskazujące, że plik jest aplikacją. Służy to jako środek bezpieczeństwa, aby ostrzec użytkownika.
- **LSRiskCategoryMayContainUnsafeExecutable**: Ta kategoria dotyczy plików, takich jak archiwa, które mogą zawierać plik wykonywalny. Safari **wywoła ostrzeżenie**, chyba że może zweryfikować, że wszystkie zawartości są bezpieczne lub neutralne.

## Pliki dziennika

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Zawiera informacje o pobranych plikach, takie jak adres URL, z którego zostały pobrane.
- **`/var/log/system.log`**: Główny dziennik systemów OSX. com.apple.syslogd.plist jest odpowiedzialny za wykonywanie syslogowania (możesz sprawdzić, czy jest wyłączony, szukając "com.apple.syslogd" w `launchctl list`).
- **`/private/var/log/asl/*.asl`**: To są Dzienniki Systemowe Apple, które mogą zawierać interesujące informacje.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Przechowuje ostatnio otwierane pliki i aplikacje przez "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Przechowuje elementy do uruchomienia po starcie systemu.
- **`$HOME/Library/Logs/DiskUtility.log`**: Plik dziennika dla aplikacji DiskUtility (informacje o dyskach, w tym USB).
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dane o punktach dostępu bezprzewodowego.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Lista dezaktywowanych demonów.

{{#include ../../../banners/hacktricks-training.md}}
