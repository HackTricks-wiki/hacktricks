# Pliki, foldery, pliki binarne i pamięć w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Układ hierarchii plików

Apple opisuje system plików macOS jako hierarchię domen systemowych, lokalnych, sieciowych i użytkownika. Dokładna zawartość różni się w zależności od wydania systemu, a lokalizacje systemowe są coraz częściej chronione lub syntetyzowane. <sup>[[1]](#references)</sup>

- **/Applications**: Zainstalowane aplikacje powinny znajdować się tutaj. Wszyscy użytkownicy będą mogli uzyskać do nich dostęp.
- **/bin**: Pliki binarne wiersza poleceń
- **/cores**: Jeśli istnieje, służy do przechowywania zrzutów pamięci
- **/dev**: Wszystko jest traktowane jako plik, więc można tutaj znaleźć urządzenia sprzętowe.
- **/etc**: Pliki konfiguracyjne
- **/Library**: Można tutaj znaleźć wiele podkatalogów i plików związanych z preferencjami, pamięcią podręczną i logami. Folder Library istnieje w katalogu głównym oraz w katalogu każdego użytkownika.
- **/private**: Nieudokumentowany, ale wiele wspomnianych folderów to dowiązania symboliczne do katalogu private.
- **/sbin**: Niezbędne pliki binarne systemu (związane z administracją)
- **/System**: Pliki wymagane przez macOS; to drzewo zawiera przede wszystkim komponenty dostarczane przez Apple.
- **/tmp**: Pliki tymczasowe (dowiązanie symboliczne do `/private/tmp`). W historycznych instalacjach stare pliki tymczasowe były zazwyczaj usuwane okresowo, czasami po trzech dniach, ale obecny czas czyszczenia zależy od systemu i zasad; nie należy zakładać, że dane będą tam przechowywane.
- **/Users**: Katalogi domowe użytkowników.
- **/usr**: Pliki konfiguracyjne i binarne systemu
- **/var**: Pliki dzienników
- **/Volumes**: Tutaj pojawiają się zamontowane woluminy.
- **/.vol**: Uruchamiając `stat a.txt`, otrzymasz coś w rodzaju `16777223 7545753 -rw-r--r-- 1 username wheel ...`, gdzie pierwsza liczba to identyfikator woluminu, na którym znajduje się plik, a druga to numer inode. Możesz uzyskać dostęp do zawartości tego pliku przez /.vol/, używając tych informacji i uruchamiając `cat /.vol/16777223/7545753`

### Foldery aplikacji

- **Aplikacje systemowe** znajdują się w `/System/Applications`
- **Zainstalowane** aplikacje są zazwyczaj instalowane w `/Applications` lub w `~/Applications`
- **Dane aplikacji** można znaleźć w `/Library/Application Support` dla aplikacji uruchamianych jako root oraz w `~/Library/Application Support` dla aplikacji uruchamianych jako użytkownik.
- **Daemony** aplikacji innych firm, które **muszą działać jako root**, zwykle znajdują się w `/Library/PrivilegedHelperTools/`.
- Aplikacje działające w **Sandboxie** są mapowane do folderu `~/Library/Containers`. Każda aplikacja ma folder nazwany zgodnie z identyfikatorem bundle aplikacji (`com.apple.Safari`).
- **Kernel** znajduje się w `/System/Library/Kernels/kernel`
- **Rozszerzenia kernela Apple** znajdują się w `/System/Library/Extensions`
- **Rozszerzenia kernela innych firm** są przechowywane w `/Library/Extensions`

### Pliki zawierające poufne informacje

macOS przechowuje poufne informacje, w tym dane uwierzytelniające, w kilku miejscach:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Podatne instalatory pkg


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Rozszerzenia specyficzne dla OS X

- **`.dmg`**: Pliki Apple Disk Image są bardzo często używane przez instalatory.
- **`.kext`**: Musi mieć określoną strukturę i jest wersją sterownika dla OS X. (jest bundle)
- **`.plist`**: Lista właściwości przechowuje uporządkowane informacje w formacie XML lub binarnym.
- Może być w formacie XML lub binarnym. Pliki binarne można odczytać za pomocą:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plist`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Bundle aplikacji, który zachowuje standardową strukturę katalogów macOS.
- **`.dylib`**: Biblioteki dynamiczne (podobne do plików DLL w Windows)
- **`.pkg`**: Są takie same jak xar (format eXtensible Archive). Polecenie instalatora może służyć do instalowania zawartości tych plików.
- **`.DS_Store`**: Ten plik znajduje się w każdym katalogu i zapisuje atrybuty oraz dostosowania katalogu.
- **`.Spotlight-V100`**: Ten folder pojawia się w katalogu głównym każdego woluminu w systemie.
- **`.metadata_never_index`**: Jeśli ten plik znajduje się w katalogu głównym woluminu, Spotlight nie będzie indeksować tego woluminu.
- **`.noindex`**: Pliki i foldery z tym rozszerzeniem nie będą indeksowane przez Spotlight.
- **`.sdef`**: Plik definicji skryptów opisujący sposób, w jaki AppleScript może współdziałać z aplikacją.

### Bundle macOS

Bundle to katalog ze standaryzowaną hierarchią, który Finder może prezentować jako pojedynczy obiekt; bundle aplikacji używają rozszerzenia `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Pamięć podręczna współdzielonych bibliotek Dyld (SLC)

W macOS i iOS często używane biblioteki systemowe i frameworki są wstępnie linkowane do **dyld shared cache**, co poprawia wydajność uruchamiania aplikacji. Chociaż jest traktowana jako jedna logiczna pamięć podręczna, obecne wydania mogą przechowywać ją jako główną pamięć podręczną oraz wiele plików subcache, zamiast dosłownie w jednym pliku. Jej format i lokalizacja są szczegółami implementacji, które zmieniają się między wydaniami systemu. <sup>[[3]](#references)</sup>

W macOS znajduje się ona w `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`, a w starszych wersjach **shared cache** można było znaleźć w **`/System/Library/dyld/`**.\
W iOS można je znaleźć w **`/System/Library/Caches/com.apple.dyld/`**.

Podobnie jak dyld shared cache, kernel i rozszerzenia kernela są również kompilowane do kernel cache, który jest ładowany podczas uruchamiania systemu.

Starsze wydania można było wyodrębniać za pomocą [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Ta wersja może nie obsługiwać obecnych formatów cache; inną opcją jest [**dyldextractor**](https://github.com/arandomdev/dyldextractor):
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Należy pamiętać, że nawet jeśli narzędzie `dyld_shared_cache_util` nie działa, można przekazać **shared dyld binary do Hopper**, a Hopper będzie w stanie zidentyfikować wszystkie biblioteki i pozwoli **wybrać, którą z nich** chcesz zbadać:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Niektóre extractors nie będą działać, ponieważ dylibs są prelinked z hard coded addresses i dlatego mogą skakać do nieznanych adresów

> [!TIP]
> Możliwe jest również pobranie Shared Library Cache innych urządzeń \*OS w macos za pomocą emulatora w Xcode. Zostaną one pobrane do: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, tak jak:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapowanie SLC

**`dyld`** używa syscall **`shared_region_check_np`**, aby sprawdzić, czy SLC został zmapowany (co zwraca adres), oraz **`shared_region_map_and_slide_np`** do zmapowania SLC.

Należy pamiętać, że nawet jeśli SLC jest slid przy pierwszym użyciu, wszystkie **procesy** korzystają z **tej samej kopii**, co **eliminowało ochronę ASLR**, jeśli attacker był w stanie uruchamiać procesy w systemie. Zostało to faktycznie wykorzystane w przeszłości i naprawione za pomocą shared region pager.

Branch pools to małe dylibs Mach-O, które tworzą niewielkie przestrzenie między mapowaniami obrazów, uniemożliwiając interpose funkcji.

### Override SLCs

Za pomocą zmiennych środowiskowych:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Umożliwi to załadowanie nowego shared library cache
- **`DYLD_SHARED_CACHE_DIR=avoid`** i ręczne zastąpienie bibliotek symlinkami do shared cache zawierającego rzeczywiste biblioteki (należy je wyekstrahować)

## Specjalne uprawnienia plików

### Uprawnienia folderów

W przypadku katalogu **read** zezwala na wyświetlanie wpisów, **write** zezwala na tworzenie lub usuwanie wpisów, a **execute** zezwala na przechodzenie. W związku z tym użytkownik, który może odczytać plik, ale nie może przechodzić przez katalog nadrzędny, nie może uzyskać dostępu do tego pliku za pomocą ścieżki. <sup>[[4]](#references)</sup>

### Modyfikatory flag

Pliki mogą mieć flagi zmieniające ich zachowanie. Flagi w katalogu można sprawdzić za pomocą `ls -lO /path/directory`.

- **`uchg`**: Znana jako flaga **uchange**, **uniemożliwia dowolne działanie** zmieniające lub usuwające **plik**. Aby ją ustawić, wykonaj: `chflags uchg file.txt`
- Użytkownik root może **usunąć flagę** i zmodyfikować plik
- **`restricted`**: Ta flaga sprawia, że plik jest **chroniony przez SIP** (nie można dodać tej flagi do pliku).
- **`Sticky bit`**: W katalogu z ustawionym sticky bit tylko właściciel pliku, właściciel katalogu lub root może zmienić nazwę wpisu albo go usunąć. Zwykle jest on włączony w `/tmp`, aby uniemożliwić użytkownikom usuwanie lub przenoszenie plików innych użytkowników.

Wszystkie flagi można znaleźć w pliku `sys/stat.h` (znajdź go za pomocą `mdfind stat.h | grep stat.h`) i są to:

- `UF_SETTABLE` 0x0000ffff: Maska flag, które może zmieniać właściciel.
- `UF_NODUMP` 0x00000001: Nie zrzucaj pliku.
- `UF_IMMUTABLE` 0x00000002: Plik nie może być zmieniany.
- `UF_APPEND` 0x00000004: Do pliku można wyłącznie dopisywać dane.
- `UF_OPAQUE` 0x00000008: Katalog jest nieprzezroczysty względem union.
- `UF_COMPRESSED` 0x00000020: Plik jest skompresowany (w niektórych systemach plików).
- `UF_TRACKED` 0x00000040: Brak powiadomień o usunięciach/zmianach nazw plików, dla których ta flaga jest ustawiona.
- `UF_DATAVAULT` 0x00000080: Do odczytu i zapisu wymagane jest entitlement.
- `UF_HIDDEN` 0x00008000: Wskazówka, że ten element nie powinien być wyświetlany w GUI.
- `SF_SUPPORTED` 0x009f0000: Maska flag obsługiwanych przez superusera.
- `SF_SETTABLE` 0x3fff0000: Maska flag, które może zmieniać superuser.
- `SF_SYNTHETIC` 0xc0000000: Maska syntetycznych flag systemowych tylko do odczytu.
- `SF_ARCHIVED` 0x00010000: Plik jest zarchiwizowany.
- `SF_IMMUTABLE` 0x00020000: Plik nie może być zmieniany.
- `SF_APPEND` 0x00040000: Do pliku można wyłącznie dopisywać dane.
- `SF_RESTRICTED` 0x00080000: Do zapisu wymagane jest entitlement.
- `SF_NOUNLINK` 0x00100000: Elementu nie można usunąć, zmienić mu nazwy ani zamontować na nim.
- `SF_FIRMLINK` 0x00800000: Plik jest firmlink.
- `SF_DATALESS` 0x40000000: Plik jest obiektem dataless.

### **ACL plików**

**ACL** plików zawierają **ACE** (Access Control Entries), w których można przypisać bardziej **szczegółowe uprawnienia** różnym użytkownikom.

Katalogowi można nadać następujące uprawnienia: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Plikowi: `read`, `write`, `append` oraz `execute`.

Gdy plik zawiera ACL, podczas wyświetlania uprawnień **pojawi się znak „+”, jak w**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Możesz **odczytać listy ACL** pliku za pomocą:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Możesz znaleźć **wszystkie pliki z ACL** za pomocą następującego polecenia (jest bardzo wolne):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Extended Attributes

Extended attributes to nazwane wartości metadanych przechowywane oddzielnie od zwykłych atrybutów pliku. Wyświetlaj je za pomocą `ls -l@`, a sprawdzaj lub modyfikuj za pomocą `xattr`. <sup>[[5]](#references)</sup> Niektóre popularne extended attributes:

- `com.apple.resourceFork`: Zgodność z resource fork. Widoczne również jako `filename/..namedfork/rsrc`
- `com.apple.quarantine`: Metadane kwarantanny macOS Gatekeeper
- `metadata:*`: Metadane macOS, takie jak `_backup_excludeItem` lub `kMD*`
- `com.apple.lastuseddate` (#PS): Data ostatniego użycia pliku
- `com.apple.FinderInfo`: Informacje macOS Finder, takie jak znaczniki kolorów
- `com.apple.TextEncoding`: Określa kodowanie tekstu plików ASCII
- `com.apple.logd.metadata`: Używane przez logd w plikach w `/var/db/diagnostics`
- `com.apple.genstore.*`: Pamięć generacyjna (`/.DocumentRevisions-V100` w katalogu głównym systemu plików)
- `com.apple.rootless`: Metadane macOS powiązane z System Integrity Protection
- `com.apple.uuidb.boot-uuid`: Oznaczenia logd epok uruchomienia systemu za pomocą unikalnego UUID
- `com.apple.decmpfs`: Metadane przejrzystej kompresji plików macOS
- `com.apple.cprotect`: \*OS: Dane szyfrowania poszczególnych plików (III/11)
- `com.apple.installd.*`: \*OS: Metadane używane przez installd, np. `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Resource forks zapewniają alternate data stream w macOS. Zawartość może być przechowywana w extended attribute `com.apple.ResourceFork` i uzyskiwana za pośrednictwem `file/..namedfork/rsrc`.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Możesz **znaleźć wszystkie pliki zawierające ten atrybut rozszerzony** za pomocą:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Rozszerzony atrybut `com.apple.decmpfs` przechowuje metadane dotyczące transparentnej kompresji; nie wskazuje na szyfrowanie. W zależności od formatu kompresji skompresowane dane mogą być przechowywane w atrybucie lub w resource fork i są transparentnie dekompresowane podczas odczytu.

Flaga `UF_COMPRESSED` jest wyświetlana jako `compressed` w `ls -lO`. Nie należy jej usuwać ręcznie: może to spowodować, że system nieprawidłowo zinterpretuje skompresowaną reprezentację.

Polecenie usuwające tę flagę pokazano tutaj, ponieważ jest przydatne podczas analizy forensic, ale uruchomienie go względem skompresowanego pliku może sprawić, że plik będzie wyglądał na pusty lub stanie się niedostępny do czasu naprawienia jego metadanych:
```bash
chflags nocompressed /path/to/file
```
Wbudowane narzędzie `/usr/bin/afscexpand` może wymusić rozwinięcie plików poddanych przezroczystej kompresji. Oddzielne narzędzie firm trzecich `afsctool` może również sprawdzać lub dekompresować kompresję systemu plików Apple, ale nie należy mylić go z wbudowanym poleceniem. <sup>[[8]](#references)</sup>


### Interesujące lokalizacje konfiguracji (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Przechowuje pliki plist flag funkcji Apple, które kontrolują opcjonalne lub eksperymentalne zachowania w daemonach / frameworkach systemowych | Jeśli attacker może ominąć SIP lub uzyskać uprawnienia, manipulowanie nimi może włączyć ukryte ścieżki kodu lub wyłączyć zabezpieczenia |
| `/System/Library/CoreServices/systemVersion.plist` | Zawiera metadane wersji macOS (ProductVersion, BuildVersion) używane przez aplikacje / instalatory do warunkowania zachowania | Modyfikacja może oszukać aplikacje lub instalatory, aby zaakceptowały nieobsługiwane wersje systemu albo odblokowały funkcje |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Preferencje aplikacji / ustawienia systemowe | Jeśli są zapisywalne, attackerzy mogą wstrzykiwać ustawienia sterujące zachowaniem aplikacji, wyłączać zabezpieczenia lub powodować błędną konfigurację |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Definicje plist dla daemonów i agentów działających w tle | Wstawienie lub manipulowanie złośliwym plikiem plist (jeśli pozwalają na to uprawnienia) umożliwia persistence lub privilege escalations |
| `/etc/hosts` | Mapowania nazw hostów ↔ adresów IP używane przez systemowy resolver DNS | Przekierowywanie nazw domen, przechwytywanie ruchu, spoofing usług pod lokalną kontrolą |
| `/etc/sudoers` | Określa, kto może uruchamiać polecenia za pomocą `sudo` i na jakich warunkach | Uszkodzony plik sudoers może przyznać kontom attackerów uprawnienia root lub niewłaściwe uprawnienia |
| `/private/var/db/dslocal/nodes/Default/users/` | Pliki plist z definicjami lokalnych kont użytkowników | Manipulowanie nimi umożliwia tworzenie lub modyfikowanie kont użytkowników, hashy haseł lub metadanych użytkowników |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Rozszerzenia jądra / sterowniki | Instalowanie lub modyfikowanie kextów może prowadzić do uzyskania kontroli na poziomie jądra; są one silnie chronione przez SIP / zasady podpisywania |
| `/private/var/db/SystemPolicyConfiguration/` | Przechowuje konfigurację egzekwowania zasad systemowych (np. Gatekeeper, notaryzacja) | Manipulowanie nimi może umożliwić obejście kontroli zasad lub reguł zaufania |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Binarne pliki pomocnicze SSH i pliki konfiguracyjne | Błędna konfiguracja prowadzi do słabego bezpieczeństwa SSH, nieautoryzowanego dostępu lub użycia niezabezpieczonych algorytmów |
| `/System/Library/Sandbox/Profiles` | Profile systemowego sandboxa (SBPL) używane do ograniczania działań procesów | Zastąpienie lub modyfikacja profili może otworzyć wektory ucieczki z sandboxa lub osłabić izolację |

> **Uwaga**: Wiele z tych ścieżek znajduje się w katalogach chronionych przez SIP (np. `/System`) i jest zabezpieczonych przed zapisem, chyba że SIP zostanie wyłączony lub ominięty.


## Universal Binaries And Mach-O Format

Mach-O jest natywnym formatem plików wykonywalnych w macOS. Universal lub fat binary zawiera wiele zależnych od architektury slice'ów Mach-O w jednym pliku; dedykowana strona wyjaśnia oba formaty:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## File Risk And Handler Metadata

LaunchServices, file quarantine i Gatekeeper wspólnie wpływają na sposób obsługi pobranych plików przez macOS oraz wybór aplikacji dla rozszerzeń i schematów URL. Ich bazy danych i wewnętrzne pliki zasobów zmieniają się między wydaniami; korzystaj z dedykowanych stron zamiast traktować prywatną ścieżkę CoreTypes jako stabilny interfejs zasad:

W wydaniach, które udostępniają starsze metadane ryzyka CoreTypes w lokalizacji `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, często spotykane kategorie to:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: zawartość uznawana za wystarczająco bezpieczną do automatycznego otwarcia zgodnie z obowiązującymi zasadami aplikacji.
- **`LSRiskCategoryNeutral`**: zawartość, która zwykle nie wywołuje ostrzeżenia i nie jest automatycznie otwierana.
- **`LSRiskCategoryUnsafeExecutable`**: zawartość wykonywalna, dla której użytkownik powinien otrzymać ostrzeżenie aplikacji.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: kontenery, takie jak archiwa, które mogą zawierać zawartość wykonywalną i wymagają dalszej analizy.

Są to szczegóły implementacyjne, a nie stabilne publiczne API zasad; potwierdź rzeczywiste metadane oraz zachowanie Safari/Gatekeeper na testowanej wersji macOS.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Zawiera informacje o pobranych plikach, takie jak URL, z którego zostały pobrane.
- **Unified log**: W aktualnych wersjach macOS odpytywanie zdarzeń systemowych i aplikacji umożliwiają polecenia `log show` oraz `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** oraz **`/private/var/log/asl/*.asl`**: Starsze artefakty logowania, które mogą nadal mieć znaczenie w starszych systemach. W tych wydaniach plik `/System/Library/LaunchDaemons/com.apple.syslogd.plist` konfiguruje `syslogd`; polecenie `launchctl list | grep com.apple.syslogd` może pomóc ustalić, czy usługa jest załadowana.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Przechowuje ostatnio otwierane pliki i aplikacje za pośrednictwem programu "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Starsza ścieżka preferencji powiązana z elementami logowania; współczesne wersje macOS używają dodatkowych mechanizmów.
- **`$HOME/Library/Logs/DiskUtility.log`**: Starszy log Disk Utility, który może zawierać informacje o dyskach, w tym urządzeniach USB.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dane dotyczące bezprzewodowych punktów dostępowych.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Starsze dane zastąpień launchd.

## References

- [1] [Apple - Przewodnik programowania systemu plików](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Przewodnik programowania bundle](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - omówienie dyld shared cache](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Przewodnik programowania systemu plików: bezpieczeństwo systemu plików macOS](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - strona podręcznika macOS](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - strona podręcznika macOS](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - strona podręcznika macOS](https://manp.gs/mac/1/afscexpand)
{{#include ../../../banners/hacktricks-training.md}}
