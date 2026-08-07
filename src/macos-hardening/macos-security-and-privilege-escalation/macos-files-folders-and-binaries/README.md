# Pliki, foldery, pliki binarne i pamięć w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Układ hierarchii plików

- **/Applications**: Zainstalowane aplikacje powinny znajdować się tutaj. Wszyscy użytkownicy będą mogli uzyskać do nich dostęp.
- **/bin**: Pliki binarne wiersza poleceń
- **/cores**: Jeśli istnieje, służy do przechowywania zrzutów pamięci
- **/dev**: Wszystko jest traktowane jako plik, więc można tu znaleźć urządzenia sprzętowe.
- **/etc**: Pliki konfiguracyjne
- **/Library**: Znajduje się tu wiele podfolderów i plików związanych z preferencjami, cache i logami. Folder Library istnieje w katalogu głównym oraz w katalogu każdego użytkownika.
- **/private**: Nieudokumentowany, ale wiele wymienionych folderów to dowiązania symboliczne do katalogu private.
- **/sbin**: Niezbędne systemowe pliki binarne (związane z administracją)
- **/System**: Pliki potrzebne do działania OS X. Powinny znajdować się tu głównie pliki specyficzne dla Apple (nie pochodzące od firm trzecich).
- **/tmp**: Pliki są usuwane po 3 dniach (jest to dowiązanie symboliczne do /private/tmp)
- **/Users**: Katalogi domowe użytkowników.
- **/usr**: Pliki konfiguracyjne i systemowe pliki binarne
- **/var**: Pliki logów
- **/Volumes**: Zamontowane dyski pojawią się tutaj.
- **/.vol**: Uruchamiając `stat a.txt`, otrzymasz coś takiego jak `16777223 7545753 -rw-r--r-- 1 username wheel ...`, gdzie pierwsza liczba to identyfikator woluminu, na którym znajduje się plik, a druga to numer inode. Możesz uzyskać dostęp do zawartości tego pliku za pośrednictwem /.vol/, używając tych informacji i uruchamiając `cat /.vol/16777223/7545753`

### Foldery Applications

- **Aplikacje systemowe** znajdują się w `/System/Applications`
- **Zainstalowane** aplikacje są zwykle instalowane w `/Applications` lub w `~/Applications`
- **Dane aplikacji** można znaleźć w `/Library/Application Support` dla aplikacji uruchamianych jako root oraz w `~/Library/Application Support` dla aplikacji uruchamianych jako użytkownik.
- **Daemony** aplikacji firm trzecich, które **muszą działać jako root**, są zwykle umieszczone w `/Library/PrivilegedHelperTools/`
- Aplikacje działające w **Sandbox** są mapowane do folderu `~/Library/Containers`. Każda aplikacja ma folder nazwany zgodnie z identyfikatorem bundle aplikacji (`com.apple.Safari`).
- **Kernel** znajduje się w `/System/Library/Kernels/kernel`
- **Rozszerzenia kernela Apple** znajdują się w `/System/Library/Extensions`
- **Rozszerzenia kernela firm trzecich** są przechowywane w `/Library/Extensions`

### Pliki zawierające poufne informacje

MacOS przechowuje informacje, takie jak hasła, w kilku miejscach:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Podatne instalatory pkg


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Rozszerzenia charakterystyczne dla OS X

- **`.dmg`**: Pliki Apple Disk Image są bardzo często używane przez instalatory.
- **`.kext`**: Musi mieć określoną strukturę i jest wersją drivera dla OS X. (jest to bundle)
- **`.plist`**: Znane również jako property list, przechowują informacje w formacie XML lub binarnym.
- Mogą być w formacie XML lub binarnym. Pliki binarne można odczytać za pomocą:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Aplikacje Apple, które mają strukturę katalogową (są bundle).
- **`.dylib`**: Biblioteki dynamiczne (odpowiednik plików DLL w Windows)
- **`.pkg`**: Są takie same jak xar (format eXtensible Archive). Polecenie installer może służyć do instalowania zawartości tych plików.
- **`.DS_Store`**: Ten plik znajduje się w każdym katalogu i przechowuje atrybuty oraz dostosowania katalogu.
- **`.Spotlight-V100`**: Ten folder pojawia się w katalogu głównym każdego woluminu w systemie.
- **`.metadata_never_index`**: Jeśli ten plik znajduje się w katalogu głównym woluminu, Spotlight nie będzie indeksować tego woluminu.
- **`.noindex`**: Pliki i foldery z tym rozszerzeniem nie będą indeksowane przez Spotlight.
- **`.sdef`**: Pliki wewnątrz bundle określające sposób interakcji z aplikacją za pomocą AppleScript.

### Bundles w macOS

Bundle to **katalog**, który **wygląda jak obiekt w Finderze** (przykładem Bundle są pliki `*.app`).


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

W macOS (i iOS) wszystkie systemowe biblioteki współdzielone, takie jak frameworks i dylibs, są **łączone w jeden plik**, nazywany **dyld shared cache**. Zwiększa to wydajność, ponieważ kod może być ładowany szybciej.

W macOS znajduje się on w `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`, a w starszych wersjach **shared cache** może znajdować się w **`/System/Library/dyld/`**.\
W iOS można je znaleźć w **`/System/Library/Caches/com.apple.dyld/`**.

Podobnie jak dyld shared cache, kernel i rozszerzenia kernela są również kompilowane do kernel cache, który jest ładowany podczas uruchamiania systemu.

Aby wyodrębnić biblioteki z pojedynczego pliku dylib shared cache, można było użyć pliku binarnego [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip), który obecnie może nie działać, ale można również użyć [**dyldextractor**](https://github.com/arandomdev/dyldextractor):
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Należy pamiętać, że nawet jeśli narzędzie `dyld_shared_cache_util` nie działa, można przekazać **shared dyld binary do Hopper**, a Hopper będzie w stanie zidentyfikować wszystkie biblioteki i pozwoli **wybrać, którą z nich** chcesz przeanalizować:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Niektóre extractors nie będą działać, ponieważ dylibs są prelinked z hard coded addresses, przez co mogą wykonywać skoki do nieznanych adresów.

> [!TIP]
> Możliwe jest również pobranie Shared Library Cache innych urządzeń \*OS w macOS przy użyciu emulatora w Xcode. Zostaną one pobrane do: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, np.:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapowanie SLC

**`dyld`** używa syscall **`shared_region_check_np`**, aby sprawdzić, czy SLC został zmapowany (zwraca on adres), oraz **`shared_region_map_and_slide_np`** do mapowania SLC.

Należy pamiętać, że nawet jeśli SLC zostanie slid podczas pierwszego użycia, wszystkie **processes** używają **tej samej kopii**, co **eliminowało ochronę ASLR**, jeśli attacker był w stanie uruchamiać processes w systemie. Zostało to faktycznie wykorzystane w przeszłości i naprawione za pomocą shared region pager.

Branch pools to małe Mach-O dylibs, które tworzą niewielkie przestrzenie między mapowaniami obrazów, uniemożliwiając interpose funkcji.

### Nadpisywanie SLC

Przy użyciu zmiennych środowiskowych:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Pozwoli to załadować nowy shared library cache
- **`DYLD_SHARED_CACHE_DIR=avoid`** i ręcznie zastąpić biblioteki symlinkami do shared cache rzeczywistymi bibliotekami (trzeba będzie je extractować)

## Specjalne uprawnienia plików

### Uprawnienia folderów

W **folderze** uprawnienie **read** pozwala go **wyświetlić**, **write** pozwala **usuwać** i **zapisywać** w nim pliki, a **execute** pozwala na **traverse** katalogu. Na przykład użytkownik z **read permission do pliku** znajdującego się w katalogu, do którego **nie ma execute permission**, **nie będzie mógł odczytać** tego pliku.

### Modyfikatory flag

Istnieją flagi, które można ustawić dla plików i które spowodują ich inne zachowanie. Możesz **sprawdzić flagi** plików w katalogu za pomocą `ls -lO /path/directory`

- **`uchg`**: Znana jako flaga **uchange**, **uniemożliwia podjęcie jakichkolwiek działań** zmieniających lub usuwających **plik**. Aby ją ustawić, wykonaj: `chflags uchg file.txt`
- Użytkownik root może **usunąć flagę** i zmodyfikować plik
- **`restricted`**: Ta flaga sprawia, że plik jest **chroniony przez SIP** (nie można dodać tej flagi do pliku).
- **`Sticky bit`**: Jeśli katalog ma sticky bit, **tylko właściciel katalogu lub root może zmieniać nazwę albo usuwać** pliki. Zwykle ustawia się go dla katalogu /tmp, aby uniemożliwić zwykłym użytkownikom usuwanie lub przenoszenie plików innych użytkowników.

Wszystkie flagi można znaleźć w pliku `sys/stat.h` (znajdź go za pomocą `mdfind stat.h | grep stat.h`) i są to:

- `UF_SETTABLE` 0x0000ffff: Maska flag, które może zmieniać właściciel.
- `UF_NODUMP` 0x00000001: Nie zrzucaj pliku.
- `UF_IMMUTABLE` 0x00000002: Plik nie może być zmieniany.
- `UF_APPEND` 0x00000004: Do pliku można tylko dopisywać dane.
- `UF_OPAQUE` 0x00000008: Katalog jest nieprzezroczysty względem union.
- `UF_COMPRESSED` 0x00000020: Plik jest skompresowany (niektóre file-systems).
- `UF_TRACKED` 0x00000040: Brak notifications dotyczących usuwania/zmiany nazw plików z ustawioną tą flagą.
- `UF_DATAVAULT` 0x00000080: Do odczytu i zapisu wymagane jest entitlement.
- `UF_HIDDEN` 0x00008000: Wskazówka, że ten element nie powinien być wyświetlany w GUI.
- `SF_SUPPORTED` 0x009f0000: Maska flag obsługiwanych przez superusera.
- `SF_SETTABLE` 0x3fff0000: Maska flag, które może zmieniać superuser.
- `SF_SYNTHETIC` 0xc0000000: Maska syntetycznych flag systemowych tylko do odczytu.
- `SF_ARCHIVED` 0x00010000: Plik jest zarchiwizowany.
- `SF_IMMUTABLE` 0x00020000: Plik nie może być zmieniany.
- `SF_APPEND` 0x00040000: Do pliku można tylko dopisywać dane.
- `SF_RESTRICTED` 0x00080000: Do zapisu wymagane jest entitlement.
- `SF_NOUNLINK` 0x00100000: Element nie może być usunięty, mieć zmienionej nazwy ani zostać zamontowany.
- `SF_FIRMLINK` 0x00800000: Plik jest firmlinkiem.
- `SF_DATALESS` 0x40000000: Plik jest obiektem bez danych.

### **ACL plików**

Pliki **ACL** zawierają **ACE** (Access Control Entries), za pomocą których można przypisać **bardziej granularne uprawnienia** różnym użytkownikom.

Katalogowi można nadać następujące uprawnienia: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Plikowi można nadać: `read`, `write`, `append`, `execute`.

Gdy plik zawiera ACL, podczas wyświetlania uprawnień **zobaczysz znak „+”, jak w**:
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
Możesz znaleźć **wszystkie pliki z ACL** za pomocą (to jest baaardzo wolne):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Atrybuty rozszerzone

Atrybuty rozszerzone mają nazwę i dowolnie wybraną wartość. Można je wyświetlać za pomocą `ls -@` i modyfikować za pomocą polecenia `xattr`. Typowe atrybuty rozszerzone to:

- `com.apple.resourceFork`: Zgodność z resource fork. Widoczny również jako `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS: mechanizm kwarantanny Gatekeeper (III/6)
- `metadata:*`: MacOS: różne metadane, takie jak `_backup_excludeItem` lub `kMD*`
- `com.apple.lastuseddate` (#PS): Data ostatniego użycia pliku
- `com.apple.FinderInfo`: MacOS: informacje Findera (np. kolorowe Tagi)
- `com.apple.TextEncoding`: Określa kodowanie tekstu plików ASCII
- `com.apple.logd.metadata`: Używany przez logd dla plików w `/var/db/diagnostics`
- `com.apple.genstore.*`: Generational storage (`/.DocumentRevisions-V100` w katalogu głównym systemu plików)
- `com.apple.rootless`: MacOS: Używany przez System Integrity Protection do oznaczania plików (III/10)
- `com.apple.uuidb.boot-uuid`: Oznaczenia logd epok uruchomienia za pomocą unikalnego UUID
- `com.apple.decmpfs`: MacOS: Przezroczysta kompresja plików (II/7)
- `com.apple.cprotect`: \*OS: Dane szyfrowania poszczególnych plików (III/11)
- `com.apple.installd.*`: \*OS: Metadane używane przez installd, np. `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Jest to sposób na uzyskanie **Alternate Data Streams in MacOS**. Można zapisać zawartość wewnątrz atrybutu rozszerzonego o nazwie **com.apple.ResourceFork** w pliku, zapisując ją w `file/..namedfork/rsrc`.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Możesz **znaleźć wszystkie pliki zawierające ten atrybut rozszerzony** za pomocą:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Atrybut rozszerzony `com.apple.decmpfs` wskazuje, że plik jest przechowywany w postaci zaszyfrowanej, `ls -l` zgłosi **rozmiar 0**, a skompresowane dane znajdują się wewnątrz tego atrybutu. Przy każdym dostępie do pliku zostanie on odszyfrowany w pamięci.

Ten atrybut można zobaczyć za pomocą `ls -lO`, gdzie plik jest oznaczony jako skompresowany, ponieważ skompresowane pliki mają również ustawioną flagę `UF_COMPRESSED`. Jeśli dla skompresowanego pliku flaga ta zostanie usunięta za pomocą `chflags nocompressed </path/to/file>`, system nie będzie wiedział, że plik był skompresowany, a tym samym nie będzie w stanie zdekompresować danych ani uzyskać do nich dostępu (uzna, że plik jest faktycznie pusty).

Narzędzie afscexpand może służyć do wymuszenia dekompresji pliku.


### Interesujące lokalizacje konfiguracji (macOS)

| Ścieżka / Lokalizacja | Przeznaczenie / Co konfiguruje | Potencjał bezpieczeństwa / ataku |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Przechowuje pliki plist z flagami funkcji Apple, które kontrolują opcjonalne lub eksperymentalne zachowania w system daemons / frameworks | Jeśli attacker zdoła obejść SIP lub uzyskać uprawnienia, manipulowanie nimi może włączyć ukryte ścieżki kodu lub wyłączyć zabezpieczenia |
| `/System/Library/CoreServices/systemVersion.plist` | Zawiera metadane wersji macOS (ProductVersion, BuildVersion) używane przez aplikacje / instalatory do warunkowania zachowania | Modyfikacja może nakłonić aplikacje lub instalatory do zaakceptowania nieobsługiwanych wersji systemu albo odblokowania funkcji |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Preferencje aplikacji / całego systemu | Jeśli są zapisywalne, attackers mogą wstrzyknąć ustawienia sterujące zachowaniem aplikacji, wyłączyć zabezpieczenia lub spowodować błędną konfigurację |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Definicje plist dla działających w tle daemons i agents | Wstawienie lub manipulowanie złośliwym plikiem plist (jeśli uprawnienia na to pozwalają) umożliwia persistence lub privilege escalation |
| `/etc/hosts` | Mapowania nazw hostów ↔ adresów IP używane przez systemowy resolver DNS | Przekierowywanie nazw domen, przechwytywanie ruchu, spoofing usług znajdujących się pod lokalną kontrolą |
| `/etc/sudoers` | Określa, kto może uruchamiać polecenia za pomocą `sudo` i na jakich warunkach | Uszkodzony plik sudoers może przyznać root lub niewłaściwe uprawnienia kontom attackerów |
| `/private/var/db/dslocal/nodes/Default/users/` | Pliki plist definicji lokalnych kont użytkowników | Manipulowanie nimi pozwala na tworzenie lub modyfikowanie kont użytkowników, hashy haseł albo metadanych użytkowników |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Rozszerzenia kernela / drivery | Instalowanie lub modyfikowanie kexts może prowadzić do kontroli na poziomie kernela; są one silnie chronione przez SIP / signature policies |
| `/private/var/db/SystemPolicyConfiguration/` | Przechowuje konfigurację egzekwowania zasad systemowych (np. Gatekeeper, notarization) | Manipulowanie tymi elementami może umożliwić obejście kontroli zasad lub reguł zaufania |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Binarne pliki pomocnicze SSH i pliki konfiguracyjne | Błędna konfiguracja prowadzi do słabego bezpieczeństwa SSH, unauthorized access lub użycia niezabezpieczonych algorytmów |
| `/System/Library/Sandbox/Profiles` | Profile systemowego sandboxa (SBPL) używane do ograniczania działań procesów | Zastąpienie lub zmiana profili może otworzyć wektory sandbox escape albo osłabić izolację |

> **Uwaga**: Wiele z tych ścieżek znajduje się w katalogach chronionych przez SIP (np. `/System`) i jest zabezpieczonych przed zapisem, chyba że SIP zostanie wyłączony lub ominięty.


## Binarne uniwersalne & format Mach-o

Binarne pliki Mac OS są zwykle kompilowane jako **universal binaries**. **Universal binary** może **obsługiwać wiele architektur w tym samym pliku**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Zrzucanie pamięci macOS

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Kategorie ryzyka plików Mac OS

Katalog `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` to miejsce, w którym przechowywane są informacje o **ryzyku związanym z różnymi rozszerzeniami plików**. Katalog ten klasyfikuje pliki do różnych poziomów ryzyka, wpływając na sposób, w jaki Safari obsługuje te pliki po pobraniu. Kategorie są następujące:

- **LSRiskCategorySafe**: Pliki w tej kategorii są uznawane za **całkowicie bezpieczne**. Safari automatycznie otworzy te pliki po ich pobraniu.
- **LSRiskCategoryNeutral**: Pliki te nie wyświetlają ostrzeżeń i **nie są automatycznie otwierane** przez Safari.
- **LSRiskCategoryUnsafeExecutable**: Pliki w tej kategorii **wywołują ostrzeżenie** informujące, że plik jest aplikacją. Jest to środek bezpieczeństwa mający ostrzec użytkownika.
- **LSRiskCategoryMayContainUnsafeExecutable**: Ta kategoria obejmuje pliki, takie jak archiwa, które mogą zawierać plik wykonywalny. Safari **wyświetli ostrzeżenie**, chyba że będzie w stanie zweryfikować, że cała zawartość jest bezpieczna lub neutralna.

## Pliki logów

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Zawiera informacje o pobranych plikach, takie jak URL, z którego zostały pobrane.
- **`/var/log/system.log`**: Główny log systemów OSX. com.apple.syslogd.plist odpowiada za działanie syslogging (można sprawdzić, czy jest wyłączony, wyszukując "com.apple.syslogd" w `launchctl list`.
- **`/private/var/log/asl/*.asl`**: Są to Apple System Logs, które mogą zawierać interesujące informacje.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Przechowuje ostatnio używane pliki i aplikacje za pośrednictwem "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Przechowuje elementy uruchamiane podczas startu systemu
- **`$HOME/Library/Logs/DiskUtility.log`**: Plik logu aplikacji DiskUtility (informacje o dyskach, w tym USB)
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dane o bezprzewodowych access points.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Lista dezaktywowanych daemons.

{{#include ../../../banners/hacktricks-training.md}}
