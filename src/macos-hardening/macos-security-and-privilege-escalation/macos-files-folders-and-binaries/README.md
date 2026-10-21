# Pliki, foldery, pliki binarne i pamięć w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Hierarchia systemu plików

Apple opisuje system plików macOS jako hierarchię domen systemowych, lokalnych, sieciowych i użytkowników. Dokładna zawartość zależy od wersji systemu, a lokalizacje systemowe są coraz częściej chronione lub emulowane. <sup>[[1]](#references)</sup>

- **/Applications**: Tutaj powinny znajdować się zainstalowane aplikacje. Wszyscy użytkownicy będą mogli uzyskać do nich dostęp.
- **/bin**: Pliki binarne wiersza poleceń
- **/cores**: Jeśli istnieje, służy do przechowywania zrzutów pamięci
- **/dev**: Wszystko traktowane jest jak plik, więc można tu znaleźć urządzenia sprzętowe.
- **/etc**: Pliki konfiguracyjne
- **/Library**: Można tu znaleźć wiele podkatalogów i plików związanych z preferencjami, pamięcią podręczną i logami. Folder Library znajduje się w katalogu głównym oraz w katalogu każdego użytkownika.
- **/private**: Nieudokumentowany, ale wiele wymienionych folderów to dowiązania symboliczne do katalogu private.
- **/sbin**: Niezbędne pliki binarne systemu (związane z administracją)
- **/System**: Pliki wymagane przez macOS; to drzewo zawiera głównie komponenty dostarczane przez Apple.
- **/tmp**: Pliki tymczasowe (dowiązanie symboliczne do `/private/tmp`). W starszych instalacjach stare pliki tymczasowe były zwykle usuwane okresowo, czasem co trzy dni, ale obecnie harmonogram czyszczenia zależy od systemu i jego zasad; nie należy zakładać, że dane będą tam przechowywane.
- **/Users**: Katalogi domowe użytkowników.
- **/usr**: Pliki konfiguracyjne i binarne systemu
- **/var**: Pliki dzienników
- **/Volumes**: Tutaj pojawiają się zamontowane woluminy.
- **/.vol**: Po uruchomieniu `stat a.txt` otrzymasz coś w rodzaju `16777223 7545753 -rw-r--r-- 1 username wheel ...`, gdzie pierwsza liczba to identyfikator woluminu, na którym znajduje się plik, a druga to numer inode. Możesz uzyskać dostęp do zawartości tego pliku przez /.vol/, używając tych informacji i polecenia `cat /.vol/16777223/7545753`

### Foldery aplikacji

- **Aplikacje systemowe** znajdują się w `/System/Applications`
- **Zainstalowane** aplikacje są zwykle instalowane w `/Applications` lub `~/Applications`
- **Dane aplikacji** można znaleźć w `/Library/Application Support` w przypadku aplikacji działających jako root oraz w `~/Library/Application Support` w przypadku aplikacji działających jako użytkownik.
- **Daemony** aplikacji firm trzecich, które **muszą działać jako root**, zwykle znajdują się w `/Library/PrivilegedHelperTools/`.
- Aplikacje działające w **sandboxie** są umieszczane w folderze `~/Library/Containers`. Każda aplikacja ma folder nazwany zgodnie z jej bundle ID (`com.apple.Safari`).
- **Kernel** znajduje się w `/System/Library/Kernels/kernel`
- **Rozszerzenia kernela Apple** znajdują się w `/System/Library/Extensions`
- **Rozszerzenia kernela firm trzecich** są przechowywane w `/Library/Extensions`

### Pliki zawierające poufne informacje

macOS przechowuje poufne informacje, w tym dane logowania, w kilku miejscach:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Podatne instalatory pkg


{{#ref}}
macos-installers-abuse.md
{{#endref}}

Informacje o różnicy między zapisywalnym woluminem Data a zabezpieczonym woluminem System widocznym w tej hierarchii znajdziesz w [macOS Sealed System Volume & DataVault](../macos-security-protections/macos-sealed-system-volume-and-datavault.md).

## Rozszerzenia specyficzne dla OS X

- **`.dmg`**: Pliki Apple Disk Image są bardzo często używane jako instalatory.
- **`.kext`**: Musi mieć określoną strukturę i jest wersją sterownika dla OS X (jest to bundle).
- **`.plist`**: Property list przechowuje uporządkowane informacje w formacie XML lub binarnym.
  - Może być w formacie XML lub binarnym. Pliki binarne można odczytać za pomocą:
    - `defaults read config.plist`
    - `/usr/libexec/PlistBuddy -c print config.plist`
    - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Bundle aplikacji zgodny ze standardową strukturą katalogów macOS.
- **`.dylib`**: Biblioteki dynamiczne (takie jak pliki DLL systemu Windows)
- **`.pkg`**: Nowoczesne, płaskie pakiety instalacyjne to archiwa XAR, ale `.pkg` to format instalatora, a nie synonim XAR. Starsze pakiety instalacyjne w formie bundle to katalogi. Zobacz [macOS installers](macos-installers-abuse.md), aby poznać strukturę pakietów i sposoby ich analizy. <sup>[[9]](#references)[[12]](#references)</sup>
- **`.DS_Store`**: Ten plik znajduje się w każdym katalogu; zapisuje atrybuty i ustawienia katalogu.
- **`.Spotlight-V100`**: Ten folder pojawia się w katalogu głównym każdego woluminu w systemie.
- **`.metadata_never_index`**: Jeśli ten plik znajduje się w katalogu głównym woluminu, Spotlight nie będzie indeksować tego woluminu.
- **`.noindex`**: Pliki i foldery z tym rozszerzeniem nie będą indeksowane przez Spotlight.
- **`.sdef`**: Plik definicji skryptów opisujący sposób, w jaki AppleScript może współdziałać z aplikacją.

### Bundles macOS

Bundle to katalog o ustandaryzowanej hierarchii, który Finder może wyświetlać jako pojedynczy obiekt; bundle aplikacji używają rozszerzenia `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

W systemach macOS i iOS często używane biblioteki systemowe i frameworki są wstępnie łączone w **dyld shared cache**, co przyspiesza uruchamianie aplikacji. Choć traktowana jest jako jedna logiczna pamięć podręczna, w obecnych wydaniach może być przechowywana jako główna pamięć podręczna oraz kilka plików podrzędnych, a nie dosłownie jako jeden plik. Jej format i lokalizacja to szczegóły implementacyjne, które zmieniają się między wydaniami systemu. <sup>[[3]](#references)</sup>

W macOS znajduje się w `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`, a w starszych wersjach **shared cache** można znaleźć w **`/System/Library/dyld/`**.\
W iOS można ją znaleźć w **`/System/Library/Caches/com.apple.dyld/`**.

Podobnie jak dyld shared cache, kernel i rozszerzenia kernela są również kompilowane do cache kernela, który jest ładowany podczas rozruchu.

W starszych wydaniach można było je wypakować za pomocą [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Ta wersja może nie obsługiwać obecnych formatów cache; inną opcją jest [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```

> [!TIP]
> Pamiętaj, że nawet jeśli narzędzie `dyld_shared_cache_util` nie działa, możesz przekazać **współdzielony plik binarny dyld do Hoppera**, a Hopper zidentyfikuje wszystkie biblioteki i pozwoli **wybrać tę**, którą chcesz zbadać:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Niektóre narzędzia do ekstrakcji nie będą działać, ponieważ dylib są prelinkowane ze sztywno zakodowanymi adresami, przez co mogą wykonywać skoki pod nieznane adresy.

> [!TIP]
> Możliwe jest również pobranie Shared Library Cache z innych urządzeń \*OS w systemie macOS za pomocą emulatora w Xcode. Zostaną pobrane do: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, na przykład: `$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapowanie SLC

**`dyld`** używa syscalla **`shared_region_check_np`**, aby sprawdzić, czy SLC zostało zmapowane (zwraca on adres), oraz **`shared_region_map_and_slide_np`**, aby zmapować SLC.

Pamiętaj, że chociaż przy pierwszym użyciu SLC jest poddawane slidowi, wszystkie **procesy** używają **tej samej kopii**, co **eliminuje ochronę ASLR**, jeśli atakujący był w stanie uruchamiać procesy w systemie. W przeszłości wykorzystano to w ataku, a problem naprawiono za pomocą shared region pager.

Branch pools to małe dylib Mach-O, które tworzą niewielkie odstępy między mapowaniami obrazów, uniemożliwiając interponowanie funkcji.

### Ograniczenia środowiska shared-cache

`DYLD_SHARED_CACHE_DIR` wskazuje katalog cache, natomiast `DYLD_SHARED_REGION` wybiera tryb shared-region. Poprzednia pisownia `DYLD_DHARED_REGION` była nieprawidłowa, a `avoid` nie jest wartością dla `DYLD_SHARED_CACHE_DIR`. Obecny dyld uzależnia tryb `private` od uprawnienia AMFI do używania niestandardowych shared cache, więc samo ustawienie zmiennych środowiskowych nie oznacza, że proces może załadować zastępczy cache. <sup>[[10]](#references)</sup>

## Specjalne uprawnienia plików

### Uprawnienia folderów

W przypadku katalogu uprawnienie **read** pozwala wyświetlać wpisy, **write** pozwala tworzyć lub usuwać wpisy, a **execute** pozwala na przechodzenie przez katalog. Dlatego użytkownik, który może odczytać plik, ale nie może przejść przez katalog nadrzędny, nie uzyska dostępu do tego pliku za pomocą ścieżki. <sup>[[4]](#references)</sup>

### Modyfikatory flag

Pliki mogą mieć flagi zmieniające ich działanie. Wyświetl flagi w katalogu za pomocą `ls -lO /path/directory`.

- **`uchg`**: Flaga **uchange** **uniemożliwia jakiekolwiek działanie** zmieniające lub usuwające **plik**. Aby ją ustawić, użyj: `chflags uchg file.txt`
  - Właściciel pliku lub root może usunąć tę flagę **użytkownika** za pomocą `chflags nouchg file.txt`; nie stanowi ona ochrony przed żadnym z nich. Oddzielna flaga niezmienności **systemu** (`schg`) jest dostępna tylko dla roota. <sup>[[11]](#references)</sup>
- **`restricted`**: Ta flaga sprawia, że plik jest **chroniony przez SIP** (nie można dodać tej flagi do pliku).
- **`Sticky bit`**: W katalogu z ustawionym sticky bitem wpis może zmienić nazwę lub usunąć tylko właściciel pliku, właściciel katalogu albo root. Jest on zwykle włączony dla `/tmp`, aby uniemożliwić użytkownikom usuwanie lub przenoszenie plików innych użytkowników.

Wszystkie flagi można znaleźć w pliku `sys/stat.h` (wyszukaj go poleceniem `mdfind stat.h | grep stat.h`):

- `UF_SETTABLE` 0x0000ffff: Maska flag, które może zmieniać właściciel.
- `UF_NODUMP` 0x00000001: Nie zrzucaj pliku.
- `UF_IMMUTABLE` 0x00000002: Pliku nie można zmieniać.
- `UF_APPEND` 0x00000004: Do pliku można tylko dopisywać.
- `UF_OPAQUE` 0x00000008: Katalog jest nieprzezroczysty względem union.
- `UF_COMPRESSED` 0x00000020: Plik jest skompresowany (niektóre systemy plików).
- `UF_TRACKED` 0x00000040: Brak powiadomień o usunięciu lub zmianie nazwy plików z tą flagą.
- `UF_DATAVAULT` 0x00000080: Do odczytu i zapisu wymagane jest entitlement.
- `UF_HIDDEN` 0x00008000: Wskazówka, że ten element nie powinien być wyświetlany w GUI.
- `SF_SUPPORTED` 0x009f0000: Maska flag obsługiwanych przez superużytkownika.
- `SF_SETTABLE` 0x3fff0000: Maska flag, które może zmieniać superużytkownik.
- `SF_SYNTHETIC` 0xc0000000: Maska syntetycznych flag tylko do odczytu systemu.
- `SF_ARCHIVED` 0x00010000: Plik jest zarchiwizowany.
- `SF_IMMUTABLE` 0x00020000: Pliku nie można zmieniać.
- `SF_APPEND` 0x00040000: Do pliku można tylko dopisywać.
- `SF_RESTRICTED` 0x00080000: Do zapisu wymagane jest entitlement.
- `SF_NOUNLINK` 0x00100000: Elementu nie można usunąć, zmienić jego nazwy ani zamontować na nim systemu plików.
- `SF_FIRMLINK` 0x00800000: Plik jest firmlinkiem.
- `SF_DATALESS` 0x40000000: Plik jest obiektem bez danych.

### **ACL plików**

**ACL** plików zawierają **ACE** (Access Control Entries), które umożliwiają przypisywanie **bardziej szczegółowych uprawnień** różnym użytkownikom.

Katalogowi można przyznać następujące uprawnienia: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Plikowi można przyznać: `read`, `write`, `append` i `execute`.

Jeśli plik zawiera ACL, podczas wyświetlania uprawnień zobaczysz **znak „+”, jak w przykładzie**:

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

Za pomocą poniższego polecenia możesz znaleźć **wszystkie pliki z ACL** (działa ono bardzo wolno):

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

### Atrybuty rozszerzone

Atrybuty rozszerzone to nazwane wartości metadanych przechowywane oddzielnie od zwykłych atrybutów pliku. Wyświetl je za pomocą `ls -l@`, a następnie sprawdź lub zmodyfikuj za pomocą `xattr`. <sup>[[5]](#references)</sup> Oto niektóre często spotykane atrybuty rozszerzone:

- `com.apple.resourceFork`: Zgodność z forkami zasobów. Widoczny również jako `filename/..namedfork/rsrc`
- `com.apple.quarantine`: Metadane kwarantanny macOS Gatekeeper
- `metadata:*`: Metadane macOS, takie jak `_backup_excludeItem` lub `kMD*`
- `com.apple.lastuseddate` (#PS): Data ostatniego użycia pliku
- `com.apple.FinderInfo`: Informacje macOS Finder, takie jak kolorowe etykiety
- `com.apple.TextEncoding`: Określa kodowanie tekstu plików tekstowych ASCII
- `com.apple.logd.metadata`: Używany przez logd w przypadku plików w `/var/db/diagnostics`
- `com.apple.genstore.*`: Pamięć generacyjna (`/.DocumentRevisions-V100` w katalogu głównym systemu plików)
- `com.apple.rootless`: Metadane macOS powiązane z System Integrity Protection
- `com.apple.uuidb.boot-uuid`: Oznaczenia logd epok rozruchu przy użyciu unikatowego UUID
- `com.apple.decmpfs`: Metadane przezroczystej kompresji plików macOS
- `com.apple.cprotect`: \*OS: Dane szyfrowania poszczególnych plików (III/11)
- `com.apple.installd.*`: \*OS: Metadane używane przez installd, np. `installType`, `uniqueInstallID`

### Forki zasobów | macOS ADS

Forki zasobów udostępniają alternatywny strumień danych w macOS. Zawartość można przechowywać w atrybucie rozszerzonym `com.apple.ResourceFork` i uzyskiwać do niej dostęp za pośrednictwem `file/..namedfork/rsrc`.

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

Atrybut rozszerzony `com.apple.decmpfs` przechowuje metadane dotyczące przezroczystej kompresji; nie oznacza szyfrowania. W zależności od formatu kompresji skompresowane dane mogą być przechowywane w atrybucie lub w fork zasobów i są przezroczysto dekompresowane podczas odczytu.

Flaga `UF_COMPRESSED` jest wyświetlana jako `compressed` w `ls -lO`. Nie usuwaj jej ręcznie: może to spowodować, że system nieprawidłowo zinterpretuje skompresowaną reprezentację.

Polecenie usuwające tę flagę pokazano poniżej, ponieważ jest przydatne podczas analizy kryminalistycznej. Uruchomienie go na skompresowanym pliku może jednak sprawić, że plik będzie wyglądał na pusty lub stanie się niedostępny, dopóki jego metadane nie zostaną naprawione:

```bash
chflags nocompressed /path/to/file
```

Wbudowane narzędzie `/usr/bin/afscexpand` może wymusić rozpakowanie plików skompresowanych w sposób przezroczysty. Oddzielne narzędzie innej firmy `afsctool` może również sprawdzać lub dekompresować pliki skompresowane przez system plików Apple, ale nie należy go mylić z wbudowanym poleceniem. <sup>[[8]](#references)</sup>


### Interesujące lokalizacje konfiguracji (macOS)

| Ścieżka / lokalizacja | Przeznaczenie / co konfiguruje | Zabezpieczenia / potencjał ataku |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Przechowuje pliki plist z flagami funkcji Apple, które kontrolują opcjonalne lub eksperymentalne działanie demonów systemowych / frameworków | Jeśli atakujący może ominąć SIP lub uzyskać uprawnienia, modyfikacja tych plików może włączyć ukryte ścieżki kodu lub wyłączyć zabezpieczenia |
| `/System/Library/CoreServices/systemVersion.plist` | Zawiera metadane wersji macOS (ProductVersion, BuildVersion) używane przez aplikacje / instalatory do warunkowania działania | Modyfikacja może skłonić aplikacje lub instalatory do zaakceptowania nieobsługiwanych wersji systemu operacyjnego lub odblokowania funkcji |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Preferencje aplikacji / całego systemu | Jeśli są zapisywalne, atakujący mogą wstrzyknąć ustawienia, aby zmienić działanie aplikacji, wyłączyć zabezpieczenia lub spowodować błędną konfigurację |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Definicje plist dla demonów i agentów działających w tle | Dodanie lub modyfikacja złośliwego pliku plist (jeśli pozwalają na to uprawnienia) umożliwia utrzymanie dostępu lub eskalację uprawnień |
| `/etc/hosts` | Mapowania nazwa hosta ↔ IP używane przez systemowy resolver DNS | Przekierowywanie nazw domen, przechwytywanie ruchu, podszywanie się pod usługi w zakresie lokalnej kontroli |
| `/etc/sudoers` | Określa, kto może uruchamiać polecenia za pomocą `sudo` i na jakich warunkach | Uszkodzony plik sudoers może nadać konto atakującego uprawnienia root lub niewłaściwe uprawnienia |
| `/private/var/db/dslocal/nodes/Default/users/` | Pliki plist z definicjami lokalnych kont użytkowników | Modyfikacja umożliwia tworzenie lub zmianę kont użytkowników, hashy haseł lub metadanych użytkownika |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Rozszerzenia jądra / sterowniki | Instalacja lub modyfikacja kextów może zapewnić kontrolę na poziomie jądra; katalogi te są silnie chronione przez SIP / zasady podpisywania |
| `/private/var/db/SystemPolicyConfiguration/` | Przechowuje konfigurację wymuszania zasad systemowych (np. Gatekeeper, notaryzacja) | Modyfikacja tych plików może umożliwić obejście kontroli zasad lub reguł zaufania |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Pliki binarne pomocnicze SSH i pliki konfiguracyjne | Błędna konfiguracja prowadzi do słabych zabezpieczeń SSH, nieautoryzowanego dostępu lub użycia niebezpiecznych algorytmów |
| `/System/Library/Sandbox/Profiles` | Profile sandboxa systemowego (SBPL) używane do ograniczania działań procesów | Zastąpienie lub zmiana profili może otworzyć wektory ucieczki z sandboxa lub osłabić izolację |

> **Uwaga**: Wiele z tych ścieżek znajduje się w katalogach chronionych przez SIP (np. `/System`), które są zabezpieczone przed zapisem, chyba że SIP zostanie wyłączony lub ominięty.  


## Binarne uniwersalne i format Mach-O

Mach-O to natywny format plików wykonywalnych w macOS. Binarne uniwersalne, czyli fat binary, zawiera wiele wycinków Mach-O przeznaczonych dla poszczególnych architektur w jednym pliku; dedykowana strona objaśnia oba formaty:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Zrzuty pamięci macOS

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Ryzyko plików i metadane obsługi

LaunchServices, kwarantanna plików i Gatekeeper łącznie wpływają na sposób obsługi pobranych plików przez macOS oraz wybór aplikacji dla rozszerzeń i schematów URL. Ich bazy danych i wewnętrzne pliki zasobów zmieniają się między wydaniami; korzystaj z dedykowanych stron zamiast traktować prywatną ścieżkę CoreTypes jako stabilny interfejs zasad:

W wydaniach, w których starsze metadane ryzyka CoreTypes są dostępne pod ścieżką `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, najczęściej spotykane kategorie to:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: zawartość uznawana za wystarczająco bezpieczną do automatycznego otwierania zgodnie z obowiązującymi zasadami aplikacji.
- **`LSRiskCategoryNeutral`**: zawartość, która zwykle nie powoduje wyświetlenia ostrzeżenia ani nie jest otwierana automatycznie.
- **`LSRiskCategoryUnsafeExecutable`**: zawartość wykonywalna, w przypadku której użytkownik powinien otrzymać ostrzeżenie aplikacji.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: kontenery, takie jak archiwa, które mogą zawierać wykonywalną zawartość i wymagają dalszej inspekcji.

Są to szczegóły implementacyjne, a nie stabilne publiczne API zasad; zweryfikuj rzeczywiste metadane oraz działanie Safari/Gatekeeper w testowanej wersji macOS.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Pliki dziennika

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Zawiera informacje o pobranych plikach, takie jak adres URL, z którego zostały pobrane.
- **Dziennik zunifikowany**: W aktualnych wersjach macOS można wyszukiwać zdarzenia systemowe i aplikacji za pomocą poleceń `log show` i `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** i **`/private/var/log/asl/*.asl`**: Starsze artefakty dzienników, które mogą nadal mieć znaczenie w starszych systemach. W tych wydaniach `/System/Library/LaunchDaemons/com.apple.syslogd.plist` konfiguruje `syslogd`; polecenie `launchctl list | grep com.apple.syslogd` może pomóc ustalić, czy usługa jest załadowana.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Przechowuje listę ostatnio otwieranych plików i aplikacji za pośrednictwem „Findera”.
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Starsza ścieżka preferencji powiązana z elementami logowania; współczesne wersje macOS korzystają z dodatkowych mechanizmów.
- **`$HOME/Library/Logs/DiskUtility.log`**: Starszy dziennik Narzędzia dyskowego, który może zawierać informacje o dyskach, w tym urządzeniach USB.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dane dotyczące bezprzewodowych punktów dostępu.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Starsze dane o nadpisaniach launchd.



## References

- [1] [Apple - Przewodnik programowania systemu plików](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Przewodnik programowania pakietów](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Forum deweloperów Apple - Przegląd współdzielonego cache dyld](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Przewodnik programowania systemu plików: zabezpieczenia systemu plików macOS](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - strona podręcznika macOS](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - strona podręcznika macOS](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - strona podręcznika macOS](https://manp.gs/mac/1/afscexpand)
- [9] [Forum deweloperów Apple - Rozpakowywanie archiwów Apple](https://developer.apple.com/forums/thread/133985)
- [10] [Apple dyld - DyldProcessConfig.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [11] [Apple - Zabezpieczenia skryptów powłoki: specjalne flagi uprawnień plików](https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html)
- [12] [Apple - Zadania związane z podpisywaniem kodu: pakiety instalatora](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
{{#include ../../../banners/hacktricks-training.md}}
