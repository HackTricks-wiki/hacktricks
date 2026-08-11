# Файли, папки, бінарні файли та пам'ять macOS

{{#include ../../../banners/hacktricks-training.md}}

## Ієрархічна структура файлової системи

Apple описує файлову систему macOS як ієрархію системних, локальних, мережевих і користувацьких доменів. Точний вміст залежить від версії ОС, а системні розташування дедалі частіше захищаються або синтезуються. <sup>[[1]](#references)</sup>

- **/Applications**: Тут мають знаходитися встановлені застосунки. Усі користувачі матимуть до них доступ.
- **/bin**: Бінарні файли командного рядка
- **/cores**: Якщо існує, використовується для зберігання core dumps
- **/dev**: Усе розглядається як файл, тому тут можна побачити апаратні пристрої.
- **/etc**: Файли конфігурації
- **/Library**: Тут можна знайти багато підкаталогів і файлів, пов'язаних із налаштуваннями, кешами та журналами. Папка Library існує в кореневому каталозі та в каталозі кожного користувача.
- **/private**: Недокументований каталог, але багато згаданих папок є символічними посиланнями на каталог private.
- **/sbin**: Основні системні бінарні файли (пов'язані з адмініструванням)
- **/System**: Файли, необхідні macOS; це дерево переважно містить компоненти, надані Apple.
- **/tmp**: Тимчасові файли (символічне посилання на `/private/tmp`). У старих інсталяціях зазвичай періодично видалялися старі тимчасові файли, іноді із зазначеним інтервалом у три дні, але в сучасних системах час очищення залежить від системи та політик; не покладайтеся на збереження даних у цьому каталозі.
- **/Users**: Домашній каталог користувачів.
- **/usr**: Конфігураційні та системні бінарні файли
- **/var**: Файли журналів
- **/Volumes**: Тут відображаються змонтовані томи.
- **/.vol**: Виконавши `stat a.txt`, ви отримаєте щось на кшталт `16777223 7545753 -rw-r--r-- 1 username wheel ...`, де перше число є ідентифікатором тому, у якому знаходиться файл, а друге — номером inode. Отримати вміст цього файлу можна через /.vol/, використовуючи ці дані та виконавши `cat /.vol/16777223/7545753`

### Папки застосунків

- **Системні застосунки** розташовані в `/System/Applications`
- **Встановлені** застосунки зазвичай встановлюються в `/Applications` або в `~/Applications`
- **Дані застосунків** можна знайти в `/Library/Application Support` для застосунків, що працюють від root, і в `~/Library/Application Support` для застосунків, що працюють від імені користувача.
- Сторонні **daemons** застосунків, яким **потрібно працювати від root**, зазвичай розташовані в `/Library/PrivilegedHelperTools/`.
- **Sandboxed** застосунки відображаються в папці `~/Library/Containers`. Кожен застосунок має папку, названу відповідно до bundle ID застосунку (`com.apple.Safari`).
- **Kernel** розташований у `/System/Library/Kernels/kernel`
- **Kernel extensions** Apple розташовані в `/System/Library/Extensions`
- **Kernel extensions** сторонніх розробників зберігаються в `/Library/Extensions`

### Файли з конфіденційною інформацією

macOS зберігає конфіденційну інформацію, зокрема облікові дані, у кількох місцях:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Вразливі pkg installers


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Специфічні розширення OS X

- **`.dmg`**: Файли Apple Disk Image дуже часто використовуються для installers.
- **`.kext`**: Має відповідати певній структурі та є версією driver для OS X (це bundle).
- **`.plist`**: Property list зберігає структуровану інформацію у форматі XML або binary.
- Може бути XML або binary. Binary-файли можна прочитати за допомогою:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plist`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Application bundle, що відповідає стандартній структурі каталогів macOS.
- **`.dylib`**: Dynamic libraries (аналог файлів DLL у Windows)
- **`.pkg`**: Те саме, що й xar (формат eXtensible Archive). Команду installer можна використовувати для встановлення вмісту цих файлів.
- **`.DS_Store`**: Цей файл знаходиться в кожному каталозі та зберігає атрибути й налаштування каталогу.
- **`.Spotlight-V100`**: Ця папка з'являється в кореневому каталозі кожного тому в системі.
- **`.metadata_never_index`**: Якщо цей файл знаходиться в корені тому, Spotlight не індексуватиме цей том.
- **`.noindex`**: Файли та папки з цим розширенням не індексуватимуться Spotlight.
- **`.sdef`**: Файл визначення scripting, який описує, як AppleScript може взаємодіяти із застосунком.

### Bundles macOS

Bundle — це каталог зі стандартизованою ієрархією, який Finder може представляти як один об'єкт; application bundles використовують розширення `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

У macOS та iOS загальновживані системні libraries і frameworks попередньо компонуються в **dyld shared cache**, що покращує швидкість запуску застосунків. Хоча він розглядається як один логічний кеш, у сучасних версіях він може зберігатися як основний cache із кількома файлами subcache, а не буквально як один файл. Його формат і розташування є деталями реалізації, що змінюються між версіями ОС. <sup>[[3]](#references)</sup>

У macOS він розташований у `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`, а в старіших версіях **shared cache** можна було знайти в **`/System/Library/dyld/`**.\
В iOS їх можна знайти в **`/System/Library/Caches/com.apple.dyld/`**.

Подібно до dyld shared cache, kernel і kernel extensions також компілюються в kernel cache, який завантажується під час boot.

У старіших версіях cache можна було видобути за допомогою [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Ця збірка може не підтримувати сучасні формати cache; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) є ще одним варіантом:
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Зверніть увагу: навіть якщо інструмент `dyld_shared_cache_util` не працює, ви можете передати **shared dyld binary до Hopper**, і Hopper зможе ідентифікувати всі бібліотеки та дозволить вам **вибрати, яку саме** досліджувати:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Деякі extractors не працюватимуть, оскільки dylibs попередньо пов'язані з жорстко заданими адресами, через що вони можуть переходити до невідомих адрес.

> [!TIP]
> Також можна завантажити Shared Library Cache інших \*OS-пристроїв у macos, використовуючи emulator в Xcode. Вони будуть завантажені до: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, наприклад:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** використовує syscall **`shared_region_check_np`**, щоб визначити, чи було зіставлено SLC (цей syscall повертає адресу), і **`shared_region_map_and_slide_np`**, щоб зіставити SLC.

Зверніть увагу: навіть якщо під час першого використання для SLC застосовується slide, усі **процеси** використовують **ту саму копію**, що **усуває захист ASLR**, якщо зловмисник зміг запускати процеси в системі. Насправді це вже експлуатувалося в минулому, після чого було виправлено за допомогою shared region pager.

Branch pools — це невеликі Mach-O dylibs, які створюють малі проміжки між image mappings, унеможливлюючи interpose функцій.

### Override SLCs

За допомогою env variables:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Це дозволить завантажити новий shared library cache
- **`DYLD_SHARED_CACHE_DIR=avoid`** і вручну замінити бібліотеки symlinks на shared cache зі справжніми бібліотеками (вам потрібно буде їх extract)

## Special File Permissions

### Folder permissions

Для directory **read** дозволяє переглядати entries, **write** дозволяє створювати або видаляти entries, а **execute** дозволяє виконувати traversal. Отже, користувач, який може прочитати file, але не може виконати traversal батьківського directory, не може отримати доступ до цього file через path. <sup>[[4]](#references)</sup>

### Flag modifiers

Files можуть містити flags, які змінюють їхню поведінку. Переглянути flags у directory можна за допомогою `ls -lO /path/directory`.

- **`uchg`**: Відомий як flag **uchange**, він **запобігає будь-якій дії**, що змінює або видаляє **file**. Щоб встановити його, виконайте: `chflags uchg file.txt`
- Користувач root може **видалити flag** і змінити file
- **`restricted`**: Цей flag робить file **захищеним SIP** (ви не можете додати цей flag до file).
- **`Sticky bit`**: У directory, де встановлено sticky bit, лише власник file, власник directory або root можуть перейменувати чи видалити entry. Зазвичай його увімкнено в `/tmp`, щоб запобігти видаленню або переміщенню користувачами files інших користувачів.

Усі flags можна знайти у file `sys/stat.h` (знайдіть його за допомогою `mdfind stat.h | grep stat.h`):

- `UF_SETTABLE` 0x0000ffff: Маска flags, які може змінювати власник.
- `UF_NODUMP` 0x00000001: Не створювати dump file.
- `UF_IMMUTABLE` 0x00000002: File не можна змінювати.
- `UF_APPEND` 0x00000004: До file можна лише додавати дані.
- `UF_OPAQUE` 0x00000008: Directory є opaque щодо union.
- `UF_COMPRESSED` 0x00000020: File стиснено (у деяких file-systems).
- `UF_TRACKED` 0x00000040: Для files із цим flag немає notifications про видалення або перейменування.
- `UF_DATAVAULT` 0x00000080: Для читання та запису потрібен entitlement.
- `UF_HIDDEN` 0x00008000: Підказка, що цей item не слід відображати в GUI.
- `SF_SUPPORTED` 0x009f0000: Маска flags, які підтримує superuser.
- `SF_SETTABLE` 0x3fff0000: Маска flags, які може змінювати superuser.
- `SF_SYNTHETIC` 0xc0000000: Маска synthetic flags, доступних лише для читання системою.
- `SF_ARCHIVED` 0x00010000: File заархівовано.
- `SF_IMMUTABLE` 0x00020000: File не можна змінювати.
- `SF_APPEND` 0x00040000: До file можна лише додавати дані.
- `SF_RESTRICTED` 0x00080000: Для запису потрібен entitlement.
- `SF_NOUNLINK` 0x00100000: Item не можна видалити, перейменувати або змонтувати на нього.
- `SF_FIRMLINK` 0x00800000: File є firmlink.
- `SF_DATALESS` 0x40000000: File є dataless object.

### **File ACLs**

File **ACLs** містять **ACE** (Access Control Entries), у яких різним користувачам можна призначати **детальніші permissions**.

Для **directory** можна надати такі permissions: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Для **file**: `read`, `write`, `append` і `execute`.

Коли file містить ACLs, під час перегляду permissions ви **побачите "+"**, як у:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Ви можете **прочитати ACLs** файлу за допомогою:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
За допомогою наведеної команди можна знайти **всі файли з ACL** (це дуже повільно):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Розширені атрибути

Розширені атрибути — це іменовані значення метаданих, які зберігаються окремо від звичайних атрибутів файла. Переглянути їх можна за допомогою `ls -l@`, а перевірити або змінити — за допомогою `xattr`. <sup>[[5]](#references)</sup> Деякі поширені розширені атрибути:

- `com.apple.resourceFork`: сумісність із resource fork. Також доступний як `filename/..namedfork/rsrc`
- `com.apple.quarantine`: метадані карантину macOS Gatekeeper
- `metadata:*`: метадані macOS, як-от `_backup_excludeItem` або `kMD*`
- `com.apple.lastuseddate` (#PS): дата останнього використання файла
- `com.apple.FinderInfo`: інформація macOS Finder, як-от кольорові теги
- `com.apple.TextEncoding`: визначає кодування тексту ASCII-файлів
- `com.apple.logd.metadata`: використовується logd для файлів у `/var/db/diagnostics`
- `com.apple.genstore.*`: генераційне сховище (`/.DocumentRevisions-V100` у корені файлової системи)
- `com.apple.rootless`: метадані macOS, пов’язані із System Integrity Protection
- `com.apple.uuidb.boot-uuid`: позначки logd для епох завантаження з унікальним UUID
- `com.apple.decmpfs`: метадані прозорого стиснення файлів macOS
- `com.apple.cprotect`: \*OS: дані шифрування окремого файла (III/11)
- `com.apple.installd.*`: \*OS: метадані, які використовує installd, наприклад `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Resource fork-и надають альтернативний потік даних у macOS. Вміст можна зберігати в розширеному атрибуті `com.apple.ResourceFork` і отримувати через `file/..namedfork/rsrc`.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Ви можете **знайти всі файли, що містять цей розширений атрибут**, за допомогою:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Розширений атрибут `com.apple.decmpfs` зберігає метадані для прозорого стиснення; він не вказує на шифрування. Залежно від формату стиснення, стиснені дані можуть зберігатися в атрибуті або у resource fork і прозоро розпаковуються під час читання.

Прапорець `UF_COMPRESSED` відображається як `compressed` у `ls -lO`. Не очищайте його вручну: це може змусити систему неправильно інтерпретувати стиснене представлення.

Команду, яка очищає цей прапорець, наведено тут, оскільки вона корисна під час forensic review, але її виконання щодо стисненого файлу може призвести до того, що файл відображатиметься як порожній або стане недоступним, доки його метадані не буде відновлено:
```bash
chflags nocompressed /path/to/file
```
Вбудована утиліта `/usr/bin/afscexpand` може примусово розгортати прозоро стиснуті файли. Окрема стороння утиліта `afsctool` також може перевіряти або розпаковувати стиснення файлової системи Apple, але її не слід плутати з вбудованою командою. <sup>[[8]](#references)</sup>


### Цікаві місця конфігурації (macOS)

| Path / Location | Призначення / Що налаштовує | Безпека / Потенціал для атак |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Зберігає plist-файли feature flags Apple, які керують необов'язковою або експериментальною поведінкою системних daemon / framework | Якщо attacker може обійти SIP або отримати привілеї, зміна цих файлів може активувати приховані code paths або вимкнути safeguards |
| `/System/Library/CoreServices/systemVersion.plist` | Містить метадані версії macOS (ProductVersion, BuildVersion), які apps / installers використовують для обмеження поведінки | Зміна може змусити apps або installers прийняти непідтримувану версію ОС або розблокувати функції |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Налаштування програм / системні налаштування | Якщо доступні для запису, attackers можуть впровадити параметри для спрямування поведінки app, вимкнення protections або спричинення misconfiguration |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Визначення plist для background daemons і agents | Вставка або зміна malicious plist (якщо дозволяють permissions) забезпечує persistence або privilege escalations |
| `/etc/hosts` | Відповідності hostname ↔ IP, які використовує системний DNS resolver | Перенаправлення domain names, перехоплення traffic, spoofing services під локальним контролем |
| `/etc/sudoers` | Визначає, хто може виконувати commands із `sudo` і за яких умов | Пошкоджений sudoers file може надати root або неналежні privileges attacker accounts |
| `/private/var/db/dslocal/nodes/Default/users/` | Plist-визначення локальних user accounts | Tampering дає змогу створювати або змінювати user accounts, password hashes або user metadata |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | Встановлення або зміна kexts може призвести до kernel-level control; вони значною мірою захищені SIP / signature policies |
| `/private/var/db/SystemPolicyConfiguration/` | Зберігає конфігурацію для enforcement системних policies (наприклад, Gatekeeper, notarization) | Tampering може дозволити обхід policy checks або trust rules |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Допоміжні SSH binaries і config files | Misconfiguration призводить до слабкої SSH security, unauthorized access або небезпечних algorithms |
| `/System/Library/Sandbox/Profiles` | Системні sandbox profiles (SBPL), які використовуються для обмеження дій process | Заміна або зміна profiles може відкрити vectors для sandbox escape або послабити containment |

> **Примітка**: Багато з цих paths розташовані в SIP-protected directories (наприклад, `/System`) і захищені від запису, якщо SIP не вимкнено або не обійдено.


## Universal Binaries And Mach-O Format

Mach-O — нативний executable format у macOS. Universal, або fat, binary містить кілька Mach-O slices, специфічних для різних architectures, в одному файлі; на окремій сторінці пояснюються обидва formats:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Дамп пам'яті macOS

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Ризики файлів і метадані обробників

LaunchServices, file quarantine і Gatekeeper разом впливають на те, як macOS обробляє downloaded files і вибирає applications для extensions та URL schemes. Їхні databases і internal resource files змінюються між releases; використовуйте спеціалізовані сторінки замість того, щоб розглядати private CoreTypes path як стабільний policy interface:

У releases, які надають legacy CoreTypes risk metadata за адресою `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, найпоширеніші категорії такі:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: content, який вважається достатньо безпечним для автоматичного відкриття відповідно до policy застосунку.
- **`LSRiskCategoryNeutral`**: content, який зазвичай не викликає warning і не відкривається автоматично.
- **`LSRiskCategoryUnsafeExecutable`**: executable content, для якого user має отримати application warning.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: containers, наприклад archives, які можуть містити executable content і потребують подальшої inspection.

Це implementation details, а не стабільний public policy API; перевіряйте фактичні metadata та поведінку Safari/Gatekeeper у версії macOS, що тестується.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Містить інформацію про downloaded files, зокрема URL, з якого їх було downloaded.
- **Unified log**: У поточних версіях macOS запитуйте system і application events за допомогою `log show` та `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** і **`/private/var/log/asl/*.asl`**: Legacy logging artifacts, які все ще можуть бути актуальними в старих systems. У таких releases `/System/Library/LaunchDaemons/com.apple.syslogd.plist` налаштовує `syslogd`; `launchctl list | grep com.apple.syslogd` може допомогти визначити, чи service loaded.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Зберігає recently accessed files і applications через "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Legacy preference path, пов'язаний із login items; сучасні версії macOS використовують додаткові mechanisms.
- **`$HOME/Library/Logs/DiskUtility.log`**: Legacy Disk Utility log, який може містити інформацію про drives, зокрема USB devices.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Дані про wireless access points.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Legacy launchd override data.

## References

- [1] [Apple - Посібник із програмування файлової системи](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Посібник із програмування Bundle](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Форуми Apple Developer - огляд dyld shared cache](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Посібник із програмування файлової системи: безпека файлової системи macOS](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - сторінка посібника macOS](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - сторінка посібника macOS](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - сторінка посібника macOS](https://manp.gs/mac/1/afscexpand)
{{#include ../../../banners/hacktricks-training.md}}
