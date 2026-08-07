# Файли, папки, бінарні файли та пам'ять macOS

{{#include ../../../banners/hacktricks-training.md}}

## Ієрархія файлової системи

- **/Applications**: Тут мають розташовуватися встановлені застосунки. Усі користувачі матимуть до них доступ.
- **/bin**: Бінарні файли командного рядка
- **/cores**: Якщо існує, використовується для зберігання core dumps
- **/dev**: Усе розглядається як файл, тому тут можна побачити збережені апаратні пристрої.
- **/etc**: Файли конфігурації
- **/Library**: Тут можна знайти багато підкаталогів і файлів, пов'язаних із налаштуваннями, кешами та журналами. Папка Library існує в кореневому каталозі та в каталозі кожного користувача.
- **/private**: Недокументований каталог, але багато згаданих папок є символічними посиланнями на каталог private.
- **/sbin**: Основні системні бінарні файли (пов'язані з адмініструванням)
- **/System**: Файли, необхідні для роботи OS X. Тут переважно мають знаходитися лише специфічні файли Apple (не third-party).
- **/tmp**: Файли видаляються через 3 дні (це soft link на /private/tmp)
- **/Users**: Домашній каталог користувачів.
- **/usr**: Конфігураційні та системні бінарні файли
- **/var**: Файли журналів
- **/Volumes**: Тут з'являються підключені диски.
- **/.vol**: Виконавши `stat a.txt`, ви отримаєте щось на кшталт `16777223 7545753 -rw-r--r-- 1 username wheel ...`, де перше число є ідентифікатором тому, на якому розташований файл, а друге — номером inode. Отримати доступ до вмісту цього файлу можна через /.vol/, використовуючи ці дані та виконавши `cat /.vol/16777223/7545753`

### Папки Applications

- **Системні застосунки** розташовані в `/System/Applications`
- **Встановлені** застосунки зазвичай встановлюються в `/Applications` або в `~/Applications`
- **Дані застосунків** можна знайти в `/Library/Application Support` для застосунків, що працюють від root, і в `~/Library/Application Support` для застосунків, що працюють від імені користувача.
- **Daemons** third-party застосунків, яким **потрібно працювати від root**, зазвичай розташовані в `/Library/PrivilegedHelperTools/`
- **Sandboxed** застосунки відображаються в папці `~/Library/Containers`. Кожен застосунок має папку, названу відповідно до bundle ID застосунку (`com.apple.Safari`).
- **Kernel** розташований у `/System/Library/Kernels/kernel`
- **Kernel extensions** Apple розташовані в `/System/Library/Extensions`
- **Kernel extensions** third-party зберігаються в `/Library/Extensions`

### Файли з конфіденційною інформацією

MacOS зберігає таку інформацію, як паролі, у кількох місцях:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Вразливі pkg installers


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Специфічні розширення OS X

- **`.dmg`**: Файли Apple Disk Image дуже часто використовуються для installers.
- **`.kext`**: Повинні відповідати певній структурі та є версією driver для OS X (це bundle).
- **`.plist`**: Також відомий як property list, зберігає інформацію у форматі XML або binary.
- Може бути XML або binary. Binary-файли можна прочитати за допомогою:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Застосунки Apple, що відповідають структурі каталогів (це bundle).
- **`.dylib`**: Dynamic libraries (як файли DLL у Windows)
- **`.pkg`**: Те саме, що й xar (eXtensible Archive format). Команду installer можна використовувати для встановлення вмісту цих файлів.
- **`.DS_Store`**: Цей файл знаходиться в кожному каталозі та зберігає атрибути й налаштування каталогу.
- **`.Spotlight-V100`**: Ця папка з'являється в кореневому каталозі кожного тому в системі.
- **`.metadata_never_index`**: Якщо цей файл знаходиться в корені тому, Spotlight не індексуватиме цей том.
- **`.noindex`**: Файли та папки з цим розширенням не індексуватимуться Spotlight.
- **`.sdef`**: Файли всередині bundles, що визначають спосіб взаємодії із застосунком через AppleScript.

### Bundles macOS

Bundle — це **каталог**, який **виглядає як об'єкт у Finder** (приклад Bundle — файли `*.app`).


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

У macOS (та iOS) усі системні shared libraries, такі як frameworks і dylibs, **об'єднані в один файл**, який називається **dyld shared cache**. Це підвищило продуктивність, оскільки код можна завантажувати швидше.

У macOS він розташований у `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`, а в старіших версіях **shared cache** можна було знайти в **`/System/Library/dyld/`**.\
В iOS їх можна знайти в **`/System/Library/Caches/com.apple.dyld/`**.

Подібно до dyld shared cache, kernel і kernel extensions також скомпільовані в kernel cache, який завантажується під час boot.

Щоб витягнути libraries з єдиного файлу dylib shared cache, можна було використовувати binary [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip), який, можливо, більше не працює, але також можна використовувати [**dyldextractor**](https://github.com/arandomdev/dyldextractor):
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Зверніть увагу, що навіть якщо інструмент `dyld_shared_cache_util` не працює, ви можете передати **спільний dyld binary до Hopper**, і Hopper зможе ідентифікувати всі бібліотеки та дозволить вам **вибрати, яку саме** досліджувати:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Деякі extractors не працюватимуть, оскільки dylibs попередньо пов’язані з жорстко заданими адресами, тому вони можуть переходити до невідомих адрес.

> [!TIP]
> Також можна завантажити Shared Library Cache інших пристроїв \*OS у macOS, використовуючи емулятор у Xcode. Вони будуть завантажені в: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, наприклад:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** використовує syscall **`shared_region_check_np`**, щоб дізнатися, чи було змонтовано SLC (цей syscall повертає адресу), і **`shared_region_map_and_slide_np`**, щоб змонтувати SLC.

Зверніть увагу, що навіть якщо під час першого використання для SLC застосовується slide, усі **процеси** використовують **ту саму копію**, що **усувало захист ASLR**, якщо attacker міг запускати процеси в системі. Насправді це було використано в минулому, після чого проблему виправили за допомогою shared region pager.

Branch pools — це невеликі Mach-O dylibs, які створюють малі проміжки між відображеннями image, унеможливлюючи interpose функцій.

### Override SLCs

За допомогою env variables:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Це дозволить завантажити новий shared library cache
- **`DYLD_SHARED_CACHE_DIR=avoid`** і вручну замінити бібліотеки на symlinks до shared cache зі справжніми бібліотеками (вам потрібно буде їх extract)

## Special File Permissions

### Folder permissions

У **folder** **read** дозволяє **перелічувати його вміст**, **write** дозволяє **видаляти** та **записувати** в нього файли, а **execute** дозволяє **проходити** через directory. Наприклад, користувач із **read permission для file** всередині directory, де він **не має execute** permission, **не зможе прочитати** цей file.

### Flag modifiers

Існують flags, які можна встановити для files і які змінять їхню поведінку. Ви можете **перевірити flags** files всередині directory за допомогою `ls -lO /path/directory`

- **`uchg`**: Відомий як flag **uchange**, він **запобігає будь-яким діям**, що змінюють або видаляють **file**. Щоб встановити його, виконайте: `chflags uchg file.txt`
- Користувач root може **видалити flag** і змінити file
- **`restricted`**: Цей flag робить file **захищеним SIP** (ви не можете додати цей flag до file).
- **`Sticky bit`**: Якщо directory має sticky bit, **лише власник directory або root може перейменовувати чи видаляти** files. Зазвичай його встановлено для directory /tmp, щоб звичайні користувачі не могли видаляти або переміщати files інших користувачів.

Усі flags можна знайти у file `sys/stat.h` (знайдіть його за допомогою `mdfind stat.h | grep stat.h`):

- `UF_SETTABLE` 0x0000ffff: Mask flags, які може змінювати owner.
- `UF_NODUMP` 0x00000001: Не створювати dump file.
- `UF_IMMUTABLE` 0x00000002: File не можна змінювати.
- `UF_APPEND` 0x00000004: До file можна лише додавати дані.
- `UF_OPAQUE` 0x00000008: Directory є opaque щодо union.
- `UF_COMPRESSED` 0x00000020: File стиснуто (деякі file-systems).
- `UF_TRACKED` 0x00000040: Для files із цим flag немає notifications про delete/rename.
- `UF_DATAVAULT` 0x00000080: Для читання та запису потрібен entitlement.
- `UF_HIDDEN` 0x00008000: Підказка, що цей item не слід відображати в GUI.
- `SF_SUPPORTED` 0x009f0000: Mask flags, які підтримує superuser.
- `SF_SETTABLE` 0x3fff0000: Mask flags, які може змінювати superuser.
- `SF_SYNTHETIC` 0xc0000000: Mask системних read-only synthetic flags.
- `SF_ARCHIVED` 0x00010000: File заархівовано.
- `SF_IMMUTABLE` 0x00020000: File не можна змінювати.
- `SF_APPEND` 0x00040000: До file можна лише додавати дані.
- `SF_RESTRICTED` 0x00080000: Для запису потрібен entitlement.
- `SF_NOUNLINK` 0x00100000: Item не можна видалити, перейменувати або змонтувати на ньому.
- `SF_FIRMLINK` 0x00800000: File є firmlink.
- `SF_DATALESS` 0x40000000: File є dataless object.

### **File ACLs**

File **ACLs** містять **ACE** (Access Control Entries), за допомогою яких різним користувачам можна призначати більш **деталізовані permissions**.

Для **directory** можна надати такі permissions: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
А для **file**: `read`, `write`, `append`, `execute`.

Коли file містить ACLs, під час перегляду permissions ви **побачите "+"**, як у:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Ви можете **прочитати ACL** файлу за допомогою:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Усі **файли з ACLs** можна знайти за допомогою (це дуууже повільно):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Розширені атрибути

Розширені атрибути мають ім'я та довільне значення; їх можна переглядати за допомогою `ls -@` і змінювати за допомогою команди `xattr`. Деякі поширені розширені атрибути:

- `com.apple.resourceFork`: сумісність із resource fork. Також доступний як `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS: механізм карантину Gatekeeper (III/6)
- `metadata:*`: MacOS: різноманітні метадані, наприклад `_backup_excludeItem` або `kMD*`
- `com.apple.lastuseddate` (#PS): дата останнього використання файлу
- `com.apple.FinderInfo`: MacOS: інформація Finder (наприклад, кольорові Tags)
- `com.apple.TextEncoding`: визначає кодування тексту ASCII-файлів
- `com.apple.logd.metadata`: використовується logd для файлів у `/var/db/diagnostics`
- `com.apple.genstore.*`: generational storage (`/.DocumentRevisions-V100` у корені файлової системи)
- `com.apple.rootless`: MacOS: використовується System Integrity Protection для маркування файлу (III/10)
- `com.apple.uuidb.boot-uuid`: позначення logd для епох завантаження з унікальним UUID
- `com.apple.decmpfs`: MacOS: прозоре стиснення файлів (II/7)
- `com.apple.cprotect`: \*OS: дані шифрування окремих файлів (III/11)
- `com.apple.installd.*`: \*OS: метадані, які використовує installd, наприклад `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Це спосіб отримання **Alternate Data Streams на машинах MacOS**. Вміст можна зберегти всередині розширеного атрибута **com.apple.ResourceFork** у файлі, зберігши його в **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Ви можете **знайти всі файли, що містять цей розширений атрибут**, за допомогою:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Розширений атрибут `com.apple.decmpfs` вказує, що файл зберігається в зашифрованому вигляді; `ls -l` повідомить про **розмір 0**, а стиснені дані містяться всередині цього атрибута. Щоразу під час доступу до файлу його буде розшифровано в пам’яті.

Цей атрибут можна побачити за допомогою `ls -lO`, де він позначається як стиснений, оскільки стиснені файли також мають прапорець `UF_COMPRESSED`. Якщо для стисненого файлу видалити цей прапорець за допомогою `chflags nocompressed </path/to/file>`, система не знатиме, що файл було стиснено, і тому не зможе розпакувати його та отримати доступ до даних (вона вважатиме, що файл насправді порожній).

Інструмент afscexpand можна використовувати для примусового розпакування файлу.


### Цікаві розташування конфігурації (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Зберігає plist-файли feature flags Apple, які керують необов’язковою або експериментальною поведінкою системних daemon / framework | Якщо attacker може обійти SIP або отримати привілеї, зміна цих файлів може активувати приховані code paths або вимкнути safeguards |
| `/System/Library/CoreServices/systemVersion.plist` | Містить метадані версії macOS (ProductVersion, BuildVersion), які використовуються apps / installers для обмеження поведінки | Зміна може змусити apps або installers прийняти непідтримувані версії ОС або розблокувати features |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Налаштування applications / system-wide | Якщо доступні для запису, attackers можуть інжектувати settings, щоб спрямувати поведінку app, вимкнути protections або спричинити misconfiguration |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Визначення plist для фонових daemons і agents | Вставлення або зміна malicious plist (якщо permissions це дозволяють) забезпечує persistence або privilege escalations |
| `/etc/hosts` | Відповідності hostname ↔ IP, які використовуються системним DNS resolver | Перенаправлення domain names, перехоплення traffic, spoofing services під локальним контролем |
| `/etc/sudoers` | Визначає, хто може виконувати commands за допомогою `sudo` і за яких умов | Пошкоджений sudoers-файл може надати root або неналежні privileges attacker accounts |
| `/private/var/db/dslocal/nodes/Default/users/` | Plist-файли визначень локальних user accounts | Зміна дозволяє створювати або змінювати user accounts, password hashes або user metadata |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | Встановлення або зміна kexts може призвести до kernel-level control; вони значною мірою захищені SIP / signature policies |
| `/private/var/db/SystemPolicyConfiguration/` | Зберігає конфігурацію для enforcement системних policies (наприклад, Gatekeeper, notarization) | Зміна цих файлів може дозволити обхід policy checks або trust rules |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binaries і configuration files | Misconfiguration призводить до слабкої SSH security, unauthorized access або insecure algorithms |
| `/System/Library/Sandbox/Profiles` | Системні sandbox profiles (SBPL), які використовуються для обмеження дій process | Заміна або зміна profiles може відкрити sandbox escape vectors або послабити containment |

> **Примітка**: Багато з цих paths розташовані в directories, захищених SIP (наприклад, `/System`), і захищені від запису, якщо SIP не вимкнено або не обійдено.


## **Universal binaries &** Mach-o Format

Бінарні файли Mac OS зазвичай компілюються як **universal binaries**. **Universal binary** може **підтримувати кілька architectures в одному файлі**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risk Category Files Mac OS

Directory `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` — це місце, де зберігається інформація про **risk, пов’язаний із різними file extensions**. Ця directory класифікує files за різними risk levels, впливаючи на те, як Safari обробляє ці files після download. Категорії такі:

- **LSRiskCategorySafe**: Files у цій категорії вважаються **повністю безпечними**. Safari автоматично відкриє ці files після їх download.
- **LSRiskCategoryNeutral**: Ці files не супроводжуються warnings і **не відкриваються Safari автоматично**.
- **LSRiskCategoryUnsafeExecutable**: Files у цій категорії **викликають warning**, який вказує, що file є application. Це security measure для попередження user.
- **LSRiskCategoryMayContainUnsafeExecutable**: Ця категорія призначена для files, наприклад archives, які можуть містити executable. Safari **викличе warning**, якщо не зможе перевірити, що весь вміст є safe або neutral.

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Містить інформацію про downloaded files, наприклад URL, з якого їх було downloaded.
- **`/var/log/system.log`**: Основний log систем OSX. com.apple.syslogd.plist відповідає за виконання syslogging (можна перевірити, чи його disabled, виконавши пошук "com.apple.syslogd" у `launchctl list`.
- **`/private/var/log/asl/*.asl`**: Це Apple System Logs, які можуть містити цікаву information.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Зберігає нещодавно accessed files і applications через "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Зберігає items, які запускаються під час system startup
- **`$HOME/Library/Logs/DiskUtility.log`**: Log file для App DiskUtility (information про drives, включно з USBs)
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Data про wireless access points.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: List deactivated daemons.

{{#include ../../../banners/hacktricks-training.md}}
