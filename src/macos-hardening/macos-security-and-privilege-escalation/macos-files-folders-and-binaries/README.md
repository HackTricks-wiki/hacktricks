# Файли, папки, бінарні файли та пам’ять macOS

{{#include ../../../banners/hacktricks-training.md}}

## Ієрархія файлової системи

Apple описує файлову систему macOS як ієрархію системного, локального, мережевого та користувацького доменів. Точний вміст залежить від версії ОС, а системні розташування дедалі частіше захищені або синтезуються. <sup>[[1]](#references)</sup>

- **/Applications**: Тут мають бути встановлені програми. Усі користувачі матимуть до них доступ.
- **/bin**: Бінарні файли командного рядка
- **/cores**: Якщо існує, використовується для зберігання дампів ядра
- **/dev**: Усе розглядається як файл, тому тут можна побачити файли пристроїв.
- **/etc**: Файли конфігурації
- **/Library**: Тут можна знайти багато підкаталогів і файлів, пов’язаних із налаштуваннями, кешами та журналами. Папка Library є в корені файлової системи та в домашньому каталозі кожного користувача.
- **/private**: Не документовано, але багато згаданих папок є символічними посиланнями на каталог private.
- **/sbin**: Важливі системні бінарні файли (пов’язані з адмініструванням)
- **/System**: Файли, необхідні macOS; це дерево переважно містить компоненти Apple.
- **/tmp**: Тимчасові файли (символічне посилання на `/private/tmp`). Історично старі тимчасові файли зазвичай періодично очищалися, іноді вказували інтервал у три дні, але зараз час очищення залежить від системи й політик; не покладайтеся на те, що дані там збережуться.
- **/Users**: Домашні каталоги користувачів.
- **/usr**: Файли конфігурації та системні бінарні файли
- **/var**: Файли журналів
- **/Volumes**: Тут з’являються підключені томи.
- **/.vol**: Виконавши `stat a.txt`, ви отримаєте щось на кшталт `16777223 7545753 -rw-r--r-- 1 username wheel ...`, де перше число — ідентифікатор тому, на якому міститься файл, а друге — номер inode. Отримати вміст цього файлу можна через /.vol, використавши ці дані: `cat /.vol/16777223/7545753`

### Папки програм

- **Системні програми** розташовані в `/System/Applications`
- **Встановлені** програми зазвичай розміщуються в `/Applications` або `~/Applications`
- **Дані програм** можна знайти в `/Library/Application Support` для програм, що запускаються від root, і в `~/Library/Application Support` для програм, що запускаються від імені користувача.
- **Демони** сторонніх програм, яким **потрібно запускатися від root**, зазвичай розташовані в `/Library/PrivilegedHelperTools/`.
- **Ізольовані** програми відображаються в папці `~/Library/Containers`. Кожна програма має папку, названу відповідно до її bundle ID (`com.apple.Safari`).
- **Ядро** розташоване в `/System/Library/Kernels/kernel`
- **Розширення ядра Apple** розташовані в `/System/Library/Extensions`
- **Сторонні розширення ядра** зберігаються в `/Library/Extensions`

### Файли з конфіденційною інформацією

macOS зберігає конфіденційну інформацію, зокрема облікові дані, у кількох місцях:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Вразливі інсталятори pkg


{{#ref}}
macos-installers-abuse.md
{{#endref}}

Щоб дізнатися про відмінності між доступним для запису томом Data і герметичним системним томом, які видно в цій ієрархії, див. [macOS Sealed System Volume & DataVault](../macos-security-protections/macos-sealed-system-volume-and-datavault.md).

## Розширення, специфічні для OS X

- **`.dmg`**: Файли образів дисків Apple часто використовуються для інсталяторів.
- **`.kext`**: Має відповідати певній структурі й є версією драйвера для OS X. (це bundle)
- **`.plist`**: Список властивостей зберігає структуровану інформацію у форматі XML або binary.
  - Може бути у форматі XML або binary. Файли binary можна прочитати за допомогою:
    - `defaults read config.plist`
    - `/usr/libexec/PlistBuddy -c print config.plist`
    - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Пакет програми зі стандартною структурою каталогів macOS.
- **`.dylib`**: Динамічні бібліотеки (як файли DLL у Windows)
- **`.pkg`**: Сучасні плоскі інсталяційні пакети — це архіви XAR, але `.pkg` — формат інсталятора, а не синонім XAR. Старіші пакети інсталяторів у вигляді bundle — це каталоги. Див. [macOS installers](macos-installers-abuse.md), щоб дізнатися про структуру пакетів і їх перевірку. <sup>[[9]](#references)[[12]](#references)</sup>
- **`.DS_Store`**: Цей файл є в кожному каталозі; він зберігає атрибути та налаштування каталогу.
- **`.Spotlight-V100`**: Ця папка є в кореневому каталозі кожного тому системи.
- **`.metadata_never_index`**: Якщо цей файл розташований у кореневому каталозі тому, Spotlight не індексуватиме цей том.
- **`.noindex`**: Файли й папки з таким розширенням не індексуватимуться Spotlight.
- **`.sdef`**: Файл визначення скриптів, який описує, як AppleScript може взаємодіяти з програмою.

### Пакети macOS

Пакет — це каталог зі стандартизованою ієрархією, який Finder може показувати як один об’єкт; пакети програм використовують розширення `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Кеш спільних бібліотек dyld (SLC)

У macOS та iOS часто використовувані системні бібліотеки й фреймворки попередньо компонуються в **кеш спільних бібліотек dyld**, що пришвидшує запуск програм. Хоча його розглядають як один логічний кеш, у поточних версіях він може зберігатися як основний кеш із кількома файлами субкешу, а не буквально як один файл. Його формат і розташування — це деталі реалізації, які змінюються залежно від версії ОС. <sup>[[3]](#references)</sup>

У macOS він розташований у `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`, а в старіших версіях **спільний кеш** можна знайти в **`/System/Library/dyld/`**.\
В iOS його можна знайти в **`/System/Library/Caches/com.apple.dyld/`**.

Подібно до кешу спільних бібліотек dyld, ядро та розширення ядра також компілюються в кеш ядра, який завантажується під час завантаження системи.

У старіших версіях кеш можна було витягти за допомогою [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Ця збірка може не підтримувати сучасні формати кешу; ще один варіант — [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```

> [!TIP]
> Зверніть увагу: навіть якщо інструмент `dyld_shared_cache_util` не працює, можна передати **спільний бінарний файл dyld у Hopper**, і Hopper зможе визначити всі бібліотеки та дозволить **вибрати ту, яку ви хочете дослідити**:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Деякі екстрактори не працюватимуть, оскільки dylib попередньо зв’язані з жорстко закодованими адресами, тому можуть переходити на невідомі адреси.

> [!TIP]
> Також можна завантажити кеш спільних бібліотек інших пристроїв \*OS у macOS за допомогою емулятора в Xcode. Вони завантажуються сюди: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, наприклад:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Зіставлення SLC

**`dyld`** використовує системний виклик **`shared_region_check_np`**, щоб визначити, чи зіставлено SLC (він повертає адресу), і **`shared_region_map_and_slide_np`**, щоб зіставити SLC.

Зверніть увагу: навіть якщо під час першого використання SLC зсувається, усі **процеси** використовують **ту саму копію**, що **усувало захист ASLR**, якщо зловмисник міг запускати процеси в системі. Це справді експлуатували раніше, після чого проблему виправили за допомогою shared region pager.

Branch pools — це невеликі Mach-O dylib, які створюють малі проміжки між зіставленнями образів, унеможливлюючи перехоплення функцій.

### Обмеження середовища shared cache

`DYLD_SHARED_CACHE_DIR` задає каталог кешу, а `DYLD_SHARED_REGION` вибирає режим shared region. Попереднє написання `DYLD_DHARED_REGION` було некоректним, а `avoid` не є допустимим значенням для `DYLD_SHARED_CACHE_DIR`. У поточній версії dyld режим `private` дозволений лише за наявності в AMFI дозволу на використання користувацьких shared cache, тому самі лише змінні середовища не дають змоги встановити, що процес може завантажити кеш на заміну. <sup>[[10]](#references)</sup>

## Спеціальні дозволи файлів

### Дозволи папок

Для каталогу **читання** дає змогу переглядати записи, **запис** — створювати або видаляти записи, а **виконання** — переходити до нього. Тому користувач, який може читати файл, але не може пройти через батьківський каталог, не матиме доступу до цього файлу за шляхом. <sup>[[4]](#references)</sup>

### Модифікатори прапорців

Файли можуть мати прапорці, які змінюють їхню поведінку. Переглянути прапорці в каталозі можна командою `ls -lO /path/directory`.

- **`uchg`**: Прапорець **uchange** **забороняє будь-які дії**, що змінюють або видаляють **файл**. Щоб установити його, виконайте: `chflags uchg file.txt`
  - Власник файла або root може зняти цей **користувацький** прапорець командою `chflags nouchg file.txt`; він не захищає файл від жодного з них. Окремий **системний** незмінний прапорець (`schg`) доступний лише root. <sup>[[11]](#references)</sup>
- **`restricted`**: Цей прапорець захищає файл за допомогою SIP (додати цей прапорець до файла не можна).
- **`Sticky bit`**: У каталозі зі встановленим sticky bit лише власник файла, власник каталогу або root можуть перейменовувати чи видаляти записи. Зазвичай цей біт увімкнено для `/tmp`, щоб користувачі не могли видаляти або переміщувати файли інших користувачів.

Усі прапорці визначені у файлі `sys/stat.h` (знайти його можна командою `mdfind stat.h | grep stat.h`):

- `UF_SETTABLE` 0x0000ffff: Маска прапорців, які може змінювати власник.
- `UF_NODUMP` 0x00000001: Не створювати дамп файла.
- `UF_IMMUTABLE` 0x00000002: Файл не можна змінювати.
- `UF_APPEND` 0x00000004: До файла можна лише дописувати.
- `UF_OPAQUE` 0x00000008: Каталог є непрозорим щодо union.
- `UF_COMPRESSED` 0x00000020: Файл стиснутий (у деяких файлових системах).
- `UF_TRACKED` 0x00000040: Для файлів із цим прапорцем не надсилаються сповіщення про видалення чи перейменування.
- `UF_DATAVAULT` 0x00000080: Для читання й запису потрібен entitlement.
- `UF_HIDDEN` 0x00008000: Підказка про те, що цей елемент не слід показувати в графічному інтерфейсі.
- `SF_SUPPORTED` 0x009f0000: Маска прапорців, підтримуваних суперкористувачем.
- `SF_SETTABLE` 0x3fff0000: Маска прапорців, які може змінювати суперкористувач.
- `SF_SYNTHETIC` 0xc0000000: Маска синтетичних прапорців системи лише для читання.
- `SF_ARCHIVED` 0x00010000: Файл заархівовано.
- `SF_IMMUTABLE` 0x00020000: Файл не можна змінювати.
- `SF_APPEND` 0x00040000: До файла можна лише дописувати.
- `SF_RESTRICTED` 0x00080000: Для запису потрібен entitlement.
- `SF_NOUNLINK` 0x00100000: Елемент не можна видалити, перейменувати або змонтувати на нього.
- `SF_FIRMLINK` 0x00800000: Файл є firmlink.
- `SF_DATALESS` 0x40000000: Файл є об’єктом без даних.

### **ACL файлів**

**ACL** файлів містять **ACE** (записи контролю доступу), за допомогою яких можна призначати різним користувачам **детальніші дозволи**.

Каталогу можна надати такі дозволи: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Для **файла**: `read`, `write`, `append` і `execute`.

Якщо файл містить ACL, у списку дозволів ви **побачите «+», як у прикладі нижче**:

```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```

Ви можете **переглянути ACL** файлу за допомогою:

```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
 0: group:everyone deny delete
```

За допомогою наведеної нижче команди можна знайти **всі файли з ACL** (це дуже повільно):

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

### Розширені атрибути

Розширені атрибути — це іменовані значення метаданих, що зберігаються окремо від звичайних атрибутів файлу. Переглянути їх можна за допомогою `ls -l@`, а перевірити або змінити — за допомогою `xattr`. <sup>[[5]](#references)</sup> Поширені розширені атрибути:

- `com.apple.resourceFork`: сумісність із resource fork. Також доступний як `filename/..namedfork/rsrc`
- `com.apple.quarantine`: метадані карантину macOS Gatekeeper
- `metadata:*`: метадані macOS, наприклад `_backup_excludeItem` або `kMD*`
- `com.apple.lastuseddate` (#PS): дата останнього використання файлу
- `com.apple.FinderInfo`: інформація macOS Finder, наприклад кольорові мітки
- `com.apple.TextEncoding`: визначає кодування текстових файлів ASCII
- `com.apple.logd.metadata`: використовується logd для файлів у `/var/db/diagnostics`
- `com.apple.genstore.*`: сховище версій (`/.DocumentRevisions-V100` у корені файлової системи)
- `com.apple.rootless`: метадані macOS, пов’язані із System Integrity Protection
- `com.apple.uuidb.boot-uuid`: позначки logd для епох завантаження з унікальним UUID
- `com.apple.decmpfs`: метадані прозорого стиснення файлів macOS
- `com.apple.cprotect`: *OS: дані шифрування окремих файлів (III/11)
- `com.apple.installd.*`: *OS: метадані, які використовує installd, наприклад `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Resource forks забезпечують альтернативний потік даних у macOS. Вміст можна зберігати в розширеному атрибуті `com.apple.ResourceFork` і отримувати через `file/..namedfork/rsrc`.

```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```

Можна **знайти всі файли, що містять цей розширений атрибут**, за допомогою:

```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```

### decmpfs

Розширений атрибут `com.apple.decmpfs` зберігає метадані для прозорого стиснення; він не вказує на шифрування. Залежно від формату стиснення, стиснені дані можуть зберігатися в атрибуті або у вилці ресурсів і прозоро розпаковуються під час читання.

Прапорець `UF_COMPRESSED` відображається як `compressed` у `ls -lO`. Не очищайте його вручну: через це система може неправильно інтерпретувати стиснене представлення.

Команду для очищення прапорця наведено тут, оскільки вона може бути корисною під час криміналістичного аналізу, але її виконання щодо стисненого файла може призвести до того, що файл здаватиметься порожнім або стане недоступним, доки його метадані не буде відновлено:

```bash
chflags nocompressed /path/to/file
```

Вбудована утиліта `/usr/bin/afscexpand` може примусово розпаковувати прозоро стиснуті файли. Окрема стороння утиліта `afsctool` також може перевіряти або розпаковувати стиснення файлової системи Apple, але її не слід плутати з вбудованою командою. <sup>[[8]](#references)</sup>


### Цікаві розташування конфігурацій (macOS)

| Шлях / розташування | Призначення / що налаштовує | Потенційний вплив на безпеку / атаки |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Містить plist-файли Apple з прапорцями функцій, які керують додатковою або експериментальною поведінкою системних демонів / фреймворків | Якщо зловмисник може обійти SIP або отримати привілеї, зміна цих файлів може активувати приховані шляхи виконання коду або вимкнути засоби захисту |
| `/System/Library/CoreServices/systemVersion.plist` | Містить метадані версії macOS (ProductVersion, BuildVersion), які програми / інсталятори використовують для вибору поведінки | Зміни можуть змусити програми або інсталятори прийняти непідтримувану версію ОС або розблокувати функції |
| `/Library/Preferences/com.apple.*.plist` і `~/Library/Preferences/*.plist` | Налаштування програм / усієї системи | Якщо файли доступні для запису, зловмисники можуть підставити налаштування, щоб керувати поведінкою програм, вимкнути захист або спричинити неправильну конфігурацію |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Визначення фонових демонів і агентів у plist-файлах | Додавання або зміна шкідливих plist-файлів (якщо дозволяють права доступу) забезпечує закріплення в системі або підвищення привілеїв |
| `/etc/hosts` | Відповідності між іменами вузлів і IP-адресами, які використовує системний DNS-резолвер | Перенаправлення доменних імен, перехоплення трафіку, підміна сервісів під локальним контролем |
| `/etc/sudoers` | Визначає, хто й за яких умов може запускати команди з `sudo` | Пошкоджений файл sudoers може надати root-доступ або неналежні привілеї обліковим записам зловмисників |
| `/private/var/db/dslocal/nodes/Default/users/` | Plist-файли з визначеннями локальних облікових записів користувачів | Зміни дають змогу створювати або змінювати облікові записи, хеші паролів чи метадані користувачів |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Розширення ядра / драйвери | Встановлення або зміна kext-файлів може надати контроль на рівні ядра; SIP і правила підпису забезпечують посилений захист |
| `/private/var/db/SystemPolicyConfiguration/` | Містить конфігурацію застосування системних політик (наприклад, Gatekeeper, нотаризації) | Зміни можуть дозволити обійти перевірки політик або правила довіри |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Допоміжні бінарні файли SSH і конфігураційні файли | Неправильна конфігурація послаблює безпеку SSH, створює ризик несанкціонованого доступу або використання незахищених алгоритмів |
| `/System/Library/Sandbox/Profiles` | Системні профілі sandbox (SBPL), що обмежують дії процесів | Заміна або зміна профілів може створити вектори виходу із sandbox або послабити ізоляцію |

> **Примітка**: Багато з цих шляхів розташовані в каталогах, захищених SIP (наприклад, `/System`), і захищені від запису, якщо SIP не вимкнено або не обійдено.  


## Універсальні бінарні файли та формат Mach-O

Mach-O — це власний формат виконуваних файлів macOS. Універсальний, або fat, бінарний файл містить кілька Mach-O-секцій, кожна з яких призначена для певної архітектури; на окремій сторінці описано обидва формати:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Дамп пам’яті macOS

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Ризики файлів і метадані обробників

LaunchServices, карантин файлів і Gatekeeper разом визначають, як macOS обробляє завантажені файли та вибирає програми для розширень файлів і схем URL. Їхні бази даних і внутрішні файли ресурсів змінюються між випусками; користуйтеся окремими сторінками замість того, щоб вважати приватний шлях CoreTypes стабільним інтерфейсом політик:

У випусках, де застарілі метадані ризику CoreTypes доступні за шляхом `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, найчастіше зустрічаються такі категорії:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: вміст, який вважається достатньо безпечним для автоматичного відкриття відповідно до політики програми.
- **`LSRiskCategoryNeutral`**: вміст, який зазвичай не спричиняє попередження і не відкривається автоматично.
- **`LSRiskCategoryUnsafeExecutable`**: виконуваний вміст, для якого користувачеві має бути показано попередження програми.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: контейнери, наприклад архіви, що можуть містити виконуваний вміст і потребують додаткової перевірки.

Це деталі реалізації, а не стабільний публічний API політик; перевіряйте фактичні метадані та поведінку Safari/Gatekeeper у тестованій версії macOS.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Файли журналів

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Містить інформацію про завантажені файли, зокрема URL-адресу, з якої їх було завантажено.
- **Уніфікований журнал**: У поточних версіях macOS системні події та події програм можна запитувати за допомогою `log show` і `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** і **`/private/var/log/asl/*.asl`**: Застарілі артефакти журналювання, які можуть бути актуальними в старіших системах. У таких випусках файл `/System/Library/LaunchDaemons/com.apple.syslogd.plist` налаштовує `syslogd`; команда `launchctl list | grep com.apple.syslogd` допоможе визначити, чи завантажено службу.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Зберігає дані про нещодавно відкриті файли й програми через "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Застарілий шлях до налаштувань, пов’язаний з елементами входу; у сучасних версіях macOS використовуються й інші механізми.
- **`$HOME/Library/Logs/DiskUtility.log`**: Застарілий журнал Disk Utility, який може містити інформацію про диски, зокрема USB-пристрої.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Дані про точки бездротового доступу.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Застарілі дані перевизначення launchd.



## References

- [1] [Apple — Посібник з програмування файлової системи](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple — Посібник з програмування пакетів](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Форуми Apple Developer — огляд спільного кешу dyld](https://developer.apple.com/forums/thread/692383)
- [4] [Apple — Посібник з програмування файлової системи: безпека файлової системи macOS](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` — довідкова сторінка macOS](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` — довідкова сторінка macOS](https://manp.gs/mac/1/log)
- [7] [Apple Developer — Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` — довідкова сторінка macOS](https://manp.gs/mac/1/afscexpand)
- [9] [Форуми Apple Developer — розпакування архівів Apple](https://developer.apple.com/forums/thread/133985)
- [10] [Apple dyld — DyldProcessConfig.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [11] [Apple — безпека shell-скриптів: спеціальні прапорці дозволів файлів](https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html)
- [12] [Apple — завдання підпису коду: пакети інсталятора](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
{{#include ../../../banners/hacktricks-training.md}}
