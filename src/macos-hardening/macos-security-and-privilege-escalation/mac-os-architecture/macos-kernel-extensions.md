# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Kernel extensions (Kexts) — це **пакети** з розширенням **`.kext`**, які **завантажуються безпосередньо в простір ядра macOS**, надаючи додаткову функціональність основній операційній системі.

### Статус знецінення та DriverKit / Системні розширення
Починаючи з **macOS Catalina (10.15)**, Apple позначила більшість застарілих KPI як *знецінені* і представила **Системні розширення та фреймворки DriverKit**, які працюють у **просторі користувача**. З **macOS Big Sur (11)** операційна система *відмовиться завантажувати* сторонні kext, які залежать від застарілих KPI, якщо машина не завантажена в режимі **Зменшеної безпеки**. На Apple Silicon, для активації kext також потрібно, щоб користувач:

1. Перезавантажився в **Recovery** → *Startup Security Utility*.
2. Вибрав **Зменшену безпеку** та позначив **“Дозволити управління розширеннями ядра від ідентифікованих розробників”**.
3. Перезавантажився та схвалив kext з **Системних налаштувань → Конфіденційність та безпека**.

Драйвери користувача, написані з використанням DriverKit/Системних розширень, значно **зменшують поверхню атаки**, оскільки збої або пошкодження пам'яті обмежені пісочницею, а не простором ядра.

> 📝 З macOS Sequoia (15) Apple повністю видалила кілька застарілих KPI для мережі та USB – єдиним рішенням, що підтримує сумісність у майбутньому для постачальників, є перехід на Системні розширення.

### Вимоги

Очевидно, що це настільки потужно, що **завантажити розширення ядра** є **складним**. Ось **вимоги**, які повинно виконати розширення ядра, щоб бути завантаженим:

- Коли **входите в режим відновлення**, розширення ядра **повинні бути дозволені** для завантаження:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Розширення ядра повинно бути **підписане сертифікатом підпису коду ядра**, який може бути **наданий тільки Apple**. Хто детально перевірить компанію та причини, чому це потрібно.
- Розширення ядра також повинно бути **нотаризоване**, Apple зможе перевірити його на наявність шкідливого ПЗ.
- Потім, **кореневий** користувач є тим, хто може **завантажити розширення ядра**, а файли всередині пакета повинні **належати кореню**.
- Під час процесу завантаження пакет повинен бути підготовлений у **захищеному місці, що не є кореневим**: `/Library/StagedExtensions` (вимагає надання `com.apple.rootless.storage.KernelExtensionManagement`).
- Нарешті, при спробі завантажити його, користувач [**отримає запит на підтвердження**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) і, якщо прийме, комп'ютер повинен бути **перезавантажений** для його завантаження.

### Процес завантаження

У Catalina це виглядало так: Цікаво відзначити, що процес **перевірки** відбувається в **просторі користувача**. Однак тільки програми з наданням **`com.apple.private.security.kext-management`** можуть **запитувати у ядра завантажити розширення**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **починає** процес **перевірки** для завантаження розширення
- Він спілкується з **`kextd`**, використовуючи **Mach service**.
2. **`kextd`** перевірить кілька речей, таких як **підпис**
- Він спілкується з **`syspolicyd`**, щоб **перевірити**, чи може розширення бути **завантаженим**.
3. **`syspolicyd`** **запитає** **користувача**, якщо розширення не було завантажено раніше.
- **`syspolicyd`** повідомить результат **`kextd`**
4. **`kextd`** нарешті зможе **сказати ядру завантажити** розширення

Якщо **`kextd`** недоступний, **`kextutil`** може виконати ті ж перевірки.

### Перерахування та управління (завантажені kexts)

`kextstat` був історичним інструментом, але він є **знеціненим** у останніх випусках macOS. Сучасний інтерфейс — це **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Стара синтаксис все ще доступний для посилання:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` також можна використовувати для **вивантаження вмісту Колекції Ядра (KC)** або перевірки, що kext вирішує всі залежності символів:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Навіть якщо очікується, що розширення ядра будуть у `/System/Library/Extensions/`, якщо ви зайдете в цю папку, ви **не знайдете жодного бінарного файлу**. Це пов'язано з **kernelcache**, і для того, щоб зворотно отримати один `.kext`, вам потрібно знайти спосіб його отримати.

**Kernelcache** - це **попередньо скомпільована та попередньо зв'язана версія ядра XNU**, разом з основними пристроями **драйверами** та **розширеннями ядра**. Він зберігається у **сжатому** форматі і розпаковується в пам'ять під час процесу завантаження. Kernelcache сприяє **швидшому часу завантаження**, маючи готову до запуску версію ядра та важливих драйверів, що зменшує час і ресурси, які інакше витрачалися б на динамічне завантаження та зв'язування цих компонентів під час завантаження.

### Local Kerlnelcache

В iOS він розташований у **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, в macOS ви можете знайти його за допомогою: **`find / -name "kernelcache" 2>/dev/null`** \
У моєму випадку в macOS я знайшов його в:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

Формат файлу IMG4 - це контейнерний формат, який використовується Apple в її пристроях iOS та macOS для безпечного **зберігання та перевірки компонентів прошивки** (таких як **kernelcache**). Формат IMG4 включає заголовок і кілька тегів, які інкапсулюють різні частини даних, включаючи фактичний корисний вантаж (такий як ядро або завантажувач), підпис і набір властивостей маніфесту. Формат підтримує криптографічну перевірку, що дозволяє пристрою підтверджувати автентичність та цілісність компонента прошивки перед його виконанням.

Зазвичай він складається з наступних компонентів:

- **Payload (IM4P)**:
- Часто стиснутий (LZFSE4, LZSS, …)
- За бажанням зашифрований
- **Manifest (IM4M)**:
- Містить підпис
- Додатковий словник ключ/значення
- **Restore Info (IM4R)**:
- Відомий також як APNonce
- Запобігає повторному використанню деяких оновлень
- OPTIONAL: Зазвичай це не знаходиться

Розпакуйте Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Завантажити

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

В [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) можна знайти всі набори для налагодження ядра. Ви можете завантажити його, змонтувати, відкрити за допомогою інструменту [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), отримати доступ до папки **`.kext`** та **витягти його**.

Перевірте його на наявність символів за допомогою:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Іноді Apple випускає **kernelcache** з **symbols**. Ви можете завантажити деякі прошивки з символами, перейшовши за посиланнями на цих сторінках. Прошивки міститимуть **kernelcache** серед інших файлів.

Щоб **extract** файли, почніть з зміни розширення з `.ipsw` на `.zip` і **unzip** його.

Після витягування прошивки ви отримаєте файл на кшталт: **`kernelcache.release.iphone14`**. Він у форматі **IMG4**, ви можете витягти цікаву інформацію за допомогою:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Інспекція kernelcache

Перевірте, чи має kernelcache символи з
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
З цим ми тепер можемо **витягти всі розширення** або **те, яке вас цікавить:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Останні вразливості та техніки експлуатації

| Рік | CVE | Резюме |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Логічна помилка в **`storagekitd`** дозволила *root* зловмиснику зареєструвати шкідливий пакет файлової системи, який в кінцевому підсумку завантажив **недодписаний kext**, **обминаючи Захист цілісності системи (SIP)** і дозволяючи постійні руткіти. Виправлено в macOS 14.2 / 15.2.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Демон установки з правом `com.apple.rootless.install` міг бути зловжитий для виконання довільних скриптів після установки, відключення SIP і завантаження довільних kext.  |

**Висновки для червоних команд**

1. **Шукайте привілейовані демони (`codesign -dvv /path/bin | grep entitlements`), які взаємодіють з Disk Arbitration, Installer або Kext Management.**
2. **Зловживання обхід SIP майже завжди надає можливість завантажити kext → виконання коду ядра**.

**Оборонні поради**

*Залишайте SIP увімкненим*, контролюйте виклики `kmutil load`/`kmutil create -n aux`, що надходять з не-Apple бінарників, і сповіщайте про будь-яке записування в `/Library/Extensions`. Події безпеки кінцевих точок `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` забезпечують майже реальний моніторинг.

## Налагодження ядра macOS та kext

Рекомендований робочий процес Apple полягає в тому, щоб створити **Kernel Debug Kit (KDK)**, який відповідає запущеній версії, а потім підключити **LLDB** через мережеву сесію **KDP (Kernel Debugging Protocol)**.

### Одноразове локальне налагодження паніки
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Живе віддалене налагодження з іншого Mac

1. Завантажте + встановіть точну версію **KDK** для цільової машини.
2. Підключіть цільовий Mac і хост Mac за допомогою **USB-C або Thunderbolt кабелю**.
3. На **цільовому**:
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. На **хості**:
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### Приєднання LLDB до конкретного завантаженого kext
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP лише надає **тільки для читання** інтерфейс. Для динамічної інструментації вам потрібно буде патчити бінарний файл на диску, використовувати **хук функцій ядра** (наприклад, `mach_override`) або мігрувати драйвер до **гіпервізора** для повного читання/запису.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
