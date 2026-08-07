# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Kernel extensions (Kexts) — це **пакети** з розширенням **`.kext`**, які **завантажуються безпосередньо в простір ядра macOS**, надаючи додаткову функціональність основній операційній системі.

### Статус deprecated і DriverKit / System Extensions
Починаючи з **macOS Catalina (10.15)**, Apple позначила більшість legacy KPI як *deprecated* і представила фреймворки **System Extensions & DriverKit**, які працюють у **user-space**. Починаючи з **macOS Big Sur (11)**, операційна система *відмовляється завантажувати* сторонні kexts, що покладаються на deprecated KPI, якщо комп'ютер не завантажено в режимі **Reduced Security**. На Apple Silicon додаткове ввімкнення kexts вимагає від користувача:

1. Перезавантажитися в **Recovery** → *Startup Security Utility*.
2. Вибрати **Reduced Security** і встановити прапорець **“Allow user management of kernel extensions from identified developers”**.
3. Перезавантажитися та схвалити kext у **System Settings → Privacy & Security**.

User-land drivers, написані за допомогою DriverKit/System Extensions, значно **зменшують attack surface**, оскільки crashes або пошкодження пам'яті обмежуються sandboxed process, а не простором ядра.<sup>[[1]](#references)</sup>

> 📝 Починаючи з macOS Sequoia (15), Apple повністю видалила кілька legacy networking і USB KPI — єдиним forward-compatible рішенням для vendors є міграція на System Extensions.

### Вимоги

Очевидно, це настільки потужний механізм, що **завантаження kernel extension є складним**. Нижче наведено **вимоги**, яким має відповідати kernel extension для завантаження:

- Під час **входу в recovery mode** має бути дозволено завантаження kernel **extensions**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension має бути **підписаний kernel code signing certificate**, який може **надати лише Apple**. Apple детально перевіряє компанію та причини, з яких цей сертифікат потрібен.
- Kernel extension також має бути **notarized** — Apple зможе перевірити його на наявність malware.
- Далі саме користувач **root** може **завантажити kernel extension**, а файли всередині пакета мають **належати root**.
- Під час процесу завантаження пакет має бути підготовлений у **захищеному розташуванні, яке не належить root**: `/Library/StagedExtensions` (потрібен grant `com.apple.rootless.storage.KernelExtensionManagement`).
- Нарешті, під час спроби завантаження користувач [**отримає запит на підтвердження**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html), а після прийняття комп'ютер потрібно **перезапустити**, щоб завантажити його.

### Процес завантаження

У Catalina це працювало так: цікаво зазначити, що процес **verification** відбувається в **userland**. Однак лише applications із grant **`com.apple.private.security.kext-management`** можуть **запитувати ядро на завантаження extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **запускає** процес **verification** для завантаження extension
- Він взаємодіє з **`kextd`**, надсилаючи дані через **Mach service**.
2. **`kextd`** перевіряє кілька речей, зокрема **signature**
- Він взаємодіє з **`syspolicyd`**, щоб **перевірити**, чи можна **завантажити** extension.
3. **`syspolicyd`** показує **prompt** **користувачу**, якщо extension раніше не завантажувалася.
- **`syspolicyd`** повідомляє результат **`kextd`**
4. **`kextd`** нарешті може **повідомити ядру про необхідність завантажити** extension

Якщо **`kextd`** недоступний, **`kextutil`** може виконати ті самі перевірки.

### Перелік і керування (завантажені kexts)

`kextstat` був історичним інструментом, але в останніх випусках macOS він є **deprecated**. Сучасний інтерфейс — **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Старий синтаксис усе ще доступний для довідки:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` також можна використовувати для **дампу вмісту Kernel Collection (KC)** або перевірки того, що kext розв'язує всі залежності символів:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Незважаючи на те, що kernel extensions мають бути розташовані в `/System/Library/Extensions/`, якщо перейти до цієї папки, ви **не знайдете жодного бінарного файлу**. Це пов’язано з **kernelcache**, і для reverse engineering одного `.kext` потрібно знайти спосіб отримати його.

**Kernelcache** — це **попередньо скомпільована та попередньо пов’язана версія ядра XNU**, разом із необхідними **драйверами** пристроїв і **kernel extensions**. Він зберігається у **стисненому** форматі та розпаковується в пам’ять під час процесу завантаження. Kernelcache забезпечує **швидше завантаження**, оскільки містить готову до запуску версію ядра та критично важливих драйверів, зменшуючи час і ресурси, які інакше витрачалися б на динамічне завантаження та компонування цих компонентів під час завантаження.

Основні переваги kernelcache — це **швидкість завантаження**, а також те, що всі модулі попередньо пов’язані (немає затримки під час завантаження). Після попереднього компонування всіх модулів KXLD можна видалити з пам’яті, тому **XNU не може завантажувати нові KEXTs.**

> [!TIP]
> Інструмент [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) розшифровує контейнери AEA (Apple Encrypted Archive / AEA asset) — зашифрований формат контейнерів, який Apple використовує для OTA-ресурсів і деяких компонентів IPSW — і може створити базовий `.dmg`/архів ресурсу, який потім можна розпакувати за допомогою наданих інструментів aastuff.


### Локальний Kerlnelcache

В iOS він розташований у **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, а в macOS його можна знайти за допомогою: **`find / -name "kernelcache" 2>/dev/null`** \
У моєму випадку в macOS я знайшов його тут:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Також тут можна знайти [**kernelcache версії 14 із символами**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

Формат файлів IMG4 — це формат контейнерів, який Apple використовує у своїх пристроях iOS і macOS для безпечного **зберігання та перевірки прошивки** (наприклад, **kernelcache**). Формат IMG4 містить заголовок і кілька тегів, які інкапсулюють різні частини даних, зокрема фактичне корисне навантаження (наприклад, ядро або bootloader), підпис і набір властивостей маніфесту. Формат підтримує криптографічну перевірку, що дає змогу пристрою підтвердити автентичність і цілісність компонента прошивки перед його виконанням.

Зазвичай він складається з таких компонентів:

- **Payload (IM4P)**:
- Часто стиснений (LZFSE4, LZSS, …)
- Опційно зашифрований
- **Manifest (IM4M)**:
- Містить підпис
- Додатковий словник Key/Value
- **Restore Info (IM4R)**:
- Також відомий як APNonce
- Запобігає повторному застосуванню деяких оновлень
- OPTIONAL: Зазвичай цього немає

Розпакування Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# imjtool (https://newandroidbook.com/tools/imjtool.html)
imjtool _img_name_ [extract]

# disarm (you can use it directly on the IMG4 file) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -L kernelcache.release.v57 # From unzip ipsw

# disamer (extract specific parts, e.g. filesets) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -e filesets kernelcache.release.d23
```
#### Disarm symbols для kernel

**`Disarm`** дозволяє символізувати функції з kernelcache за допомогою matchers. Ці matchers є простими правилами шаблонів (текстовими рядками), які повідомляють disarm, як розпізнавати та автоматично символізувати функції, аргументи й panic/log strings усередині бінарного файлу.

Отже, ви вказуєте string, який використовує функція, а disarm знаходить його та **символізує функцію**.

Деякі `xnu.matchers` можна знайти на сторінці [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html), у розділі **`Matchers`**. Ви також можете створювати власні matchers.
```bash
# Go to /tmp/extracted where disarm extracted the filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```
### Завантаження

**IPSW (iPhone/iPad Software)** — це формат пакета firmware від Apple, який використовується для відновлення пристроїв, оновлень і повних пакетів firmware. Зокрема, він містить **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

У [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) можна знайти всі kernel debug kits. Ви можете завантажити його, змонтувати, відкрити за допомогою інструмента [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), отримати доступ до папки **`.kext`** і **витягнути її вміст**.

Перевірте його на наявність символів за допомогою:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Іноді Apple випускає **kernelcache** із **symbols**. Ви можете завантажити деякі firmware із symbols, перейшовши за посиланнями на цих сторінках. Firmware міститимуть **kernelcache** серед інших файлів.

Щоб **extract** kernel cache, можна виконати:
```bash
# Install ipsw tool
brew install blacktop/tap/ipsw

# Extract only the kernelcache from the IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# You should get something like:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# If you get an IMG4 payload:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```
Ще один варіант **extract** файлів — спочатку змінити розширення з `.ipsw` на `.zip`, а потім **unzip** його.

Після розпакування firmware ви отримаєте файл на кшталт: **`kernelcache.release.iphone14`**. Він має формат **IMG4**, отримати цікаву інформацію можна за допомогою:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Перевірка kernelcache

Перевірте, чи має kernelcache символи, за допомогою
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
За допомогою цього ми можемо **видобути всі розширення** або **те, яке вас цікавить:**
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
## Нещодавні вразливості та техніки експлуатації

| Рік | CVE | Короткий опис |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Логічна помилка в **`storagekitd`** дозволяла зловмиснику з правами *root* зареєструвати шкідливий файловий bundle, який зрештою завантажував **непідписаний kext**, **обходячи System Integrity Protection (SIP)** та уможливлюючи встановлення стійких rootkit. Виправлено в macOS 14.2 / 15.2. <sup>[[2]](#references)</sup>  |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Installation daemon із entitlement `com.apple.rootless.install` можна було використати для виконання довільних post-install скриптів, вимкнення SIP і завантаження довільних kext. <sup>[[3]](#references)</sup> |

**Основні висновки для red-teamers**

1. **Шукайте daemon з entitlements (`codesign -dvv /path/bin | grep entitlements`), які взаємодіють із Disk Arbitration, Installer або Kext Management.**
2. **Експлуатація обходів SIP майже завжди надає можливість завантажити kext → виконати код у kernel**.

**Поради щодо захисту**

*Залишайте SIP увімкненим*, відстежуйте виклики `kmutil load`/`kmutil create -n aux`, що надходять від бінарних файлів не від Apple, і створюйте сповіщення про будь-який запис до `/Library/Extensions`. Події Endpoint Security `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` забезпечують видимість майже в реальному часі.

## Налагодження kernel і kext у macOS

Рекомендований Apple робочий процес полягає у створенні **Kernel Debug Kit (KDK)**, що відповідає запущеній збірці, а потім підключенні **LLDB** через мережевий сеанс **KDP (Kernel Debugging Protocol)**.

### Одноразове локальне налагодження panic
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Віддалене налагодження в реальному часі з іншого Mac

1. Завантажте й інсталюйте точну версію **KDK** для цільової машини.
2. З’єднайте цільовий Mac і Mac-хост за допомогою **USB-C або кабелю Thunderbolt**.
3. На **цільовому Mac**:
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
### Підключення LLDB до певного завантаженого kext
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP надає лише **read-only** інтерфейс. Для dynamic instrumentation потрібно внести patch до бінарного файла на диску, використати **kernel function hooking** (наприклад, `mach_override`) або перенести драйвер до **hypervisor** для повного read/write.

## Посилання

- [1] [Безпека DriverKit для macOS - Посібник з безпеки платформ Apple](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Аналіз CVE-2024-44243 — обходу System Integrity Protection у macOS через kernel extensions - Блог Microsoft Security](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Microsoft виявила нову вразливість macOS під назвою Shrootless, яка могла обійти System Integrity Protection - Блог Microsoft Security](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)

{{#include ../../../banners/hacktricks-training.md}}
