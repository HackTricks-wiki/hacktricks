# Розширення ядра macOS і kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Kernel extensions (Kexts) — це **пакети** з розширенням **`.kext`**, які **завантажуються безпосередньо в простір ядра macOS** і надають додаткову функціональність основній операційній системі.

### Статус deprecated і DriverKit / System Extensions
Починаючи з **macOS Catalina (10.15)**, Apple позначила більшість legacy KPI як *deprecated* і представила фреймворки **System Extensions і DriverKit**, які працюють у **user-space**. Починаючи з **macOS Big Sur (11)**, операційна система *відмовляється завантажувати* сторонні kexts, що використовують deprecated KPI, якщо комп’ютер завантажено в режимі **Reduced Security**. На Apple Silicon додаткове ввімкнення kexts вимагає від користувача:

1. Перезавантажитися в **Recovery** → *Startup Security Utility*.
2. Вибрати **Reduced Security** і встановити прапорець **“Allow user management of kernel extensions from identified developers”**.
3. Перезавантажитися та схвалити kext у **System Settings → Privacy & Security**.

Драйвери user-land, написані за допомогою DriverKit/System Extensions, суттєво **зменшують attack surface**, оскільки crashes або пошкодження пам’яті обмежуються sandboxed процесом, а не простором ядра.<sup>[[1]](#references)</sup>

> 📝 Починаючи з macOS Sequoia (15), Apple повністю видалила кілька legacy networking і USB KPI — єдиним forward-compatible рішенням для vendors є перехід на System Extensions.

### Вимоги

Очевидно, це настільки потужний механізм, що **завантажити kernel extension** складно. Ось **вимоги**, яким має відповідати kernel extension для завантаження:

- Під час **переходу в recovery mode** має бути дозволено завантаження kernel **extensions**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension має бути **підписаний сертифікатом для підпису коду ядра**, який може **видати лише Apple**. Apple детально перевіряє компанію та причини, з яких він потрібен.
- Kernel extension також має бути **notarized**; Apple зможе перевірити його на наявність malware.
- Далі саме користувач **root** може **завантажити kernel extension**, а файли всередині пакета мають **належати root**.
- Під час процесу завантаження пакет має бути підготовлений у **захищеному non-root розташуванні**: `/Library/StagedExtensions` (потрібен grant `com.apple.rootless.storage.KernelExtensionManagement`).
- Нарешті, під час спроби завантаження користувач [**отримає запит на підтвердження**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html), а після підтвердження комп’ютер потрібно **перезавантажити**, щоб завантажити його.

### Процес завантаження

У Catalina це відбувалося так: цікаво зазначити, що процес **перевірки** виконується в **userland**. Однак лише applications із grant **`com.apple.private.security.kext-management`** можуть **запросити в ядра завантаження extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **запускає** процес **перевірки** для завантаження extension
- Він взаємодіє з **`kextd`**, надсилаючи дані через **Mach service**.
2. **`kextd`** перевіряє кілька речей, зокрема **signature**
- Він взаємодіє з **`syspolicyd`**, щоб **перевірити**, чи можна **завантажити** extension.
3. **`syspolicyd`** показує **запит** **користувачу**, якщо extension не завантажувалася раніше.
- **`syspolicyd`** повідомляє результат **`kextd`**
4. **`kextd`** зрештою може **вказати ядру завантажити** extension

Якщо **`kextd`** недоступний, **`kextutil`** може виконати ті самі перевірки.

### Перелік і керування (завантажені kexts)

`kextstat` був історичним інструментом, але в останніх випусках macOS він **deprecated**. Сучасний інтерфейс — **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Старий синтаксис все ще доступний для довідки:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` також можна використати, щоб **дампнути вміст Kernel Collection (KC)** або перевірити, чи kext розв'язує всі залежності символів:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Незважаючи на те, що kernel extensions мають знаходитися в `/System/Library/Extensions/`, якщо перейти до цієї папки, **ви не знайдете жодного бінарного файлу**. Це пов'язано з **kernelcache**, і для reverse engineering одного `.kext` потрібно знайти спосіб його отримати.

**Kernelcache** — це **попередньо скомпільована та попередньо зв'язана версія ядра XNU**, разом із необхідними **драйверами** пристроїв і **kernel extensions**. Він зберігається у **стисненому** форматі та розпаковується в пам'ять під час процесу завантаження. Kernelcache забезпечує **швидше завантаження**, оскільки готова до запуску версія ядра та критично важливі драйвери доступні одразу, що скорочує час і ресурси, які в іншому разі витрачалися б на динамічне завантаження та зв'язування цих компонентів під час запуску.

Основними перевагами kernelcache є **швидкість завантаження**, а також те, що всі модулі попередньо зв'язані (немає перешкод під час завантаження). Після попереднього зв'язування всіх модулів KXLD можна видалити з пам'яті, тому **XNU не може завантажувати нові KEXTs.**

> [!TIP]
> Інструмент [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) розшифровує контейнери Apple AEA (Apple Encrypted Archive / AEA asset) — зашифрований формат контейнерів, який Apple використовує для OTA assets і деяких частин IPSW — та може створити базовий `.dmg`/asset archive, який потім можна розпакувати за допомогою наданих інструментів aastuff.


### Локальний Kerlnelcache

В iOS він розташований у **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, а в macOS його можна знайти за допомогою: **`find / -name "kernelcache" 2>/dev/null`** \
У моєму випадку в macOS я знайшов його тут:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Також знайдіть тут [**kernelcache версії 14 із symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### Стиснений IMG4 / BVX2 (LZFSE)

Формат файлів IMG4 — це формат контейнерів, який Apple використовує у своїх пристроях iOS і macOS для безпечного **зберігання та перевірки firmware** компонентів (наприклад, **kernelcache**). Формат IMG4 містить заголовок і кілька тегів, які інкапсулюють різні частини даних, зокрема фактичне корисне навантаження (наприклад, kernel або bootloader), підпис і набір властивостей manifest. Формат підтримує cryptographic verification, що дає пристрою змогу підтвердити автентичність і цілісність компонента firmware перед його виконанням.

Зазвичай він складається з таких компонентів:

- **Payload (IM4P)**:
- Часто стиснений (LZFSE4, LZSS, …)
- Опційно зашифрований
- **Manifest (IM4M)**:
- Містить Signature
- Додатковий словник Key/Value
- **Restore Info (IM4R)**:
- Також відомий як APNonce
- Запобігає повторному застосуванню деяких оновлень
- OPTIONAL: Зазвичай цього немає

Розпакуйте Kernelcache:
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
#### Символи Disarm для kernel

**`Disarm`** дозволяє символізувати функції з kernelcache за допомогою matcher-ів. Ці matcher-и є простими правилами шаблонів (текстовими рядками), які повідомляють disarm, як розпізнавати та автоматично символізувати функції, аргументи й panic/log-рядки всередині бінарного файлу.

Тобто ви вказуєте рядок, який використовує функція, а disarm знаходить його та **символізує**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Перейдіть до /tmp/extracted, куди disarm розпакував filesets
disarm -e filesets kernelcache.release.d23 # Завжди розпаковуйте до /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Зверніть увагу, що xnu.matchers насправді є файлом із matchers
```

### Download

An **IPSW (iPhone/iPad Software)** is Apple’s firmware package format used for device restores, updates, and full firmware bundles. Among other things, it contains the **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) it's possible to find all the kernel debug kits. You can download it, mount it, open it with [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) tool, access the **`.kext`** folder and **extract it**.

Check it for symbols with:

```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```

- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Sometime Apple releases **kernelcache** with **symbols**. You can download some firmwares with symbols by following links on those pages. The firmwares will contain the **kernelcache** among other files.

To **extract** the kernel cache you can do:

```bash
# Встановлення інструмента ipsw
brew install blacktop/tap/ipsw

# Витягнути лише kernelcache з IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Ви маєте отримати щось на кшталт:
#   out/Firmware/kernelcache.release.iPhoneXX
#   або payload IMG4: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Якщо ви отримали payload IMG4:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```

Another option to **extract** the files start by changing the extension from `.ipsw` to `.zip` and **unzip** it.

After extracting the firmware you will get a file like: **`kernelcache.release.iphone14`**. It's in **IMG4** format, you can extract the interesting info with:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

[**img4tool**](https://github.com/tihmstar/img4tool)**:**

```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

[**img4tool**](https://github.com/tihmstar/img4tool)**:**

```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

### Inspecting kernelcache

Check if the kernelcache has symbols with

```bash
nm -a kernelcache.release.iphone14.e | wc -l
```

With this we can now **extract all the extensions** or the **one you are interested in:**

```bash
# Показати всі розширення
kextex -l kernelcache.release.iphone14.e
## Витягнути com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Витягнути всі
kextex_all kernelcache.release.iphone14.e

# Перевірити розширення на наявність символів
nm -a binaries/com.apple.security.sandbox | wc -l
```


## Recent vulnerabilities & exploitation techniques

| Year | CVE | Summary |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Logic flaw in **`storagekitd`** allowed a *root* attacker to register a malicious file-system bundle that ultimately loaded an **unsigned kext**, **bypassing System Integrity Protection (SIP)** and enabling persistent rootkits. Patched in macOS 14.2 / 15.2.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Installation daemon with the entitlement `com.apple.rootless.install` could be abused to execute arbitrary post-install scripts, disable SIP and load arbitrary kexts.  |

**Take-aways for red-teamers**

1. **Look for entitled daemons (`codesign -dvv /path/bin | grep entitlements`) that interact with Disk Arbitration, Installer or Kext Management.**
2. **Abusing SIP bypasses almost always grants the ability to load a kext → kernel code execution**.

**Defensive tips**

*Keep SIP enabled*, monitor for `kmutil load`/`kmutil create -n aux` invocations coming from non-Apple binaries and alert on any write to `/Library/Extensions`. Endpoint Security events `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` provide near real-time visibility.

## Debugging macOS kernel & kexts

Apple’s recommended workflow is to build a **Kernel Debug Kit (KDK)** that matches the running build and then attach **LLDB** over a **KDP (Kernel Debugging Protocol)** network session.

### One-shot local debug of a panic

```bash
# Створіть пакет symbolication для останньої panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```

### Live remote debugging from another Mac

1. Download + install the exact **KDK** version for the target machine.
2. Connect the target Mac and the host Mac with a **USB-C or Thunderbolt cable**.
3. On the **target**:

```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```

4. On the **host**:

```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # отримати backtrace у контексті kernel
```

### Attaching LLDB to a specific loaded kext

```bash
# Визначити адресу завантаження kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Підключитися
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

{{#include ../../../banners/hacktricks-training.md}}
