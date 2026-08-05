# Розширення ядра macOS і kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Kernel extensions (Kexts) — це **пакети** з розширенням **`.kext`**, які **завантажуються безпосередньо в простір ядра macOS** і надають додаткову функціональність основній операційній системі.

### Статус застарілості та DriverKit / System Extensions
Починаючи з **macOS Catalina (10.15)**, Apple позначила більшість застарілих KPI як *deprecated* і представила фреймворки **System Extensions & DriverKit**, які працюють у **user-space**. Починаючи з **macOS Big Sur (11)**, операційна система *відмовляється завантажувати* сторонні kexts, що використовують застарілі KPI, якщо комп'ютер не завантажено в режимі **Reduced Security**. На Apple Silicon для додаткового ввімкнення kexts користувач має:

1. Перезавантажитися в **Recovery** → *Startup Security Utility*.
2. Вибрати **Reduced Security** і встановити прапорець **“Allow user management of kernel extensions from identified developers”**.
3. Перезавантажитися та схвалити kext у **System Settings → Privacy & Security**.

Драйвери user-land, написані з використанням DriverKit/System Extensions, суттєво **зменшують attack surface**, оскільки збої або пошкодження пам'яті обмежуються sandboxed process, а не простором ядра.<sup>[1]</sup>

> 📝 Починаючи з macOS Sequoia (15), Apple повністю видалила кілька застарілих networking і USB KPI — єдиним сумісним із майбутніми версіями рішенням для vendors є перехід на System Extensions.

### Вимоги

Очевидно, це настільки потужний механізм, що **завантажити kernel extension складно**. Ось **вимоги**, яким має відповідати kernel extension для завантаження:

- Під час **переходу в recovery mode** має бути дозволено завантаження kernel **extensions**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension має бути **підписана сертифікатом для підпису коду ядра**, який може **надати лише Apple**. Apple детально перевіряє компанію та причини, з яких цей сертифікат потрібен.
- Kernel extension також має бути **notarized**; Apple зможе перевірити її на наявність malware.
- Далі саме користувач **root** може **завантажити kernel extension**, а файли всередині пакета мають **належати root**.
- Під час процесу upload пакет має бути підготовлений у **захищеному місці, що не належить root**: `/Library/StagedExtensions` (потрібен grant `com.apple.rootless.storage.KernelExtensionManagement`).
- Нарешті, під час спроби завантаження користувач [**отримає запит на підтвердження**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html), і в разі підтвердження комп'ютер потрібно **перезапустити**, щоб завантажити її.

### Процес завантаження

У Catalina це працювало так: цікаво зазначити, що процес **перевірки** відбувається в userland. Однак лише застосунки з grant **`com.apple.private.security.kext-management`** можуть **запитати ядро про завантаження extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. CLI **`kextutil`** **запускає** процес **перевірки** для завантаження extension
- Він зв'язується з **`kextd`**, надсилаючи запит через **Mach service**.
2. **`kextd`** перевіряє кілька параметрів, зокрема **signature**
- Він зв'язується із **`syspolicyd`**, щоб **перевірити**, чи можна **завантажити** extension.
3. **`syspolicyd`** **запитує** **користувача**, якщо extension не завантажувалася раніше.
- **`syspolicyd`** повідомляє результат **`kextd`**
4. **`kextd`** нарешті може **повідомити ядру про необхідність завантажити** extension

Якщо **`kextd`** недоступний, **`kextutil`** може виконати ті самі перевірки.

### Перелік і керування (завантажені kexts)

`kextstat` був історичним інструментом, але в останніх версіях macOS він **deprecated**. Сучасний інтерфейс — **`kmutil`**:
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
`kmutil inspect` також можна використати, щоб **dump вмісту Kernel Collection (KC)** або перевірити, що kext розв'язує всі залежності символів:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Незважаючи на те, що очікується розташування kernel extensions у `/System/Library/Extensions/`, якщо перейти до цієї папки, ви **не знайдете жодного бінарного файла**. Це відбувається через **kernelcache**, і для reverse engineering одного `.kext` потрібно знайти спосіб його отримати.

**Kernelcache** — це **попередньо скомпільована та попередньо зв’язана версія ядра XNU**, разом із необхідними **драйверами** пристроїв і **kernel extensions**. Він зберігається у **стисненому** форматі та розпаковується в пам’ять під час процесу завантаження. Kernelcache забезпечує **швидше завантаження**, оскільки готова до запуску версія ядра та критично важливі драйвери вже доступні. Це зменшує час і ресурси, які інакше витрачалися б на динамічне завантаження та зв’язування цих компонентів під час завантаження.

Основні переваги kernelcache — це **швидкість завантаження**, а також попереднє зв’язування всіх модулів (без затримок під час завантаження). Після попереднього зв’язування всіх модулів KXLD можна видалити з пам’яті, тому **XNU не може завантажувати нові KEXTs.**

> [!TIP]
> Інструмент [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) розшифровує контейнери Apple AEA (Apple Encrypted Archive / AEA asset) — зашифрований формат контейнерів, який Apple використовує для OTA assets і деяких частин IPSW — та може створити базовий `.dmg`/asset archive, який потім можна розпакувати за допомогою наданих інструментів aastuff.


### Локальний Kerlnelcache

В iOS він розташований у **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, а в macOS його можна знайти за допомогою: **`find / -name "kernelcache" 2>/dev/null`** \
У моєму випадку в macOS я знайшов його тут:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Також тут можна знайти [**kernelcache версії 14 із symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

Формат файлів IMG4 — це формат контейнерів, який Apple використовує у своїх пристроях iOS і macOS для безпечного **зберігання та перевірки firmware** компонентів (наприклад, **kernelcache**). Формат IMG4 містить заголовок і кілька тегів, які інкапсулюють різні частини даних, зокрема фактичне корисне навантаження (наприклад, kernel або bootloader), signature і набір властивостей manifest. Формат підтримує cryptographic verification, що дає пристрою змогу підтвердити автентичність і цілісність firmware-компонента перед його виконанням.

Зазвичай він складається з таких компонентів:

- **Payload (IM4P)**:
- Часто compressed (LZFSE4, LZSS, …)
- Опціонально encrypted
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

**`Disarm`** дозволяє символізувати функції з kernelcache за допомогою matcher-ів. Ці matcher-и є простими правилами шаблонів (текстовими рядками), які вказують disarm, як розпізнавати та автоматично символізувати функції, аргументи й panic/log-рядки всередині бінарного файлу.

Отже, ви вказуєте рядок, який використовує функція, а disarm знаходить його та **символізує**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Перейдіть до /tmp/extracted, куди disarm розпакував filesets
disarm -e filesets kernelcache.release.d23 # Завжди розпаковуйте до /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Зверніть увагу, що xnu.matchers фактично є файлом із matchers
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
# Встановіть інструмент ipsw
brew install blacktop/tap/ipsw

# Витягніть лише kernelcache з IPSW
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
# Перелік усіх розширень
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
# Створення symbolication bundle для останньої panic
```bash
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
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
(lldb) bt  # get backtrace in kernel context
```

### Attaching LLDB to a specific loaded kext

```bash
# Визначення адреси завантаження kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Приєднання
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

{{#include ../../../banners/hacktricks-training.md}}
