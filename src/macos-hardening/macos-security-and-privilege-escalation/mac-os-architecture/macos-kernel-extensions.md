# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Kernel extensions (Kexts) — це пакети з розширенням **`.kext`**, які **завантажуються безпосередньо в простір ядра macOS**, додаючи додаткову функціональність до операційної системи.

### Deprecation status & DriverKit / System Extensions
Починаючи з **macOS Catalina (10.15)** Apple позначила більшість застарілих KPI як *deprecated* та представила фреймворки **System Extensions & DriverKit**, що працюють у **user-space**. З **macOS Big Sur (11)** ОС відмовлятиметься *завантажувати* сторонні kext, які покладаються на застарілі KPI, якщо машина не завантажена в режимі **Reduced Security**. На Apple Silicon для ввімкнення kext додатково потрібно, щоб користувач:

1. Reboot into **Recovery** → *Startup Security Utility*.
2. Select **Reduced Security** and tick **“Allow user management of kernel extensions from identified developers”**.
3. Reboot and approve the kext from **System Settings → Privacy & Security**.

Драйвери в user-land, написані з використанням DriverKit/System Extensions, суттєво **зменшують поверхню атаки**, оскільки крахи або пошкодження пам’яті обмежуються ізольованим процесом, а не простором ядра.

> 📝 З macOS Sequoia (15) Apple повністю видалив кілька застарілих мережевих та USB KPI — єдиним сумісним шляхом для вендорів є міграція на System Extensions.

### Requirements

Очевидно, це настільки потужно, що **завантажити kernel extension складно**. Ось **вимоги**, яким має відповідати kernel extension, щоб бути завантаженим:

- Під час **входу в режим відновлення (recovery mode)** має бути **дозволено завантаження kernel extensions**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension має бути **підписаний сертифікатом для підпису коду ядра (kernel code signing certificate)**, який може бути виданий лише **Apple**. Apple детально перевірить компанію та причини необхідності.
- Kernel extension також має бути **notarized**, Apple зможе перевірити його на наявність шкідливого ПЗ.
- Тільки користувач **root** може **завантажувати kernel extension**, а файли всередині пакета повинні **належати root**.
- Під час процесу завантаження пакет має бути підготовлений у **захищеному місці, що не належить root**: `/Library/StagedExtensions` (вимагає надання права `com.apple.rootless.storage.KernelExtensionManagement`).
- Нарешті, при спробі завантаження користувач [**отримає запит на підтвердження**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) і, якщо погодить, комп’ютер має бути **перезавантажений** для завантаження розширення.

### Loading process

У Catalina це відбувалося так: цікаво, що процес **верифікації** виконується в **userland**. Проте лише додатки з грантом **`com.apple.private.security.kext-management`** можуть **запитувати ядро на завантаження розширення**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **запускає** процес **верифікації** для завантаження розширення
- Він звертається до **`kextd`** через **Mach service**.
2. **`kextd`** перевіряє кілька речей, таких як **підпис**
- Він звертається до **`syspolicyd`**, щоб **перевірити**, чи можна **завантажити** розширення.
3. **`syspolicyd``** **показує запит користувачу**, якщо розширення раніше не було завантажене.
- **`syspolicyd`** повідомляє результат **`kextd`**
4. **`kextd`** врешті може **попросити ядро завантажити** розширення

Якщо **`kextd`** недоступний, **`kextutil`** може виконати ті самі перевірки.

### Enumeration & management (loaded kexts)

`kextstat` був історичним інструментом, але він **deprecated** у нових релізах macOS. Сучасний інтерфейс — **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Старіший синтаксис все ще доступний для довідки:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` також можна використати для вивантаження вмісту Kernel Collection (KC) або для перевірки, що kext вирішує всі залежності символів:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Навіть якщо очікується, що kernel extensions знаходяться в `/System/Library/Extensions/`, якщо ви перейдете в цю папку, ви **не знайдете жодного бінарного файлу**. Це через **kernelcache**, і щоб проаналізувати один `.kext`, потрібно знайти спосіб отримати його.

The **kernelcache** — це **попередньо скомпільована та попередньо зв’язана версія ядра XNU**, разом із необхідними пристрійними **драйверами** та **kernel extensions**. Він зберігається в **стисненому** форматі і розпаковується в пам’ять під час процесу завантаження. Kernelcache сприяє **швидшому завантаженню**, оскільки має готову до виконання версію ядра та ключових драйверів, зменшуючи час і ресурси, які в іншому випадку були б витрачені на динамічне завантаження та лінкування цих компонентів під час boot.

Головні переваги kernelcache — **швидкість завантаження** та те, що всі модулі попередньо зв’язані (немає затримки на завантаження). І після того, як усі модулі були попередньо зв’язані, KXLD може бути видалено з пам’яті, тому **XNU не може завантажувати нові KEXTs.**

> [!TIP]
> Інструмент [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) дешифрує AEA (Apple Encrypted Archive / AEA asset) контейнер — зашифрований контейнерний формат, який Apple використовує для OTA assets та деяких частин IPSW — і може відтворити підлягаючий .dmg/asset архів, який потім можна витягти за допомогою наданих інструментів aastuff.

### Локальний Kernelcache

В iOS він знаходиться в **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, в macOS ви можете знайти його за допомогою: **`find / -name "kernelcache" 2>/dev/null`** \
У моєму випадку в macOS я знайшов його в:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Також тут можна знайти [**kernelcache версії 14 з символами**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

Формат файлу IMG4 — це контейнерний формат, який Apple використовує в пристроях iOS та macOS для безпечного **зберігання та перевірки прошивок** (наприклад, **kernelcache**). Формат IMG4 містить заголовок і кілька тегів, які інкапсулюють різні частини даних, включно з фактичним payload (наприклад, ядро або bootloader), підписом та набором властивостей у маніфесті. Формат підтримує криптографічну перевірку, що дозволяє пристрою підтвердити автентичність і цілісність компонента прошивки перед його виконанням.

Зазвичай він складається з наступних компонентів:

- **Payload (IM4P)**:
- Часто стиснений (LZFSE4, LZSS, …)
- Опційно зашифрований
- **Manifest (IM4M)**:
- Містить Signature
- Додатковий словник Key/Value
- **Restore Info (IM4R)**:
- Також відомий як APNonce
- Запобігає повторному відтворенню деяких оновлень
- OPTIONAL: Зазвичай цього не знаходять

Decompress the Kernelcache:
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
#### Disarm: символи для ядра

**`Disarm`** дозволяє symbolicate functions із kernelcache, використовуючи matchers. Ці matchers — прості правила-шаблони (текстові рядки), які вказують Disarm, як розпізнавати та auto-symbolicate functions, arguments і panic/log strings всередині binary.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Перейдіть у /tmp/extracted, куди disarm розпакував filesets
disarm -e filesets kernelcache.release.d23 # Завжди розпаковувати в /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Зверніть увагу, що xnu.matchers фактично є файлом з matchers
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
# Встановити ipsw
brew install blacktop/tap/ipsw

# Витягнути лише kernelcache з IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Ви маєте отримати щось на кшталт:
#   out/Firmware/kernelcache.release.iPhoneXX
#   або IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Якщо ви отримали IMG4 payload:
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
# Перелічити всі розширення
kextex -l kernelcache.release.iphone14.e
## Витягти com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Витягти все
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
# Створіть пакет символікації для останньої kernel panic
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
(lldb) bt  # отримати стек викликів у контексті ядра
```

### Attaching LLDB to a specific loaded kext

```bash
# Визначити адресу завантаження kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Підключення
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
