# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

I/O Kit — це об'єктно-орієнтований **фреймворк драйверів пристроїв** із відкритим вихідним кодом у ядрі XNU, який обробляє **динамічно завантажувані драйвери пристроїв**. Він дає змогу додавати модульний код до ядра на льоту та підтримує різноманітне обладнання.

Драйвери IOKit фактично **експортують функції з ядра**. **Типи** параметрів цих функцій **попередньо визначені** та перевіряються. Крім того, подібно до XPC, IOKit є ще одним рівнем **над Mach messages**.

**Код ядра IOKit XNU** опублікований Apple у [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Компоненти IOKit у user space також мають відкритий вихідний код: [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Однак **жоден драйвер IOKit** не має відкритого вихідного коду. Водночас час від часу реліз драйвера може містити symbols, що спрощує його налагодження. Дізнайтеся, як [**отримати розширення драйверів із firmware тут**](#ipsw)**.**

Він написаний на **C++**. Отримати demangled C++ symbols можна за допомогою:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> **Відкриті функції** IOKit можуть виконувати **додаткові перевірки безпеки**, коли клієнт намагається викликати функцію, але зверніть увагу, що додатки зазвичай **обмежені** sandbox щодо функцій IOKit, з якими вони можуть взаємодіяти.

## Драйвери

У macOS вони розташовані в:

- **`/System/Library/Extensions`**
- Файли KEXT, вбудовані в операційну систему OS X.
- **`/Library/Extensions`**
- Файли KEXT, встановлені стороннім програмним забезпеченням

В iOS вони розташовані в:

- **`/System/Library/Extensions`**
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
До номера 9 перелічені драйвери **завантажені за адресою 0**. Це означає, що вони не є справжніми драйверами, а є **частиною ядра, і їх неможливо вивантажити**.

Щоб знайти певні розширення, можна використати:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Щоб завантажити та вивантажити розширення ядра, виконайте:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry** є важливою частиною framework IOKit у macOS та iOS, яка виконує роль бази даних для представлення апаратної конфігурації та стану системи. Це **ієрархічна сукупність об’єктів, що представляють усе апаратне забезпечення та драйвери**, завантажені в системі, а також їхні взаємозв’язки.

Отримати IORegistry можна за допомогою cli **`ioreg`**, щоб переглянути його з консолі (особливо корисно для iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Ви можете завантажити **`IORegistryExplorer`** з **Xcode Additional Tools** за посиланням [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) і переглядати **macOS IORegistry** через **графічний** інтерфейс.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

В IORegistryExplorer "planes" використовуються для організації та відображення взаємозв'язків між різними об'єктами в IORegistry. Кожна plane представляє певний тип взаємозв'язку або конкретне представлення апаратної конфігурації та конфігурації драйверів системи. Ось деякі поширені planes, які можна зустріти в IORegistryExplorer:

1. **IOService Plane**: Це найбільш загальна plane, яка відображає service objects, що представляють драйвери та nubs (канали зв'язку між драйверами). Вона показує взаємозв'язки provider-client між цими об'єктами.
2. **IODeviceTree Plane**: Ця plane представляє фізичні з'єднання між пристроями, підключеними до системи. Її часто використовують для візуалізації ієрархії пристроїв, підключених через шини, як-от USB або PCI.
3. **IOPower Plane**: Відображає об'єкти та їхні взаємозв'язки з погляду керування живленням. Вона може показати, які об'єкти впливають на стан живлення інших, що корисно для налагодження проблем, пов'язаних із живленням.
4. **IOUSB Plane**: Спеціально зосереджена на USB-пристроях та їхніх взаємозв'язках і показує ієрархію USB-хабів і підключених пристроїв.
5. **IOAudio Plane**: Ця plane призначена для представлення аудіопристроїв та їхніх взаємозв'язків у системі.
6. ...

## Приклад коду Driver Comm

Наступний код підключається до сервісу IOKit `YourServiceNameHere` і викликає selector 0:

- Спочатку він викликає **`IOServiceMatching`** і **`IOServiceGetMatchingServices`**, щоб отримати service.
- Потім встановлює з'єднання за допомогою виклику **`IOServiceOpen`**.
- І нарешті викликає функцію через **`IOConnectCallScalarMethod`**, вказуючи selector 0 (selector — це номер, призначений функції, яку потрібно викликати).

<details>
<summary>Приклад user-space виклику selector драйвера</summary>
```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get a reference to the service using its name
CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
if (matchingDict == NULL) {
NSLog(@"Failed to create matching dictionary");
return -1;
}

// Obtain an iterator over all matching services
io_iterator_t iter;
kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to get matching services");
return -1;
}

// Get a reference to the first service (assuming it exists)
io_service_t service = IOIteratorNext(iter);
if (!service) {
NSLog(@"No matching service found");
IOObjectRelease(iter);
return -1;
}

// Open a connection to the service
io_connect_t connect;
kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to open service");
IOObjectRelease(service);
IOObjectRelease(iter);
return -1;
}

// Call a method on the service
// Assume the method has a selector of 0, and takes no arguments
kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to call method");
}

// Cleanup
IOServiceClose(connect);
IOObjectRelease(service);
IOObjectRelease(iter);
}
return 0;
}
```
</details>

Існують **інші** функції, які можна використовувати для виклику функцій IOKit, окрім **`IOConnectCallScalarMethod`**, наприклад **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Реверсинг entrypoint драйвера

Наприклад, їх можна отримати з [**образу firmware (ipsw)**](#ipsw). Потім завантажте його у свій улюблений decompiler.

Можна почати декомпіляцію функції **`externalMethod`**, оскільки це функція драйвера, яка отримуватиме виклик і викликатиме правильну функцію:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Цей жахливий demangled виклик означає:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Зверніть увагу, що в попередньому визначенні пропущено параметр **`self`**, правильне визначення має вигляд:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Насправді справжнє визначення можна знайти тут: [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
З цією інформацією ви можете виконати Ctrl+Right -> `Edit function signature` і встановити відомі типи:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Новий декомпільований код виглядатиме так:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Для наступного кроку нам потрібно визначити структуру **`IOExternalMethodDispatch2022`**. Вона має відкритий код у [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), тому її можна визначити:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Тепер, перейшовши за `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`, ви побачите багато даних:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Змініть тип даних на **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

після зміни:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Оскільки, як ми тепер знаємо, тут є **масив із 7 елементів** (перевірте фінальний декомпільований код), натисніть, щоб створити масив із 7 елементів:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Після створення масиву ви побачите всі експортовані функції:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Якщо ви пам’ятаєте, щоб **викликати** **експортовану** функцію з user space, нам не потрібно викликати ім’я функції — натомість використовується **номер селектора**. Тут видно, що селектор **0** — це функція **`initializeDecoder`**, селектор **1** — **`startDecoder`**, селектор **2** — **`initializeEncoder`**...

## Актуальна поверхня атаки IOKit (2023–2025)

- **Перехоплення натискань клавіш через IOHIDFamily** — CVE-2024-27799 (14.5) показала, що клієнт `IOHIDSystem` із надмірними дозволами міг отримувати HID-події навіть за ввімкненого secure input; переконайтеся, що обробники `externalMethod` перевіряють entitlements, а не лише тип user-client.<sup>[2]</sup>
- **Пошкодження пам’яті в IOGPUFamily** — CVE-2024-44197 і CVE-2025-24257 виправили OOB-записи, доступні із sandboxed apps, які передавали некоректні дані змінної довжини до GPU user clients; типовою проблемою є недостатня перевірка меж аргументів `IOConnectCallStructMethod`.<sup>[1]</sup>
- **Моніторинг натискань клавіш у legacy-компонентах** — CVE-2023-42891 (14.2) підтвердила, що HID user clients і надалі залишаються вектором sandbox escape; виконуйте fuzzing будь-якого драйвера, який надає доступ до черг клавіатури/подій.<sup>[3]</sup>

### Поради для швидкого triage і fuzzing

- Перелічіть усі external methods для user client із userland, щоб підготувати дані для fuzzer:
```bash
# list selectors for a service
python3 - <<'PY'
from ioreg import IORegistry
svc = 'IOHIDSystem'
reg = IORegistry()
obj = reg.get_service(svc)
for sel, name in obj.external_methods():
print(f"{sel:02d} {name}")
PY
```
- Під час reverse engineering звертайте увагу на кількість `IOExternalMethodDispatch2022`. Поширений шаблон помилок у нещодавніх CVE — невідповідність `structureInputSize`/`structureOutputSize` фактичній довжині `copyin`, що призводить до heap OOB у `IOConnectCallStructMethod`.
- Досяжність Sandbox і надалі залежить від entitlements. Перш ніж витрачати час на ціль, перевірте, чи дозволений доступ клієнту зі стороннього застосунку:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Для помилок у GPU/iomfb передавання масивів, що перевищують допустимий розмір, через `IOConnectCallMethod` часто достатньо для спричинення некоректної перевірки меж. Мінімальний harness (селектор X) для спричинення плутанини з розміром:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## DriverKit — Драйвери в просторі користувача

### Основна інформація

**DriverKit** — це заміна kernel extensions (kexts) від Apple у просторі користувача, представлена в macOS 10.15. Бінарні файли DriverKit (пакети `.dext`) працюють як процеси у просторі користувача, але взаємодіють безпосередньо з kernel через привілейований інтерфейс IOKit.

Розширення DriverKit керують обладнанням:
- контролерами та пристроями **USB**
- пристроями **Thunderbolt** / PCIe
- пристроями **HID** (клавіатурами, мишами, ігровими контролерами)
- аудіообладнанням
- мережевими інтерфейсами
- пристроями **Serial** і **Block Storage**

На відміну від kexts (для яких потрібне завантаження із вимкненим SIP або notarization), розширення DriverKit встановлюються через `SystemExtensions.framework` і потребують лише **одноразового схвалення користувачем**.

### Виявлення та перелік пристроїв
```bash
# List all installed system extensions (includes DriverKit)
systemextensionsctl list

# Find all DriverKit extension bundles
find / -name "*.dext" -type d 2>/dev/null

# Check a binary's DriverKit entitlements
codesign -d --entitlements - /path/to/binary.dext/binary 2>&1 | grep driverkit

# Common DriverKit entitlements:
# com.apple.developer.driverkit                    — Base DriverKit
# com.apple.developer.driverkit.transport.usb      — USB device access
# com.apple.developer.driverkit.transport.hid      — HID device access
# com.apple.developer.driverkit.transport.pci      — PCIe device access
# com.apple.developer.driverkit.transport.serial   — Serial port access
# com.apple.developer.driverkit.family.networking  — Network interface
# com.apple.developer.driverkit.family.audio       — Audio device
```
### Наслідки для безпеки

> [!WARNING]
> Бінарні файли DriverKit мають **прямий канал зв’язку з kernel**. Надсилання некоректно сформованих повідомлень через цей канал може активувати вразливості kernel. Кожен драйвер реєструє певні класи user-client, а некоректно сформовані виклики `IOConnectCallMethod` можуть спричинити пошкодження пам’яті kernel.

**Поверхня атаки:**
1. **Fuzzing повідомлень kernel IOKit** — кожен user-client DriverKit надає селектори, які можна викликати з user space. Некоректні аргументи активують помилки kernel.
2. **Підміна USB-пристрою** — скомпрометований бінарний файл USB DriverKit може представити профіль шкідливого USB-пристрою (наприклад, імітувати клавіатуру для HID-ін’єкції).
3. **DMA-атаки** — розширення DriverKit для PCIe/Thunderbolt потенційно мають доступ через DMA до фізичної пам’яті.
4. **Persistence** — після встановлення як system extension бінарні файли DriverKit зберігаються після перезавантажень і оновлень застосунків.

### Fuzzing IOKit User-Client DriverKit
```bash
# Enumerate DriverKit user-client classes from entitlements
codesign -d --entitlements - /path/to/binary.dext/binary 2>&1 \
| grep -A5 "com.apple.developer.driverkit.transport"

# List IOService matching for DriverKit drivers
ioreg -l | grep -i "UserClientClass" | sort -u

# Check if the driver's user-client is reachable from a sandboxed app
ioreg -c IOService -r -d 1 | grep -E '"IOClass"|"CFBundleIdentifier"' | head -40

# Minimal fuzzing harness for a DriverKit selector:
```

```c
#include <IOKit/IOKitLib.h>

io_connect_t conn;
// ... open connection to the DriverKit service ...

// Fuzz selector X with oversized struct input
uint8_t buf[0x2000];
memset(buf, 'A', sizeof(buf));
size_t outSz = sizeof(buf);
kern_return_t kr = IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
// If the driver doesn't validate structureInputSize, this causes kernel OOB
```
### CVE DriverKit

| CVE | Опис |
|---|---|
| CVE-2022-26766 | Вразливість USB stack у DriverKit — виконання коду в kernel |
| CVE-2021-30838 | Плутанина типів user-client в IOKit у графічних драйверах |
| CVE-2024-44197 | OOB write в IOGPUFamily через некоректні аргументи DriverKit |

## Посилання

- [1] [Оновлення безпеки Apple – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [2] [Rapid7 – огляд IOHIDFamily CVE-2024-27799](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Оновлення безпеки Apple – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
- [4] [Apple Developer — DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer — System Extensions](https://developer.apple.com/documentation/systemextensions)

{{#include ../../../banners/hacktricks-training.md}}
