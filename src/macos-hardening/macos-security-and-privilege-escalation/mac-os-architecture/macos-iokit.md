# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

I/O Kit — це фреймворк драйверів пристроїв з відкритим кодом, об'єктно-орієнтований у ядрі XNU, що обробляє **динамічно завантажувані драйвери пристроїв**. Він дозволяє додавати модульний код у ядро на льоту, підтримуючи різне обладнання.

IOKit драйвери, по суті, **експортують функції з ядра**. Типи параметрів цих функцій **передвизначені** і перевіряються. Крім того, подібно до XPC, IOKit — це ще один шар **поверх Mach messages**.

**IOKit XNU kernel code** опубліковано Apple як open-source за адресою [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Крім того, компоненти IOKit у просторі користувача також доступні з відкритим кодом: [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Однак **жодні IOKit драйвери** не є з відкритим кодом. Водночас іноді реліз драйвера може містити символи, що полегшують його відлагодження. Дізнайтеся, як [**get the driver extensions from the firmware here**](#ipsw)**.**

Він написаний на **C++**. Ви можете отримати демангловані символи C++ за допомогою:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **відкриті функції** можуть виконувати **додаткові перевірки безпеки**, коли клієнт намагається викликати функцію, але зауважте, що додатки зазвичай **обмежені** **sandbox** щодо того, з якими функціями IOKit вони можуть взаємодіяти.

## Драйвери

У macOS вони розташовані у:

- **`/System/Library/Extensions`**
- KEXT файли, вбудовані в операційну систему OS X.
- **`/Library/Extensions`**
- KEXT файли, встановлені стороннім програмним забезпеченням

У iOS вони розташовані у:

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
До номера 9 перелічені драйвери **завантажені за адресою 0**. Це означає, що це не реальні драйвери, а **частина ядра, і їх не можна вивантажити**.

Щоб знайти конкретні розширення, ви можете використати:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Щоб завантажити та розвантажити kernel extensions, виконайте:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

The **IORegistry** — критично важлива частина IOKit фреймворку в macOS та iOS, яка слугує базою даних для представлення конфігурації апаратного забезпечення та стану системи. Це **ієрархічна колекція об'єктів, що представляють усе апаратне забезпечення та драйвери**, завантажені в систему, та їхні взаємозв'язки.

Ви можете отримати IORegistry за допомогою cli **`ioreg`** для перегляду в консолі (особливо корисно для iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
You could download **`IORegistryExplorer`** from **Xcode Additional Tools** from [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) and inspect the **macOS IORegistry** through a **graphical** interface.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

У IORegistryExplorer «planes» використовуються для організації та відображення взаємозв'язків між різними об'єктами в IORegistry. Кожна «plane» представляє певний тип зв'язку або окремий вигляд конфігурації апаратного забезпечення та драйверів системи. Нижче наведені деякі з поширених «planes», які ви можете зустріти в IORegistryExplorer:

1. **IOService Plane**: Це найзагальніша plane, яка відображає service-об'єкти, що представляють драйвери та nubs (канали зв'язку між драйверами). Вона показує provider-client відносини між цими об'єктами.
2. **IODeviceTree Plane**: Ця plane представляє фізичні з'єднання між пристроями в міру їх підключення до системи. Її часто використовують для візуалізації ієрархії пристроїв, підключених через шини, такі як USB або PCI.
3. **IOPower Plane**: Відображає об'єкти та їхні взаємозв'язки в контексті керування енергоспоживанням. Може показувати, які об'єкти впливають на стан живлення інших, що корисно для налагодження проблем, пов'язаних з енергоспоживанням.
4. **IOUSB Plane**: Спеціально зосереджена на USB-пристроях та їхніх взаємозв'язках, показуючи ієрархію USB-хабів і підключених пристроїв.
5. **IOAudio Plane**: Ця plane призначена для представлення аудіопристроїв та їхніх взаємозв'язків у системі.
6. ...

## Driver Comm Code Example

The following code connects to the IOKit service `YourServiceNameHere` and calls selector 0:

- It first calls **`IOServiceMatching`** and **`IOServiceGetMatchingServices`** to get the service.
- It then establishes a connection calling **`IOServiceOpen`**.
- And it finally calls a function with **`IOConnectCallScalarMethod`** indicating the selector 0 (the selector is the number the function you want to call has assigned).

<details>
<summary>Приклад виклику селектора драйвера з простору користувача</summary>
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

Є **інші** функції, які можна використовувати для виклику IOKit-функцій, окрім **`IOConnectCallScalarMethod`**, наприклад **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Реверсування точки входу драйвера

Ви можете отримати їх, наприклад, з [**firmware image (ipsw)**](#ipsw). Потім завантажте його у ваш улюблений декомпілятор.

Ви можете почати декомпіляцію функції **`externalMethod`**, оскільки це функція драйвера, яка приймає виклик і викликає відповідну функцію:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Цей деманглований виклик означає:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Зверніть увагу, що в попередньому визначенні параметр **`self`** пропущено; правильне визначення було б:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Насправді, ви можете знайти реальне визначення за цим посиланням [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
З цією інформацією ви можете використовувати Ctrl+Right -> `Edit function signature` і встановити відомі типи:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Новий декомпільований код виглядатиме так:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

На наступному кроці нам потрібно мати визначену структуру **`IOExternalMethodDispatch2022`**. Вона з відкритим кодом за адресою [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), ви можете визначити її так:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Тепер, слідуючи за `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`, ви бачите багато даних:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Змініть тип даних на **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

після зміни:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

І як ви бачите, там у нас є **масив із 7 елементів** (перевірте фінальний декомпільований код), натисніть, щоб створити масив із 7 елементів:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Після створення масиву ви побачите всі exported functions:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Якщо ви пам'ятаєте, щоб **call** an **exported** function з user space, нам не потрібно викликати ім'я функції, а використовується **selector number**. Тут ви бачите, що selector **0** — це функція **`initializeDecoder`**, selector **1** — **`startDecoder`**, selector **2** — **`initializeEncoder`**...

## Останні вектори атак IOKit (2023–2025)

- **Keystroke capture via IOHIDFamily** – CVE-2024-27799 (14.5) показав, що дозволений клієнт `IOHIDSystem` міг захоплювати події HID навіть при secure input; переконайтеся, що обробники `externalMethod` перевіряють entitlements, а не лише тип user-client.
- **IOGPUFamily memory corruption** – CVE-2024-44197 та CVE-2025-24257 усунули OOB writes, до яких могли дістатися sandboxed apps, що передавали пошкоджені змінної довжини дані GPU user clients; звична помилка — недостатні перевірки меж навколо аргументів `IOConnectCallStructMethod`.
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) підтвердив, що HID user clients залишаються вектором для sandbox-escape; fuzz будь-який драйвер, що експонує keyboard/event queues.

### Quick triage & fuzzing tips

- Перелічіть всі external methods для user client з userland, щоб ініціалізувати fuzzer:
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
- When reversing, зверніть увагу на кількість `IOExternalMethodDispatch2022`. Поширений шаблон багу в останніх CVE — це несумісність `structureInputSize`/`structureOutputSize` з фактичною довжиною `copyin`, що призводить до heap OOB у `IOConnectCallStructMethod`.
- Sandbox reachability все ще залежить від entitlements. Перед тим, як витрачати час на ціль, перевірте, чи клієнт дозволений для third‑party app:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Для багів GPU/iomfb, передача занадто великих масивів через `IOConnectCallMethod` часто достатня, щоб викликати неправильну перевірку меж. Мінімальний harness (selector X) для виклику size confusion:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## Посилання

- [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [Rapid7 – IOHIDFamily CVE-2024-27799 summary](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
{{#include ../../../banners/hacktricks-training.md}}
