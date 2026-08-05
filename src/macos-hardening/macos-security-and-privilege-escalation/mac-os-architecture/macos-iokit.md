# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

I/O Kit, XNU kernel içindeki açık kaynaklı, nesne yönelimli bir **device-driver framework**'üdür ve **dinamik olarak yüklenen device driver**'ları yönetir. Modüler kodun kernel'e anlık olarak eklenmesine olanak tanır ve çeşitli donanımları destekler.

IOKit driver'ları temel olarak **kernel'den fonksiyonlar export eder**. Bu fonksiyonların parametre **türleri** **önceden tanımlanmıştır** ve doğrulanır. Ayrıca, XPC'ye benzer şekilde IOKit de **Mach mesajlarının üzerinde** çalışan başka bir katmandır.

**IOKit XNU kernel kodu**, Apple tarafından [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit) adresinde open source olarak sunulmaktadır. Ayrıca, user space IOKit bileşenleri de [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser) adresinde open source olarak sunulmaktadır.

Ancak **hiçbir IOKit driver'ı** open source değildir. Bununla birlikte, zaman zaman bir driver sürümü, driver'ın debug edilmesini kolaylaştıran sembollerle birlikte yayınlanabilir. [**Firmware'den driver extension'larını nasıl alacağınızı buradan öğrenin**](#ipsw)**.**

**C++** ile yazılmıştır. Demangled C++ sembollerini şu şekilde alabilirsiniz:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **exposed functions**, bir istemci bir işlevi çağırmayı denediğinde **additional security checks** gerçekleştirebilir; ancak uygulamaların genellikle hangi IOKit işlevleriyle etkileşime girebileceği konusunda **sandbox** tarafından **limited** olduğunu unutmayın.

## Drivers

macOS'ta şu konumlarda bulunurlar:

- **`/System/Library/Extensions`**
- OS X işletim sistemine yerleşik KEXT dosyaları.
- **`/Library/Extensions`**
- 3rd party software tarafından yüklenen KEXT dosyaları

iOS'ta şu konumda bulunurlar:

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
9 numarasına kadar listelenen driver'lar **0 adresine yüklenmiştir**. Bu, bunların gerçek driver'lar olmadığı, **kernel'in bir parçası oldukları ve unload edilemeyecekleri** anlamına gelir.

Belirli extension'ları bulmak için şunu kullanabilirsiniz:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Kernel extension'ları yüklemek ve kaldırmak için:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry**, macOS ve iOS'ta sistemin donanım yapılandırmasını ve durumunu temsil eden bir veritabanı olarak görev yapan IOKit framework'ünün kritik bir parçasıdır. **Sistemde yüklü olan tüm donanım ve driver'ları ve bunların birbirleriyle olan ilişkilerini temsil eden hiyerarşik bir nesne koleksiyonudur.**

IORegistry'yi, konsoldan incelemek için **`ioreg`** CLI aracını kullanarak edinebilirsiniz (özellikle iOS için kullanışlıdır).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
**`IORegistryExplorer`**'ı [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) adresindeki **Xcode Additional Tools** üzerinden indirebilir ve **macOS IORegistry**'yi **grafiksel** bir arayüz aracılığıyla inceleyebilirsiniz.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

IORegistryExplorer'da "planes", IORegistry'deki farklı nesneler arasındaki ilişkileri düzenlemek ve görüntülemek için kullanılır. Her plane, belirli bir ilişki türünü veya sistemin donanım ve driver yapılandırmasının belirli bir görünümünü temsil eder. IORegistryExplorer'da karşılaşabileceğiniz yaygın plane'lerden bazıları şunlardır:

1. **IOService Plane**: Bu, driver'ları ve nub'ları (driver'lar arasındaki iletişim kanalları) temsil eden service nesnelerini görüntüleyen en genel plane'dir. Bu nesneler arasındaki provider-client ilişkilerini gösterir.
2. **IODeviceTree Plane**: Bu plane, cihazların sisteme bağlanma şekillerine göre aralarındaki fiziksel bağlantıları temsil eder. Genellikle USB veya PCI gibi bus'lar üzerinden bağlanan cihazların hiyerarşisini görselleştirmek için kullanılır.
3. **IOPower Plane**: Nesneleri ve aralarındaki ilişkileri power management açısından görüntüler. Hangi nesnelerin diğerlerinin power state'ini etkilediğini gösterebilir; power ile ilgili sorunlarda debugging için kullanışlıdır.
4. **IOUSB Plane**: Özellikle USB cihazlarına ve aralarındaki ilişkilere odaklanır; USB hub'larının ve bağlı cihazların hiyerarşisini gösterir.
5. **IOAudio Plane**: Bu plane, audio cihazlarını ve sistem içindeki ilişkilerini temsil eder.
6. ...

## Driver Comm Code Example

Aşağıdaki code, `YourServiceNameHere` IOKit service'ine bağlanır ve selector 0'ı çağırır:

- Önce service'i almak için **`IOServiceMatching`** ve **`IOServiceGetMatchingServices`** çağrılır.
- Ardından **`IOServiceOpen`** çağrısıyla bir bağlantı kurulur.
- Son olarak, selector 0'ı belirterek **`IOConnectCallScalarMethod`** ile bir function çağrılır (selector, çağırmak istediğiniz function'a atanmış numaradır).

<details>
<summary>Example user-space call to a driver selector</summary>
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

**`IOConnectCallScalarMethod`** dışında **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`** gibi IOKit function'larını çağırmak için kullanılabilecek **başka** function'lar da vardır...

## Driver entrypoint'ini reverse etme

Bunları örneğin bir [**firmware image (ipsw)**](#ipsw) üzerinden elde edebilirsiniz. Ardından bunları tercih ettiğiniz decompiler'a yükleyin.

Çağrıyı alacak ve doğru function'ı çağıracak driver function'ı olduğundan, **`externalMethod`** function'ını decompile etmeye başlayabilirsiniz:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Bu korkunç demangled call şu anlama gelir:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Önceki tanımda **`self`** parametresinin atlandığına dikkat edin; doğru tanım şöyle olmalıdır:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Asıl tanımı [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388) adresinde bulabilirsiniz:
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Bu bilgilerle Ctrl+Right -> `Edit function signature` seçeneğini yeniden yazabilir ve bilinen türleri ayarlayabilirsiniz:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Yeni decompiled kod şu şekilde görünecektir:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Sonraki adım için **`IOExternalMethodDispatch2022`** struct'ının tanımlanmış olması gerekir. Bu struct, [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176) adresinde opensource olarak bulunur; şu şekilde tanımlayabilirsiniz:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Şimdi `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` ifadesini takip ettiğinizde çok sayıda veri görebilirsiniz:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Data Type'ı **`IOExternalMethodDispatch2022:`** olarak değiştirin:

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

değişiklikten sonra:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Burada **7 elementten oluşan bir array** bulunduğunu bildiğimize göre (nihai decompiled kodu kontrol edin), 7 elementlik bir array oluşturmak için tıklayın:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Array oluşturulduktan sonra tüm exported function'ları görebilirsiniz:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Hatırlarsanız, user space'ten bir **exported** function'ı **call** etmek için function'ın adını çağırmamız gerekmez; bunun yerine **selector number** kullanırız. Burada selector **0**'ın **`initializeDecoder`**, selector **1**'in **`startDecoder`**, selector **2**'nin ise **`initializeEncoder`** function'ı olduğunu görebilirsiniz...

## Güncel IOKit attack surface (2023–2025)

- **IOHIDFamily üzerinden keystroke capture** – CVE-2024-27799 (14.5), izinleri fazla geniş olan bir `IOHIDSystem` client'ının secure input etkin olsa bile HID event'lerini alabileceğini gösterdi; `externalMethod` handler'larının yalnızca user-client type'ına değil, entitlement'lara da göre kontrol uyguladığından emin olun.<sup>[[2]](#references)</sup>
- **IOGPUFamily memory corruption** – CVE-2024-44197 ve CVE-2025-24257, sandboxed app'lerden GPU user client'larına gönderilen hatalı variable-length data nedeniyle erişilebilen OOB write'ları düzeltti; olağan bug, `IOConnectCallStructMethod` argümanları etrafındaki yetersiz bounds kontrolleridir.<sup>[[1]](#references)</sup>
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2), HID user client'larının sandbox-escape vector'ı olmaya devam ettiğini doğruladı; keyboard/event queue'ları sunan tüm driver'larda fuzzing yapın.<sup>[[3]](#references)</sup>

### Hızlı triage ve fuzzing ipuçları

- Bir fuzzer'ı seed etmek için userland'den bir user client için tüm external method'ları enumerate edin:
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
- Tersine mühendislik yaparken `IOExternalMethodDispatch2022` count değerlerine dikkat edin. Son CVE'lerde yaygın bir bug pattern, `structureInputSize`/`structureOutputSize` ile gerçek `copyin` length değerlerinin tutarsız olmasıdır; bu durum `IOConnectCallStructMethod` içinde heap OOB'ye yol açabilir.
- Sandbox erişilebilirliği hâlâ entitlements'a bağlıdır. Bir hedef üzerinde zaman harcamadan önce client'a third-party app üzerinden izin verilip verilmediğini kontrol edin:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- GPU/iomfb bug'larında, `IOConnectCallMethod` üzerinden aşırı büyük diziler geçirmek genellikle hatalı sınır denetimlerini tetiklemek için yeterlidir. Boyut karmaşasını tetikleyen minimal harness (selector X):
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## DriverKit — Kullanıcı Alanı Sürücüleri

### Temel Bilgiler

**DriverKit**, macOS 10.15 ile kullanıma sunulan, Apple'ın kernel extension'ların (kext'ler) kullanıcı alanındaki alternatifidir. DriverKit binary'leri (`.dext` bundle'ları) kullanıcı alanı işlemleri olarak çalışır, ancak ayrıcalıklı bir IOKit arayüzü üzerinden kernel ile doğrudan iletişim kurar.

DriverKit extension'ları donanımı yönetir:
- **USB** denetleyicileri ve cihazları
- **Thunderbolt** / PCIe cihazları
- **HID** (klavyeler, fareler, oyun kumandaları)
- **Audio** donanımı
- **Networking** arayüzleri
- **Serial** ve **Block Storage** cihazları

SIP devre dışı bırakılmış boot veya notarization gerektiren kext'lerin aksine, DriverKit extension'ları `SystemExtensions.framework` üzerinden yüklenir ve yalnızca **bir kerelik kullanıcı onayı** gerektirir.

### Keşif ve Numaralandırma
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
### Güvenlik Etkileri

> [!WARNING]
> DriverKit binaries have a **direct communication channel to the kernel**. Bu kanal üzerinden malformed messages göndermek kernel vulnerabilities tetikleyebilir. Her driver belirli user-client classes kaydeder ve malformed `IOConnectCallMethod` çağrıları kernel memory corruption'a neden olabilir.

**Saldırı yüzeyi:**
1. **Kernel IOKit message fuzzing** — Her DriverKit user-client, user space'ten çağrılabilen selector'lar sunar. Malformed arguments kernel bugs tetikler.
2. **USB device spoofing** — Compromised bir USB DriverKit binary, malicious bir USB device profile sunabilir (ör. HID injection için keyboard taklidi yapabilir).
3. **DMA attacks** — PCIe/Thunderbolt DriverKit extensions, physical memory'ye potansiyel DMA erişimine sahiptir.
4. **Persistence** — DriverKit binaries, system extension olarak yüklendikten sonra reboot'lar ve app updates boyunca kalıcı olur.

### DriverKit IOKit User-Client Fuzzing
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
### DriverKit CVE'leri

| CVE | Açıklama |
|---|---|
| CVE-2022-26766 | DriverKit USB stack açığı — kernel code execution |
| CVE-2021-30838 | Grafik driver'larında IOKit user-client type confusion |
| CVE-2024-44197 | Hatalı DriverKit argümanları aracılığıyla IOGPUFamily OOB write |

## Referanslar

- [1] [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [2] [Rapid7 – IOHIDFamily CVE-2024-27799 özeti](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
- [4] [Apple Developer — DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer — Sistem Uzantıları](https://developer.apple.com/documentation/systemextensions)

{{#include ../../../banners/hacktricks-training.md}}
