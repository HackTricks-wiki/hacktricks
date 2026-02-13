# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

I/O Kit, XNU kernel içinde açık kaynaklı, nesne yönelimli bir **device-driver framework** olup **dynamically loaded device drivers**'ı yönetir. Çeşitli donanımları destekleyerek çekirdeğe modüler kodun anında eklenmesine olanak tanır.

IOKit sürücüleri temelde çekirdekten **export functions from the kernel** sağlar. Bu fonksiyon parametre **types** önceden **predefined** olarak belirlenir ve doğrulanır. Ayrıca, XPC'ye benzer şekilde IOKit, Mach mesajlarının **top of Mach messages** üzerinde bir başka katmandır.

**IOKit XNU kernel code** Apple tarafından şu adreste açık kaynak kodlu olarak yayımlandı: [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Ayrıca, kullanıcı alanı IOKit bileşenleri de açık kaynaklıdır: [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Ancak, **no IOKit drivers** açık kaynaklı değildir. Yine de zaman zaman bir sürücü sürümü, debug etmeyi kolaylaştıran sembollerle birlikte gelebilir. Sürücü uzantılarını firmware'den nasıl [**get the driver extensions from the firmware here**](#ipsw) öğrenebileceğinizi kontrol edin.

Bu **C++** ile yazılmıştır. Demangled C++ sembollerini şu şekilde elde edebilirsiniz:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **exposed functions** bir istemci bir fonksiyonu çağırmaya çalıştığında **ek güvenlik kontrolleri** uygulayabilir; ancak uygulamaların genellikle hangi IOKit fonksiyonlarıyla etkileşime girebilecekleri konusunda **sandbox** ile **sınırlı** olduğunu unutmayın.

## Sürücüler

macOS'ta şu konumlarda bulunurlar:

- **`/System/Library/Extensions`**
- OS X işletim sistemine entegre KEXT dosyaları.
- **`/Library/Extensions`**
- 3. taraf yazılımlar tarafından yüklenen KEXT dosyaları

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
9'a kadar listelenen sürücüler **adres 0'da yüklenmiştir**. Bu, bunların gerçek sürücüler olmadığı, aksine **kernel'in bir parçası oldukları ve kaldırılamayacakları** anlamına gelir.

Belirli uzantıları bulmak için şunu kullanabilirsiniz:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Kernel extensions yüklemek ve kaldırmak için:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

The **IORegistry** macOS ve iOS içindeki IOKit framework'ünün önemli bir parçasıdır ve sistemin donanım yapılandırmasını ve durumunu temsil etmek için bir veritabanı görevi görür. Bu, sistemde yüklü tüm donanımı ve sürücüleri temsil eden nesnelerin **hiyerarşik bir koleksiyonu** ve bunların birbirleriyle olan ilişkileridir.

IORegistry'yi konsoldan incelemek için komut satırı aracı **`ioreg`** ile alabilirsiniz (özellikle iOS için kullanışlı).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
You could download **`IORegistryExplorer`** from **Xcode Additional Tools** from [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) and inspect the **macOS IORegistry** through a **graphical** interface.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

IORegistryExplorer'da, "planes" IORegistry içindeki farklı nesneler arasındaki ilişkileri düzenlemek ve görüntülemek için kullanılır. Her plane, belirli bir ilişki türünü veya sistemin donanım ve driver yapılandırmasının belirli bir görünümünü temsil eder. İşte IORegistryExplorer'da karşılaşabileceğiniz bazı yaygın plane'ler:

1. **IOService Plane**: Bu en genel plandır; driver'ları ve nubs (driver'lar arasındaki iletişim kanalları) temsil eden servis nesnelerini gösterir. Bu nesneler arasındaki provider-client ilişkilerini gösterir.
2. **IODeviceTree Plane**: Bu plane, aygıtlar sisteme bağlandıkça oluşan fiziksel bağlantıları temsil eder. Genellikle USB veya PCI gibi bus'lar üzerinden bağlı aygıtların hiyerarşisini görselleştirmek için kullanılır.
3. **IOPower Plane**: Nesneleri ve bunların güç yönetimi bağlamındaki ilişkilerini gösterir. Hangi nesnelerin diğerlerinin güç durumunu etkilediğini göstererek güçle ilgili sorunların giderilmesinde faydalıdır.
4. **IOUSB Plane**: Özellikle USB cihazlara ve bunların ilişkilerine odaklanır; USB hub'larının ve bağlı cihazların hiyerarşisini gösterir.
5. **IOAudio Plane**: Bu plane, sistem içindeki ses cihazlarını ve bunların ilişkilerini temsil etmek içindir.
6. ...

## Driver Comm Code Example

The following code connects to the IOKit service `YourServiceNameHere` and calls selector 0:

- It first calls **`IOServiceMatching`** and **`IOServiceGetMatchingServices`** to get the service.
- It then establishes a connection calling **`IOServiceOpen`**.
- And it finally calls a function with **`IOConnectCallScalarMethod`** indicating the selector 0 (the selector is the number the function you want to call has assigned).

<details>
<summary>Kullanıcı uzayından bir driver selector çağrısı örneği</summary>
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

IOKit fonksiyonlarını çağırmak için **`IOConnectCallScalarMethod`** dışında kullanılabilecek **diğer** fonksiyonlar da vardır; örneğin **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Sürücü entrypoint'ini tersine mühendislik

Bunları örneğin bir [**firmware image (ipsw)**](#ipsw) dosyasından elde edebilirsiniz. Ardından, favori decompiler'ınıza yükleyin.

**`externalMethod`** fonksiyonunun decompile'ına başlayabilirsiniz; bu, çağrıyı alacak ve doğru fonksiyonu çağıracak sürücü fonksiyonudur:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

O berbat demagled çağrı şu anlama geliyor:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Önceki tanımda **`self`** parametresinin eksik olduğuna dikkat edin; doğru tanım şöyle olacaktır:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Aslında gerçek tanımı şu adreste bulabilirsiniz [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
With this info you can rewrite Ctrl+Right -> `Edit function signature` and set the known types:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

The new decompiled code will look like:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

For the next step we need to have defined the **`IOExternalMethodDispatch2022`** struct. It's opensource in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), you could define it:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Now, following the `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` you can see a lot of data:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Change the Data Type to **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

after the change:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

And as we now in there we have an **array of 7 elements** (check the final decompiled code), click to create an array of 7 elements:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

After the array is created you can see all the exported functions:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> If you remember, to **call** an **exported** function from user space we don't need to call the name of the function, but the **selector number**. Here you can see that the selector **0** is the function **`initializeDecoder`**, the selector **1** is **`startDecoder`**, the selector **2** **`initializeEncoder`**...

## Yakın dönemdeki IOKit saldırı yüzeyi (2023–2025)

- **IOHIDFamily üzerinden tuş vuruşlarını yakalama** – CVE-2024-27799 (14.5) gösterdi ki izin verilmiş bir `IOHIDSystem` client'ı secure input olsa bile HID event'lerini alabiliyordu; `externalMethod` handler'larının sadece user-client tipine değil, entitlements'ı da zorladığından emin olun.
- **IOGPUFamily bellek bozulması** – CVE-2024-44197 ve CVE-2025-24257, yanlış biçimlendirilmiş değişken-uzunlukta veriyi GPU user client'larına ileten sandbox'lanmış uygulamalardan ulaşılabilen OOB yazma hatalarını düzeltti; tipik hata `IOConnectCallStructMethod` argümanları etrafında zayıf sınır kontrolleridir.
- **Legacy tuş vuruşu izleme** – CVE-2023-42891 (14.2) HID user client'larının hâlâ sandbox'tan kaçış vektörü olmaya devam ettiğini doğruladı; klavye/event kuyrukları açığa çıkan herhangi bir driver'ı fuzz'layın.

### Hızlı triage & fuzzing ipuçları

- Bir user client için userland'den tüm external method'ları enumerate ederek bir fuzzer için seed oluşturun:
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
- Tersine mühendislik yaparken `IOExternalMethodDispatch2022` sayımlarına dikkat edin. Son CVE'lerde yaygın bir hata deseni, gerçek `copyin` uzunluğuna kıyasla tutarsız `structureInputSize`/`structureOutputSize` değerleri olup, bunun sonucunda `IOConnectCallStructMethod` içinde heap OOB'ye yol açmasıdır.
- Sandbox erişilebilirliği hâlâ entitlements'a bağlıdır. Bir hedef üzerinde zaman harcamadan önce, third‑party app'ten client'ın izinli olup olmadığını kontrol edin:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- GPU/iomfb hataları için, aşırı büyük dizileri `IOConnectCallMethod` aracılığıyla göndermek genellikle hatalı sınır kontrollerini tetiklemek için yeterlidir. size confusion'ı tetiklemek için minimal harness (selector X):
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## Kaynaklar

- [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [Rapid7 – IOHIDFamily CVE-2024-27799 summary](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
{{#include ../../../banners/hacktricks-training.md}}
