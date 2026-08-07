# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

I/O Kit은 XNU kernel의 오픈 소스 객체 지향 **device-driver framework**이며, **동적으로 로드되는 device drivers**를 처리합니다. 이를 통해 kernel에 모듈식 코드를 즉시 추가할 수 있어 다양한 hardware를 지원합니다.

IOKit drivers는 기본적으로 **kernel에서 함수를 export**합니다. 이러한 함수 매개변수의 **types**는 **미리 정의**되어 있으며 검증됩니다. 또한 XPC와 마찬가지로 IOKit은 **Mach messages 위에 구축된** 또 다른 layer일 뿐입니다.

**IOKit XNU kernel code**는 Apple이 [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit)에서 오픈 소스로 공개하고 있습니다. 또한 user space IOKit components도 오픈 소스로 공개되어 있습니다 [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

그러나 **어떤 IOKit drivers도** 오픈 소스로 공개되어 있지 않습니다. 다만 때때로 driver 릴리스에 해당 driver를 더 쉽게 debug할 수 있도록 해주는 symbols가 포함되기도 합니다. [**여기에서 firmware에서 driver extensions를 가져오는 방법을 확인하세요**](#ipsw)**.**

이것은 **C++**로 작성되었습니다. 다음 명령으로 demangled C++ symbols를 가져올 수 있습니다:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **exposed functions**는 **client**가 함수를 호출하려 할 때 **additional security checks**를 수행할 수 있지만, 일반적으로 앱은 **sandbox**에 의해 상호작용할 수 있는 IOKit 함수가 **제한**된다는 점에 유의하세요.

## 드라이버

macOS에서는 다음 위치에 있습니다:

- **`/System/Library/Extensions`**
- OS X 운영 체제에 내장된 KEXT 파일
- **`/Library/Extensions`**
- 3rd party 소프트웨어가 설치한 KEXT 파일

iOS에서는 다음 위치에 있습니다:

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
9번까지 나열된 드라이버는 **주소 0에 로드**됩니다. 즉, 이러한 항목들은 실제 드라이버가 아니라 **kernel의 일부이며 unload할 수 없습니다**.

특정 extension을 찾으려면 다음을 사용할 수 있습니다:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
커널 확장 프로그램을 로드하고 언로드하려면 다음을 수행합니다:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry**는 macOS 및 iOS의 IOKit framework에서 중요한 부분으로, 시스템의 hardware configuration 및 state를 나타내는 database 역할을 합니다. **시스템에 로드된 모든 hardware와 driver 및 서로 간의 관계를 나타내는 object의 계층적 collection**입니다.

cli **`ioreg`**를 사용하면 console에서 IORegistry를 확인할 수 있습니다(iOS에서 특히 유용함).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
**`IORegistryExplorer`**를 [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/)의 **Xcode Additional Tools**에서 다운로드하여 **graphical** interface를 통해 **macOS IORegistry**를 검사할 수 있습니다.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

IORegistryExplorer에서 "planes"는 IORegistry의 여러 객체 간 관계를 구성하고 표시하는 데 사용됩니다. 각 plane은 특정 유형의 관계 또는 시스템 하드웨어와 driver 구성에 대한 특정 view를 나타냅니다. IORegistryExplorer에서 볼 수 있는 일반적인 plane은 다음과 같습니다.

1. **IOService Plane**: 가장 일반적인 plane으로, driver와 nub(driver 간 통신 채널)를 나타내는 service object를 표시합니다. 이러한 객체 간의 provider-client 관계를 보여줍니다.
2. **IODeviceTree Plane**: 시스템에 연결된 장치 간의 물리적 연결을 나타내는 plane입니다. USB 또는 PCI와 같은 bus를 통해 연결된 장치의 hierarchy를 시각화하는 데 자주 사용됩니다.
3. **IOPower Plane**: power management 관점에서 객체와 객체 간 관계를 표시합니다. 어떤 객체가 다른 객체의 power state에 영향을 주는지 보여줄 수 있어 power 관련 문제를 debug하는 데 유용합니다.
4. **IOUSB Plane**: USB 장치와 장치 간 관계에 초점을 맞춘 plane으로, USB hub와 연결된 장치의 hierarchy를 보여줍니다.
5. **IOAudio Plane**: 시스템 내 audio 장치와 장치 간 관계를 나타내는 plane입니다.
6. ...

## Driver Comm Code Example

다음 code는 IOKit service `YourServiceNameHere`에 연결하고 selector 0을 호출합니다.

- 먼저 **`IOServiceMatching`** 및 **`IOServiceGetMatchingServices`**를 호출하여 service를 가져옵니다.
- 그런 다음 **`IOServiceOpen`**을 호출하여 connection을 설정합니다.
- 마지막으로 selector 0을 지정하여 **`IOConnectCallScalarMethod`**로 function을 호출합니다(selector는 호출하려는 function에 할당된 번호입니다).

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

**`IOConnectCallScalarMethod`** 외에도 **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**처럼 IOKit 함수를 호출하는 데 사용할 수 있는 다른 함수들이 있습니다.

## 드라이버 entrypoint reversing

예를 들어 [**firmware image (ipsw)**](#ipsw)에서 이러한 함수를 얻을 수 있습니다. 그런 다음 이를 원하는 decompiler에 로드합니다.

호출을 수신하고 올바른 함수를 호출하는 드라이버 함수인 **`externalMethod`** 함수를 decompiling하는 것부터 시작할 수 있습니다:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

끔찍한 demangled call은 다음을 의미합니다:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
이전 정의에서 **`self`** param이 누락된 점에 유의하세요. 올바른 정의는 다음과 같습니다:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
실제 정의는 [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388)에서 확인할 수 있습니다:
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
이 정보를 사용하면 Ctrl+Right -> `Edit function signature`로 다시 작성하고 알려진 type을 설정할 수 있습니다:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

새로운 decompiled code는 다음과 같습니다:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

다음 단계에서는 **`IOExternalMethodDispatch2022`** struct가 정의되어 있어야 합니다. 이는 [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176)에 opensource로 공개되어 있으며, 다음과 같이 정의할 수 있습니다:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

이제 `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`를 따라가면 많은 data를 볼 수 있습니다:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Data Type을 **`IOExternalMethodDispatch2022:`**로 변경합니다:

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

변경 후:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

그리고 이제 이곳에 **7개 element로 구성된 array**가 있다는 것을 알 수 있으므로(최종 decompiled code 확인), 클릭하여 7개 element의 array를 생성합니다:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

array가 생성되면 모든 exported function을 확인할 수 있습니다:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 기억하시겠지만, user space에서 **exported** function을 **call**하려면 function name을 호출할 필요 없이 **selector number**를 사용하면 됩니다. 여기서 selector **0**은 **`initializeDecoder`** function이고, selector **1**은 **`startDecoder`**, selector **2**는 **`initializeEncoder`**입니다...

## 최근 IOKit attack surface (2023–2025)

- **IOHIDFamily를 통한 keystroke capture** – CVE-2024-27799 (14.5)는 permissive한 `IOHIDSystem` client가 secure input이 활성화된 경우에도 HID event를 가져올 수 있음을 보여주었습니다. `externalMethod` handler가 user-client type만 확인하지 말고 entitlement를 적용하는지 확인해야 합니다.<sup>[[2]](#references)</sup>
- **IOGPUFamily memory corruption** – CVE-2024-44197 및 CVE-2025-24257은 sandboxed app이 GPU user client에 malformed variable-length data를 전달할 때 도달 가능한 OOB write를 수정했습니다. 일반적인 bug는 `IOConnectCallStructMethod` argument에 대한 부실한 bounds 검사입니다.<sup>[[1]](#references)</sup>
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2)은 HID user client가 여전히 sandbox escape vector로 사용될 수 있음을 확인했습니다. keyboard/event queue를 노출하는 driver를 fuzz해야 합니다.<sup>[[3]](#references)</sup>

### 빠른 triage 및 fuzzing 팁

- userland에서 user client의 모든 external method를 열거하여 fuzzer의 seed로 사용합니다:
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
- Reverse할 때는 `IOExternalMethodDispatch2022` counts에 주의해야 합니다. 최근 CVE에서 흔히 나타나는 bug pattern은 `structureInputSize`/`structureOutputSize`와 실제 `copyin` length가 일치하지 않아 `IOConnectCallStructMethod`에서 heap OOB가 발생하는 것입니다.
- Sandbox reachability는 여전히 entitlements에 달려 있습니다. target에 시간을 들이기 전에 third-party app에서 client가 허용되는지 확인하세요:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- GPU/iomfb 버그의 경우, `IOConnectCallMethod`를 통해 oversized arrays를 전달하는 것만으로도 잘못된 bounds를 트리거하기에 충분한 경우가 많습니다. size confusion을 트리거하는 최소 harness(selector X):
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## DriverKit — User-Space Drivers

### 기본 정보

**DriverKit**은 macOS 10.15에 도입된, kernel extensions (kexts)을 대체하는 Apple의 user-space 솔루션입니다. DriverKit 바이너리(`.dext` bundles)는 user-space 프로세스로 실행되지만, privileged IOKit interface를 통해 kernel과 직접 통신합니다.<sup>[[4]](#references)</sup>

DriverKit extensions는 다음 hardware를 관리합니다:
- **USB** controllers 및 devices
- **Thunderbolt** / PCIe devices
- **HID** (keyboards, mice, game controllers)
- **Audio** hardware
- **Networking** interfaces
- **Serial** 및 **Block Storage** devices

SIP-disabled boot 또는 notarization이 필요했던 kexts와 달리, DriverKit extensions는 `SystemExtensions.framework`를 통해 설치되며 **one-time user approval**만 필요합니다.<sup>[[5]](#references)</sup>

### Discovery & Enumeration
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
### 보안 영향

> [!WARNING]
> DriverKit 바이너리는 **kernel에 대한 직접 통신 채널**을 가집니다. 이 채널을 통해 malformed message를 전송하면 kernel vulnerability가 발생할 수 있습니다. 각 driver는 특정 user-client class를 등록하며, malformed `IOConnectCallMethod` 호출은 kernel memory corruption을 유발할 수 있습니다.

**공격 표면:**
1. **Kernel IOKit message fuzzing** — 각 DriverKit user-client는 user space에서 호출할 수 있는 selector를 노출합니다. malformed argument는 kernel bug를 유발합니다.
2. **USB device spoofing** — 손상된 USB DriverKit binary는 malicious USB device profile을 제시할 수 있습니다(예: HID injection을 위해 keyboard로 emulate).
3. **DMA attacks** — PCIe/Thunderbolt DriverKit extension은 physical memory에 대한 잠재적인 DMA access 권한을 가집니다.
4. **Persistence** — system extension으로 설치되면 DriverKit binary는 reboot 및 app update 이후에도 persistence를 유지합니다.

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
### DriverKit CVEs

| CVE | 설명 |
|---|---|
| CVE-2022-26766 | DriverKit USB stack 취약점 — kernel code execution |
| CVE-2021-30838 | graphic drivers의 IOKit user-client type confusion |
| CVE-2024-44197 | 변조된 DriverKit arguments를 통한 IOGPUFamily OOB write |

## 참고 자료

- [1] [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [2] [Rapid7 – IOHIDFamily CVE-2024-27799 summary](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
- [4] [Apple Developer — DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer — System Extensions](https://developer.apple.com/documentation/systemextensions)

{{#include ../../../banners/hacktricks-training.md}}
