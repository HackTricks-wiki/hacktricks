# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

The I/O Kit은 XNU 커널의 오픈 소스 객체 지향 **디바이스 드라이버 프레임워크**로, **동적으로 로드되는 디바이스 드라이버들**을 처리합니다. 이는 모듈식 코드를 커널에 실시간으로 추가할 수 있게 해주어 다양한 하드웨어를 지원합니다.

IOKit 드라이버는 기본적으로 커널에서 **함수를 내보냅니다**. 이들 함수 파라미터 **타입**은 **사전 정의되어** 있으며 검증됩니다. 또한 XPC와 마찬가지로, IOKit은 **Mach messages 위의** 또 다른 레이어일 뿐입니다.

**IOKit XNU kernel code**는 Apple에서 [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit)에 오픈소스로 공개되어 있습니다. 또한 사용자 공간 IOKit 컴포넌트들도 [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser)에서 오픈소스로 제공됩니다.

하지만, **IOKit 드라이버는 오픈소스가 아닙니다**. 다만 가끔 드라이버 릴리스에 디버깅을 쉽게 해주는 심볼이 포함되어 나오는 경우가 있습니다. 방법을 확인하려면 [**get the driver extensions from the firmware here**](#ipsw)**.**

이는 **C++**로 작성되어 있습니다. demangled C++ 심볼은 다음 명령으로 얻을 수 있습니다:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **노출된 함수**는 클라이언트가 함수를 호출하려 할 때 **추가적인 보안 검사**를 수행할 수 있지만, 앱은 보통 IOKit 함수와 상호작용할 수 있는 범위가 **sandbox**에 의해 **제한**된다는 점에 유의하세요.

## 드라이버

macOS에서는 다음 위치에 있습니다:

- **`/System/Library/Extensions`**
- OS X 운영체제에 내장된 KEXT 파일.
- **`/Library/Extensions`**
- 서드파티 소프트웨어에 의해 설치된 KEXT 파일

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
숫자 9까지 나열된 drivers는 **loaded in the address 0**입니다. 이는 그것들이 실제 drivers가 아니라 **part of the kernel and they cannot be unloaded**라는 뜻입니다.

특정 extensions를 찾기 위해 다음을 사용할 수 있습니다:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
커널 익스텐션을 로드하고 언로드하려면:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry**는 macOS와 iOS의 IOKit 프레임워크에서 시스템의 하드웨어 구성과 상태를 표현하는 데이터베이스 역할을 하는 중요한 부분입니다.  
이는 **시스템에 로드된 모든 하드웨어와 드라이버를 나타내는 객체들의 계층적 컬렉션**이며, 이들 간의 관계를 나타냅니다.

콘솔에서 검사하려면 cli **`ioreg`**를 사용해 IORegistry를 가져올 수 있습니다 (특히 iOS에서 유용).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
**`IORegistryExplorer`**는 [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/)에서 제공되는 **Xcode Additional Tools**에 포함되어 있으며, 이를 다운로드하여 **macOS IORegistry**를 그래픽 인터페이스로 살펴볼 수 있습니다.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

IORegistryExplorer에서는 "planes"가 IORegistry의 서로 다른 객체들 간의 관계를 정리하고 표시하는 데 사용됩니다. 각 plane은 특정 관계 유형이나 시스템의 하드웨어 및 드라이버 구성의 특정 보기를 나타냅니다. 다음은 IORegistryExplorer에서 자주 볼 수 있는 일반적인 planes입니다:

1. **IOService Plane**: 가장 일반적인 plane으로, 드라이버와 nubs(드라이버 간 통신 채널)를 나타내는 service 객체들을 표시합니다. 이들 객체 간의 provider-client 관계를 보여줍니다.
2. **IODeviceTree Plane**: 장치들이 시스템에 연결될 때의 물리적 연결을 나타냅니다. USB나 PCI 같은 버스를 통해 연결된 장치들의 계층 구조를 시각화할 때 자주 사용됩니다.
3. **IOPower Plane**: 전원 관리 측면에서 객체들과 그 관계를 표시합니다. 어떤 객체가 다른 객체의 전원 상태에 영향을 주는지 보여주어 전원 관련 문제 디버깅에 유용합니다.
4. **IOUSB Plane**: USB 장치와 그 관계에 특화되어 있으며, USB 허브와 연결된 장치들의 계층 구조를 보여줍니다.
5. **IOAudio Plane**: 시스템 내 오디오 장치와 그 관계를 나타내는 plane입니다.
6. ...

## 드라이버 통신 코드 예제

다음 코드는 IOKit 서비스 `YourServiceNameHere`에 연결하고 selector 0을 호출합니다:

- 먼저 **`IOServiceMatching`**과 **`IOServiceGetMatchingServices`**를 호출하여 서비스를 찾습니다.
- 그런 다음 **`IOServiceOpen`**을 호출해 연결을 맺습니다.
- 마지막으로 선택자(selector) 0을 지정하여 **`IOConnectCallScalarMethod`**로 함수를 호출합니다 (선택자(selector)는 호출하려는 함수에 할당된 번호입니다).

<details>
<summary>드라이버 선택자(selector)에 대한 사용자 공간 호출 예시</summary>
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

IOKit 함수를 호출하는 데 **다른** 함수들이 있으며, **`IOConnectCallScalarMethod`** 외에도 **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`** 같은 것들이 있습니다...

## Reversing driver entrypoint

예를 들어 이러한 것들은 [**firmware image (ipsw)**](#ipsw)에서 얻을 수 있습니다. 그런 다음, 선호하는 디컴파일러에 로드하세요.

이 호출을 수신하고 올바른 함수를 호출하는 드라이버 함수이므로 **`externalMethod`** 함수를 디컴파일하는 것부터 시작할 수 있습니다:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

그 난해하게 demagled된 호출은 다음을 의미합니다:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
이전 정의에서 **`self`** 매개변수가 빠진 것을 주의하세요, 올바른 정의는 다음과 같습니다:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
실제 정의는 다음에서 확인할 수 있습니다: [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
이 정보를 사용하면 Ctrl+Right -> `Edit function signature`를 다시 작성하고 알려진 타입을 설정할 수 있습니다:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

새로 디컴파일된 코드는 다음과 같습니다:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

다음 단계에서는 **`IOExternalMethodDispatch2022`** struct가 정의되어 있어야 합니다. 해당 구조체는 오픈소스로 [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176)에 있으니, 다음과 같이 정의할 수 있습니다:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

이제 `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`를 따라가면 많은 데이터를 볼 수 있습니다:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

데이터 타입을 **`IOExternalMethodDispatch2022:`** 로 변경하세요:

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

변경 후:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

그리고 그 안에는 **7개 요소의 배열**이 있습니다(최종 디컴파일 코드를 확인하세요). 7개의 요소 배열을 만들기 위해 클릭하세요:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

배열이 생성되면 모든 exported 함수를 볼 수 있습니다:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 기억하시겠지만, 유저스페이스에서 **exported** 함수를 호출할 때 함수 이름을 직접 호출할 필요는 없고 **셀렉터 번호(selector number)** 를 사용합니다. 여기서 셀렉터 **0**은 함수 **`initializeDecoder`**, 셀렉터 **1**은 **`startDecoder`**, 셀렉터 **2**는 **`initializeEncoder`**... 입니다.

## 최근 IOKit 공격 표면 (2023–2025)

- **Keystroke capture via IOHIDFamily** – CVE-2024-27799 (14.5)은 권한이 관대한 `IOHIDSystem` 클라이언트가 secure input이 활성화된 상태에서도 HID 이벤트를 훔칠 수 있음을 보여주었습니다; `externalMethod` 핸들러는 user-client 타입만 확인하는 대신 entitlements를 강제 확인해야 합니다.
- **IOGPUFamily memory corruption** – CVE-2024-44197 및 CVE-2025-24257은 잘못된 가변 길이 데이터를 GPU 유저 클라이언트에 전달하는 샌드박스 앱에서 도달 가능한 OOB 쓰기를 수정했습니다; 일반적인 버그는 `IOConnectCallStructMethod` 인수 주변의 경계 검사 부족입니다.
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2)은 HID user clients가 여전히 샌드박스 탈출 벡터임을 확인했습니다; keyboard/event queues를 노출하는 드라이버는 모두 fuzz하세요.

### Quick triage & fuzzing tips

- 유저랜드에서 user client의 모든 external methods를 열거해 fuzzer를 시드하세요:
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
- When reversing, `IOExternalMethodDispatch2022` counts에 주의하세요. 최근 CVE들에서 흔한 버그 패턴은 `structureInputSize`/`structureOutputSize`가 실제 `copyin` 길이와 불일치하여 `IOConnectCallStructMethod`에서 heap OOB를 초래합니다.
- Sandbox reachability는 여전히 entitlements에 좌우됩니다. 타깃에 시간을 투자하기 전에, 클라이언트가 서드파티 앱에서 허용되는지 확인하세요:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
GPU/iomfb bugs의 경우, `IOConnectCallMethod`를 통해 과도하게 큰 배열을 전달하는 것만으로도 종종 잘못된 경계를 유발합니다. size confusion을 유발하는 최소 하니스 (selector X):
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## 참고 문헌

- [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [Rapid7 – IOHIDFamily CVE-2024-27799 summary](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
{{#include ../../../banners/hacktricks-training.md}}
