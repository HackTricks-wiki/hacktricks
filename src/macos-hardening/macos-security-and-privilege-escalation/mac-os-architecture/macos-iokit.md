# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

I/O KitはXNU kernelにおけるオープンソースのオブジェクト指向 **device-driver framework** であり、**動的にロードされるdevice drivers** を処理します。これにより、モジュール化されたcodeをkernelにオンザフライで追加でき、多様なhardwareをサポートします。

IOKit driversは基本的に、**kernelからfunctionをexport** します。これらのfunction parameterの **types** は **事前定義** され、検証されます。さらに、XPCと同様に、IOKitも **Mach messagesの上位にある** 別のlayerにすぎません。

**IOKit XNU kernel code** はAppleによって[https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit)でopensource化されています。また、user spaceのIOKit componentsもopensource化されています [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser)。

しかし、**IOKit driversはopensource化されていません**。とはいえ、時々、driverのreleaseにsymbolsが含まれていることがあり、debugが容易になります。[**こちらでfirmwareからdriver extensionsを取得する方法を確認してください**](#ipsw)**。**

これは **C++** で記述されています。次のコマンドでdemangled C++ symbolsを取得できます：
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit の **exposed functions** は、client が function の呼び出しを試みる際に **additional security checks** を実行する可能性があります。ただし、通常、アプリが interact できる IOKit functions は **sandbox** によって **limited** されている点に注意してください。

## Drivers

macOS では、以下に配置されています。

- **`/System/Library/Extensions`**
- OS X operating system に組み込まれた KEXT files
- **`/Library/Extensions`**
- 3rd party software によってインストールされた KEXT files

iOS では、以下に配置されています。

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
9番までは、一覧表示されているドライバは**アドレス0にロード**されています。つまり、これらは実際のドライバではなく、**kernelの一部であり、アンロードできません**。

特定のextensionを見つけるには、次を使用できます:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
kernel extensions をロードおよびアンロードするには、次を実行します。
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry** は macOS と iOS の IOKit framework における重要な部分であり、システムの hardware configuration と state を表す database として機能します。これは、システム上でロードされているすべての hardware と driver、およびそれら相互の関係を表す **object の hierarchical collection** です。

CLI の **`ioreg`** を使用すると、console から IORegistry を取得して調査できます（特に iOS で便利です）。
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
**`IORegistryExplorer`** は、[**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) の **Xcode Additional Tools** から download して、**graphical** interface を通じて **macOS IORegistry** を調査できます。

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

IORegistryExplorer では、「planes」を使用して、IORegistry 内の異なる object 間の関係を整理および表示します。各 plane は、特定の種類の関係、またはシステムの hardware と driver configuration に関する特定の view を表します。IORegistryExplorer でよく見かける plane には、次のようなものがあります。

1. **IOService Plane**: 最も一般的な plane で、driver と nub（driver 間の communication channel）を表す service object を表示します。これらの object 間の provider-client relationship を示します。
2. **IODeviceTree Plane**: device がシステムに接続される際の物理的な接続を表す plane です。USB や PCI などの bus 経由で接続された device の hierarchy を可視化するためによく使用されます。
3. **IOPower Plane**: power management の観点から object とその関係を表示します。どの object が他の object の power state に影響を与えているかを確認でき、power 関連の問題の debugging に役立ちます。
4. **IOUSB Plane**: USB device とその関係に特化した plane で、USB hub と接続された device の hierarchy を表示します。
5. **IOAudio Plane**: システム内の audio device とその関係を表すための plane です。
6. ...

## Driver Comm Code Example

次の code は、IOKit service `YourServiceNameHere` に接続し、selector 0 を call します。

- まず **`IOServiceMatching`** と **`IOServiceGetMatchingServices`** を call して service を取得します。
- 次に、**`IOServiceOpen`** を call して connection を確立します。
- 最後に、**`IOConnectCallScalarMethod`** を使用して function を call し、selector 0 を指定します（selector は、call する function に割り当てられた number です）。

<details>
<summary>driver selector に対する user-space call の例</summary>
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

**`IOConnectScalarMethod`** 以外にも、IOKit functions を呼び出すために使用できる **`IOConnectCallMethod`**、**`IOConnectCallStructMethod`** などの function があります。

## driver entrypoint の reversing

たとえば、これらは [**firmware image (ipsw)**](#ipsw) から取得できます。その後、お気に入りの decompiler に読み込んでください。

**`externalMethod`** function の decompiling から始めるとよいでしょう。これは call を受け取り、正しい function を呼び出す driver function です。

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

このひどい demangled call は次のことを意味します。
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
前の定義では **`self`** パラメータが抜けていることに注意してください。正しい定義は次のとおりです。
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
実際の定義は、[https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388) にあります：
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
この情報を使って、Ctrl+Right → `Edit function signature` を書き換え、既知の型を設定できます。

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

新しい decompiled code は次のようになります。

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

次のステップでは、**`IOExternalMethodDispatch2022`** struct を定義する必要があります。これは [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176) で opensource として公開されているため、次のように定義できます。

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

ここで、`(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` に続く部分を見ると、多くのデータがあります。

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Data Type を **`IOExternalMethodDispatch2022:`** に変更します。

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

変更後:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

また、ここには **7 elements の array** があることが分かるため（最終的な decompiled code を確認してください）、7 elements の array を作成します。

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

array の作成後、すべての exported functions を確認できます。

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 覚えているかもしれませんが、user space から **exported** function を**呼び出す**には、function の名前を呼び出す必要はなく、**selector number** を使います。ここでは、selector **0** が **`initializeDecoder`** function、selector **1** が **`startDecoder`**、selector **2** が **`initializeEncoder`** であることが分かります...

## Recent IOKit attack surface (2023–2025)

- **IOHIDFamily 経由の keystroke capture** – CVE-2024-27799 (14.5) により、permissive な `IOHIDSystem` client は secure input が有効な場合でも HID events を取得できることが示されました。`externalMethod` handlers が user-client type だけでなく entitlements も強制するようにしてください。<sup>[[2]](#references)</sup>
- **IOGPUFamily の memory corruption** – CVE-2024-44197 および CVE-2025-24257 により、sandboxed apps から到達可能で、malformed な variable-length data を GPU user clients に渡すことで発生する OOB writes が修正されました。通常の bug は、`IOConnectCallStructMethod` arguments 周辺の bounds 不備です。<sup>[[1]](#references)</sup>
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) により、HID user clients が引き続き sandbox-escape vector となることが確認されました。keyboard/event queues を公開する driver は fuzz してください。<sup>[[3]](#references)</sup>

### Quick triage & fuzzing tips

- userland から user client のすべての external methods を列挙し、fuzzer の seed にします。
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
- リバース時は、`IOExternalMethodDispatch2022` の件数に注意してください。最近の CVE でよく見られるバグパターンは、`structureInputSize`/`structureOutputSize` と実際の `copyin` 長が一致していないことです。これにより、`IOConnectCallStructMethod` で heap OOB が発生します。
- Sandbox からの到達可能性は、依然として entitlements に左右されます。対象に時間をかける前に、third-party app からクライアントの利用が許可されているか確認してください：
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- GPU/iomfb bugsでは、`IOConnectCallMethod`を介してoversized arraysを渡すだけで、bad boundsをtriggerできることが多いです。size confusionをtriggerするMinimal harness（selector X）：
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## DriverKit — User-Space Drivers

### 基本情報

**DriverKit** は、macOS 10.15 で導入された、kernel extensions（kexts）に代わる Apple の user-space 実装です。DriverKit バイナリ（`.dext` bundles）は user-space processes として実行されますが、特権 IOKit interface を介して kernel と直接通信します。<sup>[[4]](#references)</sup>

DriverKit extensions は hardware を管理します:
- **USB** controllers and devices
- **Thunderbolt** / PCIe devices
- **HID** (keyboards, mice, game controllers)
- **Audio** hardware
- **Networking** interfaces
- **Serial** and **Block Storage** devices

SIP-disabled boot または notarization が必要だった kexts とは異なり、DriverKit extensions は `SystemExtensions.framework` 経由でインストールされ、必要なのは **one-time user approval** のみです。<sup>[[5]](#references)</sup>

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
### セキュリティ上の影響

> [!WARNING]
> DriverKit binaries have **kernel との直接通信 channel** を持ちます。この channel を通じて malformed messages を送信すると、kernel vulnerabilities を trigger できる可能性があります。各 driver は特定の user-client classes を登録し、malformed `IOConnectCallMethod` calls によって kernel memory corruption が発生する可能性があります。

**攻撃対象領域:**
1. **Kernel IOKit message fuzzing** — 各 DriverKit user-client は user space から call 可能な selectors を expose します。Malformed arguments により kernel bugs が trigger されます。
2. **USB device spoofing** — Compromised USB DriverKit binary は malicious USB device profile を提示できます（例：HID injection 用の keyboard を emulate）。
3. **DMA attacks** — PCIe/Thunderbolt DriverKit extensions は physical memory への DMA access を持つ可能性があります。
4. **Persistence** — system extension として一度 install されると、DriverKit binaries は reboots や app updates 後も persist します。

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

| CVE | 説明 |
|---|---|
| CVE-2022-26766 | DriverKit USB stack の脆弱性 — kernel code execution |
| CVE-2021-30838 | graphic drivers における IOKit user-client type confusion |
| CVE-2024-44197 | 不正な DriverKit arguments を介した IOGPUFamily OOB write |

## 参考資料

- [1] [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [2] [Rapid7 – IOHIDFamily CVE-2024-27799 の概要](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
- [4] [Apple Developer — DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer — System Extensions](https://developer.apple.com/documentation/systemextensions)

{{#include ../../../banners/hacktricks-training.md}}
