# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

I/O Kit は XNU kernel におけるオープンソースのオブジェクト指向 **device-driver framework** であり、**動的にロードされる device drivers** を処理します。これにより、モジュール式のコードを kernel にオンザフライで追加でき、多様なハードウェアをサポートします。

IOKit drivers は基本的に **kernel から関数を export** します。これらの関数パラメータの **types** は **事前定義** され、検証されます。さらに、XPC と同様に、IOKit は **Mach messages** の上に構築された別のレイヤーにすぎません。

**IOKit XNU kernel code** は Apple によって [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit) でオープンソース化されています。また、user space の IOKit components も [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser) でオープンソース化されています。

ただし、**IOKit drivers は一切オープンソース化されていません**。とはいえ、場合によっては、driver の release にデバッグを容易にする symbols が含まれていることがあります。[**ここで firmware から driver extensions を取得する方法を確認してください**](#ipsw)**。**

これは **C++** で記述されています。次の方法で demangled C++ symbols を取得できます。
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **exposed functions** は、クライアントが関数を呼び出そうとした際に **追加のセキュリティチェック** を実行する可能性があります。ただし、アプリが操作できる IOKit functions は通常、**sandbox** によって **制限** されている点に注意してください。

## ドライバ

macOS では、以下に配置されています。

- **`/System/Library/Extensions`**
- OS X オペレーティングシステムに組み込まれた KEXT files。
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
9番までの一覧にあるドライバは、**アドレス 0 にロードされています**。つまり、これらは実際のドライバではなく、**kernel の一部であり、アンロードできません**。

特定の拡張機能を見つけるには、次を使用できます。
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
カーネル拡張機能をロードおよびアンロードするには、次のコマンドを実行します:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry** は macOS および iOS の IOKit framework における重要な部分であり、システムの hardware 構成と状態を表すための database として機能します。これは、システム上にロードされているすべての hardware と driver、およびそれら相互の関係を表す object の**階層的なコレクション**です。

CLI の **`ioreg`** を使用すると、console から IORegistry を取得して調査できます（特に iOS で便利です）。
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
**`IORegistryExplorer`** は **Xcode Additional Tools** から [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) をダウンロードでき、**グラフィカル**なインターフェースを通じて **macOS IORegistry** を調査できます。

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

IORegistryExplorer では、「planes」を使用して、IORegistry 内の異なるオブジェクト間の関係を整理・表示します。各 plane は、特定の種類の関係、またはシステムのハードウェアと driver 構成に関する特定のビューを表します。IORegistryExplorer で目にする可能性がある一般的な plane は以下のとおりです。

1. **IOService Plane**: 最も一般的な plane で、driver と nub（driver 間の通信チャネル）を表す service オブジェクトを表示します。これらのオブジェクト間の provider-client 関係を確認できます。
2. **IODeviceTree Plane**: デバイスがシステムに接続される際の物理的な接続を表す plane です。USB や PCI などの bus を介して接続されたデバイスの階層を可視化するためによく使用されます。
3. **IOPower Plane**: power management の観点から、オブジェクトとその関係を表示します。どのオブジェクトが他のオブジェクトの power state に影響を与えているかを確認でき、power 関連の問題の debug に役立ちます。
4. **IOUSB Plane**: USB デバイスとその関係に特化した plane で、USB hub と接続されたデバイスの階層を表示します。
5. **IOAudio Plane**: システム内の audio デバイスとその関係を表すための plane です。
6. ...

## Driver Comm Code Example

以下の code は IOKit service `YourServiceNameHere` に接続し、selector 0 を呼び出します。

- まず、**`IOServiceMatching`** と **`IOServiceGetMatchingServices`** を呼び出して service を取得します。
- 次に、**`IOServiceOpen`** を呼び出して connection を確立します。
- 最後に、selector 0（selector は、呼び出したい function に割り当てられた番号）を指定して **`IOConnectCallScalarMethod`** で function を呼び出します。

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

**`IOConnectCallScalarMethod`** 以外にも、IOKit functions の呼び出しに使用できる **`IOConnectCallMethod`**、**`IOConnectCallStructMethod`** などの functions があります。

## driver entrypoint の reversing

これらは、例えば [**firmware image (ipsw)**](#ipsw) から取得できます。その後、お気に入りの decompiler に読み込ませます。

**`externalMethod`** function の decompiling から始めるとよいでしょう。これは call を受け取り、正しい function を呼び出す driver function です。

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

このひどい call の demangled 名は次のとおりです：
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
前の定義では **`self`** パラメーターが抜けていることに注意してください。正しい定義は次のとおりです。
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
実際の定義は、[https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388) で確認できます：
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
この情報を使って Ctrl+Right -> `Edit function signature` を実行し、既知の型を設定できます:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

新しい decompiled code は次のようになります:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

次のステップでは、**`IOExternalMethodDispatch2022`** struct が定義されている必要があります。これは [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176) で opensource になっているため、次のように定義できます:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

ここで、`(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` に続いて、多くのデータが確認できます:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Data Type を **`IOExternalMethodDispatch2022:`** に変更します:

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

変更後:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

そして、ここには **7 elements の array** があることがわかるので（最終的な decompiled code を確認してください）、7 elements の array を作成します:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

array の作成後、すべての exported functions を確認できます:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 覚えているかもしれませんが、user space から **exported** function を **call** するには、function の名前を call する必要はなく、**selector number** を使用します。ここでは、selector **0** が **`initializeDecoder`** function、selector **1** が **`startDecoder`**、selector **2** が **`initializeEncoder`** であることを確認できます...

## Recent IOKit attack surface (2023–2025)

- **IOHIDFamily 経由の Keystroke capture** – CVE-2024-27799 (14.5) により、permissive な `IOHIDSystem` client は secure input が有効な場合でも HID events を取得できることが示されました。user-client type だけに依存せず、`externalMethod` handlers が entitlements を強制するようにしてください。<sup>[2]</sup>
- **IOGPUFamily の memory corruption** – CVE-2024-44197 および CVE-2025-24257 により、sandboxed apps から到達可能で、malformed な variable-length data を GPU user clients に渡すことで発生する OOB writes が修正されました。通常の bug は、`IOConnectCallStructMethod` arguments 周辺の bounds が不十分であることです。<sup>[1]</sup>
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) により、HID user clients が引き続き sandbox-escape vector であることが確認されました。keyboard/event queues を expose するすべての driver に対して fuzzing を実行してください。<sup>[3]</sup>

### Quick triage & fuzzing tips

- userland から user client のすべての external methods を enumerate し、fuzzer の seed を作成します:
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
- reverse 時は、`IOExternalMethodDispatch2022` の count に注意してください。最近の CVE でよく見られるバグパターンは、`structureInputSize`/`structureOutputSize` と実際の `copyin` length が一致していないことで、`IOConnectCallStructMethod` で heap OOB が発生します。
- Sandbox からの到達可能性は、依然として entitlements に左右されます。対象に時間をかける前に、third-party app から client の利用が許可されているか確認してください：
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- GPU/iomfbのbugでは、`IOConnectCallMethod`を介してoversized arraysを渡すだけで、bad boundsをtriggerするのに十分なことが多い。size confusionをtriggerする最小harness（selector X）：
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## DriverKit — User-Space Drivers

### 基本情報

**DriverKit** は、macOS 10.15 で導入された、kernel extensions（kexts）に代わる Apple の user-space 実装です。DriverKit バイナリ（`.dext` bundles）は user-space process として実行されますが、privileged IOKit interface を通じて kernel と直接通信します。

DriverKit extensions は、以下の hardware を管理します。
- **USB** controllers and devices
- **Thunderbolt** / PCIe devices
- **HID**（keyboards、mice、game controllers）
- **Audio** hardware
- **Networking** interfaces
- **Serial** and **Block Storage** devices

SIP-disabled boot または notarization が必要だった kexts とは異なり、DriverKit extensions は `SystemExtensions.framework` を通じてインストールされ、必要なのは **one-time user approval** のみです。

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
### セキュリティへの影響

> [!WARNING]
> DriverKit バイナリは **kernel への直接通信チャネル**を持ちます。このチャネルを介して malformed message を送信すると、kernel の脆弱性を誘発する可能性があります。各ドライバーは特定の user-client class を登録しており、malformed な `IOConnectCallMethod` 呼び出しによって kernel memory corruption が発生する可能性があります。

**Attack surface:**
1. **Kernel IOKit message fuzzing** — 各 DriverKit user-client は、user space から呼び出し可能な selector を公開します。malformed な引数によって kernel bug が誘発されます。
2. **USB device spoofing** — 侵害された USB DriverKit バイナリは、悪意のある USB device profile を提示できます（例：HID injection 用の keyboard をエミュレートする）。
3. **DMA attacks** — PCIe/Thunderbolt DriverKit extension は、physical memory への DMA access を持つ可能性があります。
4. **Persistence** — system extension としてインストールされると、DriverKit バイナリは reboot や app update 後も persist します。

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
- [2] [Rapid7 – IOHIDFamily CVE-2024-27799 summary](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
- [4] [Apple Developer — DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer — System Extensions](https://developer.apple.com/documentation/systemextensions)

{{#include ../../../banners/hacktricks-training.md}}
