# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

I/O KitはXNUカーネル内のオープンソースでオブジェクト指向の**デバイスドライバフレームワーク**で、**動的にロードされるデバイスドライバ**を扱います。モジュール化されたコードをカーネルにオンザフライで追加でき、多様なハードウェアをサポートします。

IOKitドライバは基本的にカーネルから**関数をエクスポート**します。これらの関数パラメータの**型**は**事前定義**されており、検証されます。さらに、XPCと同様に、IOKitは**Machメッセージの上の層**に過ぎません。

**IOKit XNU kernel code**はAppleによってオープンソース化されており [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit)。さらに、ユーザースペースのIOKitコンポーネントもオープンソースです [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser)。

しかし、**IOKitドライバ自体はオープンソースではありません**。とはいえ、時々ドライバのリリースにデバッグ用のシンボルが含まれることがあり、解析が容易になる場合があります。ドライバ拡張をファームウェアから[**ここで取得する方法**](#ipsw)**.**

これは**C++**で書かれています。デマングルされたC++シンボルは次のように取得できます:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> クライアントが関数を呼び出そうとすると、IOKitの**公開された関数**は**追加のセキュリティチェック**を行う場合があります。ただし、アプリは通常、IOKitがどの関数とやり取りできるかについて**sandbox**によって**制限されている**ことに注意してください。

## ドライバ

In macOS they are located in:

- **`/System/Library/Extensions`**
- OS X オペレーティングシステムに組み込まれた KEXT ファイル。
- **`/Library/Extensions`**
- サードパーティ製ソフトウェアによってインストールされた KEXT ファイル

In iOS they are located in:

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
番号9までに列挙されているドライバは**address 0 にロードされています**。これは、それらが実際のドライバではなく**カーネルの一部であり、アンロードできない**ことを意味します。

特定の拡張を見つけるには、次を使用できます:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
kernel extensions をロードおよびアンロードするには、次のようにします:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry** は macOS と iOS の IOKit フレームワークの重要な部分で、システムのハードウェア構成と状態を表すデータベースとして機能します。これは、**システムにロードされているすべてのハードウェアとドライバを表すオブジェクトの階層的な集合体**であり、それらの相互関係を表します。

コンソールから検査するために cli の **`ioreg`** を使って IORegistry を取得できます（特に iOS で便利です）。
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
You could download **`IORegistryExplorer`** from **Xcode Additional Tools** from [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) and inspect the **macOS IORegistry** through a **graphical** interface.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer, "planes" are used to organize and display the relationships between different objects in the IORegistry. Each plane represents a specific type of relationship or a particular view of the system's hardware and driver configuration. Here are some of the common planes you might encounter in IORegistryExplorer:

1. **IOService Plane**: This is the most general plane, displaying the service objects that represent drivers and nubs (communication channels between drivers). It shows the provider-client relationships between these objects.
2. **IODeviceTree Plane**: This plane represents the physical connections between devices as they are attached to the system. It is often used to visualize the hierarchy of devices connected via buses like USB or PCI.
3. **IOPower Plane**: Displays objects and their relationships in terms of power management. It can show which objects are affecting the power state of others, useful for debugging power-related issues.
4. **IOUSB Plane**: Specifically focused on USB devices and their relationships, showing the hierarchy of USB hubs and connected devices.
5. **IOAudio Plane**: This plane is for representing audio devices and their relationships within the system.
6. ...

## Driver Comm Code Example

The following code connects to the IOKit service `YourServiceNameHere` and calls selector 0:

- It first calls **`IOServiceMatching`** and **`IOServiceGetMatchingServices`** to get the service.
- It then establishes a connection calling **`IOServiceOpen`**.
- And it finally calls a function with **`IOConnectCallScalarMethod`** indicating the selector 0 (the selector is the number the function you want to call has assigned).

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

IOKit 関数を呼び出すために使用できる**他の**関数もあり、例えば **`IOConnectCallScalarMethod`** のほかに **`IOConnectCallMethod`**、**`IOConnectCallStructMethod`**... 

## Reversing driver entrypoint

これらは例えば [**firmware image (ipsw)**](#ipsw) から入手できます。次に、お気に入りのディコンパイラにロードします。

この呼び出しを受け取り、正しい関数を呼び出すドライバ関数である **`externalMethod`** 関数のデコンパイルから始めることができます:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

その煩雑にデマングルされた呼び出しが意味するのは：
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
前の定義では **`self`** パラメータが抜けていることに注意してください。正しい定義は次のようになります：
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
実際、実際の定義は [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
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
> 覚えているなら、user space から **call** する際に **exported** 関数名を直接呼ぶ必要はなく、**selector number** を使います。ここでは selector **0** が関数 **`initializeDecoder`**、selector **1** が **`startDecoder`**、selector **2** が **`initializeEncoder`** であることがわかります...

## Recent IOKit attack surface (2023–2025)

- **Keystroke capture via IOHIDFamily** – CVE-2024-27799 (14.5) は、許容的な `IOHIDSystem` client が secure input の状態でも HID イベントを取得できることを示しました；`externalMethod` ハンドラが user-client type のみでなく entitlements を強制することを確認してください。
- **IOGPUFamily memory corruption** – CVE-2024-44197 および CVE-2025-24257 は、sandboxed アプリが不正な可変長データを GPU user clients に渡した場合に到達可能な OOB writes を修正しました；典型的なバグは `IOConnectCallStructMethod` 引数周りの境界チェックの不備です。
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) は HID user clients が依然として sandbox-escape のベクターになり得ることを確認しました；keyboard/event queues を公開するドライバはすべて fuzz してください。

### Quick triage & fuzzing tips

- Enumerate all external methods for a user client from userland to seed a fuzzer:
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
- リバース時は、`IOExternalMethodDispatch2022` のカウントに注意してください。最近の CVE に見られる一般的なバグパターンは、`structureInputSize`/`structureOutputSize` と実際の `copyin` 長が不整合になり、`IOConnectCallStructMethod` で heap OOB を引き起こすことです。
- Sandbox への到達可能性は依然として entitlements に依存します。ターゲットに時間を費やす前に、サードパーティのアプリからクライアントが許可されているか確認してください:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- GPU/iomfb の脆弱性では、`IOConnectCallMethod` に過大な配列を渡すだけで不適切な境界が発生することが多い。サイズ混同を引き起こす最小ハーネス (selector X):
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## 参考資料

- [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [Rapid7 – IOHIDFamily CVE-2024-27799 summary](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
{{#include ../../../banners/hacktricks-training.md}}
