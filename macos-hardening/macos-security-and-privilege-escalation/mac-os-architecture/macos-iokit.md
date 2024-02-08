# macOS IOKit

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Basic Information

I/O Kitは、XNUカーネル内のオープンソースのオブジェクト指向の**デバイスドライバーフレームワーク**であり、**動的にロードされるデバイスドライバー**を処理します。これにより、モジュラーコードをカーネルに即座に追加し、さまざまなハードウェアをサポートできます。

IOKitドライバーは基本的にカーネルから**関数をエクスポート**します。これらの関数のパラメータ**タイプ**は**事前に定義**され、検証されます。さらに、XPCと同様に、IOKitは単なる**Machメッセージの上にある別のレイヤー**です。

**IOKit XNUカーネルコード**はAppleによってオープンソース化されており、[https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit)で入手できます。さらに、ユーザースペースのIOKitコンポーネントもオープンソース化されています [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser)。

ただし、**IOKitドライバー**はオープンソースではありません。とはいえ、時折、ドライバーのリリースによってデバッグが容易になるシンボルが付属することがあります。[**ここからファームウェアからドライバー拡張機能を取得する方法**](./#ipsw)**を確認してください**。

これは**C++**で書かれています。次のコマンドでC++のシンボルをデマングルできます：
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKitの**公開された関数**は、クライアントが関数を呼び出そうとする際に**追加のセキュリティチェック**を実行する可能性がありますが、アプリは通常、IOKit関数とやり取りできる**サンドボックス**によって**制限**されていることに注意してください。
{% endhint %}

## ドライバー

macOSでは、次の場所にあります：

- **`/System/Library/Extensions`**
- OS Xオペレーティングシステムに組み込まれたKEXTファイル。
- **`/Library/Extensions`**
- サードパーティ製のソフトウェアによってインストールされたKEXTファイル

iOSでは、次の場所にあります：

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
1. 9までの番号がリストされたドライバーは、**アドレス0にロードされます**。これは、それらが実際のドライバーではなく、**カーネルの一部であり、アンロードできない**ことを意味します。

特定の拡張機能を見つけるには、次の方法を使用できます：
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
カーネル拡張機能をロードおよびアンロードするには次のようにします：
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry（IOレジストリ）**は、macOSとiOSのIOKitフレームワークの重要な部分であり、システムのハードウェア構成と状態を表すデータベースとして機能します。これは、システムにロードされたすべてのハードウェアとドライバーを表すオブジェクトの階層的なコレクションであり、お互いとの関係を示しています。

**`ioreg`**コマンドラインインターフェース（特にiOS向けに特に便利）を使用して、コンソールからIORegistryを取得できます。
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
**IORegistryExplorer**を[**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/)から**Xcode追加ツール**をダウンロードして、**グラフィカル**インターフェースを通じて**macOS IORegistry**を調査できます。

<figure><img src="../../../.gitbook/assets/image (695).png" alt="" width="563"><figcaption></figcaption></figure>

IORegistryExplorerでは、「プレーン」が使用され、IORegistry内の異なるオブジェクト間の関係を整理して表示します。各プレーンは、システムのハードウェアとドライバー構成の特定のビューまたは特定の関係を表します。以下は、IORegistryExplorerで遭遇する可能性のある一般的なプレーンのいくつかです：

1. **IOService Plane**：これは最も一般的なプレーンで、ドライバーとナブ（ドライバー間の通信チャンネル）を表すサービスオブジェクトを表示します。これらのオブジェクト間のプロバイダー-クライアント関係を示します。
2. **IODeviceTree Plane**：このプレーンは、デバイス間の物理的な接続を表し、システムに接続されたデバイスの階層構造を視覚化するためによく使用されます。USBやPCIなどのバスを介して接続されたデバイスの階層を表示します。
3. **IOPower Plane**：電源管理の観点からオブジェクトとその関係を表示します。他のオブジェクトの電源状態に影響を与えているオブジェクトを示すことができ、電源関連の問題のデバッグに役立ちます。
4. **IOUSB Plane**：USBデバイスとその関係に特化し、USBハブと接続されたデバイスの階層を表示します。
5. **IOAudio Plane**：このプレーンは、システム内のオーディオデバイスとその関係を表します。
6. ...

## ドライバー通信コード例

次のコードは、IOKitサービス`"YourServiceNameHere"`に接続し、セレクタ0内の関数を呼び出します。これには以下の手順が含まれます：

* まず、**`IOServiceMatching`**と**`IOServiceGetMatchingServices`**を呼び出してサービスを取得します。
* 次に、**`IOServiceOpen`**を呼び出して接続を確立します。
* 最後に、**`IOConnectCallScalarMethod`**を使用してセレクタ0を指定して関数を呼び出します（セレクタは呼び出したい関数に割り当てられた番号です）。
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
**その他**の関数があり、**`IOConnectCallScalarMethod`**の他に使用できるIOKit関数があります。**`IOConnectCallMethod`**、**`IOConnectCallStructMethod`**などがあります...

## ドライバーエントリーポイントのリバースエンジニアリング

これらは、たとえば[**ファームウェアイメージ（ipsw）**](./#ipsw)から取得できます。次に、お気に入りのデコンパイラにロードします。

**`externalMethod`** 関数の逆コンパイルを開始できます。これは、呼び出しを受け取り、正しい関数を呼び出すドライバー関数です:

<figure><img src="../../../.gitbook/assets/image (696).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (697).png" alt=""><figcaption></figcaption></figure>

その酷い呼び出しは次のようになります:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

前の定義では、**`self`** パラメータが抜けていることに注意してください。適切な定義は次のようになります:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

実際には、[https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388) で実際の定義を見つけることができます。
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
この情報を使って、Ctrl+Right -> `Edit function signature` を書き直し、既知のタイプを設定します：

<figure><img src="../../../.gitbook/assets/image (702).png" alt=""><figcaption></figcaption></figure>

新しい逆コンパイルされたコードは以下のようになります：

<figure><img src="../../../.gitbook/assets/image (703).png" alt=""><figcaption></figcaption></figure>

次のステップでは、**`IOExternalMethodDispatch2022`** 構造体を定義する必要があります。これは[https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176)でオープンソースで提供されています。これを定義できます：

<figure><img src="../../../.gitbook/assets/image (698).png" alt=""><figcaption></figcaption></figure>

そして、`(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` に従って、多くのデータを見ることができます：

<figure><img src="../../../.gitbook/assets/image (704).png" alt="" width="563"><figcaption></figcaption></figure>

データ型を **`IOExternalMethodDispatch2022:`** に変更します：

<figure><img src="../../../.gitbook/assets/image (705).png" alt="" width="375"><figcaption></figcaption></figure>

変更後：

<figure><img src="../../../.gitbook/assets/image (707).png" alt="" width="563"><figcaption></figcaption></figure>

そして、ここには**7つの要素の配列**があることがわかります（最終的な逆コンパイルされたコードを確認してください）。7つの要素の配列を作成するためにクリックしてください：

<figure><img src="../../../.gitbook/assets/image (708).png" alt="" width="563"><figcaption></figcaption></figure>

配列が作成された後、すべてのエクスポートされた関数を確認できます：

<figure><img src="../../../.gitbook/assets/image (709).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
覚えておいてください。ユーザースペースから**エクスポートされた**関数を**呼び出す**際には、関数の名前ではなく、**セレクタ番号**を呼び出す必要があります。ここでは、セレクタ **0** が関数 **`initializeDecoder`**、セレクタ **1** が **`startDecoder`**、セレクタ **2** が **`initializeEncoder`** であることがわかります...
{% endhint %}
