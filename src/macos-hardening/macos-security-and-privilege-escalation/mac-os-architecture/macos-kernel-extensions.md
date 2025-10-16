# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Kernel extensions (Kexts) は、拡張子が **`.kext`** の **パッケージ** で、macOS の **kernel space に直接ロードされ**、OS に追加機能を提供します。

### Deprecation status & DriverKit / System Extensions
**macOS Catalina (10.15)** 以降、Apple は多くのレガシー KPI を *deprecated* とし、**DriverKit & System Extensions** フレームワーク（**user-space** で動作）を導入しました。**macOS Big Sur (11)** からは、レガシー KPI に依存するサードパーティ kext を、マシンが **Reduced Security** モードで起動していない限り *ロードしない* よう OS が制限します。Apple Silicon では、kext の有効化にはさらにユーザー操作が必要です:

1. Reboot into **Recovery** → *Startup Security Utility*.
2. Select **Reduced Security** and tick **“Allow user management of kernel extensions from identified developers”**.
3. Reboot and approve the kext from **System Settings → Privacy & Security**.

DriverKit/System Extensions で書かれた user-land ドライバは、クラッシュやメモリ破損が kernel space ではなくサンドボックス化されたプロセス内にとどまるため、攻撃対象領域を大幅に **縮小します**。

> 📝 From macOS Sequoia (15) Apple has removed several legacy networking and USB KPIs entirely – the only forward-compatible solution for vendors is to migrate to System Extensions.

### Requirements

当然ながら、これは強力であるがゆえに **kernel extension をロードするのは複雑** です。kernel extension がロードされるために満たすべき **要件** は以下の通りです:

- **recovery mode に入っている時**、kernel **extensions must be allowed** to be loaded:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- kernel extension は **kernel code signing certificate** で署名されている必要があり、この証明書は **Apple のみが発行可能** です。Apple は申請会社や必要性を詳細に審査します。
- kernel extension は **notarized** である必要があり、Apple はマルウェアチェックを行います。
- その後、**root** ユーザーが **kernel extension をロード** できる唯一の権限を持ち、パッケージ内のファイルは **root に属している** 必要があります。
- アップロードプロセス中、パッケージは **protected non-root location** に準備されていなければなりません: `/Library/StagedExtensions` （`com.apple.rootless.storage.KernelExtensionManagement` grant が必要）。
- 最後に、ロードを試みるとユーザーは [**receive a confirmation request**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) を受け取り、承認された場合はロードのために **再起動** が必要になります。

### Loading process

Catalina では次のような流れでした: 興味深いのは **verification** プロセスが **userland** で行われる点です。ただし、**`com.apple.private.security.kext-management`** grant を持つアプリケーションだけが **カーネルに extension のロードを要求** できます: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI が extension ロードのための **verification** プロセスを **開始** します
- それは **`kextd`** と **Mach service** を使って通信します。
2. **`kextd`** は署名などを含む複数の項目をチェックします
- **`syspolicyd`** と通信して extension が **ロード可能か** を **確認** します。
3. **`syspolicyd`** は、その extension が以前にロードされていない場合に **ユーザーにプロンプト** を表示します。
- **`syspolicyd`** は結果を **`kextd`** に報告します。
4. **`kextd`** は最終的にカーネルに extension を **ロードするよう指示** できます。

もし **`kextd`** が利用できない場合、**`kextutil`** が同じチェックを実行できます。

### Enumeration & management (loaded kexts)

`kextstat` は歴史的なツールでしたが、最近の macOS では **deprecated** です。モダンなインターフェースは **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
以前の構文は参考用にまだ利用可能です：
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` は **Kernel Collection (KC) の内容をダンプする** または kext がすべてのシンボル依存関係を解決しているかを検証するためにも利用できます:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> 通常、カーネル拡張は `/System/Library/Extensions/` にあるはずですが、このフォルダを見ても **バイナリは見つかりません**。これは **kernelcache** のためで、個々の `.kext` をリバースするにはそれを入手する方法を見つける必要があります。

The **kernelcache** is a **pre-compiled and pre-linked version of the XNU kernel**, along with essential device **drivers** and **kernel extensions**. It's stored in a **compressed** format and gets decompressed into memory during the boot-up process. The kernelcache facilitates a **faster boot time** by having a ready-to-run version of the kernel and crucial drivers available, reducing the time and resources that would otherwise be spent on dynamically loading and linking these components at boot time.

kernelcache の主な利点は **読み込みの高速化** と全モジュールが事前にリンクされていること（読み込み時間の阻害がない）です。また、すべてのモジュールが事前にリンクされると KXLD をメモリから取り除くことができ、結果として **XNU は新しい KEXTs をロードできなくなります。**

> [!TIP]
> The [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool decrypts Apple’s AEA (Apple Encrypted Archive / AEA asset) containers — the encrypted container format Apple uses for OTA assets and some IPSW pieces — and can produce the underlying .dmg/asset archive that you can then extract with the provided aastuff tools.

### ローカル kernelcache

In iOS it's located in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** in macOS you can find it with: **`find / -name "kernelcache" 2>/dev/null`** \
私の macOS 環境では以下の場所にありました：

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

ここでも見つかります: [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

The IMG4 file format is a container format used by Apple in its iOS and macOS devices for securely **storing and verifying firmware** components (like **kernelcache**). The IMG4 format includes a header and several tags which encapsulate different pieces of data including the actual payload (like a kernel or bootloader), a signature, and a set of manifest properties. The format supports cryptographic verification, allowing the device to confirm the authenticity and integrity of the firmware component before executing it.

通常、次のコンポーネントで構成されます：

- **Payload (IM4P)**:
  - Often compressed (LZFSE4, LZSS, …)
  - Optionally encrypted
- **Manifest (IM4M)**:
  - Contains Signature
  - Additional Key/Value dictionary
- **Restore Info (IM4R)**:
  - Also known as APNonce
  - Prevents replaying of some updates
  - OPTIONAL: Usually this isn't found

Decompress the Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# imjtool (https://newandroidbook.com/tools/imjtool.html)
imjtool _img_name_ [extract]

# disarm (you can use it directly on the IMG4 file) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -L kernelcache.release.v57 # From unzip ipsw

# disamer (extract specific parts, e.g. filesets) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -e filesets kernelcache.release.d23
```
#### Disarm カーネルのシンボル

**`Disarm`** は matchers を使って kernelcache から functions を symbolicate することを可能にします。  
これらの matchers は単純なパターンルール（text lines）に過ぎず、binary 内の functions、arguments、panic/log strings を disarm がどのように recognise & auto-symbolicate するかを示します。

つまり、基本的に function が使用している文字列を指定すると、disarm がそれを見つけて **symbolicate it** します。
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# disarm が filesets を抽出した /tmp/extracted に移動
disarm -e filesets kernelcache.release.d23 # 常に /tmp/extracted に抽出する
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # xnu.matchers は実際には matchers を含むファイルであることに注意
```

### Download

An **IPSW (iPhone/iPad Software)** is Apple’s firmware package format used for device restores, updates, and full firmware bundles. Among other things, it contains the **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) it's possible to find all the kernel debug kits. You can download it, mount it, open it with [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) tool, access the **`.kext`** folder and **extract it**.

Check it for symbols with:

```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```

- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Sometime Apple releases **kernelcache** with **symbols**. You can download some firmwares with symbols by following links on those pages. The firmwares will contain the **kernelcache** among other files.

To **extract** the kernel cache you can do:

```bash
# ipsw tool をインストール
brew install blacktop/tap/ipsw

# IPSW から kernelcache のみを抽出
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# 次のような出力が得られます:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# IMG4 ペイロードを取得した場合:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```

Another option to **extract** the files start by changing the extension from `.ipsw` to `.zip` and **unzip** it.

After extracting the firmware you will get a file like: **`kernelcache.release.iphone14`**. It's in **IMG4** format, you can extract the interesting info with:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

[**img4tool**](https://github.com/tihmstar/img4tool)**:**

```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

[**img4tool**](https://github.com/tihmstar/img4tool)**:**

```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

### Inspecting kernelcache

Check if the kernelcache has symbols with

```bash
nm -a kernelcache.release.iphone14.e | wc -l
```

With this we can now **extract all the extensions** or the **one you are interested in:**

```bash
# すべての拡張を一覧表示
kextex -l kernelcache.release.iphone14.e
## com.apple.security.sandbox を抽出
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# すべてを抽出
kextex_all kernelcache.release.iphone14.e

# 拡張内のシンボルを確認
nm -a binaries/com.apple.security.sandbox | wc -l
```


## Recent vulnerabilities & exploitation techniques

| Year | CVE | Summary |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Logic flaw in **`storagekitd`** allowed a *root* attacker to register a malicious file-system bundle that ultimately loaded an **unsigned kext**, **bypassing System Integrity Protection (SIP)** and enabling persistent rootkits. Patched in macOS 14.2 / 15.2.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Installation daemon with the entitlement `com.apple.rootless.install` could be abused to execute arbitrary post-install scripts, disable SIP and load arbitrary kexts.  |

**Take-aways for red-teamers**

1. **Look for entitled daemons (`codesign -dvv /path/bin | grep entitlements`) that interact with Disk Arbitration, Installer or Kext Management.**
2. **Abusing SIP bypasses almost always grants the ability to load a kext → kernel code execution**.

**Defensive tips**

*Keep SIP enabled*, monitor for `kmutil load`/`kmutil create -n aux` invocations coming from non-Apple binaries and alert on any write to `/Library/Extensions`. Endpoint Security events `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` provide near real-time visibility.

## Debugging macOS kernel & kexts

Apple’s recommended workflow is to build a **Kernel Debug Kit (KDK)** that matches the running build and then attach **LLDB** over a **KDP (Kernel Debugging Protocol)** network session.

### One-shot local debug of a panic

```bash
# 最新のカーネルパニックのシンボリケーションバンドルを作成する
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```

### Live remote debugging from another Mac

1. Download + install the exact **KDK** version for the target machine.
2. Connect the target Mac and the host Mac with a **USB-C or Thunderbolt cable**.
3. On the **target**:

```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```

4. On the **host**:

```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # カーネルコンテキストでバックトレースを取得
```

### Attaching LLDB to a specific loaded kext

```bash
# kext のロードアドレスを特定

ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# アタッチ

sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
