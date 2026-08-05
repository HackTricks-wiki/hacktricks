# macOS Kernel Extensions と Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Kernel extensions（Kexts）は **`.kext`** 拡張子を持つ **packages** であり、**macOS kernel space に直接ロード**され、メイン operating system に追加機能を提供します。

### Deprecation status と DriverKit / System Extensions
**macOS Catalina (10.15)** 以降、Apple はほとんどの legacy KPI を *deprecated* とし、**user-space** で動作する **System Extensions と DriverKit** frameworks を導入しました。**macOS Big Sur (11)** 以降、operating system は、deprecated KPI に依存する third-party kexts のロードを、マシンが **Reduced Security** mode で boot されていない限り、*拒否します*。Apple Silicon では、kexts を有効化するために、ユーザーはさらに次の操作を行う必要があります。

1. **Recovery** → *Startup Security Utility* に reboot します。
2. **Reduced Security** を選択し、**“Allow user management of kernel extensions from identified developers”** にチェックを入れます。
3. reboot し、**System Settings → Privacy & Security** から kext を approve します。

DriverKit/System Extensions で記述された user-land drivers は、crash や memory corruption が kernel space ではなく sandbox 化された process 内に限定されるため、attack surface を大幅に **reduce** します。<sup>[1]</sup>

> 📝 macOS Sequoia (15) 以降、Apple は複数の legacy networking および USB KPI を完全に削除しました。vendors にとって唯一の forward-compatible な solution は、System Extensions へ migrate することです。

### Requirements

当然ながら、これは非常に強力であるため、kernel extension の **load は複雑**です。kernel extension が load されるには、次の **requirements** を満たす必要があります。

- **recovery mode に入る**際、kernel **extensions の load が許可**されている必要があります。

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- kernel extension は kernel code signing certificate で **signed** されている必要があり、この certificate は **Apple のみが grant**できます。Apple は company と、それが必要な理由を詳細に review します。
- kernel extension は **notarized** されている必要もあり、Apple は malware の有無を check できます。
- その後、kernel extension を **load できる**のは **root** user であり、package 内の files は **root に belong**している必要があります。
- upload process 中、package は protected な non-root location である `/Library/StagedExtensions` に prepare する必要があります（`com.apple.rootless.storage.KernelExtensionManagement` grant が必要です）。
- 最後に、load を試行すると、ユーザーは [**confirmation request を受け取ります**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html)。承認した場合、load のために computer を **restart**する必要があります。

### Loading process

Catalina では次のような process でした。**verification** process が userland で行われる点は興味深いところです。ただし、kernel に extension の load を **request できる**のは、**`com.apple.private.security.kext-management`** grant を持つ applications だけです：`kextcache`、`kextload`、`kextutil`、`kextd`、`syspolicyd`

1. **`kextutil`** cli が extension の load に向けた **verification** process を **start**します。
- **Mach service** を使用して送信し、**`kextd`** と通信します。
2. **`kextd`** は **signature** など、複数の項目を check します。
- extension を **load できる**か **check**するため、**`syspolicyd`** と通信します。
3. extension が以前に load されていない場合、**`syspolicyd`** は **user に prompt**を表示します。
- **`syspolicyd`** は結果を **`kextd`** に report します。
4. **`kextd`** は最終的に、extension を **load するよう kernel に伝える**ことができます。

**`kextd`** が利用できない場合、**`kextutil`** は同じ checks を実行できます。

### Enumeration と management（loaded kexts）

`kextstat` は historical tool でしたが、recent macOS releases では **deprecated** です。modern interface は **`kmutil`** です。
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
古い構文も引き続き参照用として利用できます。
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` は、**Kernel Collection (KC) の内容をダンプしたり、kext がすべてのシンボル依存関係を解決することを検証したりするためにも活用できます**。
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> kernel extensions は `/System/Library/Extensions/` にあると想定されていますが、このフォルダーに移動しても **binary は見つかりません**。これは **kernelcache** が存在するためであり、1つの `.kext` を reverse するには、それを取得する方法を見つける必要があります。

**kernelcache** は、XNU kernel と不可欠なデバイス **drivers** および **kernel extensions** の **pre-compiled and pre-linked version** です。**compressed** 形式で保存され、boot-up process 中に memory へ decompressed されます。kernelcache は、すぐに実行できる kernel と重要な drivers を利用可能にすることで、**faster boot time** を実現します。これにより、boot time にこれらの components を動的に loading および linking するために必要となる時間と resources が削減されます。

kernelcache の主な benefits は **speed of loading** と、すべての modules が prelinked されていること（load time impediment がないこと）です。また、すべての modules が prelinked された後は、KXLD を memory から削除できるため、**XNU cannot load new KEXTs.**

> [!TIP]
> [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool は、Apple の AEA（Apple Encrypted Archive / AEA asset）containers を decrypt します。これは Apple が OTA assets と一部の IPSW pieces に使用している encrypted container format で、基盤となる .dmg/asset archive を生成できます。その後、提供されている aastuff tools で extract できます。


### Local Kernelcache

iOS では **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** にあります。macOS では次のコマンドで見つけられます: **`find / -name "kernelcache" 2>/dev/null`** \
私の macOS 環境では、次の場所にありました:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

こちらには [**symbols 付き version 14 の kernelcache**](https://x.com/tihmstar/status/1295814618242318337?lang=en) もあります。

#### IMG4 / BVX2 (LZFSE) compressed

IMG4 file format は、Apple の iOS および macOS devices で firmware components（**kernelcache** など）を安全に **storing and verifying** するために使用される container format です。IMG4 format には header と複数の tags が含まれており、actual payload（kernel や bootloader など）、signature、manifest properties の set など、さまざまな data pieces を encapsulate します。この format は cryptographic verification をサポートしており、device は firmware component を実行する前に、その authenticity と integrity を確認できます。

通常、次の components で構成されます:

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

Kernelcache を decompress します:
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
#### kernel 用の Disarm symbols

**`Disarm`** は matcher を使用して、kernelcache 内の関数を symbolicate できます。これらの matcher は単純な pattern rule（テキスト行）であり、バイナリ内の関数、引数、panic/log string を disarm が認識して自動的に symbolicate する方法を指定します。

基本的には、関数が使用している string を指定すると、disarm がそれを見つけて **symbolicate** します。
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# disarm が fileset を展開した /tmp/extracted に移動
disarm -e filesets kernelcache.release.d23 # 常に /tmp/extracted に展開
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
# ipsw toolをインストール
brew install blacktop/tap/ipsw

# IPSWからkernelcacheのみを抽出
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# 次のようになります:
#   out/Firmware/kernelcache.release.iPhoneXX
#   またはIMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# IMG4 payloadの場合:
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
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
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
# Create a symbolication bundle for the latest panic
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
# kextのロードアドレスを特定
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# アタッチ
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

{{#include ../../../banners/hacktricks-training.md}}
