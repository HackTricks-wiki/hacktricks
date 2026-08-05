# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Kernel extensions（Kexts）は **`.kext`** 拡張子を持つ **パッケージ** であり、**macOS kernel space に直接ロード** され、メイン operating system に追加機能を提供します。

### Deprecation status & DriverKit / System Extensions
**macOS Catalina (10.15)** 以降、Apple はほとんどの legacy KPI を *deprecated* とし、**user-space** で動作する **System Extensions & DriverKit** frameworks を導入しました。**macOS Big Sur (11)** 以降、operating system は、deprecated KPI に依存する third-party kexts のロードを *拒否します*。ただし、machine が **Reduced Security** mode で boot されている場合を除きます。Apple Silicon では、kexts を有効にするために、さらに user は以下を行う必要があります。

1. **Recovery** → *Startup Security Utility* に reboot します。
2. **Reduced Security** を選択し、**“Allow user management of kernel extensions from identified developers”** に check を入れます。
3. reboot し、**System Settings → Privacy & Security** から kext を approve します。

DriverKit/System Extensions で記述された User-land drivers は、crash や memory corruption が kernel space ではなく sandbox 化された process 内に限定されるため、attack surface を大幅に **reduce** します。<sup>[[1]](#references)</sup>

> 📝 macOS Sequoia (15) 以降、Apple は複数の legacy networking および USB KPI を完全に削除しました。vendor にとって forward-compatible な唯一の solution は、System Extensions へ migrate することです。

### 要件

当然ながら、これは非常に powerful であるため、**kernel extension のロードは complicated** です。kernel extension がロードされるには、以下の **requirements** を満たす必要があります。

- **Recovery mode に入る際、kernel extensions のロードが許可されている必要があります**。

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- kernel extension は **kernel code signing certificate で signed** されている必要があります。この certificate は **Apple によってのみ grant** されます。Apple は company と、それが必要な理由を詳細に review します。
- kernel extension は **notarized** されている必要もあり、Apple は malware の有無を check できます。
- その後、kernel extension を **load できるのは root user** であり、package 内の files は **root に belong** している必要があります。
- upload process 中、package は protected な non-root location である `/Library/StagedExtensions` に prepare する必要があります（`com.apple.rootless.storage.KernelExtensionManagement` grant が必要です）。
- 最後に、load を試みる際、user は [**confirmation request を受け取ります**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html)。accepted された場合、load のために computer を **restart** する必要があります。

### Loading process

Catalina では次のようになっていました。**verification** process が userland で実行される点は興味深い点です。ただし、**`com.apple.private.security.kext-management`** grant を持つ applications だけが、extension の **load を kernel に request** できます: `kextcache`、`kextload`、`kextutil`、`kextd`、`syspolicyd`

1. **`kextutil`** cli が extension の load に向けた **verification** process を **start** します。
- **Mach service** を使用して message を送信し、**`kextd`** と communication します。
2. **`kextd`** は **signature** など、複数の事項を check します。
- extension を **load できるか check** するため、**`syspolicyd`** と communication します。
3. **`syspolicyd`** は、extension が以前に load されていない場合、user に **prompt** を表示します。
- **`syspolicyd`** は result を **`kextd`** に report します。
4. **`kextd`** は最終的に extension の **load を kernel に伝える** ことができます。

**`kextd`** が利用できない場合、**`kextutil`** が同じ checks を実行できます。

### Enumeration & management (loaded kexts)

`kextstat` は historical tool でしたが、recent macOS releases では **deprecated** です。modern interface は **`kmutil`** です。
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
古い構文も引き続き参照用として利用できます:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` は、**Kernel Collection (KC) の内容をダンプ**したり、kext がすべてのシンボル依存関係を解決していることを確認したりするためにも利用できます:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> kernel extensions は `/System/Library/Extensions/` にあると想定されていますが、このフォルダに移動しても **binary は見つかりません**。これは **kernelcache** が原因であり、1つの `.kext` を reverse するには、それを取得する方法を見つける必要があります。

**kernelcache** は、重要な device **drivers** と **kernel extensions** を含む、**pre-compiled and pre-linked version of the XNU kernel** です。**compressed** 形式で保存され、boot-up process 中にメモリへ展開されます。kernelcache は、すぐに実行できる kernel と重要な drivers を用意しておくことで **faster boot time** を実現し、boot 時にこれらのコンポーネントを動的にロードしてリンクするために必要な時間とリソースを削減します。

kernelcache の主な利点は **speed of loading** と、すべての module が prelinked されていること（load time impediment がないこと）です。また、すべての module が prelinked されると、KXLD をメモリから削除できるため、**XNU cannot load new KEXTs.**

> [!TIP]
> [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool は Apple の AEA（Apple Encrypted Archive / AEA asset）container を decrypt します。これは Apple が OTA assets や一部の IPSW pieces に使用している encrypted container format であり、提供されている aastuff tools で extract できる underlying `.dmg`/asset archive を生成できます。


### Local Kernelcache

iOS では **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** にあります。macOS では次のコマンドで見つけられます: **`find / -name "kernelcache" 2>/dev/null`** \
私の macOS の場合、次の場所にありました:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

こちらには [**symbols 付き version 14 の kernelcache**](https://x.com/tihmstar/status/1295814618242318337?lang=en) もあります。

#### IMG4 / BVX2 (LZFSE) compressed

IMG4 file format は、Apple が iOS および macOS devices で **firmware** components（**kernelcache** など）を安全に **storing and verifying** するために使用する container format です。IMG4 format には header と複数の tags が含まれ、実際の payload（kernel や bootloader など）、signature、manifest properties の set など、さまざまな data が encapsulate されています。この format は cryptographic verification をサポートしており、device は firmware component を実行する前に、その authenticity と integrity を確認できます。

通常、次の components で構成されます:

- **Payload (IM4P)**:
- 多くの場合 compressed（LZFSE4、LZSS、…）
- 任意で encrypted
- **Manifest (IM4M)**:
- Signature を含む
- Additional Key/Value dictionary
- **Restore Info (IM4R)**:
- APNonce とも呼ばれる
- 一部の updates の replay を防止
- OPTIONAL: 通常は見つかりません

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

**`Disarm`** は、matchers を使用して kernelcache 内の functions を symbolicate できます。これらの matchers は単純な pattern rules（テキスト行）であり、binary 内の functions、arguments、panic/log strings を disarm が認識して自動的に symbolicate する方法を示します。

基本的には、function が使用している string を指定すると、disarm がそれを見つけて **symbolicate** します。
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# disarm が filesets を展開した /tmp/extracted に移動
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

# 次のような結果になります:
#   out/Firmware/kernelcache.release.iPhoneXX
#   またはIMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# IMG4 payloadが取得された場合:
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
# 最新の panic 用 symbolication bundle を作成
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
(lldb) bt  # get backtrace in kernel context
```

### Attaching LLDB to a specific loaded kext

```bash
# kext の load address を特定
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# アタッチ
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

{{#include ../../../banners/hacktricks-training.md}}
