# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Kernel extensions (Kexts) は **`.kext`** 拡張子を持つ**パッケージ**で、**macOS のカーネル空間に直接ロードされ**、OS に追加の機能を提供します。

### Deprecation status & DriverKit / System Extensions
**macOS Catalina (10.15)** 以降、Apple は従来の多くの KPI を *deprecated* とし、**System Extensions & DriverKit** フレームワーク（**user-space** で動作）を導入しました。**macOS Big Sur (11)** 以降、OS は deprecated な KPI に依存するサードパーティ製 kext を、マシンが **Reduced Security** モードで起動されていない限り *ロードを拒否* します。Apple Silicon では、kext を有効にするにはさらにユーザーが次を行う必要があります:

1. **Recovery** に再起動 → *Startup Security Utility*。
2. **Reduced Security** を選択し **“Allow user management of kernel extensions from identified developers”** にチェックを入れる。
3. 再起動して **System Settings → Privacy & Security** から kext を承認する。

DriverKit/System Extensions で記述されたユーザーランドドライバは、クラッシュやメモリ破損がカーネル空間ではなくサンドボックス化されたプロセス内に限定されるため、攻撃面を大幅に **削減** します。

> 📝 macOS Sequoia (15) 以降、Apple はいくつかの従来のネットワーキングおよび USB KPI を完全に削除しました — ベンダーが前方互換性を保つ唯一の解決策は System Extensions へ移行することです。

### Requirements

当然ながら、これは非常に強力なので **kernel extension をロードするのは複雑** です。kernel extension がロードされるために満たすべき**要件**は次の通りです:

- **recovery mode に入るとき**、kernel **extensions がロードを許可されている必要があります**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- kernel extension は **kernel code signing certificate** で署名されている必要があり、この証明書は **Apple によってのみ付与** されます。Apple は会社情報や必要性を詳細に審査します。
- kernel extension は **notarized** されている必要があり、Apple はマルウェアチェックを行います。
- その後、**root** ユーザーが kernel extension を **ロードできる** 権限を持ち、パッケージ内のファイルは **root 所有** である必要があります。
- アップロードプロセス中、パッケージは `/Library/StagedExtensions` のような **保護された非 root 場所** に用意されている必要があります（`com.apple.rootless.storage.KernelExtensionManagement` grant が必要）。
- 最後に、ロードを試みる際、ユーザーは [**確認要求を受け取る**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) ことになり、承認した場合はロードのためにコンピュータを **再起動** する必要があります。

### Loading process

Catalina では次のようになっていました: 興味深いことに、**検証** プロセスは **userland** で実行されます。ただし、**`com.apple.private.security.kext-management`** grant を持つアプリケーションだけが拡張をロードするようカーネルに要求できます: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI が拡張のロードのための **検証** プロセスを**開始**します
- **`kextd`** と **Mach service** を使って通信します。
2. **`kextd`** は署名などいくつかの事項をチェックします
- 拡張を **ロードできるか** を確認するために **`syspolicyd`** と通信します。
3. 拡張が以前にロードされていない場合、**`syspolicyd``** は **ユーザーにプロンプト** を表示します。
- **`syspolicyd`** は結果を **`kextd`** に報告します。
4. 最後に **`kextd`** がカーネルに拡張の **ロードを指示** できます。

もし **`kextd`** が利用できない場合、**`kextutil`** が同じチェックを実行することができます。

### Enumeration & management (loaded kexts)

`kextstat` は歴史的なツールでしたが、最近の macOS リリースでは **deprecated** です。現在のインターフェイスは **`kmutil`** です:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
古い構文は参照用にまだ利用可能です：
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` は **dump the contents of a Kernel Collection (KC)** や、kext がすべてのシンボル依存関係を解決しているかを検証するためにも利用できます:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Even though the kernel extensions are expected to be in `/System/Library/Extensions/`, if you go to this folder you **won't find any binary**. This is because of the **kernelcache** and in order to reverse one `.kext` you need to find a way to obtain it.

The **kernelcache** は **XNU kernel の事前コンパイルかつ事前リンク済みのバージョン**であり、重要なデバイスの **drivers** と **kernel extensions** が含まれます。これは **圧縮** 形式で保存され、起動時にメモリに展開されます。kernelcache は、実行準備済みのカーネルと重要なドライバを用意することで、これらのコンポーネントを起動時に動的にロード・リンクするのに要する時間とリソースを削減し、**より速いブート時間** を実現します。

kernelcache の主な利点は **speed of loading** と、すべてのモジュールが事前リンクされていること（ロード時間の阻害がない）です。また、すべてのモジュールが事前リンクされると KXLD をメモリから取り除くことができるため、**XNU cannot load new KEXTs.**

> [!TIP]
> The [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool decrypts Apple’s AEA (Apple Encrypted Archive / AEA asset) containers — the encrypted container format Apple uses for OTA assets and some IPSW pieces — and can produce the underlying .dmg/asset archive that you can then extract with the provided aastuff tools.

### ローカル Kernelcache

In iOS it's located in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** in macOS you can find it with: **`find / -name "kernelcache" 2>/dev/null`** \
In my case in macOS I found it in:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Find also here the [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

The IMG4 file format is a container format used by Apple in its iOS and macOS devices for securely **storing and verifying firmware** components (like **kernelcache**). The IMG4 format includes a header and several tags which encapsulate different pieces of data including the actual payload (like a kernel or bootloader), a signature, and a set of manifest properties. The format supports cryptographic verification, allowing the device to confirm the authenticity and integrity of the firmware component before executing it.

It's usually composed of the following components:

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
#### Disarm: カーネルのシンボル

**`Disarm`** は matchers を使って kernelcache 内の関数をシンボリケートできます。これらの matchers は単純なパターンルール（テキスト行）で、バイナリ内部の関数、引数、panic/log 文字列をどのように認識して disarm によって自動的にシンボリケートするかを指定します。

要するに、関数が使用している文字列を示すと disarm がそれを見つけて **シンボリケートします**。
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# /tmp/extracted に移動 — disarm が filesets を抽出した場所
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
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
# ipswツールをインストールする
brew install blacktop/tap/ipsw

# IPSWからkernelcacheのみを抽出する
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# 次のようなファイルが得られるはずです:
#   out/Firmware/kernelcache.release.iPhoneXX
#   またはIMG4ペイロード: out/Firmware/kernelcache.release.iPhoneXX.im4p

# IMG4ペイロードを取得した場合:
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

# 拡張のシンボルを確認
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
(lldb) bt  # get backtrace in kernel context
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
