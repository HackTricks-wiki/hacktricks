# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Kernel extensions（Kexts）は **`.kext`** 拡張子を持つ **packages** であり、**macOS kernel space に直接ロードされ**、メイン operating system に追加機能を提供します。

### 非推奨ステータスと DriverKit / System Extensions
**macOS Catalina (10.15)** 以降、Apple は従来の KPI の大半を *deprecated* とし、**user-space** で動作する **System Extensions & DriverKit** frameworks を導入しました。**macOS Big Sur (11)** 以降、operating system は、deprecated KPI に依存する third-party kexts のロードを、マシンが **Reduced Security** mode で boot されていない限り *拒否します*。Apple Silicon では、kexts を有効化するために、ユーザーはさらに次の操作を行う必要があります。

1. **Recovery** → *Startup Security Utility* に **Reboot** します。
2. **Reduced Security** を選択し、**“Allow user management of kernel extensions from identified developers”** にチェックを入れます。
3. **Reboot** し、**System Settings → Privacy & Security** から kext を承認します。

DriverKit/System Extensions で記述された User-land drivers は、crash や memory corruption が kernel space ではなく sandbox 化された process 内に閉じ込められるため、attack surface を大幅に **reduce** します。<sup>[[1]](#references)</sup>

> 📝 macOS Sequoia (15) では、Apple は複数の従来の networking および USB KPI を完全に削除しました。vendors にとって、forward-compatible な唯一の solution は System Extensions へ migrate することです。

### 要件

当然ながら、これは非常に powerful であるため、**kernel extension の load は complicated** です。kernel extension がロードされるには、次の **requirements** を満たす必要があります。

- **Recovery mode に入る際**、kernel **extensions のロードが許可**されている必要があります。

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- kernel extension は **kernel code signing certificate で signed** されている必要があり、この証明書は **Apple からのみ granted** されます。Apple は会社と、それが必要な理由を詳細に review します。
- kernel extension は **notarized** されている必要もあり、Apple は malware の有無を check できます。
- その後、**root** user が **kernel extension を load** でき、package 内の files は **root に belong** している必要があります。
- upload process 中、package は protected な non-root location である `/Library/StagedExtensions` に prepare する必要があります（`com.apple.rootless.storage.KernelExtensionManagement` grant が必要です）。
- 最後に、load を試みる際、user は [**confirmation request を受け取ります**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html)。承認した場合、load するには computer を **restart** する必要があります。

### Loading process

Catalina では次のようになっていました。**verification** process が userland で実行される点は興味深いところです。ただし、**`com.apple.private.security.kext-management`** grant を持つ applications のみが **kernel に extension の load を request** できます: `kextcache`、`kextload`、`kextutil`、`kextd`、`syspolicyd`

1. **`kextutil`** cli が extension の load に必要な **verification** process を **start** します。
- **Mach service** を使用して message を送信し、**`kextd`** と通信します。
2. **`kextd`** は **signature** など、複数の項目を check します。
- extension が **load 可能か check** するため、**`syspolicyd`** と通信します。
3. extension が以前に load されていない場合、**`syspolicyd`** は user に **prompt** を表示します。
- **`syspolicyd`** は結果を **`kextd`** に report します。
4. **`kextd`** は最終的に extension を **load するよう kernel に tell** できるようになります。

**`kextd`** が利用できない場合、**`kextutil`** は同じ checks を実行できます。

### Enumeration と management（loaded kexts）

`kextstat` は historical tool でしたが、最近の macOS releases では **deprecated** です。modern interface は **`kmutil`** です。
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
古い構文も引き続き参照用に利用できます：
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` は、**Kernel Collection (KC) の内容を dump** したり、kext がすべてのシンボル依存関係を解決できることを検証したりするためにも利用できます：
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> kernel extensions は `/System/Library/Extensions/` にあると想定されていますが、このフォルダを開いても **binary は見つかりません**。これは **kernelcache** が原因であり、1つの `.kext` を reverse するには、それを取得する方法を見つける必要があります。

**kernelcache** は、重要な device **drivers** と **kernel extensions** を含む、**pre-compiled** かつ **pre-linked** な XNU kernel のバージョンです。これは **compressed** 形式で保存され、boot-up process 中に memory へ decompressed されます。kernelcache は、すぐに実行できる kernel と重要な drivers を用意することで **faster boot time** を実現し、boot 時にこれらの component を動的に loading および linking するために必要となる時間と resources を削減します。

kernelcache の主な利点は **speed of loading** と、すべての modules が prelinked されていること（load time impediment がないこと）です。また、すべての modules が prelinked されると、KXLD を memory から削除できるため、**XNU は新しい KEXTs を load できません。**

> [!TIP]
> [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool は Apple の AEA（Apple Encrypted Archive / AEA asset）containers を decrypt します。これは Apple が OTA assets と一部の IPSW pieces に使用している encrypted container format であり、提供されている aastuff tools で extract できる underlying `.dmg` / asset archive を生成できます。


### Local Kerlnelcache

iOS では **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** にあります。macOS では次のコマンドで見つけられます: **`find / -name "kernelcache" 2>/dev/null`** \
私の macOS の場合、次の場所にありました:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

こちらには [**symbols 付き version 14 の kernelcache**](https://x.com/tihmstar/status/1295814618242318337?lang=en) もあります。

#### IMG4 / BVX2 (LZFSE) compressed

IMG4 file format は、Apple が iOS および macOS devices で firmware components（**kernelcache** など）を安全に **storing and verifying** するために使用する container format です。IMG4 format には header と複数の tags が含まれており、actual payload（kernel や bootloader など）、signature、manifest properties の set など、異なる data pieces を encapsulate します。この format は cryptographic verification をサポートしており、device は firmware component を実行する前に、その authenticity と integrity を確認できます。

通常、次の components で構成されます:

- **Payload (IM4P)**:
- 多くの場合 compressed（LZFSE4、LZSS、…）
- Optionally encrypted
- **Manifest (IM4M)**:
- Signature を含む
- Additional Key/Value dictionary
- **Restore Info (IM4R)**:
- APNonce とも呼ばれる
- 一部の updates の replay を防止する
- OPTIONAL: 通常は見つかりません

Kernelcache を Decompress します:
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
#### kernel のシンボルを無効化する

**`Disarm`** を使用すると、matcher によって kernelcache の関数をシンボル化できます。これらの matcher は単純なパターンルール（テキスト行）であり、バイナリ内の関数、引数、panic/log 文字列を disarm が認識して自動的にシンボル化する方法を指定します。

基本的には、関数が使用している文字列を指定すると、disarm がそれを見つけて **シンボル化** します。

[https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) の **`Matchers`** セクションには、いくつかの `xnu.matchers` があります。独自の matcher を作成することもできます。
```bash
# Go to /tmp/extracted where disarm extracted the filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```
### Download

**IPSW（iPhone/iPad Software）**は、デバイスの復元、アップデート、完全なfirmware bundleに使用されるAppleのfirmware package formatです。その他のものとともに、**kernelcache**が含まれています。

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

[https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases)では、すべてのkernel debug kitを見つけることができます。ダウンロードしてmountし、[Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) toolで開き、**`.kext`** folderにアクセスして**extract**できます。

次のコマンドでsymbolsを確認します：
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**、** [**ipsw.me**](https://ipsw.me/)**、** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Apple は **symbols** 付きの **kernelcache** をリリースすることがあります。これらのページにあるリンクから、symbols 付きの firmware をダウンロードできます。firmware には、その他のファイルとともに **kernelcache** が含まれています。

kernel cache を **extract** するには、次の操作を行います。
```bash
# Install ipsw tool
brew install blacktop/tap/ipsw

# Extract only the kernelcache from the IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# You should get something like:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# If you get an IMG4 payload:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```
**extract** するもう1つの方法は、まず拡張子を `.ipsw` から `.zip` に変更して、**unzip** することです。

firmware を抽出すると、**`kernelcache.release.iphone14`** のようなファイルが得られます。これは **IMG4** format なので、以下を使用して興味深い情報を抽出できます。

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### kernelcache の Inspecting

kernelcache に symbols があるか確認します。
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
これで、**すべての拡張機能**または**関心のある拡張機能**を抽出できるようになります。
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
## 最近の脆弱性と exploitation techniques

| Year | CVE | Summary |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | **`storagekitd`** の logic flaw により、*root* attacker が malicious file-system bundle を登録でき、最終的に **unsigned kext** が load された。これにより **System Integrity Protection (SIP)** を **bypassing** し、永続的な rootkit が可能になった。macOS 14.2 / 15.2 で patch 済み。 <sup>[[2]](#references)</sup>  |
| 2021 | **CVE-2021-30892** (*Shrootless*) | `com.apple.rootless.install` entitlement を持つ installation daemon が abuse され、任意の post-install scripts の execute、SIP の disable、任意の kext の load が可能だった。 <sup>[[3]](#references)</sup> |

**red-teamers 向けの take-aways**

1. **Disk Arbitration、Installer、または Kext Management とやり取りする entitled daemons（`codesign -dvv /path/bin | grep entitlements`）を探す。**
2. **SIP bypass の abuse は、ほぼ常に kext を load する能力、つまり kernel code execution を与える。**

**Defensive tips**

*SIP は有効にしておく*。Apple 製ではない binary から実行された `kmutil load` / `kmutil create -n aux` の invocation を監視し、`/Library/Extensions` へのあらゆる write に対して alert を出す。Endpoint Security event の `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` により、ほぼ real-time の visibility が得られる。

## macOS kernel と kext の debugging

Apple が推奨する workflow は、実行中の build に一致する **Kernel Debug Kit (KDK)** を build し、その後 **KDP (Kernel Debugging Protocol)** の network session 経由で **LLDB** を attach することだ。

### panic の one-shot local debug
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### 別の Mac からのライブリモートデバッグ

1. 対象マシン用の正確な **KDK** バージョンをダウンロードしてインストールします。
2. **USB-C または Thunderbolt ケーブル**で対象 Mac とホスト Mac を接続します。
3. **対象側**で:
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. **host**上で:
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### 特定のロード済み kext への LLDB のアタッチ
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP は **read-only** インターフェースのみを提供します。dynamic instrumentation を行うには、ディスク上の binary に patch を適用するか、**kernel function hooking**（例: `mach_override`）を利用するか、完全な read/write のために driver を **hypervisor** に移行する必要があります。

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Microsoft finds new macOS vulnerability, Shrootless, that could bypass System Integrity Protection - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)

{{#include ../../../banners/hacktricks-training.md}}
