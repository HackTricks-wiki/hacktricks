# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Kernel extensions (Kexts), ana işletim sistemine ek işlevsellik sağlayan ve **doğrudan macOS kernel alanına yüklenen**, **`.kext`** uzantılı **paketlerdir**.

### Kullanımdan kaldırılma durumu ve DriverKit / System Extensions
**macOS Catalina (10.15)** ile birlikte Apple, eski KPI'ların çoğunu *kullanımdan kaldırılmış* olarak işaretledi ve **user-space** içinde çalışan **System Extensions & DriverKit** framework'lerini kullanıma sundu. **macOS Big Sur (11)** sürümünden itibaren işletim sistemi, makine **Reduced Security** modunda başlatılmadıkça, kullanımdan kaldırılmış KPI'lara dayanan üçüncü taraf kext'leri *yüklemeyi reddeder*. Apple Silicon üzerinde kext'leri etkinleştirmek için kullanıcının ayrıca şunları yapması gerekir:

1. **Recovery** modunda yeniden başlatın → *Startup Security Utility*.
2. **Reduced Security** seçeneğini belirleyin ve **“Allow user management of kernel extensions from identified developers”** seçeneğini işaretleyin.
3. Yeniden başlatın ve kext'i **System Settings → Privacy & Security** üzerinden onaylayın.

DriverKit/System Extensions ile yazılan user-land driver'ları, çökmeler veya bellek bozulması kernel alanı yerine sandbox'lanmış bir process ile sınırlandırıldığından **attack surface'i önemli ölçüde azaltır**.<sup>[1]</sup>

> 📝 macOS Sequoia'dan (15) itibaren Apple, eski networking ve USB KPI'larının birkaçını tamamen kaldırdı – vendor'lar için forward-compatible tek çözüm System Extensions'a geçiş yapmaktır.

### Gereksinimler

Açıkça, bu işlem kernel extension yüklemeyi **zorlaştıracak kadar güçlüdür**. Bir kernel extension'ın yüklenebilmesi için karşılaması gereken **gereksinimler** şunlardır:

- **Recovery mode'a girilirken**, kernel **extension'larının yüklenmesine izin verilmelidir**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension, yalnızca **Apple tarafından verilebilen** bir kernel code signing certificate ile **imzalanmış** olmalıdır. Apple, şirketi ve buna neden ihtiyaç duyulduğunu ayrıntılı olarak inceleyecektir.
- Kernel extension ayrıca **notarized** olmalıdır; Apple onu malware açısından kontrol edebilir.
- Ardından, kernel extension'ı **yükleyebilen** kullanıcı **root** kullanıcısıdır ve paket içindeki dosyalar **root'a ait** olmalıdır.
- Upload işlemi sırasında paket, korumalı ve root olmayan bir konum olan `/Library/StagedExtensions` içinde hazırlanmalıdır (`com.apple.rootless.storage.KernelExtensionManagement` grant'i gerekir).
- Son olarak, yüklemeyi denediğinde kullanıcı [**bir confirmation request alır**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) ve bu kabul edilirse, yüklenebilmesi için bilgisayarın **yeniden başlatılması** gerekir.

### Yükleme süreci

Catalina'da süreç şu şekildeydi: **verification** sürecinin userland'de gerçekleştiğini belirtmek ilginçtir. Ancak yalnızca **`com.apple.private.security.kext-management`** grant'ine sahip uygulamalar bir extension'ın yüklenmesini kernel'den **talep edebilir**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli, bir extension'ın yüklenmesi için **verification** sürecini **başlatır**
- Bir **Mach service** kullanarak mesaj gönderip **`kextd`** ile iletişim kurar.
2. **`kextd`**, **signature** gibi çeşitli şeyleri kontrol eder
- Extension'ın **yüklenip yüklenemeyeceğini kontrol etmek** için **`syspolicyd`** ile iletişim kurar.
3. Extension daha önce yüklenmemişse **`syspolicyd`** kullanıcıya **prompt gösterir**.
- **`syspolicyd`**, sonucu **`kextd`**'ye bildirir
4. **`kextd`** son olarak extension'ın **yüklenmesi için kernel'e talimat verebilir**

**`kextd`** kullanılabilir değilse **`kextutil`** aynı kontrolleri gerçekleştirebilir.

### Enumeration ve management (loaded kexts)

`kextstat` geçmişte kullanılan araçtı, ancak güncel macOS sürümlerinde **deprecated** durumdadır. Modern interface **`kmutil`**'dir:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Eski sözdizimi hâlâ referans olarak kullanılabilir:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect`, bir Kernel Collection (KC) içeriğini **dump etmek** veya bir kext'in tüm sembol bağımlılıklarını çözdüğünü doğrulamak için de kullanılabilir:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Kernel extensions'ın `/System/Library/Extensions/` içinde bulunması beklense de bu klasöre gittiğinizde **hiçbir binary bulamazsınız**. Bunun nedeni **kernelcache**'tir ve bir `.kext` dosyasını reverse etmek için onu elde etmenin bir yolunu bulmanız gerekir.

**kernelcache**, temel aygıt **driver'ları** ve **kernel extension'lar** ile birlikte **XNU kernel'ının önceden derlenmiş ve önceden linklenmiş bir sürümüdür**. **Sıkıştırılmış** bir formatta saklanır ve boot-up işlemi sırasında memory'ye açılır. Kernelcache, kernel'ın ve kritik driver'ların çalışmaya hazır bir sürümünü kullanıma sunarak **daha hızlı boot süresi** sağlar; böylece boot sırasında bu bileşenleri dinamik olarak yüklemek ve linklemek için harcanacak zaman ve kaynaklar azalır.

Kernelcache'in temel avantajları **yükleme hızı** ve tüm module'lerin önceden linklenmiş olmasıdır (yükleme süresinde herhangi bir engel yoktur). Tüm module'ler önceden linklendikten sonra KXLD memory'den kaldırılabilir; bu nedenle **XNU yeni KEXT'ler yükleyemez.**

> [!TIP]
> [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool'u, Apple'ın AEA (Apple Encrypted Archive / AEA asset) container'larını deşifre eder. Bunlar Apple'ın OTA asset'leri ve bazı IPSW parçaları için kullandığı şifreli container formatıdır. Tool, daha sonra sağlanan aastuff tool'larıyla extract edebileceğiniz temel .dmg/asset archive'ını oluşturabilir.


### Yerel Kernelcache

iOS'ta `/System/Library/Caches/com.apple.kernelcaches/kernelcache` konumunda bulunur; macOS'ta şu komutla bulabilirsiniz: **`find / -name "kernelcache" 2>/dev/null`** \
Benim macOS durumumda şu konumda buldum:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Burada ayrıca [**symbols içeren version 14 kernelcache'ini**](https://x.com/tihmstar/status/1295814618242318337?lang=en) bulabilirsiniz.

#### IMG4 / BVX2 (LZFSE) compressed

IMG4 file format, Apple tarafından iOS ve macOS cihazlarında **firmware** bileşenlerini (örneğin **kernelcache**) güvenli bir şekilde **saklamak ve doğrulamak** için kullanılan bir container formatıdır. IMG4 formatı, gerçek payload'u (kernel veya bootloader gibi), bir signature'ı ve manifest property'lerinden oluşan bir seti kapsülleyen bir header ve çeşitli tag'ler içerir. Format, cryptographic verification'ı destekler ve cihazın firmware bileşenini çalıştırmadan önce gerçekliğini ve bütünlüğünü doğrulamasını sağlar.

Genellikle aşağıdaki bileşenlerden oluşur:

- **Payload (IM4P)**:
- Genellikle compressed (LZFSE4, LZSS, …)
- İsteğe bağlı olarak encrypted
- **Manifest (IM4M)**:
- Signature içerir
- Ek bir Key/Value dictionary
- **Restore Info (IM4R)**:
- APNonce olarak da bilinir
- Bazı update'lerin replay edilmesini önler
- OPTIONAL: Genellikle bu bulunmaz

Kernelcache'i decompress edin:
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
#### Kernel için Disarm sembolleri

**`Disarm`**, matcher'ları kullanarak kernelcache içindeki işlevleri symbolicate etmeye olanak tanır. Bu matcher'lar, disarm'a bir binary içindeki işlevleri, argümanları ve panic/log string'lerini nasıl tanıyıp otomatik olarak symbolicate edeceğini bildiren basit pattern kurallarıdır (metin satırlarıdır).

Temel olarak, bir işlevin kullandığı string'i belirtirsiniz ve disarm onu bulup **symbolicate eder**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# disarm'ın fileset'leri çıkardığı /tmp/extracted dizinine gidin
disarm -e filesets kernelcache.release.d23 # Her zaman /tmp/extracted dizinine çıkarın
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # xnu.matchers'ın aslında matcher'ları içeren bir dosya olduğunu unutmayın
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
# ipsw tool'u yükle
brew install blacktop/tap/ipsw

# Yalnızca kernelcache'i IPSW'den çıkar
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Şuna benzer bir çıktı almalısın:
#   out/Firmware/kernelcache.release.iPhoneXX
#   veya bir IMG4 payload'u: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Bir IMG4 payload'u alırsan:
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
# En son panic için bir symbolication bundle oluşturun
```bash
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
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
(lldb) bt  # kernel bağlamında backtrace al
```

### Attaching LLDB to a specific loaded kext

```bash
# kext'in yükleme adresini belirle
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Bağlan
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

{{#include ../../../banners/hacktricks-training.md}}
