# macOS Kernel Uzantıları & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Kernel extensions (Kexts) **paketlerdir** ve **`.kext`** uzantısına sahiptir; **macOS kernel alanına doğrudan yüklenirler** ve ana işletim sistemine ek işlevsellik sağlarlar.

### Kullanımdan Kaldırılma durumu & DriverKit / System Extensions
macOS Catalina (10.15) ile birlikte Apple çoğu eski KPI'yı *kullanımdan kaldırılmış* olarak işaretledi ve **System Extensions & DriverKit** çerçevelerini tanıttı; bunlar **kullanıcı alanında** çalışır. macOS Big Sur (11) itibarıyla işletim sistemi, makine **Reduced Security** modunda önyüklenmedikçe eski KPI'lara dayanan üçüncü taraf kext'leri *yüklemeyi reddedecektir*. Apple Silicon'da kext'leri etkinleştirmek ayrıca kullanıcıdan şunları gerektirir:

1. **Recovery** moduna yeniden başlatma → *Startup Security Utility*.
2. **Reduced Security** seçip **“Allow user management of kernel extensions from identified developers”** seçeneğini işaretleme.
3. Yeniden başlatma ve kext'i **System Settings → Privacy & Security** üzerinden onaylama.

DriverKit/System Extensions ile yazılmış kullanıcı alanı sürücüleri, çökme veya bellek bozulmaları kernel alanı yerine izole edilmiş bir süreç içinde sınırlı kaldığı için **büyük ölçüde saldırı yüzeyini azaltır**.

> 📝 macOS Sequoia (15) ile Apple birkaç eski ağ ve USB KPI'sını tamamen kaldırdı – satıcılar için ileri uyumlu tek çözüm System Extensions'e geçmektir.

### Gereksinimler

Açıkça, bu çok güçlü olduğundan bir kernel uzantısını **yüklemek karmaşıktır**. Bir kernel uzantısının yüklenebilmesi için karşılaması gereken **gereksinimler** şunlardır:

- **Recovery** moduna girildiğinde, kernel uzantılarının yüklenmesine izin verilmiş olmalıdır:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel uzantısı, yalnızca Apple tarafından verilebilen bir **kernel code signing certificate** ile **imzalanmış** olmalıdır. Apple, şirketi ve neden gerekli olduğunu ayrıntılı olarak inceleyecektir.
- Kernel uzantısı ayrıca **notarize edilmiş** olmalıdır; Apple bunu kötü amaçlı yazılım açısından kontrol edebilecektir.
- Ardından, kernel uzantısını yükleyebilecek yetkili kullanıcı **root**'tur ve paket içindeki dosyalar **root'a ait** olmalıdır.
- Yükleme sürecinde paket, korunmuş bir non-root konumda hazırlanmalıdır: `/Library/StagedExtensions` (bu, `com.apple.rootless.storage.KernelExtensionManagement` yetkisini gerektirir).
- Son olarak, yüklemeye çalışıldığında kullanıcı [**onay isteği alacak**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) ve kabul edilirse, bilgisayarın yükleme için **yeniden başlatılması** gerekir.

### Yükleme süreci

Catalina'da süreç şu şekildeydi: İlginç olan, **doğrulama** sürecinin **userland**'da gerçekleşmesidir. Ancak yalnızca `com.apple.private.security.kext-management` yetkisine sahip uygulamalar çekirdeğe bir uzantı yüklemesini **isteyebilir**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI, bir uzantıyı yüklemek için **doğrulama** sürecini **başlatır**
- **`kextutil`**, bir **Mach service** kullanarak **`kextd`** ile haberleşir.
2. **`kextd`** birkaç şeyi, örneğin **imzayı**, kontrol edecektir
- **`kextd`**, uzantının **yüklenip yüklenemeyeceğini** **kontrol etmek** için **`syspolicyd`** ile konuşur.
3. Eğer uzantı daha önce yüklenmemişse **`syspolicyd`** **kullanıcıyı** **uyarır**
- **`syspolicyd`**, sonucu **`kextd`**'ye bildirir.
4. Son olarak **`kextd`**, çekirdeğe uzantıyı **yüklemesini söyleyebilir**

Eğer **`kextd`** mevcut değilse, **`kextutil`** aynı kontrolleri gerçekleştirebilir.

### Listeleme & yönetim (yüklenmiş kext'ler)

`kextstat` tarihsel araçtı ancak son macOS sürümlerinde **kullanımdan kaldırıldı**. Modern arayüz ise **`kmutil`**'dir:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Eski sözdizimi hâlâ başvuru amaçlı mevcuttur:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` ayrıca **Kernel Collection (KC) içeriğini dökmek** veya bir kext'in tüm sembol bağımlılıklarını çözüp çözmediğini doğrulamak için kullanılabilir:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Kernel uzantılarının `/System/Library/Extensions/` içinde olması beklenmesine rağmen, bu klasöre giderseniz **hiçbir ikili (binary) bulamayacaksınız**. Bunun nedeni **kernelcache**'tir ve bir `.kext`'i tersine çevirmek için onu elde etmenin bir yolunu bulmanız gerekir.

**kernelcache**, gerekli cihaz **sürücüleri** ve **kernel uzantıları** ile birlikte XNU kernel'inin **önceden derlenmiş ve önceden bağlanmış (pre-linked) bir sürümüdür**. **Sıkıştırılmış** bir formatta saklanır ve açılış sürecinde belleğe dekomprese edilir. Kernelcache, kernel ve kritik sürücüler için çalıştırmaya hazır bir sürümün bulunmasını sağlayarak **daha hızlı bir boot süresi** sağlar; aksi takdirde bu bileşenlerin boot sırasında dinamik olarak yüklenmesi ve bağlanması için harcanacak zaman ve kaynakları azaltır.

Kernelcache'in ana faydaları **yükleme hızı** ve tüm modüllerin önceden bağlanmış olmasıdır (yükleme zamanı engeli yok). Ve tüm modüller önceden bağlandıktan sonra KXLD bellekten kaldırılabilir, böylece **XNU yeni KEXT'leri yükleyemez.**

> [!TIP]
> https://github.com/dhinakg/aeota aracı Apple’ın AEA (Apple Encrypted Archive / AEA asset) container’larını çözer — Apple’ın OTA varlıkları ve bazı IPSW parçaları için kullandığı şifreli container formatı — ve ardından sağlanan aastuff araçlarıyla çıkarabileceğiniz altındaki .dmg/asset arşivini üretebilir.

### Yerel Kernelcache

iOS'ta **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** içinde bulunur; macOS'ta ise şunu kullanarak bulabilirsiniz: **`find / -name "kernelcache" 2>/dev/null`** \
Benim durumumda macOS'ta şunu buldum:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Ayrıca buradan [**simgelerle birlikte 14 sürümü kernelcache'i**](https://x.com/tihmstar/status/1295814618242318337?lang=en) bulabilirsiniz.

#### IMG4 / BVX2 (LZFSE) sıkıştırılmış

IMG4 dosya formatı, Apple'ın iOS ve macOS cihazlarında firmware bileşenlerini (kernelcache gibi) güvenli şekilde depolamak ve doğrulamak için kullandığı bir container formatıdır. IMG4 formatı, gerçek yükü (kernel veya bootloader gibi), bir imzayı ve bir dizi manifest özelliğini kapsayan farklı veri parçalarını içeren bir header ve birkaç tag içerir. Format kriptografik doğrulamayı destekler; böylece cihaz, firmware bileşenini çalıştırmadan önce özgünlüğünü ve bütünlüğünü onaylayabilir.

Genellikle şu bileşenlerden oluşur:

- **Payload (IM4P)**:
- Genellikle sıkıştırılmıştır (LZFSE4, LZSS, …)
- Opsiyonel olarak şifrelenmiş olabilir
- **Manifest (IM4M)**:
- İmza içerir
- Ek Key/Value sözlüğü
- **Restore Info (IM4R)**:
- APNonce olarak da bilinir
- Bazı güncellemelerin tekrar oynatılmasını engeller
- OPSİYONEL: Genelde bulunmaz

Kernelcache'i dekomprese et:
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
#### Çekirdek için Disarm sembolleri

**`Disarm`** matchers kullanarak kernelcache içindeki functions'ları symbolicate etmeyi sağlar.

Bu matchers, disarm'a binary içindeki functions, arguments ve panic/log string'lerini nasıl tanıyacağını ve auto-symbolicate edeceğini söyleyen basit pattern kuralları (metin satırları)dır.

Yani temelde bir fonksiyonun kullandığı string'i belirtirsiniz ve disarm onu bulup **symbolicate it**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# disarm'ın filesetleri çıkardığı /tmp/extracted dizinine gidin
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
# ipsw aracını yükle
brew install blacktop/tap/ipsw

# IPSW'den sadece kernelcache'i çıkar
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Şuna benzer bir çıktı almalısınız:
#   out/Firmware/kernelcache.release.iPhoneXX
#   veya bir IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Eğer bir IMG4 payload alırsanız:
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
# Tüm uzantıları listele
kextex -l kernelcache.release.iphone14.e
## com.apple.security.sandbox öğesini çıkar
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Tümünü çıkar
kextex_all kernelcache.release.iphone14.e

# Uzantıyı semboller için kontrol et
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
# kext'in yükleme adresini belirle
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Bağlan
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
