# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Kernel extensions (Kexts), ana işletim sistemine ek işlevsellik sağlayan ve **doğrudan macOS kernel alanına yüklenen**, **`.kext`** uzantılı **paketlerdir**.

### Kullanımdan kaldırılma durumu ve DriverKit / System Extensions
**macOS Catalina (10.15)** ile Apple, eski KPI'ların çoğunu *deprecated* olarak işaretledi ve **user-space** ortamında çalışan **System Extensions & DriverKit** framework'lerini kullanıma sundu. **macOS Big Sur (11)** itibarıyla işletim sistemi, deprecated KPI'lara dayanan üçüncü taraf kext'leri, makine **Reduced Security** modunda boot edilmediği sürece *yüklemeyi reddeder*. Apple Silicon üzerinde kext'leri etkinleştirmek için kullanıcının ayrıca:

1. **Recovery** moduna yeniden boot etmesi → *Startup Security Utility*.
2. **Reduced Security** seçeneğini seçmesi ve **“Allow user management of kernel extensions from identified developers”** seçeneğini işaretlemesi.
3. Yeniden boot etmesi ve **System Settings → Privacy & Security** üzerinden kext'i onaylaması gerekir.

DriverKit/System Extensions ile yazılan user-land driver'lar **attack surface'i önemli ölçüde azaltır**, çünkü crash'ler veya memory corruption kernel alanı yerine sandbox'lanmış bir process ile sınırlı kalır.<sup>[[1]](#references)</sup>

> 📝 macOS Sequoia (15) ile Apple, birkaç eski networking ve USB KPI'ını tamamen kaldırdı – vendor'lar için forward-compatible tek çözüm System Extensions'a migrate etmektir.

### Gereksinimler

Açıkça, bu işlem o kadar güçlüdür ki bir kernel extension yüklemek **karmaşıktır**. Bir kernel extension'ın yüklenebilmesi için karşılaması gereken **gereksinimler** şunlardır:

- **Recovery mode'a girilirken**, kernel **extension'larının yüklenmesine izin verilmelidir**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension, yalnızca **Apple tarafından verilebilen** bir kernel code signing certificate ile **imzalanmış** olmalıdır. Apple, şirketi ve buna neden ihtiyaç duyulduğunu ayrıntılı olarak inceler.
- Kernel extension ayrıca **notarized** olmalıdır; Apple extension'ı malware açısından kontrol edebilir.
- Ardından, kernel extension'ı **yükleyebilen** kullanıcı **root** kullanıcısıdır ve paket içindeki dosyalar **root'a ait** olmalıdır.
- Upload işlemi sırasında paket, korumalı ve root olmayan bir konumda hazırlanmalıdır: `/Library/StagedExtensions` (`com.apple.rootless.storage.KernelExtensionManagement` grant'i gerektirir).
- Son olarak, yüklemeye çalışırken kullanıcı [**bir onay isteği alır**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) ve onaylanırsa extension'ı yüklemek için bilgisayar **yeniden başlatılmalıdır**.

### Yükleme süreci

Catalina'da süreç şu şekildeydi: **verification** sürecinin userland'de gerçekleştiğini belirtmek ilginçtir. Ancak yalnızca **`com.apple.private.security.kext-management`** grant'ine sahip uygulamalar **kernel'den bir extension yüklemesini isteyebilir**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli, bir extension'ın yüklenmesi için **verification** sürecini **başlatır**
- Bir **Mach service** kullanarak mesaj gönderip **`kextd`** ile iletişim kurar.
2. **`kextd`**, **signature** gibi çeşitli unsurları kontrol eder
- Extension'ın **yüklenip yüklenemeyeceğini kontrol etmek** için **`syspolicyd`** ile iletişim kurar.
3. Extension daha önce yüklenmemişse **`syspolicyd`** kullanıcıya **prompt gösterir**.
- **`syspolicyd`** sonucu **`kextd`**'ye bildirir
4. **`kextd`** sonunda kernel'e extension'ı **yüklemesini söyleyebilir**

**`kextd`** mevcut değilse, **`kextutil`** aynı kontrolleri gerçekleştirebilir.

### Enumeration ve management (loaded kexts)

`kextstat` geçmişte kullanılan tool'du ancak yeni macOS sürümlerinde **deprecated** durumdadır. Modern interface **`kmutil`**'dir:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Eski sözdizimi referans olarak hâlâ kullanılabilir:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect`, bir Kernel Collection (KC) içeriğini **dump** etmek veya bir kext'in tüm symbol dependencies'lerini çözdüğünü doğrulamak için de kullanılabilir:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Kernel extension'ların `/System/Library/Extensions/` içinde bulunması beklenmesine rağmen bu klasöre giderseniz **hiçbir binary bulamazsınız**. Bunun nedeni **kernelcache**'tir ve bir `.kext` dosyasını reverse etmek için onu elde etmenin bir yolunu bulmanız gerekir.

**Kernelcache**, temel cihaz **sürücüleri** ve **kernel extension**'larla birlikte **önceden derlenmiş ve önceden bağlanmış bir XNU kernel sürümüdür**. **Sıkıştırılmış** bir formatta saklanır ve boot işlemi sırasında belleğe açılır. Kernelcache, çalıştırılmaya hazır kernel ve kritik sürücüleri kullanılabilir durumda tutarak daha **hızlı bir boot süresi** sağlar; böylece bu bileşenlerin boot sırasında dinamik olarak yüklenmesi ve bağlanması için normalde harcanacak zaman ve kaynaklar azalır.

Kernelcache'in temel avantajları **yükleme hızıdır** ve tüm modüllerin önceden bağlanmış olmasıdır (yükleme zamanı engeli yoktur). Ayrıca tüm modüller önceden bağlandıktan sonra KXLD bellekten kaldırılabilir; böylece **XNU yeni KEXT'ler yükleyemez.**

> [!TIP]
> [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) aracı, Apple'ın AEA (Apple Encrypted Archive / AEA asset) container'larını (Apple'ın OTA asset'leri ve bazı IPSW parçaları için kullandığı şifreli container formatı) decrypt eder ve ardından sağlanan aastuff araçlarıyla extract edebileceğiniz temel `.dmg`/asset arşivini üretebilir.


### Yerel Kernelcache

iOS'ta **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** konumunda bulunur; macOS'ta şu komutla bulabilirsiniz: **`find / -name "kernelcache" 2>/dev/null`** \
Benim durumumda macOS'ta şu konumda buldum:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Ayrıca [**symbols içeren 14 sürümüne ait kernelcache'i**](https://x.com/tihmstar/status/1295814618242318337?lang=en) burada bulabilirsiniz.

#### IMG4 / BVX2 (LZFSE) compressed

IMG4 file format, Apple tarafından iOS ve macOS cihazlarında **kernelcache** gibi **firmware** bileşenlerini güvenli bir şekilde **saklamak ve doğrulamak** için kullanılan bir container formatıdır. IMG4 formatı bir header ve gerçek payload (kernel veya bootloader gibi), bir signature ve bir manifest properties kümesi dahil olmak üzere farklı veri parçalarını kapsülleyen çeşitli tag'ler içerir. Format, cryptographic verification desteği sunar ve cihazın firmware bileşenini çalıştırmadan önce bileşenin gerçekliğini ve bütünlüğünü doğrulamasını sağlar.

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

**`Disarm`**, matcher'ları kullanarak kernelcache içindeki işlevlere sembol bilgisi eklenmesini sağlar. Bu matcher'lar, disarm'a bir binary içindeki işlevleri, argümanları ve panic/log dizelerini nasıl tanıyıp otomatik olarak sembol bilgisi ekleyeceğini söyleyen basit pattern kurallarıdır (metin satırlarıdır).

Temel olarak, bir işlevin kullandığı dizeyi belirtirsiniz ve disarm bu dizeyi bulup **sembol bilgisi ekler**.

[https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) adresindeki **`Matchers`** bölümünde bazı `xnu.matchers` bulabilirsiniz. Ayrıca kendi matcher'larınızı da oluşturabilirsiniz.
```bash
# Go to /tmp/extracted where disarm extracted the filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```
### İndirme

Bir **IPSW (iPhone/iPad Software)**, Apple’ın cihaz geri yüklemeleri, güncellemeleri ve tam firmware paketleri için kullandığı firmware paket formatıdır. Diğer şeylerin yanı sıra **kernelcache** içerir.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

[https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) adresinde tüm kernel debug kitlerini bulmak mümkündür. Bunları indirebilir, mount edebilir, [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) aracıyla açabilir, **`.kext`** klasörüne erişebilir ve **extract** edebilirsiniz.

Şu komutla sembolleri kontrol edin:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Apple bazen **symbols** içeren **kernelcache** yayımlar. Bu sayfalardaki bağlantıları takip ederek **symbols** içeren bazı firmware'leri indirebilirsiniz. Firmware'ler, diğer dosyaların yanı sıra **kernelcache** de içerir.

Kernel cache'i **extract** etmek için şunları yapabilirsiniz:
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
**dosyaları çıkarmak** için başka bir seçenek, uzantıyı `.ipsw` yerine `.zip` olarak değiştirmek ve dosyayı **unzip** etmektir.

Firmware'ı çıkardıktan sonra şu tür bir dosya elde edersiniz: **`kernelcache.release.iphone14`**. Bu dosya **IMG4** formatındadır; ilginç bilgileri şu araçla çıkarabilirsiniz:

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
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### kernelcache'i İnceleme

kernelcache'in sembollere sahip olup olmadığını şununla kontrol edin
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Bununla artık **tüm uzantıları** veya **ilgilendiğiniz uzantıyı** çıkarabiliriz:
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
| 2024 | **CVE-2024-44243** | **`storagekitd`** içindeki mantık hatası, *root* saldırganın sonunda **unsigned kext** yükleyen kötü amaçlı bir file-system bundle kaydetmesine olanak sağladı; bu durum **System Integrity Protection (SIP)** mekanizmasını **bypassing** ederek kalıcı rootkit'leri mümkün kıldı. macOS 14.2 / 15.2 sürümlerinde düzeltildi. <sup>[[2]](#references)</sup>  |
| 2021 | **CVE-2021-30892** (*Shrootless*) | `com.apple.rootless.install` entitlement'ına sahip Installation daemon, rastgele post-install script'leri çalıştırmak, SIP'yi devre dışı bırakmak ve rastgele kext'ler yüklemek için kötüye kullanılabiliyordu. <sup>[[3]](#references)</sup> |

**red-teamers için çıkarımlar**

1. **Disk Arbitration, Installer veya Kext Management ile etkileşime giren entitlement'lara sahip daemon'ları (`codesign -dvv /path/bin | grep entitlements`) arayın.**
2. **SIP bypass'leri neredeyse her zaman bir kext yükleme yetkisi sağlar → kernel code execution**.

**Defensive ipuçları**

*SIP'yi etkin tutun*, Apple dışı binary'lerden gelen `kmutil load`/`kmutil create -n aux` çağrılarını izleyin ve `/Library/Extensions` konumuna yapılan tüm yazma işlemleri için uyarı oluşturun. Endpoint Security olayları `ES_EVENT_TYPE_NOTIFY_KEXTLOAD`, neredeyse gerçek zamanlı görünürlük sağlar.

## macOS kernel & kext'lerinde debugging

Apple'ın önerdiği workflow, çalışan build ile eşleşen bir **Kernel Debug Kit (KDK)** oluşturmak ve ardından bir **KDP (Kernel Debugging Protocol)** network session üzerinden **LLDB**'ye bağlanmaktır.

### Bir panic için tek seferlik local debug
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Başka bir Mac'ten canlı uzak debugging

1. Hedef makine için tam olarak aynı **KDK** sürümünü indirin ve yükleyin.
2. Hedef Mac ile host Mac'i **USB-C veya Thunderbolt kablosu** kullanarak bağlayın.
3. **Hedefte**:
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. **host** üzerinde:
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### Belirli bir yüklü kext'e LLDB ile bağlanma
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP yalnızca **read-only** bir arayüz sunar. Dinamik instrumentation için diskteki binary'yi patch etmeniz, **kernel function hooking** (ör. `mach_override`) kullanmanız veya tam read/write desteği için driver'ı bir **hypervisor**'a taşımanız gerekir.

## Referanslar

- [1] [macOS için DriverKit security - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [CVE-2024-44243'ün analizi: kernel extensions üzerinden gerçekleştirilen bir macOS System Integrity Protection bypass'ı - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Microsoft, System Integrity Protection'ı bypass edebilen yeni bir macOS vulnerability'si olan Shrootless'ı buldu - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)

{{#include ../../../banners/hacktricks-training.md}}
