# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Kernel uzantıları (Kexts), **macOS çekirdek alanına doğrudan yüklenen** ve ana işletim sistemine ek işlevsellik sağlayan **`.kext`** uzantısına sahip **paketlerdir**.

### Kullanımdan kaldırma durumu & DriverKit / Sistem Uzantıları
**macOS Catalina (10.15)** ile birlikte Apple, çoğu eski KPI'yi *kullanımdan kaldırılmış* olarak işaretledi ve **Kullanıcı Alanı**'nda çalışan **Sistem Uzantıları & DriverKit** çerçevelerini tanıttı. **macOS Big Sur (11)** ile birlikte işletim sistemi, **Azaltılmış Güvenlik** modunda önyüklenmedikçe, kullanımdan kaldırılmış KPI'lere dayanan üçüncü taraf kext'leri *yüklemeyi reddedecektir*. Apple Silicon'da, kext'leri etkinleştirmek ayrıca kullanıcının:

1. **Recovery**'ye yeniden başlatması → *Başlangıç Güvenlik Aracı*.
2. **Azaltılmış Güvenlik**'i seçmesi ve **“Tanımlı geliştiricilerden kernel uzantılarının kullanıcı yönetimine izin ver”** seçeneğini işaretlemesi.
3. Yeniden başlatması ve kext'i **Sistem Ayarları → Gizlilik & Güvenlik**'ten onaylaması gerekir.

DriverKit/Sistem Uzantıları ile yazılan kullanıcı alanı sürücüleri, çökme veya bellek bozulmalarının çekirdek alanı yerine bir sandboxed süreçle sınırlı olmasından dolayı **saldırı yüzeyini önemli ölçüde azaltır**.

> 📝 macOS Sequoia (15) ile Apple, birkaç eski ağ ve USB KPI'sini tamamen kaldırdı – satıcılar için tek ileri uyumlu çözüm, Sistem Uzantılarına geçiş yapmaktır.

### Gereksinimler

Açıkça, bu kadar güçlü olduğu için **bir kernel uzantısını yüklemek karmaşıktır**. Bir kernel uzantısının yüklenebilmesi için karşılaması gereken **gereksinimler** şunlardır:

- **Kurtarma moduna** geçerken, kernel **uzantılarının yüklenmesine izin verilmelidir**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel uzantısı, yalnızca **Apple** tarafından **verilebilen** bir kernel kod imzalama sertifikası ile **imzalanmış olmalıdır**. Şirketin detaylı bir şekilde inceleneceği ve neden gerektiği.
- Kernel uzantısı ayrıca **notarize** edilmelidir, Apple bunun için kötü amaçlı yazılım kontrolü yapabilecektir.
- Ardından, **root** kullanıcısı, **kernel uzantısını yükleyebilen** kişidir ve paket içindeki dosyalar **root'a ait olmalıdır**.
- Yükleme sürecinde, paket **korumalı bir kök olmayan konumda** hazırlanmalıdır: `/Library/StagedExtensions` (bu, `com.apple.rootless.storage.KernelExtensionManagement` iznini gerektirir).
- Son olarak, yüklemeye çalışırken, kullanıcı [**bir onay isteği alacaktır**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) ve kabul edilirse, bilgisayar **yeniden başlatılmalıdır**.

### Yükleme süreci

Catalina'da bu şekildeydi: **doğrulama** sürecinin **kullanıcı alanında** gerçekleştiğini belirtmek ilginçtir. Ancak, yalnızca **`com.apple.private.security.kext-management`** iznine sahip uygulamalar **çekirdeğe bir uzantı yüklemesi isteminde bulunabilir**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **bir uzantının yüklenmesi için doğrulama** sürecini **başlatır**
- **`kextd`** ile bir **Mach servisi** kullanarak iletişim kurar.
2. **`kextd`**, **imzayı** kontrol etmek gibi birkaç şeyi kontrol eder
- Uzantının **yüklenip yüklenemeyeceğini kontrol etmek için** **`syspolicyd`** ile iletişim kurar.
3. **`syspolicyd`**, uzantı daha önce yüklenmemişse **kullanıcıya** **sorular sorar**.
- **`syspolicyd`**, sonucu **`kextd`**'ye bildirir.
4. **`kextd`**, nihayetinde **çekirdeğe uzantıyı yüklemesini** söyleyebilir.

Eğer **`kextd`** mevcut değilse, **`kextutil`** aynı kontrolleri gerçekleştirebilir.

### Sayım & yönetim (yüklenmiş kext'ler)

`kextstat` tarihi bir araçtı ama son macOS sürümlerinde **kullanımdan kaldırılmıştır**. Modern arayüz **`kmutil`**'dir:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Eski sözdizimi hala referans için mevcuttur:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` ayrıca **bir Kernel Collection (KC) içeriğini dökmek** veya bir kext'in tüm sembol bağımlılıklarını çözdüğünü doğrulamak için de kullanılabilir:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> `/System/Library/Extensions/` içinde kernel uzantılarının bulunması beklenmesine rağmen, bu klasöre giderseniz **hiçbir ikili dosya bulamayacaksınız**. Bunun nedeni **kernelcache**'dir ve bir `.kext`'i tersine mühendislik yapmak için onu elde etmenin bir yolunu bulmanız gerekir.

**Kernelcache**, **XNU çekirdeğinin önceden derlenmiş ve önceden bağlantılı bir versiyonudur**, ayrıca temel cihaz **sürücüleri** ve **kernel uzantıları** ile birlikte gelir. **Sıkıştırılmış** bir formatta depolanır ve önyükleme süreci sırasında belleğe açılır. Kernelcache, çekirdeğin ve kritik sürücülerin çalışmaya hazır bir versiyonunu bulundurarak **daha hızlı bir önyükleme süresi** sağlar; bu, bu bileşenlerin dinamik olarak yüklenmesi ve bağlanması için harcanacak zaman ve kaynakları azaltır.

### Yerel Kernelcache

iOS'ta **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** içinde bulunur, macOS'ta ise şu komutla bulabilirsiniz: **`find / -name "kernelcache" 2>/dev/null`** \
Benim durumumda macOS'ta şurada buldum:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

IMG4 dosya formatı, Apple tarafından iOS ve macOS cihazlarında **firmware** bileşenlerini güvenli bir şekilde **saklamak ve doğrulamak** için kullanılan bir konteyner formatıdır (örneğin **kernelcache**). IMG4 formatı, gerçek yük (örneğin bir çekirdek veya önyükleyici), bir imza ve bir dizi manifest özelliklerini kapsayan başlık ve birkaç etiket içerir. Format, cihazın firmware bileşeninin özgünlüğünü ve bütünlüğünü doğrulamasına olanak tanıyan kriptografik doğrulamayı destekler.

Genellikle aşağıdaki bileşenlerden oluşur:

- **Payload (IM4P)**:
- Genellikle sıkıştırılmıştır (LZFSE4, LZSS, …)
- İsteğe bağlı olarak şifrelenmiş
- **Manifest (IM4M)**:
- İmza içerir
- Ek Anahtar/Değer sözlüğü
- **Restore Info (IM4R)**:
- APNonce olarak da bilinir
- Bazı güncellemelerin tekrar oynatılmasını engeller
- İSTEĞE BAĞLI: Genellikle bulunmaz

Kernelcache'i açın:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### İndir

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

[https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) adresinde tüm kernel hata ayıklama kitlerini bulmak mümkündür. Bunu indirebilir, bağlayabilir, [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) aracıyla açabilir, **`.kext`** klasörüne erişebilir ve **çıkarabilirsiniz**.

Semboller için kontrol edin:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Bazen Apple **kernelcache** ile **symbols** yayınlar. Bu sayfalardaki bağlantıları takip ederek sembollerle bazı firmware'leri indirebilirsiniz. Firmware'ler diğer dosyaların yanı sıra **kernelcache** içerecektir.

Dosyaları **çıkarmak** için uzantıyı `.ipsw`'den `.zip`'e değiştirin ve **açın**.

Firmware'i çıkardıktan sonra **`kernelcache.release.iphone14`** gibi bir dosya elde edeceksiniz. Bu **IMG4** formatındadır, ilginç bilgileri çıkarmak için:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Kernelcache'i İnceleme

Kernelcache'in sembollere sahip olup olmadığını kontrol edin
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Bununla artık **tüm uzantıları** veya **ilginizi çeken uzantıyı** **çıkarabiliriz:**
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
## Son güvenlik açıkları ve istismar teknikleri

| Yıl | CVE | Özet |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | **`storagekitd`** içindeki mantık hatası, *root* bir saldırganın kötü niyetli bir dosya sistemi paketi kaydetmesine izin verdi ve bu da nihayetinde **imzasız bir kext** yükleyerek **Sistem Bütünlüğü Koruması'nı (SIP) atlatmasına** ve kalıcı rootkit'ler etkinleştirmesine neden oldu. macOS 14.2 / 15.2'de yamanmıştır.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | `com.apple.rootless.install` yetkisine sahip kurulum daemon'u, keyfi post-install betiklerini çalıştırmak, SIP'yi devre dışı bırakmak ve keyfi kext'leri yüklemek için kötüye kullanılabilir.  |

**Kırmızı takım için çıkarımlar**

1. **Disk Arbitration, Installer veya Kext Yönetimi ile etkileşimde bulunan yetkili daemon'lar için (`codesign -dvv /path/bin | grep entitlements`) arama yapın.**
2. **SIP'yi kötüye kullanmak, neredeyse her zaman bir kext yükleme yeteneği sağlar → çekirdek kodu yürütme**.

**Savunma ipuçları**

*SIP'yi etkin tutun*, Apple dışı ikili dosyalardan gelen `kmutil load`/`kmutil create -n aux` çağrılarını izleyin ve `/Library/Extensions`'a yapılan her yazım için uyarı verin. Endpoint Security olayları `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` neredeyse gerçek zamanlı görünürlük sağlar.

## macOS çekirdeği ve kext'lerin hata ayıklaması

Apple'ın önerdiği iş akışı, çalışan sürümle eşleşen bir **Kernel Debug Kit (KDK)** oluşturmak ve ardından **KDP (Kernel Debugging Protocol)** ağ oturumu üzerinden **LLDB**'yi bağlamaktır.

### Bir panik için tek seferlik yerel hata ayıklama
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Başka bir Mac'ten canlı uzaktan hata ayıklama

1. Hedef makine için tam **KDK** sürümünü indirin ve kurun.
2. Hedef Mac'i ve ana Mac'i **USB-C veya Thunderbolt kablosu** ile bağlayın.
3. **Hedef** üzerinde:
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
### Belirli bir yüklü kext'e LLDB'yi Ekleme
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP yalnızca **salt okunur** bir arayüz sunar. Dinamik enstrümantasyon için, diskteki ikili dosyayı yamanız, **kernel fonksiyonunu yakalama** (örneğin `mach_override`) kullanmanız veya sürücüyü tam okuma/yazma için bir **hypervisor**'a geçirmeniz gerekecektir.

## References

- DriverKit Güvenliği – Apple Platform Güvenlik Kılavuzu
- Microsoft Güvenlik Blogu – *CVE-2024-44243 SIP bypass'ını Analiz Etme*

{{#include ../../../banners/hacktricks-training.md}}
