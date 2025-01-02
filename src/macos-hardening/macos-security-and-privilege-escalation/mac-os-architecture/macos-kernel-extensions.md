# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Kernel uzantıları (Kexts), **macOS çekirdek alanına doğrudan yüklenen** ve ana işletim sistemine ek işlevsellik sağlayan **`.kext`** uzantısına sahip **paketlerdir**.

### Gereksinimler

Açıkça, bu kadar güçlü olduğu için **bir kernel uzantısını yüklemek karmaşıktır**. Yüklenebilmesi için bir kernel uzantısının karşılaması gereken **gereksinimler** şunlardır:

- **Kurtarma moduna** girerken, kernel **uzantılarının yüklenmesine izin verilmelidir**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel uzantısı, yalnızca **Apple tarafından verilebilen** bir kernel kod imzalama sertifikası ile **imzalanmış olmalıdır**. Şirketin detaylı bir şekilde inceleneceği ve neden gerektiği.
- Kernel uzantısı ayrıca **notarize edilmelidir**, Apple bunu kötü amaçlı yazılım için kontrol edebilecektir.
- Ardından, **root** kullanıcısı kernel uzantısını **yükleyebilen** kişidir ve paket içindeki dosyalar **root'a ait olmalıdır**.
- Yükleme sürecinde, paket **korumalı bir kök olmayan konumda** hazırlanmalıdır: `/Library/StagedExtensions` (bu, `com.apple.rootless.storage.KernelExtensionManagement` iznini gerektirir).
- Son olarak, yüklemeye çalışırken, kullanıcı [**bir onay isteği alacaktır**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) ve kabul edilirse, bilgisayar **yeniden başlatılmalıdır**.

### Yükleme süreci

Catalina'da böyleydi: **Doğrulama** sürecinin **kullanıcı alanında** gerçekleştiğini belirtmek ilginçtir. Ancak, yalnızca **`com.apple.private.security.kext-management`** iznine sahip uygulamalar **çekirdekten bir uzantıyı yüklemesini isteyebilir**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **bir uzantıyı yüklemek için** **doğrulama** sürecini **başlatır**
- **`kextd`** ile bir **Mach servisi** kullanarak iletişim kuracaktır.
2. **`kextd`** birkaç şeyi kontrol edecektir, örneğin **imzayı**
- Uzantının **yüklenip yüklenemeyeceğini kontrol etmek için** **`syspolicyd`** ile iletişim kuracaktır.
3. **`syspolicyd`**, uzantı daha önce yüklenmemişse **kullanıcıya** **soracaktır**.
- **`syspolicyd`**, sonucu **`kextd`**'ye bildirecektir.
4. **`kextd`** nihayetinde **çekirdeğe uzantıyı yüklemesini söyleyebilecektir**.

Eğer **`kextd`** mevcut değilse, **`kextutil`** aynı kontrolleri gerçekleştirebilir.

### Sayım (yüklenmiş kextler)
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

> [!CAUTION]
> `/System/Library/Extensions/` içinde kernel uzantılarının bulunması beklenmesine rağmen, bu klasöre giderseniz **hiçbir ikili dosya bulamayacaksınız**. Bunun nedeni **kernelcache**'dir ve bir `.kext` dosyasını tersine mühendislik yapmak için onu elde etmenin bir yolunu bulmanız gerekir.

**Kernelcache**, **XNU çekirdeğinin önceden derlenmiş ve önceden bağlantılı bir versiyonudur**, ayrıca temel cihaz **sürücüleri** ve **kernel uzantıları** ile birlikte gelir. **Sıkıştırılmış** bir formatta depolanır ve önyükleme süreci sırasında belleğe açılır. Kernelcache, çekirdeğin ve kritik sürücülerin çalışmaya hazır bir versiyonunu bulundurarak **daha hızlı bir önyükleme süresi** sağlar; bu, bu bileşenlerin dinamik olarak yüklenmesi ve bağlanması için harcanacak zaman ve kaynakları azaltır.

### Yerel Kernelcache

iOS'ta **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** içinde bulunur, macOS'ta ise şunları kullanarak bulabilirsiniz: **`find / -name "kernelcache" 2>/dev/null`** \
Benim durumumda macOS'ta şunu buldum:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

IMG4 dosya formatı, Apple tarafından iOS ve macOS cihazlarında **firmware** bileşenlerini güvenli bir şekilde **saklamak ve doğrulamak** için kullanılan bir konteyner formatıdır (örneğin **kernelcache**). IMG4 formatı, gerçek yük (örneğin bir çekirdek veya önyükleyici), bir imza ve bir dizi manifest özelliklerini kapsayan bir başlık ve birkaç etiket içerir. Format, cihazın firmware bileşeninin özgünlüğünü ve bütünlüğünü doğrulamasına olanak tanıyan kriptografik doğrulamayı destekler.

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
# img4tool (https://github.com/tihmstar/img4tool
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

Bazen Apple **kernelcache** ile **semboller** yayınlar. Bu sayfalardaki bağlantıları takip ederek sembollerle bazı firmware'leri indirebilirsiniz. Firmware'ler diğer dosyaların yanı sıra **kernelcache** içerecektir.

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

Kernelcache'in sembollere sahip olup olmadığını kontrol edin.
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
## Hata Ayıklama

## Referanslar

- [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
- [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{{#include ../../../banners/hacktricks-training.md}}
