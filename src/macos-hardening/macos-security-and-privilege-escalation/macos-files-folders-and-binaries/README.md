# macOS Dosyaları, Klasörleri, İkili Dosyalar ve Bellek

{{#include ../../../banners/hacktricks-training.md}}

## Dosya hiyerarşisinin düzeni

Apple, macOS dosya sistemini sistem, yerel, ağ ve kullanıcı etki alanlarından oluşan bir hiyerarşi olarak belgeler. İçeriklerin tam hâli OS sürümüne göre değişir; sistem konumları giderek daha fazla korunur veya sanallaştırılır. <sup>[[1]](#references)</sup>

- **/Applications**: Yüklenen uygulamalar burada bulunmalıdır. Tüm kullanıcılar bu uygulamalara erişebilir.
- **/bin**: Komut satırı ikili dosyaları
- **/cores**: Varsa core dump dosyalarını depolamak için kullanılır.
- **/dev**: Her şey dosya olarak değerlendirilir; bu nedenle donanım aygıtlarını burada görebilirsiniz.
- **/etc**: Yapılandırma dosyaları
- **/Library**: Tercihler, önbellekler ve günlüklerle ilgili çok sayıda alt dizin ve dosya burada bulunabilir. Kök dizinde ve her kullanıcının dizininde bir Library klasörü bulunur.
- **/private**: Belgelenmemiştir; ancak belirtilen klasörlerin çoğu private dizinine giden sembolik bağlantılardır.
- **/sbin**: Temel sistem ikili dosyaları (yönetimle ilgili)
- **/System**: macOS için gerekli dosyalar; bu ağaç öncelikle Apple tarafından sağlanan bileşenleri içerir.
- **/tmp**: Geçici dosyalar (`/private/tmp` konumuna giden sembolik bağlantı). Geçmişteki kurulumlarda eski geçici dosyalar genellikle düzenli aralıklarla, kimi zaman üç günde bir olarak tanımlanan sürelerde temizlenirdi. Ancak günümüzde temizleme zamanlaması sisteme ve politikaya bağlıdır; buradaki verilerin kalıcı olacağına güvenmeyin.
- **/Users**: Kullanıcıların ana dizini.
- **/usr**: Yapılandırma ve sistem ikili dosyaları
- **/var**: Günlük dosyaları
- **/Volumes**: Bağlanan birimler burada görünür.
- **/.vol**: `stat a.txt` komutunu çalıştırdığınızda `16777223 7545753 -rw-r--r-- 1 username wheel ...` benzeri bir çıktı alırsınız. İlk sayı, dosyanın bulunduğu birimin kimlik numarası; ikinci sayı ise inode numarasıdır. Bu bilgileri kullanarak `cat /.vol/16777223/7545753` komutunu çalıştırıp dosyanın içeriğine `/.vol/` üzerinden erişebilirsiniz.

### Applications Klasörleri

- **Sistem uygulamaları** `/System/Applications` altında bulunur.
- **Yüklenen** uygulamalar genellikle `/Applications` veya `~/Applications` dizinine yüklenir.
- **Uygulama verileri**, root olarak çalışan uygulamalar için `/Library/Application Support` dizininde, kullanıcı olarak çalışan uygulamalar içinse `~/Library/Application Support` dizininde bulunabilir.
- **Root olarak çalışması gereken** üçüncü taraf uygulama **daemon**'ları genellikle `/Library/PrivilegedHelperTools/` konumunda bulunur.
- **Sandboxed** uygulamalar `~/Library/Containers` klasörüne eşlenir. Her uygulamanın, uygulamanın bundle ID'sine (`com.apple.Safari`) göre adlandırılmış bir klasörü vardır.
- **Kernel**, `/System/Library/Kernels/kernel` konumunda bulunur.
- **Apple'ın kernel extension**'ları `/System/Library/Extensions` konumunda bulunur.
- **Üçüncü taraf kernel extension**'ları `/Library/Extensions` dizininde depolanır.

### Hassas Bilgi İçeren Dosyalar

macOS, kimlik bilgileri de dâhil olmak üzere hassas bilgileri çeşitli konumlarda depolar:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Güvenlik Açığı İçeren pkg yükleyicileri


{{#ref}}
macos-installers-abuse.md
{{#endref}}

Bu hiyerarşide görünen yazılabilir Data birimi ile mühürlü System birimi arasındaki fark için bkz. [macOS Sealed System Volume & DataVault](../macos-security-protections/macos-sealed-system-volume-and-datavault.md).

## OS X'e Özgü Uzantılar

- **`.dmg`**: Apple Disk Image dosyaları, yükleyiciler için oldukça yaygındır.
- **`.kext`**: Belirli bir yapıyı izlemesi gereken, OS X sürümündeki bir driver'dır (bir bundle'dır).
- **`.plist`**: Bir property list, yapılandırılmış bilgileri XML veya ikili biçimde depolar.
  - XML veya ikili olabilir. İkili olanlar şu komutlarla okunabilir:
    - `defaults read config.plist`
    - `/usr/libexec/PlistBuddy -c print config.plist`
    - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Standart macOS dizin yapısını izleyen bir uygulama bundle'ı.
- **`.dylib`**: Dinamik kütüphaneler (Windows DLL dosyaları gibi)
- **`.pkg`**: Modern düz yükleyici paketleri XAR arşivleridir; ancak `.pkg`, bir yükleyici biçimidir ve XAR'ın eş anlamlısı değildir. Eski bundle tarzı yükleyici paketleri dizinlerdir. Paket yapısı ve inceleme hakkında bilgi için bkz. [macOS installers](macos-installers-abuse.md). <sup>[[9]](#references)[[12]](#references)</sup>
- **`.DS_Store`**: Her dizinde bulunan bu dosya, dizinin özniteliklerini ve özelleştirmelerini kaydeder.
- **`.Spotlight-V100`**: Bu klasör, sistemdeki her birimin kök dizininde bulunur.
- **`.metadata_never_index`**: Bu dosya birimin kök dizininde bulunursa Spotlight o birimi dizine eklemez.
- **`.noindex`**: Bu uzantıya sahip dosya ve klasörler Spotlight tarafından dizine eklenmez.
- **`.sdef`**: AppleScript'in bir uygulamayla nasıl etkileşime girebileceğini açıklayan bir scripting definition dosyası.

### macOS Bundle'ları

Bundle, Finder'ın tek bir nesne olarak gösterebildiği, standartlaştırılmış bir hiyerarşiye sahip dizindir; uygulama bundle'ları `.app` uzantısını kullanır. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

macOS ve iOS'ta sık kullanılan sistem kütüphaneleri ve framework'ler, uygulama başlangıç performansını artırmak için **dyld shared cache** içine önceden bağlanır. Mantıksal olarak tek bir önbellek gibi ele alınsa da güncel sürümlerde, kelimenin tam anlamıyla tek bir dosya yerine ana önbellek ile birden fazla alt önbellek dosyası bulunabilir. Biçimi ve konumu, OS sürümleri arasında değişen uygulama ayrıntılarıdır. <sup>[[3]](#references)</sup>

macOS'ta bu konum `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` şeklindedir; eski sürümlerde **shared cache**'i **`/System/Library/dyld/`** konumunda bulabilirsiniz.\
iOS'ta bunları **`/System/Library/Caches/com.apple.dyld/`** konumunda bulabilirsiniz.

Dyld shared cache'e benzer şekilde kernel ve kernel extension'lar da kernel cache içinde derlenir ve önyükleme sırasında yüklenir.

Eski sürümlerde bunlar [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) ile çıkarılabiliyordu. Bu derleme güncel cache biçimlerini desteklemeyebilir; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) başka bir seçenektir:

```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```

> [!TIP]
> `dyld_shared_cache_util` aracı çalışmasa bile **shared dyld binary'yi Hopper'a aktarabilirsiniz**; Hopper tüm kütüphaneleri tanıyabilir ve incelemek istediğinizi **seçmenize** olanak tanır:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Dylib'ler sabit kodlanmış adreslerle önceden bağlandığından bazı çıkarıcılar çalışmayabilir; bu nedenle bilinmeyen adreslere atlıyor olabilirler.

> [!TIP]
> Xcode'da bir emulator kullanarak diğer \*OS cihazlarının Shared Library Cache'ini macOS'a indirmek de mümkündür. Bunlar şu dizine indirilir: `ls $HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, örneğin: `$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### SLC'yi Eşleme

**`dyld`**, SLC'nin eşlenip eşlenmediğini öğrenmek için (adresi döndüren) **`shared_region_check_np`** syscall'ını, SLC'yi eşlemek içinse **`shared_region_map_and_slide_np`** syscall'ını kullanır.

SLC ilk kullanımda slid edilse bile tüm **process**'lerin **aynı kopyayı** kullandığını ve saldırgan sistemde process çalıştırabiliyorsa bunun **ASLR** korumasını ortadan kaldırdığını unutmayın. Bu durum geçmişte istismar edilmiş ve shared region pager ile düzeltilmiştir.

Branch pool'lar, image eşlemeleri arasında küçük boşluklar oluşturan ve işlevlerin interpose edilmesini imkânsız kılan küçük Mach-O dylib'leridir.

### Shared-cache ortam kısıtlamaları

`DYLD_SHARED_CACHE_DIR` bir cache dizini belirtirken, `DYLD_SHARED_REGION` bir shared-region modunu seçer. Önceden kullanılan `DYLD_DHARED_REGION` yazımı geçersizdi ve `avoid`, `DYLD_SHARED_CACHE_DIR` için geçerli bir değer değildir. Güncel dyld, `private` modunu özel shared cache'leri kullanma AMFI iznine bağlar; dolayısıyla yalnızca ortam değişkenlerini ayarlamak, bir process'in başka bir cache yükleyebileceği anlamına gelmez. <sup>[[10]](#references)</sup>

## Özel Dosya İzinleri

### Klasör izinleri

Bir dizinde **read** girdileri listelemeye, **write** girdi oluşturmaya veya kaldırmaya, **execute** ise dizinde gezinmeye izin verir. Bu nedenle, bir dosyayı okuyabilen ancak üst dizinlerden geçemeyen bir kullanıcı, dosyaya yolunu kullanarak erişemez. <sup>[[4]](#references)</sup>

### Flag değiştiricileri

Dosyalar davranışlarını değiştiren flag'ler taşıyabilir. Bir dizindeki flag'leri `ls -lO /path/directory` ile inceleyin.

- **`uchg`**: **uchange** flag'i olarak bilinir ve **dosyada** değişiklik yapılmasını veya dosyanın silinmesini **engeller**. Ayarlamak için: `chflags uchg file.txt`
  - Dosya sahibi veya root, bu **user** flag'ini `chflags nouchg file.txt` ile kaldırabilir; bu flag ikisine karşı koruma sağlamaz. Ayrı bir **system** immutable flag'i (`schg`) yalnızca root tarafından kullanılabilir. <sup>[[11]](#references)</sup>
- **`restricted`**: Bu flag, dosyanın **SIP tarafından korunmasını** sağlar (bu flag'i bir dosyaya ekleyemezsiniz).
- **`Sticky bit`**: Sticky bit ayarlanmış bir dizinde, bir girdiyi yalnızca dosyanın sahibi, dizinin sahibi veya root yeniden adlandırabilir ya da silebilir. Kullanıcıların diğer kullanıcıların dosyalarını silmesini veya taşımasını önlemek için genellikle `/tmp` üzerinde etkinleştirilir.

Tüm flag'ler `sys/stat.h` dosyasında bulunabilir (`mdfind stat.h | grep stat.h` ile bulun) ve şunlardır:

- `UF_SETTABLE` 0x0000ffff: Sahip tarafından değiştirilebilir flag'lerin maskesi.
- `UF_NODUMP` 0x00000001: Dosyayı dump etme.
- `UF_IMMUTABLE` 0x00000002: Dosya değiştirilemez.
- `UF_APPEND` 0x00000004: Dosyaya yalnızca ekleme yapılabilir.
- `UF_OPAQUE` 0x00000008: Dizin, union açısından opak.
- `UF_COMPRESSED` 0x00000020: Dosya sıkıştırılmış (bazı dosya sistemlerinde).
- `UF_TRACKED` 0x00000040: Bu flag ayarlanmış dosyalar silindiğinde veya yeniden adlandırıldığında bildirim gönderilmez.
- `UF_DATAVAULT` 0x00000080: Okuma ve yazma için entitlement gerekir.
- `UF_HIDDEN` 0x00008000: Bu öğenin GUI'de görüntülenmemesi gerektiğini belirtir.
- `SF_SUPPORTED` 0x009f0000: Superuser tarafından desteklenen flag'lerin maskesi.
- `SF_SETTABLE` 0x3fff0000: Superuser tarafından değiştirilebilir flag'lerin maskesi.
- `SF_SYNTHETIC` 0xc0000000: Sistem tarafından salt okunur synthetic flag'lerin maskesi.
- `SF_ARCHIVED` 0x00010000: Dosya arşivlenmiş.
- `SF_IMMUTABLE` 0x00020000: Dosya değiştirilemez.
- `SF_APPEND` 0x00040000: Dosyaya yalnızca ekleme yapılabilir.
- `SF_RESTRICTED` 0x00080000: Yazma için entitlement gerekir.
- `SF_NOUNLINK` 0x00100000: Öğe kaldırılamaz, yeniden adlandırılamaz veya üzerine mount edilemez.
- `SF_FIRMLINK` 0x00800000: Dosya bir firmlink'tir.
- `SF_DATALESS` 0x40000000: Dosya dataless bir nesnedir.

### **Dosya ACL'leri**

Dosya **ACL'leri**, farklı kullanıcılara daha **ayrıntılı izinler** atanabilen **ACE**'leri (Access Control Entries) içerir.

Bir **dizine** şu izinleri vermek mümkündür: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Bir **dosya** için: `read`, `write`, `append` ve `execute`.

Dosyada ACL'ler olduğunda, izinleri listelerken şu örnekteki gibi bir "+" **görürsünüz**:

```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```

Dosyanın ACL'lerini **okuyabilirsiniz**:

```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
 0: group:everyone deny delete
```

Aşağıdaki komutla **ACL'lere sahip tüm dosyaları** bulabilirsiniz (bu çok yavaştır):

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

### Extended Attributes

Extended attribute'lar, bir dosyanın sıradan attribute'larından ayrı olarak saklanan adlandırılmış metadata değerleridir. Bunları `ls -l@` ile listeleyin, `xattr` ile inceleyin veya değiştirin. <sup>[[5]](#references)</sup> Yaygın extended attribute'lardan bazıları:

- `com.apple.resourceFork`: Resource fork uyumluluğu. `filename/..namedfork/rsrc` olarak da görülebilir
- `com.apple.quarantine`: macOS Gatekeeper karantina metadata'sı
- `metadata:*`: `_backup_excludeItem` veya `kMD*` gibi macOS metadata'sı
- `com.apple.lastuseddate` (#PS): Dosyanın son kullanım tarihi
- `com.apple.FinderInfo`: Renk etiketleri gibi macOS Finder bilgileri
- `com.apple.TextEncoding`: ASCII metin dosyalarının metin kodlamasını belirtir
- `com.apple.logd.metadata`: `/var/db/diagnostics` içindeki dosyalarda logd tarafından kullanılır
- `com.apple.genstore.*`: Nesil tabanlı depolama (dosya sisteminin kökündeki `/.DocumentRevisions-V100`)
- `com.apple.rootless`: System Integrity Protection ile ilişkili macOS metadata'sı
- `com.apple.uuidb.boot-uuid`: Benzersiz UUID ile önyükleme dönemlerini işaretleyen logd kayıtları
- `com.apple.decmpfs`: macOS şeffaf dosya sıkıştırma metadata'sı
- `com.apple.cprotect`: \*OS: Dosya başına şifreleme verisi (III/11)
- `com.apple.installd.*`: \*OS: `installType` ve `uniqueInstallID` gibi installd tarafından kullanılan metadata

### Resource Forks | macOS ADS

Resource fork'lar macOS'ta alternatif bir data stream sağlar. İçerik `com.apple.ResourceFork` extended attribute'unda saklanabilir ve `file/..namedfork/rsrc` üzerinden erişilebilir.

```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```

Bu **genişletilmiş özniteliği içeren tüm dosyaları bulabilirsiniz**:

```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```

### decmpfs

`com.apple.decmpfs` extended attribute’ü, şeffaf sıkıştırma için metadata depolar; şifreleme olduğunu göstermez. Sıkıştırma biçimine bağlı olarak sıkıştırılmış veriler attribute’te veya bir resource fork’ta depolanabilir ve okuma sırasında şeffaf biçimde açılır.

`UF_COMPRESSED` flag’i, `ls -lO` çıktısında `compressed` olarak görünür. Bu flag’i elle temizlemeyin: bunu yapmak, sistemin sıkıştırılmış gösterimi yanlış yorumlamasına neden olabilir.

Flag’i temizleyen komut, adli inceleme sırasında yararlı olduğu için burada gösterilmiştir; ancak sıkıştırılmış bir dosyada çalıştırılması, metadata’sı onarılana kadar dosyanın boş veya erişilemez görünmesine neden olabilir:

```bash
chflags nocompressed /path/to/file
```

Yerleşik `/usr/bin/afscexpand` yardımcı programı, şeffaf biçimde sıkıştırılmış dosyaların açılmasını zorlayabilir. Ayrı bir üçüncü taraf yardımcı programı olan `afsctool` da Apple dosya sistemi sıkıştırmasını inceleyebilir veya açabilir; ancak yerleşik komutla karıştırılmamalıdır. <sup>[[8]](#references)</sup>


### İlgi çekici yapılandırma konumları (macOS)

| Yol / Konum | Amaç / Yapılandırdığı şey | Güvenlik / Saldırı Potansiyeli |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Sistem daemon’larında / framework’lerinde isteğe bağlı veya deneysel davranışları denetleyen Apple özellik bayrağı plist dosyalarını barındırır | Bir saldırgan SIP’yi aşabilir veya ayrıcalık kazanabilirse, bu dosyaları değiştirerek gizli kod yollarını etkinleştirebilir ya da korumaları devre dışı bırakabilir |
| `/System/Library/CoreServices/systemVersion.plist` | Uygulamaların / yükleyicilerin davranışlarını belirlemek için kullandığı macOS sürüm bilgilerini (ProductVersion, BuildVersion) içerir | Değiştirilmesi, uygulamaları veya yükleyicileri desteklenmeyen OS sürümlerini kabul etmeye ya da özellikleri açmaya ikna edebilir |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Uygulama / sistem genelindeki tercihleri içerir | Yazılabilir durumdaysa saldırganlar uygulama davranışını yönlendirmek, korumaları devre dışı bırakmak veya yanlış yapılandırmaya yol açmak için ayarlar ekleyebilir |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Arka plan daemon’ları ve agent’ları için plist tanımları | İzinler elveriyorsa, kötü amaçlı plist eklemek veya mevcut plist’leri değiştirmek kalıcılık ya da ayrıcalık yükseltme olanağı sağlar |
| `/etc/hosts` | Sistem DNS çözümleyicisinin kullandığı ana bilgisayar adı ↔ IP eşlemeleri | Alan adlarını yönlendirme, trafiği ele geçirme ve yerel denetim altındaki hizmetleri taklit etme olanağı sağlar |
| `/etc/sudoers` | Kimlerin hangi koşullarda `sudo` ile komut çalıştırabileceğini tanımlar | Bozulmuş bir sudoers dosyası, saldırgan hesaplarına root veya uygunsuz ayrıcalıklar verebilir |
| `/private/var/db/dslocal/nodes/Default/users/` | Yerel kullanıcı hesabı tanımlarını içeren plist dosyaları | Bu dosyaları değiştirmek; kullanıcı hesapları, parola hash’leri veya kullanıcı meta verileri oluşturmaya ya da değiştirmeye olanak tanır |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel uzantıları / sürücüleri | Kext yüklemek veya değiştirmek kernel düzeyinde denetim sağlayabilir; SIP / imza ilkeleriyle sıkı biçimde korunurlar |
| `/private/var/db/SystemPolicyConfiguration/` | Sistem ilkesi uygulama yapılandırmasını (ör. Gatekeeper, noter tasdiki) barındırır | Bu dosyaları değiştirmek, ilke denetimlerinin veya güven kurallarının aşılmasına olanak tanıyabilir |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH yardımcı ikili dosyaları ve yapılandırma dosyaları | Yanlış yapılandırma; zayıf SSH güvenliğine, yetkisiz erişime veya güvenli olmayan algoritmalara yol açar |
| `/System/Library/Sandbox/Profiles` | İşlem eylemlerini kısıtlamak için kullanılan sistem sandbox profilleri (SBPL) | Profilleri değiştirmek veya başka profillerle değiştirmek, sandbox kaçış yolları açabilir ya da sınırlandırmayı zayıflatabilir |

> **Not**: Bu yolların birçoğu SIP korumalı dizinlerde (ör. `/System`) yer alır ve SIP devre dışı bırakılmadığı veya aşılmadığı sürece yazmaya karşı korunur.  


## Evrensel İkili Dosyalar ve Mach-O Biçimi

Mach-O, macOS’in yerel çalıştırılabilir dosya biçimidir. Evrensel ya da fat ikili dosya, farklı mimarilere özgü birden fazla Mach-O dilimini tek dosyada bir araya getirir; ilgili sayfada her iki biçim de açıklanmaktadır:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS bellek dökümü

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Dosya Riski ve İşleyici Meta Verileri

LaunchServices, dosya karantinası ve Gatekeeper, macOS’in indirilen dosyaları nasıl işlediğini ve uzantılar ile URL şemaları için hangi uygulamaları seçtiğini birlikte etkiler. Bu veritabanları ve dahili kaynak dosyaları sürümler arasında değişir; özel bir CoreTypes yolunu kararlı bir ilke arayüzü olarak değerlendirmek yerine ilgili sayfalara başvurun:

Eski CoreTypes risk meta verilerini `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` altında sunan sürümlerde yaygın olarak karşılaşılan kategoriler şunlardır:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: Uygulanabilir uygulama ilkesi kapsamında otomatik açılabilecek kadar güvenli kabul edilen içerik.
- **`LSRiskCategoryNeutral`**: Normalde uyarı tetiklemeyen ve otomatik açılmayan içerik.
- **`LSRiskCategoryUnsafeExecutable`**: Kullanıcıya uygulama uyarısı gösterilmesi gereken çalıştırılabilir içerik.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: Çalıştırılabilir içerik barındırabilecek ve daha ayrıntılı inceleme gerektiren arşiv gibi kapsayıcılar.

Bunlar uygulama ayrıntılarıdır; kararlı bir genel ilke API’si değildir. Test edilen macOS sürümündeki gerçek meta verileri ve Safari/Gatekeeper davranışını doğrulayın.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Günlük dosyaları

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: İndirilen dosyalar hakkında, örneğin indirildikleri URL gibi bilgileri içerir.
- **Birleşik günlük**: Güncel macOS sürümlerinde sistem ve uygulama olaylarını `log show` ve `log stream` komutlarıyla sorgulayın. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** ve **`/private/var/log/asl/*.asl`**: Eski sistemlerde hâlâ önem taşıyabilecek eski günlük kayıtlarıdır. Bu sürümlerde `/System/Library/LaunchDaemons/com.apple.syslogd.plist`, `syslogd` yapılandırmasını içerir; `launchctl list | grep com.apple.syslogd` hizmetin yüklenip yüklenmediğini belirlemeye yardımcı olabilir.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: "Finder" üzerinden yakın zamanda erişilen dosya ve uygulamaları saklar.
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Giriş öğeleriyle ilişkilendirilen eski tercih yoludur; modern macOS sürümleri ek mekanizmalar kullanır.
- **`$HOME/Library/Logs/DiskUtility.log`**: USB aygıtları dâhil sürücüler hakkında bilgi içerebilen eski Disk Utility günlüğüdür.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Kablosuz erişim noktaları hakkında veri içerir.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Eski launchd geçersiz kılma verilerini içerir.



## References

- [1] [Apple - Dosya Sistemi Programlama Kılavuzu](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Bundle Programlama Kılavuzu](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Geliştirici Forumları - dyld paylaşımlı önbelleğine genel bakış](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Dosya Sistemi Programlama Kılavuzu: macOS Dosya Sistemi Güvenliği](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - macOS kılavuz sayfası](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - macOS kılavuz sayfası](https://manp.gs/mac/1/log)
- [7] [Apple Geliştirici - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - macOS kılavuz sayfası](https://manp.gs/mac/1/afscexpand)
- [9] [Apple Geliştirici Forumları - Apple Arşivlerini Açma](https://developer.apple.com/forums/thread/133985)
- [10] [Apple dyld - DyldProcessConfig.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [11] [Apple - Shell Script Güvenliği: özel dosya izin bayrakları](https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html)
- [12] [Apple - Kod İmzalama Görevleri: yükleyici paketleri](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
{{#include ../../../banners/hacktricks-training.md}}
