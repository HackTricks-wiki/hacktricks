# macOS Dosyaları, Klasörleri, Binaries ve Bellek

{{#include ../../../banners/hacktricks-training.md}}

## Dosya hiyerarşisi düzeni

- **/Applications**: Yüklü uygulamalar burada bulunmalıdır. Tüm kullanıcılar bunlara erişebilir.
- **/bin**: Command line binaries
- **/cores**: Varsa core dump'ları depolamak için kullanılır.
- **/dev**: Her şey bir dosya olarak ele alındığından, donanım cihazlarının burada depolandığını görebilirsiniz.
- **/etc**: Yapılandırma dosyaları
- **/Library**: Tercihler, cache'ler ve log'larla ilgili birçok alt dizin ve dosya burada bulunabilir. Root dizininde ve her kullanıcının dizininde bir Library klasörü bulunur.
- **/private**: Belgelenmemiştir, ancak bahsedilen klasörlerin çoğu private dizinine sembolik link'lerdir.
- **/sbin**: Temel system binaries (administration ile ilgili)
- **/System**: OS X'in çalışmasını sağlayan dosyalar. Burada çoğunlukla yalnızca Apple'a özgü dosyalar bulunmalıdır (third-party dosyalar değil).
- **/tmp**: Dosyalar 3 gün sonra silinir (`/private/tmp` konumuna soft link'tir).
- **/Users**: Kullanıcıların home directory'si.
- **/usr**: Config ve system binaries
- **/var**: Log dosyaları
- **/Volumes**: Mount edilmiş drive'lar burada görünür.
- **/.vol**: `stat a.txt` komutunu çalıştırdığınızda `16777223 7545753 -rw-r--r-- 1 username wheel ...` benzeri bir çıktı alırsınız; ilk sayı dosyanın bulunduğu volume'ün ID numarası, ikinci sayı ise inode numarasıdır. Bu bilgileri kullanarak `cat /.vol/16777223/7545753` komutunu çalıştırıp bu dosyanın içeriğine `/.vol/` üzerinden erişebilirsiniz.

### Applications Klasörleri

- **System applications**, `/System/Applications` altında bulunur.
- **Installed** applications genellikle `/Applications` veya `~/Applications` konumuna yüklenir.
- **Application data**, root olarak çalışan uygulamalar için `/Library/Application Support` konumunda, kullanıcı olarak çalışan uygulamalar için ise `~/Library/Application Support` konumunda bulunabilir.
- **Root olarak çalışması gereken** third-party uygulama **daemons**'ları genellikle `/Library/PrivilegedHelperTools/` konumunda bulunur.
- **Sandboxed** uygulamalar `~/Library/Containers` klasörüne map edilir. Her uygulama, uygulamanın bundle ID'sine (`com.apple.Safari`) göre adlandırılmış bir klasöre sahiptir.
- **kernel**, `/System/Library/Kernels/kernel` konumunda bulunur.
- **Apple'ın kernel extensions**'ları `/System/Library/Extensions` konumunda bulunur.
- **Third-party kernel extensions**, `/Library/Extensions` konumunda depolanır.

### Hassas Bilgiler İçeren Dosyalar

MacOS, passwords gibi bilgileri çeşitli konumlarda depolar:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Vulnerable pkg installers


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## OS X'e Özgü Extensions

- **`.dmg`**: Apple Disk Image dosyaları installers için çok sık kullanılır.
- **`.kext`**: Belirli bir yapıyı izlemelidir ve OS X'in driver sürümüdür (bir bundle'dır).
- **`.plist`**: Property list olarak da bilinir; bilgileri XML veya binary formatında depolar.
- XML veya binary olabilir. Binary olanlar şu komutlarla okunabilir:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Directory structure'ı izleyen Apple uygulamalarıdır (bir bundle'dır).
- **`.dylib`**: Dynamic libraries (Windows DLL dosyaları gibi)
- **`.pkg`**: xar (eXtensible Archive format) ile aynıdır. Installer command, bu dosyaların içeriğini yüklemek için kullanılabilir.
- **`.DS_Store`**: Bu dosya her directory'de bulunur; directory'nin attribute'larını ve özelleştirmelerini kaydeder.
- **`.Spotlight-V100`**: Bu klasör sistemdeki her volume'ün root directory'sinde görünür.
- **`.metadata_never_index`**: Bu dosya bir volume'ün root'unda bulunuyorsa Spotlight o volume'ü index'lemez.
- **`.noindex`**: Bu extension'a sahip dosya ve klasörler Spotlight tarafından index'lenmez.
- **`.sdef`**: Bir bundle içindeki, AppleScript'ten uygulamayla nasıl etkileşim kurulabileceğini belirten dosyalardır.

### macOS Bundles

Bir bundle, **Finder'da bir nesne gibi görünen** bir **directory**'dir (Bundle örneği `*.app` dosyalarıdır).


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

macOS'te (ve iOS'te) frameworks ve dylibs gibi tüm system shared libraries, **dyld shared cache** olarak adlandırılan **tek bir dosyada birleştirilir**. Bu, kodun daha hızlı yüklenebilmesini sağlayarak performansı artırmıştır.

macOS'te `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` konumunda bulunur; eski sürümlerde **shared cache**'i **`/System/Library/dyld/`** konumunda bulabilirsiniz.\
iOS'te bunları **`/System/Library/Caches/com.apple.dyld/`** konumunda bulabilirsiniz.

Dyld shared cache'e benzer şekilde kernel ve kernel extensions da bir kernel cache içinde derlenir ve boot sırasında yüklenir.

Libraries'leri tek dosyalı dylib shared cache'ten çıkarmak için [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) binary'si kullanılabiliyordu; günümüzde çalışmıyor olabilir, ancak [**dyldextractor**](https://github.com/arandomdev/dyldextractor) da kullanabilirsiniz:
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> `dyld_shared_cache_util` tool'u çalışmasa bile **shared dyld binary'yi Hopper'a aktarabileceğinizi** ve Hopper'ın tüm kütüphaneleri tanımlayarak araştırmak istediğiniz **kütüphaneyi seçmenize** olanak sağlayacağını unutmayın:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Bazı extractor'lar, dylib'ler sabit kodlanmış adreslerle prelinked edildiğinden çalışmayabilir; bu nedenle bilinmeyen adreslere atlıyor olabilirler.

> [!TIP]
> Xcode'da bir emulator kullanarak macOS içinden diğer \*OS cihazlarının Shared Library Cache'ini indirmek de mümkündür. Bunlar şu konuma indirilir: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, örneğin:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### SLC Mapping

**`dyld`**, SLC'nin map edilip edilmediğini öğrenmek için **`shared_region_check_np`** syscall'ını (adresi döndürür) ve SLC'yi map etmek için **`shared_region_map_and_slide_np`** syscall'ını kullanır.

SLC ilk kullanımda slide edilse bile tüm **process'lerin** **aynı kopyayı** kullandığını unutmayın; bu durum, saldırgan sistemde process çalıştırabiliyorsa **ASLR** korumasını ortadan kaldırıyordu. Bu durum geçmişte exploit edildi ve shared region pager ile düzeltildi.

Branch pools, image mapping'leri arasında küçük alanlar oluşturan ve fonksiyonların interpose edilmesini imkansız hale getiren küçük Mach-O dylib'lerdir.

### SLC'leri Override Etme

Aşağıdaki env değişkenlerini kullanarak:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Bu, yeni bir shared library cache yüklenmesini sağlar
- **`DYLD_SHARED_CACHE_DIR=avoid`** ve kütüphaneleri manuel olarak shared cache'teki gerçek kütüphanelere symlink'lerle değiştirin (bunları extract etmeniz gerekir)

## Özel Dosya İzinleri

### Klasör izinleri

Bir **klasörde**, **read** klasörü **listelemeye**, **write** klasördeki dosyaları **silme** ve **yazmaya**, **execute** ise dizinde **gezinmeye** olanak sağlar. Örneğin, bir dizinin içinde bulunan **bir dosya üzerinde read iznine** sahip olan, ancak dizin üzerinde **execute** izni **olmayan** bir kullanıcı **dosyayı okuyamaz**.

### Flag değiştiricileri

Dosyalarda, dosyanın farklı davranmasına neden olan bazı flag'ler ayarlanabilir. Bir dizindeki dosyaların **flag'lerini** `ls -lO /path/directory` ile **kontrol edebilirsiniz**.

- **`uchg`**: **uchange** flag'i olarak bilinir ve **dosyayı** değiştiren veya silen **herhangi bir işlemi engeller**. Ayarlamak için: `chflags uchg file.txt`
- Root user **flag'i kaldırabilir** ve dosyayı değiştirebilir
- **`restricted`**: Bu flag, dosyanın **SIP tarafından korunmasını** sağlar (bu flag'i bir dosyaya ekleyemezsiniz).
- **`Sticky bit`**: Sticky bit'e sahip bir dizinde dosyaları yalnızca **dizinin sahibi veya root yeniden adlandırabilir ya da silebilir**. Bu genellikle /tmp dizininde ayarlanır ve normal kullanıcıların diğer kullanıcıların dosyalarını silmesini veya taşımasını engeller.

Tüm flag'ler `sys/stat.h` dosyasında bulunabilir (`mdfind stat.h | grep stat.h` kullanarak bulun) ve şunlardır:

- `UF_SETTABLE` 0x0000ffff: Owner tarafından değiştirilebilen flag'lerin maskesi.
- `UF_NODUMP` 0x00000001: Dosyayı dump etme.
- `UF_IMMUTABLE` 0x00000002: Dosya değiştirilemez.
- `UF_APPEND` 0x00000004: Dosyaya yapılan yazma işlemleri yalnızca append edebilir.
- `UF_OPAQUE` 0x00000008: Directory, union'a göre opaque'tır.
- `UF_COMPRESSED` 0x00000020: Dosya compressed durumdadır (bazı file-system'ler).
- `UF_TRACKED` 0x00000040: Bu flag ayarlanmış dosyalar için silme/yeniden adlandırma bildirimi yoktur.
- `UF_DATAVAULT` 0x00000080: Okuma ve yazma için entitlement gereklidir.
- `UF_HIDDEN` 0x00008000: Bu öğenin bir GUI'de gösterilmemesi gerektiğine dair ipucu.
- `SF_SUPPORTED` 0x009f0000: Superuser tarafından desteklenen flag'lerin maskesi.
- `SF_SETTABLE` 0x3fff0000: Superuser tarafından değiştirilebilen flag'lerin maskesi.
- `SF_SYNTHETIC` 0xc0000000: Sistem tarafından salt okunur synthetic flag'lerin maskesi.
- `SF_ARCHIVED` 0x00010000: Dosya arşivlenmiştir.
- `SF_IMMUTABLE` 0x00020000: Dosya değiştirilemez.
- `SF_APPEND` 0x00040000: Dosyaya yapılan yazma işlemleri yalnızca append edebilir.
- `SF_RESTRICTED` 0x00080000: Yazma için entitlement gereklidir.
- `SF_NOUNLINK` 0x00100000: Öğe kaldırılamaz, yeniden adlandırılamaz veya üzerine mount edilemez.
- `SF_FIRMLINK` 0x00800000: Dosya bir firmlink'tir.
- `SF_DATALESS` 0x40000000: Dosya dataless object'tir.

### **Dosya ACL'leri**

Dosya **ACL'leri**, farklı kullanıcılara daha **granüler izinler** atanabilen **ACE** (Access Control Entries) içerir.

Bir **directory** için şu izinler verilebilir: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Bir **file** içinse: `read`, `write`, `append`, `execute`.

Dosya ACL içerdiğinde, **izinleri listelerken şu örnekteki gibi bir "+" işareti görürsünüz**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Dosyanın ACL'lerini şu şekilde **okuyabilirsiniz**:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
**ACL'lere sahip tüm dosyaları** şu komutla bulabilirsiniz (bu çooook yavaştır):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Genişletilmiş Öznitelikler

Genişletilmiş özniteliklerin bir adı ve istenen herhangi bir değeri vardır; bunlar `ls -@` kullanılarak görüntülenebilir ve `xattr` komutuyla değiştirilebilir. Bazı yaygın genişletilmiş öznitelikler şunlardır:

- `com.apple.resourceFork`: Resource fork uyumluluğu. Ayrıca `filename/..namedfork/rsrc` olarak da görünür
- `com.apple.quarantine`: MacOS: Gatekeeper quarantine mekanizması (III/6)
- `metadata:*`: MacOS: `_backup_excludeItem` veya `kMD*` gibi çeşitli metadata
- `com.apple.lastuseddate` (#PS): Dosyanın son kullanım tarihi
- `com.apple.FinderInfo`: MacOS: Finder bilgileri (ör. renkli Tags)
- `com.apple.TextEncoding`: ASCII metin dosyalarının text encoding bilgisini belirtir
- `com.apple.logd.metadata`: `/var/db/diagnostics` içindeki dosyalarda logd tarafından kullanılır
- `com.apple.genstore.*`: Generational storage (dosya sisteminin kökündeki `/.DocumentRevisions-V100`)
- `com.apple.rootless`: MacOS: System Integrity Protection tarafından dosyayı etiketlemek için kullanılır (III/10)
- `com.apple.uuidb.boot-uuid`: Benzersiz UUID ile boot epoch'larının logd işaretleri
- `com.apple.decmpfs`: MacOS: Transparent file compression (II/7)
- `com.apple.cprotect`: \*OS: Dosya başına encryption verileri (III/11)
- `com.apple.installd.*`: \*OS: `installType`, `uniqueInstallID` gibi installd tarafından kullanılan metadata

### Resource Forks | macOS ADS

Bu, **MacOS** makinelerinde **Alternate Data Streams** elde etmenin bir yoludur. İçeriği, bir dosyanın içindeki **com.apple.ResourceFork** adlı genişletilmiş öznitelikte, içeriği **file/..namedfork/rsrc** içine kaydederek saklayabilirsiniz.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Şu komutla **bu extended attribute'u içeren tüm dosyaları bulabilirsiniz**:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Genişletilmiş öznitelik `com.apple.decmpfs`, dosyanın şifrelenmiş olarak depolandığını belirtir; `ls -l` **0 boyut** bildirir ve sıkıştırılmış veriler bu özniteliğin içinde bulunur. Dosyaya her erişildiğinde bellekte şifresi çözülür.

Bu öznitelik, `ls -lO` komutuyla sıkıştırılmış olarak görülebilir; çünkü sıkıştırılmış dosyalar `UF_COMPRESSED` bayrağıyla da işaretlenir. Sıkıştırılmış bir dosyanın bayrağı `chflags nocompressed </path/to/file>` ile kaldırılırsa sistem dosyanın sıkıştırılmış olduğunu anlayamaz ve bu nedenle veriyi açıp erişemez (dosyanın aslında boş olduğunu düşünür).

afscexpand aracı, bir dosyanın sıkıştırmasını zorla açmak için kullanılabilir.


### İlginç yapılandırma konumları (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Sistem daemon'larındaki / framework'lerindeki isteğe bağlı veya deneysel davranışları kontrol eden Apple feature-flag plist dosyalarını depolar | Bir attacker SIP'i bypass edebilir veya privilege elde edebilirse bu dosyaları değiştirmek gizli code path'lerini etkinleştirebilir ya da güvenlik önlemlerini devre dışı bırakabilir |
| `/System/Library/CoreServices/systemVersion.plist` | Uygulamaların / installer'ların davranışlarını kısıtlamak için kullandığı macOS sürüm metadata'sını (ProductVersion, BuildVersion) içerir | Değiştirilmesi, uygulamaları veya installer'ları desteklenmeyen işletim sistemi sürümlerini kabul etmeleri ya da özelliklerin kilidini açmaları için kandırabilir |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Uygulama / sistem genelindeki tercihleri içerir | Yazılabilir durumdaysa attacker'lar uygulama davranışını yönlendirecek, korumaları devre dışı bırakacak veya yanlış yapılandırmaya neden olacak ayarlar enjekte edebilir |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Arka plan daemon'ları ve agent'ları için plist tanımlarını içerir | Kötü amaçlı plist eklenmesi veya değiştirilmesi (izinler elveriyorsa) persistence ya da privilege escalation sağlar |
| `/etc/hosts` | Sistem DNS resolver'ı tarafından kullanılan hostname ↔ IP eşleştirmelerini içerir | Domain adlarını yönlendirme, trafiği intercept etme ve yerel kontrol altındaki servisleri spoof etme |
| `/etc/sudoers` | `sudo` ile hangi kullanıcıların hangi koşullar altında komut çalıştırabileceğini tanımlar | Bozulmuş bir sudoers dosyası, attacker hesaplarına root veya uygunsuz privilege sağlayabilir |
| `/private/var/db/dslocal/nodes/Default/users/` | Yerel kullanıcı hesabı tanım plist'lerini içerir | Değiştirilmesi, kullanıcı hesaplarının, password hash'lerinin veya kullanıcı metadata'sının oluşturulmasına ya da değiştirilmesine olanak tanır |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extension'larını / driver'ları içerir | kext yüklemek veya değiştirmek kernel düzeyinde kontrole yol açabilir; SIP / signature politikaları tarafından yoğun biçimde korunur |
| `/private/var/db/SystemPolicyConfiguration/` | Sistem policy enforcement yapılandırmasını (ör. Gatekeeper, notarization) depolar | Bu dosyaların değiştirilmesi policy kontrollerinin veya trust kurallarının bypass edilmesine olanak tanıyabilir |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH yardımcı binary'lerini ve yapılandırma dosyalarını içerir | Yanlış yapılandırma zayıf SSH security'sine, unauthorized access'e veya güvensiz algorithm'lere yol açar |
| `/System/Library/Sandbox/Profiles` | Process eylemlerini kısıtlamak için kullanılan sistem sandbox profillerini (SBPL) içerir | Profillerin değiştirilmesi veya yenileriyle değiştirilmesi sandbox escape vector'leri açabilir ya da containment'ı zayıflatabilir |

> **Note**: Bu path'lerin çoğu SIP tarafından korunan dizinlerin (ör. `/System`) altında bulunur ve SIP devre dışı bırakılmadıkça veya bypass edilmedikçe yazma işlemine karşı korunur.


## **Universal binaries &** Mach-o Format

Mac OS binary'leri genellikle **universal binary** olarak derlenir. Bir **universal binary**, **aynı dosya içinde birden fazla architecture'ı destekleyebilir**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risk Category Files Mac OS

`/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` dizini, **farklı file extension'larla ilişkili risk hakkındaki bilgilerin depolandığı** konumdur. Bu dizin dosyaları çeşitli risk seviyelerine ayırır ve Safari'nin download sonrasında bu dosyaları nasıl ele alacağını etkiler. Kategoriler şunlardır:

- **LSRiskCategorySafe**: Bu kategorideki dosyalar **tamamen güvenli** kabul edilir. Safari, download edildikten sonra bu dosyaları otomatik olarak açar.
- **LSRiskCategoryNeutral**: Bu dosyalar herhangi bir uyarı göstermez ve Safari tarafından **otomatik olarak açılmaz**.
- **LSRiskCategoryUnsafeExecutable**: Bu kategorideki dosyalar, dosyanın bir application olduğunu belirten **bir uyarıyı tetikler**. Bu, kullanıcıyı uyarmaya yönelik bir security önlemidir.
- **LSRiskCategoryMayContainUnsafeExecutable**: Bu kategori, executable içerebilecek archive'lar gibi dosyalar içindir. Safari, tüm içeriklerin güvenli veya neutral olduğunu doğrulayamazsa **bir uyarı tetikler**.

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Download edilen dosyalar hakkında, örneğin dosyaların download edildiği URL gibi bilgileri içerir.
- **`/var/log/system.log`**: OSX sistemlerinin ana log'udur. `com.apple.syslogd.plist`, syslogging'in yürütülmesinden sorumludur (`launchctl list` çıktısında "com.apple.syslogd" arayarak devre dışı olup olmadığını kontrol edebilirsiniz).
- **`/private/var/log/asl/*.asl`**: Bunlar ilginç bilgiler içerebilen Apple System Logs'tur.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: "Finder" üzerinden yakın zamanda erişilen dosyaları ve application'ları depolar.
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Sistem startup'ında başlatılacak öğeleri depolar.
- **`$HOME/Library/Logs/DiskUtility.log`**: DiskUtility App'inin log dosyasıdır (USB'ler dahil drive'lar hakkında bilgi içerir).
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Wireless access point'ler hakkında veri içerir.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Devre dışı bırakılmış daemon'ların listesidir.

{{#include ../../../banners/hacktricks-training.md}}
