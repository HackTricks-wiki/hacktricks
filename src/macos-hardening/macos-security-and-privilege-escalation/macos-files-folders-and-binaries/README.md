# macOS Dosyaları, Klasörleri, Binaries ve Memory

{{#include ../../../banners/hacktricks-training.md}}

## Dosya hiyerarşisi düzeni

Apple, macOS dosya sistemini system, local, network ve user domain'lerinden oluşan bir hiyerarşi olarak belgeler. Kesin içerikler OS sürümüne göre değişir ve system konumları giderek daha fazla korunur veya sentezlenir. <sup>[[1]](#references)</sup>

- **/Applications**: Yüklü uygulamalar burada bulunmalıdır. Tüm kullanıcılar bunlara erişebilir.
- **/bin**: Command line binaries
- **/cores**: Varsa core dump'ları depolamak için kullanılır.
- **/dev**: Her şey bir dosya olarak ele alındığından, donanım aygıtlarının burada depolandığını görebilirsiniz.
- **/etc**: Configuration files
- **/Library**: Preferences, cache'ler ve log'larla ilgili birçok alt dizin ve dosya burada bulunabilir. Root dizininde ve her kullanıcının dizininde bir Library klasörü bulunur.
- **/private**: Belgelenmemiştir, ancak bahsedilen klasörlerin çoğu private dizinine symbolic link'tir.
- **/sbin**: Essential system binaries (administration ile ilgili)
- **/System**: macOS tarafından gereken dosyalar; bu ağaç öncelikli olarak Apple tarafından sağlanan bileşenleri içerir.
- **/tmp**: Geçici dosyalar (`/private/tmp` konumuna symbolic link'tir). Geçmişteki kurulumlar eski geçici dosyaları genellikle belirli aralıklarla, bazen üç gün olarak ifade edilen bir zamanlamayla temizlerdi; ancak güncel temizleme zamanlaması system ve policy'ye bağlıdır. Verilerin burada kalıcı olacağına güvenmeyin.
- **/Users**: Kullanıcıların home directory'si.
- **/usr**: Config ve system binaries
- **/var**: Log files
- **/Volumes**: Mount edilmiş volume'lar burada görünür.
- **/.vol**: `stat a.txt` komutunu çalıştırdığınızda `16777223 7545753 -rw-r--r-- 1 username wheel ...` gibi bir çıktı alırsınız; burada ilk sayı dosyanın bulunduğu volume'un ID numarası, ikinci sayı ise inode numarasıdır. Bu bilgileri kullanarak `cat /.vol/16777223/7545753` komutuyla dosyanın içeriğine `/.vol/` üzerinden erişebilirsiniz.

### Applications Folders

- **System applications**, `/System/Applications` altında bulunur.
- **Installed** applications genellikle `/Applications` veya `~/Applications` içine yüklenir.
- **Application data**, root olarak çalışan uygulamalar için `/Library/Application Support` konumunda, user olarak çalışan uygulamalar için ise `~/Library/Application Support` konumunda bulunabilir.
- **Root olarak çalışması gereken** üçüncü taraf uygulama **daemons**'ları genellikle `/Library/PrivilegedHelperTools/` konumunda bulunur.
- **Sandboxed** uygulamalar `~/Library/Containers` klasörüne map edilir. Her uygulamanın application bundle ID'sine (`com.apple.Safari`) göre adlandırılmış bir klasörü vardır.
- **Kernel**, `/System/Library/Kernels/kernel` konumunda bulunur.
- **Apple'ın kernel extensions**'ları `/System/Library/Extensions` konumunda bulunur.
- **Third-party kernel extensions**, `/Library/Extensions` içinde depolanır.

### Sensitive Information İçeren Dosyalar

macOS, credentials da dahil olmak üzere sensitive information'ı çeşitli konumlarda depolar:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Vulnerable pkg installers


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## OS X'e Özgü Extensions

- **`.dmg`**: Apple Disk Image dosyaları installer'lar için oldukça yaygındır.
- **`.kext`**: Belirli bir yapıyı izlemelidir ve driver'ın OS X sürümüdür. (bir bundle'dır)
- **`.plist`**: Bir property list, structured information'ı XML veya binary formatında depolar.
- XML veya binary olabilir. Binary olanlar şu komutlarla okunabilir:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plist`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Standart macOS directory structure'ını izleyen bir application bundle'dır.
- **`.dylib`**: Dynamic libraries (Windows DLL dosyaları gibi)
- **`.pkg`**: xar (eXtensible Archive format) ile aynıdır. Installer command, bu dosyaların içeriğini yüklemek için kullanılabilir.
- **`.DS_Store`**: Bu dosya her directory'de bulunur; directory'nin attributes ve customisation'larını kaydeder.
- **`.Spotlight-V100`**: Bu klasör system'deki her volume'un root directory'sinde görünür.
- **`.metadata_never_index`**: Bu dosya bir volume'un root'unda bulunuyorsa Spotlight o volume'u index'lemez.
- **`.noindex`**: Bu extension'a sahip dosyalar ve klasörler Spotlight tarafından index'lenmez.
- **`.sdef`**: AppleScript'in bir uygulamayla nasıl etkileşime girebileceğini açıklayan bir scripting definition file'dır.

### macOS Bundles

Bir bundle, Finder'ın tek bir nesne olarak sunabileceği standartlaştırılmış bir hiyerarşiye sahip directory'dir; application bundle'ları `.app` extension'ını kullanır. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

macOS ve iOS'ta yaygın olarak kullanılan system libraries ve framework'ler **dyld shared cache** içine önceden link'lenir; bu, uygulamaların startup performansını iyileştirir. Tek bir logical cache olarak ele alınsa da güncel sürümler bunu gerçek anlamda tek bir dosya yerine bir main cache ve birden çok subcache dosyası olarak depolayabilir. Formatı ve konumu, OS sürümleri arasında değişen implementation detail'leridir. <sup>[[3]](#references)</sup>

macOS'ta bu konum `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`, eski sürümlerde ise **shared cache**'i **`/System/Library/dyld/`** içinde bulabilirsiniz.\
iOS'ta bunları **`/System/Library/Caches/com.apple.dyld/`** içinde bulabilirsiniz.

Dyld shared cache'e benzer şekilde kernel ve kernel extensions da bir kernel cache içine derlenir ve boot sırasında yüklenir.

Eski sürümler [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) ile extract edilebilirdi. Bu build güncel cache formatlarını desteklemeyebilir; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) başka bir seçenektir:
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> `dyld_shared_cache_util` tool'u çalışmasa bile **shared dyld binary**'yi **Hopper**'a aktarabilirsiniz; Hopper tüm kütüphaneleri tanımlayabilir ve incelemek istediğiniz **hangisini** seçmenize izin verir:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Bazı extractor'lar çalışmaz; çünkü dylib'ler sabit kodlanmış adreslerle prelinked edilmiştir ve bu nedenle bilinmeyen adreslere atlıyor olabilirler.

> [!TIP]
> Xcode'da bir emulator kullanarak macos içinde diğer \*OS cihazlarının Shared Library Cache'lerini indirmek de mümkündür. Bunlar şu konuma indirilir: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, örneğin:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`**, SLC'nin map edilip edilmediğini öğrenmek için **`shared_region_check_np`** syscall'ını (adresi döndürür) ve SLC'yi map etmek için **`shared_region_map_and_slide_np`** syscall'ını kullanır.

SLC ilk kullanımda slide edilmiş olsa bile tüm **process'lerin** **aynı kopyayı** kullandığını unutmayın; bu durum, saldırgan sistemde process çalıştırabiliyorsa **ASLR** korumasını ortadan kaldırır. Bu durum geçmişte gerçekten exploit edildi ve shared region pager ile düzeltildi.

Branch pool'ları, image mapping'leri arasında küçük alanlar oluşturan ve böylece fonksiyonların interpose edilmesini imkansız hale getiren küçük Mach-O dylib'lerdir.

### Override SLCs

Şu env variable'ları kullanarak:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Bu, yeni bir shared library cache yüklenmesine izin verir
- **`DYLD_SHARED_CACHE_DIR=avoid`** ve kütüphaneleri manuel olarak shared cache'teki gerçek kütüphanelere symlink'lerle değiştirerek (bunları extract etmeniz gerekir)

## Special File Permissions

### Folder permissions

Bir directory için **read** girişlerin listelenmesine, **write** giriş oluşturulmasına veya kaldırılmasına ve **execute** traversal yapılmasına izin verir. Sonuç olarak, bir parent directory'yi traverse edemeyen ancak bir dosyayı okuyabilen kullanıcı, o dosyaya path üzerinden erişemez. <sup>[[4]](#references)</sup>

### Flag modifiers

Dosyalar davranışlarını değiştiren flag'ler taşıyabilir. Bir directory'deki flag'leri `ls -lO /path/directory` ile inceleyin.

- **`uchg`**: **uchange** flag'i olarak bilinir ve **file** üzerinde değişiklik yapacak veya onu silecek **herhangi bir action'ı engeller**. Ayarlamak için: `chflags uchg file.txt`
- Root user **flag'i kaldırabilir** ve dosyayı değiştirebilir
- **`restricted`**: Bu flag dosyanın **SIP tarafından korunmasını** sağlar (bu flag'i bir dosyaya ekleyemezsiniz).
- **`Sticky bit`**: Sticky bit ayarlanmış bir directory'de yalnızca file owner, directory owner veya root bir girişi yeniden adlandırabilir ya da silebilir. Bu özellik, kullanıcıların diğer kullanıcıların dosyalarını silmesini veya taşımasını engellemek için genellikle `/tmp` üzerinde etkinleştirilir.

Tüm flag'ler `sys/stat.h` dosyasında bulunabilir (`mdfind stat.h | grep stat.h` komutunu kullanarak bulun) ve şunlardır:

- `UF_SETTABLE` 0x0000ffff: Owner tarafından değiştirilebilen flag'lerin maskesi.
- `UF_NODUMP` 0x00000001: File dump edilmez.
- `UF_IMMUTABLE` 0x00000002: File değiştirilemez.
- `UF_APPEND` 0x00000004: File'a yapılan write işlemleri yalnızca append edilebilir.
- `UF_OPAQUE` 0x00000008: Directory, union açısından opaque'tır.
- `UF_COMPRESSED` 0x00000020: File compressed durumdadır (bazı file-system'lerde).
- `UF_TRACKED` 0x00000040: Bu flag ayarlanmış file'lar için delete/rename notification'ları yoktur.
- `UF_DATAVAULT` 0x00000080: Read ve write için entitlement gereklidir.
- `UF_HIDDEN` 0x00008000: Bu item'ın bir GUI'de görüntülenmemesi gerektiğini belirten ipucu.
- `SF_SUPPORTED` 0x009f0000: Superuser tarafından desteklenen flag'lerin maskesi.
- `SF_SETTABLE` 0x3fff0000: Superuser tarafından değiştirilebilen flag'lerin maskesi.
- `SF_SYNTHETIC` 0xc0000000: Sistem tarafından read-only olarak kullanılan synthetic flag'lerin maskesi.
- `SF_ARCHIVED` 0x00010000: File archive edilmiştir.
- `SF_IMMUTABLE` 0x00020000: File değiştirilemez.
- `SF_APPEND` 0x00040000: File'a yapılan write işlemleri yalnızca append edilebilir.
- `SF_RESTRICTED` 0x00080000: Write için entitlement gereklidir.
- `SF_NOUNLINK` 0x00100000: Item kaldırılamaz, yeniden adlandırılamaz veya üzerine mount edilemez.
- `SF_FIRMLINK` 0x00800000: File bir firmlink'tir.
- `SF_DATALESS` 0x40000000: File dataless bir object'tir.

### **File ACLs**

File **ACL**'leri, farklı kullanıcılara daha **granular permissions** atanabilen **ACE**'ler (Access Control Entries) içerir.

Bir **directory**'ye şu permissions'lar verilebilir: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Bir **file** için: `read`, `write`, `append` ve `execute`.

File ACL'ler içerdiğinde, **permissions'ları listelerken şu örnekteki gibi bir "+" görürsünüz**:
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
Aşağıdaki komutla **ACL'lere sahip tüm dosyaları** bulabilirsiniz (bu işlem çok yavaştır):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Extended Attributes

Extended attributes, bir dosyanın normal özniteliklerinden ayrı olarak depolanan, adlandırılmış metadata değerleridir. Bunları `ls -l@` ile listeleyebilir, `xattr` ile inceleyebilir veya değiştirebilirsiniz. <sup>[[5]](#references)</sup> Yaygın extended attribute'lerden bazıları şunlardır:

- `com.apple.resourceFork`: Resource fork uyumluluğu. `filename/..namedfork/rsrc` olarak da görülebilir
- `com.apple.quarantine`: macOS Gatekeeper quarantine metadata'sı
- `metadata:*`: `_backup_excludeItem` veya `kMD*` gibi macOS metadata'sı
- `com.apple.lastuseddate` (#PS): Dosyanın son kullanım tarihi
- `com.apple.FinderInfo`: Renk etiketleri gibi macOS Finder bilgileri
- `com.apple.TextEncoding`: ASCII metin dosyalarının text encoding'ini belirtir
- `com.apple.logd.metadata`: `/var/db/diagnostics` içindeki dosyalarda logd tarafından kullanılır
- `com.apple.genstore.*`: Generational storage (dosya sisteminin kök dizinindeki `/.DocumentRevisions-V100`)
- `com.apple.rootless`: System Integrity Protection ile ilişkili macOS metadata'sı
- `com.apple.uuidb.boot-uuid`: Benzersiz UUID ile boot epoch'larının logd işaretlemeleri
- `com.apple.decmpfs`: macOS transparent file compression metadata'sı
- `com.apple.cprotect`: \*OS: Dosya başına encryption verileri (III/11)
- `com.apple.installd.*`: \*OS: `installType`, `uniqueInstallID` gibi installd tarafından kullanılan metadata

### Resource Forks | macOS ADS

Resource forks, macOS üzerinde alternatif bir data stream sağlar. İçerik `com.apple.ResourceFork` extended attribute'ünde depolanabilir ve `file/..namedfork/rsrc` üzerinden erişilebilir.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Şu genişletilmiş özniteliği içeren tüm dosyaları **bulabilirsiniz**:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

`com.apple.decmpfs` extended attribute'ı şeffaf compression için metadata depolar; encryption belirtmez. Compression formatına bağlı olarak compressed data attribute içinde veya resource fork'ta depolanabilir ve okuma sırasında şeffaf biçimde decompressed edilir.

`UF_COMPRESSED` flag'i `ls -lO` çıktısında `compressed` olarak görünür. Bu flag'i manuel olarak temizlemeyin: aksi takdirde sistem compressed representation'ı yanlış yorumlayabilir.

Flag'i temizleyen command, forensic review sırasında kullanışlı olduğu için burada gösterilmiştir; ancak bunu compressed bir file üzerinde çalıştırmak, metadata onarılana kadar file'ın boş veya erişilemez görünmesine neden olabilir:
```bash
chflags nocompressed /path/to/file
```
Yerleşik `/usr/bin/afscexpand` utility'si, transparently compressed dosyaların genişletilmesini zorlayabilir. Ayrı bir third-party `afsctool` utility'si de Apple filesystem compression'ı inceleyebilir veya decompress edebilir, ancak yerleşik komutla karıştırılmamalıdır. <sup>[[8]](#references)</sup>


### İlginç yapılandırma konumları (macOS)

| Path / Location | Amaç / Yapılandırdığı şey | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | System daemons / frameworks içindeki isteğe bağlı veya deneysel davranışları kontrol eden Apple feature-flag plist dosyalarını depolar | Bir attacker SIP'i bypass edebilir veya privilege elde edebilirse, bunları değiştirmek gizli code path'lerini etkinleştirebilir veya safeguards'ları devre dışı bırakabilir |
| `/System/Library/CoreServices/systemVersion.plist` | Uygulamalar / installer'lar tarafından davranışı sınırlamak için kullanılan macOS sürüm metadata'sını (ProductVersion, BuildVersion) içerir | Değişiklik, uygulamaları veya installer'ları desteklenmeyen OS sürümlerini kabul etmeleri ya da özelliklerin kilidini açmaları konusunda yanıltabilir |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Uygulama / system-wide preferences | Yazılabilirse attacker'lar app davranışını yönlendirmek, protections'ları devre dışı bırakmak veya yanlış yapılandırmaya neden olmak için settings enjekte edebilir |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Background daemons ve agents için plist tanımları | Kötü amaçlı plist eklenmesi veya değiştirilmesi (permissions izin veriyorsa) persistence ya da privilege escalations sağlar |
| `/etc/hosts` | System DNS resolver tarafından kullanılan hostname ↔ IP eşlemeleri | Domain adlarını yönlendirme, trafiği intercept etme, local control altında servisleri spoof etme |
| `/etc/sudoers` | `sudo` ile kimlerin hangi koşullar altında komut çalıştırabileceğini tanımlar | Bozulmuş bir sudoers dosyası attacker hesaplarına root veya uygunsuz privileges verebilir |
| `/private/var/db/dslocal/nodes/Default/users/` | Local user account tanım plist'leri | Tampering, user account'ların, password hash'lerinin veya user metadata'sının oluşturulmasına ya da değiştirilmesine izin verir |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | Kext'leri yüklemek veya değiştirmek kernel-level control sağlayabilir; SIP / signature policies tarafından büyük ölçüde korunur |
| `/private/var/db/SystemPolicyConfiguration/` | System policy enforcement için yapılandırmayı (ör. Gatekeeper, notarization) depolar | Bunları değiştirmek policy check'lerinin veya trust rules'ın bypass edilmesine izin verebilir |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binaries ve config files | Yanlış yapılandırma zayıf SSH security, unauthorized access veya insecure algorithms ile sonuçlanır |
| `/System/Library/Sandbox/Profiles` | Process actions'ı kısıtlamak için kullanılan system sandbox profiles (SBPL) | Profilleri değiştirmek veya yenileriyle değiştirmek sandbox escape vector'lerini açabilir ya da containment'ı zayıflatabilir |

> **Note**: Bu path'lerin çoğu SIP-protected directories (ör. `/System`) altında yer alır ve SIP devre dışı bırakılmadıkça veya bypass edilmedikçe yazmalara karşı korunur.


## Universal Binaries ve Mach-O Formatı

Mach-O, macOS'taki native executable format'tır. Universal veya fat binary, birden fazla architecture-specific Mach-O slice'ını tek bir dosyada birleştirir; ilgili sayfa her iki formatı da açıklar:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## File Risk ve Handler Metadata

LaunchServices, file quarantine ve Gatekeeper birlikte macOS'un indirilen dosyaları nasıl işlediğini ve extensions ile URL schemes için uygulamaları nasıl seçtiğini etkiler. Bunların databases'leri ve internal resource files'ları release'ler arasında değişir; private bir CoreTypes path'ini stable bir policy interface olarak ele almak yerine ilgili sayfaları kullanın:

Legacy CoreTypes risk metadata'sını `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` altında sunan release'lerde, yaygın olarak karşılaşılan categories şunlardır:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: Uygulanabilir application policy kapsamında otomatik açılabilecek kadar güvenli kabul edilen içerik.
- **`LSRiskCategoryNeutral`**: Normalde bir warning tetiklemeyen ve otomatik olarak açılmayan içerik.
- **`LSRiskCategoryUnsafeExecutable`**: Kullanıcıya application warning gösterilmesi gereken executable içerik.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: Executable içerik barındırabilecek ve daha fazla inspection gerektiren archive gibi container'lar.

Bunlar implementation details'tır, stable bir public policy API değildir; test edilen macOS sürümündeki gerçek metadata'yı ve Safari/Gatekeeper davranışını doğrulayın.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: İndirilen dosyalar hakkında, örneğin indirildikleri URL gibi bilgiler içerir.
- **Unified log**: Güncel macOS sürümlerinde system ve application events'lerini `log show` ve `log stream` ile sorgulayın. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** ve **`/private/var/log/asl/*.asl`**: Eski sistemlerde hâlâ ilgili olabilecek legacy logging artifacts. Bu release'lerde `/System/Library/LaunchDaemons/com.apple.syslogd.plist`, `syslogd`'yi yapılandırır; `launchctl list | grep com.apple.syslogd`, servisin yüklü olup olmadığını belirlemeye yardımcı olabilir.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: "Finder" üzerinden yakın zamanda erişilen dosyaları ve uygulamaları depolar.
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Login items ile ilişkili legacy preference path'i; modern macOS sürümleri ek mechanisms kullanır.
- **`$HOME/Library/Logs/DiskUtility.log`**: USB devices dahil olmak üzere drives hakkında bilgiler içerebilen legacy Disk Utility log'u.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Wireless access points hakkında veriler.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Legacy launchd override data'sı.

## References

- [1] [Apple - File System Programming Guide](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Bundle Programming Guide](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - dyld shared cache overview](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - File System Programming Guide: macOS File System Security](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - macOS manual page](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - macOS manual page](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - macOS manual page](https://manp.gs/mac/1/afscexpand)
{{#include ../../../banners/hacktricks-training.md}}
