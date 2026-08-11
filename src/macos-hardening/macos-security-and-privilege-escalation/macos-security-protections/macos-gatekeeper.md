# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper**, Mac işletim sistemleri için geliştirilmiş ve kullanıcıların sistemlerinde **yalnızca güvenilir yazılımları çalıştırmasını** sağlamak üzere tasarlanmış bir güvenlik özelliğidir. Bir kullanıcının **App Store dışındaki kaynaklardan** indirdiği ve açmayı denediği uygulama, plug-in veya installer package gibi **yazılımları doğrulayarak** çalışır.

Gatekeeper'ın temel mekanizması **doğrulama** sürecidir. İndirilen yazılımın **tanınan bir geliştirici tarafından imzalanıp imzalanmadığını** kontrol ederek yazılımın gerçekliğini doğrular. Ayrıca yazılımın **Apple tarafından notarize edilip edilmediğini** tespit eder; böylece bilinen kötü amaçlı içerik barındırmadığını ve notarization işleminden sonra üzerinde değişiklik yapılmadığını doğrular.

Buna ek olarak Gatekeeper, indirilen yazılımın ilk kez açılmasını **kullanıcıların onayına sunarak** kullanıcı kontrolünü ve güvenliğini güçlendirir. Bu güvenlik önlemi, kullanıcıların zararsız bir veri dosyası sandıkları potansiyel olarak zararlı executable code'u yanlışlıkla çalıştırmasını önlemeye yardımcı olur.

### Application Signatures

Application signatures (code signatures olarak da bilinir), Apple'ın güvenlik altyapısının kritik bir bileşenidir. **Yazılım yazarının kimliğini** (geliştiriciyi) doğrulamak ve kodun son imzalandığı zamandan beri üzerinde değişiklik yapılmadığından emin olmak için kullanılır.

Şu şekilde çalışır:

1. **Signing the Application:** Bir geliştirici uygulamasını dağıtmaya hazır olduğunda, **private key kullanarak uygulamayı imzalar**. Bu private key, geliştirici Apple Developer Program'a kaydolduğunda **Apple'ın geliştiriciye verdiği bir certificate** ile ilişkilidir. İmzalama süreci, uygulamanın tüm bölümlerinin cryptographic hash'ini oluşturmayı ve bu hash'i geliştiricinin private key'i ile şifrelemeyi içerir.
2. **Distributing the Application:** İmzalanan uygulama, karşılık gelen public key'i içeren geliştirici certificate'i ile birlikte kullanıcılara dağıtılır.
3. **Verifying the Application:** Bir kullanıcı uygulamayı indirip çalıştırmayı denediğinde, Mac işletim sistemi hash'i çözmek için geliştirici certificate'indeki public key'i kullanır. Ardından uygulamanın mevcut durumuna göre hash'i yeniden hesaplar ve bunu çözülmüş hash ile karşılaştırır. Hash'ler eşleşirse, bu durum **geliştiricinin imzalamasından bu yana uygulamada değişiklik yapılmadığı** anlamına gelir ve sistem uygulamanın çalışmasına izin verir.

Application signatures, Apple'ın Gatekeeper teknolojisinin önemli bir parçasıdır. Bir kullanıcı **internet üzerinden indirilen bir uygulamayı açmayı** denediğinde Gatekeeper application signature'ı doğrular. Uygulama Apple tarafından tanınan bir geliştiriciye verilen bir certificate ile imzalanmışsa ve kod üzerinde değişiklik yapılmamışsa Gatekeeper uygulamanın çalışmasına izin verir. Aksi durumda uygulamayı engeller ve kullanıcıyı uyarır.

macOS Catalina'dan itibaren **Gatekeeper uygulamanın Apple tarafından notarize edilip edilmediğini de kontrol eder** ve böylece ek bir güvenlik katmanı sağlar. Notarization süreci uygulamayı bilinen security issue'lar ve malicious code açısından kontrol eder. Bu kontroller başarılı olursa Apple, uygulamaya Gatekeeper'ın doğrulayabileceği bir ticket ekler.

#### Check Signatures

Herhangi bir **malware sample** incelerken binary'nin **signature'ını** her zaman **kontrol etmelisiniz**; çünkü onu imzalayan **developer**, **malware** ile zaten **ilişkili** olabilir.
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarization

Apple'ın notarization süreci, kullanıcıları potansiyel olarak zararlı yazılımlardan korumak için ek bir güvenlik önlemi sağlar. Bu süreçte **geliştirici, uygulamasını inceleme için** **Apple's Notary Service**'e gönderir; bu hizmet App Review ile karıştırılmamalıdır. Bu hizmet, gönderilen yazılımı **kötü amaçlı içerik** ve kod imzalamayla ilgili olası sorunlar açısından inceleyen **otomatik bir sistemdir**.

Yazılım bu incelemeyi herhangi bir sorun oluşturmadan **geçerse**, Notary Service bir notarization ticket oluşturur. Ardından geliştiricinin bu ticket'ı yazılımına **eklemesi** gerekir; bu işlem 'stapling' olarak bilinir. Ayrıca notarization ticket, Gatekeeper'ın (Apple'ın güvenlik teknolojisi) erişebileceği şekilde çevrim içi olarak da yayımlanır.

Kullanıcının yazılımı ilk kez yüklemesi veya çalıştırması sırasında notarization ticket'ın (çalıştırılabilir dosyaya stapling yoluyla eklenmiş ya da çevrim içi olarak bulunmuş olması fark etmeksizin) mevcut olması, **Gatekeeper'a yazılımın Apple tarafından notarization işleminden geçirildiğini bildirir**. Bunun sonucunda Gatekeeper, ilk çalıştırma iletişim kutusunda açıklayıcı bir mesaj görüntüler ve yazılımın Apple tarafından kötü amaçlı içerik açısından denetlendiğini belirtir. Böylece bu süreç, kullanıcıların sistemlerine yükledikleri veya çalıştırdıkları yazılımların güvenliğine duyduğu güveni artırır.

### spctl & syspolicyd

> [!CAUTION]
> Sequoia sürümünden itibaren **`spctl`**'in Gatekeeper yapılandırmasını değiştirmeye izin vermediğini unutmayın.

**`spctl`**, Gatekeeper'ı (XPC mesajları aracılığıyla `syspolicyd` daemon'ı ile) listelemek ve onunla etkileşim kurmak için kullanılan CLI aracıdır. Örneğin, **GateKeeper** durumunu şu şekilde görmek mümkündür:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> GateKeeper imza kontrollerinin her dosyada değil, yalnızca **Quarantine özniteliğine sahip dosyalarda** gerçekleştirildiğini unutmayın.

GateKeeper, **tercihlere ve imzaya** göre bir binary'nin çalıştırılıp çalıştırılamayacağını kontrol eder:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`**, Gatekeeper'ı uygulamaktan sorumlu ana daemon'dur. `/var/db/SystemPolicy` konumunda bulunan bir veritabanını yönetir; [veritabanı desteğine ilişkin kodu burada](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) ve [SQL şablonunu burada](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) bulabilirsiniz. Veritabanının SIP tarafından kısıtlanmadığını ve root tarafından yazılabildiğini unutmayın. `/var/db/.SystemPolicy-default` veritabanı ise diğer veritabanının bozulması durumunda orijinal bir yedek olarak kullanılır.

Ayrıca **`/var/db/gke.bundle`** ve **`/var/db/gkopaque.bundle`** bundle'ları, veritabanına eklenen kuralları içeren dosyalar barındırır. Bu veritabanını root olarak şu komutla kontrol edebilirsiniz:
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
**`syspolicyd`** ayrıca `assess`, `update`, `record` ve `cancel` gibi farklı işlemlere sahip bir XPC sunucusu da sunar; bunlara **`Security.framework`'ün `SecAssessment*`** API'leri kullanılarak da erişilebilir ve **`spctl`** aslında XPC üzerinden **`syspolicyd`** ile iletişim kurar.

İlk kuralın "**App Store**" ile, ikincisinin ise "**Developer ID**" ile bittiğine ve önceki görselde **App Store'dan gelen ve kimliği doğrulanmış geliştiriciler tarafından imzalanan uygulamaları çalıştırmanın etkin** olduğuna dikkat edin.\
Bu ayarı App Store olarak **değiştirirseniz**, "**Notarized Developer ID" kuralları ortadan kalkar**.

Ayrıca **GKE türünde** binlerce kural vardır:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Bunlar şu konumlardan alınan hash'lerdir:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Önceki bilgileri şu komutla da listeleyebilirsiniz:
```bash
sudo spctl --list
```
**`spctl`**'nin **`--master-disable`** ve **`--global-disable`** seçenekleri bu imza kontrollerini tamamen **devre dışı bırakır**:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Tamamen etkinleştirildiğinde yeni bir seçenek görünecektir:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Şununla **bir App'in GateKeeper tarafından izin verilip verilmeyeceğini kontrol etmek** mümkündür:
```bash
spctl --assess -v /Applications/App.app
```
GateKeeper'a belirli uygulamaların şu şekilde çalıştırılmasına izin veren yeni kurallar eklemek mümkündür:
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
**kernel extensions** ile ilgili olarak, `/var/db/SystemPolicyConfiguration` klasörü yüklenmesine izin verilen kext listelerini içeren dosyalar barındırır. Ayrıca `spctl`, önceden onaylanmış ve yüklenebilmesi için NVRAM'de `kext-allowed-teams` anahtarında da saklanması gereken yeni kernel extensions ekleyebildiği için `com.apple.private.iokit.nvram-csr` entitlement'ına sahiptir.

#### macOS 15 (Sequoia) ve sonraki sürümlerde Gatekeeper'ı yönetme

- Uzun süredir kullanılan Finder **Ctrl+Open / Sağ tıklama → Open** bypass yöntemi kaldırılmıştır; kullanıcıların, ilk engelleme iletişim kutusundan sonra engellenen bir uygulamaya **System Settings → Privacy & Security → Open Anyway** üzerinden açıkça izin vermesi gerekir.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` artık kabul edilmemektedir; `spctl`, assessment ve label yönetimi açısından etkin olarak salt okunurdur; policy enforcement ise UI veya MDM üzerinden yapılandırılır.

macOS 15 Sequoia'dan itibaren son kullanıcılar Gatekeeper policy'sini `spctl` üzerinden değiştiremez. Yönetim, System Settings üzerinden veya `com.apple.systempolicy.control` payload'ına sahip bir MDM configuration profile dağıtılarak gerçekleştirilir. App Store ve identified developers'a izin veren (ancak "Anywhere" seçeneğine izin vermeyen) örnek profil bölümü:

<details>
<summary>App Store ve identified developers'a izin veren MDM profili</summary>
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>PayloadContent</key>
<array>
<dict>
<key>PayloadType</key>
<string>com.apple.systempolicy.control</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadIdentifier</key>
<string>com.example.gatekeeper</string>
<key>EnableAssessment</key>
<true/>
<key>AllowIdentifiedDevelopers</key>
<true/>
</dict>
</array>
<key>PayloadType</key>
<string>Configuration</string>
<key>PayloadIdentifier</key>
<string>com.example.profile.gatekeeper</string>
<key>PayloadUUID</key>
<string>00000000-0000-0000-0000-000000000000</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadDisplayName</key>
<string>Gatekeeper</string>
</dict>
</plist>
```
</details>

### Quarantine Files

Bir uygulama veya dosya **indirildiğinde**, web tarayıcıları veya e-posta istemcileri gibi belirli macOS **uygulamaları**, indirilen dosyaya yaygın olarak "**quarantine flag**" olarak bilinen bir **extended file attribute** ekler. Bu attribute, **dosyayı** güvenilmeyen bir kaynaktan (internet) geldiğini ve potansiyel riskler taşıyabileceğini belirtmek için kullanılan bir güvenlik önlemidir. Ancak tüm uygulamalar bu attribute'u eklemez; örneğin yaygın BitTorrent client yazılımları genellikle bu süreci atlar.

**Bir quarantine flag'in bulunması, kullanıcı dosyayı çalıştırmayı denediğinde macOS'un Gatekeeper güvenlik özelliğini tetikler**.

**Quarantine flag'in mevcut olmadığı** durumlarda (bazı BitTorrent client'larıyla indirilen dosyalarda olduğu gibi), Gatekeeper'ın **kontrolleri gerçekleştirilmeyebilir**. Bu nedenle kullanıcılar, daha az güvenli veya bilinmeyen kaynaklardan indirilen dosyaları açarken dikkatli olmalıdır.

> [!NOTE] > **Code signature'larının** **geçerliliğini** kontrol etmek, kodun ve birlikte gelen tüm kaynaklarının kriptografik **hash'lerini** oluşturmayı içeren **resource-intensive** bir süreçtir. Ayrıca certificate geçerliliğini kontrol etmek, certificate'ın yayımlandıktan sonra iptal edilip edilmediğini görmek için Apple sunucularına **online check** yapılmasını gerektirir. Bu nedenlerle, her app başlatıldığında tam bir code signature ve notarization check çalıştırmak **pratik değildir**.
>
> Bu nedenle bu kontroller yalnızca **quarantined attribute'a sahip app'ler çalıştırılırken** gerçekleştirilir.

> [!WARNING]
> Bu attribute, dosyayı oluşturan/indiren **application** tarafından **ayarlanmalıdır**.
>
> Ancak sandboxed olan dosyalar, oluşturdukları her dosyada bu attribute'un ayarlanmasını sağlar. Ayrıca non sandboxed app'ler bunu kendileri ayarlayabilir veya [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) anahtarını **Info.plist** içinde belirtebilir; bu da sistemin oluşturulan dosyalara `com.apple.quarantine` extended attribute'unu eklemesini sağlar.

Ayrıca, **`qtn_proc_apply_to_self`** çağrısı yapan bir process tarafından oluşturulan tüm dosyalar quarantined olur. Ya da **`qtn_file_apply_to_path`** API'si, belirtilen bir file path'e quarantine attribute'unu ekler.

Durumunu **kontrol etmek ve etkinleştirmek/devre dışı bırakmak** (root gereklidir) mümkündür:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Ayrıca bir dosyada **quarantine extended attribute** olup olmadığını şu şekilde bulabilirsiniz:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**extended** **attributes** öğesinin **değerini** kontrol edin ve quarantine attr değerini hangi uygulamanın yazdığını şu komutla bulun:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- The user has been allowed to execute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
Aslında bir işlem, oluşturduğu dosyalara “quarantine flags” ayarlayabilir (oluşturulan bir dosyada USER_APPROVED flag'ini uygulamayı zaten denedim, ancak uygulanmıyor):

<details>

<summary>Source Code apply quarantine flags</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

Ve **bu attribute'u** şununla kaldırın:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Ve karantinaya alınmış tüm dosyaları şu şekilde bulun:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine bilgileri ayrıca LaunchServices tarafından yönetilen **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** merkezi veritabanında da saklanır; bu da GUI'nin dosya kökenleri hakkında veri almasını sağlar. Ayrıca bu bilgiler, kökenlerini gizlemekle ilgilenebilecek uygulamalar tarafından üzerine yazılabilir. Dahası, bu işlem LaunchServices API'leri aracılığıyla yapılabilir.

#### **libquarantine.dylib**

Bu library, extended attribute alanlarını değiştirmeye olanak tanıyan çeşitli functions export eder.

`qtn_file_*` API'leri file quarantine policies ile ilgilenir; `qtn_proc_*` API'leri ise process'lere uygulanır (process tarafından oluşturulan files). Export edilmemiş `__qtn_syscall_quarantine*` functions, `mac_syscall`'ı ilk argument olarak "Quarantine" ile çağıran ve requests'leri `Quarantine.kext`'e gönderen policy'leri uygular.

#### **Quarantine.kext**

Kernel extension yalnızca **sistemdeki kernel cache** üzerinden kullanılabilir; ancak extension'ın symbolicated bir sürümünü içeren **Kernel Debug Kit'i** [**https://developer.apple.com/**](https://developer.apple.com/) adresinden indirebilirsiniz.

Bu Kext, tüm file lifecycle events'lerini (oluşturma, açma, yeniden adlandırma, hard-link oluşturma...) trap etmek için MACF üzerinden çeşitli çağrıları hook'lar; hatta `com.apple.quarantine` extended attribute'unu ayarlamasını önlemek için `setxattr` çağrısını bile hook'lar.

Ayrıca birkaç MIB kullanır:

- `security.mac.qtn.sandbox_enforce`: Quarantine'ı Sandbox ile birlikte zorunlu kılar
- `security.mac.qtn.user_approved_exec`: Quarantine edilmiş proc'lar yalnızca onaylanmış file'ları çalıştırabilir

#### Provenance xattr (Ventura and later)

macOS 13 Ventura, quarantine edilmiş bir app'in çalışmasına ilk kez izin verildiğinde doldurulan ayrı bir provenance mekanizması kullanıma sundu.<sup>[[2]](#references)</sup> İki artefact oluşturulur:

- `.app` bundle directory'si üzerindeki `com.apple.provenance` xattr'ı (primary key ve flags içeren sabit boyutlu binary value).
- App'in cdhash'ini ve metadata'sını `/var/db/SystemPolicyConfiguration/ExecPolicy/` konumundaki ExecPolicy database'inde bulunan `provenance_tracking` table'ındaki bir row'da saklar.

Pratik kullanım:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect, macOS'ta yerleşik bir **anti-malware** özelliğidir. XProtect, **herhangi bir uygulama ilk kez başlatıldığında veya değiştirildiğinde, uygulamayı bilinen malware'ler ve güvenli olmayan dosya türlerinden oluşan veritabanına karşı kontrol eder**. Safari, Mail veya Messages gibi belirli uygulamalar üzerinden bir dosya indirdiğinizde XProtect dosyayı otomatik olarak tarar. Veritabanındaki bilinen malware'lerden biriyle eşleşirse XProtect **dosyanın çalışmasını engeller** ve sizi tehdit konusunda uyarır.

XProtect veritabanı, yeni malware tanımlarıyla Apple tarafından **düzenli olarak güncellenir** ve bu güncellemeler Mac'inize otomatik olarak indirilip yüklenir. Bu, XProtect'in bilinen en yeni tehditlere karşı her zaman güncel olmasını sağlar.

Ancak **XProtect'in tüm özelliklere sahip bir antivirus çözümü olmadığını** belirtmek gerekir. Yalnızca bilinen tehditlerden oluşan belirli bir listeyi kontrol eder ve çoğu antivirus yazılımı gibi on-access scanning gerçekleştirmez.

En son XProtect güncellemesi hakkında şu komutu çalıştırarak bilgi alabilirsiniz:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect, SIP korumalı **/Library/Apple/System/Library/CoreServices/XProtect.bundle** konumunda bulunur ve bundle içinde XProtect'in kullandığı bilgileri bulabilirsiniz:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Bu cdhash'lere sahip kodların legacy entitlements kullanmasına izin verir.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleID ve TeamID üzerinden yüklenmesi engellenen veya minimum bir sürüm belirten plugin ve extension listesi.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Malware tespit etmek için Yara kuralları.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Engellenen application'ların hash'lerini ve TeamID'lerini içeren SQLite3 database.

XProtect ile ilişkili olan ancak Gatekeeper sürecine dahil olmayan başka bir App'in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** konumunda bulunduğunu unutmayın.

> XProtect Remediator: Modern macOS'ta Apple, malware ailelerini tespit etmek ve remediation uygulamak için launchd üzerinden periyodik olarak çalışan on-demand scanner'lar (XProtect Remediator) sağlar. Bu scan'leri unified log'larda gözlemleyebilirsiniz:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeper Değil

> [!CAUTION]
> Gatekeeper'ın **bir application'ı her çalıştırdığınızda yürütülmediğini** unutmayın; yalnızca _**AppleMobileFileIntegrity**_ (AMFI), daha önce Gatekeeper tarafından çalıştırılmış ve doğrulanmış bir app'i yürüttüğünüzde **executable code signature'larını doğrular**.

Bu nedenle daha önce bir app'i Gatekeeper ile cache'lemek, ardından **application'ın executable olmayan dosyalarını** (Electron asar veya NIB dosyaları gibi) **değiştirmek** ve başka bir protection mevcut değilse application'ın **malicious** eklemelerle **yürütülmesini** sağlamak mümkündü.

Ancak artık bu mümkün değil, çünkü macOS **application bundle'ları içindeki dosyaların değiştirilmesini engelliyor**. Bu nedenle [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack'ini denerseniz, app'i Gatekeeper ile cache'lemek için çalıştırdıktan sonra bundle'ı değiştiremeyeceğiniz için artık bunu abuse etmenin mümkün olmadığını göreceksiniz. Örneğin Contents directory'sinin adını exploit'te belirtildiği gibi NotCon olarak değiştirir ve ardından app'in main binary'sini Gatekeeper ile cache'lemek için çalıştırırsanız, bir error tetiklenir ve çalıştırılmaz.

## Gatekeeper Bypasses

Gatekeeper'ı bypass etmenin herhangi bir yolu (kullanıcıya bir şey download ettirmeyi ve Gatekeeper'ın bunu engellemesi gerekirken çalıştırmasını sağlamayı başarmak), macOS'ta vulnerability olarak kabul edilir. Bunlar, geçmişte Gatekeeper'ı bypass etmeye izin veren technique'lere atanmış bazı CVE'lerdir:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Extraction için **Archive Utility** kullanıldığında, **886 karakteri aşan path'lere** sahip dosyaların com.apple.quarantine extended attribute'ünü almadığı gözlemlendi. Bu durum, bu dosyaların Gatekeeper'ın security check'lerini **bypass etmesine** istemeden izin verir.<sup>[[5]](#references)</sup>

Daha fazla bilgi için [**original report'a**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) bakın.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Bir application **Automator** ile oluşturulduğunda, çalıştırmak için ihtiyaç duyduğu bilgiler executable içinde değil, `application.app/Contents/document.wflow` içinde bulunur. Executable, **Automator Application Stub** adlı generic bir Automator binary'sidir.

Bu nedenle `application.app/Contents/MacOS/Automator\ Application\ Stub` dosyasını **system içindeki başka bir Automator Application Stub'a symbolic link ile işaret edecek şekilde** oluşturabilirsiniz; böylece **actual executable quarantine xattr'üne sahip olmadığı için Gatekeeper'ı tetiklemeden**, `document.wflow` (script'iniz) içindeki şeyleri çalıştırır.<sup>[[6]](#references)</sup>

Beklenen location'a bir örnek: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Daha fazla bilgi için [**original report'a**](https://ronmasas.com/posts/bypass-macos-gatekeeper) bakın.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Bu bypass'te, `application.app` yerine `application.app/Contents` üzerinden compression işlemine başlayan bir zip file oluşturuldu. Bu nedenle **quarantine attr**, **`application.app/Contents` içindeki tüm dosyalara** uygulandı ancak Gatekeeper'ın kontrol ettiği **`application.app` dosyasına** uygulanmadı. Böylece `application.app` tetiklendiğinde **quarantine attribute'üne sahip olmadığı için** Gatekeeper bypass edildi.<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Daha fazla bilgi için [**orijinal rapora**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) göz atın.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Bileşenler farklı olsa da bu güvenlik açığının exploitation yöntemi öncekiyle oldukça benzerdir. Bu durumda **`application.app/Contents`** üzerinden bir Apple Archive oluşturacağız; böylece **`application.app`**, **Archive Utility** tarafından açıldığında quarantine attr almayacaktır.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Daha fazla bilgi için [**orijinal rapora**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) bakın.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

**`writeextattr`** ACL'si, herhangi bir kullanıcının bir dosyadaki attribute'u yazmasını engellemek için kullanılabilir:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Ayrıca, **AppleDouble** dosya formatı bir dosyayı ACE'leriyle birlikte kopyalar.<sup>[[9]](#references)</sup>

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) içinde, **`com.apple.acl.text`** adlı xattr içinde depolanan ACL metin gösteriminin sıkıştırması açılan dosyada ACL olarak ayarlanacağını görmek mümkündür. Dolayısıyla, bir uygulamayı, başka xattr'ların üzerine yazılmasını engelleyen bir ACL içeren **AppleDouble** dosya formatıyla bir zip dosyasına sıkıştırırsanız... quarantine xattr'ı uygulamaya ayarlanmaz:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Daha fazla bilgi için [**orijinal rapora**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) bakın.<sup>[[9]](#references)</sup>

Bunun AppleArchives ile de exploit edilebileceğini unutmayın:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Bazı macOS dahili sorunları nedeniyle **Google Chrome'un indirilen dosyalara quarantine attribute ayarlamadığı** keşfedildi.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble, bir dosyanın attribute'larını `._` ile başlayan ayrı bir dosyada depolar; bu, dosya attribute'larının **macOS makineleri arasında** kopyalanmasına yardımcı olur. Ancak bir AppleDouble dosyası decompress edildikten sonra, `._` ile başlayan dosyaya **quarantine attribute verilmedi**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
Quarantine attribute ayarlanmamış bir dosya oluşturulabildiği için **Gatekeeper'ı bypass etmek mümkündü.** Bunun için AppleDouble adlandırma kuralını kullanarak (başına `._` ekleyerek) bir **DMG file application** oluşturmak ve **quarantine attribute** içermeyen bu gizli dosyaya sembolik bağlantı olan **görünür bir dosya** oluşturmak yeterliydi.\
**dmg file çalıştırıldığında**, quarantine attribute içermediği için **Gatekeeper'ı bypass eder.**
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### [CVE-2023-41067]

macOS Sonoma 14.0'da düzeltilen bir Gatekeeper bypass'ı, hazırlanmış uygulamaların uyarı göstermeden çalışmasına izin veriyordu. Ayrıntılar, patch uygulandıktan sonra kamuya açıklandı ve sorun, düzeltme yayınlanmadan önce gerçek dünyada aktif olarak istismar ediliyordu. Sonoma 14.0 veya daha yenisinin yüklü olduğundan emin olun.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

macOS 14.4'te (Mart 2024'te yayınlandı) bulunan ve `libarchive`'in kötü amaçlı ZIP'leri işleme biçiminden kaynaklanan bir Gatekeeper bypass'ı, uygulamaların assessment işleminden kaçmasına izin veriyordu. Apple'ın sorunu giderdiği 14.4 veya daha yeni bir sürüme güncelleyin.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

İndirilen bir uygulamaya gömülü **Automator Quick Action workflow**, Gatekeeper assessment işlemi olmadan tetiklenebiliyordu; bunun nedeni workflow'ların veri olarak değerlendirilmesi ve normal notarization uyarısı yolunun dışında Automator helper tarafından çalıştırılmasıydı. Bu nedenle, shell script çalıştıran bir Quick Action içeren hazırlanmış bir `.app` (örneğin `Contents/PlugIns/*.workflow/Contents/document.wflow` içinde), başlatıldığında hemen çalışabiliyordu. Apple, Ventura **13.7**, Sonoma **14.7** ve Sequoia **15** sürümlerinde ek bir onay iletişim kutusu ekledi ve assessment yolunu düzeltti.<sup>[[3]](#references)</sup>

### Üçüncü taraf unarchiver'ların quarantine bilgisini yanlış aktarması (2023–2024)

Popüler extraction araçlarındaki (ör. The Unarchiver) çeşitli güvenlik açıkları, arşivlerden çıkarılan dosyaların `com.apple.quarantine` xattr bilgisini kaybetmesine neden olarak Gatekeeper bypass fırsatları oluşturdu. Test sırasında her zaman macOS Archive Utility'ye veya patch uygulanmış araçlara güvenin ve extraction sonrasında xattr bilgilerini doğrulayın.

### uchg (bu [sunumdan](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Bir uygulama içeren bir dizin oluşturun.
- Uygulamaya uchg ekleyin.
- Uygulamayı bir tar.gz dosyasına sıkıştırın.
- tar.gz dosyasını bir kurbana gönderin.
- Kurban tar.gz dosyasını açar ve uygulamayı çalıştırır.
- Gatekeeper uygulamayı kontrol etmez.<sup>[[12]](#references)</sup>

### Quarantine xattr'ını Önleme

Bir ".app" bundle'ına quarantine xattr eklenmezse, çalıştırıldığında **Gatekeeper tetiklenmez**.

## References

- [1] [Apple Platform Security: macOS Sonoma 14.4'ün güvenlik içeriği hakkında (CVE-2024-27853 dahil)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: macOS artık uygulamaların provenance bilgisini nasıl takip ediyor](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: macOS Sonoma 14.7 / Ventura 13.7'nin güvenlik içeriği hakkında (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia, Control‑click “Open” Gatekeeper bypass'ını kaldırıyor](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: CVE-2021-1810'un keşfi](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, macOS Gatekeeper'ı bypass etme](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs, Gatekeeper bypass'ına olanak tanıyan Safari güvenlik açığını tespit ediyor](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs, Gatekeeper bypass'ına olanak tanıyan macOS Archive Utility güvenlik açığını (CVE-2022-32910) tespit ediyor](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper'ın Achilles topuğu: Bir macOS güvenlik açığının ortaya çıkarılması](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Bir Gatekeeper bypass'ının keşfi (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Mac Monitor yardımıyla bir Gatekeeper bypass exploit'ini bulma ve bildirme](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: macOS Security and Privacy Mechanisms'ı bypass etme — Gatekeeper'dan System Integrity Protection'a (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: macOS Sonoma 14'ün güvenlik içeriği hakkında (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
{{#include ../../../banners/hacktricks-training.md}}
