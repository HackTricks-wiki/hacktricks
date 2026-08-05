# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper**, Mac işletim sistemleri için geliştirilmiş ve kullanıcıların sistemlerinde **yalnızca güvenilir yazılımları çalıştırmasını** sağlamak üzere tasarlanmış bir güvenlik özelliğidir. Kullanıcının **App Store dışındaki kaynaklardan** indirdiği ve açmaya çalıştığı yazılımları (uygulama, plug-in veya installer package gibi) **doğrulayarak** çalışır.

Gatekeeper'ın temel mekanizması **verification** sürecidir. İndirilen yazılımın **tanınan bir developer tarafından imzalanıp imzalanmadığını** kontrol ederek yazılımın gerçekliğini doğrular. Ayrıca yazılımın Apple tarafından **notarize edilip edilmediğini** denetler; böylece bilinen kötü amaçlı içerik barındırmadığını ve notarization sonrasında değiştirilmediğini doğrular.

Buna ek olarak Gatekeeper, indirilen yazılımların ilk kez açılmasını **kullanıcılardan onay isteyerek** kullanıcı denetimini ve güvenliğini güçlendirir. Bu koruma, kullanıcıların zararsız bir data file zannedebilecekleri potansiyel olarak zararlı executable code'u yanlışlıkla çalıştırmasını önlemeye yardımcı olur.

### Application Signatures

Application signatures (code signatures olarak da bilinir), Apple'ın güvenlik altyapısının kritik bir bileşenidir. Yazılım author'ının (developer'ın) **kimliğini doğrulamak** ve code'un son imzalandığından beri değiştirilmediğinden emin olmak için kullanılır.

İşleyiş şekli şöyledir:

1. **Signing the Application:** Bir developer uygulamasını dağıtmaya hazır olduğunda, **private key kullanarak uygulamayı imzalar**. Bu private key, developer Apple Developer Program'a kaydolduğunda Apple'ın developer'a verdiği **certificate ile ilişkilidir**. İmzalama süreci, uygulamanın tüm bölümlerinin cryptographic hash'ini oluşturmayı ve bu hash'i developer'ın private key'iyle şifrelemeyi içerir.
2. **Distributing the Application:** İmzalanan uygulama, ilgili public key'i içeren developer certificate'ı ile birlikte kullanıcılara dağıtılır.
3. **Verifying the Application:** Kullanıcı uygulamayı indirip çalıştırmayı denediğinde, Mac işletim sistemi hash'i çözmek için developer certificate'ındaki public key'i kullanır. Ardından uygulamanın mevcut durumuna göre hash'i yeniden hesaplar ve bunu çözülen hash ile karşılaştırır. Eşleşmeleri, **uygulamanın developer tarafından imzalanmasından bu yana değiştirilmediği** anlamına gelir ve sistem uygulamanın çalışmasına izin verir.

Application signatures, Apple'ın Gatekeeper teknolojisinin önemli bir parçasıdır. Kullanıcı **internet'ten indirilmiş bir uygulamayı açmaya** çalıştığında Gatekeeper application signature'ı doğrular. Uygulama Apple tarafından tanınan bir developer'a verilmiş bir certificate ile imzalanmışsa ve code değiştirilmemişse Gatekeeper uygulamanın çalışmasına izin verir. Aksi takdirde uygulamayı engeller ve kullanıcıyı uyarır.

macOS Catalina'dan itibaren **Gatekeeper, uygulamanın Apple tarafından notarize edilip edilmediğini de kontrol eder** ve böylece ek bir güvenlik katmanı sağlar. Notarization süreci uygulamayı bilinen security sorunları ve malicious code açısından kontrol eder. Bu kontroller başarılı olursa Apple, Gatekeeper'ın doğrulayabileceği bir ticket'ı uygulamaya ekler.

#### Check Signatures

Herhangi bir **malware sample** incelerken binary'nin **signature'ını** her zaman **kontrol etmelisiniz**; çünkü onu imzalayan **developer** daha önce **malware ile ilişkili** olabilir.
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

Apple'ın notarization süreci, kullanıcıları potansiyel olarak zararlı yazılımlardan korumak için ek bir güvenlik önlemi görevi görür. Bu süreçte **geliştirici, uygulamasını inceleme için** **Apple's Notary Service**'e gönderir; bu hizmet App Review ile karıştırılmamalıdır. Bu hizmet, gönderilen yazılımı **zararlı içerik** ve kod imzalamayla ilgili olası sorunlar açısından inceleyen **otomatik bir sistemdir**.

Yazılım bu incelemeyi herhangi bir sorun oluşturmadan **geçerse**, Notary Service bir notarization ticket oluşturur. Ardından geliştiricinin bu **ticket'ı yazılımına eklemesi** gerekir; bu işlem 'stapling' olarak bilinir. Ayrıca notarization ticket çevrimiçi olarak da yayımlanır; böylece Apple'ın güvenlik teknolojisi olan Gatekeeper bu ticket'a erişebilir.

Kullanıcının yazılımı ilk kez yüklemesi veya çalıştırması sırasında, notarization ticket'ın - çalıştırılabilir dosyaya stapled edilmiş ya da çevrimiçi bulunmuş olması fark etmeksizin - mevcut olması, **Gatekeeper'a yazılımın Apple tarafından notarization işleminden geçirildiğini bildirir**. Bunun sonucunda Gatekeeper, ilk çalıştırma iletişim kutusunda açıklayıcı bir mesaj görüntüler ve yazılımın Apple tarafından zararlı içerik açısından kontrollerden geçirildiğini belirtir. Böylece bu süreç, kullanıcıların sistemlerine yükledikleri veya çalıştırdıkları yazılımın güvenliğine olan güvenini artırır.

### spctl & syspolicyd

> [!CAUTION]
> Sequoia sürümünden itibaren **`spctl`**'nin Gatekeeper yapılandırmasını değiştirmeye artık izin vermediğini unutmayın.

**`spctl`**, Gatekeeper'ı (XPC mesajları aracılığıyla `syspolicyd` daemon'ı ile) listelemek ve onunla etkileşim kurmak için kullanılan CLI aracıdır. Örneğin, GateKeeper'ın **durumunu** şu şekilde görmek mümkündür:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> GateKeeper imza kontrollerinin her dosyada değil, yalnızca **Quarantine attribute** içeren dosyalarda gerçekleştirildiğini unutmayın.

GateKeeper, **preferences & signature** doğrultusunda bir binary dosyanın çalıştırılıp çalıştırılamayacağını kontrol eder:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`**, Gatekeeper'ı uygulamaktan sorumlu ana daemon'dur. `/var/db/SystemPolicy` konumunda bulunan bir database'i yönetir. [database'i destekleyen kodu burada](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) ve [SQL template'ini burada](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) bulabilirsiniz. Database'in SIP tarafından kısıtlanmadığını ve root tarafından yazılabilir olduğunu unutmayın. `/var/db/.SystemPolicy-default` database'i ise diğer database'in bozulması durumunda orijinal bir yedek olarak kullanılır.

Ayrıca **`/var/db/gke.bundle`** ve **`/var/db/gkopaque.bundle`** bundle'ları, database'e eklenen kuralları içeren dosyalar barındırır. Bu database'i root olarak şu komutla kontrol edebilirsiniz:
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
**`syspolicyd`** ayrıca `assess`, `update`, `record` ve `cancel` gibi farklı işlemlere sahip bir XPC sunucusu sunar; bunlara **Security.framework'ün `SecAssessment*`** API'leri kullanılarak da erişilebilir ve **`spctl`** aslında XPC aracılığıyla **`syspolicyd`** ile iletişim kurar.

İlk kuralın "**App Store**" ile, ikincisinin ise "**Developer ID**" ile sona erdiğine ve önceki görüntüde **App Store'dan ve tanımlanmış geliştiricilerden gelen uygulamaları çalıştırmanın etkin olduğuna** dikkat edin.\
Bu ayarı **App Store** olarak **değiştirirseniz**, "**Notarized Developer ID" kuralları ortadan kalkar**.

Ayrıca **GKE** türünde binlerce kural vardır:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Bunlar şu dosyalardaki hash'lerdir:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Alternatif olarak, önceki bilgileri şu komutla listeleyebilirsiniz:
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

Şunları kullanarak **bir App'in GateKeeper tarafından izin verilip verilmeyeceğini kontrol etmek** mümkündür:
```bash
spctl --assess -v /Applications/App.app
```
Belirli uygulamaların çalıştırılmasına izin vermek için GateKeeper'a yeni kurallar eklemek mümkündür:
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
**kernel extensions** ile ilgili olarak, `/var/db/SystemPolicyConfiguration` klasörü yüklenmesine izin verilen kext listelerini içeren dosyalar barındırır. Ayrıca `spctl`, önceden onaylanmış ve yüklenmesine izin verilen yeni kernel extensions ekleyebildiği için `com.apple.private.iokit.nvram-csr` entitlement'ına sahiptir; bu kernel extensions'ların `kext-allowed-teams` anahtarında NVRAM'e de kaydedilmesi gerekir.

#### macOS 15 (Sequoia) ve sonraki sürümlerde Gatekeeper'ı yönetme

- Uzun süredir kullanılan Finder **Ctrl+Open / Sağ tık → Open** bypass yöntemi kaldırılmıştır; kullanıcıların, ilk engelleme iletişim kutusundan sonra engellenen bir uygulamaya **System Settings → Privacy & Security → Open Anyway** üzerinden açıkça izin vermesi gerekir.<sup>[4]</sup>
- `spctl --master-disable/--global-disable` artık kabul edilmez; `spctl`, assessment ve label yönetimi için fiilen salt okunur durumdadır; policy enforcement ise UI veya MDM üzerinden yapılandırılır.

macOS 15 Sequoia'dan itibaren end users, Gatekeeper policy ayarını `spctl` üzerinden değiştiremez. Yönetim, System Settings üzerinden veya `com.apple.systempolicy.control` payload'ına sahip bir MDM configuration profile dağıtılarak gerçekleştirilir. App Store ve identified developers'a izin veren (ancak "Anywhere" seçeneğine izin vermeyen) örnek profile snippet'i:

<details>
<summary>App Store ve identified developers'a izin veren MDM profile</summary>
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

Bir uygulama veya dosya **indirildiğinde**, web tarayıcıları veya e-posta istemcileri gibi belirli macOS **uygulamaları**, indirilen dosyaya genellikle "**quarantine flag**" olarak bilinen bir **extended file attribute** ekler. Bu attribute, **dosyayı** güvenilmeyen bir kaynaktan (internet) geldiğini ve potansiyel riskler taşıyabileceğini belirtmek üzere işaretleyen bir güvenlik önlemidir. Ancak tüm uygulamalar bu attribute'u eklemez; örneğin yaygın BitTorrent client yazılımları genellikle bu süreci atlar.

**Bir quarantine flag'in bulunması, kullanıcı dosyayı çalıştırmayı denediğinde macOS'un Gatekeeper güvenlik özelliğini tetikler**.

**Quarantine flag mevcut değilse** (bazı BitTorrent client'larıyla indirilen dosyalarda olduğu gibi), Gatekeeper'ın **kontrolleri gerçekleştirilmeyebilir**. Bu nedenle kullanıcılar, daha az güvenli veya bilinmeyen kaynaklardan indirilen dosyaları açarken dikkatli olmalıdır.

> [!NOTE] > **Kod imzalarının** **geçerliliğini** kontrol etmek, kodun ve pakete dahil tüm kaynakların kriptografik **hash'lerini** oluşturmayı içeren **kaynak yoğun** bir işlemdir. Ayrıca sertifika geçerliliğinin kontrol edilmesi, sertifikanın yayımlandıktan sonra iptal edilip edilmediğini görmek için Apple sunucularına **online check** yapılmasını gerektirir. Bu nedenlerle, her uygulama başlatıldığında tam bir kod imzası ve notarization kontrolü çalıştırmak **pratik değildir**.
>
> Bu nedenle bu kontroller **yalnızca quarantine attribute'una sahip uygulamalar çalıştırılırken gerçekleştirilir.**

> [!WARNING]
> Bu attribute, **dosyayı oluşturan/indiren uygulama tarafından ayarlanmalıdır**.
>
> Ancak sandboxed dosyalar oluşturan dosyaların tümünde bu attribute ayarlanır. Ayrıca non sandboxed uygulamalar bunu kendileri ayarlayabilir veya [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) anahtarını [**Info.plist**] içinde belirtebilir; bu da sistemin oluşturulan dosyalara `com.apple.quarantine` extended attribute'unu ayarlamasını sağlar,

Ayrıca, **`qtn_proc_apply_to_self`** çağrısı yapan bir process tarafından oluşturulan tüm dosyalar quarantined olur. Ya da **`qtn_file_apply_to_path`** API'si, belirtilen bir file path'e quarantine attribute'unu ekler.

**Durumunu kontrol etmek ve etkinleştirmek/devre dışı bırakmak** (root gerekir) mümkündür:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Bir dosyada **quarantine extended attribute** olup olmadığını şu şekilde de **bulabilirsiniz**:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**extended** **attributes**'ın **değerini** kontrol edin ve quarantine attr'ını yazan uygulamayı bulun:
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
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
Aslında bir işlem, oluşturduğu dosyalara "quarantine flags" ayarlayabilir (oluşturulan bir dosyada USER_APPROVED flag'ini uygulamayı zaten denedim, ancak uygulanmıyor):

<details>

<summary>quarantine flags uygulayan Source Code</summary>
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

Ve bu **attribute**'u şu şekilde kaldırın:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Ve karantinaya alınmış tüm dosyaları şu komutla bulun:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine bilgileri ayrıca LaunchServices tarafından yönetilen **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** konumundaki merkezi bir veritabanında da depolanır; bu veritabanı GUI'nin dosya kaynakları hakkında veri edinmesini sağlar. Ayrıca bu veritabanı, kaynaklarını gizlemekle ilgilenebilecek uygulamalar tarafından üzerine yazılabilir. Dahası, bu işlem LaunchServices APIS aracılığıyla da gerçekleştirilebilir.

#### **libquarantine.dylib**

Bu library, extended attribute alanlarını değiştirmeye olanak tanıyan çeşitli functions dışa aktarır.

`qtn_file_*` API'leri file quarantine policies ile ilgilenirken, `qtn_proc_*` API'leri processes'e uygulanır (process tarafından oluşturulan files). Dışa aktarılmayan `__qtn_syscall_quarantine*` functions, `mac_syscall` işlevini ilk argüman olarak "Quarantine" ile çağıran ve policies'i uygulayan functions'tır; bu çağrı istekleri `Quarantine.kext`'e gönderir.

#### **Quarantine.kext**

Kernel extension yalnızca **system üzerindeki kernel cache** aracılığıyla kullanılabilir; ancak [**https://developer.apple.com/**](https://developer.apple.com/) adresinden, extension'ın symbolicated bir sürümünü içeren **Kernel Debug Kit'i indirebilirsiniz**.

Bu Kext, tüm file lifecycle events'lerini yakalamak için MACF aracılığıyla çeşitli çağrıları hook'lar: Creation, opening, renaming, hard-linkning... hatta `com.apple.quarantine` extended attribute'unu ayarlamasını önlemek için `setxattr` çağrısını bile.

Ayrıca birkaç MIB kullanır:

- `security.mac.qtn.sandbox_enforce`: Quarantine'ı Sandbox ile birlikte enforce eder
- `security.mac.qtn.user_approved_exec`: Querantined procs yalnızca approved files'ı execute edebilir

#### Provenance xattr (Ventura and later)

macOS 13 Ventura, quarantined bir app'in çalışmasına ilk kez izin verildiğinde doldurulan ayrı bir provenance mechanism'i kullanıma sundu.<sup>[2]</sup> İki artefact oluşturulur:

- `.app` bundle directory üzerinde `com.apple.provenance` xattr'ı (primary key ve flags içeren, fixed-size binary value).
- `/var/db/SystemPolicyConfiguration/ExecPolicy/` konumundaki ExecPolicy database içinde yer alan `provenance_tracking` table'ında app'in cdhash'ini ve metadata'sını depolayan bir row.

Practical usage:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect, macOS'te yerleşik bir **anti-malware** özelliğidir. XProtect, **herhangi bir uygulamayı ilk kez başlatıldığında veya değiştirildiğinde, bilinen malware'ler ve güvenli olmayan dosya türlerinden oluşan veritabanına karşı kontrol eder**. Safari, Mail veya Messages gibi belirli uygulamalar üzerinden bir dosya indirdiğinizde XProtect dosyayı otomatik olarak tarar. Veritabanındaki bilinen malware'lerden biriyle eşleşirse XProtect **dosyanın çalışmasını engeller** ve sizi tehdit konusunda uyarır.

XProtect veritabanı, yeni malware tanımlarıyla Apple tarafından **düzenli olarak güncellenir** ve bu güncellemeler Mac'inize otomatik olarak indirilip yüklenir. Bu, XProtect'in bilinen en yeni tehditlere karşı her zaman güncel olmasını sağlar.

Ancak **XProtect'in tam özellikli bir antivirus çözümü olmadığını** belirtmek gerekir. Yalnızca belirli bir bilinen tehdit listesini kontrol eder ve çoğu antivirus yazılımı gibi erişim sırasında tarama gerçekleştirmez.

Aşağıdaki komutu çalıştırarak en son XProtect güncellemesi hakkında bilgi alabilirsiniz:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect, SIP tarafından korunan **/Library/Apple/System/Library/CoreServices/XProtect.bundle** konumunda bulunur ve bundle içinde XProtect'in kullandığı bilgileri bulabilirsiniz:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Bu cdhash'lere sahip code'un legacy entitlements kullanmasına izin verir.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleID ve TeamID üzerinden yüklenmesine izin verilmeyen plugin ve extension'ların listesini içerir veya minimum bir sürüm belirtir.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Malware tespit etmek için Yara kurallarını içerir.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Engellenen application'ların hash'lerini ve TeamID'lerini içeren SQLite3 database'idir.

**/Library/Apple/System/Library/CoreServices/XProtect.app** konumunda XProtect ile ilişkili başka bir App bulunduğunu, ancak bunun Gatekeeper sürecine dahil olmadığını unutmayın.

> XProtect Remediator: Modern macOS'ta Apple, malware ailelerini tespit etmek ve remediate etmek için launchd üzerinden periyodik olarak çalışan on-demand scanner'lar (XProtect Remediator) sunar. Bu scan'leri unified log'larda gözlemleyebilirsiniz:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeper Değil

> [!CAUTION]
> Gatekeeper'ın **bir application'ı her çalıştırdığınızda yürütülmediğini** unutmayın; yalnızca _**AppleMobileFileIntegrity**_ daha önce çalıştırılmış ve Gatekeeper tarafından doğrulanmış bir app'i çalıştırdığınızda **executable code signatures'ı verify eder**.

Bu nedenle, daha önce bir app'i Gatekeeper ile cache'lemek, ardından application'ın **executable olmayan dosyalarını** (Electron asar veya NIB dosyaları gibi) **modify etmek** ve başka bir protection mevcut değilse application'ı **malicious** eklemelerle **çalıştırmak** mümkündü.

Ancak artık bu mümkün değil, çünkü macOS application bundle'ları içindeki **dosyaların modify edilmesini engeller**. Bu nedenle [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack'ini denerseniz, app'i Gatekeeper ile cache'lemek için çalıştırdıktan sonra bundle'ı modify edemeyeceğiniz için artık bunun abuse edilemediğini göreceksiniz. Örneğin Contents directory'sinin adını exploit'te belirtildiği gibi NotCon olarak değiştirir ve ardından app'in main binary'sini Gatekeeper ile cache'lemek için çalıştırırsanız, bu bir error tetikler ve app çalıştırılmaz.

## Gatekeeper Bypasses

Gatekeeper'ı bypass etmenin herhangi bir yolu (kullanıcıya bir şey download ettirmeyi ve Gatekeeper'ın engellemesi gereken bir şeyi çalıştırmasını sağlamayı başarmak), macOS'ta vulnerability olarak kabul edilir. Geçmişte Gatekeeper'ı bypass etmeye izin veren technique'lere atanan CVE'lerden bazıları şunlardır:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Extraction için **Archive Utility** kullanıldığında, **886 karakteri aşan path'lere** sahip dosyaların com.apple.quarantine extended attribute'ünü almadığı gözlemlendi. Bu durum, söz konusu dosyaların Gatekeeper'ın security check'lerini **bypass etmesine** istemeden olanak tanır.<sup>[5]</sup>

Daha fazla bilgi için [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) belgesine bakın.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Bir application **Automator** ile oluşturulduğunda, çalıştırmak için ihtiyaç duyduğu bilgiler executable içinde değil, `application.app/Contents/document.wflow` içindedir. Executable, **Automator Application Stub** adı verilen generic bir Automator binary'sidir.

Bu nedenle `application.app/Contents/MacOS/Automator\ Application\ Stub` dosyasını **system içindeki başka bir Automator Application Stub'a symbolic link ile point edecek** şekilde ayarlayabilir ve `document.wflow` içindeki şeyi (script'inizi) **Gatekeeper'ı tetiklemeden** çalıştırmasını sağlayabilirsiniz; çünkü gerçek executable quarantine xattr'a sahip değildir.<sup>[6]</sup>

Örnek beklenen location: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Daha fazla bilgi için [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) belgesine bakın.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Bu bypass'te bir zip file, `application.app` yerine compression işlemine `application.app/Contents` içinden başlayacak şekilde oluşturuldu. Bu nedenle **quarantine attr**, **`application.app/Contents` içindeki tüm file'lara** uygulandı, ancak Gatekeeper'ın kontrol ettiği **`application.app`** dosyasına uygulanmadı. Böylece Gatekeeper bypass edildi; çünkü `application.app` tetiklendiğinde **quarantine attribute'üne sahip değildi.**<sup>[7]</sup>
```bash
zip -r test.app/Contents test.zip
```
Daha fazla bilgi için [**orijinal rapora**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) bakın.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Bileşenler farklı olsa da bu açığın exploitation süreci önceki açığa oldukça benzer. Bu durumda **`application.app/Contents`** dizininden bir Apple Archive oluşturacağız; böylece **`application.app`**, **Archive Utility** tarafından decompress edildiğinde quarantine attr almayacak.<sup>[8]</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Daha fazla bilgi için [**orijinal rapora**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) göz atın.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

**`writeextattr`** ACL’si, herhangi bir kişinin bir dosyadaki özniteliğe yazmasını engellemek için kullanılabilir:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Ayrıca, **AppleDouble** dosya formatı, bir dosyayı ACE'leriyle birlikte kopyalar.<sup>[9]</sup>

[**Kaynak kodunda**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), **`com.apple.acl.text`** adlı xattr içinde depolanan ACL metin gösteriminin, sıkıştırılmış dosyada ACL olarak ayarlanacağını görmek mümkündür. Dolayısıyla, bir uygulamayı, diğer xattr'ların üzerine yazılmasını engelleyen bir ACL ile **AppleDouble** dosya formatını kullanarak bir zip dosyasına sıkıştırırsanız... quarantine xattr'ı uygulamaya ayarlanmaz:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Daha fazla bilgi için [**orijinal rapora**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) bakın.

Bunun AppleArchives ile de exploit edilebileceğini unutmayın:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Bazı macOS dahili sorunları nedeniyle **Google Chrome'un indirilen dosyalara quarantine attribute ayarlamadığı** keşfedildi.<sup>[10]</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble dosya formatları, bir dosyanın attribute'larını `._` ile başlayan ayrı bir dosyada depolar; bu, dosya attribute'larının **macOS makineleri arasında** kopyalanmasına yardımcı olur. Ancak bir AppleDouble dosyası açıldıktan sonra, `._` ile başlayan dosyaya **quarantine attribute verilmediği** fark edildi.<sup>[11]</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Karantina özniteliği ayarlanmamış bir dosya oluşturulabildiği için **Gatekeeper'ı bypass etmek mümkündü.** Bunun için AppleDouble adlandırma kuralını (`._` ile başlatma) kullanarak bir **DMG file application** oluşturuluyor ve görünür bir dosya, karantina özniteliği olmayan bu gizli dosyaya **symlink** olarak oluşturuluyordu.\
**dmg file çalıştırıldığında**, karantina özniteliğine sahip olmadığı için **Gatekeeper'ı bypass eder.**
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

macOS Sonoma 14.0'da düzeltilen bir Gatekeeper bypass'ı, özel olarak hazırlanmış uygulamaların uyarı göstermeden çalışmasına izin veriyordu. Ayrıntılar patch uygulandıktan sonra kamuya açıklandı ve sorun düzeltilmeden önce aktif olarak istismar ediliyordu. Sonoma 14.0 veya daha yenisinin yüklü olduğundan emin olun.

### [CVE-2024-27853]

Mart 2024'te yayımlanan macOS 14.4'teki bir Gatekeeper bypass'ı, `libarchive` tarafından kötü amaçlı ZIP dosyalarının işlenmesinden kaynaklanıyordu ve uygulamaların assessment işleminden kaçmasına izin veriyordu. Apple'ın sorunu giderdiği 14.4 veya daha yeni bir sürüme güncelleyin.<sup>[1]</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

İndirilen bir uygulamaya gömülü bir **Automator Quick Action workflow**, Gatekeeper assessment işlemi olmadan tetiklenebiliyordu; bunun nedeni workflow'ların veri olarak değerlendirilmesi ve normal notarization uyarısı yolunun dışında Automator helper tarafından çalıştırılmasıydı. Bu nedenle, shell script çalıştıran bir Quick Action içeren hazırlanmış bir `.app` (örneğin `Contents/PlugIns/*.workflow/Contents/document.wflow` içinde), başlatılır başlatılmaz çalışabiliyordu. Apple ek bir onay iletişim kutusu ekledi ve assessment yolunu Ventura **13.7**, Sonoma **14.7** ve Sequoia **15** sürümlerinde düzeltti.<sup>[3]</sup>

### Third‑party unarchivers mis-propagating quarantine (2023–2024)

Popüler extraction araçlarındaki (ör. The Unarchiver) çeşitli güvenlik açıkları, arşivlerden çıkarılan dosyaların `com.apple.quarantine` xattr değerini alamamasına neden olarak Gatekeeper bypass fırsatları oluşturdu. Test sırasında her zaman macOS Archive Utility'ye veya patch uygulanmış araçlara güvenin ve extraction sonrasında xattr değerlerini doğrulayın.

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Bir app içeren bir directory oluşturun.
- App'e uchg ekleyin.
- App'i bir tar.gz dosyasına sıkıştırın.
- tar.gz dosyasını bir victim'a gönderin.
- Victim tar.gz dosyasını açar ve app'i çalıştırır.
- Gatekeeper app'i kontrol etmez.<sup>[12]</sup>

### Prevent Quarantine xattr

Bir ".app" bundle'ına quarantine xattr eklenmezse, çalıştırıldığında **Gatekeeper tetiklenmez**.


## References

- [1] [Apple Platform Security: About the security content of macOS Sonoma 14.4 (includes CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: How macOS now tracks the provenance of apps](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: About the security content of macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia removes the Control‑click “Open” Gatekeeper bypass](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: The Discovery of CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Bypassing The macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identifies Safari vulnerability allowing for Gatekeeper bypass](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identifies macOS Archive Utility vulnerability allowing for Gatekeeper bypass (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper's Achilles heel: Unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Discovery of a Gatekeeper Bypass (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Finding and reporting a Gatekeeper bypass exploit with help from Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Bypassing macOS Security and Privacy Mechanisms — From Gatekeeper to System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)

{{#include ../../../banners/hacktricks-training.md}}
