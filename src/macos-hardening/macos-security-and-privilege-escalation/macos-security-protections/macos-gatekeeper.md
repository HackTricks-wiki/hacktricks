# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper**, Mac işletim sistemleri için geliştirilmiş ve kullanıcıların sistemlerinde **yalnızca güvenilir yazılımları çalıştırmasını** sağlamaya yönelik bir güvenlik özelliğidir. Kullanıcının indirdiği ve **App Store dışındaki kaynaklardan** açmayı denediği yazılımları (uygulama, plug-in veya installer package gibi) **doğrulayarak** çalışır.

Gatekeeper'ın temel mekanizması **doğrulama** sürecidir. İndirilen yazılımın, yazılımın gerçekliğini doğrulamak için **tanınan bir developer tarafından imzalanıp imzalanmadığını** kontrol eder. Ayrıca yazılımın Apple tarafından **notarize edilip edilmediğini** belirleyerek bilinen kötü amaçlı içerikten arındırılmış olduğunu ve notarization sonrasında değiştirilmediğini doğrular.

Buna ek olarak Gatekeeper, indirilen yazılımın ilk kez açılmasını **kullanıcıların onaylamasını isteyerek** kullanıcı kontrolünü ve güvenliğini güçlendirir. Bu koruma, kullanıcıların zararsız bir data file zannettikleri, potansiyel olarak zararlı executable code'u yanlışlıkla çalıştırmasını önlemeye yardımcı olur.

### Application Signatures

Application signatures veya code signatures olarak da bilinen uygulama imzaları, Apple'ın güvenlik altyapısının kritik bir bileşenidir. **Yazılım author'ının (developer'ın) kimliğini doğrulamak** ve code'un son kez imzalandığından beri değiştirilmediğinden emin olmak için kullanılır.

İşleyişi şöyledir:

1. **Signing the Application:** Bir developer uygulamasını dağıtmaya hazır olduğunda, **private key kullanarak uygulamayı imzalar**. Bu private key, developer'ın Apple Developer Program'a kaydolduğu sırada Apple'ın developer'a verdiği bir **certificate ile ilişkilidir**. İmzalama süreci, uygulamanın tüm bölümlerinin cryptographic hash'ini oluşturmayı ve bu hash'i developer'ın private key'i ile encrypt etmeyi içerir.
2. **Distributing the Application:** İmzalanan uygulama, karşılık gelen public key'i içeren developer certificate'ı ile birlikte kullanıcılara dağıtılır.
3. **Verifying the Application:** Kullanıcı uygulamayı indirip çalıştırmayı denediğinde Mac işletim sistemi, hash'i decrypt etmek için developer certificate'ındaki public key'i kullanır. Ardından uygulamanın mevcut durumuna göre hash'i yeniden hesaplar ve bunu decrypt edilmiş hash ile karşılaştırır. Hash'ler eşleşirse, **uygulamanın developer tarafından imzalanmasından beri değiştirilmediği** anlamına gelir ve sistem uygulamanın çalışmasına izin verir.

Application signatures, Apple'ın Gatekeeper teknolojisinin önemli bir parçasıdır. Kullanıcı **internet'ten indirilmiş bir uygulamayı açmayı** denediğinde Gatekeeper application signature'ı doğrular. Uygulama Apple tarafından bilinen bir developer'a verilmiş bir certificate ile imzalanmışsa ve code değiştirilmemişse Gatekeeper uygulamanın çalışmasına izin verir. Aksi takdirde uygulamayı engeller ve kullanıcıyı uyarır.

macOS Catalina'dan itibaren **Gatekeeper, uygulamanın Apple tarafından notarize edilip edilmediğini de kontrol eder** ve böylece ek bir güvenlik katmanı sağlar. Notarization süreci uygulamayı bilinen security issue'lar ve malicious code açısından kontrol eder. Bu kontroller başarıyla geçilirse Apple, Gatekeeper'ın doğrulayabileceği bir ticket'ı uygulamaya ekler.

#### Check Signatures

Bazı **malware sample**'larını kontrol ederken binary'nin **signature'ını** her zaman **kontrol etmelisiniz**; çünkü onu imzalayan **developer** daha önce **malware ile ilişkili** olabilir.
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

Apple'ın notarization süreci, kullanıcıları potansiyel olarak zararlı yazılımlardan korumak için ek bir güvenlik önlemi görevi görür. Bu süreçte **geliştirici, uygulamasını inceleme için** **Apple's Notary Service**'e gönderir; bu hizmet App Review ile karıştırılmamalıdır. Bu hizmet, gönderilen yazılımı **kötü amaçlı içerik** ve code-signing ile ilgili olası sorunlar açısından inceleyen **otomatik bir sistemdir**.

Yazılım herhangi bir sorun oluşturmadan bu incelemeyi **geçerse**, Notary Service bir notarization ticket oluşturur. Geliştiricinin daha sonra bu **ticket'ı yazılımına eklemesi** gerekir; bu işlem 'stapling' olarak adlandırılır. Ayrıca notarization ticket çevrimiçi olarak da yayımlanır ve Apple'ın security technology'si olan Gatekeeper bu ticket'a erişebilir.

Kullanıcının yazılımı ilk kez yüklemesi veya çalıştırması sırasında, notarization ticket'ın - yürütülebilir dosyaya stapled edilmiş ya da çevrimiçi olarak bulunmuş olması fark etmeksizin - mevcut olması, **Gatekeeper'a yazılımın Apple tarafından notarized edildiğini bildirir**. Bunun sonucunda Gatekeeper, ilk çalıştırma iletişim kutusunda açıklayıcı bir mesaj görüntüler ve yazılımın Apple tarafından kötü amaçlı içerik açısından kontrol edildiğini belirtir. Böylece bu süreç, kullanıcıların sistemlerine yükledikleri veya çalıştırdıkları yazılımın güvenliğine duydukları güveni artırır.

### spctl & syspolicyd

> [!CAUTION]
> Sequoia sürümünden itibaren **`spctl`** artık Gatekeeper yapılandırmasının değiştirilmesine izin vermez.

**`spctl`**, Gatekeeper'ı (`syspolicyd` daemon'ı ile XPC messages üzerinden) listelemek ve onunla etkileşim kurmak için kullanılan CLI tool'dur. Örneğin, **GateKeeper'ın durumunu** şu şekilde görmek mümkündür:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> GateKeeper signature kontrollerinin her dosya için değil, yalnızca **Quarantine attribute** içeren dosyalar için gerçekleştirildiğini unutmayın.

GateKeeper, **preferences & signature** değerlerine göre bir binary'nin çalıştırılıp çalıştırılamayacağını kontrol eder:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`**, Gatekeeper'ı uygulamaktan sorumlu ana daemon'dur. `/var/db/SystemPolicy` konumunda bulunan bir database'i yönetir ve [database desteğini sağlayan code burada](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp), [SQL template'ini ise burada](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) bulabilirsiniz. Database'in SIP tarafından kısıtlanmadığını ve root tarafından yazılabildiğini unutmayın. Ayrıca `/var/db/.SystemPolicy-default` database'i, diğer database'in bozulması durumunda original backup olarak kullanılır.

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
**`syspolicyd`** ayrıca `assess`, `update`, `record` ve `cancel` gibi farklı işlemlere sahip bir XPC sunucusu da sunar; bunlara **Security.framework`ün `SecAssessment*`** API'leri kullanılarak da erişilebilir ve **`spctl`** aslında XPC üzerinden **`syspolicyd`** ile iletişim kurar.

İlk kuralın "**App Store**" ile, ikincisinin ise "**Developer ID**" ile bittiğine ve önceki görüntüde **App Store'dan ve tanınan geliştiricilerden gelen uygulamaları çalıştırmanın etkin olduğuna** dikkat edin.\
Bu ayarı App Store olarak **değiştirirseniz**, "**Notarized Developer ID" rules will disappear**.

Ayrıca **GKE** türünde binlerce kural vardır:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Bunlar şu kaynaklardan alınan hash'lerdir:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Ya da önceki bilgileri şu komutla listeleyebilirsiniz:
```bash
sudo spctl --list
```
**`spctl`** seçenekleri olan **`--master-disable`** ve **`--global-disable`**, bu signature kontrollerini tamamen **devre dışı bırakır**:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Tamamen etkinleştirildiğinde yeni bir seçenek görünür:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Şununla **bir App'in GateKeeper tarafından izin verilip verilmeyeceğini kontrol etmek** mümkündür:
```bash
spctl --assess -v /Applications/App.app
```
GateKeeper'a aşağıdaki komutla belirli uygulamaların çalıştırılmasına izin veren yeni kurallar eklemek mümkündür:
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
**kernel extensions** ile ilgili olarak, `/var/db/SystemPolicyConfiguration` klasörü yüklenmesine izin verilen kext'lerin listelerini içeren dosyalar barındırır. Ayrıca `spctl`, yeni önceden onaylanmış kernel extensions ekleyebildiği için `com.apple.private.iokit.nvram-csr` entitlement'ına sahiptir; bu kernel extensions'ların `kext-allowed-teams` key'i altında NVRAM'e de kaydedilmesi gerekir.

#### macOS 15 (Sequoia) ve sonraki sürümlerde Gatekeeper yönetimi

- Uzun süredir kullanılan Finder **Ctrl+Open / Right-click → Open** bypass yöntemi kaldırılmıştır; kullanıcıların, ilk engelleme iletişim kutusundan sonra engellenen bir uygulamaya **Sistem Ayarları → Gizlilik ve Güvenlik → Yine de Aç** üzerinden açıkça izin vermesi gerekir.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` artık kabul edilmez; `spctl`, assessment ve label management için fiilen read-only durumdadır; policy enforcement ise UI veya MDM üzerinden yapılandırılır.

macOS 15 Sequoia'dan itibaren son kullanıcılar Gatekeeper politikasını `spctl` üzerinden değiştiremez. Yönetim, Sistem Ayarları üzerinden veya `com.apple.systempolicy.control` payload'ına sahip bir MDM configuration profile dağıtılarak gerçekleştirilir. App Store ve identified developers'a izin veren (ancak "Anywhere" seçeneğine izin vermeyen) örnek profile snippet'i:

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

Bir uygulama veya dosya **indirildiğinde**, web tarayıcıları veya e-posta istemcileri gibi belirli macOS **uygulamaları**, indirilen dosyaya genellikle "**quarantine flag**" olarak bilinen bir **extended file attribute** ekler. Bu attribute, **dosyayı** güvenilmeyen bir kaynaktan (internet) geldiğini ve potansiyel riskler taşıyabileceğini belirtmek için kullanılan bir güvenlik önlemidir. Ancak tüm uygulamalar bu attribute'u eklemez; örneğin yaygın BitTorrent client yazılımları genellikle bu süreci bypass eder.

**Bir quarantine flag'in mevcut olması, kullanıcı dosyayı çalıştırmayı denediğinde macOS'un Gatekeeper güvenlik özelliğini tetikler**.

**Quarantine flag mevcut değilse** (bazı BitTorrent client'larıyla indirilen dosyalarda olduğu gibi), Gatekeeper'ın **kontrolleri gerçekleştirilmeyebilir**. Bu nedenle kullanıcılar, daha az güvenli veya bilinmeyen kaynaklardan indirilen dosyaları açarken dikkatli olmalıdır.

> [!NOTE] > Kod imzalarının **geçerliliğini** **kontrol etmek**, kodun ve tüm bundled resource'larının kriptografik **hash** değerlerini oluşturmayı içeren **kaynak yoğun** bir süreçtir. Ayrıca sertifika geçerliliğinin kontrol edilmesi, sertifikanın verildikten sonra iptal edilip edilmediğini kontrol etmek için Apple sunucularına **online check** yapılmasını gerektirir. Bu nedenlerle, her uygulama başlatıldığında tam bir code signature ve notarization check çalıştırmak **pratik değildir**.
>
> Bu nedenle bu kontroller, **yalnızca quarantine attribute'una sahip uygulamalar çalıştırılırken gerçekleştirilir.**

> [!WARNING]
> Bu attribute, dosyayı oluşturan/indiren **uygulama tarafından ayarlanmalıdır**.
>
> Ancak sandboxed dosyalar, oluşturdukları her dosyada bu attribute'un ayarlanmasını sağlar. Ayrıca non sandboxed uygulamalar bunu kendileri ayarlayabilir veya [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) anahtarını **Info.plist** içinde belirtebilir; bu da sistemin oluşturulan dosyalara `com.apple.quarantine` extended attribute'unu eklemesini sağlar,

Ayrıca **`qtn_proc_apply_to_self`** çağrısını yapan bir process tarafından oluşturulan tüm dosyalar quarantined olur. Ya da **`qtn_file_apply_to_path`** API'si, belirtilen dosya path'ine quarantine attribute'unu ekler.

Durumunu **kontrol etmek ve etkinleştirmek/devre dışı bırakmak** (root gerekir) mümkündür:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Ayrıca bir dosyanın quarantine extended attribute değerine sahip olup olmadığını şu şekilde **bulabilirsiniz**:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**extended** **attributes** değerini kontrol edin ve quarantine attr'ı yazan uygulamayı bulun:
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
Aslında bir process, oluşturduğu files için "quarantine flags" ayarlayabilir (oluşturulan bir file'a USER_APPROVED flag'ini uygulamayı zaten denedim, ancak uygulanmıyor):

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

Ve bu özniteliği şununla kaldırın:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Ve karantinaya alınmış tüm dosyaları şu şekilde bulun:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine bilgileri, GUI'nin dosya kaynakları hakkındaki verileri almasını sağlayan **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** konumunda LaunchServices tarafından yönetilen merkezi bir veritabanında da saklanır. Ayrıca bu veritabanı, kaynaklarını gizlemekle ilgilenebilecek uygulamalar tarafından üzerine yazılabilir. Bu işlem LaunchServices API'leri üzerinden de gerçekleştirilebilir.

#### **libquarantine.dylib**

Bu library, extended attribute alanlarını değiştirmeye olanak tanıyan çeşitli işlevleri dışa aktarır.

`qtn_file_*` API'leri dosya quarantine policy'leriyle ilgilenir; `qtn_proc_*` API'leri ise process'lere uygulanır (process tarafından oluşturulan dosyalar). Dışa aktarılmamış `__qtn_syscall_quarantine*` işlevleri, `mac_syscall` işlevini ilk argüman olarak `"Quarantine"` ile çağıran ve policy'leri uygulayan işlevlerdir; bu çağrı istekleri `Quarantine.kext`'e gönderir.

#### **Quarantine.kext**

Kernel extension yalnızca sistemdeki **kernel cache** üzerinden kullanılabilir; ancak **Kernel Debug Kit'i** [**https://developer.apple.com/**](https://developer.apple.com/) adresinden indirebilirsiniz. Bu kit, extension'ın symbolicated bir sürümünü içerir.

Bu Kext, tüm file lifecycle event'lerini yakalamak için MACF üzerinden çeşitli çağrıları hook'lar: oluşturma, açma, yeniden adlandırma, hard-link oluşturma... hatta `com.apple.quarantine` extended attribute'unu ayarlamasını engellemek için `setxattr` çağrısını bile.

Ayrıca birkaç MIB kullanır:

- `security.mac.qtn.sandbox_enforce`: Quarantine'ı Sandbox ile birlikte enforce eder
- `security.mac.qtn.user_approved_exec`: Querantine edilmiş process'ler yalnızca onaylanmış dosyaları çalıştırabilir

#### Provenance xattr (Ventura ve sonrası)

macOS 13 Ventura, quarantine edilmiş bir uygulamanın çalışmasına ilk kez izin verildiğinde doldurulan ayrı bir provenance mekanizması kullanıma sundu.<sup>[[2]](#references)</sup> İki artefact oluşturulur:

- `.app` bundle directory üzerinde `com.apple.provenance` xattr'ı (primary key ve flag'leri içeren sabit boyutlu binary değer).
- `/var/db/SystemPolicyConfiguration/ExecPolicy/` içindeki ExecPolicy veritabanının `provenance_tracking` tablosunda uygulamanın cdhash ve metadata'sını saklayan bir satır.

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

XProtect, macOS'ta yerleşik bir **anti-malware** özelliğidir. XProtect, **herhangi bir uygulamayı ilk kez başlatıldığında veya değiştirildiğinde, bilinen malware'ler ve güvenli olmayan dosya türlerinden oluşan veritabanına karşı kontrol eder**. Safari, Mail veya Messages gibi belirli uygulamalar üzerinden bir dosya indirdiğinizde XProtect dosyayı otomatik olarak tarar. Veritabanındaki bilinen malware'lerden biriyle eşleşirse XProtect **dosyanın çalışmasını engeller** ve sizi tehdit konusunda uyarır.

XProtect veritabanı, yeni malware tanımlarıyla Apple tarafından **düzenli olarak güncellenir** ve bu güncellemeler Mac'inize otomatik olarak indirilip yüklenir. Bu sayede XProtect, bilinen en güncel tehditlere karşı her zaman güncel kalır.

Bununla birlikte, **XProtect'in tam özellikli bir antivirüs çözümü olmadığını** belirtmek gerekir. Yalnızca bilinen tehditlerden oluşan belirli bir listeyi kontrol eder ve çoğu antivirüs yazılımı gibi erişim sırasında tarama gerçekleştirmez.

Aşağıdaki komutu çalıştırarak en son XProtect güncellemesi hakkında bilgi alabilirsiniz:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect, SIP tarafından korunan **/Library/Apple/System/Library/CoreServices/XProtect.bundle** konumunda bulunur ve bundle içinde XProtect'in kullandığı bilgileri bulabilirsiniz:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Bu cdhash'lere sahip kodların legacy entitlements kullanmasına izin verir.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleID ve TeamID üzerinden yüklenmesine izin verilmeyen veya minimum bir sürüm belirten plugin ve extension'ların listesi.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Malware tespit etmek için Yara kuralları.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Engellenen application'ların hash'lerini ve TeamID'lerini içeren SQLite3 database.

**`/Library/Apple/System/Library/CoreServices/XProtect.app`** konumunda XProtect ile ilişkili başka bir App daha bulunduğunu, ancak bunun Gatekeeper sürecine dahil olmadığını unutmayın.

> XProtect Remediator: Modern macOS'ta Apple, malware ailelerini tespit etmek ve remediate etmek için launchd üzerinden periyodik olarak çalışan on-demand scanner'lar (XProtect Remediator) sağlar. Bu scan'leri unified log'larda gözlemleyebilirsiniz:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeper Değil

> [!CAUTION]
> Gatekeeper'ın bir application'ı her çalıştırdığınızda **çalıştırılmadığını** unutmayın; yalnızca _**AppleMobileFileIntegrity**_ tarafından, Gatekeeper tarafından daha önce çalıştırılmış ve doğrulanmış bir app'i çalıştırdığınızda **executable code signature'ları doğrulanır**.

Bu nedenle daha önce bir app'i Gatekeeper ile cache'lemek, ardından application'ın **executable olmayan dosyalarını** (Electron asar veya NIB dosyaları gibi) **değiştirmek** mümkündü ve başka bir protection mevcut değilse application, **malicious** eklemelerle **çalıştırılabiliyordu**.

Ancak artık bu mümkün değildir çünkü macOS, **application bundle'larının içindeki dosyaların değiştirilmesini engeller**. Bu nedenle [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack'ini denerseniz, app'i Gatekeeper ile cache'lemek için çalıştırdıktan sonra bundle'ı değiştiremeyeceğiniz için bunun artık abuse edilemediğini göreceksiniz. Örneğin Contents directory'sinin adını exploit'te belirtildiği gibi NotCon olarak değiştirir ve ardından Gatekeeper ile cache'lemek için app'in main binary'sini çalıştırırsanız, bir error tetiklenir ve çalıştırılmaz.

## Gatekeeper Bypasses

Gatekeeper'ı bypass etmenin herhangi bir yolu (kullanıcıya bir şey download ettirmeyi ve Gatekeeper'ın bunu engellemesi gerekirken çalıştırmasını sağlamayı başarmak) macOS'ta bir vulnerability olarak değerlendirilir. Bunlar, geçmişte Gatekeeper'ı bypass etmeye izin veren tekniklere atanmış CVE'lerden bazılarıdır:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Extraction için **Archive Utility** kullanıldığında, **886 karakteri aşan path'lere** sahip dosyaların com.apple.quarantine extended attribute'ünü almadığı gözlemlenmiştir. Bu durum, söz konusu dosyaların **Gatekeeper'ın** security check'lerini **bypass etmesine** istemeden izin verir.<sup>[[5]](#references)</sup>

Daha fazla bilgi için [**original report'a**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) bakın.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Bir application **Automator** ile oluşturulduğunda, çalıştırılması için gereken bilgiler executable içinde değil, `application.app/Contents/document.wflow` içinde bulunur. Executable, **Automator Application Stub** adı verilen generic bir Automator binary'sidir.

Bu nedenle `application.app/Contents/MacOS/Automator\ Application\ Stub` dosyasını **system içindeki başka bir Automator Application Stub'a symbolic link ile işaret edecek şekilde** ayarlayabilirsiniz; böylece **actual executable quarantine xattr'a sahip olmadığı için Gatekeeper'ı tetiklemeden** `document.wflow` (script'iniz) içindeki şeyi çalıştırır.<sup>[[6]](#references)</sup>

Beklenen konum örneği: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Daha fazla bilgi için [**original report'a**](https://ronmasas.com/posts/bypass-macos-gatekeeper) bakın.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Bu bypass'te, bir zip file `application.app` yerine `application.app/Contents` üzerinden başlayan bir application ile oluşturulmuştur. Bu nedenle **quarantine attr, `application.app` dışındaki `application.app/Contents` içindeki tüm dosyalara** uygulanmış; ancak Gatekeeper'ın kontrol ettiği **`application.app` dosyasına** uygulanmamıştır. Dolayısıyla `application.app` tetiklendiğinde **quarantine attribute'üne sahip olmadığı için** Gatekeeper bypass edilmiştir.<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Daha fazla bilgi için [**orijinal rapora**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) göz atın.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Bileşenler farklı olsa da bu vulnerability'nin exploitation'ı bir öncekiyle oldukça benzerdir. Bu durumda **`application.app/Contents`** üzerinden bir Apple Archive oluşturacağız; böylece **`application.app`**, **Archive Utility** tarafından decompress edildiğinde quarantine attr'ını almayacaktır.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Daha fazla bilgi için [**orijinal rapora**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) göz atın.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

**`writeextattr`** ACL'si, herhangi bir kişinin bir dosyaya öznitelik yazmasını engellemek için kullanılabilir:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Dahası, **AppleDouble** dosya formatı bir dosyayı ACE'leriyle birlikte kopyalar.<sup>[[9]](#references)</sup>

[**Kaynak kodunda**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), **`com.apple.acl.text`** adlı xattr içinde depolanan ACL metin gösteriminin, sıkıştırması açılmış dosyada ACL olarak ayarlanacağını görmek mümkündür. Dolayısıyla bir uygulamayı, diğer xattr'ların uygulamaya yazılmasını engelleyen bir ACL ile **AppleDouble** dosya formatını kullanan bir zip dosyasına sıkıştırırsanız... quarantine xattr uygulamaya ayarlanmaz:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Daha fazla bilgi için [**orijinal raporu**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) inceleyin.<sup>[[9]](#references)</sup>

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

AppleDouble file format'ları, bir dosyanın attribute'larını `._` ile başlayan ayrı bir dosyada depolar; bu, dosya attribute'larının **macOS makineleri arasında** kopyalanmasına yardımcı olur. Ancak bir AppleDouble dosyası decompress edildikten sonra `._` ile başlayan dosyaya **quarantine attribute verilmediği** fark edildi.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Quarantine attribute ayarlanmamış bir dosya oluşturulabildiği için, **Gatekeeper'ı bypass etmek mümkün oluyordu.** Bunun yöntemi, AppleDouble adlandırma kuralını kullanarak (adı `._` ile başlatarak) bir **DMG file application** oluşturmak ve **quarantine attribute** içermeyen bu gizli dosyaya sembolik bağlantı olarak görünen bir dosya oluşturmaktı.\
**DMG file çalıştırıldığında**, quarantine attribute içermediği için **Gatekeeper'ı bypass eder**.
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

macOS Sonoma 14.0'da düzeltilen bir Gatekeeper bypass açığı, özel olarak hazırlanmış uygulamaların kullanıcıya uyarı gösterilmeden çalışmasına izin veriyordu. Ayrıntılar, patch uygulandıktan sonra kamuya açıklandı ve sorun, düzeltme yayınlanmadan önce gerçek saldırılarda aktif olarak istismar edildi. Sonoma 14.0 veya sonraki bir sürümün yüklü olduğundan emin olun.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Mart 2024'te yayımlanan macOS 14.4'teki bir Gatekeeper bypass açığı, `libarchive` tarafından kötü amaçlı ZIP dosyalarının işlenmesinden kaynaklanıyordu ve uygulamaların assessment işleminden kaçmasına izin veriyordu. Apple'ın sorunu giderdiği 14.4 veya sonraki bir sürüme update edin.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

İndirilen bir uygulamanın içine gömülü bir **Automator Quick Action workflow**, Gatekeeper assessment işlemi olmadan tetiklenebiliyordu; bunun nedeni workflow'ların data olarak değerlendirilmesi ve normal notarization prompt yolunun dışında Automator helper tarafından çalıştırılmasıydı. Bu nedenle, shell script çalıştıran bir Quick Action içeren (ör. `Contents/PlugIns/*.workflow/Contents/document.wflow` içinde) özel olarak hazırlanmış bir `.app`, başlatılır başlatılmaz çalışabiliyordu. Apple, ek bir consent dialog ekledi ve assessment yolunu Ventura **13.7**, Sonoma **14.7** ve Sequoia **15** sürümlerinde düzeltti.<sup>[[3]](#references)</sup>

### Third-party unarchiver'ların quarantine bilgisini yanlış aktarması (2023–2024)

Popüler extraction tool'larındaki (ör. The Unarchiver) çeşitli vulnerability'ler, archive'lardan çıkarılan dosyaların `com.apple.quarantine` xattr bilgisini almamasına neden olarak Gatekeeper bypass fırsatları oluşturdu. Test sırasında her zaman macOS Archive Utility'ye veya patch uygulanmış tool'lara güvenin ve extraction sonrasında xattr bilgilerini doğrulayın.

### uchg (bu [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)'tan)

- Bir app içeren bir directory oluşturun.
- App'e uchg ekleyin.
- App'i bir tar.gz file'ına compress edin.
- tar.gz file'ını bir victim'a gönderin.
- Victim, tar.gz file'ını açar ve app'i çalıştırır.
- Gatekeeper app'i check etmez.<sup>[[12]](#references)</sup>

### Quarantine xattr'ını önleme

Bir ".app" bundle'ına quarantine xattr eklenmezse, çalıştırıldığında **Gatekeeper tetiklenmez**.

## References

- [1] [Apple Platform Security: macOS Sonoma 14.4'ün security içeriği hakkında (CVE-2024-27853 dahil)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: macOS artık app'lerin provenance bilgisini nasıl takip ediyor](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: macOS Sonoma 14.7 / Ventura 13.7'nin security içeriği hakkında (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia, Control-click “Open” Gatekeeper bypass'ını kaldırıyor](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: CVE-2021-1810'un keşfi](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, macOS Gatekeeper'ı Bypass Etme](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs, Gatekeeper bypass'a izin veren Safari vulnerability'sini tespit etti](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs, Gatekeeper bypass'a izin veren macOS Archive Utility vulnerability'sini tespit etti (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper'ın Achilles heel'i: Bir macOS vulnerability'sini ortaya çıkarmak](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Bir Gatekeeper Bypass'ın keşfi (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Mac Monitor yardımıyla bir Gatekeeper bypass exploit'ini bulma ve raporlama](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: macOS Security ve Privacy Mechanism'larını Bypass Etme — Gatekeeper'dan System Integrity Protection'a (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: macOS Sonoma 14'ün security içeriği hakkında (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)

{{#include ../../../banners/hacktricks-training.md}}
