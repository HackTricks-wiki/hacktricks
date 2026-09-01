# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper**, Mac işletim sistemleri için geliştirilmiş ve kullanıcıların sistemlerinde **yalnızca güvenilir software çalıştırmasını** sağlamayı amaçlayan bir security özelliğidir. Bir kullanıcının **App Store dışındaki kaynaklardan** indirdiği ve açmayı denediği app, plug-in veya installer package gibi **software'leri doğrulayarak** çalışır.

Gatekeeper'ın temel mekanizması **verification** sürecidir. İndirilen software'in **tanınan bir developer tarafından imzalanıp imzalanmadığını** kontrol ederek software'in gerçekliğini doğrular. Ayrıca software'in **Apple tarafından notarised edilip edilmediğini** belirleyerek bilinen malicious content içermediğini ve notarisation sonrasında değiştirilmediğini doğrular.

Bunun yanı sıra Gatekeeper, indirilen software'in ilk kez açılmasını **kullanıcıların onayına sunarak** kullanıcı kontrolünü ve security'yi güçlendirir. Bu güvenlik önlemi, kullanıcıların zararsız bir data file sandıkları potansiyel olarak zararlı executable code'u yanlışlıkla çalıştırmasını önlemeye yardımcı olur.

### Application Signatures

Application signatures veya code signatures olarak da bilinen uygulama imzaları, Apple'ın security altyapısının kritik bir bileşenidir. **Software author'ın (developer'ın) kimliğini doğrulamak** ve code'un son imzalandığı zamandan beri değiştirilmediğinden emin olmak için kullanılır.

Şu şekilde çalışır:

1. **Signing the Application:** Bir developer application'ını dağıtmaya hazır olduğunda, **private key kullanarak application'ı imzalar**. Bu private key, Apple Developer Program'a kaydolduğunda **Apple'ın developer'a verdiği bir certificate ile ilişkilidir**. İmzalama işlemi, app'in tüm bölümlerinin cryptographic hash'ini oluşturmayı ve bu hash'i developer'ın private key'iyle şifrelemeyi içerir.
2. **Distributing the Application:** İmzalanmış application daha sonra, karşılık gelen public key'i içeren developer certificate'ı ile birlikte kullanıcılara dağıtılır.
3. **Verifying the Application:** Bir kullanıcı application'ı indirip çalıştırmayı denediğinde, Mac işletim sistemi hash'i decrypt etmek için developer certificate'ındaki public key'i kullanır. Ardından application'ın mevcut durumuna göre hash'i yeniden hesaplar ve bunu decrypt edilmiş hash ile karşılaştırır. Eşleşmeleri durumunda, **application'ın developer tarafından imzalanmasından sonra değiştirilmediği** anlamına gelir ve sistem application'ın çalışmasına izin verir.

Application signatures, Apple'ın Gatekeeper teknolojisinin temel bir parçasıdır. Bir kullanıcı **internet'ten indirilmiş bir application'ı açmayı** denediğinde Gatekeeper application signature'ını doğrular. Apple tarafından tanınan bir developer'a verilen certificate ile imzalanmışsa ve code değiştirilmemişse Gatekeeper application'ın çalışmasına izin verir. Aksi takdirde application'ı engeller ve kullanıcıyı uyarır.

macOS Catalina'dan itibaren **Gatekeeper application'ın Apple tarafından notarized edilip edilmediğini de kontrol eder** ve böylece ekstra bir security katmanı ekler. Notarization süreci application'ı bilinen security sorunları ve malicious code açısından kontrol eder ve bu kontroller başarılı olursa Apple application'a Gatekeeper'ın doğrulayabileceği bir ticket ekler.

#### Check Signatures

Herhangi bir **malware sample**'ını kontrol ederken binary'nin **signature'ını her zaman kontrol etmelisiniz**; çünkü onu imzalayan **developer** daha önce **malware** ile **ilişkili** olabilir.
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

Apple'ın notarization süreci, kullanıcıları potansiyel olarak zararlı yazılımlardan korumak için ek bir güvenlik önlemi görevi görür. Bu süreçte **developer, uygulamasını** App Review ile karıştırılmaması gereken **Apple's Notary Service** tarafından **incelenmek üzere gönderir**. Bu hizmet, gönderilen yazılımı **malicious content** ve code-signing ile ilgili olası sorunlar açısından inceleyen **automated system**'dir.

Yazılım herhangi bir sorun tespit edilmeden bu incelemeyi **geçerse**, Notary Service bir notarization ticket oluşturur. Ardından developer'ın bu ticket'ı yazılımına **eklemesi** gerekir; bu işlem 'stapling' olarak bilinir. Ayrıca notarization ticket, Gatekeeper'ın (Apple'ın güvenlik teknolojisi) erişebilmesi için çevrimiçi olarak da yayımlanır.

Kullanıcının yazılımı ilk kez yüklemesi veya çalıştırması sırasında notarization ticket'ın varlığı (ister executable'a stapled edilmiş ister çevrimiçi olarak bulunmuş olsun), **Gatekeeper'a yazılımın Apple tarafından notarized edildiğini bildirir**. Bunun sonucunda Gatekeeper, ilk çalıştırma iletişim kutusunda açıklayıcı bir mesaj göstererek yazılımın Apple tarafından malicious content açısından denetimlerden geçirildiğini belirtir. Böylece bu süreç, kullanıcıların sistemlerine yükledikleri veya çalıştırdıkları yazılımın güvenliğine duyduğu güveni artırır.

### spctl & syspolicyd

> [!CAUTION]
> Sequoia sürümünden itibaren **`spctl`**'in Gatekeeper yapılandırmasını değiştirmeye artık izin vermediğini unutmayın.

**`spctl`**, Gatekeeper'ı (`syspolicyd` daemon'ı ile XPC messages aracılığıyla) listelemek ve onunla etkileşim kurmak için kullanılan CLI tool'dur. Örneğin, **GateKeeper**'ın **status** bilgisi şu şekilde görüntülenebilir:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> GateKeeper imza kontrollerinin her dosya için değil, yalnızca **Quarantine özniteliğine sahip dosyalar** için gerçekleştirildiğini unutmayın.

GateKeeper, **tercihlere ve imzaya** göre bir binary'nin çalıştırılıp çalıştırılamayacağını kontrol eder:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`**, Gatekeeper'ı uygulamaktan sorumlu ana daemon'dur. `/var/db/SystemPolicy` konumunda bulunan bir database'i yönetir ve [database desteğini sağlayan koda buradan](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp), [SQL şablonuna ise buradan](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) ulaşabilirsiniz. Database'in SIP tarafından kısıtlanmadığını ve root tarafından yazılabilir olduğunu unutmayın; `/var/db/.SystemPolicy-default` database'i ise diğer database'in bozulması durumunda orijinal yedek olarak kullanılır.

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
**`syspolicyd`** ayrıca `assess`, `update`, `record` ve `cancel` gibi farklı işlemlere sahip bir XPC sunucusu da sunar; bunlara **`Security.framework`'ün `SecAssessment*`** API'leri kullanılarak da erişilebilir ve **`spctl`** aslında XPC aracılığıyla **`syspolicyd`** ile iletişim kurar.

İlk kuralın "**App Store**" ile, ikincisinin ise "**Developer ID**" ile bittiğine ve önceki görüntüde **App Store'dan ve kimliği belirlenmiş geliştiricilerden gelen uygulamaları çalıştırmanın etkin olduğuna** dikkat edin.\
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
Bunlar şu kaynaklardan alınan hash'lerdir:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Alternatif olarak, önceki bilgileri şu komutla listeleyebilirsiniz:
```bash
sudo spctl --list
```
**`spctl`**'nin **`--master-disable`** ve **`--global-disable`** seçenekleri bu imza denetimlerini tamamen **devre dışı bırakır**:
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

Bir App'in **GateKeeper tarafından izin verilip verilmeyeceğini kontrol etmek** için:
```bash
spctl --assess -v /Applications/App.app
```
macOS 14 ve sonraki sürümlerde **`syspolicy_check`**, bir uygulama bundle'ı için dağıtım öncesi kullanışlı bir üst düzey kontroldür. Basit bir `spctl` sonucuna kıyasla daha uygulanabilir trusted-execution tanılamaları üretir; ancak Apple, quarantine propagation sürecini de test ettiği için gerçek indirme/çıkarma/ilk çalıştırma yolunun test edilmesini yine de önerir.<sup>[[14]](#references)</sup>
```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```
GateKeeper'a aşağıdaki yöntemle belirli uygulamaların çalıştırılmasına izin veren yeni kurallar eklemek mümkündür:
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
**kernel extensions** ile ilgili olarak, `/var/db/SystemPolicyConfiguration` klasörü yüklenmesine izin verilen kext listelerini içeren dosyalar barındırır. Ayrıca `spctl`, önceden onaylanmış ve eklenmesi gereken yeni kernel extensions'ları ekleyebildiği için `com.apple.private.iokit.nvram-csr` entitlement'ına sahiptir; bu kernel extensions'lar NVRAM'de `kext-allowed-teams` anahtarı altında da kaydedilmelidir.

#### macOS 15 (Sequoia) ve sonraki sürümlerde Gatekeeper'ı yönetme

- Uzun süredir kullanılan Finder **Ctrl+Open / Sağ tıklama → Open** bypass yöntemi kaldırılmıştır; kullanıcıların, ilk engelleme iletişim kutusundan sonra engellenen bir uygulamaya **System Settings → Privacy & Security → Open Anyway** üzerinden açıkça izin vermesi gerekir.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` artık unattended policy changes olarak kabul edilmemektedir. Rule database'i veya global assessment state'i değiştiren işlemler deprecated durumdadır; bu nedenle assessment için `spctl` kullanın ve enforcement'ı UI veya MDM üzerinden yapılandırın.

macOS 15 Sequoia'dan itibaren end users artık Gatekeeper policy'sini `spctl` üzerinden değiştiremez. Yönetim, System Settings üzerinden veya `com.apple.systempolicy.control` payload'ına sahip bir MDM configuration profile dağıtılarak gerçekleştirilir. App Store ve identified developers'a izin veren (ancak "Anywhere" seçeneğine izin vermeyen) örnek profile snippet'i:

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

### Quarantine Dosyaları

Bir uygulama veya dosya **indirildiğinde**, web tarayıcıları veya e-posta istemcileri gibi belirli macOS **uygulamaları**, indirilen dosyaya yaygın olarak "**quarantine flag**" olarak bilinen bir **genişletilmiş dosya özniteliği** ekler. Bu öznitelik, **dosyayı**, güvenilmeyen bir kaynaktan (internet) geldiğini ve potansiyel riskler taşıyabileceğini **belirtmek** için bir güvenlik önlemi olarak kullanılır. Ancak tüm uygulamalar bu özniteliği eklemez; örneğin yaygın BitTorrent istemci yazılımları genellikle bu işlemi atlar.

**Bir quarantine flag'in mevcut olması, kullanıcı dosyayı çalıştırmayı denediğinde macOS'un Gatekeeper güvenlik özelliğini tetikler**.

**Quarantine flag'in mevcut olmadığı** durumlarda (bazı BitTorrent istemcileri aracılığıyla indirilen dosyalarda olduğu gibi), Gatekeeper'ın **kontrolleri gerçekleştirilmeyebilir**. Bu nedenle kullanıcılar, daha az güvenli veya bilinmeyen kaynaklardan indirilen dosyaları açarken dikkatli olmalıdır.

> [!NOTE] > Kod imzalarının **geçerliliğini** **kontrol etmek**, kodun ve paketlenmiş tüm kaynaklarının kriptografik **hash** değerlerinin oluşturulmasını içeren, **kaynak tüketen** bir işlemdir. Ayrıca sertifikanın geçerliliğini kontrol etmek, sertifikanın düzenlenmesinden sonra iptal edilip edilmediğini görmek için Apple sunucularına **online bir kontrol** yapılmasını gerektirir. Bu nedenlerle, her uygulama başlatıldığında tam bir kod imzası ve notarization kontrolü çalıştırmak **uygulanabilir değildir**.
>
> Bu nedenle bu kontroller yalnızca **quarantined özniteliğine sahip uygulamalar çalıştırılırken** gerçekleştirilir.

> [!WARNING]
> Bu öznitelik, dosyayı oluşturan/indiren uygulama tarafından **ayarlanmalıdır**.
>
> Ancak sandboxed dosyalar, oluşturdukları her dosyada bu özniteliğin ayarlanmasını sağlar. Ayrıca non sandboxed uygulamalar bunu kendileri ayarlayabilir veya **Info.plist** içinde [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) anahtarını belirtebilir; bu da sistemin oluşturulan dosyalara `com.apple.quarantine` genişletilmiş özniteliğini ayarlamasını sağlar,

Ayrıca **`qtn_proc_apply_to_self`** çağrısını yapan bir process tarafından oluşturulan tüm dosyalar quarantined olur. Alternatif olarak **`qtn_file_apply_to_path`** API'si, belirtilen dosya yoluna quarantine özniteliğini ekler.

**Durumunu kontrol etmek ve etkinleştirmek/devre dışı bırakmak** (root gerektirir) için:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Ayrıca bir dosyada **quarantine extended attribute** bulunup bulunmadığını şu şekilde **kontrol edebilirsiniz**:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**extended** **attributes** değerini kontrol edin ve **quarantine** attr değerini yazan uygulamayı şu şekilde bulun:
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
Aslında bir process, oluşturduğu dosyalara "quarantine flags" ayarlayabilir (Oluşturulan bir dosyada USER_APPROVED flag'ini uygulamayı zaten denedim, ancak uygulanmıyor):

<details>

<summary>Kaynak Kodu: quarantine flags uygulama</summary>
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

Ve **bu özniteliği** şununla kaldırın:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Ve karantinaya alınmış tüm dosyaları şu komutla bulun:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine bilgileri ayrıca LaunchServices tarafından **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** konumunda yönetilen merkezi bir veritabanında da saklanır; bu, GUI'nin dosya kaynakları hakkında veri almasını sağlar. Ayrıca bu bilgiler, kaynaklarını gizlemekle ilgilenebilecek uygulamalar tarafından üzerine yazılabilir. Dahası, bu işlem LaunchServices API'leri üzerinden gerçekleştirilebilir.

#### **libquarantine.dylib**

Bu library, extended attribute alanlarını değiştirmeye olanak tanıyan çeşitli işlevleri dışa aktarır.

`qtn_file_*` API'leri file quarantine policies ile ilgilenir; `qtn_proc_*` API'leri ise process'lere uygulanır (process tarafından oluşturulan dosyalar). Dışa aktarılmamış `__qtn_syscall_quarantine*` işlevleri, `mac_syscall`'ı ilk argüman olarak "Quarantine" ile çağırarak istekleri `Quarantine.kext`'e gönderen ve policies'leri uygulayan işlevlerdir.

#### **Quarantine.kext**

Kernel extension yalnızca **kernel cache on the system** üzerinden kullanılabilir; ancak extension'ın symbolicated bir sürümünü içeren **Kernel Debug Kit'i** [**https://developer.apple.com/**](https://developer.apple.com/) adresinden _indirebilirsiniz_.

Bu Kext, tüm file lifecycle event'lerini yakalamak için MACF aracılığıyla çeşitli çağrıları hook'lar: Creation, opening, renaming, hard-linkning... hatta `com.apple.quarantine` extended attribute'unun ayarlanmasını engellemek için `setxattr`'i bile.

Ayrıca birkaç MIB kullanır:

- `security.mac.qtn.sandbox_enforce`: Quarantine'ı Sandbox ile birlikte zorunlu kılar
- `security.mac.qtn.user_approved_exec`: Querantined procs yalnızca onaylanmış dosyaları çalıştırabilir

#### Provenance xattr (Ventura and later)

macOS 13 Ventura, quarantined bir app'in çalışmasına ilk kez izin verildiğinde doldurulan ayrı bir provenance mekanizması sunmuştur.<sup>[[2]](#references)</sup> İki artefact oluşturulur:

- `.app` bundle directory üzerinde `com.apple.provenance` xattr'ı (primary key ve flags içeren sabit boyutlu binary değer).
- `/var/db/SystemPolicyConfiguration/ExecPolicy/` konumundaki ExecPolicy database içinde, app'in cdhash'ini ve metadata'sını depolayan `provenance_tracking` tablosunda bir satır.

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

XProtect, macOS'te yerleşik bir **anti-malware** özelliğidir. XProtect, **herhangi bir uygulamayı ilk kez başlatıldığında veya değiştirildiğinde, bilinen malware ve güvenli olmayan dosya türlerinden oluşan veritabanına karşı kontrol eder**. Safari, Mail veya Messages gibi belirli uygulamalar üzerinden bir dosya indirdiğinizde XProtect dosyayı otomatik olarak tarar. Veritabanındaki bilinen malware türlerinden biriyle eşleşirse XProtect **dosyanın çalışmasını engeller** ve sizi tehdit hakkında uyarır.

XProtect veritabanı, yeni malware tanımlarıyla Apple tarafından **düzenli olarak güncellenir** ve bu güncellemeler Mac'inize otomatik olarak indirilip yüklenir. Bu, XProtect'in en son bilinen tehditlere karşı her zaman güncel olmasını sağlar.

Ancak **XProtect'in tam özellikli bir antivirus çözümü olmadığını** belirtmek gerekir. Yalnızca bilinen tehditlerden oluşan belirli bir listeyi kontrol eder ve çoğu antivirus yazılımı gibi erişim sırasında tarama gerçekleştirmez.

Aşağıdaki komutu çalıştırarak en son XProtect güncellemesi hakkında bilgi alabilirsiniz:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect, SIP tarafından korunan **/Library/Apple/System/Library/CoreServices/XProtect.bundle** konumunda bulunur ve bundle içinde XProtect'in kullandığı bilgileri bulabilirsiniz:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Bu cdhash'lere sahip kodların legacy entitlements kullanmasına izin verir.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleID ve TeamID aracılığıyla yüklenmesi engellenen veya minimum sürüm belirten plugin ve extension listesi.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Malware tespit etmek için Yara kuralları.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Engellenen uygulamaların hash'lerini ve TeamID'leri içeren SQLite3 database.

**`/Library/Apple/System/Library/CoreServices/XProtect.app`** konumunda XProtect ile ilişkili başka bir App daha bulunduğunu, ancak bunun Gatekeeper sürecine dahil olmadığını unutmayın.

> XProtect Remediator: Modern macOS'ta Apple, malware ailelerini tespit etmek ve düzeltmek için launchd aracılığıyla periyodik olarak çalışan on-demand scanner'lar (XProtect Remediator) sunar. Bu taramaları unified log'larda gözlemleyebilirsiniz:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeper Değil

> [!CAUTION]
> Gatekeeper'ın **bir uygulamayı her çalıştırdığınızda yürütülmediğini** unutmayın; yalnızca _**AppleMobileFileIntegrity**_ daha önce Gatekeeper tarafından yürütülmüş ve doğrulanmış bir uygulamayı çalıştırdığınızda **çalıştırılabilir kod imzalarını doğrular**.

Bu nedenle, daha önce bir uygulamayı Gatekeeper ile cache'lemek, ardından **uygulamanın çalıştırılabilir olmayan dosyalarını** (Electron asar veya NIB dosyaları gibi) **değiştirmek** ve başka bir protection mevcut değilse uygulamanın **malicious** eklemelerle **yürütülmesini** sağlamak mümkündü.

Ancak artık bu mümkün değildir; çünkü macOS, **uygulama bundle'larının içindeki dosyaların değiştirilmesini engeller**. Bu nedenle [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack'ini denerseniz, uygulamayı Gatekeeper ile cache'lemek için çalıştırdıktan sonra bundle'ı değiştiremeyeceğiniz için artık bunu abuse etmenin mümkün olmadığını göreceksiniz. Örneğin Contents directory'sinin adını exploit'te belirtildiği gibi NotCon olarak değiştirir ve ardından uygulamanın main binary'sini Gatekeeper ile cache'lemek için çalıştırırsanız, bir error tetiklenir ve uygulama çalıştırılmaz.

## Gatekeeper Bypass'leri

Gatekeeper'ı bypass etmenin herhangi bir yolu (kullanıcıya bir şey download ettirip Gatekeeper'ın engellemesi gerekirken bunu çalıştırmasını sağlamayı başarmak), macOS'ta vulnerability olarak kabul edilir. Bunlar, geçmişte Gatekeeper'ı bypass etmeye izin veren tekniklere atanmış bazı CVE'lerdir:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Extraction için **Archive Utility** kullanıldığında, **886 karakteri aşan path'lere** sahip dosyaların com.apple.quarantine extended attribute'ünü almadığı gözlemlenmiştir. Bu durum, söz konusu dosyaların istemeden **Gatekeeper'ın** security check'lerini **bypass etmesine** izin verir.<sup>[[5]](#references)</sup>

Daha fazla bilgi için [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) sayfasına bakın.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Bir application **Automator** ile oluşturulduğunda, çalıştırmak için ihtiyaç duyduğu bilgiler executable içinde değil, `application.app/Contents/document.wflow` içinde bulunur. Executable, **Automator Application Stub** adlı generic bir Automator binary'sidir.

Bu nedenle `application.app/Contents/MacOS/Automator\ Application\ Stub` dosyasını **system içindeki başka bir Automator Application Stub'a symbolic link ile işaret edecek şekilde** ayarlayabilirsiniz; böylece `document.wflow` içinde bulunanları (script'inizi) **Gatekeeper'ı tetiklemeden** çalıştırır, çünkü gerçek executable quarantine xattr'üne sahip değildir.<sup>[[6]](#references)</sup>

Beklenen konum örneği: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Daha fazla bilgi için [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) sayfasına bakın.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Bu bypass'te, bir zip file `application.app` yerine `application.app/Contents` üzerinden compress edilmeye başlanacak şekilde oluşturulmuştur. Bu nedenle **quarantine attr**, **`application.app/Contents` içindeki tüm dosyalara** uygulanmış, ancak Gatekeeper'ın kontrol ettiği **`application.app` dosyasına** uygulanmamıştır. Böylece Gatekeeper bypass edilmiştir; çünkü `application.app` tetiklendiğinde **quarantine attribute'üne sahip değildi.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Daha fazla bilgi için [**orijinal rapora**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) göz atın.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Bileşenler farklı olsa da bu zafiyetin exploitation yöntemi bir öncekiyle oldukça benzerdir. Bu durumda **`application.app/Contents`** konumundan bir Apple Archive oluşturacağız; böylece **`application.app`**, **Archive Utility** tarafından açıldığında quarantine özniteliğini almayacaktır.<sup>[[8]](#references)</sup>
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
Ayrıca, **AppleDouble** dosya formatı bir dosyayı ACE'leriyle birlikte kopyalar.<sup>[[9]](#references)</sup>

[**Kaynak kodda**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), **`com.apple.acl.text`** adlı xattr içinde depolanan ACL metin temsilinin, sıkıştırması açılan dosyada ACL olarak ayarlanacağını görmek mümkündür. Bu nedenle, bir uygulamayı, diğer xattr'ların üzerine yazılmasını engelleyen bir ACL ile **AppleDouble** dosya formatını kullanarak bir zip dosyasına sıkıştırırsanız... quarantine xattr'ı uygulamaya ayarlanmaz:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Daha fazla bilgi için [**orijinal rapora**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) göz atın.<sup>[[9]](#references)</sup>

Bunun AppleArchives ile de exploit edilebileceğini unutmayın:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Bazı macOS dahili sorunları nedeniyle **Google Chrome'un indirilen dosyalara karantina özniteliğini ayarlamadığı** keşfedildi.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble, bir dosyanın özniteliklerini adı `._` ile başlayan ayrı bir dosyada depolar; bu, dosya özniteliklerinin **macOS makineleri arasında kopyalanmasına** yardımcı olur. Ancak bir AppleDouble dosyasının sıkıştırması açıldıktan sonra, `._` ile başlayan dosyaya **karantina özniteliği verilmedi**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
Karantina özniteliği ayarlanmamış bir dosya oluşturulabildiğinden, **Gatekeeper'ı atlamak mümkündü.** Bunun yöntemi, AppleDouble adlandırma kuralını (`._` ile başlayacak şekilde) kullanarak bir **DMG file application** oluşturmak ve **karantina özniteliği olmayan bu gizli dosyaya sembolik bağlantı olarak görünen bir dosya** oluşturmaktı.\
**dmg file çalıştırıldığında**, karantina özniteliğine sahip olmadığından **Gatekeeper'ı atlar**.
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

Apple, iyileştirilmiş kontroller aracılığıyla macOS Sonoma 14.0 sürümünde bir LaunchServices mantık hatasını düzeltti. Kamuya açık advisory yalnızca bir app'in Gatekeeper'ı bypass edebileceğini belirtiyor; bu nedenle yalnızca CVE girdisine dayanarak belirli bir taşıyıcı formatı veya exploitation chain sonucu çıkarmayın.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

macOS 14.4'te (Mart 2024'te yayımlandı), `libarchive` tarafından kötü amaçlı ZIP'lerin işlenmesinden kaynaklanan bir Gatekeeper bypass'ı, app'lerin assessment'tan kaçmasına izin veriyordu. Apple'ın sorunu giderdiği 14.4 veya sonraki bir sürüme güncelleyin.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

İndirilen bir app'in içine gömülü bir **Automator Quick Action workflow**, Gatekeeper assessment'ı olmadan tetiklenebiliyordu; bunun nedeni workflow'ların veri olarak değerlendirilmesi ve normal notarization prompt yolunun dışında Automator helper tarafından çalıştırılmasıydı. Bu nedenle, shell script çalıştıran bir Quick Action içeren hazırlanmış bir `.app` (örneğin `Contents/PlugIns/*.workflow/Contents/document.wflow` içinde) launch sırasında hemen çalışabiliyordu. Apple, Ventura **13.7**, Sonoma **14.7** ve Sequoia **15** sürümlerinde ek bir consent dialog ekledi ve assessment yolunu düzeltti.<sup>[[3]](#references)</sup>

### Extraction ve copy sınırlarındaki quarantine propagation hataları

2024 tarihli bir çalışma, test edilen iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) ve 7z Utility (DMG/ZIP/7Z) sürümlerinde propagation açıkları buldu; ayrıca VMware Tools ile host-to-guest copy işlemleri sırasında attribute'un kaybolduğunu gözlemledi. Birkaç vendor daha sonra fix duyurdu; bu nedenle bu adları kalıcı bir vulnerable-software listesi olarak değil, **version-specific retesting** için ipuçları olarak değerlendirin. Aynı trust-boundary sorunu native Unix workflow'ları için de geçerlidir: `curl`/`scp` quarantine eklemez ve command-line `tar`/`unzip`, bunu bir taşıyıcı arşivden otomatik olarak devralmaz.<sup>[[15]](#references)</sup>

Offensive testing için her **browser**, mail client, archive, disk-image, cloud-sync, shared-folder ve VM-copy geçişinden sonra taşıyıcıyı ve son app'i karşılaştırın. Açık bir `spctl` rejection, eksik bir xattr'ı düzeltmez: quarantine olmadan normal first-open Gatekeeper yolu bu assessment'ı hiç istemeyebilir.<sup>[[15]](#references)</sup>
```bash
# 1. Confirm the browser-downloaded carrier is quarantined
xattr -p com.apple.quarantine ./payload.zip

# 2. Extract/copy it through the application under test, then inspect the result
xattr -p com.apple.quarantine ./out/Payload.app || echo "QUARANTINE LOST"
spctl --assess --type execute -vv ./out/Payload.app

# 3. Enumerate every app bundle whose top-level directory lost the marker
find ./out -type d -name '*.app' -prune -exec sh -c \
'for app do xattr -p com.apple.quarantine "$app" >/dev/null 2>&1 || echo "$app"; done' sh {} +
```
### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Bir uygulama içeren bir dizin oluşturun.
- Uygulamaya uchg ekleyin.
- Uygulamayı bir tar.gz dosyasına sıkıştırın.
- tar.gz dosyasını kurbana gönderin.
- Kurban tar.gz dosyasını açar ve uygulamayı çalıştırır.
- Gatekeeper uygulamayı denetlemez.<sup>[[12]](#references)</sup>

### Quarantine xattr'ı Önleme

Bir ".app" bundle'ına quarantine xattr eklenmezse, çalıştırıldığında **Gatekeeper tetiklenmez**.

Genişletilmiş öznitelikleri önleyebilen veya kaldırabilen filesystem-, flag-, ACL- ve AppleDouble tabanlı primitive'ler için [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) bölümüne bakın.



## References

- [1] [Apple Platform Security: macOS Sonoma 14.4'ün güvenlik içeriği hakkında (CVE-2024-27853 dahil)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: macOS artık uygulamaların provenance bilgisini nasıl izliyor](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: macOS Sonoma 14.7 / Ventura 13.7'ün güvenlik içeriği hakkında (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia, Control‑click “Open” Gatekeeper bypass'ını kaldırıyor](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: CVE-2021-1810'ın keşfi](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, macOS Gatekeeper'ı bypass etme](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs, Gatekeeper bypass'ına olanak tanıyan Safari vulnerability'sini tespit ediyor](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs, Gatekeeper bypass'ına olanak tanıyan macOS Archive Utility vulnerability'sini tespit ediyor (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper'ın Achilles heel'i: Bir macOS vulnerability'sini ortaya çıkarmak](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Bir Gatekeeper Bypass'ının Keşfi (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Mac Monitor yardımıyla bir Gatekeeper bypass exploit'ini bulma ve bildirme](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: macOS Security and Privacy Mechanisms'ı Bypass Etme — Gatekeeper'dan System Integrity Protection'a (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: macOS Sonoma 14'ün güvenlik içeriği hakkında (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Notarised bir ürünü test etme](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Gatekeeper Bypass — Bir macOS Security Mechanism'ındaki zayıflıkları ortaya çıkarma](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
