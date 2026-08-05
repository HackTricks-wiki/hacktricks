# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper**, Mac işletim sistemleri için geliştirilmiş ve kullanıcıların sistemlerinde **yalnızca güvenilir yazılımları çalıştırmasını** sağlamayı amaçlayan bir güvenlik özelliğidir. Bir kullanıcının **App Store dışındaki kaynaklardan** indirdiği ve açmayı denediği bir uygulama, plug-in veya installer package gibi **yazılımları doğrulayarak** çalışır.

Gatekeeper'ın temel mekanizması **doğrulama** sürecidir. İndirilen yazılımın **tanınan bir geliştirici tarafından imzalanıp imzalanmadığını** kontrol ederek yazılımın gerçekliğini doğrular. Ayrıca yazılımın **Apple tarafından notarise edilip edilmediğini** belirler; bu sayede yazılımın bilinen kötü amaçlı içerik barındırmadığı ve notarisation sonrasında değiştirilmediği doğrulanır.

Buna ek olarak Gatekeeper, indirilen yazılımın ilk kez açılmasını **kullanıcılardan onaylamalarını isteyerek** kullanıcı kontrolünü ve güvenliğini güçlendirir. Bu koruma, kullanıcıların zararsız bir data file zannettikleri potansiyel olarak zararlı executable code'u yanlışlıkla çalıştırmasını önlemeye yardımcı olur.

### Application Signatures

Application signatures veya code signatures olarak da bilinen uygulama imzaları, Apple'ın güvenlik altyapısının kritik bir bileşenidir. **Yazılım yazarının (geliştiricinin) kimliğini doğrulamak** ve code'un son imzalandığı tarihten bu yana değiştirilmediğinden emin olmak için kullanılırlar.

İşleyiş şekli şöyledir:

1. **Signing the Application:** Bir geliştirici uygulamasını dağıtmaya hazır olduğunda, **private key kullanarak uygulamayı imzalar**. Bu private key, geliştirici Apple Developer Program'a kaydolduğunda **Apple'ın geliştiriciye verdiği bir certificate** ile ilişkilidir. Signing işlemi, uygulamanın tüm bölümlerinin cryptographic hash'ini oluşturmayı ve bu hash'i geliştiricinin private key'i ile şifrelemeyi içerir.
2. **Distributing the Application:** İmzalanan uygulama, karşılık gelen public key'i içeren geliştiricinin certificate'ı ile birlikte kullanıcılara dağıtılır.
3. **Verifying the Application:** Bir kullanıcı uygulamayı indirip çalıştırmayı denediğinde, Mac işletim sistemi hash'i çözmek için geliştiricinin certificate'ındaki public key'i kullanır. Ardından uygulamanın mevcut durumuna göre hash'i yeniden hesaplar ve bunu çözülmüş hash ile karşılaştırır. Hash'ler eşleşirse, **uygulamanın geliştirici tarafından imzalanmasından bu yana değiştirilmediği** anlamına gelir ve sistem uygulamanın çalışmasına izin verir.

Application signatures, Apple'ın Gatekeeper teknolojisinin önemli bir parçasıdır. Bir kullanıcı **internet üzerinden indirilmiş bir uygulamayı açmayı** denediğinde Gatekeeper application signature'ı doğrular. Uygulama Apple tarafından tanınan bir geliştiriciye verilmiş bir certificate ile imzalanmışsa ve code değiştirilmemişse Gatekeeper uygulamanın çalışmasına izin verir. Aksi takdirde uygulamayı engeller ve kullanıcıyı uyarır.

macOS Catalina'dan itibaren **Gatekeeper ayrıca uygulamanın Apple tarafından notarize edilip edilmediğini de kontrol eder** ve böylece ek bir güvenlik katmanı sağlar. Notarization süreci uygulamayı bilinen güvenlik sorunları ve kötü amaçlı code açısından kontrol eder. Bu kontroller başarılı olursa Apple, Gatekeeper'ın doğrulayabileceği bir ticket'ı uygulamaya ekler.

#### Check Signatures

Herhangi bir **malware sample** incelerken binary'nin **signature'ını** her zaman **kontrol etmelisiniz**; çünkü imzalayan **developer** daha önce **malware** ile **ilişkili** olabilir.
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

Apple'ın notarization süreci, kullanıcıları potansiyel olarak zararlı yazılımlardan korumak için ek bir güvenlik önlemi görevi görür. Bu süreç, **geliştiricinin uygulamasını inceleme için** **Apple's Notary Service**'e göndermesini içerir; bu hizmet App Review ile karıştırılmamalıdır. Bu hizmet, gönderilen yazılımı **kötü amaçlı içerik** ve code-signing ile ilgili olası sorunlar açısından inceleyen **otomatik bir sistemdir**.

Yazılım bu incelemeyi herhangi bir sorun oluşturmadan **geçerse**, Notary Service bir notarization ticket oluşturur. Geliştiricinin daha sonra bu **ticket'ı yazılımına eklemesi** gerekir; bu işlem 'stapling' olarak bilinir. Ayrıca notarization ticket, Gatekeeper'ın (Apple'ın güvenlik teknolojisi) erişebileceği şekilde çevrim içi olarak da yayımlanır.

Kullanıcının yazılımı ilk kez yüklemesi veya çalıştırması sırasında, notarization ticket'ın varlığı - ister executable'a stapled edilmiş ister çevrim içi bulunmuş olsun - **Gatekeeper'a yazılımın Apple tarafından notarization işleminden geçirildiğini bildirir**. Bunun sonucunda Gatekeeper, ilk çalıştırma iletişim kutusunda açıklayıcı bir mesaj görüntüler ve yazılımın Apple tarafından kötü amaçlı içerik açısından kontrol edildiğini belirtir. Böylece bu süreç, kullanıcıların sistemlerine yükledikleri veya çalıştırdıkları yazılımların güvenliğine duydukları güveni artırır.

### spctl & syspolicyd

> [!CAUTION]
> Sequoia sürümünden itibaren **`spctl`**'in Gatekeeper yapılandırmasını değiştirmeye artık izin vermediğini unutmayın.

**`spctl`**, Gatekeeper'ı (`syspolicyd` daemon'ı ile XPC mesajları üzerinden) listelemek ve onunla etkileşim kurmak için kullanılan CLI aracıdır. Örneğin, **GateKeeper**'ın **durumunu** şu şekilde görmek mümkündür:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> GateKeeper imza kontrollerinin her dosya için değil, yalnızca **Quarantine attribute** özelliğine sahip **files** için gerçekleştirildiğini unutmayın.

GateKeeper, **preferences & the signature** doğrultusunda bir **binary**'nin çalıştırılıp çalıştırılamayacağını kontrol eder:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`**, Gatekeeper'ı uygulamaktan sorumlu ana daemon'dur. `/var/db/SystemPolicy` konumunda bir database tutar ve [database'i destekleyen kodu burada](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp), [SQL template'ini ise burada](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) bulabilirsiniz. Database'in SIP tarafından kısıtlanmadığını ve root tarafından yazılabilir olduğunu unutmayın; ayrıca `/var/db/.SystemPolicy-default` database'i, diğeri bozulursa orijinal backup olarak kullanılır.

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
**`syspolicyd`** ayrıca `assess`, `update`, `record` ve `cancel` gibi farklı işlemlere sahip bir XPC sunucusu da sunar; bunlara **Security.framework'ün `SecAssessment*`** API'leri kullanılarak da erişilebilir ve **`spctl`** aslında XPC aracılığıyla **`syspolicyd`** ile iletişim kurar.

İlk kuralın "**App Store**", ikincisinin ise "**Developer ID**" ile bittiğine ve önceki görüntüde **App Store'dan ve kimliği doğrulanmış geliştiricilerden gelen uygulamaları çalıştırmanın etkin** olduğuna dikkat edin.\
Bu ayarı **App Store** olarak **değiştirirseniz**, "**Notarized Developer ID**" kuralları ortadan kalkar.

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

Önceki bilgileri şu komutla listeleyebilirsiniz:
```bash
sudo spctl --list
```
**`spctl`**'nin **`--master-disable`** ve **`--global-disable`** seçenekleri, bu imza kontrollerini tamamen **devre dışı bırakır**:
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

Bir App'in **GateKeeper tarafından çalıştırılmasına izin verilip verilmeyeceğini kontrol etmek** için:
```bash
spctl --assess -v /Applications/App.app
```
GateKeeper'a yeni kurallar ekleyerek belirli uygulamaların çalıştırılmasına izin vermek mümkündür:
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
Regarding **kernel extensions**, `/var/db/SystemPolicyConfiguration` klasörü, yüklenmesine izin verilen kext listelerini içeren dosyalar barındırır. Ayrıca `spctl`, yeni önceden onaylanmış kernel extensions ekleyebildiği için `com.apple.private.iokit.nvram-csr` entitlement'ına sahiptir; bu extensions'ların NVRAM'de `kext-allowed-teams` anahtarında da saklanması gerekir.

#### macOS 15 (Sequoia) ve sonraki sürümlerde Gatekeeper'ı yönetme

- Uzun süredir kullanılan Finder **Ctrl+Open / Sağ tıklama → Open** bypass yöntemi kaldırılmıştır; kullanıcıların, ilk engelleme iletişim kutusundan sonra engellenen bir uygulamaya **System Settings → Privacy & Security → Open Anyway** üzerinden açıkça izin vermesi gerekir.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` artık kabul edilmez; `spctl`, assessment ve label yönetimi için fiilen salt okunur durumdadır; policy enforcement ise UI veya MDM üzerinden yapılandırılır.

macOS 15 Sequoia'dan itibaren son kullanıcılar Gatekeeper policy'sini artık `spctl` üzerinden değiştiremez. Yönetim, System Settings üzerinden veya `com.apple.systempolicy.control` payload'ına sahip bir MDM configuration profile dağıtılarak gerçekleştirilir. App Store ve identified developers'a izin veren (ancak "Anywhere" seçeneğine izin vermeyen) örnek profil parçası:

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

Bir uygulama veya dosya **indirildiğinde**, web tarayıcıları veya e-posta istemcileri gibi belirli macOS **uygulamaları**, indirilen dosyaya genellikle "**quarantine flag**" olarak bilinen bir **genişletilmiş dosya özniteliği** ekler. Bu öznitelik, **dosyayı** güvenilmeyen bir kaynaktan (internet) geldiğini ve potansiyel riskler taşıyabileceğini belirtmek üzere **işaretleyen** bir güvenlik önlemidir. Ancak tüm uygulamalar bu özniteliği eklemez; örneğin yaygın BitTorrent istemci yazılımları genellikle bu işlemi atlar.

**Bir quarantine flag'in mevcut olması, kullanıcı dosyayı çalıştırmayı denediğinde macOS'un Gatekeeper güvenlik özelliğine sinyal gönderir**.

**Quarantine flag mevcut değilse** (bazı BitTorrent istemcileri aracılığıyla indirilen dosyalarda olduğu gibi), Gatekeeper'ın **kontrolleri gerçekleştirilmeyebilir**. Bu nedenle kullanıcılar, daha az güvenli veya bilinmeyen kaynaklardan indirilen dosyaları açarken dikkatli olmalıdır.

> [!NOTE] > Kod imzalarının **geçerliliğini** **kontrol etmek**, kodun ve içerdiği tüm kaynakların kriptografik **hash'lerini** oluşturmayı içeren **kaynak yoğun** bir işlemdir. Ayrıca sertifika geçerliliğinin kontrol edilmesi, sertifikanın yayımlandıktan sonra iptal edilip edilmediğini görmek için Apple sunucularına **çevrimiçi bir kontrol** yapılmasını gerektirir. Bu nedenlerle, her uygulama başlatıldığında tam bir kod imzası ve notarization kontrolü çalıştırmak **pratik değildir**.
>
> Bu nedenle bu kontroller **yalnızca quarantine özniteliğine sahip uygulamalar çalıştırılırken gerçekleştirilir.**

> [!WARNING]
> Bu öznitelik, dosyayı oluşturan/indiren uygulama tarafından **ayarlanmalıdır**.
>
> Ancak sandboxed dosyalar, oluşturdukları her dosyada bu özniteliğe sahip olur. Ayrıca non sandboxed uygulamalar bunu kendileri ayarlayabilir veya [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) anahtarını [**Info.plist**] içinde belirtebilir; bu da sistemin oluşturulan dosyalara `com.apple.quarantine` genişletilmiş özniteliğini ayarlamasını sağlar.

Ayrıca **`qtn_proc_apply_to_self`** çağrısını yapan bir işlem tarafından oluşturulan tüm dosyalar quarantined olur. Alternatif olarak **`qtn_file_apply_to_path`** API'si, belirtilen dosya yoluna quarantine özniteliğini ekler.

Durumunu **kontrol etmek ve etkinleştirmek/devre dışı bırakmak** (root gereklidir) mümkündür:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Ayrıca bir dosyanın **quarantine extended attribute** içerip içermediğini şu şekilde **öğrenebilirsiniz**:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**extended** **attributes** değerini kontrol edin ve quarantine attr'ını hangi app'in yazdığını bulun:
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
Aslında bir process, oluşturduğu dosyalara "quarantine flags" ayarlayabilir (oluşturulan bir dosyada USER_APPROVED flag'ini uygulamayı zaten denedim ancak uygulanmadı):

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

Ve bu attribute'u şu komutla kaldırın:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Ve tüm karantinaya alınmış dosyaları şu komutla bulun:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Karantina bilgileri, LaunchServices tarafından yönetilen ve **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** konumunda bulunan merkezi bir veritabanında da saklanır; bu sayede GUI dosyaların kaynakları hakkında veri elde edebilir. Ayrıca bu bilgiler, kaynaklarını gizlemekle ilgilenebilecek uygulamalar tarafından üzerine yazılabilir. Dahası, bu işlem LaunchServices API'leri kullanılarak gerçekleştirilebilir.

#### **libquarantine.dylib**

Bu library, extended attribute alanlarını değiştirmeye olanak tanıyan çeşitli işlevleri dışa aktarır.

`qtn_file_*` API'leri dosya karantina politikalarıyla ilgilenirken, `qtn_proc_*` API'leri process'lere uygulanır (process tarafından oluşturulan dosyalar). Dışa aktarılmayan `__qtn_syscall_quarantine*` işlevleri, politikaları uygulayan işlevlerdir; bu işlevler ilk argüman olarak "Quarantine" değerini alan `mac_syscall` çağrısını gerçekleştirir ve istekleri `Quarantine.kext`'e gönderir.

#### **Quarantine.kext**

Kernel extension yalnızca sistemdeki **kernel cache** üzerinden kullanılabilir; ancak **Kernel Debug Kit'i** [**https://developer.apple.com/**](https://developer.apple.com/) adresinden indirebilirsiniz. Bu kit, extension'ın symbolicated bir sürümünü içerir.

Bu Kext, tüm dosya yaşam döngüsü olaylarını yakalamak için MACF üzerinden çeşitli çağrıları hook'lar: oluşturma, açma, yeniden adlandırma, hard link oluşturma ve hatta `com.apple.quarantine` extended attribute'unun ayarlanmasını engellemek için `setxattr`.

Ayrıca birkaç MIB kullanır:

- `security.mac.qtn.sandbox_enforce`: Sandbox ile birlikte quarantine'ı zorunlu kılar
- `security.mac.qtn.user_approved_exec`: Querantine edilmiş proc'lar yalnızca onaylanmış dosyaları çalıştırabilir

#### Provenance xattr (Ventura ve sonrası)

macOS 13 Ventura, quarantine edilmiş bir uygulamanın çalışmasına ilk kez izin verildiğinde doldurulan ayrı bir provenance mekanizması sunmuştur.<sup>[[2]](#references)</sup> İki artefact oluşturulur:

- `.app` bundle directory üzerinde `com.apple.provenance` xattr'ı (primary key ve flag'leri içeren, sabit boyutlu binary değer).
- Uygulamanın cdhash ve metadata'sını `/var/db/SystemPolicyConfiguration/ExecPolicy/` konumundaki ExecPolicy veritabanının `provenance_tracking` tablosunda saklayan bir satır.

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

XProtect, macOS'ta yerleşik olarak bulunan bir **anti-malware** özelliğidir. XProtect, **herhangi bir uygulama ilk kez başlatıldığında veya değiştirildiğinde, uygulamayı bilinen malware'ler ve güvenli olmayan dosya türlerinden oluşan veritabanına karşı kontrol eder**. Safari, Mail veya Messages gibi belirli uygulamalar üzerinden bir dosya indirdiğinizde XProtect dosyayı otomatik olarak tarar. Veritabanındaki bilinen malware'lerden biriyle eşleşirse XProtect **dosyanın çalışmasını engeller** ve sizi tehdit hakkında uyarır.

XProtect veritabanı, yeni malware tanımlarıyla Apple tarafından **düzenli olarak güncellenir** ve bu güncellemeler Mac'inize otomatik olarak indirilip yüklenir. Bu, XProtect'in bilinen en son tehditlere karşı her zaman güncel olmasını sağlar.

Bununla birlikte, **XProtect'in tüm özelliklere sahip bir antivirus çözümü olmadığını** belirtmek gerekir. Yalnızca bilinen tehditlerden oluşan belirli bir listeyi kontrol eder ve çoğu antivirus yazılımı gibi on-access scanning gerçekleştirmez.

Çalıştırarak en son XProtect güncellemesi hakkında bilgi alabilirsiniz:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect, **/Library/Apple/System/Library/CoreServices/XProtect.bundle** konumunda, SIP tarafından korunan bir yerde bulunur ve bundle içinde XProtect'in kullandığı bilgileri bulabilirsiniz:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Bu cdhash'lere sahip code'un legacy entitlements kullanmasına izin verir.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleID ve TeamID aracılığıyla yüklenmesi engellenen veya minimum bir sürüm belirten plugin ve extension listesi.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Malware tespit etmek için Yara rules.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Engellenen application'ların hash'lerini ve TeamID'lerini içeren SQLite3 database.

**/Library/Apple/System/Library/CoreServices/XProtect.app** konumunda, XProtect ile ilgili olan ancak Gatekeeper process'ine dahil olmayan başka bir App bulunduğunu unutmayın.

> XProtect Remediator: Modern macOS'ta Apple, malware family'lerini tespit etmek ve remediate etmek için launchd aracılığıyla periyodik olarak çalışan on-demand scanner'lar (XProtect Remediator) sağlar. Bu scan'leri unified log'larda gözlemleyebilirsiniz:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeper Değil

> [!CAUTION]
> Gatekeeper'ın **bir application'ı her execute ettiğinizde çalıştırılmadığını** unutmayın; yalnızca _**AppleMobileFileIntegrity**_ tarafından, daha önce Gatekeeper ile execute edilmiş ve verify edilmiş bir app'i execute ettiğinizde **executable code signature'ları verify edilir**.

Bu nedenle, daha önce bir app'i Gatekeeper ile cache'lemek, ardından application'ın **executable olmayan file'larını** (Electron asar veya NIB file'ları gibi) **modify etmek** ve başka bir protection mevcut değilse application'ı **malicious** eklemelerle **execute etmek** mümkündü.

Ancak artık bu mümkün değildir; çünkü macOS, application bundle'ları içindeki file'ların **modify edilmesini engeller**. Bu nedenle [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack'ini denerseniz, app'i Gatekeeper ile cache'lemek için execute ettikten sonra bundle'ı modify edemeyeceğiniz için bunun artık abuse edilemediğini görürsünüz. Örneğin exploit'te belirtildiği gibi Contents directory'sinin adını NotCon olarak değiştirir ve ardından app'in main binary'sini Gatekeeper ile cache'lemek için execute ederseniz, bu bir error tetikler ve execute edilmez.

## Gatekeeper Bypasses

Gatekeeper'ı bypass etmenin herhangi bir yolu (kullanıcıya bir şey download ettirip Gatekeeper'ın bunu engellemesi gerekirken execute ettirmeyi başarmak), macOS'ta vulnerability olarak kabul edilir. Bunlar, geçmişte Gatekeeper'ı bypass etmeye izin veren technique'lere atanmış bazı CVE'lerdir:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Extraction için **Archive Utility** kullanıldığında, **886 karakteri aşan path'lere** sahip file'ların com.apple.quarantine extended attribute'ünü almadığı gözlemlenmiştir. Bu durum, söz konusu file'ların Gatekeeper'ın security check'lerini **bypass etmesine** istemeden izin verir.<sup>[[5]](#references)</sup>

Daha fazla bilgi için [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) sayfasını inceleyin.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Bir application **Automator** ile oluşturulduğunda, execute etmek için ihtiyaç duyduğu bilgiler executable içinde değil, `application.app/Contents/document.wflow` içinde bulunur. Executable, **Automator Application Stub** adı verilen generic bir Automator binary'sidir.

Bu nedenle `application.app/Contents/MacOS/Automator\ Application\ Stub`'ı **system içindeki başka bir Automator Application Stub'a symbolic link ile point edecek** şekilde ayarlayabilirsiniz ve bu, `document.wflow` (script'iniz) içinde bulunan şeyi **Gatekeeper'ı tetiklemeden** execute eder; çünkü actual executable quarantine xattr'üne sahip değildir.<sup>[[6]](#references)</sup>

Beklenen location'a bir örnek: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Daha fazla bilgi için [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) sayfasını inceleyin.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Bu bypass'te, `application.app` yerine `application.app/Contents` üzerinden compression işlemine başlayan bir zip file oluşturulmuştur. Bu nedenle **quarantine attr**, **`application.app/Contents` içindeki tüm file'lara** uygulanmış, ancak Gatekeeper'ın kontrol ettiği **`application.app`'e** uygulanmamıştır; dolayısıyla `application.app` tetiklendiğinde **quarantine attribute'üne sahip olmadığı** için Gatekeeper bypass edilmiştir.<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Daha fazla bilgi için [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) sayfasına göz atın.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Bileşenler farklı olsa da bu vulnerability'nin exploitation yöntemi öncekiyle oldukça benzerdir. Bu durumda **`application.app/Contents`** üzerinden bir Apple Archive oluşturacağız; böylece **`application.app`**, **Archive Utility** tarafından decompressed edildiğinde quarantine attr almayacaktır.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Daha fazla bilgi için [**orijinal rapora**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) göz atın.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

**`writeextattr`** ACL'si, herhangi bir kişinin bir dosyadaki özniteliğe yazmasını engellemek için kullanılabilir:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Ayrıca **AppleDouble** dosya formatı, bir dosyayı ACE'leriyle birlikte kopyalar.<sup>[[9]](#references)</sup>

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) içinde, **`com.apple.acl.text`** adlı xattr içinde depolanan ACL metin gösteriminin, decompressed file üzerinde ACL olarak ayarlanacağını görmek mümkündür. Dolayısıyla, bir uygulamayı kendisine başka xattr'ların yazılmasını engelleyen bir ACL ile **AppleDouble** dosya formatını kullanarak bir zip file içine sıkıştırırsanız... quarantine xattr uygulamaya ayarlanmaz:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Daha fazla bilgi için [**orijinal rapora**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) göz atın.

Bunun AppleArchives ile de exploit edilebileceğini unutmayın:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Bazı macOS dahili sorunları nedeniyle **Google Chrome'un indirilen dosyalara quarantine attribute'ünü ayarlamadığı** keşfedildi.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble file format'ları, bir dosyanın attribute'lerini `._` ile başlayan ayrı bir dosyada depolar; bu, dosya attribute'lerinin **macOS makineleri arasında** kopyalanmasına yardımcı olur. Ancak bir AppleDouble file decompress edildikten sonra `._` ile başlayan dosyaya **quarantine attribute'ünün verilmediği** fark edildi.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Karantina özniteliğinin ayarlanmayacağı bir dosya oluşturulabildiği için **Gatekeeper'ı atlamak mümkündü.** Bunun için AppleDouble adlandırma kuralını kullanarak (adını `._` ile başlatarak) bir **DMG file application** oluşturmak ve bu gizli dosyaya, karantina özniteliği olmayan bir sembolik bağlantı olarak **görünür bir dosya** oluşturmak yeterliydi.\
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

macOS Sonoma 14.0'da düzeltilen bir Gatekeeper bypass'ı, özel olarak hazırlanmış uygulamaların herhangi bir uyarı gösterilmeden çalışmasına izin veriyordu. Ayrıntılar, yama yayımlandıktan sonra kamuya açıklandı ve sorun düzeltilmeden önce gerçek saldırılarda aktif olarak kullanıldı. Sonoma 14.0 veya daha yeni bir sürümün yüklü olduğundan emin olun.

### [CVE-2024-27853]

Mart 2024'te yayımlanan macOS 14.4'teki bir Gatekeeper bypass'ı, `libarchive` tarafından kötü amaçlı ZIP dosyalarının işlenmesinden kaynaklanıyor ve uygulamaların değerlendirmeden kaçmasına izin veriyordu. Apple'ın sorunu giderdiği 14.4 veya daha yeni bir sürüme güncelleyin.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

İndirilen bir uygulamaya gömülü bir **Automator Quick Action workflow**, Gatekeeper değerlendirmesi olmadan tetiklenebiliyordu; bunun nedeni workflow'ların veri olarak kabul edilmesi ve normal notarization uyarısı yolunun dışında Automator yardımcısı tarafından çalıştırılmasıydı. Bu nedenle, shell script çalıştıran bir Quick Action içeren hazırlanmış bir `.app` (örneğin `Contents/PlugIns/*.workflow/Contents/document.wflow` içinde), başlatılır başlatılmaz çalışabiliyordu. Apple, Ventura **13.7**, Sonoma **14.7** ve Sequoia **15** sürümlerinde ek bir onay iletişim kutusu ekledi ve değerlendirme yolunu düzeltti.<sup>[[3]](#references)</sup>

### Üçüncü taraf unarchiver'ların quarantine bilgisini hatalı aktarması (2023–2024)

Popüler extraction araçlarındaki (ör. The Unarchiver) çeşitli güvenlik açıkları, arşivlerden çıkarılan dosyaların `com.apple.quarantine` xattr bilgisini taşımamasına neden olarak Gatekeeper bypass fırsatları oluşturdu. Test sırasında her zaman macOS Archive Utility'ye veya yamalanmış araçlara güvenin ve extraction sonrasında xattr bilgilerini doğrulayın.

### uchg (bu [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)'tan)

- Bir uygulama içeren bir dizin oluşturun.
- Uygulamaya uchg ekleyin.
- Uygulamayı bir tar.gz dosyasına sıkıştırın.
- tar.gz dosyasını bir kurbana gönderin.
- Kurban tar.gz dosyasını açar ve uygulamayı çalıştırır.
- Gatekeeper uygulamayı kontrol etmez.<sup>[[12]](#references)</sup>

### Quarantine xattr'ını Önleme

Bir ".app" bundle'ına quarantine xattr eklenmezse, çalıştırıldığında **Gatekeeper tetiklenmez**.


## Referanslar

- [1] [Apple Platform Security: macOS Sonoma 14.4'ün güvenlik içeriği hakkında (CVE-2024-27853 dahildir)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: macOS artık uygulamaların kökenini nasıl takip ediyor](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: macOS Sonoma 14.7 / Ventura 13.7'nin güvenlik içeriği hakkında (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia, Control‑click “Open” Gatekeeper bypass'ını kaldırıyor](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: CVE-2021-1810'un keşfi](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, macOS Gatekeeper bypass](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs, Gatekeeper bypass'a izin veren Safari güvenlik açığını tespit etti](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs, Gatekeeper bypass'a izin veren macOS Archive Utility güvenlik açığını tespit etti (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper'ın Aşil topuğu: Bir macOS güvenlik açığının ortaya çıkarılması](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Bir Gatekeeper bypass'ının keşfi (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Mac Monitor yardımıyla bir Gatekeeper bypass exploit'inin bulunması ve bildirilmesi](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: macOS Security and Privacy Mechanisms bypass — Gatekeeper'dan System Integrity Protection'a (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)

{{#include ../../../banners/hacktricks-training.md}}
