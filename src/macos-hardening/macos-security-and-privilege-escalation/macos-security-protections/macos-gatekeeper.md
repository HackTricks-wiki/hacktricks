# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper**, Mac işletim sistemleri için geliştirilmiş bir güvenlik özelliğidir ve kullanıcıların sistemlerinde **sadece güvenilir yazılımları çalıştırmasını** sağlamaya yöneliktir. Kullanıcının **App Store dışındaki kaynaklardan** indirdiği ve açmaya çalıştığı uygulama, eklenti veya kurulum paketleri gibi yazılımları **doğrulayarak** çalışır.

Gatekeeper'ın temel mekanizması doğrulama sürecidir. İndirilen yazılımın **tanınmış bir geliştirici tarafından imzalanıp imzalanmadığını** kontrol eder ve yazılımın gerçekliğini teyit eder. Ayrıca yazılımın **Apple tarafından notarize edilmiş** olup olmadığını kontrol ederek, bilinen kötü amaçlı içerik barındırmadığını ve notarize işleminden sonra değiştirilmediğini doğrular.

Buna ek olarak, Gatekeeper indirilen yazılımların ilk açılışında kullanıcıdan onay isteyerek kullanıcı kontrolünü ve güvenliği güçlendirir. Bu koruma, kullanıcıların zararsız bir veri dosyası zannettikleri potansiyel olarak zararlı yürütülebilir kodu yanlışlıkla çalıştırmasını önlemeye yardımcı olur.

### Application Signatures

Uygulama imzaları, diğer adıyla kod imzaları, Apple’ın güvenlik altyapısının kritik bir bileşenidir. Bunlar, yazılım yazarının (geliştiricinin) kimliğini doğrulamak ve kodun en son imzalandığı tarihten bu yana değiştirilmediğini garanti etmek için kullanılır.

İşleyişi şu şekildedir:

1. **Signing the Application:** Geliştirici uygulamayı dağıtmaya hazır olduğunda, uygulamayı **özel bir anahtar kullanarak imzalar**. Bu özel anahtar, geliştirici Apple Developer Programına kaydolduğunda Apple tarafından verilen bir sertifika ile ilişkilidir. İmzalama işlemi, uygulamanın tüm parçalarının kriptografik bir özetinin oluşturulmasını ve bu özetin geliştiricinin özel anahtarıyla şifrelenmesini içerir.
2. **Distributing the Application:** İmzalanmış uygulama, geliştiricinin sertifikasıyla birlikte kullanıcılara dağıtılır; bu sertifika ilgili açık anahtarı içerir.
3. **Verifying the Application:** Kullanıcı uygulamayı indirip çalıştırmaya çalıştığında, macOS işletim sistemi geliştiricinin sertifikasındaki açık anahtarı kullanarak özetin şifresini çözer. Ardından uygulamanın mevcut durumu temelinde özet yeniden hesaplanır ve çözülen özetle karşılaştırılır. Eşleşirlerse, **uygulamanın geliştirici tarafından imzalandığı tarihten bu yana değiştirilmediği** anlamına gelir ve sistem uygulamanın çalışmasına izin verir.

Uygulama imzaları, Gatekeeper teknolojisinin temel parçalarındandır. Kullanıcı internetten indirilen bir uygulamayı **açmaya çalıştığında**, Gatekeeper uygulama imzasını doğrular. Eğer uygulama Apple tarafından bilinen bir geliştiriciye verilen bir sertifika ile imzalanmışsa ve kodunda değişiklik yoksa, Gatekeeper uygulamanın çalışmasına izin verir. Aksi takdirde uygulamayı engeller ve kullanıcıyı uyarır.

macOS Catalina’dan itibaren, **Gatekeeper ayrıca uygulamanın Apple tarafından notarize edilip edilmediğini de kontrol eder**, böylece ek bir güvenlik katmanı sağlar. Notarization süreci uygulamayı bilinen güvenlik sorunları ve kötü amaçlı kod açısından tarar; eğer bu kontroller geçilirse Apple uygulamaya Gatekeeper tarafından doğrulanabilecek bir bilet ekler.

#### Check Signatures

Bazı **malware sample** incelerken her zaman ikili dosyanın **imzasını kontrol etmelisiniz**, çünkü onu imzalayan **geliştirici** zaten **malware** ile ilişkili olabilir.
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
### Notarizasyon

Apple'ın notarizasyon süreci, kullanıcıları potansiyel olarak zararlı yazılımlardan korumaya yönelik ek bir güvenlik katmanı sağlar. Bu süreç, **geliştiricinin uygulamasını inceleme için Apple'ın Notary Service'ine göndermesini** içerir; bu, App Review ile karıştırılmamalıdır. Bu servis, gönderilen yazılımı **otomatik bir sistem** olarak **zararlı içerik** ve kod imzalama ile ilgili olası sorunlar açısından denetler.

Eğer yazılım bu incelemeyi herhangi bir sorun olmadan **geçerse**, Notary Service bir notarization ticket üretir. Geliştirici daha sonra bu bileti yazılımına **eklemek** zorundadır; bu işleme 'stapling' denir. Ayrıca, notarization bileti çevrimiçi olarak yayımlanır ve Gatekeeper, Apple'ın güvenlik teknolojisi, bu bilete erişebilir.

Kullanıcının yazılımı ilk kez yüklemesi veya çalıştırması sırasında, notarization biletinin varlığı — ister yürütülebilir dosyaya 'staple' edilmiş olsun, ister çevrimiçi bulunuyor olsun — **Gatekeeper'a yazılımın Apple tarafından notarize edildiğini bildirir**. Bunun sonucunda, Gatekeeper ilk başlatma iletişim kutusunda yazılımın Apple tarafından zararlı içerik açısından kontrol edildiğini belirten açıklayıcı bir mesaj gösterir. Bu süreç, kullanıcıların sistemlerine yükledikleri veya çalıştırdıkları yazılımın güvenliğine dair güvenini artırır.

### spctl & syspolicyd

> [!CAUTION]
> Sequoia sürümünden itibaren, **`spctl`** Gatekeeper yapılandırmasını değiştirmeye artık izin vermez.

**`spctl`** Gatekeeper'ı (XPC mesajları aracılığıyla `syspolicyd` daemon ile) listelemek ve onunla etkileşimde bulunmak için kullanılan CLI aracıdır. Örneğin, GateKeeper'ın **durumunu** şu şekilde görmek mümkündür:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> GateKeeper imza kontrollerinin sadece **Quarantine attribute**'üne sahip dosyalara uygulandığını, tüm dosyalara uygulanmadığını unutmayın.

GateKeeper, **tercihler & imza**'ya göre bir binary'nin çalıştırılıp çalıştırılamayacağını kontrol eder:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** GateKeeper'ı uygulamaktan sorumlu ana daemon'dur. `/var/db/SystemPolicy` konumunda bir veritabanı tutar ve veritabanını destekleyen kodu [database here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) ve [SQL template here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) adreslerinde bulabilirsiniz. Veritabanının SIP tarafından kısıtlanmadığını ve root tarafından yazılabilir olduğunu; ayrıca diğer veritabanı bozulursa orijinal yedek olarak `/var/db/.SystemPolicy-default` veritabanının kullanıldığını unutmayın.

Ayrıca **`/var/db/gke.bundle`** ve **`/var/db/gkopaque.bundle`** paketleri, veritabanına eklenen kuralları içeren dosyalar barındırır. Bu veritabanını root olarak şu şekilde kontrol edebilirsiniz:
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
**`syspolicyd`** ayrıca `assess`, `update`, `record` ve `cancel` gibi farklı operasyonlara sahip bir XPC sunucusu açığa çıkarır; bunlara **`Security.framework`'s `SecAssessment*`** API'leri aracılığıyla da erişilebilir ve **`spctl`** aslında XPC üzerinden **`syspolicyd`** ile iletişim kurar.

İlk kuralın "**App Store**" ile bittiğine ve ikincisinin "**Developer ID**" ile bittiğine dikkat edin ve önceki görüntüde **App Store ve tanımlanmış geliştiricilerden gelen uygulamaları çalıştırmaya izin verildiği** gösteriliyordu.\ Eğer bu ayarı App Store olarak **değiştirirseniz**, "**Notarized Developer ID" kuralları kaybolacaktır**.

Ayrıca **type GKE** türünde binlerce kural da vardır :
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Bunlar aşağıdaki dosyalardan alınan hashes:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Veya önceki bilgileri şu komutla listeleyebilirsiniz:
```bash
sudo spctl --list
```
**`spctl`**'in **`--master-disable`** ve **`--global-disable`** seçenekleri bu imza kontrollerini tamamen **devre dışı bırakır:**
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Tamamen etkinleştirildiğinde, yeni bir seçenek görünecektir:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

**GateKeeper tarafından bir App'e izin verilip verilmeyeceğini kontrol etmek** mümkündür:
```bash
spctl --assess -v /Applications/App.app
```
GateKeeper'a belirli uygulamaların çalıştırılmasına izin vermek için yeni kurallar eklemek mümkündür:
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
Regarding **çekirdek uzantıları**, the folder `/var/db/SystemPolicyConfiguration` contains files with lists of kexts allowed to be loaded. Moreover, `spctl` has the entitlement `com.apple.private.iokit.nvram-csr` because it's capable of adding new pre-approved kernel extensions which need to be saved also in NVRAM in a `kext-allowed-teams` key.

#### macOS 15 (Sequoia) ve sonrası için Gatekeeper Yönetimi

- Uzun süredir kullanılan Finder **Ctrl+Open / Right‑click → Open** atlatması kaldırıldı; kullanıcılar ilk engelleme iletişim kutusundan sonra engellenen bir uygulamayı **System Settings → Privacy & Security → Open Anyway** üzerinden açıkça izin vermelidir.
- `spctl --master-disable/--global-disable` artık kabul edilmiyor; `spctl` değerlendirme ve etiket yönetimi için fiilen salt okunurdur ve politika uygulaması UI veya MDM aracılığıyla yapılandırılır.

macOS 15 Sequoia'dan itibaren son kullanıcılar `spctl` üzerinden Gatekeeper politikasını değiştiremez. Yönetim, System Settings üzerinden veya `com.apple.systempolicy.control` payload'ına sahip bir MDM yapılandırma profili dağıtılarak yapılır. App Store ve identified developers'a izin vermek için (ancak "Anywhere" için değil) örnek profil kesiti:

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

### Karantina Dosyaları

Bir uygulama veya dosya **indirildiğinde**, web tarayıcıları veya e‑posta istemcileri gibi belirli macOS **uygulamaları**, indirilen dosyaya genellikle "**quarantine flag**" olarak bilinen bir genişletilmiş dosya özniteliği **ekler**. Bu öznitelik, dosyanın güvenilmeyen bir kaynaktan (internet) geldiğini ve potansiyel risk taşıyabileceğini **işaretlemek** için bir güvenlik önlemidir. Ancak, tüm uygulamalar bu özniteliği eklemez; örneğin yaygın BitTorrent istemci yazılımları genellikle bu süreci atlar.

**Bir quarantine flag'in varlığı, kullanıcı dosyayı çalıştırmayı denediğinde macOS'un Gatekeeper güvenlik özelliğini tetikler.**

Eğer **quarantine flag mevcut değilse** (bazı BitTorrent istemcileriyle indirilen dosyalarda olduğu gibi), Gatekeeper'in **kontrolleri yapılmayabilir**. Bu nedenle, daha az güvenli veya bilinmeyen kaynaklardan indirilen dosyaları açarken kullanıcıların dikkatli olması gerekir.

> [!NOTE] > **Kod imzalarının geçerliliğini kontrol etmek**, kodun ve paketlenmiş tüm kaynaklarının kriptografik **hash'lerini** oluşturmayı içeren **kaynak yoğun** bir işlemdir. Ayrıca, sertifika geçerliliğini kontrol etmek, sertifikanın verildikten sonra iptal edilip edilmediğini görmek için Apple sunucularına yapılan bir **çevrimiçi kontrol** gerektirir. Bu nedenlerle, tam bir code signature ve notarization kontrolünü her uygulama başlatıldığında çalıştırmak **pratik değildir**.
>
> Bu yüzden, bu kontroller **sadece karantinelenmiş özniteliğe sahip uygulamalar çalıştırıldığında yapılır.**

> [!WARNING]
> Bu öznitelik, dosyayı oluşturan/indiren **uygulama tarafından ayarlanmalıdır.**
>
> Ancak, sandbox'lanmış uygulamaların oluşturduğu tüm dosyalara bu öznitelik otomatik olarak eklenir. Sandbox'lanmamış uygulamalar ise bunu kendileri ayarlayabilirler veya sistemin oluşturulan dosyalara `com.apple.quarantine` genişletilmiş özniteliğini eklemesini sağlamak için **Info.plist** içinde [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) anahtarını belirtebilirler.

Ayrıca, **`qtn_proc_apply_to_self`** çağıran bir süreç tarafından oluşturulan tüm dosyalar karantinaya alınır. Veya **`qtn_file_apply_to_path`** API'si belirtilen bir dosya yoluna karantina özniteliği ekler.

Durumunu **kontrol etmek ve etkinleştirmek/devre dışı bırakmak** (root gerekli) şununla mümkündür:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Ayrıca **bir dosyanın quarantine genişletilmiş özniteliğine sahip olup olmadığını** şu komutla bulabilirsiniz:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**Genişletilmiş** **özniteliklerin** **değerini** kontrol edin ve quarantine özniteliğini hangi uygulamanın yazdığını şu komutla bulun:
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
Gerçekte bir işlem oluşturduğu dosyalara karantina bayrakları ayarlayabilir (zaten oluşturduğum bir dosyada USER_APPROVED bayrağını uygulamayı denedim ama uygulanmıyor):

<details>

<summary>Kaynak Kod: karantina bayraklarını uygulama</summary>
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

Ve o özniteliği **kaldırın**:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Ve karantinaya alınmış tüm dosyaları şu komutla bulun:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Karantina bilgileri ayrıca GUI'nin dosya kökeni hakkında veri almasını sağlayan, LaunchServices tarafından yönetilen merkezi bir veritabanında **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** içinde saklanır. Ek olarak, kökenini gizlemek isteyen uygulamalar tarafından bu kayıtlar üzerine yazılabilir. Bu işlem LaunchServices APIS üzerinden de yapılabilir.

#### **libquarantine.dylib**

Bu kütüphane extended attribute alanlarını manipüle etmeye izin veren birkaç fonksiyon export eder.

`qtn_file_*` API'leri dosya karantina politikaları ile ilgilenir, `qtn_proc_*` API'leri ise process'lere uygulanır (process tarafından oluşturulan dosyalar). Export edilmeyen `__qtn_syscall_quarantine*` fonksiyonları politikaları uygulayanlardır; bu fonksiyonlar istekleri `Quarantine.kext`'e gönderen ilk argüman olarak "Quarantine" ile `mac_syscall`'u çağırır.

#### **Quarantine.kext**

Kernel uzantısı yalnızca sistemdeki kernel cache üzerinden erişilebilir; ancak, [**https://developer.apple.com/**](https://developer.apple.com/)'den **Kernel Debug Kit**'i indirerek eklentinin symbolicated bir versiyonunu elde edebilirsiniz.

Bu Kext, tüm dosya yaşam döngüsü olaylarını yakalamak için MACF üzerinden çeşitli çağrıları hook'lar: oluşturma, açma, yeniden adlandırma, hard-link oluşturma... hatta `setxattr`'ı bile, `com.apple.quarantine` extended attribute'ünün ayarlanmasını engellemek için.

Ayrıca birkaç MIB kullanır:

- `security.mac.qtn.sandbox_enforce`: Sandbox ile birlikte karantinanın uygulanmasını zorlar
- `security.mac.qtn.user_approved_exec`: Karantinadaki procs yalnızca onaylanmış dosyaları çalıştırabilir

#### Provenance xattr (Ventura ve sonrası)

macOS 13 Ventura, karantinaya alınmış bir uygulamanın ilk kez çalışmasına izin verildiğinde doldurulan ayrı bir provenance mekanizması getirdi. İki artefakt oluşturulur:

- `.app` bundle dizinindeki `com.apple.provenance` xattr (birincil anahtar ve flag'ler içeren sabit boyutlu ikili değer).
- `/var/db/SystemPolicyConfiguration/ExecPolicy/` içindeki ExecPolicy veritabanında `provenance_tracking` tablosuna eklenen bir satır; uygulamanın cdhash ve metadata'sını saklar.

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

XProtect, macOS'ta yerleşik bir **anti-malware** özelliğidir. XProtect, bilinen malware ve güvensiz dosya türlerinin bulunduğu veritabanına karşı **herhangi bir uygulamayı ilk çalıştırıldığında veya değiştirildiğinde kontrol eder**. Safari, Mail veya Messages gibi belirli uygulamalar aracılığıyla bir dosya indirdiğinizde, XProtect dosyayı otomatik olarak tarar. Eğer veritabanındaki herhangi bir bilinen malware ile eşleşirse, XProtect dosyanın **çalıştırulmasını engeller** ve tehdidi size bildirir.

XProtect veritabanı, Apple tarafından yeni malware tanımlarıyla **düzenli olarak güncellenir**, ve bu güncellemeler Mac'inize otomatik olarak indirilip kurulur. Bu, XProtect'in her zaman bilinen en son tehditlerle güncel kalmasını sağlar.

Ancak belirtmek gerekir ki **XProtect tam özellikli bir antivirus çözümü değildir**. Sadece belirli bir bilinen tehdit listesi için kontrol yapar ve çoğu antivirus yazılımı gibi on-access scanning gerçekleştirmez.

En son XProtect güncellemesi hakkında bilgiyi almak için şu komutu çalıştırabilirsiniz:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect, SIP tarafından korunan şu konumda bulunur: **/Library/Apple/System/Library/CoreServices/XProtect.bundle** ve bundle içinde XProtect'in kullandığı bilgileri bulabilirsiniz:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Bu cdhash'lere sahip kodların legacy entitlements kullanmasına izin verir.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleID ve TeamID ile yüklenmesi engellenen eklentiler ve eklentilerin asgari sürümlerini listeler.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: malware tespit etmek için Yara kuralları.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Engellenmiş uygulamaların hash'leri ve TeamID'leri içeren SQLite3 veritabanı.

XProtect ile ilgili ancak Gatekeeper süreciyle doğrudan ilişkili olmayan başka bir App'in de bulunduğunu unutmayın: **`/Library/Apple/System/Library/CoreServices/XProtect.app`**.

> XProtect Remediator: Modern macOS'ta Apple, belirli malware ailelerini algılayıp düzeltmek için launchd aracılığıyla periyodik olarak çalışan isteğe bağlı tarayıcılar (XProtect Remediator) sağlar. Bu taramaları unified log'larda gözlemleyebilirsiniz:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Not Gatekeeper

> [!CAUTION]
> Gatekeeper'in her uygulama çalıştırıldığında çalıştırılmadığını unutmayın; yalnızca _**AppleMobileFileIntegrity**_ (AMFI), daha önce Gatekeeper tarafından çalıştırılmış ve doğrulanmış bir uygulamayı çalıştırdığınızda **yürütülebilir kod imzalarını doğrular**.

Bu yüzden daha önce bir uygulamayı Gatekeeper ile önbelleğe almak için çalıştırmak, ardından uygulamanın yürütülebilir olmayan dosyalarını (ör. Electron asar veya NIB dosyaları) değiştirmek mümkün ve başka bir koruma yoksa uygulama bu kötü amaçlı eklemelerle **çalıştırılabiliyordu**.

Ancak artık bu mümkün değil çünkü macOS uygulama bundle'larının içindeki dosyaların **değiştirilmesini engelliyor**. Yani [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) saldırısını denerseniz, artık suistimal edilemediğini görürsünüz; çünkü uygulamayı Gatekeeper ile önbelleğe almak için çalıştırdıktan sonra bundle'ı değiştiremezsiniz. Örneğin exploit'te belirtildiği gibi Contents dizininin adını NotCon olarak değiştirir ve sonra uygulamanın ana ikili dosyasını Gatekeeper ile önbelleğe almak için çalıştırırsanız, hata tetiklenir ve uygulama çalışmaz.

## Gatekeeper Bypasses

Gatekeeper'ı atlatmanın herhangi bir yolu (kullanıcının bir şeyi indirmesini ve Gatekeeper'ın engellemesi gerekirken çalıştırmasını sağlamak) macOS'ta bir güvenlik açığı olarak değerlendirilir. Geçmişte Gatekeeper'ı atlamaya izin veren tekniklere atanan bazı CVE'ler şunlardır:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Archive Utility ile çıkarma yapıldığında, **886 karakteri aşan yolları olan** dosyaların com.apple.quarantine genişletilmiş özniteliği almadığı gözlemlendi. Bu durum, bu dosyaların istemeden Gatekeeper'ın güvenlik kontrollerini **aşmasına** izin veriyor.

Daha fazla bilgi için [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)'a bakın.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Bir uygulama **Automator** ile oluşturulduğunda, çalıştırmak için gereken bilgiler `application.app/Contents/document.wflow` içinde olur; yürütülebilir dosya içinde değil. Yürütülebilir dosya sadece **Automator Application Stub** adında genel bir Automator ikilisidir.

Bu nedenle, `application.app/Contents/MacOS/Automator\ Application\ Stub` dosyasını sistem içindeki başka bir Automator Application Stub'a sembolik link ile işaret edecek şekilde ayarlayabilir ve `document.wflow` içindekileri (sizin script'inizi) **Gatekeeper tetiklenmeden** çalıştırabilirsiniz; çünkü gerçek yürütülebilir dosya quarantine xattr'ına sahip değildir.

Beklenen örnek konum: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Daha fazla bilgi için [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper)'a bakın.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Bu bypass'ta bir zip dosyası, uygulamayı `application.app/Contents` içinden sıkıştırmaya başlayacak şekilde oluşturuldu. Bu durumda **quarantine attr** `application.app/Contents` içindeki tüm dosyalara uygulanıyordu fakat Gatekeeper'ın kontrol ettiği `application.app`'e uygulanmamıştı; dolayısıyla `application.app` tetiklendiğinde **karantina özniteliği yoktu** ve Gatekeeper atlanmış oldu.
```bash
zip -r test.app/Contents test.zip
```
Daha fazla bilgi için [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) adresini inceleyin.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Bileşenler farklı olsa da, bu güvenlik açığının istismarı bir öncekine çok benzerdir. Bu durumda **`application.app/Contents`**'ten bir Apple Archive oluşturulur; bu nedenle **`application.app` won't get the quarantine attr**, **Archive Utility** tarafından açıldığında.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Daha fazla bilgi için [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) adresini kontrol edin.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** bir dosyaya kimsenin öznitelik yazmasını engellemek için kullanılabilir:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Ayrıca, **AppleDouble** dosya formatı bir dosyayı ACEs dahil kopyalar.

In the [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) it's possible to see that the ACL text representation stored inside the xattr called **`com.apple.acl.text`** is going to be set as ACL in the decompressed file. So, if you compressed an application into a zip file with **AppleDouble** file format with an ACL that prevents other xattrs to be written to it... the quarantine xattr wasn't set into de application:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Daha fazla bilgi için [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) adresini inceleyin.

Bunun ayrıca AppleArchives ile de istismar edilebileceğini unutmayın:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Bazı macOS dahili problemleri nedeniyle **Google Chrome'un indirilen dosyalara karantina özniteliğini atamadığı** keşfedildi.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble dosya formatları bir dosyanın özniteliklerini `._` ile başlayan ayrı bir dosyada saklar; bu, dosya özniteliklerini **macOS makineleri arasında** kopyalamaya yardımcı olur. Ancak, bir AppleDouble dosyası açıldıktan sonra `._` ile başlayan dosyaya **karantina özniteliği verilmediği** fark edildi.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Quarantine attribute ayarlı olmayan bir dosya oluşturabilmek, **Gatekeeper'ı bypass etmek** mümkündü. Hile, AppleDouble name convention'ı kullanarak (başına `._` koyarak) **bir DMG file application oluşturmak** ve quarantine attribute'u olmayan bu gizli dosyaya işaret eden **görünür bir dosyayı sym link olarak oluşturmak**ti.\
**DMG file çalıştırıldığında**, quarantine attribute'u olmadığı için **Gatekeeper'ı bypass edecekti**.
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

macOS Sonoma 14.0'te düzeltlen bir Gatekeeper atlatması, istekte bulunmadan özel hazırlanmış uygulamaların çalışmasına izin veriyordu. Yama sonrası ayrıntılar kamuya açıklandı ve sorun düzeltilmeden önce aktif olarak kötü amaçla kullanıldı. Sonoma 14.0 veya daha yeni bir sürümün yüklü olduğundan emin olun.

### [CVE-2024-27853]

Mart 2024'te yayımlanan macOS 14.4'te `libarchive`'in kötü amaçlı ZIP'leri işlemesinden kaynaklanan bir Gatekeeper atlatması, uygulamaların değerlendirmeden kaçmasına izin veriyordu. Apple'ın sorunu giderdiği 14.4 veya daha yeni sürüme güncelleyin.

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

İndirilen bir uygulamaya gömülü bir **Automator Quick Action workflow**, workflow'lar veri olarak muamele edildiği ve Automator yardımcı programı tarafından normal notarization prompt path'in dışında yürütüldüğü için Gatekeeper değerlendirmesi olmadan tetiklenebiliyordu. Bir shell script çalıştıran bir Quick Action içeren özel hazırlanmış bir `.app` (ör. `Contents/PlugIns/*.workflow/Contents/document.wflow` içinde) bu nedenle başlatıldığında hemen çalıştırılabilirdi. Apple ek bir onay iletişim kutusu ekledi ve değerlendirme yolunu Ventura **13.7**, Sonoma **14.7** ve Sequoia **15**'te düzeltti.

### Third‑party unarchivers mis‑propagating quarantine (2023–2024)

Popüler çıkarma araçlarındaki birkaç zafiyet (ör. The Unarchiver), arşivlerden çıkarılan dosyaların `com.apple.quarantine` xattr'ını kaçırmasına neden oldu ve bu da Gatekeeper atlatma imkanları sağladı. Test yaparken her zaman macOS Archive Utility veya yamalanmış araçlara güvenin ve çıkarma sonrası xattr'ları doğrulayın.

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Create a directory containing an app.
- Add uchg to the app.
- Compress the app to a tar.gz file.
- Send the tar.gz file to a victim.
- The victim opens the tar.gz file and runs the app.
- Gatekeeper does not check the app.

### Prevent Quarantine xattr

Bir ".app" bundle'ında quarantine xattr eklenmemişse, çalıştırıldığında **Gatekeeper tetiklenmez**.


## References

- Apple Platform Security: About the security content of macOS Sonoma 14.4 (includes CVE-2024-27853) – [https://support.apple.com/en-us/HT214084](https://support.apple.com/en-us/HT214084)
- Eclectic Light: How macOS now tracks the provenance of apps – [https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- Apple: About the security content of macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128) – [https://support.apple.com/en-us/121234](https://support.apple.com/en-us/121234)
- MacRumors: macOS 15 Sequoia removes the Control‑click “Open” Gatekeeper bypass – [https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)

{{#include ../../../banners/hacktricks-training.md}}
