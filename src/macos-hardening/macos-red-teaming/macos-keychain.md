# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), uygulama parolaları, internet parolaları, kullanıcı tarafından oluşturulan sertifikalar, ağ parolaları ve kullanıcı tarafından oluşturulan açık/özel anahtarlar gibi **kullanıcıya özgü kimlik bilgilerini** depolamak için kullanılır.
- **System Keychain** (`/Library/Keychains/System.keychain`), WiFi parolaları, sistem kök sertifikaları, sistem özel anahtarları ve sistem uygulama parolaları gibi **sistem genelindeki kimlik bilgilerini** depolar.<sup>[[1]](#references)</sup>
  - `/System/Library/Keychains/*` altında sertifikalar gibi başka bileşenler bulunabilir.
- Kullanıcı başına **data protection keychain**, Keychain Access'te **Local Items** veya **iCloud** olarak görünür. `login.keychain-db` dosyasından ayrıdır ve yalnızca yerel olan ve eşzamanlanabilir öğeleri içerir; `security` öncelikle dosya tabanlı keychain'ler için kullanılan bir araçtır, bu nedenle `dump-keychain` sonucunun kısa olması burada kimlik bilgilerinin bulunmadığı anlamına gelmez.<sup>[[5]](#references)</sup>
- **iOS**'ta `/private/var/Keychains/` konumunda yalnızca bir **Keychain** bulunur. Bu klasör ayrıca `TrustStore`, sertifika yetkilileri (`caissuercache`) ve OSCP girdileri (`ocspache`) için veritabanları içerir.
  - Uygulamalar, keychain'de yalnızca uygulama tanımlayıcılarına göre belirlenen özel alanlarıyla sınırlandırılır.

### Password Keychain Access

Kopyalanmış **dosya tabanlı** bir keychain düz metin değildir. Korunan öğelerin çevrimdışı olarak şifresini çözmek için keychain parolası veya eşdeğer anahtar materyali gerekir; [**Chainbreaker**](https://github.com/n0fate/chainbreaker) bu biçimi hedefler.<sup>[[1]](#references)</sup> Bu, kilidi açılmış bir kullanıcı oturumunda yapılan canlı okumadan farklıdır; canlı okumada öğe erişim denetimleri, oturum açma parolasını yeniden gerektirmeden okumaya izin verebilir veya parola istemini tetikleyebilir. Data protection keychain farklı bir koruma ve erişim grubu modeline sahiptir.<sup>[[5]](#references)</sup>

## Keychain Entries Protections

### File-based keychain ACLs

Aşağıdaki `SecAccess` ACL ve partition-list kuralları **dosya tabanlı** keychain'leri tanımlar. Data protection keychain öğeleri bunun yerine kod imzalama erişim gruplarını ve isteğe bağlı `SecAccessControl` koşullarını kullanır; erişilebilirliklerini dosya tabanlı ACL dökümünden çıkarmayın.<sup>[[5]](#references)</sup>

Dosya tabanlı keychain'deki her girdi, keychain girdisinde çeşitli işlemleri kimin gerçekleştirebileceğini belirleyen **Access Control List (ACL)** kurallarına tabidir. Bu işlemler şunları içerir:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Yetkili tarafın sırrın düz metnini almasına izin verir.
- **`kSecACLAuthorizationExportWrapped`**: Yetkili tarafın, sırrın başka bir sağlanan parolayla şifrelenmiş düz metnini almasına izin verir.
- **`kSecACLAuthorizationAny`**: Yetkili tarafın herhangi bir işlemi gerçekleştirmesine izin verir.

ACL'lere ayrıca bu işlemleri parola istemi olmadan gerçekleştirebilecek **güvenilir uygulamaların listesi** eşlik eder. Bu liste şu şekilde olabilir:<sup>[[1]](#references)</sup>

- **N`il`** (yetkilendirme gerekmez, **herkes güvenilirdir**)
- **Boş** liste (**hiç kimse** güvenilir değildir)
- Belirli **uygulamaların** **listesi**.

Girdi ayrıca **teamid, apple** ve **cdhash** değerlerini belirlemek için kullanılan **`kSecACLAuthorizationPartitionID`** anahtarını da içerebilir.<sup>[[1]](#references)[[2]](#references)</sup>

- **teamid** belirtilmişse, uygulamanın **girdi değerine** parola **istemeden** **erişebilmesi** için aynı **teamid** değerine sahip olması gerekir.
- **apple** belirtilmişse, uygulamanın **Apple tarafından imzalanmış** olması gerekir.
- **cdhash** belirtilmişse, uygulamanın belirtilen **cdhash** değerine sahip olması gerekir.

### Creating a file-based keychain entry

**Keychain Access.app** kullanılarak **yeni** bir **girdi** oluşturulduğunda şu kurallar geçerlidir:<sup>[[1]](#references)</sup>

- Tüm uygulamalar şifreleme yapabilir.
- Kullanıcıdan parola istemeden **hiçbir uygulama** dışa aktarma/şifre çözme işlemi yapamaz.
- Tüm uygulamalar bütünlük denetimini görebilir.
- Hiçbir uygulama ACL'leri değiştiremez.
- **partitionID**, **`apple`** olarak ayarlanır.

Bir **uygulama keychain'de girdi oluşturduğunda** kurallar biraz farklıdır:<sup>[[1]](#references)</sup>

- Tüm uygulamalar şifreleme yapabilir.
- Yalnızca **girdiyi oluşturan uygulama** (veya açıkça eklenen diğer uygulamalar), kullanıcıdan parola istemeden dışa aktarma/şifre çözme işlemi yapabilir.
- Tüm uygulamalar bütünlük denetimini görebilir.
- Hiçbir uygulama ACL'leri değiştiremez.
- **partitionID**, **`teamid:[teamID here]`** olarak ayarlanır.

## Accessing the Keychain

### `security`

```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entry's PartitionID value
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S` öğenin partition list değerini ayarlar; `-k` ise bu değişikliği yapmak için gereken mevcut Keychain parolasını sağlar. Parola alan bayrak kullanımdan kaldırılmıştır.<sup>[[4]](#references)</sup> Güncellemenin başarılı olması, sonraki bir okuma işleminin sessiz gerçekleşeceğini kanıtlamaz: Gözlemlenen, devre dışı bırakılmış bir prototipte, öğeyi `Security.framework` üzerinden sorguladığında yine de bir onay istemi tetiklendi. Eşleşen bir partition ID, yukarıda açıklanan ACL ve güvenilen uygulama kontrollerinin yalnızca bir parçasıdır; bu nedenle gerçek okuma yolunu doğrulayın.<sup>[[3]](#references)</sup>

### API'ler

> [!TIP]
> İstem **oluşturmayan** sırların **keychain'de listelenmesi ve dökülmesi**, [**LockSmith**](https://github.com/its-a-feature/LockSmith) aracıyla yapılabilir.
>
> Diğer API uç noktaları [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) kaynak kodunda bulunabilir.

**Security Framework**'ü kullanarak her keychain girdisini listeleyebilir ve bu girdi hakkında **bilgi** alabilir ya da Apple'ın açık kaynaklı cli aracı [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**'ye** bakabilirsiniz. Bazı API örnekleri:<sup>[[1]](#references)</sup>

- **`SecItemCopyMatching`** API'si her girdi hakkında bilgi verir ve bu API kullanılırken ayarlanabilecek bazı öznitelikler vardır:
  - **`kSecReturnData`**: True ise verinin şifresini çözmeye çalışır (olası açılır pencereleri önlemek için false olarak ayarlayın)
  - **`kSecReturnRef`**: Bir anahtar, sertifika veya kimlik için nesne referansı alır; parola öğelerinin bu nesne gösterimi yoktur. Daha sonra hedefli bir sorguda parolayı belirlemek için `kSecReturnPersistentRef` kullanın.<sup>[[6]](#references)</sup>
  - **`kSecReturnAttributes`**: Girdiler hakkındaki metadata'yı alır
  - **`kSecMatchLimit`**: Döndürülecek sonuç sayısı
  - **`kSecClass`**: Keychain girdisinin türü

Her girdinin **ACL**'lerini alın:<sup>[[1]](#references)</sup>

- **`SecAccessCopyACLList`** API'siyle **keychain öğesinin ACL**'sini alabilirsiniz. Her girdide aşağıdakiler bulunan bir ACL listesi döndürür (`kSecACLAuthorizationExportClear` ve daha önce bahsedilen diğerleri gibi):<sup>[[1]](#references)[[2]](#references)</sup>
  - Açıklama
  - **Güvenilen Uygulama Listesi**. Şunlardan biri olabilir:
    - Bir uygulama: /Applications/Slack.app
    - Bir binary: /usr/libexec/airportd
    - Bir grup: group://AirPort

Veriyi dışa aktarın:<sup>[[1]](#references)</sup>

- **`SecKeychainItemCopyContent`** API'si düz metni alır
- **`SecItemExport`** API'si anahtarları ve sertifikaları dışa aktarır, ancak içeriği şifrelenmiş olarak dışa aktarmak için parola ayarlamak gerekebilir

Bir sırrı istem oluşturmadan **dışa aktarabilmek** için gerekenler şunlardır:<sup>[[1]](#references)</sup>

- **1 veya daha fazla güvenilen** uygulama listelenmişse:
  - Uygun **yetkilendirmelere** sahip olmak gerekir (**`Nil`** veya gizli bilgiye erişim yetkilendirmesinde izin verilen uygulamalar listesinin **bir parçası** olmak)
  - Kod imzasının **PartitionID** ile eşleşmesi gerekir
  - Kod imzasının **güvenilen uygulamalardan** biriyle eşleşmesi gerekir (veya doğru KeychainAccessGroup'un üyesi olmak gerekir)
- **Tüm uygulamalar güvenilirse**:
  - Uygun **yetkilendirmelere** sahip olmak gerekir
  - Kod imzasının **PartitionID** ile eşleşmesi gerekir
    - **PartitionID yoksa** bu gereklilik geçerli değildir

> [!CAUTION]
> Dolayısıyla, **1 uygulama listelenmişse**, o uygulamaya **kod enjekte etmeniz** gerekir.
>
> **partitionID** içinde **apple** belirtilmişse, buna `osascript` ile erişebilirsiniz. Dolayısıyla partitionID içinde apple bulunan tüm uygulamalara güvenen öğelere bu şekilde erişilebilir. Bunun için **`Python`** da kullanılabilir.

### İki ek öznitelik

- **Invisible**: Girdiyi **UI** Keychain uygulamasında **gizleyen** bir boolean bayraktır<sup>[[1]](#references)</sup>
- **General**: **Metadata** depolamak içindir (yani **ŞİFRELENMEZ**)<sup>[[1]](#references)</sup>
  - Microsoft, hassas uç noktaya erişmek için kullanılan tüm refresh token'ları düz metin olarak depoluyordu.<sup>[[1]](#references)</sup>

### Data protection keychain: önce listeleyin, ardından tek bir öğeyi sorgulayın

`kSecUseDataProtectionKeychain: true` ile **hedef kullanıcının login bağlamında**, **imzalı bir uygulamadan** `SecItemCopyMatching` çalıştırın; `security dump-keychain` komutunun veya varsayılan bir SecItem sorgusunun bu depoda arama yaptığını varsaymayın. Çağıran yalnızca yetkili olduğu erişim gruplarını görür.<sup>[[5]](#references)</sup>

Test kodu başka bir işlem içinde çalışıyorsa, data protection keychain erişimi ana makine çalıştırılabilir dosyasının entitlements değerlerini izler. Gerçek imzalı entitlements değerlerini `codesign -d --entitlements - /path/to/Target.app` ile inceleyin ve ilgili kontroller için [macOS code-signing entitlements](../macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements.md) sayfasına bakın.<sup>[[7]](#references)</sup>

Önce tek bir öğe sınıfı için yalnızca **öznitelikleri** isteyin. `kSecAttrSynchronizableAny` hem yerel hem de iCloud ile eşzamanlanan eşleşmeleri kapsar; bu parametrenin çıkarılması eşzamanlanan öğeleri kapsam dışı bırakır.<sup>[[8]](#references)</sup> `kSecUseAuthenticationUISkip`, geniş kapsamlı listeleme sırasında korumalı eşleşmeleri atlama pahasına kimlik doğrulama arayüzünün açılmasını önler.<sup>[[9]](#references)</sup> Gerekirse `kSecClassInternetPassword` ile tekrarlayın.

```swift
import Security
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecUseDataProtectionKeychain as String: true,
    kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true,
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
]
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)
print(status)
if status == errSecSuccess, let items = result as? [[String: Any]] {
    for item in items { print(item) }
}
```

İzin verilen bir secret okuması için seçilen öğeye yönelik **yeni**, dar kapsamlı bir sorgu oluşturun (örneğin sınıf, hizmet ve hesap), `kSecReturnData: true` ve `kSecMatchLimit: kSecMatchLimitOne` ayarlarını yapın ve öğeye özgü kimlik doğrulaması veya bir hata bekleyin. Parola öğeleri için `kSecReturnData` ile `kSecMatchLimitAll` ayarlarını **birlikte kullanmayın**.<sup>[[10]](#references)</sup> `errSecItemNotFound` sonucu, kimlik bilgisinin bulunmadığı anlamına gelmek yerine yanlış store, sync filtresi veya eksik access-group yetkisini de gösterebilir.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>



## References

- [1] [#OBTS v5.0: macOS Keychain’i Kilit Açma - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - MacSync macOS hırsızının yeni sürümü kripto meraklılarını ve geliştiricileri hedef alıyor](https://securelist.com/macsync-new-version/121383/)
- [4] [Apple security(1) man sayfası kopyası](https://keith.github.io/xcode-man-pages/security.1.html)
- [5] [Apple TN3137 — Mac keychain API’leri ve uygulamaları hakkında](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [6] [Apple Developer Forums — SecItem: Temel bilgiler](https://developer.apple.com/forums/thread/724023)
- [7] [Apple Developer Forums — SecItem: Tuzaklar ve en iyi uygulamalar](https://developer.apple.com/forums/thread/724013)
- [8] [Apple Developer — kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [9] [Apple Developer — Face ID veya Touch ID ile Keychain öğelerine erişme](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [10] [Apple Developer — SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29)
{{#include ../../banners/hacktricks-training.md}}
