# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Ana Keychain'ler

- **Kullanıcı Keychain'i** (`~/Library/Keychains/login.keychain-db`), uygulama parolaları, internet parolaları, kullanıcı tarafından oluşturulan sertifikalar, ağ parolaları ve kullanıcı tarafından oluşturulan açık/özel anahtarlar gibi **kullanıcıya özgü kimlik bilgilerini** depolamak için kullanılır.
- **Sistem Keychain'i** (`/Library/Keychains/System.keychain`), WiFi parolaları, sistem kök sertifikaları, sistem özel anahtarları ve sistem uygulama parolaları gibi **sistem genelindeki kimlik bilgilerini** depolar.<sup>[[1]](#references)</sup>
  - `/System/Library/Keychains/*` içinde sertifikalar gibi başka bileşenler de bulunabilir.
- **iOS**'ta `/private/var/Keychains/` konumunda bulunan yalnızca bir **Keychain** vardır. Bu klasör ayrıca `TrustStore`, sertifika yetkilileri (`caissuercache`) ve OSCP girdileri (`ocspache`) için veritabanları içerir.
  - Uygulamalar, uygulama tanımlayıcılarına göre Keychain'de yalnızca kendi özel alanlarına erişebilir.

### Parola ile Keychain Erişimi

Bu dosyalar yerleşik korumaya sahip olmadığından **indirilebilir**; ancak şifrelenmiştir ve şifrelerinin çözülmesi için **kullanıcının düz metin parolası gerekir**. Şifre çözme için [**Chainbreaker**](https://github.com/n0fate/chainbreaker) gibi bir araç kullanılabilir.<sup>[[1]](#references)</sup>

## Keychain Girdilerinin Koruması

### ACL'ler

Keychain'deki her girdi, girdide kimlerin hangi işlemleri gerçekleştirebileceğini belirleyen **Erişim Denetim Listeleri (ACL'ler)** tarafından yönetilir. Bu işlemler şunları içerir:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Yetkili kişinin gizli bilgiyi düz metin olarak almasına izin verir.
- **`kSecACLAuthorizationExportWrapped`**: Yetkili kişinin gizli bilgiyi, sağlanan başka bir parolayla şifrelenmiş olarak almasına izin verir.
- **`kSecACLAuthorizationAny`**: Yetkili kişinin herhangi bir işlemi gerçekleştirmesine izin verir.

ACL'lere, bu işlemleri izin istemi göstermeden gerçekleştirebilecek **güvenilir uygulamaların listesi** de eşlik eder. Bu liste şu şekilde olabilir:<sup>[[1]](#references)</sup>

- **N`il`** (yetkilendirme gerekmez, **herkese güvenilir**)
- **Boş** bir liste (**hiç kimseye** güvenilmez)
- Belirli **uygulamaların listesi**.

Girdi ayrıca **teamid, apple** ve **cdhash** değerlerini belirlemek için kullanılan **`kSecACLAuthorizationPartitionID`** anahtarını da içerebilir.<sup>[[1]](#references)[[2]](#references)</sup>

- **teamid** belirtilmişse, uygulamanın girdi değerine **izin istemi olmadan erişebilmesi** için **aynı teamid'ye** sahip olması gerekir.
- **apple** belirtilmişse, uygulamanın **Apple tarafından imzalanmış** olması gerekir.
- **cdhash** belirtilmişse, uygulamanın belirtilen **cdhash** değerine sahip olması gerekir.

### Keychain Girdisi Oluşturma

**`Keychain Access.app`** kullanılarak **yeni** bir **girdi** oluşturulduğunda şu kurallar geçerlidir:<sup>[[1]](#references)</sup>

- Tüm uygulamalar şifreleme yapabilir.
- **Hiçbir uygulama**, kullanıcıdan izin istemeden dışa aktarma/şifre çözme işlemi yapamaz.
- Tüm uygulamalar bütünlük denetimini görebilir.
- Hiçbir uygulama ACL'leri değiştiremez.
- **partitionID**, **`apple`** olarak ayarlanır.

**Bir uygulama Keychain'de girdi oluşturduğunda** kurallar biraz farklıdır:<sup>[[1]](#references)</sup>

- Tüm uygulamalar şifreleme yapabilir.
- Yalnızca **girdiyi oluşturan uygulama** (veya açıkça eklenen diğer uygulamalar), kullanıcıdan izin istemeden dışa aktarma/şifre çözme işlemi yapabilir.
- Tüm uygulamalar bütünlük denetimini görebilir.
- Hiçbir uygulama ACL'leri değiştiremez.
- **partitionID**, **`teamid:[teamID here]`** olarak ayarlanır.

## Keychain'e Erişme

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

`-S` öğenin partition list'ini ayarlar; `-k` ise bu değişikliği yapmak için gereken mevcut Keychain parolasını sağlar. Parola alan bu bayrak kullanımdan kaldırılmıştır.<sup>[[4]](#references)</sup> Başarılı bir güncelleme, sonraki bir okumanın sessizce gerçekleşeceğini kanıtlamaz: gözlemlenen, devre dışı bırakılmış bir prototipte öğe `Security.framework` üzerinden sorgulandığında yine de bir onay istemi tetiklendi. Eşleşen bir partition ID, yukarıda açıklanan ACL ve trusted-application kontrollerinin yalnızca bir parçasıdır; bu nedenle gerçek okuma yolunu doğrulayın.<sup>[[3]](#references)</sup>

### API'ler

> [!TIP]
> İstem oluşturmayacak sırların **Keychain'de listelenmesi ve dökülmesi**, [**LockSmith**](https://github.com/its-a-feature/LockSmith) aracıyla yapılabilir.
>
> Diğer API uç noktalarını [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) kaynak kodunda bulabilirsiniz.

Her Keychain girdisi hakkındaki **bilgileri** listelemek ve almak için **Security Framework**'ü kullanın. Alternatif olarak Apple'ın açık kaynaklı cli aracı [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**'ye** de bakabilirsiniz. Bazı API örnekleri:<sup>[[1]](#references)</sup>

- **`SecItemCopyMatching`** API'si her girdi hakkında bilgi sağlar ve bu API'yi kullanırken ayarlayabileceğiniz bazı öznitelikler vardır:
  - **`kSecReturnData`**: true ise verilerin şifresini çözmeye çalışır (olası açılır pencereleri önlemek için false olarak ayarlayın)
  - **`kSecReturnRef`**: Keychain öğesine ait referansı da alır (daha sonra açılır pencere olmadan şifre çözmenin mümkün olduğunu görürseniz true olarak ayarlayın)
  - **`kSecReturnAttributes`**: Girdiler hakkındaki metadata'yı alır
  - **`kSecMatchLimit`**: Döndürülecek sonuç sayısı
  - **`kSecClass`**: Keychain girdisinin türü

Her girdinin **ACL**'lerini alın:<sup>[[1]](#references)</sup>

- **`SecAccessCopyACLList`** API'siyle **Keychain öğesinin ACL'sini** alabilirsiniz. Daha önce bahsedilen `kSecACLAuthorizationExportClear` ve diğerleri gibi ACL'lerin bir listesini döndürür; her girdide şunlar bulunur:<sup>[[1]](#references)[[2]](#references)</sup>
  - Açıklama
  - **Trusted Application List**. Şunlardan biri olabilir:
    - Bir uygulama: /Applications/Slack.app
    - Bir binary: /usr/libexec/airportd
    - Bir grup: group://AirPort

Verileri dışa aktarın:<sup>[[1]](#references)</sup>

- **`SecKeychainItemCopyContent`** API'si açık metni alır
- **`SecItemExport`** API'si anahtarları ve sertifikaları dışa aktarır; ancak içeriği şifrelenmiş olarak dışa aktarmak için parola ayarlamak gerekebilir

İşte bir sırrı istem olmadan **dışa aktarabilmek** için gerekenler:<sup>[[1]](#references)</sup>

- **1 veya daha fazla trusted** uygulama listelenmişse:
  - Uygun **yetkilere** sahip olmanız gerekir (**`Nil`** olmalı veya sır bilgilerine erişim yetkisinde izin verilen uygulamalar listesinde **yer almalısınız**)
  - Code signature, **PartitionID** ile eşleşmelidir
  - Code signature, **trusted app**'lerden biriyle eşleşmelidir (veya doğru KeychainAccessGroup'un üyesi olmalıdır)
- **Tüm uygulamalar trusted** ise:
  - Uygun **yetkilere** sahip olmanız gerekir
  - Code signature, **PartitionID** ile eşleşmelidir
    - **PartitionID yoksa** bu koşul gerekmez

> [!CAUTION]
> Dolayısıyla, **1 uygulama listelenmişse**, o uygulamaya **code inject etmeniz** gerekir.
>
> **partitionID** içinde **apple** belirtilmişse, buna **`osascript`** ile erişebilirsiniz. Yani partitionID'sinde apple bulunan ve tüm uygulamalara güvenen her şey için bu yöntem kullanılabilir. Bunun için **`Python`** da kullanılabilir.

### İki ek öznitelik

- **Invisible**: Girdiyi Keychain **UI** uygulamasında **gizleyen** bir boolean bayraktır<sup>[[1]](#references)</sup>
- **General**: **Metadata** depolamak içindir (yani **ŞİFRELENMEZ**)<sup>[[1]](#references)</sup>
  - Microsoft, hassas uç noktaya erişmek için gereken tüm refresh token'ları düz metin olarak depoluyordu.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [#OBTS v5.0: "macOS Keychain'de Kilit Açma" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - MacSync macOS hırsızının yeni sürümü kripto meraklılarını ve geliştiricileri hedef alıyor](https://securelist.com/macsync-new-version/121383/)
- [4] [Apple security(1) kılavuz sayfası aynası](https://keith.github.io/xcode-man-pages/security.1.html)
