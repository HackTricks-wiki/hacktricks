# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), uygulama parolaları, internet parolaları, kullanıcı tarafından oluşturulan sertifikalar, ağ parolaları ve kullanıcı tarafından oluşturulan genel/özel anahtarlar gibi **kullanıcıya özel kimlik bilgilerini** depolamak için kullanılır.
- **System Keychain** (`/Library/Keychains/System.keychain`), WiFi parolaları, sistem kök sertifikaları, sistem özel anahtarları ve sistem uygulama parolaları gibi **sistem genelindeki kimlik bilgilerini** depolar.<sup>[[1]](#references)</sup>
- `/System/Library/Keychains/*` içinde sertifikalar gibi başka bileşenleri bulmak mümkündür.
- **iOS** üzerinde `/private/var/Keychains/` konumunda yalnızca bir **Keychain** bulunur. Bu klasör ayrıca `TrustStore`, sertifika otoriteleri (`caissuercache`) ve OSCP girdileri (`ocspache`) için veritabanlarını da içerir.
- Uygulamalar, uygulama tanımlayıcılarına göre yalnızca Keychain içindeki kendi özel alanlarıyla sınırlandırılır.

### Password Keychain Access

Bu dosyalar kendiliğinden bir korumaya sahip olmasalar ve **download** edilebilseler de şifrelidir ve **şifrelerinin çözülmesi için kullanıcının düz metin parolasını gerektirir**. Şifre çözme için [**Chainbreaker**](https://github.com/n0fate/chainbreaker) gibi bir tool kullanılabilir.<sup>[[1]](#references)</sup>

## Keychain Entries Protections

### ACLs

Keychain içindeki her entry, Keychain entry'si üzerinde kimlerin çeşitli işlemleri gerçekleştirebileceğini belirleyen **Access Control Lists (ACLs)** tarafından yönetilir:<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: Sahibinin secret'ın clear text halini almasına izin verir.
- **ACLAuhtorizationExportWrapped**: Sahibinin clear text'i sağlanan başka bir parolayla şifrelenmiş şekilde almasına izin verir.
- **ACLAuhtorizationAny**: Sahibinin herhangi bir işlem gerçekleştirmesine izin verir.

ACLs'lere ayrıca, prompt gösterilmeden bu işlemleri gerçekleştirebilen **trusted applications** listesi eşlik eder. Bu liste şunlardan biri olabilir:<sup>[[1]](#references)</sup>

- **N`il`** (authorization gerektirmez, **herkese güvenilir**)
- Boş bir liste (**hiç kimseye** güvenilmez)
- Belirli **uygulamalardan** oluşan bir **liste**.

Entry ayrıca **`ACLAuthorizationPartitionID`** anahtarını içerebilir; bu anahtar **teamid, apple** ve **cdhash** değerlerini tanımlamak için kullanılır.<sup>[[1]](#references)</sup>

- **teamid** belirtilmişse, **entry** değerine **prompt** olmadan **erişmek** için kullanılan uygulamanın **aynı teamid** değerine sahip olması gerekir.
- **apple** belirtilmişse, uygulamanın **Apple** tarafından **imzalanmış** olması gerekir.
- **cdhash** belirtilmişse, **app** belirli **cdhash** değerine sahip olmalıdır.

### Creating a Keychain Entry

**Keychain Access.app** kullanılarak **yeni** bir **entry** oluşturulduğunda şu kurallar uygulanır:<sup>[[1]](#references)</sup>

- Tüm uygulamalar encrypt edebilir.
- **Hiçbir app**, kullanıcıya prompt gösterilmeden export/decrypt edemez.
- Tüm uygulamalar integrity check'i görebilir.
- Hiçbir app ACLs'leri değiştiremez.
- **partitionID**, **`apple`** olarak ayarlanır.

Bir **application** Keychain içinde bir entry oluşturduğunda kurallar biraz farklıdır:<sup>[[1]](#references)</sup>

- Tüm uygulamalar encrypt edebilir.
- Yalnızca **entry'yi oluşturan application** (veya açıkça eklenen diğer uygulamalar), kullanıcıya prompt gösterilmeden export/decrypt edebilir.
- Tüm uygulamalar integrity check'i görebilir.
- Hiçbir app ACLs'leri değiştiremez.
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

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> **prompt oluşturmayacak** şekilde **keychain enumeration ve secret dumping** işlemleri [**LockSmith**](https://github.com/its-a-feature/LockSmith) aracıyla yapılabilir.
>
> Diğer API endpoint'leri [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) source code içinde bulunabilir.

**Security Framework** kullanarak her keychain entry hakkında **info** listeleyin ve alın. Alternatif olarak Apple'ın open source CLI aracı [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**'ı** da inceleyebilirsiniz. Bazı API örnekleri:<sup>[[1]](#references)</sup>

- **`SecItemCopyMatching`** API'si her entry hakkında info verir ve bunu kullanırken ayarlayabileceğiniz bazı attribute'lar vardır:
- **`kSecReturnData`**: True ise data'yı decrypt etmeyi dener (olası pop-up'ları önlemek için false olarak ayarlayın)
- **`kSecReturnRef`**: keychain item'a referansı da alır (daha sonra pop-up olmadan decrypt edebildiğinizi görürseniz true olarak ayarlayın)
- **`kSecReturnAttributes`**: Entry'ler hakkında metadata alır
- **`kSecMatchLimit`**: Kaç sonuç döndürüleceği
- **`kSecClass`**: Keychain entry'nin türü

Her entry'nin **ACL**'lerini alın:<sup>[[1]](#references)</sup>

- **`SecAccessCopyACLList`** API'siyle **keychain item'ın ACL**'sini alabilirsiniz. Bu API, daha önce bahsedilen `ACLAuhtorizationExportClear` ve diğerleri gibi ACL'lerin bir listesini döndürür; her listede şunlar bulunur:
- Description
- **Trusted Application List**. Bu şunlardan biri olabilir:
- Bir app: /Applications/Slack.app
- Bir binary: /usr/libexec/airportd
- Bir group: group://AirPort

Data'yı export edin:<sup>[[1]](#references)</sup>

- **`SecKeychainItemCopyContent`** API'si plaintext'i alır
- **`SecItemExport`** API'si key'leri ve certificate'ları export eder, ancak content'i encrypted olarak export etmek için password ayarlamanız gerekebilir

Bunlar, **prompt olmadan bir secret'ı export edebilmek** için gerekenlerdir:<sup>[[1]](#references)</sup>

- Listelenen **1+ trusted** app varsa:
- Uygun **authorizations** gerekir (**`Nil`** olmalı veya secret info'ya erişim için authorization içindeki izin verilen app listesinin **parçası** olmalısınız)
- Code signature'ın **PartitionID** ile eşleşmesi gerekir
- Code signature'ın **trusted app**'lerden birininkiyle eşleşmesi (veya doğru KeychainAccessGroup'un üyesi olunması) gerekir
- **Tüm applications trusted** ise:
- Uygun **authorizations** gerekir
- Code signature'ın **PartitionID** ile eşleşmesi gerekir
- **PartitionID yoksa** bunun yapılması gerekmez

> [!CAUTION]
> Bu nedenle, **1 application listelenmişse**, o application'a **code inject etmeniz** gerekir.
>
> **PartitionID** içinde **apple** belirtilmişse, buna **`osascript`** ile erişebilirsiniz; yani PartitionID içinde apple bulunan tüm applications'a güveniliyorsa. Bunun için **`Python`** da kullanılabilir.

### Two additional attributes

- **Invisible**: Entry'yi **UI** Keychain app'inden **gizlemek** için kullanılan bir boolean flag'dir<sup>[[1]](#references)</sup>
- **General**: **Metadata** depolamak içindir (yani **ENCRYPTED DEĞİLDİR**)<sup>[[1]](#references)</sup>
- Microsoft, sensitive endpoint'e erişmek için kullanılan tüm refresh token'ları plaintext olarak depoluyordu.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
