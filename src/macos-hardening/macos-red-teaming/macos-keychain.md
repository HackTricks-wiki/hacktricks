# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Ana Keychain'ler

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), uygulama parolaları, internet parolaları, kullanıcı tarafından oluşturulan sertifikalar, ağ parolaları ve kullanıcı tarafından oluşturulan public/private key'ler gibi **kullanıcıya özel kimlik bilgilerini** depolamak için kullanılır.
- **System Keychain** (`/Library/Keychains/System.keychain`), WiFi parolaları, sistem root sertifikaları, sistem private key'leri ve sistem uygulama parolaları gibi **sistem genelindeki kimlik bilgilerini** depolar.<sup>[[1]](#references)</sup>
- `/System/Library/Keychains/*` konumunda sertifikalar gibi başka bileşenleri bulmak mümkündür.
- **iOS** üzerinde `/private/var/Keychains/` konumunda yalnızca bir **Keychain** bulunur. Bu klasör ayrıca `TrustStore`, sertifika otoriteleri (`caissuercache`) ve OSCP girdileri (`ocspache`) için veritabanlarını da içerir.
- Uygulamalar, uygulama tanımlayıcılarına göre keychain'de yalnızca kendi private alanlarıyla sınırlandırılır.

### Password Keychain Access

Bu dosyalar kendi başlarına herhangi bir korumaya sahip olmasalar ve **download** edilebilseler de şifrelenmiştir ve şifrelerinin çözülmesi için **kullanıcının plaintext parolası** gerekir. Şifre çözme için [**Chainbreaker**](https://github.com/n0fate/chainbreaker) gibi bir tool kullanılabilir.<sup>[[1]](#references)</sup>

## Keychain Entries Protections

### ACLs

Keychain'deki her entry, keychain entry'si üzerinde çeşitli işlemleri kimin gerçekleştirebileceğini belirleyen **Access Control List (ACL)**'ler tarafından yönetilir:<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: Holder'ın secret'ın clear text'ini almasına izin verir.
- **ACLAuhtorizationExportWrapped**: Holder'ın clear text'i sağlanan başka bir parolayla şifrelenmiş şekilde almasına izin verir.
- **ACLAuhtorizationAny**: Holder'ın herhangi bir işlem gerçekleştirmesine izin verir.

ACL'lere ayrıca, bu işlemleri prompt göstermeden gerçekleştirebilecek **trusted applications listesi** eşlik eder. Bu liste şu şekilde olabilir:<sup>[[1]](#references)</sup>

- **N`il`** (authorization gerekmez, **herkese güvenilir**)
- **Boş** bir liste (**hiç kimseye** güvenilmez)
- Belirli **uygulamaların** **listesi**.

Ayrıca entry, **`ACLAuthorizationPartitionID`** key'ini içerebilir; bu key **teamid, apple** ve **cdhash** değerlerini tanımlamak için kullanılır.<sup>[[1]](#references)</sup>

- **teamid** belirtilmişse, **entry** değerine **prompt** olmadan **erişmek** için kullanılan uygulamanın **aynı teamid** değerine sahip olması gerekir.
- **apple** belirtilmişse uygulamanın **Apple** tarafından **signed** olması gerekir.
- **cdhash** belirtilmişse **app**'in belirtilen **cdhash** değerine sahip olması gerekir.

### Creating a Keychain Entry

**Keychain Access.app** kullanılarak **yeni** bir **entry** oluşturulduğunda şu kurallar geçerlidir:<sup>[[1]](#references)</sup>

- Tüm uygulamalar encrypt edebilir.
- Kullanıcıya prompt gösterilmeden **hiçbir uygulama** export/decrypt edemez.
- Tüm uygulamalar integrity check'i görebilir.
- Hiçbir uygulama ACL'leri değiştiremez.
- **partitionID**, `apple` olarak ayarlanır.

Bir **uygulama keychain'de bir entry oluşturduğunda** kurallar biraz farklıdır:<sup>[[1]](#references)</sup>

- Tüm uygulamalar encrypt edebilir.
- Yalnızca **entry'yi oluşturan uygulama** (veya açıkça eklenen diğer uygulamalar) kullanıcıya prompt gösterilmeden export/decrypt edebilir.
- Tüm uygulamalar integrity check'i görebilir.
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

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> **Prompt oluşturmayan** secret'ların **keychain enumeration ve dumping** işlemleri [**LockSmith**](https://github.com/its-a-feature/LockSmith) aracıyla yapılabilir.
>
> Diğer API endpoint'leri [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) source code içinde bulunabilir.

**Security Framework** kullanarak her keychain entry'si hakkında **info** listeleyip alabilir veya Apple'ın open source cli tool'u [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**'yi** inceleyebilirsiniz. Bazı API örnekleri:<sup>[[1]](#references)</sup>

- **`SecItemCopyMatching`** API'si her entry hakkında bilgi verir ve bunu kullanırken ayarlayabileceğiniz bazı attribute'lar vardır:
- **`kSecReturnData`**: True ise data'yı decrypt etmeye çalışır (potansiyel pop-up'ları önlemek için false olarak ayarlayın)
- **`kSecReturnRef`**: Keychain item'ına ait reference'ı da alır (daha sonra pop-up olmadan decrypt edebildiğinizi görmeniz durumunda true olarak ayarlayın)
- **`kSecReturnAttributes`**: Entry'ler hakkında metadata alır
- **`kSecMatchLimit`**: Döndürülecek result sayısı
- **`kSecClass`**: Keychain entry'sinin türü

Her entry'nin **ACL**'lerini alın:<sup>[[1]](#references)</sup>

- **`SecAccessCopyACLList`** API'siyle **keychain item'ının ACL**'sini alabilirsiniz; API, daha önce bahsedilen `ACLAuhtorizationExportClear` ve diğerleri gibi ACL'lerden oluşan bir liste döndürür ve her listede şunlar bulunur:
- Description
- **Trusted Application List**. Bu şunlardan biri olabilir:
- Bir app: /Applications/Slack.app
- Bir binary: /usr/libexec/airportd
- Bir group: group://AirPort

Data'yı export edin:<sup>[[1]](#references)</sup>

- **`SecKeychainItemCopyContent`** API'si plaintext'i alır
- **`SecItemExport`** API'si key'leri ve certificate'ları export eder; ancak content'i encrypted olarak export etmek için password ayarlamanız gerekebilir

Bunlar, **prompt olmadan bir secret'ı export edebilmek** için gerekenlerdir:<sup>[[1]](#references)</sup>

- **1+ trusted** app listelenmişse:
- Uygun **authorization**'lara (**`Nil`** veya secret info'ya erişim için authorization'daki izin verilen app listesinde **yer almak**) sahip olmanız gerekir
- Code signature'ın **PartitionID** ile eşleşmesi gerekir
- Code signature'ın **trusted app**'lerden birininkiyle eşleşmesi (veya doğru KeychainAccessGroup'un member'ı olmanız) gerekir
- **All applications trusted** ise:
- Uygun **authorization**'lara sahip olmanız gerekir
- Code signature'ın **PartitionID** ile eşleşmesi gerekir
- **PartitionID** yoksa buna gerek yoktur

> [!CAUTION]
> Bu nedenle, listelenmiş **1 application** varsa, o application'a **code inject** etmeniz gerekir.
>
> **partitionID** içinde **apple** belirtilmişse, buna **`osascript`** ile erişebilirsiniz; dolayısıyla partitionID içinde apple bulunan tüm application'lara güvenen uygulamalara bu şekilde erişilebilir. Bunun için **`Python`** da kullanılabilir.

### Two additional attributes

- **Invisible**: Entry'yi **UI** Keychain app'inden **gizlemek** için kullanılan bir boolean flag'dir<sup>[[1]](#references)</sup>
- **General**: **Metadata** depolamak içindir (yani **ENCRYPTED DEĞİLDİR**)<sup>[[1]](#references)</sup>
- Microsoft, sensitive endpoint'e erişmek için kullanılan tüm refresh token'ları plain text olarak depoluyordu.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
