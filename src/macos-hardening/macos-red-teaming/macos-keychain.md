# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), uygulama parolaları, internet parolaları, kullanıcı tarafından oluşturulan sertifikalar, ağ parolaları ve kullanıcı tarafından oluşturulan public/private key'ler gibi **kullanıcıya özel kimlik bilgilerini** depolamak için kullanılır.
- **System Keychain** (`/Library/Keychains/System.keychain`), WiFi parolaları, sistem root sertifikaları, sistem private key'leri ve sistem uygulama parolaları gibi **sistem genelindeki kimlik bilgilerini** depolar.<sup>[[1]](#references)</sup>
- `/System/Library/Keychains/*` içinde sertifikalar gibi diğer bileşenleri bulmak mümkündür.
- **iOS** üzerinde `/private/var/Keychains/` konumunda yalnızca bir **Keychain** bulunur. Bu klasör ayrıca `TrustStore`, sertifika otoriteleri (`caissuercache`) ve OSCP girdileri (`ocspache`) için veritabanlarını da içerir.
- Uygulamalar, uygulama tanımlayıcılarına göre keychain içinde yalnızca kendi private alanlarıyla sınırlandırılır.

### Password Keychain Access

Bu dosyalar doğrudan korumaya sahip olmadıkları ve **download edilebildikleri** halde şifrelenmiştir ve **kullanıcının plaintext parolasının decryption için kullanılmasını** gerektirir. Decryption için [**Chainbreaker**](https://github.com/n0fate/chainbreaker) gibi bir tool kullanılabilir.<sup>[[1]](#references)</sup>

## Keychain Entries Protections

### ACLs

Keychain içindeki her entry, keychain entry üzerinde kimlerin çeşitli işlemleri gerçekleştirebileceğini belirleyen **Access Control Lists (ACLs)** tarafından yönetilir. Bunlar şunları içerir:<sup>[[1]](#references)</sup>

- **ACLAuthorizationExportClear**: Holder'ın secret'ın clear text'ini almasına izin verir.
- **ACLAuthorizationExportWrapped**: Holder'ın clear text'i, sağlanan başka bir parolayla encrypted biçimde almasına izin verir.
- **ACLAuthorizationAny**: Holder'ın herhangi bir işlem gerçekleştirmesine izin verir.

ACL'lere ayrıca bu işlemleri prompting olmadan gerçekleştirebilecek **trusted applications listesi** eşlik eder. Bu liste şu şekilde olabilir:<sup>[[1]](#references)</sup>

- **N`il`** (authorization gerektirmez, **herkes trusted'dır**)
- Boş bir liste (**hiç kimse trusted değildir**)
- Belirli **uygulamaların** **listesi**.

Ayrıca entry, **`ACLAuthorizationPartitionID`** key'ini içerebilir; bu key **teamid, apple** ve **cdhash** değerlerini tanımlamak için kullanılır.<sup>[[1]](#references)</sup>

- **teamid** belirtilmişse, uygulamanın **entry** değerine **prompt** olmadan **erişebilmesi** için **aynı teamid** değerine sahip olması gerekir.
- **apple** belirtilmişse uygulamanın **Apple** tarafından **signed** olması gerekir.
- **cdhash** belirtilmişse **app**'in belirli bir **cdhash** değerine sahip olması gerekir.

### Creating a Keychain Entry

**`Keychain Access.app`** kullanılarak **yeni** bir **entry** oluşturulduğunda aşağıdaki kurallar geçerlidir:<sup>[[1]](#references)</sup>

- Tüm app'ler encrypt edebilir.
- **Hiçbir app** (kullanıcıya prompt gösterilmeden) export/decrypt yapamaz.
- Tüm app'ler integrity check'i görebilir.
- Hiçbir app ACL'leri değiştiremez.
- **partitionID**, **`apple`** olarak ayarlanır.

Bir **uygulama keychain içinde bir entry oluşturduğunda** kurallar biraz farklıdır:<sup>[[1]](#references)</sup>

- Tüm app'ler encrypt edebilir.
- Yalnızca **oluşturan uygulama** (veya açıkça eklenen diğer app'ler) (kullanıcıya prompt gösterilmeden) export/decrypt yapabilir.
- Tüm app'ler integrity check'i görebilir.
- Hiçbir app ACL'leri değiştiremez.
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
security set-generic-password-partition-list -s "test service" -a "test account" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> **Prompt oluşturmayan** **keychain enumeration and dumping** işlemleri, [**LockSmith**](https://github.com/its-a-feature/LockSmith) aracıyla gerçekleştirilebilir.
>
> Diğer API endpoint'leri, [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) kaynak kodunda bulunabilir.

**Security Framework** kullanarak her keychain girdisini listeleyin ve hakkında **bilgi** alın. Alternatif olarak Apple'ın open source cli aracı [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**'yi** de inceleyebilirsiniz. Bazı API örnekleri:<sup>[[1]](#references)</sup>

- **`SecItemCopyMatching`** API'si her girdi hakkında bilgi verir ve kullanılırken ayarlanabilecek bazı attribute'lar vardır:
- **`kSecReturnData`**: true ise verinin şifresini çözmeye çalışır (olası pop-up'ları önlemek için false olarak ayarlayın)
- **`kSecReturnRef`**: keychain item'a ait referansı da alın (daha sonra pop-up olmadan şifre çözebildiğinizi görmeniz ihtimaline karşı true olarak ayarlayın)
- **`kSecReturnAttributes`**: Girdiler hakkında metadata alın
- **`kSecMatchLimit`**: Kaç sonuç döndürüleceği
- **`kSecClass`**: Keychain girdisinin türü

Her girdinin **ACL**'lerini alın:<sup>[[1]](#references)</sup>

- **`SecAccessCopyACLList`** API'siyle **keychain item için ACL** alabilirsiniz. Daha önce bahsedilenler gibi (`ACLAuthorizationExportClear` ve diğerleri) bir ACL listesi döndürür; burada her girdide şunlar bulunur:
- Description
- **Trusted Application List**. Bu liste şunlardan biri olabilir:
- Bir app: /Applications/Slack.app
- Bir binary: /usr/libexec/airportd
- Bir group: group://AirPort

Verileri export edin:<sup>[[1]](#references)</sup>

- **`SecKeychainItemCopyContent`** API'si plaintext'i alır
- **`SecItemExport`** API'si key'leri ve certificate'ları export eder; ancak içeriği şifrelenmiş olarak export etmek için password ayarlamanız gerekebilir

Bunlar, **prompt olmadan bir secret'ı export edebilmek** için gerekenlerdir:<sup>[[1]](#references)</sup>

- **1 veya daha fazla trusted** app listelenmişse:
- Uygun **authorizations** gerekir (**`Nil`** olması veya secret bilgisine erişim için authorization'da izin verilen app'ler listesinin **parçası** olmanız)
- Code signature'ın **PartitionID** ile eşleşmesi gerekir
- Code signature'ın **trusted app**'lerden birininkiyle eşleşmesi gerekir (veya doğru KeychainAccessGroup'un üyesi olunması gerekir)
- **Tüm application'lar trusted** ise:
- Uygun **authorizations** gerekir
- Code signature'ın **PartitionID** ile eşleşmesi gerekir
- **PartitionID yoksa** buna gerek yoktur

> [!CAUTION]
> Bu nedenle, **1 application listelenmişse**, o application'a **code inject** etmeniz gerekir.
>
> **apple**, **partitionID** içinde belirtilmişse, **`osascript`** ile erişebilirsiniz; yani partitionID'sinde apple bulunan tüm application'lara güvenen herhangi bir şey kullanılabilir. Bunun için **`Python`** da kullanılabilir.

### İki ek attribute

- **Invisible**: Girdiyi **UI** Keychain app'inden gizlemek için kullanılan bir boolean flag'dir<sup>[[1]](#references)</sup>
- **General**: **metadata** depolamak içindir (yani **ENCRYPTED DEĞİLDİR**)<sup>[[1]](#references)</sup>
- Microsoft, sensitive endpoint'e erişmek için kullanılan tüm refresh token'ları plaintext olarak depoluyordu.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "macOS Keychain'i Maymuncukla Açma" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
{{#include ../../banners/hacktricks-training.md}}
