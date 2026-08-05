# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), uygulama parolaları, internet parolaları, kullanıcı tarafından oluşturulan sertifikalar, network parolaları ve kullanıcı tarafından oluşturulan public/private key'ler gibi **kullanıcıya özel kimlik bilgilerini** depolamak için kullanılır.
- **System Keychain** (`/Library/Keychains/System.keychain`), WiFi parolaları, sistem root sertifikaları, sistem private key'leri ve sistem uygulama parolaları gibi **sistem genelindeki kimlik bilgilerini** depolar.<sup>[1]</sup>
- `/System/Library/Keychains/*` içinde sertifikalar gibi başka bileşenler de bulunabilir.
- **iOS** içinde `/private/var/Keychains/` konumunda yalnızca bir **Keychain** bulunur. Bu klasör ayrıca `TrustStore`, sertifika otoriteleri (`caissuercache`) ve OSCP girdileri (`ocspache`) için veritabanları içerir.
- Uygulamalar, uygulama tanımlayıcılarına göre Keychain'de yalnızca kendi private alanlarıyla sınırlandırılır.

### Password Keychain Access

Bu dosyalar, doğrudan korumaya sahip olmamalarına ve **download edilebilmelerine** rağmen şifrelenmiştir ve şifrelerinin çözülmesi için **kullanıcının plaintext parolası** gerekir. Şifre çözme için [**Chainbreaker**](https://github.com/n0fate/chainbreaker) gibi bir tool kullanılabilir.<sup>[1]</sup>

## Keychain Entries Protections

### ACLs

Keychain'deki her entry, Keychain entry'si üzerinde kimlerin çeşitli işlemleri gerçekleştirebileceğini belirleyen **Access Control List'ler (ACLs)** tarafından yönetilir:<sup>[1]</sup>

- **ACLAuhtorizationExportClear**: Holder'ın secret'ın clear text'ini almasına izin verir.
- **ACLAuhtorizationExportWrapped**: Holder'ın clear text'i, sağlanan başka bir parolayla şifrelenmiş şekilde almasına izin verir.
- **ACLAuhtorizationAny**: Holder'ın herhangi bir işlem gerçekleştirmesine izin verir.

ACL'lere ayrıca bu işlemleri prompt göstermeden gerçekleştirebilecek **trusted applications listesi** eşlik eder. Bu liste şunlardan biri olabilir:<sup>[1]</sup>

- **N`il`** (authorization gerekmez, **herkes trusted'dır**)
- **Boş** bir liste (**hiç kimse trusted değildir**)
- Belirli **uygulamaların** **listesi**.

Entry ayrıca **`ACLAuthorizationPartitionID`** key'ini de içerebilir; bu key **teamid, apple** ve **cdhash** değerlerini tanımlamak için kullanılır.<sup>[1]</sup>

- **teamid** belirtilmişse, **entry** değerine bir **prompt** olmadan **erişmek** için kullanılan uygulamanın **aynı teamid** değerine sahip olması gerekir.
- **apple** belirtilmişse, uygulamanın **Apple** tarafından **signed** edilmesi gerekir.
- **cdhash** belirtilmişse, **app**'in belirtilen **cdhash** değerine sahip olması gerekir.

### Creating a Keychain Entry

**Keychain Access.app** kullanılarak **yeni** bir **entry** oluşturulduğunda aşağıdaki kurallar uygulanır:<sup>[1]</sup>

- Tüm uygulamalar encrypt edebilir.
- **Hiçbir app** export/decrypt edemez (kullanıcıya prompt gösterilmeden).
- Tüm uygulamalar integrity check'i görebilir.
- Hiçbir app ACL'leri değiştiremez.
- **partitionID** `apple` olarak ayarlanır.

**Bir uygulama Keychain'de bir entry oluşturduğunda** kurallar biraz farklıdır:<sup>[1]</sup>

- Tüm uygulamalar encrypt edebilir.
- Yalnızca **entry'yi oluşturan uygulama** (veya açıkça eklenen diğer uygulamalar) export/decrypt edebilir (kullanıcıya prompt gösterilmeden).
- Tüm uygulamalar integrity check'i görebilir.
- Hiçbir app ACL'leri değiştiremez.
- **partitionID** `teamid:[teamID here]` olarak ayarlanır.

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
> **prompt oluşturmayacak** secret'ların **keychain enumeration ve dumping** işlemleri [**LockSmith**](https://github.com/its-a-feature/LockSmith) aracıyla yapılabilir.
>
> Diğer API endpoint'leri [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) source code içinde bulunabilir.

**Security Framework** kullanarak her keychain entry'sini listeleyin ve **info** alın veya Apple'ın open source cli tool'u [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**'yi** de inceleyebilirsiniz. Bazı API örnekleri:<sup>[1]</sup>

- **`SecItemCopyMatching`** API'si her entry hakkında bilgi verir ve kullanılırken ayarlayabileceğiniz bazı attribute'lar vardır:
- **`kSecReturnData`**: True ise data'yı decrypt etmeyi dener (olası pop-up'ları önlemek için false olarak ayarlayın)
- **`kSecReturnRef`**: keychain item'a ait reference'ı da alır (daha sonra pop-up olmadan decrypt edebildiğinizi görürseniz true olarak ayarlayın)
- **`kSecReturnAttributes`**: Entry'ler hakkında metadata alır
- **`kSecMatchLimit`**: Döndürülecek sonuç sayısı
- **`kSecClass`**: Keychain entry'sinin türü

Her entry'nin **ACL**'lerini alın:<sup>[1]</sup>

- **`SecAccessCopyACLList`** API'si ile **keychain item için ACL** alabilirsiniz. Bu API, daha önce bahsedilen `ACLAuhtorizationExportClear` ve diğerleri gibi ACL'lerden oluşan bir liste döndürür; her listede şunlar bulunur:
- Description
- **Trusted Application List**. Şunlardan biri olabilir:
- Bir app: /Applications/Slack.app
- Bir binary: /usr/libexec/airportd
- Bir group: group://AirPort

Data'yı export edin:<sup>[1]</sup>

- **`SecKeychainItemCopyContent`** API'si plaintext'i alır
- **`SecItemExport`** API'si key'leri ve certificate'ları export eder; ancak içeriği encrypted olarak export etmek için password ayarlamanız gerekebilir

Bunlar, bir secret'ı prompt olmadan **export edebilmek** için gerekenlerdir:<sup>[1]</sup>

- **1 veya daha fazla trusted** app listelenmişse:
- Uygun **authorizations** gereklidir (**`Nil`** olmalı veya secret info'ya erişim için authorization içindeki izin verilen app'ler listesinin **parçası** olmalısınız)
- Code signature'ın **PartitionID** ile eşleşmesi gerekir
- Code signature'ın **trusted app**'lerden birininkiyle eşleşmesi gerekir (veya doğru KeychainAccessGroup'un üyesi olmanız gerekir)
- **Tüm application'lar trusted** ise:
- Uygun **authorizations** gereklidir
- Code signature'ın **PartitionID** ile eşleşmesi gerekir
- **PartitionID** yoksa buna gerek yoktur

> [!CAUTION]
> Bu nedenle, listede **1 application** varsa, o application'a **code inject** etmeniz gerekir.
>
> **apple**, **partitionID** içinde belirtilmişse, ona **`osascript`** ile erişebilirsiniz; yani **partitionID** içinde apple bulunan tüm application'lara güveniliyorsa bu mümkündür. Bunun için **`Python`** da kullanılabilir.

### İki ek attribute

- **Invisible**: Entry'yi **UI** Keychain app'inden **gizlemek** için kullanılan boolean flag'dir<sup>[1]</sup>
- **General**: **Metadata** depolamak içindir (yani **ENCRYPTED DEĞİLDİR**)<sup>[1]</sup>
- Microsoft, sensitive endpoint'e erişmek için kullanılan tüm refresh token'ları plain text olarak depoluyordu.<sup>[1]</sup>

## References

- [1] [#OBTS v5.0: "macOS Keychain'de Lock Picking" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
