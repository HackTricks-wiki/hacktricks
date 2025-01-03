# macOS Anahtarlık

{{#include ../../banners/hacktricks-training.md}}

## Ana Anahtarlıklar

- **Kullanıcı Anahtarlığı** (`~/Library/Keychains/login.keychain-db`), uygulama şifreleri, internet şifreleri, kullanıcı tarafından oluşturulan sertifikalar, ağ şifreleri ve kullanıcı tarafından oluşturulan açık/özel anahtarlar gibi **kullanıcıya özgü kimlik bilgilerini** saklamak için kullanılır.
- **Sistem Anahtarlığı** (`/Library/Keychains/System.keychain`), WiFi şifreleri, sistem kök sertifikaları, sistem özel anahtarları ve sistem uygulama şifreleri gibi **sistem genelinde kimlik bilgilerini** saklar.
- `/System/Library/Keychains/*` içinde sertifikalar gibi diğer bileşenleri bulmak mümkündür.
- **iOS**'ta `/private/var/Keychains/` konumunda yalnızca bir **Anahtarlık** bulunmaktadır. Bu klasör ayrıca `TrustStore`, sertifika otoriteleri (`caissuercache`) ve OSCP girişleri (`ocspache`) için veritabanlarını içerir.
- Uygulamalar, uygulama tanımlayıcılarına dayalı olarak anahtarlıkta yalnızca özel alanlarına erişimle kısıtlanacaktır.

### Şifre Anahtarlığı Erişimi

Bu dosyalar, doğrudan koruma içermemelerine rağmen **indirilebilir**, şifrelenmiştir ve **şifresiz kullanıcı parolasının çözülmesi** gerekmektedir. [**Chainbreaker**](https://github.com/n0fate/chainbreaker) gibi bir araç şifre çözme için kullanılabilir.

## Anahtarlık Girişi Koruma

### ACL'ler

Anahtarlıkta her giriş, çeşitli eylemleri gerçekleştirebilecek kişileri belirleyen **Erişim Kontrol Listeleri (ACL'ler)** ile yönetilmektedir:

- **ACLAuhtorizationExportClear**: Sahip olanın sıfır metin gizliliğini almasına izin verir.
- **ACLAuhtorizationExportWrapped**: Sahip olanın başka bir sağlanan şifre ile şifrelenmiş sıfır metin almasına izin verir.
- **ACLAuhtorizationAny**: Sahip olanın herhangi bir eylemi gerçekleştirmesine izin verir.

ACL'ler, bu eylemleri istem olmadan gerçekleştirebilecek **güvenilir uygulamalar listesi** ile birlikte gelir. Bu şunlar olabilir:

- **N`il`** (yetki gerektirmeyen, **herkes güvenilir**)
- **Boş** bir liste (**hiç kimse** güvenilir değil)
- Belirli **uygulamaların** **listesi**.

Ayrıca giriş, **`ACLAuthorizationPartitionID`** anahtarını içerebilir; bu, **teamid, apple** ve **cdhash**'i tanımlamak için kullanılır.

- Eğer **teamid** belirtilmişse, **giriş** değerine **istem olmadan** erişmek için kullanılan uygulamanın **aynı teamid**'ye sahip olması gerekir.
- Eğer **apple** belirtilmişse, uygulamanın **Apple** tarafından **imzalanmış** olması gerekir.
- Eğer **cdhash** belirtilmişse, **uygulama** belirli bir **cdhash**'e sahip olmalıdır.

### Anahtarlık Girişi Oluşturma

Bir **yeni** **giriş** **`Keychain Access.app`** kullanılarak oluşturulduğunda, aşağıdaki kurallar geçerlidir:

- Tüm uygulamalar şifreleyebilir.
- **Hiçbir uygulama** dışa aktaramaz/şifre çözemez (kullanıcıyı istemeden).
- Tüm uygulamalar bütünlük kontrolünü görebilir.
- Hiçbir uygulama ACL'leri değiştiremez.
- **partitionID** **`apple`** olarak ayarlanır.

Bir **uygulama anahtarlıkta bir giriş oluşturduğunda**, kurallar biraz farklıdır:

- Tüm uygulamalar şifreleyebilir.
- Sadece **oluşturan uygulama** (veya açıkça eklenen diğer uygulamalar) dışa aktarabilir/şifre çözebilir (kullanıcıyı istemeden).
- Tüm uygulamalar bütünlük kontrolünü görebilir.
- Hiçbir uygulama ACL'leri değiştiremez.
- **partitionID** **`teamid:[teamID burada]`** olarak ayarlanır.

## Anahtarlığa Erişim

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
> **Anahtar zinciri numaralandırma ve gizli bilgilerin dökümü** için **uyarı oluşturmayacak** olanlar, [**LockSmith**](https://github.com/its-a-feature/LockSmith) aracıyla yapılabilir.
>
> Diğer API uç noktaları [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) kaynak kodunda bulunabilir.

Her anahtar zinciri girişi hakkında **bilgi** listeleyin ve alın, **Güvenlik Çerçevesi** kullanarak veya Apple'ın açık kaynaklı cli aracı [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**'yi** kontrol edebilirsiniz. Bazı API örnekleri:

- API **`SecItemCopyMatching`** her giriş hakkında bilgi verir ve kullanırken ayarlayabileceğiniz bazı özellikler vardır:
- **`kSecReturnData`**: Eğer doğruysa, veriyi şifre çözmeye çalışır (potansiyel açılır pencereleri önlemek için yanlış olarak ayarlayın)
- **`kSecReturnRef`**: Anahtar zinciri öğesine referans da alın (daha sonra açılır pencere olmadan şifre çözebileceğinizi görürseniz doğru olarak ayarlayın)
- **`kSecReturnAttributes`**: Girişler hakkında meta verileri alın
- **`kSecMatchLimit`**: Kaç sonuç döndürüleceği
- **`kSecClass`**: Hangi tür anahtar zinciri girişi

Her girişin **ACL'lerini** alın:

- API **`SecAccessCopyACLList`** ile **anahtar zinciri öğesi için ACL** alabilirsiniz ve bu, her liste için:
- Açıklama
- **Güvenilir Uygulama Listesi**. Bu şunlar olabilir:
- Bir uygulama: /Applications/Slack.app
- Bir ikili: /usr/libexec/airportd
- Bir grup: group://AirPort

Verileri dışa aktarın:

- API **`SecKeychainItemCopyContent`** düz metni alır
- API **`SecItemExport`** anahtarları ve sertifikaları dışa aktarır ancak içeriği şifreli olarak dışa aktarmak için şifre ayarlamanız gerekebilir

Ve bu, **uyarı olmadan bir gizli bilgiyi dışa aktarabilmek için** gereken **şartlardır**:

- Eğer **1+ güvenilir** uygulama listelenmişse:
- Uygun **yetkilere** ihtiyaç vardır (**`Nil`**, veya gizli bilgilere erişim için yetkilendirilmiş uygulama listesinde **yer almak**)
- **PartitionID** ile eşleşen kod imzasına ihtiyaç vardır
- Bir **güvenilir uygulama** ile eşleşen kod imzasına ihtiyaç vardır (veya doğru KeychainAccessGroup'un üyesi olmalısınız)
- Eğer **tüm uygulamalar güvenilir** ise:
- Uygun **yetkilere** ihtiyaç vardır
- **PartitionID** ile eşleşen kod imzasına ihtiyaç vardır
- Eğer **PartitionID** yoksa, bu gerekli değildir

> [!CAUTION]
> Bu nedenle, eğer **1 uygulama listelenmişse**, o uygulamaya **kod enjekte etmeniz** gerekir.
>
> Eğer **partitionID** içinde **apple** belirtilmişse, **`osascript`** ile erişebilirsiniz, bu nedenle partitionID içinde apple olan tüm uygulamalara güvenen herhangi bir şey. Bunun için **`Python`** da kullanılabilir.

### İki ek özellik

- **Görünmez**: Bu, girişi **UI** Anahtar Zinciri uygulamasından **gizlemek** için bir boolean bayraktır
- **Genel**: **meta verileri** depolamak içindir (yani ŞİFRELİ DEĞİLDİR)
- Microsoft, hassas uç noktaya erişim için tüm yenileme jetonlarını düz metin olarak saklıyordu.

## References

- [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
