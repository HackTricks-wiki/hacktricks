# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Yetkilendirmeler DB**

`/var/db/auth.db` konumunda bulunan veritabanı, hassas işlemleri gerçekleştirme izinlerini depolamak için kullanılan veritabanıdır. Bu işlemler tamamen **user space** içinde gerçekleştirilir ve genellikle, bu veritabanını kontrol ederek **calling client**'ın belirli bir eylemi gerçekleştirme konusunda **authorized** olup olmadığını denetlemesi gereken **XPC services** tarafından kullanılır.

Başlangıçta bu veritabanı, `/System/Library/Security/authorization.plist` içeriğinden oluşturulur. Ardından bazı servisler, başka izinler eklemek için bu veritabanındaki verileri ekleyebilir veya değiştirebilir.

Kurallar, veritabanındaki `rules` tablosunda depolanır ve aşağıdaki sütunları içerir:

- **id**: Her kural için otomatik olarak artırılan ve primary key olarak kullanılan benzersiz tanımlayıcı.
- **name**: Authorization system içinde kuralı tanımlamak ve referans vermek için kullanılan benzersiz ad.
- **type**: Authorization logic'i tanımlamak üzere 1 veya 2 değerleriyle sınırlı olan kural türünü belirtir.
- **class**: Kuralı belirli bir sınıfa kategorize eder ve pozitif bir integer olmasını sağlar.
- İzin verme için "allow", reddetme için "deny", `group` özelliği üyeliği erişime izin veren bir grubu belirtiyorsa "user", karşılanması gereken bir kuralı dizi içinde belirtiyorsa "rule", ardından `mechanisms` array'i gelen "evaluate-mechanisms"; bu array'deki değerler ya builtins ya da `/System/Library/CoreServices/SecurityAgentPlugins/` veya `/Library/Security//SecurityAgentPlugins` içindeki bir bundle adıdır.
- **group**: Group-based authorization için kuralla ilişkili user group'u belirtir.
- **kofn**: Toplam sayının kaç alt kuralından kaçının karşılanması gerektiğini belirleyen "k-of-n" parametresini temsil eder.
- **timeout**: Kural tarafından verilen authorization'ın süresi dolmadan önce geçecek saniye cinsinden süreyi tanımlar.
- **flags**: Kuralın davranışını ve özelliklerini değiştiren çeşitli flag'leri içerir.
- **tries**: Security'yi artırmak için izin verilen authorization denemelerinin sayısını sınırlar.
- **version**: Version control ve güncellemeler için kuralın sürümünü takip eder.
- **created**: Auditing amacıyla kuralın oluşturulduğu timestamp'i kaydeder.
- **modified**: Kuralda yapılan son değişikliğin timestamp'ini depolar.
- **hash**: Kuralın bütünlüğünü sağlamak ve kurcalamayı tespit etmek için kuralın hash değerini içerir.
- **identifier**: Kuralın external reference'ları için UUID gibi benzersiz bir string identifier sağlar.
- **requirement**: Kuralın belirli authorization gereksinimlerini ve mekanizmalarını tanımlayan serialized data içerir.
- **comment**: Documentation ve clarity amacıyla kural hakkında human-readable bir açıklama veya comment sunar.

### Örnek
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
Ayrıca [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) adresinde `authenticate-admin-nonshared` ifadesinin anlamını görmek mümkündür:<sup>[[1]](#references)</sup>
```json
{
"allow-root": "false",
"authenticate-user": "true",
"class": "user",
"comment": "Authenticate as an administrator.",
"group": "admin",
"session-owner": "false",
"shared": "false",
"timeout": "30",
"tries": "10000",
"version": "1"
}
```
## Authd

Hassas eylemleri gerçekleştirmek üzere client'ları authorize etmek için gelen istekleri alan bir daemon'dur. `XPCServices/` klasörü içinde tanımlanan bir XPC service olarak çalışır ve log'larını `/var/log/authd.log` dosyasına yazar.

Ayrıca security tool kullanılarak birçok `Security.framework` API'si test edilebilir. Örneğin `AuthorizationExecuteWithPrivileges` şu şekilde çalıştırılabilir: `security execute-with-privileges /bin/ls`

Bu işlem, `/usr/libexec/security_authtrampoline /bin/ls` komutunu root olarak fork ve exec eder; ardından ls'yi root olarak çalıştırmak için bir prompt üzerinden izin ister:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Overview of the macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)


{{#include ../../../banners/hacktricks-training.md}}
