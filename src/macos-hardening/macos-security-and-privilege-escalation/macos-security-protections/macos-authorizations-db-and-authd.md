# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Yetkilendirmeler DB**

`/var/db/auth.db` konumundaki database, hassas işlemleri gerçekleştirme izinlerini depolamak için kullanılan database'dir. Bu işlemler tamamen **user space** içinde gerçekleştirilir ve genellikle **XPC services** tarafından, bu database'i kontrol ederek **calling client'ın** belirli bir eylemi gerçekleştirmeye yetkili olup olmadığını doğrulamak için kullanılır.

Başlangıçta bu database, `/System/Library/Security/authorization.plist` içeriğinden oluşturulur. Ardından bazı servisler, başka izinler eklemek için bu database'e veri ekleyebilir veya verileri değiştirebilir.

Kurallar, database içindeki `rules` tablosunda saklanır ve aşağıdaki sütunları içerir:

- **id**: Her kural için otomatik olarak artırılan ve primary key olarak kullanılan benzersiz bir identifier.
- **name**: Authorization system içinde kuralı tanımlamak ve referans göstermek için kullanılan benzersiz kural adı.
- **type**: Authorization logic'i tanımlamak üzere 1 veya 2 değerleriyle sınırlı olan kural türünü belirtir.
- **class**: Kuralı belirli bir class içinde kategorize eder ve pozitif bir integer olmasını gerektirir.
- "allow" izin verme, "deny" reddetme, `group` özelliği erişime izin veren bir grubu belirtiyorsa "user", karşılanması gereken bir kuralı array içinde belirtmek için "rule", ardından `mechanisms` array'i gelen "evaluate-mechanisms"; bu array'deki değerler ya builtins ya da `/System/Library/CoreServices/SecurityAgentPlugins/` veya `/Library/Security//SecurityAgentPlugins` içindeki bir bundle adıdır.
- **group**: Group-based authorization için kuralla ilişkili user group'u belirtir.
- **kofn**: Toplam bir sayı içinden kaç alt kuralın karşılanması gerektiğini belirleyen "k-of-n" parametresini temsil eder.
- **timeout**: Kural tarafından verilen authorization'ın süresi dolmadan önce geçecek saniye cinsinden süreyi tanımlar.
- **flags**: Kuralın davranışını ve özelliklerini değiştiren çeşitli flag'leri içerir.
- **tries**: Güvenliği artırmak için izin verilen authorization denemelerinin sayısını sınırlar.
- **version**: Version control ve güncellemeler için kuralın sürümünü takip eder.
- **created**: Denetim amacıyla kuralın oluşturulduğu timestamp'i kaydeder.
- **modified**: Kuralda yapılan son değişikliğin timestamp'ini saklar.
- **hash**: Kuralın bütünlüğünü sağlamak ve kurcalamayı tespit etmek için kuralın hash değerini tutar.
- **identifier**: Kuralın harici referansları için UUID gibi benzersiz bir string identifier sağlar.
- **requirement**: Kuralın belirli authorization gereksinimlerini ve mekanizmalarını tanımlayan serialized verileri içerir.
- **comment**: Documentation ve açıklık amacıyla kural hakkında human-readable bir açıklama veya yorum sunar.

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

Hassas işlemleri gerçekleştirmeleri için istemcileri yetkilendirme isteklerini alan bir daemon'dur. `XPCServices/` klasörü içinde tanımlanmış bir XPC service olarak çalışır ve loglarını `/var/log/authd.log` dosyasına yazar.

Ayrıca `security` tool kullanılarak birçok `Security.framework` API'si test edilebilir. Örneğin, `AuthorizationExecuteWithPrivileges` şu şekilde çalıştırılabilir: `security execute-with-privileges /bin/ls`

Bu işlem, `/bin/ls` komutunu root olarak çalıştırmak üzere `/usr/libexec/security_authtrampoline /bin/ls` komutunu fork edip exec eder ve root olarak ls çalıştırmak için bir istemde izin ister:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## Referanslar

- [1] [authenticate-admin-nonshared - macOS Authorization Right'a Genel Bakış](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)

{{#include ../../../banners/hacktricks-training.md}}
