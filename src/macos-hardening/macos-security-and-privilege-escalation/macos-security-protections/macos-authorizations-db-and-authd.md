# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Yetkilendirmeler DB**

`/var/db/auth.db` konumundaki veritabanı, hassas işlemleri gerçekleştirme izinlerini depolamak için kullanılır. Bu işlemler tamamen **user space** içinde gerçekleştirilir ve genellikle, **çağıran istemcinin** bu veritabanını kontrol ederek belirli bir eylemi gerçekleştirme yetkisine sahip olup olmadığını denetlemesi gereken **XPC services** tarafından kullanılır.

Başlangıçta bu veritabanı, `/System/Library/Security/authorization.plist` içeriğinden oluşturulur. Ardından bazı servisler, başka izinler eklemek için bu veritabanına veri ekleyebilir veya verileri değiştirebilir.

Kurallar, veritabanındaki `rules` tablosunda saklanır ve aşağıdaki sütunları içerir:

- **id**: Her kural için otomatik olarak artırılan ve birincil anahtar olarak kullanılan benzersiz tanımlayıcı.
- **name**: Yetkilendirme sistemi içinde kuralı tanımlamak ve referans vermek için kullanılan benzersiz kural adı.
- **type**: Kuralın türünü belirtir; yetkilendirme mantığını tanımlamak için 1 veya 2 değerleriyle sınırlıdır.
- **class**: Kuralı belirli bir sınıfa kategorize eder ve pozitif bir tamsayı olmasını sağlar.
- "allow" izin vermek, "deny" reddetmek, `group` özelliği üyeliği erişime izin veren bir grubu belirtiyorsa "user", bir dizide karşılanması gereken bir kuralı belirtmek için "rule", ardından yerleşik değerler veya `/System/Library/CoreServices/SecurityAgentPlugins/` ya da `/Library/Security//SecurityAgentPlugins` içindeki bir bundle adı olan `mechanisms` dizisiyle birlikte "evaluate-mechanisms"
- **group**: Grup tabanlı yetkilendirme için kuralla ilişkili kullanıcı grubunu belirtir.
- **kofn**: Toplam kural sayısı içinden kaç alt kuralın karşılanması gerektiğini belirleyen "k-of-n" parametresini temsil eder.
- **timeout**: Kural tarafından verilen yetkilendirmenin sona ermesinden önce geçecek süreyi saniye cinsinden tanımlar.
- **flags**: Kuralın davranışını ve özelliklerini değiştiren çeşitli flag'leri içerir.
- **tries**: Güvenliği artırmak için izin verilen yetkilendirme denemelerinin sayısını sınırlar.
- **version**: Sürüm kontrolü ve güncellemeler için kuralın sürümünü takip eder.
- **created**: Denetim amacıyla kuralın oluşturulduğu zaman damgasını kaydeder.
- **modified**: Kuralda yapılan son değişikliğin zaman damgasını saklar.
- **hash**: Kuralın bütünlüğünü doğrulamak ve kurcalamayı tespit etmek için kuralın hash değerini içerir.
- **identifier**: Kural için UUID gibi harici referanslarda kullanılan benzersiz bir dize tanımlayıcı sağlar.
- **requirement**: Kuralın özel yetkilendirme gereksinimlerini ve mekanizmalarını tanımlayan serileştirilmiş verileri içerir.
- **comment**: Belgeleme ve açıklık amacıyla kural hakkında insanlar tarafından okunabilir bir açıklama veya yorum sunar.

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
Ayrıca [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) adresinde `authenticate-admin-nonshared` ifadesinin anlamını görmek mümkündür:<sup>[1]</sup>
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

Hassas eylemleri gerçekleştirmek üzere istemcileri yetkilendirmek için gelen istekleri alan bir daemon'dur. `XPCServices/` klasörü içinde tanımlanan bir XPC service olarak çalışır ve loglarını `/var/log/authd.log` dosyasına yazar.

Ayrıca `security` tool'u kullanılarak birçok `Security.framework` API'si test edilebilir. Örneğin `AuthorizationExecuteWithPrivileges` şu şekilde çalıştırılabilir: `security execute-with-privileges /bin/ls`

Bu işlem, `/bin/ls` komutunu root olarak çalıştırmak üzere `/usr/libexec/security_authtrampoline /bin/ls` dosyasını fork edip exec eder ve ls komutunu root olarak çalıştırmak için bir izin istemi görüntüler:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - macOS Authorization Right'a Genel Bakış](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)

{{#include ../../../banners/hacktricks-training.md}}
