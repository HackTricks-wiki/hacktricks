# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## Authorization Database

Security framework'ünün Authorization Services bileşenleri, ayrıcalıklı yardımcıların ve diğer bileşenlerin adlandırılmış authorization rights değerlerini değerlendirmesine olanak tanır. Güncel macOS sürümlerinde bu kuralların çoğu `/var/db/auth.db` dosyasında kalıcı olarak tutulur ve `authd` tarafından değerlendirilir; bu dosya ve SQLite şeması uygulama ayrıntılarıdır ve sürümler arasında değişebilir.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

System varsayılanları geçmişte `/System/Library/Security/authorization.plist` dosyasından alınarak oluşturulmuştur; installer'lar veya ayrıcalıklı servisler adlandırılmış haklar ekleyebilir. Veritabanını doğrudan düzenlemek yerine desteklenen `security authorizationdb read|write|remove` arayüzünü kullanın.<sup>[[3]](#references)</sup>

Belgelendirilen build'de gözlemlenen `rules` tablosu aşağıdaki sütunları içerir. Bunu sabit bir public schema olarak değil, adli inceleme haritası olarak değerlendirin:

- **id**: Her rule için otomatik olarak artırılan ve primary key olarak kullanılan benzersiz tanımlayıcı.
- **name**: Authorization system içinde rule'u tanımlamak ve referans vermek için kullanılan benzersiz ad.
- **type**: Authorization logic'i tanımlamak üzere 1 veya 2 değerleriyle sınırlı olan rule türünü belirtir.
- **class**: Rule'u belirli bir class içinde kategorize eder ve pozitif bir integer olmasını sağlar.
- Yaygın rule class'ları arasında `allow`, `deny`, `user`, `rule` ve `evaluate-mechanisms` bulunur. Mechanism'ler built-in olabilir veya `/System/Library/CoreServices/SecurityAgentPlugins/` ya da `/Library/Security/SecurityAgentPlugins/` altındaki Security Agent plug-in'leri olabilir.<sup>[[2]](#references)</sup>
- **group**: Group-based authorization için rule ile ilişkili user group'u belirtir.
- **kofn**: Toplam sayı içindeki kaç subrule'un karşılanması gerektiğini belirleyen "k-of-n" parametresini temsil eder.
- **timeout**: Rule tarafından verilen authorization'ın sona ermesinden önce geçecek saniye cinsinden süreyi tanımlar.
- **flags**: Rule'un davranışını ve özelliklerini değiştiren çeşitli flag'leri içerir.
- **tries**: Güvenliği artırmak amacıyla izin verilen authorization denemelerinin sayısını sınırlar.
- **version**: Version control ve güncellemeler için rule'un sürümünü takip eder.
- **created**: Auditing amacıyla rule'un oluşturulduğu timestamp'i kaydeder.
- **modified**: Rule'da yapılan son değişikliğin timestamp'ini saklar.
- **hash**: Bütünlüğünü doğrulamak ve tampering'i tespit etmek için rule'un hash değerini tutar.
- **identifier**: Rule'a dış referanslar için UUID gibi benzersiz bir string identifier sağlar.
- **requirement**: Rule'un belirli authorization gereksinimlerini ve mechanism'lerini tanımlayan serialize edilmiş verileri içerir.
- **comment**: Documentation ve açıklık amacıyla rule hakkında human-readable bir açıklama veya comment sunar.

### Example
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
Aşağıdaki decode edilmiş kural, belgelenmiş bir macOS sürümünde `authenticate-admin-nonshared` özelliğini gösterir:<sup>[[1]](#references)</sup>
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

`authd`, Authorization Services isteklerini değerlendiren XPC service'tir. Güncel macOS derlemelerinde bundle'ı `/System/Library/Frameworks/Security.framework/XPCServices/authd.xpc` konumunda incelenebilir; bu yol bir implementation detail'dir ve sürümlere göre farklılık gösterebilir. Eski sürümlerde `/var/log/authd.log` dosyasına yazılırdı; güncel sürümler ağırlıklı olarak unified logging system'i kullanır ve bu sistem `authd` process predicate'iyle `log show`/`log stream` kullanılarak sorgulanabilir.<sup>[[2]](#references)</sup><sup>[[5]](#references)</sup>

`security` tool'u çeşitli Authorization Services işlemlerini kullanıma sunar. Tarihsel bir örnekte `security execute-with-privileges /bin/ls` ile `AuthorizationExecuteWithPrivileges` çağrılır. Apple bu API'yi macOS 10.7'de deprecated etti; modern privileged helper'lar bunun yerine launchd-managed helper ve XPC authorization kullanmalıdır.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>

Bunu hâlâ destekleyen sürümlerde `/usr/libexec/security_authtrampoline` kullanılır ve komut root olarak çalıştırılmadan önce bir authorization prompt görüntülenir:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - macOS Authorization Right'a Genel Bakış](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)
- [2] [Apple Authorization Services Programming Guide (archive)](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/)
- [3] [`security(1)` macOS manual page](https://keith.github.io/xcode-man-pages/security.1.html)
- [4] [Apple - Daemons and Services Programming Guide: launchd jobs oluşturma](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [5] [Apple open-source Security projesi - `authd`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/authd)
{{#include ../../../banners/hacktricks-training.md}}
