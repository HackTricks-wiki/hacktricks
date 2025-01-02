# macOS XPC Bağlantı Süreci Kontrolü

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Bağlantı Süreci Kontrolü

Bir XPC hizmetine bağlantı kurulduğunda, sunucu bağlantının izinli olup olmadığını kontrol eder. Genellikle gerçekleştireceği kontroller şunlardır:

1. Bağlanan **sürecin Apple imzalı** bir sertifika ile imzalanıp imzalanmadığını kontrol et.
- Eğer bu **doğrulanmazsa**, bir saldırgan **sahte bir sertifika** oluşturarak diğer kontrollerle eşleşebilir.
2. Bağlanan sürecin **kuruluşun sertifikası** ile imzalanıp imzalanmadığını kontrol et (takım ID doğrulaması).
- Eğer bu **doğrulanmazsa**, Apple'dan alınan **herhangi bir geliştirici sertifikası** imzalamak için kullanılabilir ve hizmete bağlanabilir.
3. Bağlanan sürecin **uygun bir paket kimliğine** sahip olup olmadığını kontrol et.
- Eğer bu **doğrulanmazsa**, aynı kuruluş tarafından **imzalanmış herhangi bir araç** XPC hizmeti ile etkileşimde bulunmak için kullanılabilir.
4. (4 veya 5) Bağlanan sürecin **uygun bir yazılım sürüm numarasına** sahip olup olmadığını kontrol et.
- Eğer bu **doğrulanmazsa**, eski, güvensiz istemciler, süreç enjeksiyonuna karşı savunmasız olarak XPC hizmetine bağlanmak için kullanılabilir, diğer kontroller mevcut olsa bile.
5. (4 veya 5) Bağlanan sürecin tehlikeli yetkilendirmeleri olmayan **sertleştirilmiş çalışma zamanı** olup olmadığını kontrol et (örneğin, rastgele kütüphanelerin yüklenmesine veya DYLD env vars kullanmaya izin verenler gibi).
1. Eğer bu **doğrulanmazsa**, istemci **kod enjeksiyonuna karşı savunmasız** olabilir.
6. Bağlanan sürecin hizmete bağlanmasına izin veren bir **yetkilendirme** olup olmadığını kontrol et. Bu, Apple ikili dosyaları için geçerlidir.
7. **Doğrulama**, bağlanan **istemcinin denetim belirtecine** **dayanmalıdır** ve süreç kimliğine (**PID**) **değil** çünkü ilki **PID yeniden kullanım saldırılarını** önler.
- Geliştiriciler **denetim belirteci** API çağrısını nadiren kullanır çünkü bu **özel**dir, bu nedenle Apple istediği zaman **değiştirebilir**. Ayrıca, özel API kullanımı Mac App Store uygulamalarında yasaklanmıştır.
- **`processIdentifier`** yöntemi kullanılıyorsa, savunmasız olabilir.
- **`xpc_dictionary_get_audit_token`** yerine **`xpc_connection_get_audit_token`** kullanılmalıdır, çünkü sonuncusu da [belirli durumlarda savunmasız olabilir](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### İletişim Saldırıları

PID yeniden kullanım saldırısı hakkında daha fazla bilgi için kontrol edin:

{{#ref}}
macos-pid-reuse.md
{{#endref}}

**`xpc_connection_get_audit_token`** saldırısı hakkında daha fazla bilgi için kontrol edin:

{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Aşağı Dönüş Saldırıları Önleme

Trustcache, yalnızca izin verilen değiştirilmemiş ikili dosyaların çalıştırılmasını sağlayan Apple Silicon makinelerinde tanıtılan bir savunma yöntemidir. Bu, aşağı sürüm versiyonlarının çalıştırılmasını önler.

### Kod Örnekleri

Sunucu bu **doğrulamayı** **`shouldAcceptNewConnection`** adlı bir işlevde uygulayacaktır.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
NSXPCConnection nesnesinin **özel** bir özelliği **`auditToken`** (kullanılması gereken ama değişebilecek olan) ve **genel** bir özelliği **`processIdentifier`** (kullanılmaması gereken) vardır.

Bağlanan süreç, şöyle bir şeyle doğrulanabilir:
```objectivec
[...]
SecRequirementRef requirementRef = NULL;
NSString requirementString = @"anchor apple generic and identifier \"xyz.hacktricks.service\" and certificate leaf [subject.CN] = \"TEAMID\" and info [CFBundleShortVersionString] >= \"1.0\"";
/* Check:
- Signed by a cert signed by Apple
- Check the bundle ID
- Check the TEAMID of the signing cert
- Check the version used
*/

// Check the requirements with the PID (vulnerable)
SecRequirementCreateWithString(requirementString, kSecCSDefaultFlags, &requirementRef);
SecCodeCheckValidity(code, kSecCSDefaultFlags, requirementRef);

// Check the requirements wuing the auditToken (secure)
SecTaskRef taskRef = SecTaskCreateWithAuditToken(NULL, ((ExtendedNSXPCConnection*)newConnection).auditToken);
SecTaskValidateForRequirement(taskRef, (__bridge CFStringRef)(requirementString))
```
Eğer bir geliştirici istemcinin sürümünü kontrol etmek istemiyorsa, en azından istemcinin işlem enjeksiyonuna karşı savunmasız olmadığını kontrol edebilir:
```objectivec
[...]
CFDictionaryRef csInfo = NULL;
SecCodeCopySigningInformation(code, kSecCSDynamicInformation, &csInfo);
uint32_t csFlags = [((__bridge NSDictionary *)csInfo)[(__bridge NSString *)kSecCodeInfoStatus] intValue];
const uint32_t cs_hard = 0x100;        // don't load invalid page.
const uint32_t cs_kill = 0x200;        // Kill process if page is invalid
const uint32_t cs_restrict = 0x800;    // Prevent debugging
const uint32_t cs_require_lv = 0x2000; // Library Validation
const uint32_t cs_runtime = 0x10000;   // hardened runtime
if ((csFlags & (cs_hard | cs_require_lv)) {
return Yes; // Accept connection
}
```
{{#include ../../../../../../banners/hacktricks-training.md}}
