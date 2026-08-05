# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

Bir XPC service'a bağlantı kurulduğunda, server bağlantıya izin verilip verilmediğini kontrol eder. Genellikle gerçekleştireceği kontroller şunlardır:

1. Bağlanan **process'in Apple tarafından imzalanmış** bir sertifikayla (yalnızca Apple tarafından verilen) imzalanıp imzalanmadığını kontrol eder.
- Bu **doğrulanmazsa**, saldırgan diğer kontrollerle eşleşen **sahte bir sertifika** oluşturabilir.
2. Bağlanan process'in **kuruluşun sertifikasıyla** imzalanıp imzalanmadığını (team ID verification) kontrol eder.
- Bu **doğrulanmazsa**, Apple tarafından verilen **herhangi bir developer certificate** imzalama ve service'a bağlanma amacıyla kullanılabilir.
3. Bağlanan process'in **uygun bir bundle ID** içerip içermediğini kontrol eder.
- Bu **doğrulanmazsa**, **aynı kuruluş tarafından imzalanmış** herhangi bir araç XPC service ile etkileşim kurmak için kullanılabilir.
4. (4 veya 5) Bağlanan process'in **uygun bir software version number** içerip içermediğini kontrol eder.
- Bu **doğrulanmazsa**, process injection'a karşı savunmasız eski ve güvensiz client'lar, diğer kontroller mevcut olsa bile XPC service'a bağlanmak için kullanılabilir.
5. (4 veya 5) Bağlanan process'in, tehlikeli entitlements olmadan (rastgele library'ler yüklemeye veya DYLD env vars kullanmaya izin verenler gibi) hardened runtime kullanıp kullanmadığını kontrol eder.
1. Bu **doğrulanmazsa**, client **code injection'a karşı savunmasız** olabilir.
6. Bağlanan process'in service'a bağlanmasına izin veren bir **entitlement** içerip içermediğini kontrol eder. Bu, Apple binary'leri için geçerlidir.
7. **Verification**, process ID'si (**PID**) yerine bağlanan **client'ın audit token'ına** dayanmalıdır; çünkü ikincisi **PID reuse attack'larını** önler.
- Developer'lar **audit token** API çağrısını, **private** olduğu ve Apple'ın herhangi bir zamanda değiştirebileceği için **nadiren kullanır**. Ayrıca private API kullanımı Mac App Store uygulamalarında yasaktır.
- **`processIdentifier`** method'u kullanılırsa savunmasız olabilir.
- **`xpc_connection_get_audit_token`** yerine **`xpc_dictionary_get_audit_token`** kullanılmalıdır; çünkü ilki belirli durumlarda [savunmasız olabilir](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[5]</sup>

### Communication Attacks

PID reuse attack hakkında daha fazla bilgi için:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

**`xpc_connection_get_audit_token`** attack hakkında daha fazla bilgi için:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Downgrade Attacks Prevention

Trustcache, Apple Silicon makinelerinde tanıtılan ve yalnızca izin verilen, değiştirilmemiş binary'lerin çalıştırılabilmesi için Apple binary'lerinin CDHSAH değerlerinden oluşan bir veritabanı depolayan savunma yöntemidir. Bu, downgrade edilmiş sürümlerin çalıştırılmasını önler.

### Code Examples

Server bu **verification** işlemini **`shouldAcceptNewConnection`** adlı bir function içinde gerçekleştirecektir.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
NSXPCConnection nesnesi **özel** bir **`auditToken`** özelliğine (kullanılması gereken ancak değişebilecek olan) ve **genel** bir **`processIdentifier`** özelliğine (kullanılmaması gereken) sahiptir.

Bağlanan süreç şu şekilde doğrulanabilir:<sup>[1][2][3]</sup>
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
Bir geliştirici istemcinin sürümünü kontrol etmek istemiyorsa, en azından istemcinin process injection'a karşı savunmasız olmadığını kontrol edebilir:
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
Yukarıdaki `cs_*` sabitleri, XNU'nun `osfmk/kern/cs_blobs.h` dosyasında tanımlanan code-signing flag'leridir; bu nedenle tahmin edilmek yerine kaynak koda karşı kontrol edilebilirler:<sup>[4]</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## Referanslar

- [1] [Apple Developer — Code Signing Requirement Language](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../../../banners/hacktricks-training.md}}
