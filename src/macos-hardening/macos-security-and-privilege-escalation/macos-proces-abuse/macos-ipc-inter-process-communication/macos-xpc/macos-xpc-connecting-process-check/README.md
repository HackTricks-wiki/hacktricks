# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

Bir XPC service'e bağlantı kurulduğunda, server bağlantıya izin verilip verilmediğini kontrol eder. Genellikle gerçekleştireceği kontroller şunlardır:

1. Bağlanan **process'in Apple-signed** bir sertifikayla imzalanıp imzalanmadığını kontrol eder (yalnızca Apple tarafından verilen sertifikalar).
- Bu **doğrulanmazsa**, bir attacker diğer kontrollerle eşleşen **fake certificate** oluşturabilir.
2. Bağlanan process'in **organization’s certificate** ile imzalanıp imzalanmadığını kontrol eder (team ID verification).
- Bu **doğrulanmazsa**, Apple tarafından verilen **herhangi bir developer certificate** signing için kullanılabilir ve service'e bağlanılabilir.
3. Bağlanan process'in **uygun bir bundle ID** içerip içermediğini kontrol eder.
- Bu **doğrulanmazsa**, **aynı organization tarafından imzalanmış** herhangi bir tool XPC service ile etkileşime geçmek için kullanılabilir.
4. (4 veya 5) Bağlanan process'in **uygun bir software version number** içerip içermediğini kontrol eder.
- Bu **doğrulanmazsa,** process injection'a karşı vulnerable olan eski ve insecure client'lar, diğer kontroller mevcut olsa bile XPC service'e bağlanmak için kullanılabilir.
5. (4 veya 5) Bağlanan process'in dangerous entitlements olmadan hardened runtime kullanıp kullanmadığını kontrol eder (arbitrary library yüklemeye veya DYLD env vars kullanmaya izin verenler gibi).
1. Bu **doğrulanmazsa,** client **code injection'a karşı vulnerable** olabilir.
6. Bağlanan process'in service'e bağlanmasına izin veren bir **entitlement** içerip içermediğini kontrol eder. Bu, Apple binaries için geçerlidir.
7. **Verification**, process ID'si (**PID**) yerine bağlanan **client’ın audit token'ı** temel alınarak yapılmalıdır; çünkü ilki **PID reuse attacks**'ı önler.
- Developer'lar **audit token** API call'unu **nadiren kullanır**, çünkü bu API **private**'tır ve Apple bunu herhangi bir zamanda **değiştirebilir**. Ayrıca private API kullanımı Mac App Store uygulamalarında yasaktır.
- **`processIdentifier`** method'u kullanılırsa vulnerable olabilir.
- **`xpc_connection_get_audit_token`** yerine **`xpc_dictionary_get_audit_token`** kullanılmalıdır; çünkü ilki [belirli durumlarda vulnerable olabilir](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

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

Trustcache, Apple Silicon makinelerinde kullanılan ve Apple binaries'lerinin CDHSAH veritabanını depolayan bir defensive method'dur; böylece yalnızca izin verilen, değiştirilmemiş binaries çalıştırılabilir. Bu, downgrade edilmiş version'ların çalıştırılmasını önler.

### Code Examples

Server, bu **verification** işlemini **`shouldAcceptNewConnection`** adlı bir function içinde gerçekleştirecektir.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
NSXPCConnection nesnesi, **private** bir **`auditToken`** özelliğine (kullanılması gereken ancak değişebilecek olan) ve **public** bir **`processIdentifier`** özelliğine (kullanılmaması gereken) sahiptir.

Bağlantı kuran süreç şu şekilde doğrulanabilir:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
Bir geliştirici istemcinin sürümünü kontrol etmek istemiyorsa, en azından istemcinin process injection’a karşı savunmasız olmadığını kontrol edebilir:
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
Yukarıdaki `cs_*` sabitleri, XNU'nun `osfmk/kern/cs_blobs.h` dosyasında tanımlanan kod imzalama bayraklarıdır; bu nedenle tahmin edilmek yerine kaynak kodla karşılaştırılarak kontrol edilebilirler:<sup>[[4]](#references)</sup>
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
