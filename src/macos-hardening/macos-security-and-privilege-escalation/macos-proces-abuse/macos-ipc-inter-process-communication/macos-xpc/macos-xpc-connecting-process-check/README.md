# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

Bir XPC service'e bağlantı kurulduğunda, server bağlantıya izin verilip verilmediğini kontrol eder. Genellikle gerçekleştireceği kontroller şunlardır:

1. Bağlanan **process'in Apple-signed** bir certificate ile imzalanıp imzalanmadığını kontrol eder (yalnızca Apple tarafından verilir).
- Bu **doğrulanmazsa**, bir attacker diğer kontrollerle eşleşen **fake certificate** oluşturabilir.
2. Bağlanan process'in **organization’s certificate** ile imzalanıp imzalanmadığını kontrol eder (team ID verification).
- Bu **doğrulanmazsa**, Apple tarafından verilen **herhangi bir developer certificate** signing için kullanılabilir ve service'e bağlantı kurulabilir.
3. Bağlanan process'in **proper bundle ID** içerip içermediğini kontrol eder.
- Bu **doğrulanmazsa**, **aynı org tarafından imzalanmış** herhangi bir tool XPC service ile etkileşim kurmak için kullanılabilir.
4. (4 veya 5) Bağlanan process'in **proper software version number** değerine sahip olup olmadığını kontrol eder.
- Bu **doğrulanmazsa**, process injection'a karşı vulnerable olan eski ve insecure bir client, diğer kontroller mevcut olsa bile XPC service'e bağlanmak için kullanılabilir.
5. (4 veya 5) Bağlanan process'in dangerous entitlements olmadan hardened runtime kullanıp kullanmadığını kontrol eder (arbitrary libraries yüklemeye veya DYLD env vars kullanmaya izin verenler gibi).
1. Bu **doğrulanmazsa**, client **code injection'a karşı vulnerable** olabilir.
6. Bağlanan process'in service'e bağlanmasına izin veren bir **entitlement** içerip içermediğini kontrol eder. Bu, Apple binaries için geçerlidir.
7. **verification**, process ID'sine (**PID**) dayanmak **yerine**, bağlanan **client’ın audit token'ı** temel alınarak yapılmalıdır; çünkü ilki **PID reuse attacks**'i önler.
- Developer'lar **audit token** API call'unu, **private** olduğu için **nadiren kullanır**; dolayısıyla Apple bunu herhangi bir zamanda **değiştirebilir**. Ayrıca private API kullanımı Mac App Store apps için izinli değildir.
- **`processIdentifier`** method'u kullanılırsa vulnerable olabilir.
- **`xpc_connection_get_audit_token`** yerine **`xpc_dictionary_get_audit_token`** kullanılmalıdır; çünkü ikincisi bazı durumlarda [vulnerable olabilir](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

### Communication Attacks

PID reuse attack hakkında daha fazla bilgi için:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

**`xpc_connection_get_audit_token`** attack check hakkında daha fazla bilgi için:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Downgrade Attacks Prevention

Trustcache, Apple Silicon makinelerinde tanıtılan ve Apple binaries'lerinin CDHSAH veritabanını depolayan bir defensive method'dur; böylece yalnızca izin verilen ve modify edilmemiş binaries execute edilebilir. Bu, downgrade edilmiş version'ların execute edilmesini önler.

### Code Examples

Server bu **verification** işlemini **`shouldAcceptNewConnection`** adlı bir function içinde gerçekleştirir.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
`NSXPCConnection` nesnesi, **private** bir **`auditToken`** özelliğine (kullanılması gereken özellik budur, ancak private API değişebilir) ve authentication için kullanılmaması gereken **public** bir **`processIdentifier`** özelliğine sahiptir.

Bağlantı kuran process aşağıdakine benzer bir yöntemle doğrulanabilir:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
Bir developer, client'ın sürümünü kontrol etmek istemiyorsa en azından client'ın process injection'a karşı savunmasız olmadığını kontrol edebilir:
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
Yukarıdaki `cs_*` sabitleri, XNU'nun `osfmk/kern/cs_blobs.h` dosyasında tanımlanan kod imzalama bayraklarıdır; bu nedenle tahmin edilmek yerine kaynakla karşılaştırılarak kontrol edilebilir:<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## References

- [1] [Apple Developer — Kod İmzalama Gereksinimi Dili](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` kod imzalama bayrakları)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
{{#include ../../../../../../banners/hacktricks-training.md}}
