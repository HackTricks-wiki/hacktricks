# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

Wanneer 'n verbinding met 'n XPC service gevestig word, sal die server kontroleer of die verbinding toegelaat word. Dit is die kontroles wat dit gewoonlik sal uitvoer:

1. Kontroleer of die verbindende **process met 'n Apple-signed** sertifikaat onderteken is (slegs deur Apple uitgereik).
- Indien dit **nie geverifieer word nie**, kan 'n aanvaller 'n **fake certificate** skep om by enige ander kontrole te pas.
2. Kontroleer of die verbindende process met die **organisasie se sertifikaat** onderteken is, (team ID verification).
- Indien dit **nie geverifieer word nie**, kan **enige developer certificate** van Apple vir signing gebruik word om aan die service te koppel.
3. Kontroleer of die verbindende process 'n **proper bundle ID** bevat.
- Indien dit **nie geverifieer word nie**, kan enige tool wat deur dieselfde organisasie **signed** is, gebruik word om met die XPC service te interaksie.
4. (4 of 5) Kontroleer of die verbindende process 'n **proper software version number** het.
- Indien dit **nie geverifieer word nie**, kan 'n ou, onveilige client wat kwesbaar is vir process injection, gebruik word om aan die XPC service te koppel, selfs wanneer die ander kontroles in plek is.
5. (4 of 5) Kontroleer of die verbindende process hardened runtime het sonder gevaarlike entitlements (soos dié wat dit toelaat om arbitrêre libraries te laai of DYLD env vars te gebruik)
1. Indien dit **nie geverifieer word nie,** kan die client **kwesbaar wees vir code injection**
6. Kontroleer of die verbindende process 'n **entitlement** het wat dit toelaat om aan die service te koppel. Dit is van toepassing op Apple binaries.
7. Die **verification** moet **gebaseer** wees op die verbindende **client se audit token** **eerder** as sy process ID (**PID**), aangesien eersgenoemde **PID reuse attacks** voorkom.
- Developers **gebruik selde die audit token** API call, aangesien dit **private** is, en Apple dit dus enige tyd kan **verander**. Daarbenewens word die gebruik van private API's nie in Mac App Store-apps toegelaat nie.
- Indien die **`processIdentifier`**-metode gebruik word, kan dit kwesbaar wees
- **`xpc_dictionary_get_audit_token`** moet eerder as **`xpc_connection_get_audit_token`** gebruik word, aangesien laasgenoemde ook in [sekere situasies kwesbaar](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/) kan wees.<sup>[[5]](#references)</sup>

### Communication Attacks

Vir meer inligting oor die PID reuse attack, kyk na:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Vir meer inligting oor die **`xpc_connection_get_audit_token`** attack, kyk na:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Downgrade Attacks Prevention

Trustcache is 'n defensive method wat in Apple Silicon-masjiene bekendgestel is en 'n database van CDHSAH van Apple binaries stoor sodat slegs toegelate, nie-gemodifiseerde binaries uitgevoer kan word. Dit voorkom die uitvoering van downgrade versions.

### Code Examples

Die server sal hierdie **verification** implementeer in 'n funksie genaamd **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Die `NSXPCConnection`-objek het ’n **private** **`auditToken`**-eienskap (die een wat gebruik behoort te word, hoewel ’n private API kan verander) en ’n **publieke** **`processIdentifier`**-eienskap (wat nie vir authentication gebruik behoort te word nie).

Die verbindende proses kan met iets soos die volgende geverifieer word:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
As ’n developer nie die weergawe van die client wil nagaan nie, kan hy ten minste nagaan dat die client nie kwesbaar is vir process injection nie:
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
Die `cs_*`-konstantes hierbo is die code-signing flags wat in XNU se `osfmk/kern/cs_blobs.h` gedefinieer word, sodat hulle teen die bron nagegaan kan word eerder as om dit te raai:<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## References

- [1] [Apple Developer — Taal vir Code Signing Requirements](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
{{#include ../../../../../../banners/hacktricks-training.md}}
