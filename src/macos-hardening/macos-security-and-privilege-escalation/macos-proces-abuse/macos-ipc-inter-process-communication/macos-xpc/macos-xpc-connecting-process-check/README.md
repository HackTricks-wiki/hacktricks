# macOS XPC-verbindende proseskontrole

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC-verbindende proseskontrole

Wanneer 'n verbinding met 'n XPC-diens gevestig word, sal die bediener kontroleer of die verbinding toegelaat word. Dit is die kontroles wat dit gewoonlik uitvoer:

1. Kontroleer of die verbindende **proses met 'n Apple-ondertekende** sertifikaat onderteken is (slegs deur Apple uitgereik).
- As dit **nie geverifieer word nie**, kan 'n aanvaller 'n **vals sertifikaat** skep om by enige ander kontrole te pas.
2. Kontroleer of die verbindende proses met die **organisasie se sertifikaat** onderteken is (team ID-verifikasie).
- As dit **nie geverifieer word nie**, kan **enige ontwikkelaarsertifikaat** van Apple vir ondertekening gebruik word om aan die diens te koppel.
3. Kontroleer of die verbindende proses 'n **korrekte bundle ID** bevat.
- As dit **nie geverifieer word nie**, kan enige hulpmiddel wat **deur dieselfde organisasie onderteken** is, gebruik word om met die XPC-diens te kommunikeer.
4. (4 of 5) Kontroleer of die verbindende proses 'n **korrekte sagtewareweergawenommer** het.
- As dit **nie geverifieer word nie**, kan ou, onveilige kliënte wat kwesbaar is vir process injection, gebruik word om aan die XPC-diens te koppel, selfs wanneer die ander kontroles ingestel is.
5. (4 of 5) Kontroleer of die verbindende proses hardened runtime het sonder gevaarlike entitlements (soos dié wat toelaat dat arbitrêre libraries gelaai word of DYLD env vars gebruik word)
1. As dit **nie geverifieer word nie**, kan die kliënt **kwesbaar wees vir code injection**
6. Kontroleer of die verbindende proses 'n **entitlement** het wat dit toelaat om aan die diens te koppel. Dit is van toepassing op Apple-binaries.
7. Die **verifikasie** moet **gebaseer** wees op die verbindende **kliënt se audit token** **eerder** as sy proses-ID (**PID**), aangesien eersgenoemde **PID reuse attacks** voorkom.
- Ontwikkelaars **gebruik selde die audit token** API-call, aangesien dit **privaat** is, en Apple dit enige tyd kan **verander**. Daarbenewens word die gebruik van private API's nie in Mac App Store-apps toegelaat nie.
- As die **`processIdentifier`**-metode gebruik word, kan dit kwesbaar wees
- **`xpc_dictionary_get_audit_token`** moet eerder as **`xpc_connection_get_audit_token`** gebruik word, aangesien laasgenoemde ook [in sekere situasies kwesbaar kan wees](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[5]</sup>

### Kommunikasie-aanvalle

Vir meer inligting oor die PID reuse attack-kontrole:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Vir meer inligting oor die **`xpc_connection_get_audit_token`** attack-kontrole:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Voorkoming van downgrade attacks

Trustcache is 'n defensiewe metode wat op Apple Silicon-masjiene bekendgestel is en 'n databasis van CDHSAH van Apple-binaries stoor, sodat slegs toegelate, ongemodifiseerde binaries uitgevoer kan word. Dit voorkom die uitvoering van downgrade-weergawes.

### Kodevoorbeelde

Die bediener sal hierdie **verifikasie** implementeer in 'n funksie genaamd **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Die objek NSXPCConnection het ’n **private** eienskap **`auditToken`** (die een wat gebruik behoort te word, maar kan verander) en ’n **public** eienskap **`processIdentifier`** (die een wat nie gebruik behoort te word nie).

Die verbindende proses kan met iets soos die volgende geverifieer word:<sup>[1][2][3]</sup>
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
As 'n developer nie die weergawe van die client wil nagaan nie, kan hy ten minste nagaan dat die client nie kwesbaar is vir process injection nie:
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
Die `cs_*`-konstantes hierbo is die code-signing flags wat in XNU se `osfmk/kern/cs_blobs.h` gedefinieer word, dus kan hulle teen die bron nagegaan word eerder as om daaroor te raai:<sup>[4]</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## Verwysings

- [1] [Apple Developer — Code Signing Requirement Language](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../../../banners/hacktricks-training.md}}
