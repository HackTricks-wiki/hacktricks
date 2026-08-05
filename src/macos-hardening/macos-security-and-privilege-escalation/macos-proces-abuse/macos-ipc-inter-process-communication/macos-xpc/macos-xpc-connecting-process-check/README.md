# Ukaguzi wa Mchakato Unaounganisha wa macOS XPC

{{#include ../../../../../../banners/hacktricks-training.md}}

## Ukaguzi wa Mchakato Unaounganisha wa XPC

Muunganisho unapowekwa kwenye XPC service, server itaangalia ikiwa muunganisho huo unaruhusiwa. Hizi ndizo ukaguzi ambao kwa kawaida ingefanya:

1. Angalia ikiwa **process ime-signed kwa certificate iliyosainiwa na Apple** (hutolewa na Apple pekee).
- Ikiwa hii **haijathibitishwa**, mshambulizi anaweza kuunda **fake certificate** ili ilingane na ukaguzi mwingine wowote.
2. Angalia ikiwa process ime-signed kwa certificate ya **organization**, (uthibitishaji wa team ID).
- Ikiwa hii **haijathibitishwa**, **developer certificate yoyote** kutoka Apple inaweza kutumika ku-sign, na kuunganisha kwenye service.
3. Angalia ikiwa process **ina bundle ID sahihi**.
- Ikiwa hii **haijathibitishwa**, tool yoyote **iliyo-signed na org hiyo hiyo** inaweza kutumika kuingiliana na XPC service.
4. (4 au 5) Angalia ikiwa process inayounganisha ina **nambari sahihi ya software version**.
- Ikiwa hii **haijathibitishwa,** clients za zamani, zisizo salama, zilizo katika hatari ya process injection zinaweza kutumika kuunganisha kwenye XPC service hata ukaguzi mwingine ukiwa umewekwa.
5. (4 au 5) Angalia ikiwa process inayounganisha ina hardened runtime bila dangerous entitlements (kama zile zinazoruhusu kupakia libraries za kiholela au kutumia DYLD env vars)
1. Ikiwa hii **haijathibitishwa,** client inaweza kuwa **katika hatari ya code injection**
6. Angalia ikiwa process inayounganisha ina **entitlement** inayoiruhusu kuunganisha kwenye service. Hii inatumika kwa Apple binaries.
7. **Verification** lazima **itegemee** **audit token** ya **client inayounganisha** **badala ya** process ID (**PID**) yake, kwa sababu ya kwanza huzuia **PID reuse attacks**.
- Developers **mara chache hutumia audit token** API call kwa kuwa ni **private**, hivyo Apple inaweza **kuibadilisha** wakati wowote. Zaidi ya hayo, matumizi ya private API hayaruhusiwi katika Mac App Store apps.
- Ikiwa method **`processIdentifier`** inatumika, inaweza kuwa katika hatari
- **`xpc_dictionary_get_audit_token`** inapaswa kutumiwa badala ya **`xpc_connection_get_audit_token`**, kwa kuwa ya mwisho inaweza pia kuwa [katika hatari katika hali fulani](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[5]</sup>

### Communication Attacks

Kwa maelezo zaidi kuhusu PID reuse attack, angalia:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Kwa maelezo zaidi kuhusu attack ya **`xpc_connection_get_audit_token`**, angalia:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Kuzuia Downgrade Attacks

Trustcache ni defensive method iliyoanzishwa katika mashine za Apple Silicon inayohifadhi database ya CDHSAH ya Apple binaries, ili binaries zisizobadilishwa na zinazoruhusiwa pekee ziweze kutekelezwa. Hii huzuia utekelezaji wa downgrade versions.

### Code Examples

Server itaweka **verification** hii katika function inayoitwa **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Object NSXPCConnection ina property **`auditToken`** ya **private** (hiyo ndiyo inapaswa kutumiwa, lakini inaweza kubadilika) na property **`processIdentifier`** ya **public** (hiyo haipaswi kutumiwa).

Process inayounganisha inaweza kuthibitishwa kwa kitu kama hiki:<sup>[1][2][3]</sup>
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
Ikiwa developer hataki kukagua version ya client, anaweza angalau kukagua kwamba client haina udhaifu wa process injection:
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
Konstanti za `cs_*` zilizo hapo juu ni flags za code-signing zilizofafanuliwa katika XNU's `osfmk/kern/cs_blobs.h`, hivyo zinaweza kuthibitishwa dhidi ya msimbo chanzo badala ya kukisiwa:<sup>[4]</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## Marejeo

- [1] [Apple Developer — Lugha ya Mahitaji ya Code Signing](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (flags za `CS_*` code-signing)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — Ulaghai wa audit token wa XPC](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../../../banners/hacktricks-training.md}}
