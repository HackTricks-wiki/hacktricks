# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

Muunganisho unapowekwa kwenye XPC service, server itaangalia ikiwa muunganisho unaruhusiwa. Hizi ndizo check ambazo kwa kawaida ingefanya:

1. Angalia ikiwa **process inayounganisha imesainiwa kwa certificate iliyosainiwa na Apple** (inayotolewa na Apple pekee).
- Ikiwa **hii haijathibitishwa**, attacker anaweza kuunda **certificate bandia** ili ilingane na check nyingine yoyote.
2. Angalia ikiwa process inayounganisha imesainiwa kwa certificate ya **organization**, (team ID verification).
- Ikiwa **hii haijathibitishwa**, **developer certificate yoyote** kutoka Apple inaweza kutumika kusaini na kuunganisha kwenye service.
3. Angalia ikiwa process inayounganisha **ina bundle ID sahihi**.
- Ikiwa **hii haijathibitishwa**, tool yoyote **iliyosainiwa na org hiyo hiyo** inaweza kutumika kuingiliana na XPC service.
4. (4 au 5) Angalia ikiwa process inayounganisha ina **nambari sahihi ya software version**.
- Ikiwa **hii haijathibitishwa**, client ya zamani na isiyo salama, iliyo hatarini kwa process injection, inaweza kutumika kuunganisha kwenye XPC service hata check nyingine zikiwa zimewekwa.
5. (4 au 5) Angalia ikiwa process inayounganisha ina hardened runtime bila dangerous entitlements (kama zile zinazoruhusu kupakia libraries kiholela au kutumia DYLD env vars)
1. Ikiwa **hii haijathibitishwa,** client inaweza kuwa **hatarini kwa code injection**
6. Angalia ikiwa process inayounganisha ina **entitlement** inayoiruhusu kuunganisha kwenye service. Hii inatumika kwa Apple binaries.
7. **Verification** lazima **itegemee** **audit token** ya **client inayounganisha** **badala ya** process ID yake (**PID**), kwa sababu ya kwanza huzuia **PID reuse attacks**.
- Developers **hutumia mara chache API call ya audit token** kwa sababu ni **private**, hivyo Apple inaweza **kuibadilisha** wakati wowote. Zaidi ya hayo, kutumia private API hairuhusiwi kwenye apps za Mac App Store.
- Ikiwa method **`processIdentifier`** inatumika, inaweza kuwa hatarini
- **`xpc_dictionary_get_audit_token`** inapaswa kutumika badala ya **`xpc_connection_get_audit_token`**, kwa sababu ya mwisho pia inaweza kuwa [hatarini katika hali fulani](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

### Communication Attacks

Kwa maelezo zaidi kuhusu PID reuse attack, angalia:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Kwa maelezo zaidi kuhusu **`xpc_connection_get_audit_token`** attack, angalia:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Downgrade Attacks Prevention

Trustcache ni defensive method iliyoanzishwa kwenye mashine za Apple Silicon ambayo huhifadhi database ya CDHSAH za Apple binaries ili binaries zilizoidhinishwa na ambazo hazijabadilishwa pekee ziweze kutekelezwa. Hii huzuia utekelezaji wa downgrade versions.

### Code Examples

Server itatekeleza **verification** hii kwenye function inayoitwa **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Kitu cha `NSXPCConnection` kina property **`auditToken`** ya **private** (ndiyo inayopaswa kutumiwa, ingawa private API inaweza kubadilika) na property **`processIdentifier`** ya **public** (ambayo haipaswi kutumiwa kwa authentication).

Process inayounganisha inaweza kuthibitishwa kwa kitu kama hiki:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
Ikiwa developer hataki kuangalia version ya client, anaweza angalau kuangalia kwamba client haiwezi kushambuliwa kupitia process injection:
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
Konstant za `cs_*` hapo juu ni flags za code-signing zilizobainishwa katika XNU's `osfmk/kern/cs_blobs.h`, kwa hiyo zinaweza kuchunguzwa dhidi ya source badala ya kukisiwa:<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## References

- [1] [Apple Developer — Lugha ya Mahitaji ya Code Signing](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (flags za code-signing za `CS_*`)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
{{#include ../../../../../../banners/hacktricks-training.md}}
