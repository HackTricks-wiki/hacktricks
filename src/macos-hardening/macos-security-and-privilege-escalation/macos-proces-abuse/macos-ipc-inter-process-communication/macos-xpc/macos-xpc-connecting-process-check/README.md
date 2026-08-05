# Ukaguzi wa Mchakato Unaounganisha wa XPC

{{#include ../../../../../../banners/hacktricks-training.md}}

## Ukaguzi wa Mchakato Unaounganisha wa XPC

Muunganisho unapoanzishwa kwenye XPC service, server itaangalia ikiwa muunganisho huo unaruhusiwa. Hizi ndizo check ambazo kwa kawaida itafanya:

1. Angalia ikiwa **process inasainiwa kwa certificate iliyosainiwa na Apple** (hutolewa na Apple pekee).
- Ikiwa **hili halijathibitishwa**, attacker anaweza kuunda **certificate bandia** ili ilingane na check nyingine yoyote.
2. Angalia ikiwa process inayounganisha imesainiwa kwa certificate ya **organization**, (team ID verification).
- Ikiwa **hili halijathibitishwa**, **certificate yoyote ya developer** kutoka Apple inaweza kutumika kusaini na kuunganisha kwenye service.
3. Angalia ikiwa process inayounganisha **ina bundle ID sahihi**.
- Ikiwa **hili halijathibitishwa**, tool yoyote **iliyosainiwa na org hiyo hiyo** inaweza kutumika kuingiliana na XPC service.
4. (4 au 5) Angalia ikiwa process inayounganisha ina **nambari sahihi ya software version**.
- Ikiwa **hili halijathibitishwa,** client wa zamani na asiye salama, aliye katika hatari ya process injection, anaweza kutumika kuunganisha kwenye XPC service hata kama check nyingine zipo.
5. (4 au 5) Angalia ikiwa process inayounganisha ina hardened runtime bila dangerous entitlements (kama zile zinazoruhusu kupakia libraries kiholela au kutumia DYLD env vars)
1. Ikiwa **hili halijathibitishwa,** client anaweza kuwa **katika hatari ya code injection**
6. Angalia ikiwa process inayounganisha ina **entitlement** inayoiruhusu kuunganisha kwenye service. Hili linatumika kwa Apple binaries.
7. **Verification** lazima **itegemee** **audit token** ya **client anayeunganisha** **badala ya** process ID yake (**PID**), kwa kuwa ya kwanza huzuia **PID reuse attacks**.
- Developers **hutumia kwa nadra API ya audit token** kwa sababu ni **private**, hivyo Apple inaweza kuibadilisha wakati wowote. Zaidi ya hayo, kutumia private API hakuruhusiwi katika apps za Mac App Store.
- Ikiwa method **`processIdentifier`** itatumika, inaweza kuwa katika hatari
- **`xpc_dictionary_get_audit_token`** inapaswa kutumika badala ya **`xpc_connection_get_audit_token`**, kwa kuwa ya mwisho inaweza pia kuwa [katika hatari katika hali fulani](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

### Communication Attacks

Kwa maelezo zaidi kuhusu PID reuse attack, angalia:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Kwa maelezo zaidi kuhusu attack ya **`xpc_connection_get_audit_token`**, angalia:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Downgrade Attacks Prevention

Trustcache ni njia ya ulinzi iliyoanzishwa katika mashine za Apple Silicon ambayo huhifadhi database ya CDHSAH za Apple binaries ili binaries zisizorekebishwa na zinazoruhusiwa pekee ziweze kutekelezwa. Hii huzuia utekelezaji wa downgrade versions.

### Mifano ya Code

Server itatekeleza **verification** hii katika function inayoitwa **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Object NSXPCConnection ina property **`auditToken`** ya **private** (ile inayopaswa kutumiwa lakini inaweza kubadilika) na property **`processIdentifier`** ya **public** (ile ambayo haipaswi kutumiwa).

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
Ikiwa developer hataki kuangalia version ya client, anaweza angalau kuangalia kwamba client haina vulnerability ya process injection:
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
Konstanti za `cs_*` zilizo hapo juu ni flags za code-signing zilizofafanuliwa katika `osfmk/kern/cs_blobs.h` ya XNU, hivyo zinaweza kukaguliwa dhidi ya source badala ya kukisia:<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## Marejeo

- [1] [Apple Developer — Language ya Mahitaji ya Code Signing](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (flags za code-signing `CS_*`)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../../../banners/hacktricks-training.md}}
