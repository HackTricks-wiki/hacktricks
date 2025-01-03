# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

Wakati muunganisho unapoanzishwa na huduma ya XPC, seva itakagua ikiwa muunganisho unaruhusiwa. Hizi ndizo ukaguzi ambao kawaida hufanywa:

1. Angalia ikiwa **mchakato unaounganisha umewekwa saini na cheti kilichosainiwa na Apple** (ambacho kinatolewa tu na Apple).
- Ikiwa hii **haihakikishwi**, mshambuliaji anaweza kuunda **cheti bandia** ili kufanana na ukaguzi mwingine wowote.
2. Angalia ikiwa mchakato unaounganisha umewekwa saini na **cheti cha shirika**, (uthibitisho wa kitambulisho cha timu).
- Ikiwa hii **haihakikishwi**, **cheti chochote cha mende** kutoka Apple kinaweza kutumika kwa ajili ya saini, na kuungana na huduma.
3. Angalia ikiwa mchakato unaounganisha **una kitambulisho sahihi cha kifurushi**.
- Ikiwa hii **haihakikishwi**, chombo chochote **kilichosainiwa na shirika hilo hilo** kinaweza kutumika kuingiliana na huduma ya XPC.
4. (4 au 5) Angalia ikiwa mchakato unaounganisha una **nambari sahihi ya toleo la programu**.
- Ikiwa hii **haihakikishwi**, wateja wa zamani, wasio salama, walio hatarini kwa sindano ya mchakato wanaweza kutumika kuungana na huduma ya XPC hata na ukaguzi mwingine ukiwa mahali.
5. (4 au 5) Angalia ikiwa mchakato unaounganisha una **runtime iliyoharden bila ruhusa hatari** (kama zile zinazoruhusu kupakia maktaba zisizo za kawaida au kutumia DYLD env vars)
1. Ikiwa hii **haihakikishwi**, mteja anaweza kuwa **hatari kwa sindano ya msimbo**
6. Angalia ikiwa mchakato unaounganisha una **ruhusa** inayoruhusu kuungana na huduma. Hii inatumika kwa binaries za Apple.
7. **Uthibitisho** lazima uwe **kulingana** na **tokeni ya ukaguzi ya mteja** **badala** ya kitambulisho chake cha mchakato (**PID**) kwani ya kwanza inazuia **shambulio la upya wa PID**.
- Wandevu **hawatumii mara kwa mara API ya tokeni ya ukaguzi** kwani ni **binafsi**, hivyo Apple inaweza **kubadilisha** wakati wowote. Aidha, matumizi ya API binafsi hayaruhusiwi katika programu za Mac App Store.
- Ikiwa njia **`processIdentifier`** inatumika, inaweza kuwa hatarini
- **`xpc_dictionary_get_audit_token`** inapaswa kutumika badala ya **`xpc_connection_get_audit_token`**, kwani ya mwisho inaweza pia kuwa [hatari katika hali fulani](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Communication Attacks

Kwa maelezo zaidi kuhusu shambulio la upya wa PID angalia:

{{#ref}}
macos-pid-reuse.md
{{#endref}}

Kwa maelezo zaidi kuhusu shambulio la **`xpc_connection_get_audit_token`** angalia:

{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Downgrade Attacks Prevention

Trustcache ni njia ya kujihami iliyowekwa katika mashine za Apple Silicon ambayo inahifadhi hifadhidata ya CDHSAH ya binaries za Apple ili tu binaries zisizobadilishwa zinazoruhusiwa ziweze kutekelezwa. Hii inazuia utekelezaji wa toleo la chini.

### Code Examples

Seva itatekeleza **uthibitisho** huu katika kazi inayoitwa **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Objekti NSXPCConnection ina mali **ya faragha** **`auditToken`** (ile inapaswa kutumika lakini inaweza kubadilika) na mali **ya umma** **`processIdentifier`** (ile isiyopaswa kutumika).

Mchakato unaounganisha unaweza kuthibitishwa kwa kitu kama:
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
Ikiwa mendelevu hataki kuangalia toleo la mteja, anaweza kuangalia kwamba mteja si hatarishi kwa sindano ya mchakato angalau:
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
