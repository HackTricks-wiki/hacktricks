# Kontrola procesu łączącego się z macOS XPC

{{#include ../../../../../../banners/hacktricks-training.md}}

## Kontrola procesu łączącego się z XPC

Gdy połączenie z usługą XPC zostanie ustanowione, serwer sprawdzi, czy połączenie jest dozwolone. Zwykle wykonuje następujące kontrole:

1. Sprawdza, czy **proces jest podpisany certyfikatem podpisanym przez Apple** (wydawanym wyłącznie przez Apple).
- Jeśli **nie zostanie to zweryfikowane**, atakujący może utworzyć **fałszywy certyfikat**, aby spełnić dowolną inną kontrolę.
2. Sprawdza, czy proces łączący się jest podpisany **certyfikatem organizacji** (weryfikacja team ID).
- Jeśli **nie zostanie to zweryfikowane**, do podpisania i połączenia z usługą można użyć **dowolnego certyfikatu deweloperskiego** firmy Apple.
3. Sprawdza, czy proces łączący się **zawiera prawidłowy bundle ID**.
- Jeśli **nie zostanie to zweryfikowane**, każde narzędzie **podpisane przez tę samą organizację** może zostać użyte do interakcji z usługą XPC.
4. (4 lub 5) Sprawdza, czy proces łączący się ma **prawidłowy numer wersji oprogramowania**.
- Jeśli **nie zostanie to zweryfikowane**, do połączenia z usługą XPC można użyć starego, niezabezpieczonego klienta podatnego na process injection, nawet jeśli pozostałe kontrole są wdrożone.
5. (4 lub 5) Sprawdza, czy proces łączący się korzysta z hardened runtime bez niebezpiecznych entitlements (takich jak te, które umożliwiają ładowanie dowolnych bibliotek lub używanie zmiennych środowiskowych DYLD).
1. Jeśli **nie zostanie to zweryfikowane**, klient może być **podatny na code injection**
6. Sprawdza, czy proces łączący się ma **entitlement**, który umożliwia mu połączenie z usługą. Dotyczy to binariów Apple.
7. **Weryfikacja** musi być **oparta** na **audit tokenie** łączącego się **klienta**, a nie na jego identyfikatorze procesu (**PID**), ponieważ ten pierwszy zapobiega **atakom polegającym na ponownym użyciu PID**.
- Deweloperzy **rzadko korzystają z API audit token**, ponieważ jest ono **prywatne**, więc Apple może je **w dowolnym momencie zmienić**. Ponadto używanie prywatnego API jest niedozwolone w aplikacjach Mac App Store.
- Jeśli używana jest metoda **`processIdentifier`**, może ona być podatna
- Należy używać **`xpc_dictionary_get_audit_token`** zamiast **`xpc_connection_get_audit_token`**, ponieważ ta druga metoda może być również [podatna w określonych sytuacjach](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

### Ataki komunikacyjne

Więcej informacji na temat ataku polegającego na ponownym użyciu PID:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Więcej informacji na temat ataku z użyciem **`xpc_connection_get_audit_token`**:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache — zapobieganie atakom downgrade

Trustcache to metoda obronna wprowadzona w maszynach z Apple Silicon, która przechowuje bazę danych CDHSAH binariów Apple, dzięki czemu można wykonywać wyłącznie dozwolone, niemodyfikowane binaria. Zapobiega to wykonywaniu wersji downgrade.

### Przykłady kodu

Serwer zaimplementuje tę **weryfikację** w funkcji o nazwie **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Obiekt `NSXPCConnection` ma **prywatną** właściwość **`auditToken`** (tej właśnie należy używać, chociaż private API może ulec zmianie) oraz **publiczną** właściwość **`processIdentifier`** (której nie należy używać do uwierzytelniania).

Proces łączący można zweryfikować w sposób podobny do:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
Jeśli deweloper nie chce sprawdzać wersji klienta, powinien przynajmniej sprawdzić, czy klient nie jest podatny na process injection:
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
Stałe `cs_*` powyżej to flagi code-signing zdefiniowane w `osfmk/kern/cs_blobs.h`, więc można je sprawdzić w źródle zamiast zgadywać:<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## References

- [1] [Apple Developer — Język wymagań podpisywania kodu](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (flagi podpisywania kodu `CS_*`)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — spoofing tokenu audytu XPC](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
{{#include ../../../../../../banners/hacktricks-training.md}}
