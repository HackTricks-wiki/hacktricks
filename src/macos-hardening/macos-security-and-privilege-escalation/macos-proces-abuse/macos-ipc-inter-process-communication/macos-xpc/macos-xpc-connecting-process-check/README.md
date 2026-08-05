# Sprawdzanie procesu łączącego się z XPC w macOS

{{#include ../../../../../../banners/hacktricks-training.md}}

## Sprawdzanie procesu łączącego się z XPC

Gdy połączenie z usługą XPC zostanie ustanowione, serwer sprawdzi, czy połączenie jest dozwolone. Zwykle wykonywane są następujące kontrole:

1. Sprawdzenie, czy **proces jest podpisany certyfikatem podpisanym przez Apple** (wydawanym wyłącznie przez Apple).
- Jeśli to **nie zostanie zweryfikowane**, attacker może utworzyć **fałszywy certyfikat**, aby spełnić dowolną inną kontrolę.
2. Sprawdzenie, czy proces łączący się jest podpisany certyfikatem **organizacji** (weryfikacja team ID).
- Jeśli to **nie zostanie zweryfikowane**, do podpisania i połączenia z usługą można użyć **dowolnego certyfikatu deweloperskiego** firmy Apple.
3. Sprawdzenie, czy proces łączący się **zawiera prawidłowy bundle ID**.
- Jeśli to **nie zostanie zweryfikowane**, dowolne narzędzie **podpisane przez tę samą organizację** może zostać użyte do interakcji z usługą XPC.
4. (4 lub 5) Sprawdzenie, czy proces łączący się ma **prawidłowy numer wersji software**.
- Jeśli to **nie zostanie zweryfikowane**, do połączenia z usługą XPC można użyć starego, niezabezpieczonego klienta podatnego na process injection, nawet gdy pozostałe kontrole są wdrożone.
5. (4 lub 5) Sprawdzenie, czy proces łączący się ma hardened runtime bez niebezpiecznych entitlements (takich jak te, które pozwalają ładować dowolne biblioteki lub używać zmiennych środowiskowych DYLD)
1. Jeśli to **nie zostanie zweryfikowane**, klient może być **podatny na code injection**
6. Sprawdzenie, czy proces łączący się ma **entitlement**, który pozwala mu połączyć się z usługą. Dotyczy to binariów Apple.
7. **Weryfikacja** musi być oparta **na audit tokenie** łączącego się **klienta**, a **nie** na jego identyfikatorze procesu (**PID**), ponieważ to pierwsze rozwiązanie zapobiega **atakom związanym z ponownym użyciem PID**.
- Deweloperzy **rzadko używają API audit tokena**, ponieważ jest ono **prywatne**, więc Apple może je **w dowolnym momencie zmienić**. Ponadto używanie prywatnego API nie jest dozwolone w aplikacjach Mac App Store.
- Jeśli używana jest metoda **`processIdentifier`**, może ona być podatna na atak
- Należy używać **`xpc_dictionary_get_audit_token`** zamiast **`xpc_connection_get_audit_token`**, ponieważ to drugie może być również [podatne w określonych sytuacjach](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[5]</sup>

### Ataki na komunikację

Więcej informacji o ataku polegającym na ponownym użyciu PID:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Więcej informacji o ataku związanym z **`xpc_connection_get_audit_token`**:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - zapobieganie atakom downgrade

Trustcache to metoda defensywna wprowadzona w urządzeniach z Apple Silicon, która przechowuje bazę danych CDHSAH binariów Apple, dzięki czemu można wykonywać wyłącznie dozwolone, niemodyfikowane binaria. Zapobiega to wykonywaniu wersji downgrade.

### Przykłady kodu

Serwer zaimplementuje tę **weryfikację** w funkcji o nazwie **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Obiekt NSXPCConnection ma **prywatną** właściwość **`auditToken`** (tej należy używać, ale może się ona zmienić) oraz **publiczną** właściwość **`processIdentifier`** (tej nie należy używać).

Proces łączący się można zweryfikować na przykład tak:<sup>[1][2][3]</sup>
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
Jeśli deweloper nie chce sprawdzać wersji klienta, może przynajmniej sprawdzić, czy klient nie jest podatny na process injection:
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
Stałe `cs_*` powyżej to flagi code-signingu zdefiniowane w `osfmk/kern/cs_blobs.h`, więc można je sprawdzić w źródle zamiast zgadywać:<sup>[4]</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## Odnośniki

- [1] [Apple Developer — Język wymagań podpisywania kodu](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (flagi podpisywania kodu `CS_*`)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../../../banners/hacktricks-training.md}}
