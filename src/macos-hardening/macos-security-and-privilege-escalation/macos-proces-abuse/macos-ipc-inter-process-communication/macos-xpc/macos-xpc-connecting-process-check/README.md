# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

Gdy nawiązywane jest połączenie z usługą XPC, serwer sprawdzi, czy połączenie jest dozwolone. Oto kontrole, które zazwyczaj są przeprowadzane:

1. Sprawdzenie, czy **proces łączący jest podpisany certyfikatem podpisanym przez Apple** (wydawanym tylko przez Apple).
- Jeśli **to nie jest zweryfikowane**, atakujący może stworzyć **fałszywy certyfikat**, aby dopasować się do innej kontroli.
2. Sprawdzenie, czy proces łączący jest podpisany **certyfikatem organizacji** (weryfikacja ID zespołu).
- Jeśli **to nie jest zweryfikowane**, **dowolny certyfikat dewelopera** z Apple może być użyty do podpisania i połączenia z usługą.
3. Sprawdzenie, czy proces łączący **zawiera odpowiedni identyfikator pakietu**.
- Jeśli **to nie jest zweryfikowane**, każde narzędzie **podpisane przez tę samą organizację** może być użyte do interakcji z usługą XPC.
4. (4 lub 5) Sprawdzenie, czy proces łączący ma **odpowiedni numer wersji oprogramowania**.
- Jeśli **to nie jest zweryfikowane**, stary, niebezpieczny klient, podatny na wstrzykiwanie procesów, może być użyty do połączenia z usługą XPC, nawet przy innych kontrolach.
5. (4 lub 5) Sprawdzenie, czy proces łączący ma wzmocniony czas działania bez niebezpiecznych uprawnień (jak te, które pozwalają na ładowanie dowolnych bibliotek lub używanie zmiennych środowiskowych DYLD).
1. Jeśli **to nie jest zweryfikowane**, klient może być **podatny na wstrzykiwanie kodu**.
6. Sprawdzenie, czy proces łączący ma **uprawnienie**, które pozwala mu połączyć się z usługą. Dotyczy to binariów Apple.
7. **Weryfikacja** musi być **oparta** na **tokenie audytu klienta** **zamiast** na jego identyfikatorze procesu (**PID**), ponieważ ten pierwszy zapobiega **atakom na ponowne użycie PID**.
- Deweloperzy **rzadko używają tokena audytu** w wywołaniach API, ponieważ jest on **prywatny**, więc Apple może **zmienić** go w dowolnym momencie. Dodatkowo, użycie prywatnych API nie jest dozwolone w aplikacjach Mac App Store.
- Jeśli używana jest metoda **`processIdentifier`**, może być podatna.
- **`xpc_dictionary_get_audit_token`** powinno być używane zamiast **`xpc_connection_get_audit_token`**, ponieważ to ostatnie może być również [podatne w pewnych sytuacjach](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Communication Attacks

Aby uzyskać więcej informacji na temat ataku na ponowne użycie PID, sprawdź:

{{#ref}}
macos-pid-reuse.md
{{#endref}}

Aby uzyskać więcej informacji na temat ataku **`xpc_connection_get_audit_token`**, sprawdź:

{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Downgrade Attacks Prevention

Trustcache to metoda defensywna wprowadzona w maszynach Apple Silicon, która przechowuje bazę danych CDHSAH binariów Apple, aby tylko dozwolone, niezmodyfikowane binaria mogły być wykonywane. Co zapobiega wykonywaniu wersji downgrade.

### Code Examples

Serwer zaimplementuje tę **weryfikację** w funkcji zwanej **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Obiekt NSXPCConnection ma **prywatną** właściwość **`auditToken`** (ta, która powinna być używana, ale może się zmienić) oraz **publiczną** właściwość **`processIdentifier`** (ta, która nie powinna być używana).

Proces łączący można zweryfikować za pomocą czegoś takiego:
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
Jeśli deweloper nie chce sprawdzać wersji klienta, mógłby przynajmniej sprawdzić, że klient nie jest podatny na wstrzykiwanie procesów:
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
