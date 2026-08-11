# macOS XPC provera procesa koji se povezuje

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC provera procesa koji se povezuje

Kada se uspostavi veza sa XPC servisom, server će proveriti da li je veza dozvoljena. Ovo su provere koje bi obično izvršio:

1. Proverava da li je **proces koji se povezuje potpisan sertifikatom koji je potpisao Apple** (koji izdaje isključivo Apple).
- Ako ovo **nije verifikovano**, napadač bi mogao da kreira **lažni sertifikat** koji odgovara bilo kojoj drugoj proveri.
2. Proverava da li je proces koji se povezuje potpisan sertifikatom **organizacije** (verifikacija team ID-ja).
- Ako ovo **nije verifikovano**, za potpisivanje se može koristiti **bilo koji developerski sertifikat** kompanije Apple, a zatim se povezati sa servisom.
3. Proverava da li proces koji se povezuje **sadrži odgovarajući bundle ID**.
- Ako ovo **nije verifikovano**, bilo koji alat **potpisan od strane iste organizacije** mogao bi da se koristi za interakciju sa XPC servisom.
4. (4 ili 5) Proverava da li proces koji se povezuje ima **odgovarajući broj verzije softvera**.
- Ako ovo **nije verifikovano**, stari, nebezbedni klijent ranjiv na process injection mogao bi da se koristi za povezivanje sa XPC servisom, čak i kada su ostale provere na mestu.
5. (4 ili 5) Proverava da li proces koji se povezuje koristi hardened runtime bez opasnih entitlements (kao što su oni koji omogućavaju učitavanje proizvoljnih biblioteka ili korišćenje DYLD env varijabli)
1. Ako ovo **nije verifikovano,** klijent bi mogao biti **ranjiv na code injection**
6. Proverava da li proces koji se povezuje ima **entitlement** koji mu omogućava povezivanje sa servisom. Ovo se odnosi na Apple binarne fajlove.
7. **Verifikacija** mora biti zasnovana **na audit tokenu** **klijenta koji se povezuje**, a ne na njegovom ID-ju procesa (**PID**), jer prvi sprečava **PID reuse napade**.
- Developeri **retko koriste audit token** API poziv zato što je **privatan**, pa bi Apple mogao da ga promeni u bilo kom trenutku. Pored toga, korišćenje privatnih API-ja nije dozvoljeno u aplikacijama za Mac App Store.
- Ako se koristi metoda **`processIdentifier`**, ona bi mogla biti ranjiva
- Trebalo bi koristiti **`xpc_dictionary_get_audit_token`** umesto **`xpc_connection_get_audit_token`**, jer bi ova druga funkcija takođe mogla biti [ranjiva u određenim situacijama](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

### Communication Attacks

Za više informacija o PID reuse napadu pogledajte:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Za više informacija o napadu na **`xpc_connection_get_audit_token`** pogledajte:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Prevencija Downgrade Attacks

Trustcache je odbrambena metoda uvedena na Apple Silicon računarima koja čuva bazu podataka CDHSAH vrednosti Apple binarnih fajlova, tako da se mogu izvršavati samo dozvoljeni i izmenjeni binarni fajlovi. Ovo sprečava izvršavanje downgrade verzija.

### Code Examples

Server će ovu **verifikaciju** implementirati u funkciji pod nazivom **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Objekat `NSXPCConnection` ima **privatno** svojstvo **`auditToken`** (ono koje treba koristiti, iako se privatni API može promeniti) i **javno** svojstvo **`processIdentifier`** (koje ne treba koristiti za autentifikaciju).

Proces koji se povezuje može se proveriti na primer ovako:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
Ako developer ne želi da proverava verziju client-a, mogao bi barem da proveri da client nije ranjiv na process injection:
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
Konstante `cs_*` iznad predstavljaju zastavice za code-signing definisane u XNU-ovom `osfmk/kern/cs_blobs.h`, tako da se mogu proveriti u odnosu na izvorni kod, umesto da se nagađaju:<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## References

- [1] [Apple Developer — Jezik zahteva za potpisivanje koda](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (zastavice potpisivanja koda `CS_*`)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — lažiranje XPC audit tokena](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
{{#include ../../../../../../banners/hacktricks-training.md}}
