# Provera procesa koji se povezuje na macOS XPC

{{#include ../../../../../../banners/hacktricks-training.md}}

## Provera procesa koji se povezuje na XPC

Kada se uspostavi veza sa XPC service-om, server će proveriti da li je veza dozvoljena. Ovo su provere koje se obično izvršavaju:

1. Provera da li je **proces koji se povezuje potpisan sertifikatom koji je potpisao Apple** (koji izdaje isključivo Apple).
- Ako ovo **nije provereno**, napadač bi mogao da kreira **lažni sertifikat** koji odgovara bilo kojoj drugoj proveri.
2. Provera da li je proces koji se povezuje potpisan sertifikatom organizacije (provera team ID-ja).
- Ako ovo **nije provereno**, za potpisivanje i povezivanje sa service-om može se koristiti **bilo koji developerski sertifikat** kompanije Apple.
3. Provera da li proces koji se povezuje **sadrži odgovarajući bundle ID**.
- Ako ovo **nije provereno**, bilo koji alat **potpisan od strane iste organizacije** mogao bi da se koristi za interakciju sa XPC service-om.
4. (4 ili 5) Provera da li proces koji se povezuje ima **odgovarajući broj verzije softvera**.
- Ako ovo **nije provereno**, za povezivanje sa XPC service-om mogli bi se koristiti stari, nebezbedni klijenti, ranjivi na process injection, čak i kada su ostale provere implementirane.
5. (4 ili 5) Provera da li proces koji se povezuje koristi hardened runtime bez opasnih entitlements-a (kao što su oni koji omogućavaju učitavanje proizvoljnih biblioteka ili korišćenje DYLD env vars)
1. Ako ovo **nije provereno**, klijent bi mogao biti **ranjiv na code injection**
6. Provera da li proces koji se povezuje ima **entitlement** koji mu omogućava povezivanje sa service-om. Ovo se odnosi na Apple binarne fajlove.
7. **Verifikacija** mora biti zasnovana **na audit token-u klijenta** koji se povezuje, **umesto** na njegovom ID-u procesa (**PID**), pošto prvi sprečava **PID reuse napade**.
- Developeri **retko koriste audit token** API poziv zato što je **privatan**, pa bi Apple mogao da ga promeni u bilo kom trenutku. Pored toga, korišćenje privatnih API-ja nije dozvoljeno u aplikacijama za Mac App Store.
- Ako se koristi metod **`processIdentifier`**, može biti ranjiv
- Trebalo bi koristiti **`xpc_dictionary_get_audit_token`** umesto **`xpc_connection_get_audit_token`**, pošto bi potonji takođe mogao biti [ranjiv u određenim situacijama](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

### Communication Attacks

Za više informacija o PID reuse napadu pogledajte:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Za više informacija o napadu **`xpc_connection_get_audit_token`** pogledajte:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Sprečavanje Downgrade Attacks

Trustcache je odbrambena metoda uvedena na Apple Silicon uređajima koja čuva bazu podataka CDHSAH vrednosti Apple binarnih fajlova, tako da se mogu izvršavati samo dozvoljeni nemodifikovani binarni fajlovi. Time se sprečava izvršavanje downgrade verzija.

### Primeri koda

Server će ovu **verifikaciju** implementirati u funkciji pod nazivom **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Objekat NSXPCConnection ima **privatno** svojstvo **`auditToken`** (ono koje bi trebalo koristiti, ali bi moglo da se promeni) i **javno** svojstvo **`processIdentifier`** (ono koje ne bi trebalo koristiti).

Proces koji se povezuje mogao bi da se proveri na sledeći način:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
Konstante `cs_*` iznad predstavljaju code-signing zastavice definisane u XNU datoteci `osfmk/kern/cs_blobs.h`, pa se mogu proveriti u izvornom kodu umesto da se nagađaju:<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## Reference

- [1] [Apple Developer — Code Signing Requirement Language](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../../../banners/hacktricks-training.md}}
