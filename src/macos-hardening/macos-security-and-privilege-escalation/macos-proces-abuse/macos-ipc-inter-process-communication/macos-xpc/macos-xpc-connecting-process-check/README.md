# Provera procesa koji se povezuje sa macOS XPC

{{#include ../../../../../../banners/hacktricks-training.md}}

## Provera procesa koji se povezuje sa XPC-om

Kada se uspostavi veza sa XPC servisom, server će proveriti da li je veza dozvoljena. Ovo su provere koje se obično izvršavaju:

1. Proverava se da li je **proces potpisan sertifikatom koji je potpisao Apple** (koji izdaje isključivo Apple).
- Ako ovo **nije potvrđeno**, napadač bi mogao da napravi **lažni sertifikat** koji odgovara bilo kojoj drugoj proveri.
2. Proverava se da li je proces koji se povezuje potpisan **sertifikatom organizacije** (verifikacija team ID-ja).
- Ako ovo **nije potvrđeno**, za potpisivanje i povezivanje sa servisom može se koristiti **bilo koji developerski sertifikat** kompanije Apple.
3. Proverava se da li proces koji se povezuje **sadrži odgovarajući bundle ID**.
- Ako ovo **nije potvrđeno**, bilo koji alat **potpisan od strane iste organizacije** mogao bi da se koristi za interakciju sa XPC servisom.
4. (4 ili 5) Proverava se da li proces koji se povezuje ima **odgovarajući broj verzije softvera**.
- Ako ovo **nije potvrđeno**, mogli bi da se koriste stari, nebezbedni klijenti, ranjivi na process injection, za povezivanje sa XPC servisom čak i kada su ostale provere implementirane.
5. (4 ili 5) Proverava se da li proces koji se povezuje koristi hardened runtime bez opasnih entitlements (kao što su oni koji omogućavaju učitavanje proizvoljnih biblioteka ili korišćenje DYLD env varijabli)
1. Ako ovo **nije potvrđeno**, klijent bi mogao biti **ranjiv na code injection**
6. Proverava se da li proces koji se povezuje ima **entitlement** koji mu omogućava povezivanje sa servisom. Ovo se primenjuje na Apple binarne datoteke.
7. **Verifikacija** mora biti zasnovana **na audit tokenu klijenta** koji se povezuje, **a ne** na njegovom ID-u procesa (**PID**), pošto prvi sprečava **PID reuse attacks**.
- Developeri **retko koriste audit token** API poziv, jer je **privatan**, pa bi Apple mogao da ga **promeni** u bilo kom trenutku. Pored toga, korišćenje privatnih API-ja nije dozvoljeno u aplikacijama za Mac App Store.
- Ako se koristi metod **`processIdentifier`**, on bi mogao biti ranjiv
- Trebalo bi koristiti **`xpc_dictionary_get_audit_token`** umesto **`xpc_connection_get_audit_token`**, jer bi drugi mogao biti [ranjiv u određenim situacijama](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

### Communication Attacks

Za više informacija o PID reuse attack proveri:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Za više informacija o proveri napada **`xpc_connection_get_audit_token`**:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Prevencija Downgrade Attacks

Trustcache je odbrambeni metod uveden na Apple Silicon uređajima, koji čuva bazu podataka CDHSAH vrednosti Apple binarnih datoteka kako bi se mogle izvršavati samo dozvoljene, neizmenjene binarne datoteke. Time se sprečava izvršavanje downgrade verzija.

### Primeri koda

Server će implementirati ovu **verifikaciju** u funkciji pod nazivom **`shouldAcceptNewConnection`**.
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
Ako developer ne želi da proverava verziju clienta, mogao bi barem da proveri da client nije ranjiv na process injection:
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
Konstante `cs_*` iznad predstavljaju zastavice za potpisivanje koda definisane u XNU datoteci `osfmk/kern/cs_blobs.h`, tako da se mogu proveriti u odnosu na izvorni kod umesto nagađanja:<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## Reference

- [1] [Apple Developer — Jezik zahteva za Code Signing](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` zastavice za code signing)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../../../banners/hacktricks-training.md}}
