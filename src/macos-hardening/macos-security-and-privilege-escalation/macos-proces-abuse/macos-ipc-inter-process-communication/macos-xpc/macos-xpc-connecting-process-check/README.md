# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

Kada se uspostavi veza sa XPC servisom, server će proveriti da li je veza dozvoljena. Ovo su provere koje bi obično izvršio:

1. Proveri da li je **proces koji se povezuje potpisan Apple-ovim** sertifikatom (samo ga izdaje Apple).
- Ako ovo **nije verifikovano**, napadač bi mogao da kreira **lažni sertifikat** koji bi odgovarao bilo kojoj drugoj proveri.
2. Proveri da li je proces koji se povezuje potpisan **sertifikatom organizacije** (verifikacija tim ID-a).
- Ako ovo **nije verifikovano**, **bilo koji developerski sertifikat** od Apple-a može se koristiti za potpisivanje i povezivanje sa servisom.
3. Proveri da li proces koji se povezuje **sadrži odgovarajući bundle ID**.
- Ako ovo **nije verifikovano**, bilo koji alat **potpisan od iste organizacije** mogao bi se koristiti za interakciju sa XPC servisom.
4. (4 ili 5) Proveri da li proces koji se povezuje ima **odgovarajući broj verzije softvera**.
- Ako ovo **nije verifikovano**, stari, nesigurni klijenti, ranjivi na injekciju procesa mogli bi se koristiti za povezivanje sa XPC servisom čak i sa ostalim proverama na snazi.
5. (4 ili 5) Proveri da li proces koji se povezuje ima ojačanu runtime bez opasnih prava (kao što su ona koja omogućavaju učitavanje proizvoljnih biblioteka ili korišćenje DYLD env varijabli).
1. Ako ovo **nije verifikovano**, klijent bi mogao biti **ranjiv na injekciju koda**.
6. Proveri da li proces koji se povezuje ima **pravo** koje mu omogućava povezivanje sa servisom. Ovo se primenjuje na Apple binarne datoteke.
7. **Verifikacija** mora biti **zasnovana** na **audit token-u klijenta** **umesto** na njegovom ID-u procesa (**PID**) pošto prvi sprečava **napade ponovne upotrebe PID-a**.
- Programeri **retko koriste audit token** API poziv pošto je **privatan**, tako da Apple može **promeniti** u bilo kojem trenutku. Pored toga, korišćenje privatnog API-ja nije dozvoljeno u aplikacijama Mac App Store-a.
- Ako se metoda **`processIdentifier`** koristi, može biti ranjiva.
- **`xpc_dictionary_get_audit_token`** treba koristiti umesto **`xpc_connection_get_audit_token`**, pošto bi poslednji mogao biti [ranjiv u određenim situacijama](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Communication Attacks

Za više informacija o napadu ponovne upotrebe PID-a proverite:

{{#ref}}
macos-pid-reuse.md
{{#endref}}

Za više informacija o napadu **`xpc_connection_get_audit_token`** proverite:

{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Prevencija napada na snižavanje

Trustcache je odbrambena metoda uvedena u Apple Silicon mašinama koja čuva bazu podataka CDHSAH Apple binarnih datoteka tako da se samo dozvoljene neizmenjene binarne datoteke mogu izvršiti. Što sprečava izvršavanje sniženih verzija.

### Code Examples

Server će implementirati ovu **verifikaciju** u funkciji nazvanoj **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Objekat NSXPCConnection ima **privatnu** osobinu **`auditToken`** (onu koja bi trebala da se koristi, ali može da se promeni) i **javnu** osobinu **`processIdentifier`** (onu koja ne bi trebala da se koristi).

Povezani proces može se verifikovati sa nečim poput:
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
Ako programer ne želi da proveri verziju klijenta, mogao bi da proveri da klijent nije podložan procesnoj injekciji barem:
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
