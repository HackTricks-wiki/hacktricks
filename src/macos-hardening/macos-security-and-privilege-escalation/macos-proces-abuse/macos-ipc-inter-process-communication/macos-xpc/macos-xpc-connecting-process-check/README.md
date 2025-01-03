# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

Quando viene stabilita una connessione a un servizio XPC, il server verificherà se la connessione è consentita. Questi sono i controlli che di solito esegue:

1. Controlla se il **processo di connessione è firmato con un certificato firmato da Apple** (rilasciato solo da Apple).
- Se questo **non è verificato**, un attaccante potrebbe creare un **certificato falso** per soddisfare qualsiasi altro controllo.
2. Controlla se il processo di connessione è firmato con il **certificato dell'organizzazione** (verifica dell'ID del team).
- Se questo **non è verificato**, **qualsiasi certificato di sviluppatore** di Apple può essere utilizzato per la firma e connettersi al servizio.
3. Controlla se il processo di connessione **contiene un ID bundle appropriato**.
- Se questo **non è verificato**, qualsiasi strumento **firmato dalla stessa org** potrebbe essere utilizzato per interagire con il servizio XPC.
4. (4 o 5) Controlla se il processo di connessione ha un **numero di versione software appropriato**.
- Se questo **non è verificato**, un vecchio client insicuro, vulnerabile all'iniezione di processi, potrebbe essere utilizzato per connettersi al servizio XPC anche con gli altri controlli in atto.
5. (4 o 5) Controlla se il processo di connessione ha un runtime rinforzato senza diritti pericolosi (come quelli che consentono di caricare librerie arbitrarie o utilizzare variabili d'ambiente DYLD).
1. Se questo **non è verificato**, il client potrebbe essere **vulnerabile all'iniezione di codice**.
6. Controlla se il processo di connessione ha un **diritto** che gli consente di connettersi al servizio. Questo è applicabile per i binari Apple.
7. La **verifica** deve essere **basata** sul **token di audit del client di connessione** **invece** che sul suo ID processo (**PID**) poiché il primo previene **attacchi di riutilizzo del PID**.
- Gli sviluppatori **raramente utilizzano l'API del token di audit** poiché è **privata**, quindi Apple potrebbe **cambiarla** in qualsiasi momento. Inoltre, l'uso di API private non è consentito nelle app del Mac App Store.
- Se viene utilizzato il metodo **`processIdentifier`**, potrebbe essere vulnerabile.
- **`xpc_dictionary_get_audit_token`** dovrebbe essere utilizzato invece di **`xpc_connection_get_audit_token`**, poiché quest'ultimo potrebbe anche essere [vulnerabile in determinate situazioni](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Communication Attacks

Per ulteriori informazioni sull'attacco di riutilizzo del PID controlla:

{{#ref}}
macos-pid-reuse.md
{{#endref}}

Per ulteriori informazioni sull'attacco **`xpc_connection_get_audit_token`** controlla:

{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Downgrade Attacks Prevention

Trustcache è un metodo difensivo introdotto nelle macchine Apple Silicon che memorizza un database di CDHSAH dei binari Apple in modo che solo i binari non modificati autorizzati possano essere eseguiti. Questo previene l'esecuzione di versioni downgrade.

### Code Examples

Il server implementerà questa **verifica** in una funzione chiamata **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
L'oggetto NSXPCConnection ha una proprietà **privata** **`auditToken`** (quella che dovrebbe essere utilizzata ma potrebbe cambiare) e una proprietà **pubblica** **`processIdentifier`** (quella che non dovrebbe essere utilizzata).

Il processo di connessione potrebbe essere verificato con qualcosa come:
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
Se un sviluppatore non vuole controllare la versione del client, potrebbe almeno verificare che il client non sia vulnerabile all'iniezione di processi:
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
