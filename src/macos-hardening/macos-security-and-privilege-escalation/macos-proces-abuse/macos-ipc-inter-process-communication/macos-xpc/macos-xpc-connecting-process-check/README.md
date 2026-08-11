# Controllo del processo di connessione XPC

{{#include ../../../../../../banners/hacktricks-training.md}}

## Controllo del processo di connessione XPC

Quando viene stabilita una connessione a un servizio XPC, il server verifica se la connessione è consentita. Questi sono i controlli che normalmente esegue:

1. Verifica se il **processo è firmato con un certificato firmato da Apple** (rilasciato esclusivamente da Apple).
- Se questa verifica **non viene eseguita**, un attacker potrebbe creare un **certificato falso** per superare qualsiasi altro controllo.
2. Verifica se il processo connesso è firmato con il **certificato dell’organizzazione** (verifica del team ID).
- Se questa verifica **non viene eseguita**, è possibile utilizzare **qualsiasi certificato sviluppatore** di Apple per firmare il processo e connettersi al servizio.
3. Verifica se il processo connesso **contiene un bundle ID valido**.
- Se questa verifica **non viene eseguita**, qualsiasi tool **firmato dalla stessa organizzazione** potrebbe essere utilizzato per interagire con il servizio XPC.
4. (4 o 5) Verifica se il processo connesso dispone di un **numero di versione software valido**.
- Se questa verifica **non viene eseguita**, potrebbe essere utilizzato un client obsoleto e insicuro, vulnerabile alla process injection, per connettersi al servizio XPC anche con gli altri controlli attivi.
5. (4 o 5) Verifica se il processo connesso dispone dell’hardened runtime senza entitlements pericolosi (come quelli che consentono di caricare librerie arbitrarie o utilizzare variabili d’ambiente DYLD)
1. Se questa verifica **non viene eseguita**, il client potrebbe essere **vulnerabile alla code injection**
6. Verifica se il processo connesso dispone di un **entitlement** che gli consente di connettersi al servizio. Questo è applicabile ai binari Apple.
7. La **verifica** deve essere **basata sull’audit token** del **client connesso** **anziché** sul suo process ID (**PID**), poiché il primo impedisce gli **attacchi di riutilizzo del PID**.
- Gli sviluppatori **utilizzano raramente l’API dell’audit token** poiché è **privata**, quindi Apple potrebbe **modificarla** in qualsiasi momento. Inoltre, l’utilizzo di API private non è consentito nelle app del Mac App Store.
- Se viene utilizzato il metodo **`processIdentifier`**, potrebbe essere vulnerabile
- È necessario utilizzare **`xpc_dictionary_get_audit_token`** invece di **`xpc_connection_get_audit_token`**, poiché quest’ultimo potrebbe essere [vulnerabile in determinate situazioni](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

### Attacchi alla comunicazione

Per ulteriori informazioni sull’attacco di riutilizzo del PID, consulta:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Per ulteriori informazioni sull’attacco a **`xpc_connection_get_audit_token`**, consulta:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Prevenzione degli attacchi di downgrade

Trustcache è un metodo difensivo introdotto nei dispositivi Apple Silicon che memorizza un database di CDHSAH dei binari Apple, in modo che possano essere eseguiti solo binari consentiti e non modificati. Questo impedisce l’esecuzione di versioni downgrade.

### Esempi di codice

Il server implementerà questa **verifica** in una funzione chiamata **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
L'oggetto `NSXPCConnection` ha una proprietà **`auditToken`** **privata** (quella che dovrebbe essere usata, sebbene una API privata possa cambiare) e una proprietà **`processIdentifier`** **pubblica** (che non dovrebbe essere usata per l'autenticazione).

Il processo di connessione potrebbe essere verificato in questo modo:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
Se uno sviluppatore non vuole verificare la versione del client, potrebbe almeno controllare che il client non sia vulnerabile al process injection:
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
Le costanti `cs_*` sopra riportate sono i flag di code-signing definiti in `osfmk/kern/cs_blobs.h` di XNU, quindi possono essere verificate rispetto al sorgente anziché essere intuite:<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## References

- [1] [Apple Developer — Linguaggio dei requisiti di firma del codice](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (flag di code signing `CS_*`)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — spoofing dell'audit token XPC](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
{{#include ../../../../../../banners/hacktricks-training.md}}
