# XPC-Prüfung des verbindenden Prozesses

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC-Prüfung des verbindenden Prozesses

Wenn eine Verbindung zu einem XPC service hergestellt wird, prüft der Server, ob die Verbindung zulässig ist. Diese Prüfungen werden normalerweise durchgeführt:

1. Prüfen, ob der verbindende **Prozess mit einem von Apple signierten** Zertifikat signiert ist (wird ausschließlich von Apple ausgestellt).
- Wenn dies **nicht verifiziert wird**, könnte ein Angreifer ein **gefälschtes Zertifikat** erstellen, das jede andere Prüfung erfüllt.
2. Prüfen, ob der verbindende Prozess mit dem Zertifikat der **Organisation** signiert ist (Team-ID-Verifizierung).
- Wenn dies **nicht verifiziert wird**, kann **jedes Entwicklerzertifikat** von Apple zum Signieren und Verbinden mit dem service verwendet werden.
3. Prüfen, ob der verbindende Prozess eine **korrekte Bundle-ID** enthält.
- Wenn dies **nicht verifiziert wird**, könnte jedes **von derselben Organisation signierte** Tool zur Interaktion mit dem XPC service verwendet werden.
4. (4 oder 5) Prüfen, ob der verbindende Prozess eine **korrekte Softwareversionsnummer** besitzt.
- Wenn dies **nicht verifiziert wird,** könnten alte, unsichere Clients, die für Process Injection anfällig sind, verwendet werden, um sich trotz der anderen Prüfungen mit dem XPC service zu verbinden.
5. (4 oder 5) Prüfen, ob der verbindende Prozess über eine hardened runtime ohne gefährliche Entitlements verfügt (z. B. solche, die das Laden beliebiger Bibliotheken oder die Verwendung von DYLD-Umgebungsvariablen erlauben)
1. Wenn dies **nicht verifiziert wird,** könnte der Client **für Code Injection anfällig sein**
6. Prüfen, ob der verbindende Prozess ein **Entitlement** besitzt, das ihm die Verbindung mit dem service erlaubt. Dies gilt für Apple-Binaries.
7. Die **Verifizierung** muss auf dem **Audit Token** des verbindenden **Clients** basieren und **nicht** auf seiner Prozess-ID (**PID**), da Ersteres **PID-Reuse-Angriffe** verhindert.
- Entwickler verwenden die API für das **Audit Token** **selten**, da sie **privat** ist und Apple sie jederzeit **ändern** könnte. Außerdem ist die Verwendung privater APIs in Mac App Store-Apps nicht erlaubt.
- Wenn die Methode **`processIdentifier`** verwendet wird, könnte sie anfällig sein
- **`xpc_dictionary_get_audit_token`** sollte anstelle von **`xpc_connection_get_audit_token`** verwendet werden, da Letzteres in bestimmten Situationen ebenfalls [anfällig sein könnte](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

### Communication Attacks

Weitere Informationen zum PID-Reuse-Angriff:

{{#ref}}
macos-pid-reuse.md
{{#endref}}

Weitere Informationen zum Angriff auf **`xpc_connection_get_audit_token`**:

{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Verhinderung von Downgrade-Angriffen

Trustcache ist eine auf Apple Silicon-Maschinen eingeführte defensive Methode, die eine Datenbank mit CDHSAH von Apple-Binaries speichert, sodass nur zulässige, nicht modifizierte Binaries ausgeführt werden können. Dadurch wird die Ausführung von Downgrade-Versionen verhindert.

### Code Examples

Der Server implementiert diese **Verifizierung** in einer Funktion namens **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Das Objekt NSXPCConnection verfügt über die **private** Eigenschaft **`auditToken`** (die verwendet werden sollte, sich jedoch ändern könnte) sowie über die **öffentliche** Eigenschaft **`processIdentifier`** (die nicht verwendet werden sollte).

Der verbindende Prozess könnte beispielsweise wie folgt überprüft werden:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
Wenn ein Entwickler die Version des Clients nicht überprüfen möchte, könnte er zumindest prüfen, dass der Client nicht für Process Injection anfällig ist:
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
Die oben genannten `cs_*`-Konstanten sind die in XNUs `osfmk/kern/cs_blobs.h` definierten code-signing flags und können daher anhand des Quellcodes überprüft werden, anstatt sie zu erraten:<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## Referenzen

- [1] [Apple Developer — Code Signing Requirement Language](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../../../banners/hacktricks-training.md}}
