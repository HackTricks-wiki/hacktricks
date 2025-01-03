# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

Wenn eine Verbindung zu einem XPC-Dienst hergestellt wird, überprüft der Server, ob die Verbindung erlaubt ist. Dies sind die Überprüfungen, die normalerweise durchgeführt werden:

1. Überprüfen, ob der verbindende **Prozess mit einem von Apple signierten** Zertifikat signiert ist (nur von Apple ausgegeben).
- Wenn dies **nicht verifiziert** wird, könnte ein Angreifer ein **gefälschtes Zertifikat** erstellen, um andere Überprüfungen zu umgehen.
2. Überprüfen, ob der verbindende Prozess mit dem **Zertifikat der Organisation** signiert ist (Team-ID-Überprüfung).
- Wenn dies **nicht verifiziert** wird, kann **jedes Entwicklerzertifikat** von Apple zur Signierung verwendet werden, um sich mit dem Dienst zu verbinden.
3. Überprüfen, ob der verbindende Prozess **eine gültige Bundle-ID** enthält.
- Wenn dies **nicht verifiziert** wird, könnte jedes Tool, das **von derselben Organisation signiert** ist, verwendet werden, um mit dem XPC-Dienst zu interagieren.
4. (4 oder 5) Überprüfen, ob der verbindende Prozess eine **gültige Softwareversionsnummer** hat.
- Wenn dies **nicht verifiziert** wird, könnte ein alter, unsicherer Client, der anfällig für Prozessinjektionen ist, verwendet werden, um sich mit dem XPC-Dienst zu verbinden, selbst wenn die anderen Überprüfungen vorhanden sind.
5. (4 oder 5) Überprüfen, ob der verbindende Prozess eine gehärtete Laufzeit ohne gefährliche Berechtigungen hat (wie die, die das Laden beliebiger Bibliotheken oder die Verwendung von DYLD-Umgebungsvariablen ermöglichen).
1. Wenn dies **nicht verifiziert** wird, könnte der Client **anfällig für Code-Injektionen** sein.
6. Überprüfen, ob der verbindende Prozess eine **Berechtigung** hat, die es ihm erlaubt, sich mit dem Dienst zu verbinden. Dies gilt für Apple-Binärdateien.
7. Die **Überprüfung** muss **auf dem Audit-Token des verbindenden Clients** **basieren** und nicht auf seiner Prozess-ID (**PID**), da letzteres **PID-Wiederverwendungsangriffe** verhindert.
- Entwickler **verwenden selten den Audit-Token** API-Aufruf, da er **privat** ist, sodass Apple ihn jederzeit **ändern** könnte. Darüber hinaus ist die Verwendung privater APIs in Mac App Store-Apps nicht erlaubt.
- Wenn die Methode **`processIdentifier`** verwendet wird, könnte sie anfällig sein.
- **`xpc_dictionary_get_audit_token`** sollte anstelle von **`xpc_connection_get_audit_token`** verwendet werden, da letzteres auch in bestimmten Situationen [anfällig sein könnte](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Communication Attacks

Für weitere Informationen über den PID-Wiederverwendungsangriff siehe:

{{#ref}}
macos-pid-reuse.md
{{#endref}}

Für weitere Informationen über den **`xpc_connection_get_audit_token`** Angriff siehe:

{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Downgrade Attacks Prevention

Trustcache ist eine defensive Methode, die in Apple Silicon-Maschinen eingeführt wurde und eine Datenbank von CDHSAH von Apple-Binärdateien speichert, sodass nur erlaubte, nicht modifizierte Binärdateien ausgeführt werden können. Dies verhindert die Ausführung von Downgrade-Versionen.

### Code Examples

Der Server wird diese **Überprüfung** in einer Funktion namens **`shouldAcceptNewConnection`** implementieren.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Das Objekt NSXPCConnection hat eine **private** Eigenschaft **`auditToken`** (die verwendet werden sollte, aber sich ändern könnte) und eine **public** Eigenschaft **`processIdentifier`** (die nicht verwendet werden sollte).

Der verbindende Prozess könnte mit etwas wie folgendem überprüft werden:
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
Wenn ein Entwickler die Version des Clients nicht überprüfen möchte, könnte er zumindest überprüfen, ob der Client nicht anfällig für Prozessinjektion ist:
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
