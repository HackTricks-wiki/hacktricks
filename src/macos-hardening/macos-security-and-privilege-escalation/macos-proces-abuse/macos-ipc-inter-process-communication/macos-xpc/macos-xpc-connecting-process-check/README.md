# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

Cuando se establece una conexión a un servicio XPC, el servidor verificará si la conexión está permitida. Estas son las verificaciones que normalmente realizaría:

1. Verificar si el **proceso que se conecta está firmado con un certificado firmado por Apple** (solo otorgado por Apple).
- Si esto **no se verifica**, un atacante podría crear un **certificado falso** para coincidir con cualquier otra verificación.
2. Verificar si el proceso que se conecta está firmado con el **certificado de la organización** (verificación del ID del equipo).
- Si esto **no se verifica**, **cualquier certificado de desarrollador** de Apple puede ser utilizado para firmar y conectarse al servicio.
3. Verificar si el proceso que se conecta **contiene un ID de paquete adecuado**.
- Si esto **no se verifica**, cualquier herramienta **firmada por la misma organización** podría ser utilizada para interactuar con el servicio XPC.
4. (4 o 5) Verificar si el proceso que se conecta tiene un **número de versión de software adecuado**.
- Si esto **no se verifica**, un cliente antiguo e inseguro, vulnerable a la inyección de procesos, podría ser utilizado para conectarse al servicio XPC incluso con las otras verificaciones en su lugar.
5. (4 o 5) Verificar si el proceso que se conecta tiene un runtime endurecido sin derechos peligrosos (como los que permiten cargar bibliotecas arbitrarias o usar variables de entorno DYLD).
1. Si esto **no se verifica**, el cliente podría ser **vulnerable a la inyección de código**.
6. Verificar si el proceso que se conecta tiene un **derecho** que le permite conectarse al servicio. Esto es aplicable para binarios de Apple.
7. La **verificación** debe basarse en el **token de auditoría del cliente que se conecta** **en lugar** de su ID de proceso (**PID**) ya que el primero previene **ataques de reutilización de PID**.
- Los desarrolladores **raramente utilizan la llamada a la API del token de auditoría** ya que es **privada**, por lo que Apple podría **cambiarla** en cualquier momento. Además, el uso de API privadas no está permitido en las aplicaciones de Mac App Store.
- Si se utiliza el método **`processIdentifier`**, podría ser vulnerable.
- **`xpc_dictionary_get_audit_token`** debería ser utilizado en lugar de **`xpc_connection_get_audit_token`**, ya que este último también podría ser [vulnerable en ciertas situaciones](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Communication Attacks

Para más información sobre el ataque de reutilización de PID, consulta:

{{#ref}}
macos-pid-reuse.md
{{#endref}}

Para más información sobre el ataque **`xpc_connection_get_audit_token`**, consulta:

{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Prevención de Ataques de Downgrade

Trustcache es un método defensivo introducido en máquinas Apple Silicon que almacena una base de datos de CDHSAH de binarios de Apple para que solo se puedan ejecutar binarios no modificados permitidos. Lo que previene la ejecución de versiones de downgrade.

### Code Examples

El servidor implementará esta **verificación** en una función llamada **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
El objeto NSXPCConnection tiene una propiedad **privada** **`auditToken`** (la que debería usarse pero podría cambiar) y una propiedad **pública** **`processIdentifier`** (la que no debería usarse).

El proceso de conexión podría verificarse con algo como:
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
Si un desarrollador no quiere verificar la versión del cliente, podría comprobar que el cliente no es vulnerable a la inyección de procesos al menos:
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
