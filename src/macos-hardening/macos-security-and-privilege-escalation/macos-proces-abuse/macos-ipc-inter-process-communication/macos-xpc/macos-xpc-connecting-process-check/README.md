# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## Comprobación del proceso que se conecta a XPC

Cuando se establece una conexión con un servicio XPC, el servidor comprobará si la conexión está permitida. Estas son las comprobaciones que normalmente realizaría:

1. Comprobar si el **proceso que se conecta está firmado con un** certificado **firmado por Apple** (solo proporcionado por Apple).
- Si esto **no se verifica**, un atacante podría crear un **certificado falso** que coincida con cualquier otra comprobación.
2. Comprobar si el proceso que se conecta está firmado con el **certificado de la organización** (verificación del team ID).
- Si esto **no se verifica**, se puede utilizar **cualquier certificado de desarrollador** de Apple para firmar y conectarse al servicio.
3. Comprobar si el proceso que se conecta **contiene un bundle ID adecuado**.
- Si esto **no se verifica**, cualquier herramienta **firmada por la misma organización** podría utilizarse para interactuar con el servicio XPC.
4. (4 o 5) Comprobar si el proceso que se conecta tiene un **número de versión de software adecuado**.
- Si esto **no se verifica**, podría utilizarse para conectarse al servicio XPC un cliente antiguo e inseguro vulnerable a process injection, incluso con las demás comprobaciones implementadas.
5. (4 o 5) Comprobar si el proceso que se conecta tiene hardened runtime sin entitlements peligrosos (como los que permiten cargar librerías arbitrarias o utilizar variables de entorno DYLD)
1. Si esto **no se verifica,** el cliente podría ser **vulnerable a code injection**
6. Comprobar si el proceso que se conecta tiene un **entitlement** que le permita conectarse al servicio. Esto es aplicable a los binarios de Apple.
7. La **verificación** debe estar **basada** en el **audit token** del **cliente que se conecta** **en lugar de** su ID de proceso (**PID**), ya que el primero evita los **PID reuse attacks**.
- Los desarrolladores **rara vez utilizan la** API de **audit token**, ya que es **privada**, por lo que Apple podría **cambiarla** en cualquier momento. Además, el uso de APIs privadas no está permitido en las aplicaciones de Mac App Store.
- Si se utiliza el método **`processIdentifier`**, podría ser vulnerable
- Debe utilizarse **`xpc_dictionary_get_audit_token`** en lugar de **`xpc_connection_get_audit_token`**, ya que este último también podría ser [vulnerable en determinadas situaciones](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

### Communication Attacks

Para obtener más información sobre el PID reuse attack, consulta:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Para obtener más información sobre el ataque **`xpc_connection_get_audit_token`**, consulta:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Prevención de Downgrade Attacks

Trustcache es un método defensivo introducido en los equipos Apple Silicon que almacena una base de datos de CDHSAH de binarios de Apple, de modo que solo puedan ejecutarse binarios permitidos y no modificados. Esto evita la ejecución de versiones downgrade.

### Code Examples

El servidor implementará esta **verificación** en una función llamada **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
El objeto `NSXPCConnection` tiene una propiedad **privada** **`auditToken`** (la que debería usarse, aunque una API privada puede cambiar) y una propiedad **pública** **`processIdentifier`** (que no debería usarse para la autenticación).

El proceso que realiza la conexión podría verificarse con algo como:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
Si un desarrollador no quiere comprobar la versión del cliente, al menos podría comprobar que el cliente no sea vulnerable a process injection:
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
Las constantes `cs_*` anteriores son los flags de code-signing definidos en `XNU's osfmk/kern/cs_blobs.h`, por lo que pueden comprobarse en el código fuente en lugar de suponerse:<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## References

- [1] [Apple Developer — Lenguaje de requisitos de firma de código](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (indicadores de code-signing `CS_*`)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — suplantación de audit token en XPC](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
{{#include ../../../../../../banners/hacktricks-training.md}}
