# Verificación del Proceso de Conexión en macOS XPC

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Verificación del Proceso de Conexión en XPC

Cuando se establece una conexión con un servicio XPC, el servidor verificará si la conexión está permitida. Estas son las comprobaciones que normalmente realizará:

1. Verificar si el **proceso de conexión está firmado con un certificado firmado por Apple** (solo otorgado por Apple).
   * Si esto **no se verifica**, un atacante podría crear un **certificado falso** para coincidir con cualquier otra comprobación.
2. Verificar si el proceso de conexión está firmado con el **certificado de la organización**, (verificación del ID del equipo).
   * Si esto **no se verifica**, **cualquier certificado de desarrollador** de Apple se puede usar para firmar y conectarse al servicio.
3. Verificar si el proceso de conexión **contiene un ID de paquete adecuado**.
   * Si esto **no se verifica**, cualquier herramienta **firmada por la misma organización** podría usarse para interactuar con el servicio XPC.
4. (4 o 5) Verificar si el proceso de conexión tiene un **número de versión de software adecuado**.
   * Si esto **no se verifica**, clientes antiguos e inseguros, vulnerables a la inyección de procesos, podrían usarse para conectarse al servicio XPC incluso con las otras comprobaciones en su lugar.
5. (4 o 5) Verificar si el proceso de conexión tiene un tiempo de ejecución reforzado sin permisos peligrosos (como los que permiten cargar bibliotecas arbitrarias o usar variables de entorno DYLD)
   * Si esto **no se verifica**, el cliente podría ser **vulnerable a la inyección de código**
6. Verificar si el proceso de conexión tiene un **permiso** que le permite conectarse al servicio. Esto es aplicable para binarios de Apple.
7. La **verificación** debe **basarse** en el **token de auditoría del cliente** que se conecta **en lugar** de su ID de proceso (**PID**), ya que el primero previene **ataques de reutilización de PID**.
   * Los desarrolladores **raramente usan la llamada a la API del token de auditoría** ya que es **privada**, por lo que Apple podría **cambiarla** en cualquier momento. Además, el uso de API privadas no está permitido en las aplicaciones de Mac App Store.
   * Si se utiliza el método **`processIdentifier`**, podría ser vulnerable
   * En lugar de **`xpc_connection_get_audit_token`**, se debería usar **`xpc_dictionary_get_audit_token`**, ya que el último también podría ser [vulnerable en ciertas situaciones](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Ataques de Comunicación

Para más información sobre el ataque de reutilización de PID, consulta:

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

Para más información sobre el ataque **`xpc_connection_get_audit_token`**, consulta:

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - Prevención de Ataques de Degradación

Trustcache es un método defensivo introducido en las máquinas de Apple Silicon que almacena una base de datos de CDHSAH de binarios de Apple para que solo se puedan ejecutar binarios no modificados y permitidos. Esto previene la ejecución de versiones anteriores.

### Ejemplos de Código

El servidor implementará esta **verificación** en una función llamada **`shouldAcceptNewConnection`**.

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

El objeto NSXPCConnection tiene una propiedad **privada** **`auditToken`** (la que debería usarse pero podría cambiar) y una propiedad **pública** **`processIdentifier`** (la que no debería usarse).

El proceso de conexión podría verificarse con algo como:

{% code overflow="wrap" %}
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
{% endcode %}

Si un desarrollador no desea verificar la versión del cliente, podría al menos asegurarse de que el cliente no sea vulnerable a la inyección de procesos:

{% code overflow="wrap" %}
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
<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
