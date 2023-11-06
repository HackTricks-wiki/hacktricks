# Comprobación de Conexión de Proceso XPC en macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Comprobación de Conexión de Proceso XPC

Cuando se establece una conexión a un servicio XPC, el servidor verificará si la conexión está permitida. Estas son las comprobaciones que normalmente se realizan:

1. Comprobar si el **proceso de conexión está firmado con un certificado firmado por Apple** (solo otorgado por Apple).
* Si esto **no se verifica**, un atacante podría crear un **certificado falso** para coincidir con cualquier otra comprobación.
2. Comprobar si el proceso de conexión está firmado con el **certificado de la organización** (verificación del ID del equipo).
* Si esto **no se verifica**, se puede utilizar cualquier certificado de desarrollador de Apple para firmar y conectarse al servicio.
3. Comprobar si el proceso de conexión **contiene un ID de paquete adecuado**.
* Si esto **no se verifica**, cualquier herramienta **firmada por la misma organización** podría utilizarse para interactuar con el servicio XPC.
4. (4 o 5) Comprobar si el proceso de conexión tiene un **número de versión de software adecuado**.
* Si esto **no se verifica**, se podrían utilizar clientes antiguos e inseguros, vulnerables a la inyección de procesos, para conectarse al servicio XPC incluso con las demás comprobaciones en su lugar.
5. (4 o 5) Comprobar si el proceso de conexión tiene un tiempo de ejecución endurecido sin permisos peligrosos (como los que permiten cargar bibliotecas arbitrarias o usar variables de entorno DYLD).
* Si esto **no se verifica**, el cliente podría ser **vulnerable a la inyección de código**.
6. Comprobar si el proceso de conexión tiene un **permiso** que le permite conectarse al servicio. Esto es aplicable para los binarios de Apple.
7. La **verificación** debe basarse en el **token de auditoría del cliente de conexión** en lugar de su ID de proceso (**PID**), ya que lo primero evita los ataques de reutilización de PID.
* Los desarrolladores **rara vez utilizan** la llamada a la API del token de auditoría ya que es **privada**, por lo que Apple podría **cambiarla** en cualquier momento. Además, no se permite el uso de API privadas en las aplicaciones de la Mac App Store.
* Debe utilizarse **`xpc_dictionary_get_audit_token`** en lugar de **`xpc_connection_get_audit_token`**, ya que este último también podría ser [vulnerable en ciertas situaciones](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Ataques de Comunicación

Para obtener más información sobre el ataque de reutilización de PID, consulta:

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

Para obtener más información sobre el ataque **`xpc_connection_get_audit_token`**, consulta:

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Prevención de Ataques de Degradación en Trustcache

Trustcache es un método defensivo introducido en las máquinas Apple Silicon que almacena una base de datos de CDHSAH de los binarios de Apple para que solo se puedan ejecutar binarios no modificados permitidos. Esto evita la ejecución de versiones anteriores.

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

El objeto NSXPCConnection tiene una propiedad **privada** llamada **`auditToken`** (la que se debería usar pero podría cambiar) y una propiedad **pública** llamada **`processIdentifier`** (la que no se debería usar).

El proceso de conexión se puede verificar de la siguiente manera:

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
Si un desarrollador no quiere verificar la versión del cliente, al menos podría verificar que el cliente no sea vulnerable a la inyección de procesos:

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
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
