# macOS Keychain

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Cadenas de claves principales

* La **Cadena de claves de usuario** (`~/Library/Keychains/login.keycahin-db`), que se utiliza para almacenar **credenciales específicas del usuario** como contraseñas de aplicaciones, contraseñas de Internet, certificados generados por el usuario, contraseñas de red y claves públicas / privadas generadas por el usuario.
* La **Cadena de claves del sistema** (`/Library/Keychains/System.keychain`), que almacena **credenciales de todo el sistema** como contraseñas de WiFi, certificados raíz del sistema, claves privadas del sistema y contraseñas de aplicaciones del sistema.

### Acceso a la cadena de claves de contraseñas

Estos archivos, aunque no tienen protección inherente y se pueden **descargar**, están cifrados y requieren la **contraseña en texto plano del usuario para descifrarlos**. Se puede utilizar una herramienta como [**Chainbreaker**](https://github.com/n0fate/chainbreaker) para descifrarlos.

## Protecciones de entradas de la cadena de claves

### ACLs

Cada entrada en la cadena de claves está gobernada por **Listas de control de acceso (ACL)** que dictan quién puede realizar varias acciones en la entrada de la cadena de claves, incluyendo:

* **ACLAuhtorizationExportClear**: Permite al titular obtener el texto claro del secreto.
* **ACLAuhtorizationExportWrapped**: Permite al titular obtener el texto claro cifrado con otra contraseña proporcionada.
* **ACLAuhtorizationAny**: Permite al titular realizar cualquier acción.

Las ACL también están acompañadas por una **lista de aplicaciones de confianza** que pueden realizar estas acciones sin solicitar permiso. Esto podría ser:

* &#x20;**N`il`** (no se requiere autorización, **todos son de confianza**)
* Una lista **vacía** (nadie es de confianza)
* **Lista** de **aplicaciones** específicas.

Además, la entrada puede contener la clave **`ACLAuthorizationPartitionID`**, que se utiliza para identificar el **teamid, apple** y **cdhash.**

* Si se especifica el **teamid**, entonces para **acceder** al valor de la entrada **sin** una **solicitud**, la aplicación utilizada debe tener el **mismo teamid**.
* Si se especifica el **apple**, entonces la aplicación debe estar **firmada** por **Apple**.
* Si se indica el **cdhash**, entonces la **aplicación** debe tener el **cdhash** específico.

### Creación de una entrada de cadena de claves

Cuando se crea una **nueva entrada** utilizando **`Keychain Access.app`**, se aplican las siguientes reglas:

* Todas las aplicaciones pueden cifrar.
* **Ninguna aplicación** puede exportar/descifrar (sin solicitar al usuario).
* Todas las aplicaciones pueden ver la comprobación de integridad.
* Ninguna aplicación puede cambiar las ACL.
* El **partitionID** se establece en **`apple`**.

Cuando una **aplicación crea una entrada en la cadena de claves**, las reglas son ligeramente diferentes:

* Todas las aplicaciones pueden cifrar.
* Solo la **aplicación creadora** (o cualquier otra aplicación agregada explícitamente) puede exportar/descifrar (sin solicitar al usuario).
* Todas las aplicaciones pueden ver la comprobación de integridad.
* Ninguna aplicación puede cambiar las ACL.
* El **partitionID** se establece en **`teamid:[teamID aquí]`**.

## Acceso a la cadena de claves

### `security`
```bash
# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S
```
### APIs

{% hint style="success" %}
La **enumeración y volcado** de secretos del **llavero que no generan una ventana emergente** se puede hacer con la herramienta [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Lista y obtén **información** sobre cada entrada del llavero:

* La API **`SecItemCopyMatching`** da información sobre cada entrada y hay algunos atributos que se pueden establecer al usarla:
  * **`kSecReturnData`**: Si es verdadero, intentará descifrar los datos (establecer en falso para evitar posibles ventanas emergentes)
  * **`kSecReturnRef`**: Obtener también la referencia al elemento del llavero (establecer en verdadero en caso de que luego vea que puede descifrar sin ventana emergente)
  * **`kSecReturnAttributes`**: Obtener metadatos sobre las entradas
  * **`kSecMatchLimit`**: Cuántos resultados devolver
  * **`kSecClass`**: Qué tipo de entrada del llavero

Obtén **ACLs** de cada entrada:

* Con la API **`SecAccessCopyACLList`** puedes obtener el **ACL para el elemento del llavero**, y devolverá una lista de ACL (como `ACLAuhtorizationExportClear` y los otros mencionados anteriormente) donde cada lista tiene:
  * Descripción
  * **Lista de aplicaciones de confianza**. Esto podría ser:
    * Una aplicación: /Applications/Slack.app
    * Un binario: /usr/libexec/airportd
    * Un grupo: group://AirPort

Exporta los datos:

* La API **`SecKeychainItemCopyContent`** obtiene el texto sin formato
* La API **`SecItemExport`** exporta las claves y certificados, pero es posible que tenga que establecer contraseñas para exportar el contenido cifrado

Y estos son los **requisitos** para poder **exportar un secreto sin una ventana emergente**:

* Si hay **1 o más aplicaciones de confianza** listadas:
  * Necesita las **autorizaciones** apropiadas (**`Nil`**, o ser **parte** de la lista permitida de aplicaciones en la autorización para acceder a la información secreta)
  * Necesita que la firma del código coincida con **PartitionID**
  * Necesita que la firma del código coincida con la de una **aplicación de confianza** (o ser miembro del grupo KeychainAccessGroup correcto)
* Si **todas las aplicaciones son de confianza**:
  * Necesita las **autorizaciones** apropiadas
  * Necesita que la firma del código coincida con **PartitionID**
    * Si **no hay PartitionID**, entonces esto no es necesario

{% hint style="danger" %}
Por lo tanto, si hay **1 aplicación listada**, necesitas **inyectar código en esa aplicación**.

Si **apple** está indicado en el **PartitionID**, se puede acceder con **`osascript`** a cualquier cosa que confíe en todas las aplicaciones con apple en el PartitionID. **`Python`** también se puede usar para esto.
{% endhint %}

### Dos atributos adicionales

* **Invisible**: Es una bandera booleana para **ocultar** la entrada de la aplicación **UI** del llavero
* **General**: Es para almacenar **metadatos** (por lo que NO ESTÁ CIFRADO)
  * Microsoft estaba almacenando en texto sin formato todos los tokens de actualización para acceder a puntos finales sensibles.

## Referencias

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿o quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
