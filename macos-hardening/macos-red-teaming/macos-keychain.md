# Llavero de macOS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Llaveros Principales

* El **Llavero de Usuario** (`~/Library/Keychains/login.keycahin-db`), que se utiliza para almacenar **credenciales específicas del usuario** como contraseñas de aplicaciones, contraseñas de internet, certificados generados por el usuario, contraseñas de redes y claves públicas/privadas generadas por el usuario.
* El **Llavero del Sistema** (`/Library/Keychains/System.keychain`), que almacena **credenciales de todo el sistema** como contraseñas de WiFi, certificados raíz del sistema, claves privadas del sistema y contraseñas de aplicaciones del sistema.

### Acceso al Llavero de Contraseñas

Estos archivos, aunque no tienen protección inherente y pueden ser **descargados**, están encriptados y requieren la **contraseña en texto plano del usuario para ser descifrados**. Se podría utilizar una herramienta como [**Chainbreaker**](https://github.com/n0fate/chainbreaker) para el descifrado.

## Protecciones de las Entradas del Llavero

### ACLs

Cada entrada en el llavero está gobernada por **Listas de Control de Acceso (ACLs)** que dictan quién puede realizar diversas acciones en la entrada del llavero, incluyendo:

* **ACLAuhtorizationExportClear**: Permite al poseedor obtener el texto claro del secreto.
* **ACLAuhtorizationExportWrapped**: Permite al poseedor obtener el texto claro encriptado con otra contraseña proporcionada.
* **ACLAuhtorizationAny**: Permite al poseedor realizar cualquier acción.

Las ACLs están acompañadas por una **lista de aplicaciones de confianza** que pueden realizar estas acciones sin solicitar autorización. Esto podría ser:

* &#x20;**N`il`** (no se requiere autorización, **todos son de confianza**)
* Una lista **vacía** (**nadie** es de confianza)
* **Lista** de **aplicaciones** específicas.

Además, la entrada puede contener la clave **`ACLAuthorizationPartitionID`,** que se utiliza para identificar el **teamid, apple,** y **cdhash.**

* Si se especifica el **teamid**, entonces para **acceder al valor de la entrada** **sin** un **aviso** la aplicación utilizada debe tener el **mismo teamid**.
* Si se especifica el **apple**, entonces la aplicación necesita estar **firmada** por **Apple**.
* Si se indica el **cdhash**, entonces la **aplicación** debe tener el **cdhash** específico.

### Creando una Entrada en el Llavero

Cuando se crea una **nueva** **entrada** utilizando **`Keychain Access.app`**, se aplican las siguientes reglas:

* Todas las aplicaciones pueden encriptar.
* **Ninguna aplicación** puede exportar/descifrar (sin solicitar al usuario).
* Todas las aplicaciones pueden ver la verificación de integridad.
* Ninguna aplicación puede cambiar las ACLs.
* El **partitionID** se establece en **`apple`**.

Cuando una **aplicación crea una entrada en el llavero**, las reglas son ligeramente diferentes:

* Todas las aplicaciones pueden encriptar.
* Solo la **aplicación creadora** (o cualquier otra aplicación explícitamente añadida) puede exportar/descifrar (sin solicitar al usuario).
* Todas las aplicaciones pueden ver la verificación de integridad.
* Ninguna aplicación puede cambiar las ACLs.
* El **partitionID** se establece en **`teamid:[teamID aquí]`**.

## Accediendo al Llavero

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
La **enumeración de llaveros y el volcado** de secretos que **no generarán un aviso** se pueden realizar con la herramienta [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Listar y obtener **información** sobre cada entrada del llavero:

* La API **`SecItemCopyMatching`** proporciona información sobre cada entrada y hay algunos atributos que puedes configurar al usarla:
* **`kSecReturnData`**: Si es verdadero, intentará descifrar los datos (establecer en falso para evitar posibles ventanas emergentes)
* **`kSecReturnRef`**: Obtener también referencia al elemento del llavero (establecer en verdadero en caso de que luego veas que puedes descifrar sin ventana emergente)
* **`kSecReturnAttributes`**: Obtener metadatos sobre las entradas
* **`kSecMatchLimit`**: Cuántos resultados devolver
* **`kSecClass`**: Qué tipo de entrada del llavero

Obtener **ACLs** de cada entrada:

* Con la API **`SecAccessCopyACLList`** puedes obtener el **ACL para el elemento del llavero**, y devolverá una lista de ACLs (como `ACLAuhtorizationExportClear` y los otros mencionados anteriormente) donde cada lista tiene:
* Descripción
* **Lista de Aplicaciones Confiables**. Esto podría ser:
* Una aplicación: /Applications/Slack.app
* Un binario: /usr/libexec/airportd
* Un grupo: group://AirPort

Exportar los datos:

* La API **`SecKeychainItemCopyContent`** obtiene el texto plano
* La API **`SecItemExport`** exporta las claves y certificados pero podría tener que establecer contraseñas para exportar el contenido cifrado

Y estos son los **requisitos** para poder **exportar un secreto sin un aviso**:

* Si hay **1+ aplicaciones confiables** listadas:
* Necesitar las **autorizaciones** apropiadas (**`Nil`**, o ser **parte** de la lista de aplicaciones permitidas en la autorización para acceder a la información secreta)
* Necesitar que la firma de código coincida con **PartitionID**
* Necesitar que la firma de código coincida con la de una **aplicación confiable** (o ser miembro del correcto KeychainAccessGroup)
* Si **todas las aplicaciones son confiables**:
* Necesitar las **autorizaciones** apropiadas
* Necesitar que la firma de código coincida con **PartitionID**
* Si **no hay PartitionID**, entonces esto no es necesario

{% hint style="danger" %}
Por lo tanto, si hay **1 aplicación listada**, necesitas **inyectar código en esa aplicación**.

Si **apple** está indicado en el **partitionID**, podrías acceder con **`osascript`** así que cualquier cosa que confíe en todas las aplicaciones con apple en el partitionID. **`Python`** también podría usarse para esto.
{% endhint %}

### Dos atributos adicionales

* **Invisible**: Es una bandera booleana para **ocultar** la entrada de la aplicación **UI** Keychain
* **General**: Es para almacenar **metadatos** (por lo que NO ESTÁ CIFRADO)
* Microsoft estaba almacenando en texto plano todos los tokens de actualización para acceder a puntos finales sensibles.

## Referencias

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
