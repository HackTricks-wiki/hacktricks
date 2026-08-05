# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Keychains principales

- El **User Keychain** (`~/Library/Keychains/login.keychain-db`), que se utiliza para almacenar **credenciales específicas del usuario**, como contraseñas de aplicaciones, contraseñas de Internet, certificados generados por el usuario, contraseñas de red y claves públicas/privadas generadas por el usuario.
- El **System Keychain** (`/Library/Keychains/System.keychain`), que almacena **credenciales de todo el sistema**, como contraseñas de WiFi, certificados raíz del sistema, claves privadas del sistema y contraseñas de aplicaciones del sistema.<sup>[1]</sup>
- Es posible encontrar otros componentes, como certificados, en `/System/Library/Keychains/*`
- En **iOS** solo hay un **Keychain**, ubicado en `/private/var/Keychains/`. Esta carpeta también contiene bases de datos para `TrustStore`, autoridades de certificación (`caissuercache`) y entradas OSCP (`ocspache`).
- Las aplicaciones estarán restringidas en el keychain únicamente a su área privada, según su identificador de aplicación.

### Acceso mediante contraseña al Keychain

Estos archivos, aunque no tienen protección inherente y pueden ser **downloaded**, están cifrados y requieren la **contraseña del usuario en texto plano para ser descifrados**. Una herramienta como [**Chainbreaker**](https://github.com/n0fate/chainbreaker) podría utilizarse para el descifrado.<sup>[1]</sup>

## Protecciones de las entradas del Keychain

### ACLs

Cada entrada del keychain está regulada por **Access Control Lists (ACLs)**, que determinan quién puede realizar varias acciones sobre la entrada del keychain, incluyendo:<sup>[1]</sup>

- **ACLAuhtorizationExportClear**: Permite al titular obtener el secreto en texto plano.
- **ACLAuhtorizationExportWrapped**: Permite al titular obtener el texto plano cifrado con otra contraseña proporcionada.
- **ACLAuhtorizationAny**: Permite al titular realizar cualquier acción.

Las ACLs también incluyen una **lista de aplicaciones de confianza** que pueden realizar estas acciones sin mostrar un aviso. Esta lista puede ser:<sup>[1]</sup>

- **N`il`** (no se requiere autorización, **todos son de confianza**)
- Una lista **vacía** (**nadie** es de confianza)
- **Lista** de **aplicaciones** específicas.

Además, la entrada puede contener la clave **`ACLAuthorizationPartitionID`,** que se utiliza para identificar **teamid, apple** y **cdhash**.<sup>[1]</sup>

- Si se especifica **teamid**, para poder **acceder al valor de la entrada** **sin** mostrar un **aviso**, la aplicación utilizada debe tener el **mismo teamid**.
- Si se especifica **apple**, la aplicación debe estar **firmada** por **Apple**.
- Si se indica **cdhash**, la **aplicación** debe tener el **cdhash** específico.

### Creación de una entrada del Keychain

Cuando se crea una **nueva** **entrada** utilizando **`Keychain Access.app`**, se aplican las siguientes reglas:<sup>[1]</sup>

- Todas las aplicaciones pueden cifrar.
- **Ninguna aplicación** puede exportar/descifrar (sin solicitar confirmación al usuario).
- Todas las aplicaciones pueden ver la comprobación de integridad.
- Ninguna aplicación puede modificar las ACLs.
- El **partitionID** se establece en **`apple`**.

Cuando una **aplicación crea una entrada en el keychain**, las reglas son ligeramente diferentes:<sup>[1]</sup>

- Todas las aplicaciones pueden cifrar.
- Solo la **aplicación que la crea** (o cualquier otra aplicación añadida explícitamente) puede exportar/descifrar (sin solicitar confirmación al usuario).
- Todas las aplicaciones pueden ver la comprobación de integridad.
- Ninguna aplicación puede modificar las ACLs.
- El **partitionID** se establece en **`teamid:[teamID here]`**.

## Acceso al Keychain

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> La **enumeración y el dumping de secretos del keychain** que **no generen un prompt** se pueden realizar con la herramienta [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Otros endpoints de API se pueden encontrar en el código fuente [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) de Apple.

Lista y obtén **info** sobre cada entrada del keychain usando el **Security Framework** o también puedes consultar la herramienta cli open source de Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Algunos ejemplos de API:<sup>[1]</sup>

- La API **`SecItemCopyMatching`** proporciona información sobre cada entrada y hay algunos atributos que puedes establecer al usarla:
- **`kSecReturnData`**: Si es true, intentará descifrar los datos (establecerlo en false para evitar posibles pop-ups)
- **`kSecReturnRef`**: Obtiene también la referencia al elemento del keychain (establecerlo en true si posteriormente compruebas que puedes descifrarlo sin pop-up)
- **`kSecReturnAttributes`**: Obtiene metadata sobre las entradas
- **`kSecMatchLimit`**: Cuántos resultados devolver
- **`kSecClass`**: Qué tipo de entrada del keychain

Obtén las **ACLs** de cada entrada:<sup>[1]</sup>

- Con la API **`SecAccessCopyACLList`** puedes obtener la **ACL del elemento del keychain**, y devolverá una lista de ACLs (como `ACLAuhtorizationExportClear` y las otras mencionadas anteriormente), donde cada lista contiene:
- Descripción
- **Trusted Application List**. Esta puede incluir:
- Una app: /Applications/Slack.app
- Un binario: /usr/libexec/airportd
- Un grupo: group://AirPort

Exporta los datos:<sup>[1]</sup>

- La API **`SecKeychainItemCopyContent`** obtiene el plaintext
- La API **`SecItemExport`** exporta las keys y los certificados, pero puede ser necesario establecer passwords para exportar el contenido cifrado

Y estos son los **requisitos** para poder **exportar un secreto sin un prompt**:<sup>[1]</sup>

- Si hay **1+** apps **trusted** listadas:
- Se necesitan las **authorizations** apropiadas (**`Nil`**, o formar **parte** de la lista permitida de apps en la autorización para acceder a la información sensible)
- La code signature debe coincidir con **PartitionID**
- La code signature debe coincidir con la de una **trusted app** (o ser miembro del KeychainAccessGroup correcto)
- Si **todas las aplicaciones son trusted**:
- Se necesitan las **authorizations** apropiadas
- La code signature debe coincidir con **PartitionID**
- Si no hay **PartitionID**, esto no es necesario

> [!CAUTION]
> Por lo tanto, si hay **1 aplicación listada**, necesitas **inyectar código en esa aplicación**.
>
> Si se indica **apple** en el **partitionID**, podrías acceder a ella con **`osascript`**, por lo que cualquier aplicación que confíe en todas las aplicaciones con apple en el partitionID. También se podría utilizar **`Python`** para esto.

### Two additional attributes

- **Invisible**: Es un flag booleano para **ocultar** la entrada de la app **UI** Keychain<sup>[1]</sup>
- **General**: Sirve para almacenar **metadata** (por lo que **NO ESTÁ CIFRADA**)<sup>[1]</sup>
- Microsoft estaba almacenando en plaintext todos los refresh tokens para acceder a endpoints sensibles.<sup>[1]</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
