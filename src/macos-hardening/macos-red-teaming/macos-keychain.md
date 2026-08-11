# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Keychains principales

- El **User Keychain** (`~/Library/Keychains/login.keychain-db`), que se utiliza para almacenar **credenciales específicas del usuario**, como contraseñas de aplicaciones, contraseñas de Internet, certificados generados por el usuario, contraseñas de red y claves públicas/privadas generadas por el usuario.
- El **System Keychain** (`/Library/Keychains/System.keychain`), que almacena **credenciales de todo el sistema**, como contraseñas de WiFi, certificados raíz del sistema, claves privadas del sistema y contraseñas de aplicaciones del sistema.<sup>[[1]](#references)</sup>
- Es posible encontrar otros componentes, como certificados, en `/System/Library/Keychains/*`
- En **iOS** solo existe un **Keychain**, ubicado en `/private/var/Keychains/`. Esta carpeta también contiene bases de datos para `TrustStore`, autoridades certificadoras (`caissuercache`) y entradas OSCP (`ocspache`).
- Las aplicaciones estarán restringidas en el keychain únicamente a su área privada, según su identificador de aplicación.

### Acceso mediante contraseña al Keychain

Estos archivos, aunque no tienen protección inherente y pueden ser **descargados**, están cifrados y requieren la **contraseña del usuario en texto plano para ser descifrados**. Se podría utilizar una herramienta como [**Chainbreaker**](https://github.com/n0fate/chainbreaker) para descifrarlos.<sup>[[1]](#references)</sup>

## Protecciones de las entradas del Keychain

### ACLs

Cada entrada del keychain está gobernada por **listas de control de acceso (ACLs)**, que determinan quién puede realizar diversas acciones sobre la entrada del keychain, incluyendo:<sup>[[1]](#references)</sup>

- **ACLAuthorizationExportClear**: Permite al titular obtener el secreto en texto plano.
- **ACLAuthorizationExportWrapped**: Permite al titular obtener el texto plano cifrado con otra contraseña proporcionada.
- **ACLAuthorizationAny**: Permite al titular realizar cualquier acción.

Las ACLs también están acompañadas de una **lista de aplicaciones de confianza** que pueden realizar estas acciones sin mostrar un aviso. Esta lista puede ser:<sup>[[1]](#references)</sup>

- **N`il`** (no se requiere autorización, **todos son de confianza**)
- Una lista **vacía** (**nadie** es de confianza)
- **Lista** de **aplicaciones** específicas.

Además, la entrada puede contener la clave **`ACLAuthorizationPartitionID`,** que se utiliza para identificar el **teamid, apple** y **cdhash**.<sup>[[1]](#references)</sup>

- Si se especifica el **teamid**, la aplicación debe tener el **mismo teamid** para **acceder al valor de la entrada** sin un **aviso**.
- Si se especifica **apple**, la aplicación debe estar **firmada** por **Apple**.
- Si se indica el **cdhash**, la **aplicación** debe tener el **cdhash** específico.

### Creación de una entrada del Keychain

Cuando se crea una **nueva** **entrada** mediante **`Keychain Access.app`**, se aplican las siguientes reglas:<sup>[[1]](#references)</sup>

- Todas las aplicaciones pueden cifrar.
- **Ninguna aplicación** puede exportar/descifrar (sin mostrar un aviso al usuario).
- Todas las aplicaciones pueden ver la comprobación de integridad.
- Ninguna aplicación puede modificar las ACLs.
- El **partitionID** se establece en **`apple`**.

Cuando una **aplicación crea una entrada en el keychain**, las reglas son ligeramente diferentes:<sup>[[1]](#references)</sup>

- Todas las aplicaciones pueden cifrar.
- Solo la **aplicación que la creó** (o cualquier otra aplicación añadida explícitamente) puede exportar/descifrar (sin mostrar un aviso al usuario).
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

# Change the specified entry's PartitionID value
security set-generic-password-partition-list -s "test service" -a "test account" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> La **enumeración y extracción de secretos del keychain** que **no generen un prompt** se puede realizar con la herramienta [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Se pueden encontrar otros endpoints de API en el código fuente de [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) de código abierto.

Lista y obtén **información** sobre cada entrada del keychain usando el **Security Framework**, o también puedes consultar la herramienta CLI de código abierto de Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Algunos ejemplos de API:<sup>[[1]](#references)</sup>

- La API **`SecItemCopyMatching`** proporciona información sobre cada entrada y permite establecer algunos atributos al utilizarla:
- **`kSecReturnData`**: Si es true, intentará descifrar los datos (establecer en false para evitar posibles pop-ups)
- **`kSecReturnRef`**: Obtiene también una referencia al elemento del keychain (establecer en true si posteriormente compruebas que puedes descifrarlo sin un pop-up)
- **`kSecReturnAttributes`**: Obtiene metadatos sobre las entradas
- **`kSecMatchLimit`**: Cuántos resultados devolver
- **`kSecClass`**: Qué tipo de entrada del keychain

Obtén las **ACLs** de cada entrada:<sup>[[1]](#references)</sup>

- Con la API **`SecAccessCopyACLList`** puedes obtener la **ACL del elemento del keychain**. Devuelve una lista de ACLs (como `ACLAuthorizationExportClear` y las demás mencionadas anteriormente), donde cada entrada tiene:
- Descripción
- **Trusted Application List**. Esta puede contener:
- Una app: /Applications/Slack.app
- Un binario: /usr/libexec/airportd
- Un grupo: group://AirPort

Exporta los datos:<sup>[[1]](#references)</sup>

- La API **`SecKeychainItemCopyContent`** obtiene el texto plano
- La API **`SecItemExport`** exporta las claves y los certificados, pero puede ser necesario establecer contraseñas para exportar el contenido cifrado

Y estos son los **requisitos** para poder **exportar un secreto sin un prompt**:<sup>[[1]](#references)</sup>

- Si hay **1 o más apps trusted** listadas:
- Se necesitan las **autorizaciones** apropiadas (**`Nil`**, o formar **parte** de la lista permitida de apps en la autorización para acceder a la información secreta)
- La firma de código debe coincidir con **PartitionID**
- La firma de código debe coincidir con la de una **app trusted** (o ser miembro del KeychainAccessGroup correcto)
- Si **todas las aplicaciones son trusted**:
- Se necesitan las **autorizaciones** apropiadas
- La firma de código debe coincidir con **PartitionID**
- Si no hay **PartitionID**, esto no es necesario

> [!CAUTION]
> Por lo tanto, si hay **1 aplicación listada**, necesitas **inyectar código en esa aplicación**.
>
> Si se indica **apple** en el **partitionID**, podrías acceder a él con **`osascript`**, por lo que cualquier aplicación que confíe en todas las aplicaciones con apple en el partitionID. También se podría utilizar **`Python`**.

### Dos atributos adicionales

- **Invisible**: Es un indicador booleano para **ocultar** la entrada de la app **UI** Keychain<sup>[[1]](#references)</sup>
- **General**: Sirve para almacenar **metadatos** (por lo que NO ESTÁ CIFRADO)<sup>[[1]](#references)</sup>
- Microsoft almacenaba en texto plano todos los refresh tokens para acceder a endpoints sensibles.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Forzando la cerradura del macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
{{#include ../../banners/hacktricks-training.md}}
