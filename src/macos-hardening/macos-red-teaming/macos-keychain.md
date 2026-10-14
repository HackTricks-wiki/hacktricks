# Llavero de macOS

{{#include ../../banners/hacktricks-training.md}}

## Llaveros principales

- El **llavero del usuario** (`~/Library/Keychains/login.keychain-db`), que se utiliza para almacenar **credenciales específicas del usuario**, como contraseñas de aplicaciones, contraseñas de Internet, certificados generados por el usuario, contraseñas de red y claves públicas/privadas generadas por el usuario.
- El **llavero del sistema** (`/Library/Keychains/System.keychain`), que almacena **credenciales de todo el sistema**, como contraseñas de WiFi, certificados raíz del sistema, claves privadas del sistema y contraseñas de aplicaciones del sistema.<sup>[[1]](#references)</sup>
  - Es posible encontrar otros componentes, como certificados, en `/System/Library/Keychains/*`
- En **iOS** solo hay un **llavero**, ubicado en `/private/var/Keychains/`. Esta carpeta también contiene bases de datos de `TrustStore`, autoridades de certificación (`caissuercache`) y entradas OSCP (`ocspache`).
  - Las aplicaciones solo tendrán acceso a su área privada del llavero, según su identificador de aplicación.

### Acceso al llavero mediante contraseña

Aunque estos archivos no tienen protección inherente y se pueden **descargar**, están cifrados y requieren la **contraseña del usuario en texto plano para descifrarlos**. Se podría utilizar una herramienta como [**Chainbreaker**](https://github.com/n0fate/chainbreaker) para descifrarlos.<sup>[[1]](#references)</sup>

## Protecciones de las entradas del llavero

### ACL

Cada entrada del llavero se rige por **listas de control de acceso (ACL)**, que determinan quién puede realizar distintas acciones sobre ella, como:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Permite al titular obtener el secreto en texto claro.
- **`kSecACLAuthorizationExportWrapped`**: Permite al titular obtener el texto claro cifrado con otra contraseña proporcionada.
- **`kSecACLAuthorizationAny`**: Permite al titular realizar cualquier acción.

Las ACL también incluyen una **lista de aplicaciones de confianza** que pueden realizar estas acciones sin mostrar un aviso. Puede tratarse de:<sup>[[1]](#references)</sup>

- **N`il`** (no se requiere autorización, **todos son de confianza**)
- Una lista **vacía** (**nadie** es de confianza)
- Una **lista** de **aplicaciones** específicas.

La entrada también puede contener la clave **`kSecACLAuthorizationPartitionID`,** que se utiliza para identificar **teamid, apple** y **cdhash**.<sup>[[1]](#references)[[2]](#references)</sup>

- Si se especifica **teamid**, la aplicación debe tener el **mismo teamid** para **acceder al valor** de la entrada **sin** mostrar un **aviso**.
- Si se especifica **apple**, la aplicación debe estar **firmada** por **Apple**.
- Si se indica **cdhash**, la **aplicación** debe tener el **cdhash** específico.

### Creación de una entrada en el llavero

Cuando se crea una **nueva** **entrada** usando **`Keychain Access.app`**, se aplican las siguientes reglas:<sup>[[1]](#references)</sup>

- Todas las aplicaciones pueden cifrar.
- **Ninguna aplicación** puede exportar/descifrar (sin mostrar un aviso al usuario).
- Todas las aplicaciones pueden ver la comprobación de integridad.
- Ninguna aplicación puede cambiar las ACL.
- El **partitionID** se establece en **`apple`**.

Cuando una **aplicación crea una entrada en el llavero**, las reglas son ligeramente distintas:<sup>[[1]](#references)</sup>

- Todas las aplicaciones pueden cifrar.
- Solo la **aplicación que la creó** (o cualquier otra aplicación añadida explícitamente) puede exportar/descifrar (sin mostrar un aviso al usuario).
- Todas las aplicaciones pueden ver la comprobación de integridad.
- Ninguna aplicación puede cambiar las ACL.
- El **partitionID** se establece en **`teamid:[teamID here]`**.

## Acceso al llavero

### `security`

```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entry's PartitionID value
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S` establece la lista de particiones del elemento, mientras que `-k` proporciona la contraseña actual del Keychain necesaria para realizar ese cambio; la opción que recibe la contraseña está obsoleta.<sup>[[4]](#references)</sup> Una actualización correcta no demuestra que una lectura posterior se realice sin avisos: se observó que un prototipo deshabilitado seguía mostrando un aviso de confirmación al consultar el elemento mediante `Security.framework`. Un ID de partición coincidente es solo una parte de las comprobaciones de ACL y de aplicaciones de confianza descritas anteriormente, así que verifica la ruta de lectura real.<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> La **enumeración y extracción de secretos del Keychain** que **no generarán un aviso** se puede realizar con la herramienta [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Puedes encontrar otros endpoints de API en el código fuente de [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Enumera y obtén **información** sobre cada entrada del Keychain mediante **Security Framework**; también puedes consultar la herramienta CLI de código abierto de Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Algunos ejemplos de API:<sup>[[1]](#references)</sup>

- La API **`SecItemCopyMatching`** proporciona información sobre cada entrada y tiene varios atributos que puedes establecer al usarla:
  - **`kSecReturnData`**: Si es true, intentará descifrar los datos (establécelo en false para evitar posibles ventanas emergentes)
  - **`kSecReturnRef`**: También obtiene una referencia al elemento del Keychain (establécelo en true por si luego descubres que puedes descifrarlo sin una ventana emergente)
  - **`kSecReturnAttributes`**: Obtiene metadatos sobre las entradas
  - **`kSecMatchLimit`**: Cuántos resultados devolver
  - **`kSecClass`**: Qué tipo de entrada del Keychain

Obtén las **ACL** de cada entrada:<sup>[[1]](#references)</sup>

- Con la API **`SecAccessCopyACLList`** puedes obtener la **ACL del elemento del Keychain**. Devuelve una lista de ACL (como `kSecACLAuthorizationExportClear` y las otras mencionadas anteriormente), donde cada entrada tiene:<sup>[[1]](#references)[[2]](#references)</sup>
  - Una descripción
  - **Una lista de aplicaciones de confianza**. Puede incluir:
    - Una app: /Applications/Slack.app
    - Un binario: /usr/libexec/airportd
    - Un grupo: group://AirPort

Exporta los datos:<sup>[[1]](#references)</sup>

- La API **`SecKeychainItemCopyContent`** obtiene el texto sin cifrar
- La API **`SecItemExport`** exporta las claves y los certificados, pero puede que tengas que establecer contraseñas para exportar el contenido cifrado

Estos son los **requisitos** para poder **exportar un secreto sin que aparezca un aviso**:<sup>[[1]](#references)</sup>

- Si hay **1 o más apps de confianza** en la lista:
  - Se necesitan las **autorizaciones** apropiadas (**`Nil`** o formar **parte** de la lista de apps permitidas en la autorización para acceder a la información secreta)
  - La firma del código debe coincidir con **PartitionID**
  - La firma del código debe coincidir con la de una **app de confianza** (o se debe pertenecer al KeychainAccessGroup correcto)
- Si **todas las aplicaciones son de confianza**:
  - Se necesitan las **autorizaciones** apropiadas
  - La firma del código debe coincidir con **PartitionID**
    - Si no hay **PartitionID**, no es necesario

> [!CAUTION]
> Por lo tanto, si hay **1 aplicación en la lista**, debes **inyectar código en esa aplicación**.
>
> Si **apple** aparece en **partitionID**, puedes acceder mediante **`osascript`**; esto aplica a cualquier elemento que confíe en todas las aplicaciones y tenga apple en partitionID. También se puede usar **`Python`**.

### Dos atributos adicionales

- **Invisible**: Es un indicador booleano para **ocultar** la entrada en la app **Keychain** de la **UI**<sup>[[1]](#references)</sup>
- **General**: Sirve para almacenar **metadatos** (por lo que NO ESTÁ CIFRADO)<sup>[[1]](#references)</sup>
  - Microsoft almacenaba en texto sin cifrar todos los refresh tokens para acceder a endpoints sensibles.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [#OBTS v5.0: «Forzar la cerradura del Keychain de macOS» - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - Una nueva versión del ladrón de macOS MacSync apunta a entusiastas de las criptomonedas y desarrolladores](https://securelist.com/macsync-new-version/121383/)
- [4] [Copia espejo de la página man de Apple security(1)](https://keith.github.io/xcode-man-pages/security.1.html)
