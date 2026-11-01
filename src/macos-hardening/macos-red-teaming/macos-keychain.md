# Keychain de macOS

{{#include ../../banners/hacktricks-training.md}}

## Keychains principales

- El **Keychain del usuario** (`~/Library/Keychains/login.keychain-db`), que se utiliza para almacenar **credenciales específicas del usuario**, como contraseñas de aplicaciones, contraseñas de internet, certificados generados por el usuario, contraseñas de red y claves públicas/privadas generadas por el usuario.
- El **Keychain del sistema** (`/Library/Keychains/System.keychain`), que almacena **credenciales de todo el sistema**, como contraseñas de WiFi, certificados raíz del sistema, claves privadas del sistema y contraseñas de aplicaciones del sistema.<sup>[[1]](#references)</sup>
  - Es posible encontrar otros componentes, como certificados, en `/System/Library/Keychains/*`
- El **keychain de protección de datos** de cada usuario aparece como **Local Items** o **iCloud** en Keychain Access. Es independiente de `login.keychain-db` e incluye elementos solo locales y sincronizables; `security` es principalmente una herramienta para keychains basados en archivos, por lo que un resultado breve de `dump-keychain` no descarta que haya credenciales aquí.<sup>[[5]](#references)</sup>
- En **iOS** solo hay un **Keychain**, ubicado en `/private/var/Keychains/`. Esta carpeta también contiene bases de datos para `TrustStore`, autoridades de certificados (`caissuercache`) y entradas de OSCP (`ocspache`).
  - Las apps estarán restringidas en el keychain únicamente a su área privada, según su identificador de aplicación.

### Acceso a contraseñas del Keychain

Un keychain **basado en archivos** copiado no está en texto plano. El descifrado sin conexión de sus elementos protegidos requiere la contraseña del keychain o material de clave equivalente; [**Chainbreaker**](https://github.com/n0fate/chainbreaker) está diseñado para este formato.<sup>[[1]](#references)</sup> Esto difiere de una lectura en vivo en una sesión de usuario desbloqueada, donde los controles de acceso de los elementos pueden permitir la lectura o activar una solicitud sin requerir nuevamente la contraseña de inicio de sesión. El keychain de protección de datos tiene un modelo de protección y de grupos de acceso diferente.<sup>[[5]](#references)</sup>

## Protecciones de las entradas del Keychain

### ACL de keychains basados en archivos

Las reglas de ACL de `SecAccess` y de la lista de particiones que se indican a continuación describen keychains **basados en archivos**. En cambio, los elementos del keychain de protección de datos utilizan grupos de acceso de firma de código y condiciones opcionales de `SecAccessControl`; no deduzcas su accesibilidad a partir de un volcado de ACL de un keychain basado en archivos.<sup>[[5]](#references)</sup>

Cada entrada de un keychain basado en archivos se rige por **listas de control de acceso (ACL)** que determinan quién puede realizar distintas acciones sobre la entrada, entre ellas:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Permite al titular obtener el secreto en texto claro.
- **`kSecACLAuthorizationExportWrapped`**: Permite al titular obtener el texto claro cifrado con otra contraseña proporcionada.
- **`kSecACLAuthorizationAny`**: Permite al titular realizar cualquier acción.

Las ACL también incluyen una **lista de aplicaciones de confianza** que pueden realizar estas acciones sin mostrar una solicitud. Esta puede ser:<sup>[[1]](#references)</sup>

- **N`il`** (no se requiere autorización, **todos son de confianza**)
- Una lista **vacía** (**nadie** es de confianza)
- Una **lista** de **aplicaciones** específicas.

Además, la entrada podría contener la clave **`kSecACLAuthorizationPartitionID`,** que se utiliza para identificar **teamid, apple** y **cdhash**.<sup>[[1]](#references)[[2]](#references)</sup>

- Si se especifica **teamid**, la aplicación debe tener el **mismo teamid** para **acceder al valor** de la entrada **sin** una **solicitud**.
- Si se especifica **apple**, la app debe estar **firmada** por **Apple**.
- Si se indica **cdhash**, la **app** debe tener el **cdhash** específico.

### Crear una entrada en un keychain basado en archivos

Cuando se crea una **nueva** **entrada** mediante **`Keychain Access.app`**, se aplican las siguientes reglas:<sup>[[1]](#references)</sup>

- Todas las apps pueden cifrar.
- **Ninguna app** puede exportar/descifrar (sin solicitarlo al usuario).
- Todas las apps pueden ver la comprobación de integridad.
- Ninguna app puede cambiar las ACL.
- El **partitionID** se establece en **`apple`**.

Cuando una **aplicación crea una entrada en el keychain**, las reglas son ligeramente diferentes:<sup>[[1]](#references)</sup>

- Todas las apps pueden cifrar.
- Solo la **aplicación creadora** (o cualquier otra app añadida explícitamente) puede exportar/descifrar (sin solicitarlo al usuario).
- Todas las apps pueden ver la comprobación de integridad.
- Ninguna app puede cambiar las ACL.
- El **partitionID** se establece en **`teamid:[teamID here]`**.

## Acceder al Keychain

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

`-S` establece la lista de particiones del elemento, mientras que `-k` proporciona la contraseña actual del Keychain necesaria para realizar ese cambio; la opción que acepta la contraseña está obsoleta.<sup>[[4]](#references)</sup> Una actualización exitosa no demuestra que una lectura posterior no genere avisos: un prototipo deshabilitado observado seguía mostrando un aviso de confirmación cuando consultaba el elemento mediante `Security.framework`. Un ID de partición coincidente es solo una parte de las comprobaciones de ACL y de aplicaciones de confianza descritas anteriormente, así que verifica la ruta de lectura real.<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> La **enumeración del Keychain y la extracción de secretos** que **no generarán un aviso** se pueden realizar con la herramienta [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Puedes encontrar otros endpoints de API en el código fuente de [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Enumera y obtén **información** sobre cada entrada del Keychain usando **Security Framework** o también puedes consultar la herramienta CLI de código abierto de Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Algunos ejemplos de API:<sup>[[1]](#references)</sup>

- La API **`SecItemCopyMatching`** proporciona información sobre cada entrada y tiene algunos atributos que puedes establecer al usarla:
  - **`kSecReturnData`**: Si es true, intentará descifrar los datos (establece el valor en false para evitar posibles avisos emergentes)
  - **`kSecReturnRef`**: Obtiene una referencia de objeto para una clave, un certificado o una identidad; los elementos de contraseña no tienen esta representación de objeto. Usa `kSecReturnPersistentRef` para identificar una contraseña en una consulta específica posterior.<sup>[[6]](#references)</sup>
  - **`kSecReturnAttributes`**: Obtiene metadatos sobre las entradas
  - **`kSecMatchLimit`**: Cuántos resultados devolver
  - **`kSecClass`**: Qué tipo de entrada del Keychain

Obtén las **ACL** de cada entrada:<sup>[[1]](#references)</sup>

- Con la API **`SecAccessCopyACLList`** puedes obtener la **ACL del elemento del Keychain**. Devuelve una lista de ACL (como `kSecACLAuthorizationExportClear` y las otras mencionadas anteriormente), donde cada entrada tiene:<sup>[[1]](#references)[[2]](#references)</sup>
  - Descripción
  - **Lista de aplicaciones de confianza**. Puede ser:
    - Una app: /Applications/Slack.app
    - Un binario: /usr/libexec/airportd
    - Un grupo: group://AirPort

Exporta los datos:<sup>[[1]](#references)</sup>

- La API **`SecKeychainItemCopyContent`** obtiene el texto sin cifrar
- La API **`SecItemExport`** exporta las claves y los certificados, pero puede que haya que establecer contraseñas para exportar el contenido cifrado

Estos son los **requisitos** para poder **exportar un secreto sin que aparezca un aviso**:<sup>[[1]](#references)</sup>

- Si hay **1 o más apps de confianza** en la lista:
  - Se necesitan las **autorizaciones** apropiadas (**`Nil`** o formar **parte** de la lista de apps permitidas en la autorización para acceder a la información secreta)
  - La firma del código debe coincidir con el **PartitionID**
  - La firma del código debe coincidir con la de una **app de confianza** (o ser miembro del KeychainAccessGroup correcto)
- Si **todas las aplicaciones son de confianza**:
  - Se necesitan las **autorizaciones** apropiadas
  - La firma del código debe coincidir con el **PartitionID**
    - Si no hay **PartitionID**, no es necesario

> [!CAUTION]
> Por lo tanto, si hay **1 aplicación en la lista**, debes **inyectar código en esa aplicación**.
>
> Si se indica **apple** en el **partitionID**, podrías acceder con **`osascript`** a cualquier elemento que confíe en todas las aplicaciones con apple en el partitionID. También se puede usar **`Python`**.

### Dos atributos adicionales

- **Invisible**: Es un indicador booleano para **ocultar** la entrada de la app Keychain de la **UI**<sup>[[1]](#references)</sup>
- **General**: Sirve para almacenar **metadatos** (por lo tanto, NO ESTÁ CIFRADO)<sup>[[1]](#references)</sup>
  - Microsoft almacenaba en texto sin cifrar todos los refresh tokens para acceder a endpoints sensibles.<sup>[[1]](#references)</sup>

### Keychain de protección de datos: enumerar y luego consultar un elemento

Ejecuta `SecItemCopyMatching` desde una **app firmada en el contexto de inicio de sesión del usuario objetivo** con `kSecUseDataProtectionKeychain: true`; no des por sentado que `security dump-keychain` o una consulta SecItem predeterminada buscaron en este almacén. El proceso que realiza la llamada solo ve los grupos de acceso que tiene autorizados.<sup>[[5]](#references)</sup>

Si el código de prueba se ejecuta dentro de otro proceso, el acceso a su Keychain de protección de datos se rige por los entitlements del ejecutable anfitrión. Inspecciona los entitlements firmados reales con `codesign -d --entitlements - /path/to/Target.app` y consulta [macOS code-signing entitlements](../macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements.md) para ver comprobaciones relacionadas.<sup>[[7]](#references)</sup>

Primero solicita **solo atributos** para una clase de elemento. `kSecAttrSynchronizableAny` incluye coincidencias locales y sincronizables con iCloud; si se omite, se excluyen los elementos sincronizables.<sup>[[8]](#references)</sup> `kSecUseAuthenticationUISkip` evita la interfaz de autenticación durante una enumeración amplia, a costa de omitir las coincidencias protegidas.<sup>[[9]](#references)</sup> Si es necesario, repite la operación con `kSecClassInternetPassword`.

```swift
import Security
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecUseDataProtectionKeychain as String: true,
    kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true,
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
]
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)
print(status)
if status == errSecSuccess, let items = result as? [[String: Any]] {
    for item in items { print(item) }
}
```

Para una lectura autorizada de secretos, crea una consulta **nueva** y acotada para el elemento seleccionado (por ejemplo, clase, servicio y cuenta), establece `kSecReturnData: true` y `kSecMatchLimit: kSecMatchLimitOne`, y espera una autenticación específica del elemento o un error. No combines `kSecReturnData` con `kSecMatchLimitAll` para elementos de contraseña.<sup>[[10]](#references)</sup> Un resultado `errSecItemNotFound` también puede deberse a que se esté consultando el almacén equivocado, a un filtro de sincronización o a que falte el entitlement del grupo de acceso, en lugar de indicar que la credencial no existe.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>



## References

- [1] [#OBTS v5.0: «Forzar la cerradura del llavero de macOS» - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - Una nueva versión del stealer de macOS MacSync apunta a entusiastas de las criptomonedas y desarrolladores](https://securelist.com/macsync-new-version/121383/)
- [4] [Copia espejo de la página del manual security(1) de Apple](https://keith.github.io/xcode-man-pages/security.1.html)
- [5] [Apple TN3137 — Sobre las API e implementaciones del llavero de Mac](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [6] [Apple Developer Forums — SecItem: Fundamentos](https://developer.apple.com/forums/thread/724023)
- [7] [Apple Developer Forums — SecItem: Errores comunes y prácticas recomendadas](https://developer.apple.com/forums/thread/724013)
- [8] [Apple Developer — kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [9] [Apple Developer — Acceso a elementos del llavero con Face ID o Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [10] [Apple Developer — SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29)
{{#include ../../banners/hacktricks-training.md}}
