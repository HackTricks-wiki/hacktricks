# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## Base de datos de Authorization

Los Authorization Services del Security framework permiten que los helpers con privilegios y otros componentes evalúen derechos de autorización con nombre. En las versiones actuales de macOS, muchas de esas reglas se almacenan en `/var/db/auth.db` y son evaluadas por `authd`; este archivo y su esquema de SQLite son detalles de implementación y pueden cambiar entre versiones.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Históricamente, los valores predeterminados del sistema se han inicializado desde `/System/Library/Security/authorization.plist`, y los instaladores o servicios con privilegios pueden añadir derechos con nombre. Se recomienda utilizar la interfaz compatible `security authorizationdb read|write|remove` en lugar de editar directamente la base de datos.<sup>[[3]](#references)</sup>

La tabla `rules` observada en la build documentada contiene las siguientes columnas. Considérala un mapa forense, no un esquema público estable:

- **id**: Un identificador único para cada regla, incrementado automáticamente y utilizado como clave primaria.
- **name**: El nombre único de la regla utilizado para identificarla y referenciarla dentro del sistema de autorización.
- **type**: Especifica el tipo de regla, restringido a los valores 1 o 2 para definir su lógica de autorización.
- **class**: Clasifica la regla en una clase específica, garantizando que sea un entero positivo.
- Las clases de reglas comunes incluyen `allow`, `deny`, `user`, `rule` y `evaluate-mechanisms`. Los mecanismos pueden ser integrados o plug-ins de Security Agent ubicados en `/System/Library/CoreServices/SecurityAgentPlugins/` o `/Library/Security/SecurityAgentPlugins/`.<sup>[[2]](#references)</sup>
- **group**: Indica el grupo de usuarios asociado con la regla para la autorización basada en grupos.
- **kofn**: Representa el parámetro "k-of-n", que determina cuántas subreglas deben cumplirse de un número total.
- **timeout**: Define la duración en segundos antes de que expire la autorización concedida por la regla.
- **flags**: Contiene varios flags que modifican el comportamiento y las características de la regla.
- **tries**: Limita el número de intentos de autorización permitidos para mejorar la seguridad.
- **version**: Registra la versión de la regla para el control de versiones y las actualizaciones.
- **created**: Registra la marca de tiempo en la que se creó la regla con fines de auditoría.
- **modified**: Almacena la marca de tiempo de la última modificación realizada en la regla.
- **hash**: Contiene un valor hash de la regla para garantizar su integridad y detectar manipulaciones.
- **identifier**: Proporciona un identificador de cadena único, como un UUID, para referencias externas a la regla.
- **requirement**: Contiene datos serializados que definen los requisitos y mecanismos de autorización específicos de la regla.
- **comment**: Ofrece una descripción o comentario legible para las personas sobre la regla, para facilitar la documentación y la claridad.

### Ejemplo
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
La siguiente regla decodificada ilustra `authenticate-admin-nonshared` en una versión documentada de macOS:<sup>[[1]](#references)</sup>
```json
{
"allow-root": "false",
"authenticate-user": "true",
"class": "user",
"comment": "Authenticate as an administrator.",
"group": "admin",
"session-owner": "false",
"shared": "false",
"timeout": "30",
"tries": "10000",
"version": "1"
}
```
## Authd

`authd` es el servicio XPC que evalúa las solicitudes de Authorization Services. En las compilaciones actuales de macOS, su bundle puede inspeccionarse en `/System/Library/Frameworks/Security.framework/XPCServices/authd.xpc`; la ruta es un detalle de implementación y puede variar entre versiones. Las versiones antiguas escribían en `/var/log/authd.log`; las actuales utilizan principalmente el sistema de unified logging, que puede consultarse con `log show`/`log stream` usando un predicado del proceso `authd`.<sup>[[2]](#references)</sup><sup>[[5]](#references)</sup>

La herramienta `security` expone varias operaciones de Authorization Services. Un ejemplo histórico invoca `AuthorizationExecuteWithPrivileges` con `security execute-with-privileges /bin/ls`. Apple deprecó esa API en macOS 10.7; los privileged helpers modernos deberían utilizar un helper gestionado por launchd y autorización mediante XPC.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>

En las versiones que todavía lo admiten, esto utiliza `/usr/libexec/security_authtrampoline` y muestra un aviso de autorización antes de ejecutar el comando como root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Descripción general del Authorization Right de macOS](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)
- [2] [Guía de programación de Apple Authorization Services (archivo)](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/)
- [3] [Página del manual de macOS de `security(1)`](https://keith.github.io/xcode-man-pages/security.1.html)
- [4] [Apple - Guía de programación de Daemons and Services: Creación de trabajos de launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [5] [Proyecto Security de código abierto de Apple - `authd`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/authd)
{{#include ../../../banners/hacktricks-training.md}}
