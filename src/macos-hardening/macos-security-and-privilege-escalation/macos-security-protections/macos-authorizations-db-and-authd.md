# Base de datos de autorizaciones de macOS y Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Base de datos de autorizaciones**

La base de datos ubicada en `/var/db/auth.db` se utiliza para almacenar permisos para realizar operaciones sensibles. Estas operaciones se realizan completamente en **user space** y normalmente son utilizadas por **XPC services**, que necesitan comprobar **si el cliente que realiza la llamada está autorizado** para realizar una determinada acción consultando esta base de datos.

Inicialmente, esta base de datos se crea a partir del contenido de `/System/Library/Security/authorization.plist`. Después, algunos servicios pueden añadir o modificar esta base de datos para agregarle otros permisos.

Las reglas se almacenan en la tabla `rules` dentro de la base de datos, que contiene las siguientes columnas:

- **id**: Un identificador único para cada regla, incrementado automáticamente y utilizado como clave primaria.
- **name**: El nombre único de la regla, utilizado para identificarla y referenciarla dentro del sistema de autorizaciones.
- **type**: Especifica el tipo de regla, restringido a los valores 1 o 2 para definir su lógica de autorización.
- **class**: Clasifica la regla dentro de una clase específica, garantizando que sea un entero positivo.
- "allow" para permitir, "deny" para denegar, "user" si la propiedad group indica un grupo cuya pertenencia permite el acceso, "rule" indica en un array una regla que debe cumplirse, "evaluate-mechanisms" seguido de un array `mechanisms` cuyos elementos pueden ser builtins o el nombre de un bundle dentro de `/System/Library/CoreServices/SecurityAgentPlugins/` o `/Library/Security//SecurityAgentPlugins`
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
- **comment**: Ofrece una descripción o comentario legible para las personas sobre la regla, con fines de documentación y claridad.

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
Además, en [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) es posible ver el significado de `authenticate-admin-nonshared`:<sup>[[1]](#references)</sup>
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

Es un daemon que recibirá solicitudes para autorizar a los clientes a realizar acciones sensibles. Funciona como un servicio XPC definido dentro de la carpeta `XPCServices/` y escribe sus logs en `/var/log/authd.log`.

Además, mediante la herramienta security es posible probar muchas APIs de `Security.framework`. Por ejemplo, ejecutar `AuthorizationExecuteWithPrivileges`: `security execute-with-privileges /bin/ls`

Esto hará fork y exec de `/usr/libexec/security_authtrampoline /bin/ls` como root, lo que solicitará permisos mediante un prompt para ejecutar ls como root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## Referencias

- [1] [authenticate-admin-nonshared - Descripción general del Authorization Right de macOS](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)

{{#include ../../../banners/hacktricks-training.md}}
