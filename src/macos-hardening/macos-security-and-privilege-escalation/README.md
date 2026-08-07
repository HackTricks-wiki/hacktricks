# Seguridad y escalada de privilegios en macOS

{{#include ../../banners/hacktricks-training.md}}

## Conceptos básicos de macOS

Si no estás familiarizado con macOS, deberías empezar aprendiendo los conceptos básicos de macOS:

- **Archivos y permisos** especiales de macOS:


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- **Usuarios** comunes de macOS


{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**


{{#ref}}
macos-applefs.md
{{#endref}}

- La **arquitectura** del k**ernel**


{{#ref}}
mac-os-architecture/
{{#endref}}

- **Servicios y protocolos de red** comunes de macOS


{{#ref}}
macos-protocols.md
{{#endref}}

- macOS **Opensource**: [https://opensource.apple.com/](https://opensource.apple.com/)
- Para descargar un `tar.gz`, cambia una URL como [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) por [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MDM de macOS

En las empresas, es muy probable que los sistemas **macOS** estén **gestionados con un MDM**. Por lo tanto, desde la perspectiva de un atacante, es interesante saber **cómo funciona**:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### macOS: inspección, debugging y fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Protecciones de seguridad de macOS


{{#ref}}
macos-security-protections/
{{#endref}}

## Superficie de ataque

### Permisos de archivos

Si un **process ejecutándose como root escribe** un archivo que puede ser controlado por un usuario, este podría aprovecharlo para **escalar privilegios**.\
Esto podría ocurrir en las siguientes situaciones:

- El archivo utilizado ya fue creado por un usuario (pertenece al usuario)
- El archivo utilizado puede ser escrito por el usuario debido a un grupo
- El archivo utilizado está dentro de un directorio perteneciente al usuario (el usuario podría crear el archivo)
- El archivo utilizado está dentro de un directorio perteneciente a root, pero el usuario tiene acceso de escritura debido a un grupo (el usuario podría crear el archivo)

Poder **crear un archivo** que va a ser **utilizado por root** permite a un usuario **aprovechar su contenido** o incluso crear **symlinks/hardlinks** para apuntarlo a otro lugar.

Para este tipo de vulnerabilidades, no olvides **comprobar los instaladores `.pkg` vulnerables**:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Extensión de archivo y handlers de esquemas URL

Las aplicaciones extrañas registradas mediante extensiones de archivo podrían ser abusadas, y se pueden registrar diferentes aplicaciones para abrir protocolos específicos


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## Escalada de privilegios mediante TCC / SIP de macOS

En macOS, las **aplicaciones y los binarios pueden tener permisos** para acceder a carpetas o configuraciones que los hacen más privilegiados que otros.

Por lo tanto, un atacante que quiera comprometer con éxito una máquina macOS deberá **escalar sus privilegios de TCC** (o incluso **bypassear SIP**, dependiendo de sus necesidades).

Estos privilegios suelen otorgarse en forma de **entitlements** con los que está firmada la aplicación, o la aplicación puede solicitar determinados accesos y, después de que el **usuario los apruebe**, estos pueden encontrarse en las **bases de datos de TCC**. Otra forma en la que un process puede obtener estos privilegios es siendo **child de un process** con esos **privilegios**, ya que normalmente se **heredan**.<sup>[[5]](#references)</sup>

Sigue estos enlaces para encontrar diferentes formas de [**escalar privilegios en TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), [**bypassear TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) y consultar cómo en el pasado se ha [**bypasseado SIP**](macos-security-protections/macos-sip.md#sip-bypasses).

## Escalada de privilegios tradicional en macOS

Por supuesto, desde la perspectiva de los red teams también deberías estar interesado en escalar a root. Consulta el siguiente post para obtener algunas pistas:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## Cumplimiento normativo de macOS

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Referencias

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
