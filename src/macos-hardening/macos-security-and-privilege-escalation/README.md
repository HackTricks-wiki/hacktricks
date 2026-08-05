# Seguridad y escalada de privilegios en macOS

{{#include ../../banners/hacktricks-training.md}}

## Conceptos básicos de MacOS

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

### MDM de MacOS

En las empresas, es muy probable que los sistemas **macOS** estén **gestionados con un MDM**. Por lo tanto, desde la perspectiva de un atacante, es interesante saber **cómo funciona**:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS: inspección, depuración y fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Protecciones de seguridad de MacOS


{{#ref}}
macos-security-protections/
{{#endref}}

## Superficie de ataque

### Permisos de archivos

Si un **proceso ejecutándose como root escribe** en un archivo que puede ser controlado por un usuario, este podría aprovecharlo para **escalar privilegios**.\
Esto podría ocurrir en las siguientes situaciones:

- El archivo utilizado ya fue creado por un usuario (pertenece al usuario)
- El archivo utilizado puede ser escrito por el usuario debido a un grupo
- El archivo utilizado está dentro de un directorio propiedad del usuario (el usuario podría crear el archivo)
- El archivo utilizado está dentro de un directorio propiedad de root, pero el usuario tiene acceso de escritura debido a un grupo (el usuario podría crear el archivo)

Poder **crear un archivo** que va a ser **utilizado por root** permite a un usuario **aprovechar su contenido** o incluso crear **symlinks/hardlinks** para apuntarlo a otro lugar.

Para este tipo de vulnerabilidades, no olvides **comprobar los instaladores `.pkg` vulnerables**:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Extensión de archivo y handlers de esquemas URL

Las aplicaciones extrañas registradas mediante extensiones de archivo podrían ser abusadas, y se pueden registrar distintas aplicaciones para abrir protocolos específicos.


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## Escalada de privilegios mediante TCC / SIP de macOS

En macOS, las **aplicaciones y los binarios pueden tener permisos** para acceder a carpetas o configuraciones que los hacen más privilegiados que otros.

Por lo tanto, un atacante que quiera comprometer correctamente una máquina macOS tendrá que **escalar sus privilegios TCC** (o incluso **omitir SIP**, dependiendo de sus necesidades).

Estos privilegios suelen otorgarse en forma de **entitlements** con los que está firmada la aplicación, o la aplicación puede solicitar ciertos accesos y, después de que el **usuario los apruebe**, estos pueden encontrarse en las **bases de datos de TCC**. Otra forma en la que un proceso puede obtener estos privilegios es siendo **hijo de un proceso** con esos **privilegios**, ya que normalmente se **heredan**.

Sigue estos enlaces para encontrar distintas formas de [**escalar privilegios en TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), [**omitir TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) y saber cómo en el pasado [**se ha omitido SIP**](macos-security-protections/macos-sip.md#sip-bypasses).

## Escalada de privilegios tradicional en macOS

Por supuesto, desde la perspectiva de un red team, también deberías estar interesado en escalar a root. Consulta la siguiente publicación para obtener algunas pistas:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## Cumplimiento de normativas en macOS

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Referencias

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
