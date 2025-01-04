# Seguridad y Escalación de Privilegios en macOS

{{#include ../../banners/hacktricks-training.md}}

## MacOS Básico

Si no estás familiarizado con macOS, deberías comenzar a aprender los conceptos básicos de macOS:

- Archivos y **permisos especiales de macOS:**

{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- **Usuarios comunes de macOS**

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

- Servicios y **protocolos de red comunes de macOS**

{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Para descargar un `tar.gz`, cambia una URL como [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) a [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MDM de MacOS

En las empresas, los sistemas **macOS** probablemente serán **gestionados con un MDM**. Por lo tanto, desde la perspectiva de un atacante, es interesante saber **cómo funciona eso**:

{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Inspección, Depuración y Fuzzing

{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Protecciones de Seguridad de MacOS

{{#ref}}
macos-security-protections/
{{#endref}}

## Superficie de Ataque

### Permisos de Archivos

Si un **proceso que se ejecuta como root escribe** un archivo que puede ser controlado por un usuario, el usuario podría abusar de esto para **escalar privilegios**.\
Esto podría ocurrir en las siguientes situaciones:

- El archivo utilizado ya fue creado por un usuario (pertenece al usuario)
- El archivo utilizado es escribible por el usuario debido a un grupo
- El archivo utilizado está dentro de un directorio propiedad del usuario (el usuario podría crear el archivo)
- El archivo utilizado está dentro de un directorio propiedad de root, pero el usuario tiene acceso de escritura sobre él debido a un grupo (el usuario podría crear el archivo)

Poder **crear un archivo** que va a ser **utilizado por root**, permite a un usuario **aprovechar su contenido** o incluso crear **symlinks/hardlinks** para apuntar a otro lugar.

Para este tipo de vulnerabilidades, no olvides **verificar instaladores `.pkg` vulnerables**:

{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Controladores de Aplicaciones de Extensión de Archivo y Esquema de URL

Aplicaciones extrañas registradas por extensiones de archivo podrían ser abusadas y diferentes aplicaciones pueden registrarse para abrir protocolos específicos.

{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## Escalación de Privilegios TCC / SIP en macOS

En macOS, **las aplicaciones y binarios pueden tener permisos** para acceder a carpetas o configuraciones que los hacen más privilegiados que otros.

Por lo tanto, un atacante que quiera comprometer con éxito una máquina macOS necesitará **escalar sus privilegios TCC** (o incluso **eludir SIP**, dependiendo de sus necesidades).

Estos privilegios generalmente se otorgan en forma de **derechos** con los que la aplicación está firmada, o la aplicación podría solicitar algunos accesos y después de que el **usuario los apruebe**, pueden encontrarse en las **bases de datos TCC**. Otra forma en que un proceso puede obtener estos privilegios es siendo un **hijo de un proceso** con esos **privilegios**, ya que generalmente son **heredados**.

Sigue estos enlaces para encontrar diferentes formas de [**escalar privilegios en TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), para [**eludir TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) y cómo en el pasado [**se ha eludido SIP**](macos-security-protections/macos-sip.md#sip-bypasses).

## Escalación de Privilegios Tradicional en macOS

Por supuesto, desde la perspectiva de un equipo rojo, también deberías estar interesado en escalar a root. Consulta la siguiente publicación para algunos consejos:

{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## Cumplimiento de macOS

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Referencias

- [**Respuesta a Incidentes de OS X: Scripting y Análisis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
- [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
