# macOS 安全与权限提升

{{#include ../../banners/hacktricks-training.md}}

## 基础 MacOS

如果您对 macOS 不熟悉，您应该开始学习 macOS 的基础知识：

- 特殊的 macOS **文件与权限：**

{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- 常见的 macOS **用户**

{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**

{{#ref}}
macos-applefs.md
{{#endref}}

- k**ernel** 的 **架构**

{{#ref}}
mac-os-architecture/
{{#endref}}

- 常见的 macOS n**etwork services & protocols**

{{#ref}}
macos-protocols.md
{{#endref}}

- **开源** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- 要下载 `tar.gz`，将 URL 更改为 [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

在公司中，**macOS** 系统很可能会被 **MDM 管理**。因此，从攻击者的角度来看，了解 **其工作原理** 是很有趣的：

{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - 检查、调试和模糊测试

{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOS 安全保护

{{#ref}}
macos-security-protections/
{{#endref}}

## 攻击面

### 文件权限

如果 **以 root 身份运行的进程写入** 一个可以被用户控制的文件，用户可能会利用这一点来 **提升权限**。\
这可能发生在以下情况下：

- 使用的文件已经由用户创建（属于用户）
- 使用的文件因组而可被用户写入
- 使用的文件位于用户拥有的目录中（用户可以创建该文件）
- 使用的文件位于 root 拥有的目录中，但用户因组而对其具有写入权限（用户可以创建该文件）

能够 **创建一个将被 root 使用的文件**，允许用户 **利用其内容**，甚至创建 **符号链接/硬链接** 指向另一个位置。

对于这种漏洞，不要忘记 **检查易受攻击的 `.pkg` 安装程序**：

{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### 文件扩展名与 URL 方案应用处理程序

通过文件扩展名注册的奇怪应用程序可能会被滥用，不同的应用程序可以注册以打开特定协议

{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP 权限提升

在 macOS 中，**应用程序和二进制文件可以拥有** 访问文件夹或设置的权限，使其比其他应用程序更具特权。

因此，想要成功攻陷 macOS 机器的攻击者需要 **提升其 TCC 权限**（甚至 **绕过 SIP**，具体取决于其需求）。

这些权限通常以 **应用程序签名的授权** 形式授予，或者应用程序可能请求某些访问权限，在 **用户批准后**，它们可以在 **TCC 数据库** 中找到。进程获得这些权限的另一种方式是成为具有这些 **权限** 的进程的 **子进程**，因为它们通常是 **继承的**。

请访问这些链接以找到不同的方式 [**提升 TCC 中的权限**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses)，以 [**绕过 TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) 以及过去 [**如何绕过 SIP**](macos-security-protections/macos-sip.md#sip-bypasses)。

## macOS 传统权限提升

当然，从红队的角度来看，您也应该对提升到 root 感兴趣。查看以下帖子以获取一些提示：

{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS 合规性

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## 参考文献

- [**OS X 事件响应：脚本和分析**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
- [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
