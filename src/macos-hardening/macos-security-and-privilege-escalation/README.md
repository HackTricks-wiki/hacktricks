# macOS 安全与权限提升

{{#include ../../banners/hacktricks-training.md}}

## macOS 基础

如果你不熟悉 macOS，应先学习 macOS 的基础知识：

- 特殊的 macOS **文件与权限：**


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- 常见 macOS **用户**


{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**


{{#ref}}
macos-applefs.md
{{#endref}}

- k**ernel** 的**架构**


{{#ref}}
mac-os-architecture/
{{#endref}}

- 常见 macOS **网络服务与协议**


{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS：[https://opensource.apple.com/](https://opensource.apple.com/)
- 要下载 `tar.gz`，请将类似 [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) 的 URL 更改为 [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

在企业中，**macOS** 系统很可能会通过 MDM 进行**管理**。因此，从攻击者的角度来看，了解**其工作方式**很有意义：


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - 检查、Debugging 与 Fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOS 安全防护


{{#ref}}
macos-security-protections/
{{#endref}}

## 攻击面

### 文件权限

如果一个**以 root 身份运行的进程写入**一个可由用户控制的文件，该用户就可以利用这一点来**提升权限**。\
这可能发生在以下情况中：

- 使用的文件已经由用户创建（归用户所有）
- 由于用户属于某个组，使用的文件可由用户写入
- 使用的文件位于归用户所有的目录中（用户可以创建该文件）
- 使用的文件位于归 root 所有的目录中，但由于用户属于某个组，用户拥有对该目录的写入权限（用户可以创建该文件）

如果能够**创建一个文件**，并且该文件将被 **root 使用**，用户就可以**利用其内容**，甚至创建**符号链接/硬链接**，将其指向其他位置。

对于这类漏洞，不要忘记**检查存在漏洞的 `.pkg` 安装程序**：


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### 文件扩展名与 URL scheme 应用处理程序

通过文件扩展名注册的异常应用可能会被滥用，并且可以注册不同的应用来打开特定协议


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP 权限提升

在 macOS 中，**应用程序和二进制文件可以拥有权限**，从而访问文件夹或设置，使其权限高于其他对象。

因此，想要成功入侵 macOS 机器的攻击者需要**提升其 TCC 权限**（或者根据需要**绕过 SIP**）。

这些权限通常以应用程序签名所包含的**entitlements**形式授予；应用程序也可能请求某些访问权限，并在**用户批准这些权限**后，将其记录在**TCC 数据库**中。进程获取这些权限的另一种方式，是成为拥有这些**权限**的进程的**子进程**，因为这些权限通常会被**继承**。

请通过以下链接了解在 TCC 中不同的[**权限提升方式**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses)、[**绕过 TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) 的方法，以及过去[**绕过 SIP 的方式**](macos-security-protections/macos-sip.md#sip-bypasses)。

## macOS 传统权限提升

当然，从 red teams 的角度来看，你也应该关注如何提升到 root。以下文章提供了一些提示：


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS 合规性

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## 参考资料

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
