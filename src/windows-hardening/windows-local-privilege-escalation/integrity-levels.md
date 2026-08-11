# 完整性级别

{{#include ../../banners/hacktricks-training.md}}

## 完整性级别

在 Windows Vista 及更高版本中，可保护对象可以携带**完整性级别**标签。大多数对象被视为中完整性，而专为低完整性应用程序设计的特定位置可以标记为低完整性。标准用户启动的进程通常以中完整性运行，提升权限的应用程序以高完整性运行，许多服务则以系统完整性运行。<sup>[[1]](#references)</sup>

一项关键规则是，完整性级别低于对象级别的进程无法修改该对象。Windows 会先应用强制完整性控制（MIC）检查，然后再评估对象的自主访问控制列表（DACL）。常见的级别包括：<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**：最低级别，由 `SECURITY_MANDATORY_UNTRUSTED_RID` 表示。现实中的一个例子是，Chromium 的 Windows sandbox 最初会为 sandboxed targets 分配 Low integrity，启动后再将 renderer targets 降低为 Untrusted integrity。<sup>[[5]](#references)</sup>
- **Low**：主要用于互联网交互，尤其是在 Internet Explorer 的 Protected Mode 中，会影响相关文件和进程，以及 **Temporary Internet Folder** 等特定文件夹。Low integrity 进程面临严格限制，包括无法写入注册表，以及对用户配置文件的写入权限受限。
- **Medium**：大多数活动的默认级别，分配给标准用户以及未设置特定完整性级别的对象。即使是 Administrators 组的成员，默认情况下也以此级别运行。
- **High**：为管理员保留，允许他们修改完整性级别较低的对象，包括自身处于高完整性级别的对象。
- **System**：Windows 内核和核心服务的最高运行级别，即使管理员也无法达到，从而确保关键系统功能受到保护。

Windows 还定义了高于 System 的受保护进程完整性值。不过，**TrustedInstaller** 是 Windows 服务身份，而不是独立的 MIC 级别；它修改受保护操作系统资源的能力来自授予该身份的权限。

你可以使用 **Sysinternals** 中的 **Process Explorer**，打开进程属性并查看 **Security** 选项卡，以获取进程的完整性级别：<sup>[[3]](#references)</sup>

![完整性级别 - 完整性级别：你可以使用 Sysinternals 中的 Process Explorer，通过访问进程属性并查看 "...](<../../images/image (824).png>)

你也可以使用 `whoami /groups` 获取**当前完整性级别**：

![完整性级别 - 完整性级别：你也可以使用 whoami /groups 获取当前完整性级别](<../../images/image (325).png>)

### 文件系统中的完整性级别

文件系统中的对象可能具有**最低完整性级别要求**。低于该级别的进程会受到对象强制策略的限制，即使对象的 DACL 原本会授予访问权限也是如此。例如，在标准用户控制台中创建一个普通文件，然后检查其权限：<sup>[[1]](#references)[[4]](#references)</sup>
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
现在，将该文件的最低完整性级别设为 **High**。这**必须通过以** **administrator** 身份运行的**控制台完成，因为普通控制台以 Medium 完整性级别运行，**不允许**为对象分配 High 完整性级别：
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
用户 `DESKTOP-IDJHTKP\user` 对该文件拥有 **FULL privileges**，因为该用户创建了该文件。但是，强制标签会阻止用户修改该文件，除非进程以 High integrity 运行。由于显示的强制策略为 `(NW)`，即 no-write-up，用户仍然可以读取该文件：
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **因此，当文件具有最低完整性级别时，要修改该文件，必须至少在该完整性级别下运行。**

### 二进制文件中的完整性级别

以下示例使用位于 `C:\Windows\System32\cmd-low.exe` 的 `cmd.exe` 副本，并**从管理员控制台为其分配 Low 完整性级别**：
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
现在，当我运行 `cmd-low.exe` 时，它将**以 Low integrity level 运行**，而不是 Medium integrity level：

![文件系统中的完整性级别 - 二进制文件中的完整性级别：现在，当我运行 cmd-low.exe 时，它将以 Low integrity level 运行，而不是 Medium integrity level](<../../images/image (313).png>)

为二进制文件分配 High integrity 标签（`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`）不会使其自动以 High integrity 运行。如果从 Medium-integrity process 中调用它，它将以 Medium integrity 运行，因为新进程会采用可执行文件和调用方 integrity level 中较低的那个。<sup>[[1]](#references)</sup>

### 进程中的完整性级别

并非所有文件和文件夹都有明确的最低 integrity 标签，**但每个进程都会以某个 integrity level 运行**。与文件系统对象一样，**想要获得对另一个进程的写入权限的进程，必须至少具有相同的 integrity level**。因此，Low-integrity process 无法以完全访问权限打开 Medium-integrity process。<sup>[[1]](#references)</sup>

由于存在这些限制，最安全的方法是**让每个进程都以能够完成其预期工作的最低 integrity level 运行**。

## References

- [1] [Microsoft Learn – 强制完整性控制](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – MANDATORY_LEVEL 枚举](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Chromium source – 默认 Windows sandbox integrity policy](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
{{#include ../../banners/hacktricks-training.md}}
