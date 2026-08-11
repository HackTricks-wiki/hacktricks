# Integrity Levels

{{#include ../../banners/hacktricks-training.md}}

## Integrity Levels

在 Windows Vista 及更高版本中，可保护对象可以携带**完整性级别**标签。大多数对象被视为中完整性，而专为低完整性应用程序设计的特定位置可以被标记为低完整性。标准用户启动的进程通常以中完整性运行，提升权限的应用程序以高完整性运行，许多服务则以系统完整性运行。<sup>[[1]](#references)</sup>

一个关键规则是，完整性级别低于对象级别的进程无法修改该对象。Windows 会在评估对象的自主访问控制列表（DACL）之前，先执行此强制完整性控制（MIC）检查。常见级别包括：<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**：最低级别，由 `SECURITY_MANDATORY_UNTRUSTED_RID`（`S-1-16-0`）表示。不要将此完整性标签与**Anonymous Logon** 身份（`S-1-5-7`）混淆；身份验证身份与 MIC 标签属于不同的 SID 命名空间。一个现实中的例子是，Chromium 的 Windows sandbox 最初会为 sandboxed targets 分配 Low 完整性，然后在启动后将 renderer targets 降低为 Untrusted 完整性。<sup>[[5]](#references)[[6]](#references)</sup>
- **Low**：主要用于互联网交互，尤其是在 Internet Explorer 的 Protected Mode 中，会影响相关文件和进程，以及 **Temporary Internet Folder** 等特定文件夹。Low 完整性进程面临严格限制，包括无法写入注册表，以及只能有限地写入用户配置文件。
- **Medium**：大多数活动的默认级别，分配给标准用户以及未指定特定完整性级别的对象。即使是 Administrators 组成员，默认也以此级别运行。
- **High**：为管理员保留，允许其修改完整性级别较低的对象，包括处于 High 级别的对象本身。
- **System**：Windows 内核和核心服务的最高运行级别，即使管理员也无法达到，用于保护关键系统功能。

Windows 还定义了一个高于 System 的受保护进程完整性值。不过，**TrustedInstaller** 是一种 Windows 服务身份，而不是单独的 MIC 级别；它能够修改受保护的操作系统资源，是因为该身份被授予了相应权限。

不要假设系统驱动器根目录之类的位置始终具有固定的 High 完整性标签。应使用 `icacls` 检查有效 DACL 以及任何显式的强制标签；未标记的对象在 MIC 中会被视为 Medium，但其 DACL 和所有权仍可能独立限制访问。<sup>[[1]](#references)[[4]](#references)</sup>

你可以使用 **Sysinternals** 中的 **Process Explorer** 获取进程的完整性级别：打开进程属性并查看 **Security** 选项卡：<sup>[[3]](#references)</sup>

![Integrity Levels - Integrity Levels: 你可以使用 Sysinternals 中的 Process Explorer 获取进程的完整性级别，方法是访问进程属性并查看 "...](<../../images/image (824).png>)

你也可以使用 `whoami /groups` 获取**当前完整性级别**：

![Integrity Levels - Integrity Levels: 你也可以使用 whoami /groups 获取当前完整性级别](<../../images/image (325).png>)

### 文件系统中的完整性级别

文件系统中的对象可能具有**最低完整性级别要求**。低于该级别的进程会受到对象强制策略的限制，即使其 DACL 原本会授予访问权限也是如此。例如，在标准用户控制台中创建一个普通文件，然后检查其权限：<sup>[[1]](#references)[[4]](#references)</sup>
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
现在，为该文件分配最低 **High** 完整性级别。此操作**必须在以管理员身份运行的控制台中完成**，因为常规控制台以 Medium 完整性级别运行，**不允许**为对象分配 High 完整性级别：
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
用户 `DESKTOP-IDJHTKP\user` 对该文件拥有 **FULL privileges**，因为该用户创建了该文件。但是，强制标签会阻止该用户修改文件，除非进程以高完整性运行。由于显示的强制策略为 `(NW)`，即 no-write-up，用户仍然可以读取该文件：
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **因此，当文件具有最低完整性级别时，要修改该文件，必须至少以该完整性级别运行。**

### 二进制文件中的完整性级别

以下示例使用 `cmd.exe` 的副本 `C:\Windows\System32\cmd-low.exe`，并**从管理员控制台为其分配 Low 完整性级别**：
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
现在，当我运行 `cmd-low.exe` 时，它会**以低完整性级别运行**，而不是中完整性级别：

![文件系统中的完整性级别 - 二进制文件中的完整性级别：现在，当我运行 cmd-low.exe 时，它会以低完整性级别运行，而不是中完整性级别](<../../images/image (313).png>)

为二进制文件分配高完整性标签（`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`）并不会使其自动以高完整性级别运行。如果从中完整性级别的进程中启动，它会以中完整性级别运行，因为新进程会采用可执行文件与调用方完整性级别中较低的那个。<sup>[[1]](#references)</sup>

### 进程中的完整性级别

并非所有文件和文件夹都有明确的最低完整性标签，**但每个进程都会以某个完整性级别运行**。与文件系统对象一样，**想要获得对另一个进程的写入权限的进程，必须至少具有相同的完整性级别**。因此，低完整性级别的进程无法以完全访问权限打开中完整性级别的进程。<sup>[[1]](#references)</sup>

由于这些限制，最安全的方法是**让每个进程以仍能完成其预期工作的最低完整性级别运行**。

## References

- [1] [Microsoft Learn – 强制完整性控制](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – MANDATORY_LEVEL 枚举](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Chromium source – 默认 Windows sandbox 完整性策略](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
- [6] [Microsoft Learn – 众所周知的 SID](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
{{#include ../../banners/hacktricks-training.md}}
