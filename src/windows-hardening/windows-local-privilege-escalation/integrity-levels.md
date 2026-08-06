# Integrity Levels

{{#include ../../banners/hacktricks-training.md}}

## Integrity Levels

在 Windows Vista 及更高版本中，所有受保护的项目都带有一个 **integrity level** 标签。此设置主要为文件和注册表项分配“medium” integrity level，但某些文件夹和文件除外，Internet Explorer 7 可以在 low integrity level 下写入这些文件夹和文件。默认情况下，标准用户启动的进程具有 medium integrity level，而服务通常以 system integrity level 运行。high-integrity 标签用于保护根目录。

一个关键规则是：integrity level 低于对象级别的进程无法修改该对象。integrity levels 包括：

- **Untrusted**：用于匿名登录的进程。例如：Chrome
- **Low**：主要用于互联网交互，尤其是 Internet Explorer 的 Protected Mode，会影响相关文件和进程，以及 **Temporary Internet Folder** 等特定文件夹。Low integrity 进程会受到严格限制，包括无法写入注册表，以及对用户配置文件的写入权限受限。
- **Medium**：大多数活动的默认级别，分配给标准用户以及未指定特定 integrity level 的对象。即使是 Administrators 组的成员，默认情况下也以此级别运行。
- **High**：为管理员保留，使其能够修改 integrity level 较低的对象，包括自身处于 high level 的对象。
- **System**：Windows 内核和核心服务的最高运行级别，即使管理员也无法达到，从而确保关键系统功能受到保护。
- **Installer**：高于其他所有级别的特殊级别，使处于此级别的对象能够卸载任何其他对象。

你可以使用 **Sysinternals** 中的 **Process Explorer** 获取进程的 integrity level：打开进程的 **properties**，然后查看 "**Security**" 选项卡：

![Integrity Levels - Integrity Levels：你可以使用 Sysinternals 中的 Process Explorer 获取进程的 integrity level，打开进程的 properties，然后查看 "...](<../../images/image (824).png>)

你也可以使用 `whoami /groups` 获取你的 **current integrity level**

![Integrity Levels - Integrity Levels：你也可以使用 whoami /groups 获取你的 current integrity level](<../../images/image (325).png>)

### Integrity Levels in File-system

文件系统中的对象可能需要满足某个 **minimum integrity level requirement**；如果进程不具备所需的 integrity level，就无法与该对象进行交互。\
例如，让我们**在普通用户控制台中创建一个普通文件并检查其权限**：
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
现在，让我们为该文件分配最低 **High** integrity level。此操作**必须从以** **administrator** 身份运行的**常规控制台**中完成，因为**普通控制台**将以 Medium Integrity level 运行，并且**无法**为对象分配 High Integrity level：
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
这就变得有意思了。可以看到，用户 `DESKTOP-IDJHTKP\user` 对该文件拥有 **完全权限**（实际上，正是该用户创建了此文件），然而，由于实施了最低完整性级别，除非该用户在 High Integrity Level 中运行，否则将无法再修改该文件（注意，他仍然能够读取该文件）：
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **因此，当文件具有最低完整性级别时，要修改该文件，你至少需要在该完整性级别下运行。**

### 二进制文件中的完整性级别

我复制了一份 `cmd.exe` 到 `C:\Windows\System32\cmd-low.exe`，并在 **administrator console 中将其设置为低完整性级别：**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
现在，当我运行 `cmd-low.exe` 时，它将**在低完整性级别下运行**，而不是中等完整性级别：

![文件系统中的完整性级别 - 二进制文件中的完整性级别：现在，当我运行 cmd-low.exe 时，它将以低完整性级别运行，而不是中等完整性级别](<../../images/image (313).png>)

对于好奇的读者，如果你为一个二进制文件分配高完整性级别（`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`），它不会自动以高完整性级别运行（如果你从中等完整性级别下调用它——默认情况——它将以中等完整性级别运行）。

### 进程中的完整性级别

并非所有文件和文件夹都有最低完整性级别，**但所有进程都在某个完整性级别下运行**。与文件系统中的情况类似，**如果一个进程想要写入另一个进程，它必须至少具有相同的完整性级别**。这意味着，低完整性级别的进程无法以完全访问权限打开中等完整性级别进程的句柄。

由于本节和上一节中提到的限制，从安全角度来看，始终**建议让进程以可能的最低完整性级别运行**。

{{#include ../../banners/hacktricks-training.md}}
