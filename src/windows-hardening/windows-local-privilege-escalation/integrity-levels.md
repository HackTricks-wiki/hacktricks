# Integrity Levels

{{#include ../../banners/hacktricks-training.md}}

## Integrity Levels

在 Windows Vista 及更高版本中，所有受保护的项目都有一个 **完整性级别** 标签。此设置通常将“中等”完整性级别分配给文件和注册表项，除了某些 Internet Explorer 7 可以以低完整性级别写入的文件夹和文件。默认情况下，标准用户启动的进程具有中等完整性级别，而服务通常在系统完整性级别下运行。高完整性标签保护根目录。

一个关键规则是，低于对象级别的进程无法修改对象。完整性级别如下：

- **不可信**：此级别适用于匿名登录的进程。 %%%示例：Chrome%%%
- **低**：主要用于互联网交互，特别是在 Internet Explorer 的受保护模式中，影响相关文件和进程，以及某些文件夹，如 **临时 Internet 文件夹**。低完整性进程面临重大限制，包括无法写入注册表和有限的用户配置文件写入访问权限。
- **中**：大多数活动的默认级别，分配给标准用户和没有特定完整性级别的对象。即使是管理员组的成员默认也在此级别操作。
- **高**：保留给管理员，允许他们修改低完整性级别的对象，包括高完整性级别的对象。
- **系统**：Windows 内核和核心服务的最高操作级别，甚至管理员也无法触及，确保保护重要的系统功能。
- **安装程序**：一个独特的级别，超越所有其他级别，使该级别的对象能够卸载任何其他对象。

您可以使用 **Sysinternals** 的 **Process Explorer** 获取进程的完整性级别，访问进程的 **属性** 并查看 "**安全性**" 选项卡：

![](<../../images/image (824).png>)

您还可以使用 `whoami /groups` 获取您的 **当前完整性级别**

![](<../../images/image (325).png>)

### Integrity Levels in File-system

文件系统中的对象可能需要 **最低完整性级别要求**，如果进程没有此完整性级别，则无法与其交互。\
例如，让我们 **从普通用户控制台创建一个常规文件并检查权限**：
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
现在，让我们为文件分配一个最低的完整性级别为 **高**。这 **必须在以** **管理员** 身份运行的 **控制台** 中完成，因为 **常规控制台** 将以中等完整性级别运行，并且 **不允许** 将高完整性级别分配给对象：
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
这就是事情变得有趣的地方。你可以看到用户 `DESKTOP-IDJHTKP\user` 对文件拥有 **完全权限**（实际上这是创建该文件的用户），然而，由于实施的最低完整性级别，他将无法再修改该文件，除非他在高完整性级别下运行（请注意，他仍然可以读取该文件）：
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!NOTE]
> **因此，当一个文件具有最低完整性级别时，要修改它，您需要至少以该完整性级别运行。**

### 二进制中的完整性级别

我在 `C:\Windows\System32\cmd-low.exe` 中复制了 `cmd.exe` 并从管理员控制台将其设置为 **低完整性级别：**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
现在，当我运行 `cmd-low.exe` 时，它将**在低完整性级别下运行**，而不是中等级别：

![](<../../images/image (313).png>)

对于好奇的人，如果你给一个二进制文件分配高完整性级别（`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`），它不会自动以高完整性级别运行（如果你从中等完整性级别调用它 -- 默认情况下 -- 它将以中等完整性级别运行）。

### 进程中的完整性级别

并非所有文件和文件夹都有最低完整性级别，**但所有进程都在完整性级别下运行**。与文件系统发生的情况类似，**如果一个进程想要在另一个进程内写入，它必须至少具有相同的完整性级别**。这意味着低完整性级别的进程无法以完全访问权限打开中等完整性级别进程的句柄。

由于本节和前一节中提到的限制，从安全角度来看，始终**建议以尽可能低的完整性级别运行进程**。

{{#include ../../banners/hacktricks-training.md}}
