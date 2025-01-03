# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

每个**登录**到系统的**用户持有一个包含安全信息的访问令牌**，用于该登录会话。当用户登录时，系统会创建一个访问令牌。**每个代表用户执行的进程**都有一个访问令牌的副本。该令牌标识用户、用户的组和用户的权限。令牌还包含一个登录SID（安全标识符），用于标识当前的登录会话。

您可以通过执行 `whoami /all` 查看此信息。
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
或使用来自 Sysinternals 的 _Process Explorer_（选择进程并访问“安全”选项卡）：

![](<../../images/image (772).png>)

### 本地管理员

当本地管理员登录时，**会创建两个访问令牌**：一个具有管理员权限，另一个具有普通权限。**默认情况下**，当该用户执行进程时，将使用具有**常规**（非管理员）**权限的令牌**。当该用户尝试**以管理员身份执行**任何操作（例如“以管理员身份运行”）时，**UAC** 将被用来请求权限。\
如果您想要[**了解更多关于 UAC 的信息，请阅读此页面**](../authentication-credentials-uac-and-efs/#uac)**。**

### 凭据用户 impersonation

如果您拥有**任何其他用户的有效凭据**，您可以**使用这些凭据创建**一个**新的登录会话**：
```
runas /user:domain\username cmd.exe
```
**访问令牌**还包含**LSASS**中的登录会话的**引用**，这在进程需要访问网络的某些对象时非常有用。\
您可以使用以下方法启动一个**使用不同凭据访问网络服务**的进程：
```
runas /user:domain\username /netonly cmd.exe
```
如果您拥有用于访问网络中对象的有效凭据，但这些凭据在当前主机中无效，因为它们仅将在网络中使用（在当前主机中将使用您当前用户的权限），这将非常有用。

### 令牌类型

可用的令牌有两种类型：

- **Primary Token**：它作为进程安全凭据的表示。创建和将主令牌与进程关联的操作需要提升的权限，强调了权限分离的原则。通常，身份验证服务负责令牌的创建，而登录服务处理其与用户操作系统外壳的关联。值得注意的是，进程在创建时会继承其父进程的主令牌。
- **Impersonation Token**：使服务器应用程序能够暂时采用客户端的身份以访问安全对象。该机制分为四个操作级别：
  - **Anonymous**：授予服务器与未识别用户相似的访问权限。
  - **Identification**：允许服务器验证客户端的身份，而不利用其进行对象访问。
  - **Impersonation**：使服务器能够在客户端身份下操作。
  - **Delegation**：类似于Impersonation，但包括将这种身份假设扩展到服务器交互的远程系统的能力，以确保凭据的保留。

#### 模拟令牌

使用metasploit的 _**incognito**_ 模块，如果您拥有足够的权限，您可以轻松地 **列出** 和 **模拟** 其他 **令牌**。这可能有助于执行 **作为其他用户的操作**。您还可以使用此技术 **提升权限**。

### 令牌权限

了解哪些 **令牌权限可以被滥用以提升权限：**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

查看 [**所有可能的令牌权限及其一些定义在此外部页面**](https://github.com/gtworek/Priv2Admin)。

## 参考

在这些教程中了解更多关于令牌的信息：[https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) 和 [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

{{#include ../../banners/hacktricks-training.md}}
