# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## 访问令牌

系统中每个**已登录用户**都持有一个包含该登录会话**安全信息**的访问令牌。系统会在用户登录时创建一个访问令牌。**代表用户执行的每个进程**都会拥有该访问令牌的副本。该令牌标识用户、用户组以及用户的权限。令牌还包含一个 logon SID（Security Identifier），用于标识当前登录会话。

你可以通过执行 `whoami /all` 查看这些信息
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
或者使用 _Process Explorer_ 来自 Sysinternals（选择进程并访问“Security”选项卡）：

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### 本地管理员

当本地管理员登录时，会创建**两个 access tokens**：一个具有管理员权限，另一个具有普通权限。**默认情况下**，当该用户执行一个进程时，会使用具有**常规**（非管理员）**权限**的那个。当该用户尝试**以管理员身份执行**任何操作（例如“Run as Administrator”）时，将使用 **UAC** 来请求权限。\
如果你想[**了解更多关于 UAC，请阅读此页面**](../authentication-credentials-uac-and-efs/index.html#uac)**。**

实际上，这意味着一个**未提升权限的管理员 shell 通常使用过滤后的 token**。这就是为什么 `whoami /groups` 通常会将 **`BUILTIN\Administrators` 显示为 `Deny only`**，直到该进程被提升。在内部，Windows 会保留一个**关联的提升 token**（`TokenLinkedToken`），并使用诸如 `TokenElevationType` 之类的字段跟踪状态。

### Credentials user impersonation

如果你拥有**任何其他用户的有效凭据**，你可以使用这些凭据**创建**一个**新的 logon session**：
```
runas /user:domain\username cmd.exe
```
**access token** 还有一个在 **LSASS** 中的登录会话的 **reference**，如果进程需要访问网络中的某些对象，这会很有用。\
你可以使用以下方式启动一个进程，让它**使用不同的 credentials 访问网络服务**：
```
runas /user:domain\username /netonly cmd.exe
```
如果你有可用凭据可以访问网络中的对象，但这些凭据在当前主机内无效，因为它们只会用于网络访问（在当前主机上会使用你当前用户的权限）。

#### `runas /netonly` 详情

`runas /netonly`（以及 C2 helpers such as `make_token`）会创建一个 **`LOGON32_LOGON_NEW_CREDENTIALS`** token。理解这一点对 lateral movement 很有用，因为：

- **本地**，新进程会保留 **相同的本地身份**、组、完整性级别，以及与当前 token 大部分相同的访问决策。
- **远程**，出站认证可以对 SMB / WinRM / LDAP / HTTP / Kerberos / NTLM 使用 **提供的凭据**。
- 因此 `whoami` 可能仍然显示 **原始本地用户**，而网络访问则以 **备用账户** 的身份进行。

当这些凭据在域内或另一台主机上有效，但用户 **不能或不应** 在当前机器上本地登录时，这是一个很好的选择。

### Token 类型

有两种可用的 token 类型：

- **Primary Token**：它表示一个进程的安全凭据。Primary token 的创建以及与进程的关联都需要提升权限，这体现了权限分离原则。通常，认证服务负责创建 token，而 logon 服务负责将其关联到用户的操作系统 shell。值得注意的是，进程在创建时会继承其父进程的 primary token。
- **Impersonation Token**：使服务器应用能够临时采用客户端的身份来访问安全对象。该机制分为四个操作级别：
- **Anonymous**：授予的服务器访问权限类似于一个未识别用户。
- **Identification**：允许服务器验证客户端身份，但不使用它进行对象访问。
- **Impersonation**：使服务器能够以客户端身份运行。
- **Delegation**：类似于 Impersonation，但还包括将这种身份假设扩展到服务器交互的远程系统的能力，并确保凭据保留。

#### Impersonate Tokens

使用 metasploit 的 _**incognito**_ 模块，如果你有足够权限，可以很容易地 **列出** 并 **impersonate** 其他 **tokens**。这对执行 **仿佛你就是另一个用户** 的操作很有用。你也可以用这种技术 **提升权限**。

一些在操作中很容易忘记的实用说明：

- **`CreateProcessWithTokenW`** 需要调用者具备 **`SeImpersonatePrivilege`**，新进程会在 **调用者的 session** 中运行。
- 当 **`CreateProcessWithTokenW`** 因 `1314` 失败时，或者你需要在 **token 所引用的 session** 中启动进程时，通常使用 **`CreateProcessAsUserW`** 作为替代。
- 如果 token 来自 **`LogonUser(LOGON32_LOGON_NETWORK)`**，它通常是一个 **impersonation token**，因此在尝试用它创建进程前，需要先 **`DuplicateTokenEx(..., TokenPrimary, ...)`**。
- 并不是所有 impersonation token 都同样有用：**`SecurityIdentification`** 只能让你查看用户，但 **不能以该用户身份执行操作**。如果某个 coercion primitive 或 pipe/RPC client 只给你 identification-level token，请检查 **`TokenImpersonationLevel`**，并切换到能生成 **`SecurityImpersonation`** 或更高级别的 primitive。

#### 不接触 LSASS 的 Token 窃取

如果你已经处于 **service** 或 **SYSTEM** 上下文，并且 **有特权的用户已登录**，那么窃取或复制该用户的 token 往往比转储 **LSASS** 更隐蔽。在许多真实入侵中，这已经足以：

- 以该用户身份执行本地操作
- 以该用户身份访问远程资源
- 在不先提取可复用凭据的情况下执行 AD 操作

关于在特权上下文中进行 **session/user token hijacking** 的示例，请查看 [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md)。记住，像 **`WTSQueryUserToken`** 这样的 API 是为 **高度可信的服务** 设计的，通常需要 **`LocalSystem` + `SeTcbPrivilege`**，所以它们主要在你已经控制了 service-level 上下文后才有用。关于先获取 **SYSTEM** 的特定提权方式，请查看下面的页面。

### Token Privileges

了解哪些 **token privileges can be abused to escalate privileges:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

看看这个外部页面中 [**所有可能的 token privileges 以及一些定义**](https://github.com/gtworek/Priv2Admin)。

## References

- [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)
- [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
