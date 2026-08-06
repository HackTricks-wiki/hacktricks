# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

每个**登录到系统的用户**都**持有一个包含该登录会话安全信息的访问令牌**。用户登录时，系统会创建一个访问令牌。代表该用户**执行的每个进程**都**拥有该访问令牌的副本**。该令牌用于标识用户、用户所属的组以及用户的权限。令牌还包含一个用于标识当前登录会话的登录 SID（安全标识符）。

你可以通过执行 `whoami /all` 查看这些信息。
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
或使用 Sysinternals 中的 _Process Explorer_（选择进程并访问“Security”选项卡）：

![Access Tokens - Access Tokens: 或使用 Sysinternals 中的 Process Explorer（选择进程并访问“Security”选项卡）](<../../images/image (772).png>)

### 本地管理员

当本地管理员登录时，会创建 **两个 access tokens**：一个具有管理员权限，另一个具有普通权限。**默认情况下**，该用户执行进程时，使用的是具有**普通**（非管理员）**权限**的 token。当该用户尝试以**管理员身份执行**任何内容时（例如使用“Run as Administrator”），将使用 **UAC** 请求许可。\
如果你想[**进一步了解 UAC，请阅读此页面**](../authentication-credentials-uac-and-efs/index.html#uac)**。**

实际上，这意味着**未提升权限的管理员 shell 通常使用经过筛选的 token**。因此，在进程完成提升之前，`whoami /groups` 通常会将 **`BUILTIN\Administrators` 显示为 `Deny only`**。在内部，Windows 会保留一个**关联的提升 token**（`TokenLinkedToken`），并使用 `TokenElevationType` 等字段跟踪状态。

### Credentials user impersonation

如果你拥有任何其他用户的**有效凭据**，就可以使用这些凭据创建一个**新的登录会话**：
```
runas /user:domain\username cmd.exe
```
**access token** 还包含 **LSASS** 中登录会话的 **reference**，如果进程需要访问网络中的某些对象，这会很有用。\
你可以启动一个进程，使其 **uses different credentials for accessing network services**，方法如下：
```
runas /user:domain\username /netonly cmd.exe
```
如果你拥有可用于访问网络中对象的有效凭据，但这些凭据在当前主机内无效，那么这会非常有用，因为它们只会用于网络访问（在当前主机中，将使用你当前用户的权限）。

#### `runas /netonly` details

`runas /netonly`（以及 `make_token` 等 C2 helpers）会创建一个 **`LOGON32_LOGON_NEW_CREDENTIALS`** token。在 lateral movement 期间理解这一点非常有用，因为：<sup>[[3]](#references)</sup>

- **在本地**，新进程会保留**相同的本地身份**、组、完整性级别，以及与当前 token 大部分相同的访问决策。
- **在远程**，出站身份验证可以对 SMB / WinRM / LDAP / HTTP / Kerberos / NTLM 使用**所提供的凭据**。
- 因此，`whoami` 可能仍然显示**原始本地用户**，而网络访问实际上使用的是**备用账户**。

当凭据在域中或另一台主机上有效，但用户**无法或不应当在当前机器上本地登录**时，这是一个很好的选项。

### Types of tokens

有两种可用的 token：

- **Primary Token**：它代表进程的安全凭据。创建 primary token 并将其关联到进程的操作需要提升的权限，这体现了权限分离原则。通常，身份验证服务负责创建 token，而 logon service 负责将其关联到用户的操作系统 shell。需要注意的是，进程在创建时会继承其父进程的 primary token。
- **Impersonation Token**：允许 server application 临时采用 client 的身份，以访问安全对象。该机制分为四个操作级别：
- **Anonymous**：授予 server 类似于未识别用户的访问权限。
- **Identification**：允许 server 验证 client 的身份，但不能使用该身份访问对象。
- **Impersonation**：允许 server 使用 client 的身份运行。
- **Delegation**：与 Impersonation 类似，但还可以将此身份扩展到 server 交互的远程系统，从而保留凭据。

#### Impersonate Tokens

如果你拥有足够的权限，可以使用 metasploit 的 _**incognito**_ module 轻松**列出**并**模拟**其他 **tokens**。这对于执行**仿佛是其他用户进行的操作**非常有用。你也可以使用此技术**提升权限**。

操作时一些容易忘记的实用注意事项：<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** 要求调用者具有 **`SeImpersonatePrivilege`**，并且新进程会在**调用者的 session**中运行。
- 当 **`CreateProcessWithTokenW`** 因 `1314` 失败，或者你需要在**token 所引用的 session**中启动进程时，通常可以使用 **`CreateProcessAsUserW`** 作为 fallback。
- 如果 token 来自 **`LogonUser(LOGON32_LOGON_NETWORK)`**，它通常是一个 **impersonation token**，因此在尝试使用它启动进程前，需要执行 **`DuplicateTokenEx(..., TokenPrimary, ...)`**。
- 并非所有 impersonation token 都同样有用：**`SecurityIdentification`** 允许你检查用户，但**不能以该用户身份执行操作**。如果 coercion primitive 或 pipe/RPC client 只为你提供了 identification-level token，请检查 **`TokenImpersonationLevel`**，并改用能够生成 **`SecurityImpersonation`** 或更高等级 token 的 primitive。

#### Token theft without touching LSASS

如果你已经拥有 **service** 或 **SYSTEM** context，并且**特权用户已登录**，那么窃取或复制该用户的 token 通常比 dump **LSASS** 更隐蔽。在许多真实入侵中，这已经足以：<sup>[[2]](#references)</sup>

- 以该用户身份执行本地操作
- 以该用户身份访问远程资源
- 在无需先提取可复用凭据的情况下执行 AD 操作

有关从特权 context 执行 **session/user token hijacking** 的示例，请查看 [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md)。请记住，**`WTSQueryUserToken`** 等 API 面向**高度可信的服务**，通常要求 **`LocalSystem` + `SeTcbPrivilege`**，因此它们主要适用于你已经控制 service-level context 之后。有关首先获取 **SYSTEM** 的、特定于权限的方法，请查看下面的页面。

### Token Privileges

了解哪些 **token privileges 可以被滥用来提升权限：**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

请查看 [**all the possible token privileges and some definitions on this external page**](https://github.com/gtworek/Priv2Admin)。

## References

- [1] [Understanding and Abusing Access Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Demystifying Cobalt Strike's "make_token" Command](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
