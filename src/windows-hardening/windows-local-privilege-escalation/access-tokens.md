# 访问令牌

{{#include ../../banners/hacktricks-training.md}}

## 访问令牌

每个进程都有一个**主访问令牌**，用于定义其安全上下文。线程通常使用该令牌，但也可以临时拥有一个**模拟令牌**。令牌包含用户 SID、组 SID、特权、完整性信息，以及用于标识登录会话的登录 SID。进程通常会继承对父进程主令牌的引用；它们不会获得该令牌内容的独立副本。<sup>[[4]](#references)</sup>

你可以执行 `whoami /all` 查看这些信息。

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

or 使用 Sysinternals 的 _Process Explorer_（选择进程并打开“Security”选项卡）：

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### 本地管理员

当管理员适用 **UAC Admin Approval Mode** 时，交互式登录会创建一个完整的管理员 token 和一个经过筛选的 token。Explorer 和普通子进程默认使用经过筛选的 token。**Run as administrator** 等提权请求会要求 UAC 使用完整 token 启动程序。内置 Administrator 帐户以及禁用 Admin Approval Mode 时，具体行为有所不同。<sup>[[5]](#references)</sup>

请阅读专门的 [**UAC 页面**](../authentication-credentials-uac-and-efs/uac-user-account-control.md)，了解绕过技术和策略详情。

实际上，这意味着**未提权的管理员 shell 通常使用经过筛选的 token**。这就是为什么在进程提权之前，`whoami /groups` 经常会将 **`BUILTIN\Administrators` 显示为 `Deny only`**。在内部，Windows 会保留一个**关联的提权 token**（`TokenLinkedToken`），并使用 `TokenElevationType` 等字段跟踪其状态。

### 用户凭据模拟

如果你拥有**任何其他用户的有效凭据**，就可以使用这些凭据**创建**一个**新的登录会话**：

```
runas /user:domain\username cmd.exe
```

**access token** 还包含对 **LSASS** 中登录会话的**引用**，当进程需要访问网络上的某些对象时，这很有用。\
你可以启动一个**使用不同凭据访问网络服务**的进程：

```
runas /user:domain\username /netonly cmd.exe
```

如果你有可用于访问网络中对象的有效凭据，这会很有用；但这些凭据在当前主机上无效，因为它们只会用于网络访问（在当前主机上会使用你当前用户的权限）。

#### `runas /netonly` 详细说明

`runas /netonly`（以及 `make_token` 等 C2 辅助工具）会创建一个 **`LOGON32_LOGON_NEW_CREDENTIALS`** token。在横向移动期间理解这一点非常有用：<sup>[[3]](#references)</sup>

- **本地**：新进程保留**相同的本地身份**、组、完整性级别，以及与当前 token 相同的大部分访问决策。
- **远程**：出站身份验证可以使用**提供的凭据**进行 SMB / WinRM / LDAP / HTTP / Kerberos / NTLM 身份验证。
- 因此，`whoami` 仍可能显示**原始本地用户**，而网络访问则以**备用账户**的身份进行。

当凭据在域或另一台主机上有效，但该用户**无法或不应在当前计算机上本地登录**时，这是一个很好的选择。

### Token 类型

有两种类型的 token 可用：<sup>[[4]](#references)[[6]](#references)</sup>

- **Primary token**：表示进程的安全上下文。子进程通常会继承父进程的 primary token，而显式 token 的进程创建 API 则有各自的 token 访问权限和调用者特权要求。
- **Impersonation token**：允许服务器线程临时使用客户端的安全上下文进行访问检查。它有四个级别：
  - **Anonymous**：授予服务器类似于未识别用户的访问权限。
  - **Identification**：允许服务器验证客户端身份，但不能用该身份访问对象。
  - **Impersonation**：允许服务器以客户端身份运行。
  - **Delegation**：当身份验证机制和账户配置支持委派时，允许服务器在远程系统上模拟客户端。

#### 使用捕获的 token 前进行分类

不要只根据用户名选择 token。同一账户可以有多个 token，其登录会话、服务 SID、特权、完整性级别、限制和网络凭据各不相同。<sup>[[9]](#references)</sup> 至少使用 `GetTokenInformation` 查询 **`TokenType`**、**`TokenImpersonationLevel`**、**`TokenElevationType`**、**`TokenLinkedToken`**、**`TokenIntegrityLevel`**、**`TokenSessionId`**、**`TokenIsRestricted`** / **`TokenHasRestrictions`**，以及 **`TokenStatistics.AuthenticationId`**。<sup>[[7]](#references)</sup>

受限 token 可能包含仅用于拒绝的 SID、已移除的特权和限制 SID。如果存在限制 SID，Windows 会使用已启用的 SID 执行一次访问检查，再使用限制 SID 执行另一次；**两次检查都必须允许访问**。因此，输出中存在看似有用的用户 SID 或已启用的组，本身并不能证明该 token 可以访问目标对象。<sup>[[8]](#references)</sup>

对照文档中记录的 token 和进程创建要求，按以下流程判断：<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. 要将 **primary token** 提供给 `CreateProcessWithTokenW` 或 `CreateProcessAsUserW`，句柄必须具有 `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` 权限。
2. 使用 `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)` 转换 **impersonation token**。Identification 级别的 token 可以提供身份信息，但不能以该客户端身份执行访问检查。
3. `CreateProcessWithTokenW` 需要 `SeImpersonatePrivilege`，并会在调用者的会话中启动子进程。`CreateProcessAsUserW` 则使用 token 的会话，但通常需要 `SeIncreaseQuotaPrivilege`，有时还需要 `SeAssignPrimaryTokenPrivilege`。如果有凭据但缺少这些特权，文档中列出的替代方案是 `CreateProcessWithLogonW`。

#### 搜索 token 句柄，而不只是进程所有者

仅打开每个进程的 primary token，可能会遗漏服务和代理进程中作为普通句柄保留的 **impersonation token**。一种可复用的句柄表工作流是：枚举系统句柄、筛选 token 对象、使用 `PROCESS_DUP_HANDLE` 打开每个所有者进程、将候选句柄复制到当前进程，然后查询上述字段。确认复制后的句柄具有 `TOKEN_QUERY` 和 `TOKEN_DUPLICATE` 权限；看到 token 句柄并不意味着它可以被复制为可用的 primary token。受保护进程和进程 DACL 仍可能阻止打开所有者进程的句柄。<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` 可以自动枚举进程 primary token 和保留的 token 句柄。`list_token` 会为每个用户名保留一个优先候选项，而 `list_all_token` 会列出所有候选项。指定 PID 可将枚举范围限制为一个所有者进程。<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

对于手动检查和访问验证，**TokenUniverse** 可以打开进程/线程令牌、搜索现有令牌句柄、检查限制和登录会话、复制令牌，并测试多种进程创建方法。<sup>[[13]](#references)</sup> 有关底层跨进程句柄原语，请参阅：

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### 模拟令牌

如果你有足够的权限，可以使用 metasploit 的 _**incognito**_ 模块轻松**列出**并**模拟**其他**令牌**。这有助于**以其他用户的身份执行操作**。你也可以使用这种技术**提升权限**。

操作时容易忘记的一些实用提示：<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** 要求调用方具有 **`SeImpersonatePrivilege`**，并且新进程将在**调用方的会话**中运行。
- 如果 `CreateProcessWithTokenW` 因错误 `1314` 失败，只有当调用方满足其权限要求时，才可以将 **`CreateProcessAsUserW`** 作为备用方案。如果子进程必须在**令牌所引用的会话**中运行，那么它也是正确的选择。<sup>[[9]](#references)[[10]](#references)</sup>
- 如果令牌来自 **`LogonUser(LOGON32_LOGON_NETWORK)`**，它通常是一个**模拟令牌**，因此在尝试用它启动进程之前，需要先调用 **`DuplicateTokenEx(..., TokenPrimary, ...)`**。
- 并非所有模拟令牌都同样有用：**`SecurityIdentification`** 允许你检查用户，但**不能以该用户的身份执行操作**。如果某个 coercion 原语或 pipe/RPC 客户端只提供 identification 级别的令牌，请检查 **`TokenImpersonationLevel`**，并改用能提供 **`SecurityImpersonation`** 或更高级别令牌的原语。

#### 不接触 LSASS 的令牌窃取

如果你已经获得 **service** 或 **SYSTEM** 上下文，且有**特权用户已登录**，那么窃取或复制该用户的令牌通常比转储 **LSASS** 更不易引起注意。在许多真实入侵中，这就足以：<sup>[[2]](#references)</sup>

- 以该用户身份执行本地操作
- 以该用户身份访问远程资源
- 在提取可重复使用的凭据之前执行 AD 操作

有关从特权上下文进行**会话/用户令牌劫持**的示例，请参阅 [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md)。请注意，**`WTSQueryUserToken`** 等 API 面向**高度可信的服务**，通常要求 **`LocalSystem` + `SeTcbPrivilege`**，因此它们主要适用于你已经控制服务级上下文的情况。如需了解先获取 **SYSTEM** 的特定权限利用方法，请参阅以下页面。

### 令牌权限

了解哪些**令牌权限可被滥用来提升权限：**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

请参阅[**此外部页面，其中列出了所有可能的令牌权限并提供了一些定义**](https://github.com/gtworek/Priv2Admin)。

## References

- [1] [理解并滥用访问令牌 — 第二部分](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [滥用 Windows 令牌，在不接触 LSASS 的情况下攻陷 Active Directory](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [揭开 Cobalt Strike「make_token」命令的神秘面纱](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [访问令牌 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [用户帐户控制的工作原理 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [模拟级别 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [TOKEN_INFORMATION_CLASS 枚举 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [受限令牌 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [CreateProcessWithTokenW 函数 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [CreateProcessAsUserW 函数 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [DuplicateHandle 函数 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
