# 访问令牌

{{#include ../../banners/hacktricks-training.md}}

## 访问令牌

每个进程都有一个**主访问令牌**，用于定义其安全上下文。线程通常使用该令牌，但也可以临时拥有一个**模拟令牌**。令牌包含用户 SID、组 SID、特权、完整性信息，以及用于标识登录会话的登录 SID。进程通常会继承对父进程主令牌的引用，而不会获得其内容的独立副本。<sup>[[4]](#references)</sup>

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

or using _Process Explorer_ from Sysinternals（选择进程并访问“Security”选项卡）：

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### 本地管理员

当 **UAC Admin Approval Mode** 应用于管理员时，交互式登录会创建一个完整的管理员 token 和一个受限 token。Explorer 和普通子进程默认使用受限 token。诸如 **Run as administrator** 这样的提升请求会要求 UAC 使用完整 token 启动程序。内置 Administrator 账户以及禁用 Admin Approval Mode 时，具体行为会有所不同。<sup>[[5]](#references)</sup>

请阅读专门的 [**UAC 页面**](../authentication-credentials-uac-and-efs/uac-user-account-control.md)，了解绕过技术和策略详情。

实际上，这意味着**未提升权限的管理员 shell 通常使用受限 token**。因此，在进程提升权限之前，`whoami /groups` 通常会将 **`BUILTIN\Administrators` 显示为 `Deny only`**。在内部，Windows 会保留一个**关联的提升权限 token**（`TokenLinkedToken`），并通过 `TokenElevationType` 等字段跟踪状态。

### 凭据用户模拟

如果你拥有**任何其他用户的有效凭据**，就可以使用这些凭据**创建**一个**新的登录会话**：

```
runas /user:domain\username cmd.exe
```

**access token** 还包含对 **LSASS** 中登录会话的**引用**，如果进程需要访问网络中的某些对象，这会很有用。\
你可以启动一个**使用不同凭据访问网络服务**的进程，方法如下：

```
runas /user:domain\username /netonly cmd.exe
```

如果你拥有可用于访问网络中对象的有效凭据，这会很有用；但这些凭据在当前主机上无效，因为它们只会用于网络访问（在当前主机上仍会使用当前用户的权限）。

#### `runas /netonly` details

`runas /netonly`（以及 `make_token` 等 C2 辅助工具）会创建 **`LOGON32_LOGON_NEW_CREDENTIALS`** token。在横向移动期间，理解这一点非常有用：<sup>[[3]](#references)</sup>

- **在本地**，新进程会保留**相同的本地身份**、组、完整性级别，以及与当前 token 大致相同的访问决策。
- **在远程**，出站身份验证可以使用**提供的凭据**进行 SMB / WinRM / LDAP / HTTP / Kerberos / NTLM 身份验证。
- 因此，`whoami` 仍可能显示**原始本地用户**，而网络访问使用的则是**另一个账户**。

当凭据在域中或另一台主机上有效，但用户**无法或不应在当前机器上本地登录**时，这是一个很好的选择。

### Types of tokens

可用的 token 有两种类型：<sup>[[4]](#references)[[6]](#references)</sup>

- **Primary token**：表示进程的安全上下文。子进程通常会继承父进程的 primary token，而使用显式 token 的进程创建 API 则有各自的 token 访问和调用者权限要求。
- **Impersonation token**：允许服务器线程临时使用客户端的安全上下文进行访问检查。它有四个级别：
  - **Anonymous**：授予服务器类似于未识别用户的访问权限。
  - **Identification**：允许服务器验证客户端身份，但不能用该身份访问对象。
  - **Impersonation**：允许服务器以客户端身份运行。
  - **Delegation**：当身份验证机制和账户配置支持委派时，允许服务器在远程系统上模拟客户端。

#### Triage a captured token before using it

不要只根据用户名选择 token。同一账户可能拥有多个 token，它们的登录会话、服务 SID、权限、完整性级别、限制和网络凭据各不相同。<sup>[[9]](#references)</sup> 使用 `GetTokenInformation` 至少查询 **`TokenType`**、**`TokenImpersonationLevel`**、**`TokenElevationType`**、**`TokenLinkedToken`**、**`TokenIntegrityLevel`**、**`TokenSessionId`**、**`TokenIsRestricted`** / **`TokenHasRestrictions`**，以及 **`TokenStatistics.AuthenticationId`**。<sup>[[7]](#references)</sup>

受限 token 可能包含仅用于拒绝访问的 SID、已移除的权限和限制 SID。如果存在限制 SID，Windows 会执行一次包含已启用 SID 的访问检查，并再执行一次包含限制 SID 的访问检查；**两次检查都必须允许访问**。因此，输出中看似有利的用户 SID 或已启用的组，本身并不能证明该 token 可以访问目标对象。<sup>[[8]](#references)</sup>

对于文档中所述的 token 和进程创建要求，可按以下流程判断：<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. **Primary token** 在传递给 `CreateProcessWithTokenW` 或 `CreateProcessAsUserW` 之前，其句柄必须具有 `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` 权限。
2. 使用 `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)` 转换 **impersonation token**。Identification 级别的 token 可以暴露身份数据，但无法以该客户端身份执行访问检查。
3. `CreateProcessWithTokenW` 需要 `SeImpersonatePrivilege`，并会在调用者的会话中启动子进程。`CreateProcessAsUserW` 则使用 token 的会话，但通常需要 `SeIncreaseQuotaPrivilege`，有时还需要 `SeAssignPrimaryTokenPrivilege`。如果有凭据但缺少这些权限，文档中建议使用 `CreateProcessWithLogonW` 作为替代方案。

#### Hunt token handles, not only process owners

只打开每个进程的 primary token，可能会漏掉服务和代理进程中作为普通句柄保留的 **impersonation token**。一种可复用的句柄表工作流是：枚举系统句柄，筛选 token 对象，使用 `PROCESS_DUP_HANDLE` 打开每个所有者，将候选句柄复制到当前进程，然后查询上述字段。确认复制后的句柄包含 `TOKEN_QUERY` 和 `TOKEN_DUPLICATE`；发现 token 句柄并不意味着它可以被复制为可用的 primary token。受保护进程和进程 DACL 仍可能阻止打开所有者进程的句柄。<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` 会自动枚举进程 primary token 和保留的 token 句柄。`list_token` 会为每个用户名保留一个优先候选项，而 `list_all_token` 会打印所有候选项。指定 PID 可将枚举范围限制为单个所有者进程。<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

对于手动检查和访问验证，**TokenUniverse** 可以打开进程/线程令牌、搜索现有令牌句柄、检查限制和登录会话、复制令牌，并测试多种进程创建方法。<sup>[[13]](#references)</sup> 有关底层跨进程句柄原语，请参见：

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

### 搜寻正在生效的线程模拟令牌

即使服务线程的**进程主令牌**属于服务帐户，它也可以暂时模拟客户端，因此扫描进程所有者可能会遗漏客户端上下文。<sup>[[4]](#references)</sup> TokenUniverse 可以列出可访问的进程/线程令牌；在 System Informer 中，检查进程的 **Threads** 选项卡及其 **Impersonation** 列，寻找候选线程。<sup>[[13]](#references)[[14]](#references)</sup>

若要针对性地通过 API 检查，先获取 `TH32CS_SNAPTHREAD` 快照，将 `THREADENTRY32.th32OwnerProcessID` 筛选为服务 PID，然后对每个可访问线程调用 `OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid)` 和 `OpenThreadToken(thread, TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &token)`。<sup>[[15]](#references)[[16]](#references)</sup> `TRUE` 会使令牌打开访问检查使用调用方的**进程**上下文；如果扫描器本身正在以 identification 级别进行模拟，这一点很重要。<sup>[[17]](#references)</sup> 在尝试上述复制/进程创建流程前，先查询令牌的用户、类型、模拟级别和登录 ID。<sup>[[7]](#references)</sup> 线程可能会在枚举与打开之间停止模拟；令牌不存在、匿名令牌、受保护的线程、线程 DACL 和令牌 DACL 都可能阻止收集。<sup>[[16]](#references)[[17]](#references)</sup> 与扫描服务保留的令牌句柄不同，这种方法检查的是**当前分配给线程的令牌**。

如果想通过让特权客户端连接到你的管道来获取线程令牌，而不是扫描现有线程，请参见 [named-pipe client impersonation](named-pipe-client-impersonation.md)。

#### 模拟令牌

如果拥有足够的权限，可以使用 metasploit 的 _**incognito**_ 模块轻松**列出**并**模拟**其他**令牌**。这有助于**以其他用户的身份执行操作**。你也可以利用此技术**提升权限**。

操作时容易忘记的一些实用注意事项：<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** 要求调用方拥有 **`SeImpersonatePrivilege`**，并且新进程将在**调用方的会话**中运行。
- 只有在调用方满足其权限要求时，**`CreateProcessAsUserW`** 才能作为 `CreateProcessWithTokenW` 返回 `1314` 时的备选方案。如果子进程必须在**令牌所引用的会话**中运行，它也是正确的选择。<sup>[[9]](#references)[[10]](#references)</sup>
- **`LogonUser(LOGON32_LOGON_NETWORK)`** 返回一个**模拟令牌**。在创建进程前，使用 **`DuplicateTokenEx(..., TokenPrimary, ...)`** 将其转换。即使完成转换，生成的进程也无法使用该网络登录访问经过身份验证的远程共享或打印机：此登录类型不会缓存凭据。如果你拥有凭据且需要后续网络访问，请使用交互式或 network-cleartext 登录；不要将其与 `LOGON32_LOGON_NEW_CREDENTIALS`（`runas /netonly`）混淆，后者会保留本地身份，同时提供出站凭据。<sup>[[18]](#references)</sup>
- 并非所有模拟令牌都同样有用：**`SecurityIdentification`** 允许你检查用户，但**不能以该用户身份操作**。如果 coercion 原语或 pipe/RPC 客户端只提供 identification 级别的令牌，请检查 **`TokenImpersonationLevel`**，并改用能提供 **`SecurityImpersonation`** 或更高级别令牌的原语。

#### 无需接触 LSASS 的令牌窃取

如果你已经拥有 **service** 或 **SYSTEM** 上下文，且有**特权用户已登录**，窃取或复制该用户的令牌通常比转储 **LSASS** 更不易引起注意。在许多真实入侵中，这足以：<sup>[[2]](#references)</sup>

- 以该用户身份执行本地操作
- 以该用户身份访问远程资源
- 无需先提取可复用凭据即可执行 AD 操作

有关从特权上下文执行**会话/用户令牌劫持**的示例，请查看 [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md)。请记住，**`WTSQueryUserToken`** 等 API 面向**高度可信的服务**，通常要求 **`LocalSystem` + `SeTcbPrivilege`**，因此主要适用于你已经控制服务级别上下文的情况。若要了解获取 **SYSTEM** 的特定权限利用方法，请查看以下页面。

### 令牌权限

了解哪些**令牌权限可用于提升权限：**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

请参阅[**此外部页面，了解所有可能的令牌权限及其定义**](https://github.com/gtworek/Priv2Admin)。



## References

- [1] [了解并滥用访问令牌——第二部分](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [滥用 Windows 令牌，在不接触 LSASS 的情况下攻陷 Active Directory](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [揭秘 Cobalt Strike 的“make_token”命令](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
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
- [14] [System Informer 线程令牌功能请求](https://github.com/winsiderss/systeminformer/issues/1275)
- [15] [遍历线程列表 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list)
- [16] [NtOpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenthreadtoken)
- [17] [OpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
- [18] [LogonUserA - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera)
{{#include ../../banners/hacktricks-training.md}}
